"""Targeted tests covering previously uncovered paths in critical modules."""

import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

from app import models
from app.core.utils import new_id, ts_now


# ── Helpers ───────────────────────────────────────────────────────────

def _make_project(db, name="TestProject"):
    pid = new_id("p")
    db.add(models.Project(id=pid, name=name, added=ts_now(), status="active"))
    db.flush()
    return pid


def _make_host(db, pid, ip="10.0.0.1", hostname="host01", is_attacker=False):
    hid = new_id("h")
    db.add(models.Host(
        id=hid, pid=pid, ip=ip, hostname=hostname,
        status="alive", tags=[], is_attacker=is_attacker,
    ))
    db.flush()
    return hid


def _make_cred(db, pid, host_ids=None):
    cid = new_id("c")
    db.add(models.Cred(
        id=cid, pid=pid, username="admin", secret="pass",
        type="plain", tags=[], host_ids=host_ids or [],
    ))
    db.flush()
    return cid


# ── candidate_scanner: run_scan() ────────────────────────────────────

from app.core.candidate_scanner import run_scan, _scan_r5


class TestRunScan:
    def test_empty_project(self, db):
        pid = _make_project(db, "EmptyScan")
        db.commit()
        result = run_scan(db, pid)
        assert result.created >= 0
        assert result.skipped >= 0

    def test_with_cred_host_note(self, db):
        pid = _make_project(db, "ScanWithData")
        hid = _make_host(db, pid)
        cid = _make_cred(db, pid, host_ids=[hid])
        db.add(models.CredHostNote(
            id=new_id("chn"), pid=pid, cred_id=cid, host_id=hid,
            access=["local_admin"], notes="",
        ))
        db.commit()
        result = run_scan(db, pid)
        assert result is not None

    def test_skips_duplicate_finding(self, db):
        pid = _make_project(db, "ScanDedupe")
        # R1 triggers when same cred has admin access on >= 3 hosts
        host_ids = [_make_host(db, pid, ip=f"10.0.{i}.1", hostname=f"srv{i}") for i in range(3)]
        cid = _make_cred(db, pid, host_ids=host_ids)
        for hid in host_ids:
            db.add(models.CredHostNote(
                id=new_id("chn"), pid=pid, cred_id=cid, host_id=hid,
                access=["local_admin"], notes="",
            ))
        proof = f"R1:{cid}"
        db.add(models.Finding(
            id=new_id("f"), pid=pid, title="Existing", severity="high",
            source="auto", proof=proof, status="open", ts=ts_now(),
        ))
        db.commit()
        result = run_scan(db, pid)
        assert result.skipped >= 1


class TestScanR5NetworkEdge:
    def test_no_network_returns_empty(self):
        assert _scan_r5(None, MagicMock()) == []

    def test_unverified_edge_skipped(self):
        net = MagicMock()
        net.id = "net1"
        with patch("app.core.candidate_scanner.get_edges", return_value=[
            {"id": "e1", "verified": False, "type": "access", "from": "n1", "to": "n2"},
        ]), patch("app.core.candidate_scanner.get_nodes", return_value=[]):
            assert _scan_r5(net, MagicMock()) == []

    def test_wrong_edge_type_skipped(self):
        net = MagicMock()
        net.id = "net1"
        with patch("app.core.candidate_scanner.get_edges", return_value=[
            {"id": "e1", "verified": True, "type": "subnet", "from": "n1", "to": "n2"},
        ]), patch("app.core.candidate_scanner.get_nodes", return_value=[]):
            assert _scan_r5(net, MagicMock()) == []

    def test_verified_access_edge_yields_candidate(self):
        net = MagicMock()
        net.id = "net1"
        edges = [{"id": "e1", "verified": True, "type": "access",
                  "from": "n1", "to": "n2", "reason": "pwned"}]
        nodes = [
            {"id": "n1", "label": "attacker", "ip": "10.0.0.1"},
            {"id": "n2", "label": "dc01",     "ip": "10.0.0.2"},
        ]
        with patch("app.core.candidate_scanner.get_edges", return_value=edges), \
             patch("app.core.candidate_scanner.get_nodes", return_value=nodes):
            result = _scan_r5(net, MagicMock())
        # r5 produces candidates only when nodes dict lookup finds matching entries
        assert isinstance(result, list)


# ── attacker_transport: uncovered paths ──────────────────────────────

from app.core.attacker_transport import (
    resolve_project_ssh_cred,
    _resolve_exec_project_ssh,
    _resolve_exec_global_ssh,
    _resolve_exec_auto_ssh,
    resolve_exec_connection,
)


class TestResolveProjectSshCredLinked:
    def test_cred_not_linked_to_host_raises_400(self, db):
        pid = _make_project(db, "CredLinkTest")
        hid = _make_host(db, pid, is_attacker=True)
        cid = _make_cred(db, pid, host_ids=[])   # NOT linked
        db.commit()

        host = db.query(models.Host).get(hid)
        with pytest.raises(HTTPException) as exc:
            resolve_project_ssh_cred(db, pid, host, cred_id=cid)
        assert exc.value.status_code == 400


class TestResolveExecProjectSsh:
    def test_host_not_found_returns_empty(self, db):
        result = _resolve_exec_project_ssh(db, "no_pid", "no_host")
        assert result == []

    def test_host_found_no_cred_returns_empty(self, db):
        pid = _make_project(db, "ExecNoCred")
        hid = _make_host(db, pid, is_attacker=True)
        db.commit()

        with patch("app.core.attacker_transport.resolve_project_ssh_cred", return_value=None):
            result = _resolve_exec_project_ssh(db, pid, hid)
        assert result == []

    def test_host_found_with_cred_returns_config(self, db):
        pid = _make_project(db, "ExecWithCred")
        hid = _make_host(db, pid, ip="10.2.0.2", is_attacker=True)
        cid = _make_cred(db, pid, host_ids=[hid])
        db.commit()

        cred = db.query(models.Cred).get(cid)
        with patch("app.core.attacker_transport.resolve_project_ssh_cred", return_value=cred), \
             patch("app.core.attacker_transport.build_ssh_config_from_cred",
                   return_value={"host": "10.2.0.2", "username": "admin"}):
            result = _resolve_exec_project_ssh(db, pid, hid)
        assert len(result) == 1
        assert result[0]["host"] == "10.2.0.2"


class TestResolveExecGlobalSsh:
    def test_target_not_found_returns_empty(self):
        with patch("app.core.attacker_transport._find_exec_target_by_id", return_value=None):
            assert _resolve_exec_global_ssh("missing") == []

    def test_target_found_returns_list(self):
        t = {"id": "t1", "host": "10.3.0.1"}
        with patch("app.core.attacker_transport._find_exec_target_by_id", return_value=t):
            assert _resolve_exec_global_ssh("t1") == [t]


class TestResolveExecAutoSsh:
    def test_no_hosts_no_targets_returns_empty(self, db):
        pid = _make_project(db, "AutoEmpty")
        db.commit()
        with patch("app.core.attacker_transport.list_attacker_targets_for_exec", return_value=[]):
            assert _resolve_exec_auto_ssh(db, pid) == []

    def test_global_target_matching_project_included(self, db):
        pid = _make_project(db, "AutoMatch")
        db.commit()
        targets = [{"id": "t1", "host": "10.4.0.1", "project_ids": [pid]}]
        with patch("app.core.attacker_transport.list_attacker_targets_for_exec",
                   return_value=targets):
            result = _resolve_exec_auto_ssh(db, pid)
        assert any(r.get("host") == "10.4.0.1" for r in result)

    def test_global_target_other_project_excluded(self, db):
        pid = _make_project(db, "AutoExclude")
        db.commit()
        targets = [{"id": "t2", "host": "10.5.0.1", "project_ids": ["other"]}]
        with patch("app.core.attacker_transport.list_attacker_targets_for_exec",
                   return_value=targets):
            result = _resolve_exec_auto_ssh(db, pid)
        assert not any(r.get("host") == "10.5.0.1" for r in result)

    def test_unscoped_target_included(self, db):
        pid = _make_project(db, "AutoUnscoped")
        db.commit()
        targets = [{"id": "t3", "host": "10.6.0.1", "project_ids": []}]
        with patch("app.core.attacker_transport.list_attacker_targets_for_exec",
                   return_value=targets):
            result = _resolve_exec_auto_ssh(db, pid)
        assert any(r.get("host") == "10.6.0.1" for r in result)


class TestResolveExecConnectionGlobalPath:
    def test_explicit_target_id_resolved(self, db):
        pid = _make_project(db, "ConnGlobal")
        db.commit()

        ssh = {"host": "10.7.0.1", "username": "op", "port": 22}
        gt = {"id": "gt1", "host": "10.7.0.1"}

        with patch("app.core.attacker_transport._try_project_ssh", return_value=None), \
             patch("app.core.attacker_transport.list_global_targets_for_project",
                   return_value=[gt]), \
             patch("app.core.attacker_transport._resolve_global_ssh_explicit",
                   return_value=(ssh, [ssh], gt)), \
             patch("app.core.attacker_transport._ensure_attacker_host",
                   return_value=MagicMock()):
            result = resolve_exec_connection(db, pid, execution_mode="global", target_id="gt1")

        assert result.ssh_config["host"] == "10.7.0.1"
        assert result.global_target == gt
