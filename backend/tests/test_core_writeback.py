"""Extended tests for app.core.writeback — additional uncovered paths."""

import pytest
from sqlalchemy.orm import Session
from unittest.mock import patch, MagicMock

from app import models
from app.core.job_tracker import queue_job, finish_job
from app.core.utils import new_id
from app.core.writeback import (
    _find_cred_by_username,
    _mark_hosts_compromised,
    _link_cred_to_hosts,
    _writeback_httpx_tags,
    _writeback_exec_cred_link,
    _writeback_netexec,
    apply_writeback,
)


@pytest.fixture()
def pid(db: Session) -> str:
    p_id = new_id("prj")
    db.add(models.Project(id=p_id, name="Test Project", added="2024-01-01"))
    db.commit()
    return p_id


def _make_host(db: Session, pid: str, **overrides) -> models.Host:
    h = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=overrides.get("ip", "10.0.0.1"),
        hostname=overrides.get("hostname", ""),
        os=overrides.get("os", "Linux"),
        status=overrides.get("status", "up"),
        ports=overrides.get("ports", []),
        services=overrides.get("services", []),
        tags=overrides.get("tags", []),
    )
    db.add(h)
    db.commit()
    return h


def _make_cred(db: Session, pid: str, **overrides) -> models.Cred:
    c = models.Cred(
        id=new_id("crd"),
        pid=pid,
        username=overrides.get("username", "admin"),
        secret=overrides.get("secret", ""),
        type=overrides.get("type", "plain"),
        service=overrides.get("service", "smb"),
        domain=overrides.get("domain", ""),
        host_ids=overrides.get("host_ids", []),
        tags=overrides.get("tags", []),
    )
    db.add(c)
    db.commit()
    return c


def _make_finished_job(
    db: Session, pid: str, connector_key: str, operation: str,
    *, output: str = "", error_output: str = "",
    request_json: dict | None = None, result: dict | None = None,
) -> models.Job:
    job = queue_job(
        db, pid, connector_key, f"test {connector_key}",
        connector_key=connector_key,
        operation=operation,
        request_json=request_json or {},
    )
    return finish_job(
        db, job,
        status="done",
        output=output,
        error_output=error_output,
        result=result or {},
    )


class TestFindCredByUsername:
    def test_finds_by_username(self, db: Session, pid: str):
        cred = _make_cred(db, pid, username="admin")
        found = _find_cred_by_username(db, pid, "admin", "")
        assert found is not None
        assert found.id == cred.id

    def test_finds_by_domain_qualified(self, db: Session, pid: str):
        cred = _make_cred(db, pid, username="CORP\\admin")
        found = _find_cred_by_username(db, pid, "admin", "CORP")
        assert found is not None

    def test_returns_none_not_found(self, db: Session, pid: str):
        found = _find_cred_by_username(db, pid, "nonexistent", "")
        assert found is None


class TestMarkHostsCompromised:
    def test_marks_matching_hosts(self, db: Session, pid: str):
        h1 = _make_host(db, pid, ip="10.0.0.1", status="up")
        _make_host(db, pid, ip="10.0.0.2", status="up")
        changed = _mark_hosts_compromised(db, pid, {"10.0.0.1"})
        assert len(changed) == 1
        assert h1.status == "compromised"
        assert "pwned" in (h1.tags or [])

    def test_already_compromised_not_changed(self, db: Session, pid: str):
        h = _make_host(db, pid, ip="10.0.0.1", status="compromised", tags=["pwned"])
        changed = _mark_hosts_compromised(db, pid, {"10.0.0.1"})
        assert len(changed) == 0

    def test_no_matching_hosts(self, db: Session, pid: str):
        _make_host(db, pid, ip="10.0.0.1")
        changed = _mark_hosts_compromised(db, pid, {"10.0.0.99"})
        assert len(changed) == 0


class TestLinkCredToHosts:
    def test_links_when_cred_found(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.1")
        cred = _make_cred(db, pid, username="admin", secret="P@ss")
        req = {"username": "admin", "password": "P@ss", "domain": ""}
        _link_cred_to_hosts(db, pid, req, [host])
        db.flush()
        found = _find_cred_by_username(db, pid, "admin", "")
        assert host.id in (found.host_ids or [])

    def test_skips_without_username(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.1")
        cred = _make_cred(db, pid, username="admin")
        req = {"password": "P@ss"}
        _link_cred_to_hosts(db, pid, req, [host])
        db.refresh(cred)
        assert host.id not in (cred.host_ids or [])

    def test_skips_without_password_or_hash(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.1")
        cred = _make_cred(db, pid, username="admin")
        req = {"username": "admin"}
        _link_cred_to_hosts(db, pid, req, [host])
        db.refresh(cred)
        assert host.id not in (cred.host_ids or [])


class TestWritebackHttpxNoTarget:
    def test_no_target_no_crash(self, db: Session, pid: str):
        _writeback_httpx_tags(db, pid, {}, {})


class TestWritebackExecCredLinkEdgeCases:
    def test_nonexistent_cred(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.1")
        _writeback_exec_cred_link(db, pid, {"host_id": host.id, "cred_id": "nonexistent"}, {"host_id": host.id})


class TestWritebackNetexec:
    def test_no_pwned_ips_is_noop(self, db: Session, pid: str):
        _writeback_netexec(db, pid, {}, {}, "SMB    10.0.0.1    445    DC01    admin")


class TestApplyWritebackEdgeCases:
    def test_httpx_by_hostname(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.1", hostname="web01.local", tags=[])
        job = _make_finished_job(
            db, pid, "httpx", "scan",
            request_json={"target": "web01.local"},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.flush()
        assert "web" in (host.tags or [])
