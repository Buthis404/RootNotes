"""
Tests for core/writeback.py — post-job enrichment rules.

Each test creates a finished job + the necessary project state, then calls
apply_writeback and verifies the expected host/cred mutations.
"""

import pytest
from sqlalchemy.orm import Session

from app import models
from app.core.job_tracker import queue_job, finish_job
from app.core.utils import new_id
from app.core.writeback import (
    _tags_for_ports,
    _add_tags,
    _collect_pwned_ips,
    _parse_port_num,
    apply_writeback,
)


# ── fixtures ──────────────────────────────────────────────────────────


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


# ── _parse_port_num ──────────────────────────────────────────────────


class TestParsePortNum:
    def test_plain_number(self):
        assert _parse_port_num("80") == 80

    def test_slash_proto(self):
        assert _parse_port_num("443/tcp") == 443

    def test_invalid(self):
        assert _parse_port_num("abc") is None

    def test_none(self):
        assert _parse_port_num(None) is None

    def test_empty(self):
        assert _parse_port_num("") is None


# ── _tags_for_ports ──────────────────────────────────────────────────


class TestTagsForPorts:
    def test_dc_port_88(self):
        assert "dc" in _tags_for_ports(["88/tcp"])

    def test_ldap_ports(self):
        tags = _tags_for_ports(["389/tcp", "636/tcp"])
        assert "ldap" in tags

    def test_smb_port(self):
        assert "smb" in _tags_for_ports(["445/tcp"])

    def test_web_ports(self):
        for port in ["80/tcp", "443/tcp", "8080/tcp", "8443/tcp"]:
            assert "web" in _tags_for_ports([port])

    def test_ssh_port(self):
        assert "ssh" in _tags_for_ports(["22/tcp"])

    def test_rdp_port(self):
        assert "rdp" in _tags_for_ports(["3389/tcp"])

    def test_mssql_port(self):
        assert "mssql" in _tags_for_ports(["1433/tcp"])

    def test_winrm_port(self):
        assert "winrm" in _tags_for_ports(["5985/tcp"])

    def test_no_matching_ports(self):
        assert _tags_for_ports(["9999/tcp"]) == set()

    def test_empty_list(self):
        assert _tags_for_ports([]) == set()

    def test_multiple_ports(self):
        tags = _tags_for_ports(["88/tcp", "445/tcp", "80/tcp"])
        assert tags == {"dc", "smb", "web"}

    def test_mixed_invalid_ports(self):
        tags = _tags_for_ports(["80/tcp", "bad", None, "443/tcp"])
        assert tags == {"web"}


# ── _add_tags ────────────────────────────────────────────────────────


class TestAddTags:
    def test_adds_new_tags(self, db: Session, pid: str):
        host = _make_host(db, pid, tags=["existing"])
        changed = _add_tags(host, {"new", "also_new"})
        assert changed is True
        assert set(host.tags) == {"existing", "new", "also_new"}

    def test_no_change_if_already_present(self, db: Session, pid: str):
        host = _make_host(db, pid, tags=["dc", "smb"])
        changed = _add_tags(host, {"dc"})
        assert changed is False
        assert set(host.tags) == {"dc", "smb"}

    def test_empty_host_tags(self, db: Session, pid: str):
        host = _make_host(db, pid, tags=[])
        changed = _add_tags(host, {"web"})
        assert changed is True
        assert host.tags == ["web"]


# ── _collect_pwned_ips ───────────────────────────────────────────────


class TestCollectPwnedIps:
    def test_single_pwned_line(self):
        output = "SMB    10.0.0.5    445    DC01    (Pwn3d!)"
        assert _collect_pwned_ips(output) == {"10.0.0.5"}

    def test_multiple_pwned_lines(self):
        output = (
            "SMB    10.0.0.5    445    DC01    (Pwn3d!)\n"
            "SMB    10.0.0.6    445    WS01    (Pwn3d!)\n"
        )
        assert _collect_pwned_ips(output) == {"10.0.0.5", "10.0.0.6"}

    def test_case_insensitive(self):
        output = "SMB    10.0.0.5    445    DC01    (pwn3d!)"
        assert _collect_pwned_ips(output) == {"10.0.0.5"}

    def test_no_pwned(self):
        output = "SMB    10.0.0.5    445    DC01    admin"
        assert _collect_pwned_ips(output) == set()

    def test_pwned_without_ip(self):
        output = "something (Pwn3d!) happened"
        assert _collect_pwned_ips(output) == set()


# ── apply_writeback: nmap tags ────────────────────────────────────────


class TestWritebackNmap:
    def test_auto_tags_by_ports(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.1", ports=["88/tcp", "445/tcp", "80/tcp"])
        job = _make_finished_job(
            db, pid, "nmap", "scan",
            request_json={"target": "10.0.0.1"},
            result={"hosts_found": 1},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(host)
        tags = set(host.tags or [])
        assert "dc" in tags
        assert "smb" in tags
        assert "web" in tags

    def test_no_duplicate_tags(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.2", ports=["445/tcp"], tags=["smb", "existing"])
        job = _make_finished_job(
            db, pid, "nmap", "scan",
            request_json={"target": "10.0.0.2"},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(host)
        assert host.tags.count("smb") == 1

    def test_ignores_failed_job(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.3", ports=["88/tcp"], tags=[])
        job = queue_job(
            db, pid, "nmap", "nmap fail",
            connector_key="nmap", operation="scan",
            request_json={"target": "10.0.0.3"},
        )
        finish_job(db, job, status="failed", error_output="timeout")
        apply_writeback(db, job, job.result_json or {})
        db.refresh(host)
        assert "dc" not in (host.tags or [])


# ── apply_writeback: netexec pwned ────────────────────────────────────


class TestWritebackNetexec:
    def test_marks_pwned_host_compromised(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.5", status="up")
        job = _make_finished_job(
            db, pid, "netexec", "scan",
            output="SMB    10.0.0.5    445    DC01    (Pwn3d!)\n",
            request_json={"username": "admin", "password": "test"},  # NOSONAR
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(host)
        assert host.status == "compromised"
        assert "pwned" in (host.tags or [])

    def test_does_not_downgrade_from_compromised(self, db: Session, pid: str):
        """If host is already compromised, status stays compromised."""
        host = _make_host(db, pid, ip="10.0.0.6", status="compromised")
        job = _make_finished_job(
            db, pid, "netexec", "scan",
            output="SMB    10.0.0.6    445    WS01    admin\n",
            request_json={},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(host)
        assert host.status == "compromised"

    def test_links_cred_to_host(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.7", status="up")
        cred = _make_cred(db, pid, username="admin", secret="P@ss")
        job = _make_finished_job(
            db, pid, "netexec", "scan",
            output="SMB    10.0.0.7    445    WS01    (Pwn3d!)\n",
            request_json={"username": "admin", "password": "P@ss"},  # NOSONAR
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(cred)
        assert host.id in (cred.host_ids or [])

    def test_no_pwned_ips_is_noop(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.8", status="up")
        job = _make_finished_job(
            db, pid, "netexec", "scan",
            output="SMB    10.0.0.8    445    WS01    admin\n",
            request_json={},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(host)
        assert host.status == "up"
        assert "pwned" not in (host.tags or [])

    def test_multiple_pwned_hosts(self, db: Session, pid: str):
        h1 = _make_host(db, pid, ip="10.0.0.10", status="up")
        h2 = _make_host(db, pid, ip="10.0.0.11", status="up")
        job = _make_finished_job(
            db, pid, "netexec", "scan",
            output=(
                "SMB    10.0.0.10    445    DC01    (Pwn3d!)\n"
                "SMB    10.0.0.11    445    WS01    (Pwn3d!)\n"
            ),
            request_json={},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(h1)
        db.refresh(h2)
        assert h1.status == "compromised"
        assert h2.status == "compromised"


# ── apply_writeback: httpx web tag ────────────────────────────────────


class TestWritebackHttpx:
    def test_adds_web_tag_to_target(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.20", tags=[])
        job = _make_finished_job(
            db, pid, "httpx", "scan",
            request_json={"target": "10.0.0.20"},
            result={"urls_found": 1},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(host)
        assert "web" in (host.tags or [])

    def test_no_web_tag_without_host(self, db: Session, pid: str):
        """If no matching host exists, no crash."""
        job = _make_finished_job(
            db, pid, "httpx", "scan",
            request_json={"target": "10.0.0.99"},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        # no crash = pass

    def test_hostname_match(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.21", hostname="web01.local", tags=[])
        job = _make_finished_job(
            db, pid, "httpx", "scan",
            request_json={"target": "web01.local"},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(host)
        assert "web" in (host.tags or [])


# ── apply_writeback: attacker_ssh cred link ───────────────────────────


class TestWritebackExecCredLink:
    def test_links_cred_to_host(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.30")
        cred = _make_cred(db, pid, username="ssh_user", secret="pass")
        job = _make_finished_job(
            db, pid, "attacker_ssh", "exec",
            request_json={"host_id": host.id, "cred_id": cred.id},
            result={"host_id": host.id},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(cred)
        assert host.id in (cred.host_ids or [])

    def test_no_link_without_host_id(self, db: Session, pid: str):
        cred = _make_cred(db, pid, username="admin2", secret="pass")
        job = _make_finished_job(
            db, pid, "attacker_ssh", "exec",
            request_json={"cred_id": cred.id},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(cred)
        assert cred.host_ids == []

    def test_no_link_without_cred_id(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.31")
        cred = _make_cred(db, pid, username="admin3", secret="pass")
        job = _make_finished_job(
            db, pid, "attacker_ssh", "exec",
            request_json={"host_id": host.id},
            result={"host_id": host.id},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(cred)
        assert cred.host_ids == []

    def test_no_duplicate_host_links(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.32")
        cred = _make_cred(db, pid, username="admin4", secret="pass", host_ids=[host.id])
        job = _make_finished_job(
            db, pid, "attacker_ssh", "exec",
            request_json={"host_id": host.id, "cred_id": cred.id},
            result={"host_id": host.id},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(cred)
        assert cred.host_ids.count(host.id) == 1

    def test_result_host_id_used_as_fallback(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.33")
        cred = _make_cred(db, pid, username="admin5", secret="pass")
        # request_json has no host_id, but result does
        job = _make_finished_job(
            db, pid, "attacker_ssh", "exec",
            request_json={"cred_id": cred.id},
            result={"host_id": host.id},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(cred)
        assert host.id in (cred.host_ids or [])


# ── apply_writeback: structured result always populated ───────────────


class TestStructuredResultPopulation:
    def test_structured_key_added(self, db: Session, pid: str):
        job = _make_finished_job(
            db, pid, "nmap", "scan",
            request_json={"target": "10.0.0.1"},
            result={"hosts_found": 2},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(job)
        assert "structured" in (job.result_json or {})

    def test_structured_has_ok_field(self, db: Session, pid: str):
        job = _make_finished_job(
            db, pid, "nmap", "scan",
            request_json={"target": "10.0.0.1"},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(job)
        sr = (job.result_json or {}).get("structured", {})
        assert "ok" in sr
        assert sr["ok"] is True  # job was done

    def test_structured_failed_job(self, db: Session, pid: str):
        job = queue_job(
            db, pid, "nmap", "fail",
            connector_key="nmap", operation="scan",
            request_json={"target": "10.0.0.1"},
        )
        finish_job(db, job, status="failed", error_output="boom")
        apply_writeback(db, job, job.result_json or {})
        db.refresh(job)
        sr = (job.result_json or {}).get("structured", {})
        assert sr.get("ok") is False


# ── apply_writeback: no crash on unknown connector ────────────────────


class TestWritebackUnknownConnector:
    def test_unknown_connector_is_noop(self, db: Session, pid: str):
        job = _make_finished_job(
            db, pid, "custom_tool", "scan",
            request_json={},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        # no crash = pass

    def test_wrong_operation_is_noop(self, db: Session, pid: str):
        host = _make_host(db, pid, ip="10.0.0.1", status="up", tags=[])
        job = _make_finished_job(
            db, pid, "nmap", "import",
            request_json={"target": "10.0.0.1"},
            result={},
        )
        apply_writeback(db, job, job.result_json or {})
        db.refresh(host)
        # No tags should be added for nmap/import
        assert host.tags == []
