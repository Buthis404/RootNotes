"""
Tests for core/job_runner.py — job dispatch, handler registration,
supports_queued_execution, and the pure helper functions that can be
exercised without SSH/network.

The actual SSH runner handlers (_run_nmap_job, _run_exec_job, etc.) require
a live attacker target and are not tested here — we test the dispatch
mechanism and the synchronous helpers that transform data.
"""

import pytest
from sqlalchemy.orm import Session

from app import models
from app.core.job_runner import (
    supports_queued_execution,
    _JOB_HANDLERS,
    _parse_c2_exec_payload,
    _parse_donpapi_payload,
    _donpapi_resolve_cred,
    run_queued_job,
)

# These scan helpers were extracted from job_runner into scan_helpers in v0.9.0
# and lost their leading underscore. Aliased back so the test body is unchanged.
from app.core.scan_helpers import (
    nmap_upsert_host as _nmap_upsert_host,
    cme_upsert_host as _cme_upsert_host,
    cme_upsert_cred as _cme_upsert_cred,
    cme_build_auth as _cme_build_auth,
    cme_process_hosts as _cme_process_hosts,
    cme_process_creds as _cme_process_creds,
    ffuf_severity as _ffuf_severity,
)
from app.core.job_tracker import queue_job, finish_job
from app.core.utils import new_id


# ── fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def pid(db: Session) -> str:
    """Create a minimal project row so FK constraints pass."""
    p_id = new_id("prj")
    db.add(models.Project(id=p_id, name="Test Project", added="2024-01-01"))
    db.commit()
    return p_id


def _make_job(db: Session, pid: str, **overrides) -> models.Job:
    return queue_job(db, pid, "nmap", "test job", connector_key="nmap", operation="scan",
                     request_json=overrides.get("request_json", {}))


# ── supports_queued_execution ─────────────────────────────────────────


class TestSupportsQueuedExecution:
    def test_known_pairs(self):
        assert supports_queued_execution("nmap", "scan") is True
        assert supports_queued_execution("nuclei", "scan") is True
        assert supports_queued_execution("netexec", "scan") is True
        assert supports_queued_execution("attacker_ssh", "exec") is True
        assert supports_queued_execution("topology", "auto_build") is True
        assert supports_queued_execution("topology", "rebuild_layout") is True
        assert supports_queued_execution("httpx", "scan") is True
        assert supports_queued_execution("ffuf", "scan") is True
        assert supports_queued_execution("c2", "exec") is True
        assert supports_queued_execution("donpapi", "scan") is True

    def test_unknown_connector(self):
        assert supports_queued_execution("unknown_tool", "scan") is False

    def test_known_connector_wrong_operation(self):
        assert supports_queued_execution("nmap", "exec") is False
        assert supports_queued_execution("attacker_ssh", "scan") is False

    def test_empty_strings(self):
        assert supports_queued_execution("", "") is False


# ── handler registration ─────────────────────────────────────────────


class TestHandlerRegistration:
    def test_all_supported_pairs_have_handlers(self):
        for key in [
            ("nmap", "scan"),
            ("nuclei", "scan"),
            ("netexec", "scan"),
            ("attacker_ssh", "exec"),
            ("topology", "auto_build"),
            ("topology", "rebuild_layout"),
            ("httpx", "scan"),
            ("ffuf", "scan"),
            ("c2", "exec"),
            ("donpapi", "scan"),
        ]:
            assert key in _JOB_HANDLERS, f"Missing handler for {key}"

    def test_handler_is_callable(self):
        """Handlers may be sync or async — _dispatch_job awaits the result only
        when it's a coroutine, so both forms are valid. Just require callables."""
        for key, handler in _JOB_HANDLERS.items():
            assert callable(handler), f"Handler for {key} is not callable"


# ── run_queued_job dispatch ───────────────────────────────────────────


class TestRunQueuedJobDispatch:
    @pytest.mark.asyncio
    async def test_nonexistent_job_is_noop(self, db: Session):
        """Should not raise if job_id does not exist."""
        await run_queued_job("job_nonexistent")

    @pytest.mark.asyncio
    async def test_non_queued_job_is_noop(self, db: Session, pid: str):
        """A job already in 'done' status should not be dispatched."""
        job = queue_job(db, pid, "nmap", "done job", connector_key="nmap", operation="scan")
        finish_job(db, job, status="done", output="ok")
        await run_queued_job(job.id)
        db.refresh(job)
        assert job.status == "done"

    @pytest.mark.asyncio
    async def test_unsupported_connector_fails_gracefully(self, db: Session, pid: str):
        """A job with an unsupported (connector, op) pair should be marked failed."""
        job = queue_job(
            db, pid, "custom", "unsupported",
            connector_key="custom_tool",
            operation="do_thing",
            request_json={},
        )
        await run_queued_job(job.id)
        db.refresh(job)
        assert job.status == "failed"
        assert "not supported" in (job.error_output or "").lower()


# ── _nmap_upsert_host ────────────────────────────────────────────────


class TestNmapUpsertHost:
    def test_creates_new_host(self, db: Session, pid: str):
        host_data = {
            "ip": "10.0.0.1",
            "hostname": "web01",
            "os": "Linux",
            "ports": ["80/tcp", "443/tcp"],
            "services": ["http", "https"],
        }
        host, created = _nmap_upsert_host(db, pid, host_data)
        assert created is True
        assert host.ip == "10.0.0.1"
        assert host.hostname == "web01"
        assert host.status == "up"
        assert "nmap" in (host.tags or [])
        assert host.import_source == "nmap"

    def test_updates_existing_host(self, db: Session, pid: str):
        # Create initial host
        db.add(models.Host(
            id=new_id("hst"), pid=pid, ip="10.0.0.1",
            hostname="", os="", status="alive",
            ports=["22/tcp"], services=["ssh"],
        ))
        db.commit()

        host_data = {
            "ip": "10.0.0.1",
            "hostname": "web01",
            "os": "Linux",
            "ports": ["80/tcp"],
            "services": ["http"],
        }
        host, created = _nmap_upsert_host(db, pid, host_data)
        assert created is False
        assert host.hostname == "web01"
        assert set(host.ports) == {"22/tcp", "80/tcp"}
        assert set(host.services) == {"ssh", "http"}
        assert host.status == "up"

    def test_does_not_overwrite_hostname(self, db: Session, pid: str):
        db.add(models.Host(
            id=new_id("hst"), pid=pid, ip="10.0.0.2",
            hostname="original", os="", status="alive",
            ports=[], services=[],
        ))
        db.commit()

        host_data = {"ip": "10.0.0.2", "hostname": "new", "os": "", "ports": [], "services": []}
        host, created = _nmap_upsert_host(db, pid, host_data)
        assert created is False
        assert host.hostname == "original"  # not overwritten

    def test_does_not_overwrite_os(self, db: Session, pid: str):
        db.add(models.Host(
            id=new_id("hst"), pid=pid, ip="10.0.0.3",
            hostname="", os="Windows", status="alive",
            ports=[], services=[],
        ))
        db.commit()

        host_data = {"ip": "10.0.0.3", "hostname": "", "os": "Linux", "ports": [], "services": []}
        host, created = _nmap_upsert_host(db, pid, host_data)
        assert created is False
        assert host.os == "Windows"

    def test_empty_ports_no_crash(self, db: Session, pid: str):
        host_data = {"ip": "10.0.0.4", "hostname": "", "os": "", "ports": [], "services": []}
        host, created = _nmap_upsert_host(db, pid, host_data)
        assert created is True
        assert host.ports == []


# ── _cme_upsert_host ──────────────────────────────────────────────────


class TestCmeUpsertHost:
    def test_creates_new_host(self, db: Session, pid: str):
        h = {"ip": "192.168.1.10", "hostname": "DC01", "ports": ["445/tcp"], "services": ["smb"]}
        host, created = _cme_upsert_host(db, pid, h)
        assert created is True
        assert host.ip == "192.168.1.10"
        assert host.os == "Windows"
        assert "cme" in (host.tags or [])

    def test_updates_existing_host(self, db: Session, pid: str):
        db.add(models.Host(
            id=new_id("hst"), pid=pid, ip="192.168.1.10",
            hostname="", os="Linux", status="alive",
            ports=["22/tcp"], services=["ssh"],
        ))
        db.commit()

        h = {"ip": "192.168.1.10", "hostname": "DC01", "ports": ["445/tcp"], "services": ["smb"]}
        host, created = _cme_upsert_host(db, pid, h)
        assert created is False
        assert host.hostname == "DC01"
        assert set(host.ports) == {"22/tcp", "445/tcp"}


# ── _cme_upsert_cred ──────────────────────────────────────────────────


class TestCmeUpsertCred:
    def test_creates_new_cred(self, db: Session, pid: str):
        c = {"username": "admin", "secret": "P@ss123", "type": "plain", "service": "smb"}
        cred, created = _cme_upsert_cred(db, pid, c, "CORP", set())
        assert created is True
        assert cred.username == "admin"
        assert cred.domain == "CORP"
        assert "cme" in (cred.tags or [])

    def test_skips_duplicate_by_username_service(self, db: Session, pid: str):
        existing_keys = {("admin", "smb")}
        c = {"username": "admin", "secret": "other", "type": "plain", "service": "smb"}
        cred, created = _cme_upsert_cred(db, pid, c, "CORP", existing_keys)
        assert created is False
        assert cred is None

    def test_same_user_different_service_creates(self, db: Session, pid: str):
        existing_keys = {("admin", "smb")}
        c = {"username": "admin", "secret": "P@ss", "type": "plain", "service": "winrm"}
        cred, created = _cme_upsert_cred(db, pid, c, "CORP", existing_keys)
        assert created is True
        assert cred.service == "winrm"


# ── _cme_build_auth ───────────────────────────────────────────────────


class TestCmeBuildAuth:
    def test_hash_auth(self):
        payload = {"username": "admin", "hash": "AADM123"}
        result = _cme_build_auth(payload)
        assert "-H 'AADM123'" in result
        assert "-u 'admin'" in result

    def test_password_auth(self):
        payload = {"username": "admin", "password": "secret"}  # NOSONAR
        result = _cme_build_auth(payload)
        assert "-u 'admin'" in result
        assert "-p 'secret'" in result

    def test_username_only(self):
        payload = {"username": "guest"}
        result = _cme_build_auth(payload)
        assert "-u 'guest'" in result
        assert "-p " not in result
        assert "-H " not in result

    def test_no_auth(self):
        result = _cme_build_auth({})
        assert result == ""

    def test_hash_takes_priority_over_password(self):
        payload = {"username": "admin", "password": "secret", "hash": "AADM123"}  # NOSONAR
        result = _cme_build_auth(payload)
        assert "-H 'AADM123'" in result
        assert "-p " not in result


# ── _cme_process_hosts / _cme_process_creds ───────────────────────────


class TestCmeProcessHelpers:
    def test_process_hosts_creates_and_discovers_domains(self, db: Session, pid: str):
        hosts = [
            {"ip": "10.0.0.1", "hostname": "DC01", "domain": "corp.local", "ports": [], "services": []},
            {"ip": "10.0.0.2", "hostname": "WS01", "domain": "", "ports": [], "services": []},
        ]
        host_objects, domains, created = _cme_process_hosts(db, pid, hosts)
        assert created == 2
        assert len(host_objects) == 2
        assert domains["10.0.0.1"] == "corp.local"
        assert "10.0.0.2" not in domains

    def test_process_creds_deduplicates(self, db: Session, pid: str):
        creds = [
            {"username": "admin", "secret": "pass1", "type": "plain", "service": "smb"},
            {"username": "admin", "secret": "pass2", "type": "plain", "service": "smb"},
            {"username": "guest", "secret": "", "type": "plain", "service": "smb"},
        ]
        cred_objects, created = _cme_process_creds(db, pid, creds, "CORP", set())
        assert created == 2  # first admin + guest; second admin skipped


# ── _ffuf_severity ────────────────────────────────────────────────────


class TestFfufSeverity:
    def test_default_info(self):
        assert _ffuf_severity(403, "/normal") == "info"

    def test_200_is_low(self):
        assert _ffuf_severity(200, "/page") == "low"

    def test_204_is_low(self):
        assert _ffuf_severity(204, "/page") == "low"

    def test_admin_path_is_medium(self):
        assert _ffuf_severity(200, "/admin") == "medium"

    def test_env_file_is_medium(self):
        assert _ffuf_severity(200, "/.env") == "medium"

    def test_case_insensitive_path(self):
        assert _ffuf_severity(200, "/ADMIN") == "medium"

    def test_backup_keyword(self):
        assert _ffuf_severity(200, "/backup.zip") == "medium"

    def test_secret_keyword(self):
        assert _ffuf_severity(200, "/secret_data") == "medium"

    def test_config_keyword(self):
        assert _ffuf_severity(200, "/config.json") == "medium"

    def test_passwd_keyword(self):
        assert _ffuf_severity(200, "/etc/passwd") == "medium"


# ── _parse_c2_exec_payload ────────────────────────────────────────────


class TestParseC2ExecPayload:
    def test_defaults(self, db: Session, pid: str):
        job = _make_job(db, pid, request_json={})
        p = _parse_c2_exec_payload(job)
        assert p["mode"] == "command"
        assert p["wait_for_output"] is True
        assert p["timeout_seconds"] == 12
        assert p["credential_source"] == "rootnotes"

    def test_bof_mode_fallback_title(self, db: Session, pid: str):
        """When no explicit title, BOF mode generates a default title."""
        job = queue_job(
            db, pid, "c2", "",
            connector_key="c2", operation="exec",
            request_json={"mode": "bof"},
        )
        p = _parse_c2_exec_payload(job)
        assert p["mode"] == "bof"
        assert "BOF" in p["title"]

    def test_bof_mode_keeps_job_title(self, db: Session, pid: str):
        """When job has a title, it takes priority over the mode-based default."""
        job = _make_job(db, pid, request_json={"mode": "bof"})
        p = _parse_c2_exec_payload(job)
        assert p["mode"] == "bof"
        # job.title = "test job" → takes precedence over "Adaptix BOF"
        assert p["title"] == "test job"

    def test_custom_title(self, db: Session, pid: str):
        job = _make_job(db, pid, request_json={"title": "Custom Task"})
        p = _parse_c2_exec_payload(job)
        assert p["title"] == "Custom Task"

    def test_strips_whitespace(self, db: Session, pid: str):
        job = _make_job(db, pid, request_json={
            "integration_id": "  int1  ",
            "agent_id": " ag1 ",
            "commandline": " whoami ",
        })
        p = _parse_c2_exec_payload(job)
        assert p["integration_id"] == "int1"
        assert p["agent_id"] == "ag1"
        assert p["commandline"] == "whoami"


# ── _parse_donpapi_payload ────────────────────────────────────────────


class TestParseDonpapiPayload:
    def test_defaults(self, db: Session, pid: str):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1"})
        p = _parse_donpapi_payload(job)
        assert p["target"] == "10.0.0.1"
        assert p["fetch_loot"] is True
        assert p["timeout_seconds"] == 600
        assert p["output_dir"].startswith("/data/uploads/donpapi_")

    def test_custom_timeout(self, db: Session, pid: str):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1", "timeout_seconds": 300})
        p = _parse_donpapi_payload(job)
        assert p["timeout_seconds"] == 300

    def test_target_from_job_target(self, db: Session, pid: str):
        job = queue_job(
            db, pid, "donpapi", "dp test",
            connector_key="donpapi", operation="scan",
            target="10.0.0.5",
            request_json={},
        )
        p = _parse_donpapi_payload(job)
        assert p["target"] == "10.0.0.5"


# ── _donpapi_resolve_cred ─────────────────────────────────────────────


class TestDonpapiResolveCred:
    def test_inline_username_password(self):
        u, d, pw, nh, err = _donpapi_resolve_cred(
            None, "", "", "admin", "corp.local", "P@ss123", ""
        )
        assert err is None
        assert u == "admin"
        assert pw == "P@ss123"

    def test_inline_nthash(self):
        u, d, pw, nh, err = _donpapi_resolve_cred(
            None, "", "", "admin", "corp.local", "", "AADM123"
        )
        assert err is None
        assert nh == "AADM123"

    def test_missing_username(self):
        _, _, _, _, err = _donpapi_resolve_cred(
            None, "", "", "", "", "", ""
        )
        assert "username" in err

    def test_missing_secret(self):
        _, _, _, _, err = _donpapi_resolve_cred(
            None, "", "", "admin", "", "", ""
        )
        assert "password or nthash" in err

    def test_cred_from_db(self, db: Session, pid: str):
        """When cred_id is provided, resolve username/secret from DB."""
        from app.core.crypto import encrypt_str

        cred_id = new_id("crd")
        db.add(models.Cred(
            id=cred_id, pid=pid, username="svc_backup",
            secret=encrypt_str("BackupP@ss"), type="plain",
            service="smb", domain="CORP",
        ))
        db.commit()

        u, d, pw, nh, err = _donpapi_resolve_cred(
            db, pid, cred_id, "", "", "", ""
        )
        assert err is None
        assert u == "svc_backup"
        assert pw == "BackupP@ss"
        assert d == "CORP"

    def test_cred_id_not_found(self, db: Session, pid: str):
        _, _, _, _, err = _donpapi_resolve_cred(
            db, pid, "cred_nonexistent", "", "", "", ""
        )
        assert "not in project" in err

    def test_cred_hash_type_resolves_to_nthash(self, db: Session, pid: str):
        from app.core.crypto import encrypt_str

        cred_id = new_id("crd")
        db.add(models.Cred(
            id=cred_id, pid=pid, username="hashuser",
            secret=encrypt_str("AADMDEADBEEF"), type="ntlm",
            service="smb", domain="CORP",
        ))
        db.commit()

        u, d, pw, nh, err = _donpapi_resolve_cred(
            db, pid, cred_id, "", "", "", ""
        )
        assert err is None
        assert nh == "AADMDEADBEEF"


# ── CancellationToken integration with run_queued_job ─────────────────


class TestCancellationTokenIntegration:
    @pytest.mark.asyncio
    async def test_cancelled_token_skips_dispatch(self, db: Session, pid: str):
        """A pre-cancelled token should let the handler see cancellation
        and the job should end up in a non-running state."""
        from app.core.transport import CancellationToken

        job = queue_job(
            db, pid, "topology", "auto build",
            connector_key="topology", operation="auto_build",
            request_json={},
        )
        token = CancellationToken()
        token.cancel()

        # run_queued_job catches exceptions and marks failed
        await run_queued_job(job.id, cancel_token=token)
        db.refresh(job)
        # Job will be either failed or done depending on handler behavior
        # with a cancelled token — the key assertion is it's not stuck in "running"
        assert job.status in ("done", "failed", "cancelled")
