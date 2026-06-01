"""Tests for app.core.job_runner — handlers, pure helpers, dispatch."""

import asyncio
import pytest
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

from sqlalchemy.orm import Session

from app import models
from app.core.job_runner import (
    _JOB_HANDLERS,
    _c2_exec_resolve,
    _dispatch_job,
    _donpapi_resolve_cred,
    _parse_c2_exec_payload,
    _parse_donpapi_payload,
    _resolve_cred_from_db,
    _resolve_exec_job_connection,
    _run_c2_exec_job,
    _run_cme_job,
    _run_donpapi_job,
    _run_exec_job,
    _run_ffuf_job,
    _run_httpx_job,
    _run_nmap_job,
    _run_nuclei_job,
    _run_topology_auto_build_job,
    _run_topology_rebuild_job,
    run_queued_job,
    schedule_job_run,
    supports_queued_execution,
)
from app.core.job_tracker import finish_job, mark_job_running, queue_job
from app.core.transport import CancellationToken
from app.core.utils import new_id


@pytest.fixture()
def pid(db: Session) -> str:
    p_id = new_id("prj")
    db.add(models.Project(id=p_id, name="Test Project", added="2024-01-01"))
    db.commit()
    return p_id


def _make_job(db, pid, connector_key="nmap", operation="scan", **kw):
    return queue_job(
        db, pid, kw.get("job_type", connector_key), kw.get("title", kw.get("job_title", "test")),
        connector_key=connector_key, operation=operation,
        target=kw.get("target", ""),
        request_json=kw.get("request_json", {}),
        command=kw.get("command", ""),
        created_by=kw.get("created_by", "tester"),
    )


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

    def test_unknown(self):
        assert supports_queued_execution("foo", "bar") is False

    def test_empty(self):
        assert supports_queued_execution("", "") is False


class TestScheduleJobRun:
    @patch("app.core.worker_pool.get_pool")
    def test_submits_to_pool(self, mock_get_pool):
        mock_pool = MagicMock()
        mock_get_pool.return_value = mock_pool
        schedule_job_run("job1", pid="p1", priority=5)
        mock_pool.submit.assert_called_once_with("job1", pid="p1", priority=5)


class TestRunQueuedJob:
    @pytest.mark.asyncio
    @patch("app.core.job_runner.SessionLocal")
    async def test_nonexistent_job(self, mock_sl):
        mock_session = MagicMock()
        mock_sl.return_value = mock_session
        mock_session.query.return_value.filter.return_value.first.return_value = None
        await run_queued_job("job_nonexistent")

    @pytest.mark.asyncio
    @patch("app.core.job_runner.SessionLocal")
    async def test_non_queued_job_is_noop(self, mock_sl, db, pid):
        job = _make_job(db, pid)
        finish_job(db, job, status="done", output="ok")
        mock_session = MagicMock()
        mock_sl.return_value = mock_session
        mock_session.query.return_value.filter.return_value.first.return_value = job
        await run_queued_job(job.id)

    @pytest.mark.asyncio
    @patch("app.core.job_runner.SessionLocal")
    async def test_unsupported_connector_fails(self, mock_sl, db, pid):
        job = _make_job(db, pid, connector_key="custom_tool", operation="do_thing")
        mock_session = MagicMock()
        mock_sl.return_value = mock_session
        mock_session.query.return_value.filter.return_value.first.side_effect = [job, job]
        await run_queued_job(job.id)

    @pytest.mark.asyncio
    @patch("app.core.job_runner.apply_writeback")
    @patch("app.core.job_runner._dispatch_job", new_callable=AsyncMock)
    @patch("app.core.job_runner.SessionLocal")
    async def test_writeback_called(self, mock_sl, mock_dispatch, mock_wb, db, pid):
        job = _make_job(db, pid)
        job.result_json = {"hosts_found": 3}
        mock_session = MagicMock()
        mock_sl.return_value = mock_session
        mock_session.query.return_value.filter.return_value.first.side_effect = [job, job]
        mock_session.refresh = MagicMock()
        await run_queued_job(job.id)
        mock_wb.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.core.job_runner._dispatch_job", new_callable=AsyncMock, side_effect=RuntimeError("boom"))
    @patch("app.core.job_runner.SessionLocal")
    async def test_exception_marks_failed(self, mock_sl, mock_dispatch, db, pid):
        job = _make_job(db, pid)
        mock_session = MagicMock()
        mock_sl.return_value = mock_session
        mock_session.query.return_value.filter.return_value.first.side_effect = [job, job]
        await run_queued_job(job.id)


class TestDispatchJob:
    @pytest.mark.asyncio
    async def test_calls_handler(self, db, pid):
        job = _make_job(db, pid)
        handler = AsyncMock()
        token = CancellationToken()
        with patch.dict(_JOB_HANDLERS, {("nmap", "scan"): handler}):
            await _dispatch_job(db, job, token)
        handler.assert_called_once_with(db, job, token)

    @pytest.mark.asyncio
    async def test_missing_handler_fails_job(self, db, pid):
        job = _make_job(db, pid, connector_key="unknown", operation="unknown")
        token = CancellationToken()
        with patch.dict(_JOB_HANDLERS, {}, clear=True):
            await _dispatch_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "not supported" in (job.error_output or "").lower()

    @pytest.mark.asyncio
    async def test_sync_handler(self, db, pid):
        job = _make_job(db, pid, connector_key="topology", operation="auto_build")
        token = CancellationToken()
        handler = MagicMock(return_value=None)
        with patch.dict(_JOB_HANDLERS, {("topology", "auto_build"): handler}):
            await _dispatch_job(db, job, token)
        handler.assert_called_once()


class TestParseC2ExecPayload:
    def test_defaults(self, db, pid):
        job = _make_job(db, pid)
        p = _parse_c2_exec_payload(job)
        assert p["mode"] == "command"
        assert p["wait_for_output"] is True
        assert p["timeout_seconds"] == 12
        assert p["credential_source"] == "rootnotes"

    def test_bof_mode_title(self, db, pid):
        job = _make_job(db, pid, request_json={"mode": "bof"}, job_title="")
        p = _parse_c2_exec_payload(job)
        assert p["mode"] == "bof"
        assert "BOF" in p["title"]

    def test_custom_title(self, db, pid):
        job = _make_job(db, pid, request_json={"title": "My Task"})
        p = _parse_c2_exec_payload(job)
        assert p["title"] == "My Task"

    def test_strips_whitespace(self, db, pid):
        job = _make_job(db, pid, request_json={
            "integration_id": "  int1  ",
            "agent_id": " ag1 ",
            "commandline": " whoami ",
        })
        p = _parse_c2_exec_payload(job)
        assert p["integration_id"] == "int1"
        assert p["agent_id"] == "ag1"
        assert p["commandline"] == "whoami"

    def test_custom_timeout(self, db, pid):
        job = _make_job(db, pid, request_json={"timeout_seconds": 30})
        p = _parse_c2_exec_payload(job)
        assert p["timeout_seconds"] == 30

    def test_wait_for_output_false(self, db, pid):
        job = _make_job(db, pid, request_json={"wait_for_output": False})
        p = _parse_c2_exec_payload(job)
        assert p["wait_for_output"] is False

    def test_payload_title_overrides_job_title(self, db, pid):
        job = _make_job(db, pid, request_json={"title": "Snippet"})
        p = _parse_c2_exec_payload(job)
        assert p["title"] == "Snippet"

    def test_commandline_from_job(self, db, pid):
        job = _make_job(db, pid, command="whoami.exe", request_json={})
        p = _parse_c2_exec_payload(job)
        assert p["commandline"] == "whoami.exe"


class TestParseDonpapiPayload:
    def test_defaults(self, db, pid):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1"})
        p = _parse_donpapi_payload(job)
        assert p["target"] == "10.0.0.1"
        assert p["fetch_loot"] is True
        assert p["timeout_seconds"] == 600

    def test_target_from_job(self, db, pid):
        job = _make_job(db, pid, target="10.0.0.5", request_json={})
        p = _parse_donpapi_payload(job)
        assert p["target"] == "10.0.0.5"

    def test_custom_timeout(self, db, pid):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1", "timeout_seconds": 300})
        p = _parse_donpapi_payload(job)
        assert p["timeout_seconds"] == 300

    def test_output_dir_default(self, db, pid):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1"})
        p = _parse_donpapi_payload(job)
        assert "donpapi_" in p["output_dir"]

    def test_custom_output_dir(self, db, pid):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1", "output_dir": "/tmp/custom"})
        p = _parse_donpapi_payload(job)
        assert p["output_dir"] == "/tmp/custom"


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
        _, _, _, _, err = _donpapi_resolve_cred(None, "", "", "", "", "", "")
        assert "username" in err

    def test_missing_secret(self):
        _, _, _, _, err = _donpapi_resolve_cred(None, "", "", "admin", "", "", "")
        assert "password or nthash" in err

    def test_cred_id_not_found(self, db, pid):
        _, _, _, _, err = _donpapi_resolve_cred(db, pid, "cred_nonexistent", "", "", "", "")
        assert "not in project" in err

    def test_cred_from_db(self, db, pid):
        from app.core.crypto import encrypt_str
        cred_id = new_id("crd")
        db.add(models.Cred(
            id=cred_id, pid=pid, username="svc_backup",
            secret=encrypt_str("BackupP@ss"), type="plain",
            service="smb", domain="CORP",
        ))
        db.commit()
        u, d, pw, nh, err = _donpapi_resolve_cred(db, pid, cred_id, "", "", "", "")
        assert err is None
        assert u == "svc_backup"
        assert pw == "BackupP@ss"
        assert d == "CORP"

    def test_cred_hash_type(self, db, pid):
        from app.core.crypto import encrypt_str
        cred_id = new_id("crd")
        db.add(models.Cred(
            id=cred_id, pid=pid, username="hashuser",
            secret=encrypt_str("AADMDEADBEEF"), type="ntlm",
            service="smb", domain="CORP",
        ))
        db.commit()
        u, d, pw, nh, err = _donpapi_resolve_cred(db, pid, cred_id, "", "", "", "")
        assert err is None
        assert nh == "AADMDEADBEEF"


class TestResolveCredFromDb:
    def test_not_found(self, db, pid):
        u, d, pw, nh, err = _resolve_cred_from_db(db, pid, "bad_id", "", "", "", "")
        assert "not in project" in err

    def test_fills_username(self, db, pid):
        from app.core.crypto import encrypt_str
        cred_id = new_id("crd")
        db.add(models.Cred(
            id=cred_id, pid=pid, username="admin",
            secret=encrypt_str("pass123"), type="plain",
            service="smb",
        ))
        db.commit()
        u, d, pw, nh, err = _resolve_cred_from_db(db, pid, cred_id, "", "", "", "")
        assert err is None
        assert u == "admin"
        assert pw == "pass123"

    def test_preserves_inline_overrides(self, db, pid):
        from app.core.crypto import encrypt_str
        cred_id = new_id("crd")
        db.add(models.Cred(
            id=cred_id, pid=pid, username="admin",
            secret=encrypt_str("db_pass"), type="plain",
            service="smb", domain="DBDOM",
        ))
        db.commit()
        u, d, pw, nh, err = _resolve_cred_from_db(
            db, pid, cred_id, "override_user", "override_dom", "inline_pw", ""
        )
        assert err is None
        assert u == "override_user"
        assert d == "override_dom"
        assert pw == "inline_pw"


class TestResolveExecJobConnection:
    @patch("app.core.attacker_transport.resolve_exec_connection")
    def test_success(self, mock_resolve, db, pid):
        from app.core.attacker_transport import ResolvedConnection
        mock_ssh = {"host": "10.0.0.1", "port": 22}
        mock_host = MagicMock()
        mock_cred = MagicMock()
        mock_resolve.return_value = ResolvedConnection(
            ssh_config=mock_ssh, attacker_host=mock_host, resolved_cred=mock_cred
        )
        job = _make_job(db, pid, connector_key="attacker_ssh", operation="exec")
        result, err = _resolve_exec_job_connection(db, job, {})
        assert err is None
        assert result is not None

    @patch("app.core.attacker_transport.resolve_exec_connection", side_effect=Exception("no route"))
    def test_failure(self, mock_resolve, db, pid):
        job = _make_job(db, pid, connector_key="attacker_ssh", operation="exec")
        result, err = _resolve_exec_job_connection(db, job, {})
        assert result is None
        assert "no route" in err


class TestC2ExecResolve:
    @patch("app.routers.c2._visible_integrations_for_pid", return_value=[])
    @patch("app.routers.c2._load_integrations", return_value=[])
    def test_missing_fields(self, mock_load, mock_vis, db, pid):
        host, cfg, err = _c2_exec_resolve(db, pid, "", "", "", "")
        assert err is not None
        assert "requires" in err

    @patch("app.routers.c2._visible_integrations_for_pid", return_value=[])
    @patch("app.routers.c2._load_integrations", return_value=[])
    def test_host_not_found(self, mock_load, mock_vis, db, pid):
        host, cfg, err = _c2_exec_resolve(db, pid, "int1", "ag1", "h_missing", "whoami")
        assert "not in project" in err

    @patch("app.routers.c2.SUPPORTED_EXEC_C2_TYPES", ["adaptix"])
    @patch("app.routers.c2._visible_integrations_for_pid", return_value=[
        {"id": "int1", "type": "other_framework"}
    ])
    @patch("app.routers.c2._load_integrations", return_value=[])
    def test_unsupported_type(self, mock_load, mock_vis, db, pid):
        h_id = new_id("hst")
        db.add(models.Host(id=h_id, pid=pid, ip="10.0.0.1"))
        db.commit()
        host, cfg, err = _c2_exec_resolve(db, pid, "int1", "ag1", h_id, "whoami")
        assert "supported only" in err.lower()

    @patch("app.routers.c2.SUPPORTED_EXEC_C2_TYPES", ["adaptix"])
    @patch("app.routers.c2._visible_integrations_for_pid", return_value=[
        {"id": "int1", "type": "adaptix"}
    ])
    @patch("app.routers.c2._load_integrations", return_value=[])
    def test_success(self, mock_load, mock_vis, db, pid):
        h_id = new_id("hst")
        db.add(models.Host(id=h_id, pid=pid, ip="10.0.0.1"))
        db.commit()
        host, cfg, err = _c2_exec_resolve(db, pid, "int1", "ag1", h_id, "whoami")
        assert err is None
        assert host is not None
        assert cfg is not None

    @patch("app.routers.c2._visible_integrations_for_pid", return_value=[])
    @patch("app.routers.c2._load_integrations", return_value=[])
    def test_integration_not_visible(self, mock_load, mock_vis, db, pid):
        h_id = new_id("hst")
        db.add(models.Host(id=h_id, pid=pid, ip="10.0.0.1"))
        db.commit()
        host, cfg, err = _c2_exec_resolve(db, pid, "int_missing", "ag1", h_id, "whoami")
        assert "not visible" in err


class TestRunNmapJob:
    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_nmap_xml", return_value=[])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    @patch("app.core.job_runner.bcast")
    async def test_success_empty(self, mock_bcast, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_nmap_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_missing_target(self, mock_ssh, mock_cfg, db, pid):
        job = _make_job(db, pid, request_json={})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_nmap_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "Missing target" in job.error_output

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_nmap_xml", return_value=[])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": True
    })
    async def test_cancelled(self, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_nmap_job(db, job, token)
        db.refresh(job)
        assert job.status == "cancelled"

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_nmap_xml", return_value=[
        {"ip": "10.0.0.1", "hostname": "web", "os": "Linux", "ports": ["80/tcp"], "services": ["http"]}
    ])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "<xml/>", "stderr": "", "cancelled": False
    })
    @patch("app.core.job_runner.bcast")
    async def test_with_hosts(self, mock_bcast, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_nmap_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"
        assert job.result_json["hosts_found"] == 1
        assert job.result_json["hosts_created"] == 1

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_nmap_xml", return_value=[])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": False, "stdout": "", "stderr": "err", "cancelled": False
    })
    async def test_ssh_failure(self, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, request_json={"target": "10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_nmap_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"


class TestRunNucleiJob:
    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_nuclei_jsonl", return_value=[])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_success_empty(self, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, request_json={"target": "http://10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_nuclei_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_missing_target(self, mock_ssh, mock_cfg, db, pid):
        job = _make_job(db, pid, request_json={})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_nuclei_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "Missing target" in job.error_output

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_nuclei_jsonl", return_value=[
        {"title": "XSS", "severity": "high", "description": "desc", "proof": "p", "cve": "CVE-2024-1"}
    ])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "jsonl", "stderr": "", "cancelled": False
    })
    @patch("app.core.events.bcast_batch", new_callable=AsyncMock)
    async def test_creates_finding(self, mock_bcast_batch, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, request_json={"target": "http://10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_nuclei_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"
        assert job.result_json["findings_created"] == 1

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_nuclei_jsonl", return_value=[
        {"title": "XSS", "severity": "high", "description": "desc", "proof": "p", "cve": ""}
    ])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "jsonl", "stderr": "", "cancelled": False
    })
    @patch("app.core.events.bcast_batch", new_callable=AsyncMock)
    async def test_skips_duplicate_finding(self, mock_bcast_batch, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, request_json={"target": "http://10.0.0.1"})
        mark_job_running(db, job)
        existing = models.Finding(
            id=new_id("fnd"), pid=pid, title="XSS", severity="high",
            description="", proof="", cve="", status="open", ts="2024-01-01 00:00",
        )
        db.add(existing)
        db.commit()
        token = CancellationToken()
        await _run_nuclei_job(db, job, token)
        db.refresh(job)
        assert job.result_json["findings_created"] == 0


class TestRunCmeJob:
    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_cme_output", return_value={"hosts": [], "creds": []})
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    @patch("app.core.events.bcast_batch", new_callable=AsyncMock)
    async def test_success_empty(self, mock_bcast_batch, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="netexec", operation="scan",
                        request_json={"target": "10.0.0.1", "protocol": "smb"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_cme_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_missing_target(self, mock_ssh, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="netexec", operation="scan", request_json={})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_cme_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_cme_output", return_value={
        "hosts": [{"ip": "10.0.0.1", "hostname": "DC", "domain": "corp", "ports": [], "services": []}],
        "creds": [{"username": "admin", "secret": "P@ss", "type": "plain", "service": "smb"}],
    })
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "cme_out", "stderr": "", "cancelled": False
    })
    @patch("app.core.events.bcast_batch", new_callable=AsyncMock)
    async def test_with_hosts_and_creds(self, mock_bcast_batch, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="netexec", operation="scan",
                        request_json={"target": "10.0.0.1", "protocol": "smb"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_cme_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"
        assert job.result_json["hosts_found"] == 1
        assert job.result_json["creds_found"] == 1

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_cme_output", return_value={"hosts": [], "creds": []})
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": True
    })
    async def test_cancelled(self, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="netexec", operation="scan",
                        request_json={"target": "10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_cme_job(db, job, token)
        db.refresh(job)
        assert job.status == "cancelled"


class TestRunExecJob:
    @pytest.mark.asyncio
    @patch("app.core.attacker_transport.resolve_exec_connection")
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "root", "stderr": "", "cancelled": False, "exit_code": 0
    })
    @patch("app.core.job_runner.bcast")
    async def test_success(self, mock_bcast, mock_ssh, mock_resolve, db, pid):
        h_id = new_id("hst")
        db.add(models.Host(id=h_id, pid=pid, ip="10.0.0.1", is_attacker=True))
        db.commit()
        from app.core.attacker_transport import ResolvedConnection
        host_obj = db.query(models.Host).get(h_id)
        mock_resolve.return_value = ResolvedConnection(
            ssh_config={"host": "10.0.0.1", "port": 22},
            attacker_host=host_obj,
            resolved_cred=None,
        )
        job = _make_job(db, pid, connector_key="attacker_ssh", operation="exec",
                        command="whoami", request_json={"command": "whoami"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_exec_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"

    @pytest.mark.asyncio
    @patch("app.core.attacker_transport.resolve_exec_connection", side_effect=Exception("no conn"))
    async def test_connection_failure(self, mock_resolve, db, pid):
        job = _make_job(db, pid, connector_key="attacker_ssh", operation="exec",
                        command="whoami", request_json={"command": "whoami"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_exec_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "no conn" in job.error_output

    @pytest.mark.asyncio
    @patch("app.core.attacker_transport.resolve_exec_connection")
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": True
    })
    @patch("app.core.job_runner.bcast")
    async def test_cancelled(self, mock_bcast, mock_ssh, mock_resolve, db, pid):
        h_id = new_id("hst")
        db.add(models.Host(id=h_id, pid=pid, ip="10.0.0.1", is_attacker=True))
        db.commit()
        from app.core.attacker_transport import ResolvedConnection
        host_obj = db.query(models.Host).get(h_id)
        mock_resolve.return_value = ResolvedConnection(
            ssh_config={"host": "10.0.0.1", "port": 22},
            attacker_host=host_obj,
            resolved_cred=None,
        )
        job = _make_job(db, pid, connector_key="attacker_ssh", operation="exec",
                        command="whoami", request_json={"command": "whoami"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_exec_job(db, job, token)
        db.refresh(job)
        assert job.status == "cancelled"


class TestRunHttpxJob:
    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_httpx_jsonl", return_value=[])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_success_empty(self, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="httpx", operation="scan",
                        request_json={"target": "http://10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_httpx_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_missing_target(self, mock_ssh, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="httpx", operation="scan", request_json={})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_httpx_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_httpx_jsonl", return_value=[
        {"host": "10.0.0.1", "url": "http://10.0.0.1", "status": 200, "title": "Home", "tech": ["nginx"], "port": "80/tcp"}
    ])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "jsonl", "stderr": "", "cancelled": False
    })
    @patch("app.core.job_runner.bcast")
    async def test_with_results(self, mock_bcast, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="httpx", operation="scan",
                        request_json={"target": "http://10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_httpx_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"
        assert job.result_json["urls_found"] == 1

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_httpx_jsonl", return_value=[])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": True
    })
    async def test_cancelled(self, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="httpx", operation="scan",
                        request_json={"target": "http://10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_httpx_job(db, job, token)
        db.refresh(job)
        assert job.status == "cancelled"


class TestRunFfufJob:
    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_ffuf_json", return_value=[])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_success_empty(self, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="ffuf", operation="scan",
                        request_json={"target_url": "http://10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_ffuf_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_missing_target_url(self, mock_ssh, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="ffuf", operation="scan", request_json={})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_ffuf_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "Missing target_url" in job.error_output

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_ffuf_json", return_value=[])
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": True
    })
    async def test_cancelled(self, mock_ssh, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="ffuf", operation="scan",
                        request_json={"target_url": "http://10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_ffuf_job(db, job, token)
        db.refresh(job)
        assert job.status == "cancelled"


class TestRunTopologyAutoBuildJob:
    @patch("app.routers.topology._run_auto_build", return_value={"ok": True, "nodes": 5})
    def test_success(self, mock_ab, db, pid):
        job = _make_job(db, pid, connector_key="topology", operation="auto_build")
        mark_job_running(db, job)
        token = CancellationToken()
        _run_topology_auto_build_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"

    @patch("app.routers.topology._run_auto_build", return_value={"ok": False, "error": "no hosts"})
    def test_failure(self, mock_ab, db, pid):
        job = _make_job(db, pid, connector_key="topology", operation="auto_build")
        mark_job_running(db, job)
        token = CancellationToken()
        _run_topology_auto_build_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "no hosts" in (job.error_output or "")

    @patch("app.routers.topology._run_auto_build", return_value={"ok": True})
    def test_with_request_json(self, mock_ab, db, pid):
        job = _make_job(db, pid, connector_key="topology", operation="auto_build",
                        request_json={"keep_manual_positions": False, "create_missing_networks": False})
        mark_job_running(db, job)
        token = CancellationToken()
        _run_topology_auto_build_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"


class TestRunTopologyRebuildJob:
    @patch("app.routers.topology.compute_layout", return_value=[
        {"id": "n1", "ip": "10.0.0.1", "x": 100, "y": 200}
    ])
    @patch("app.core.job_runner.get_edges", return_value=[])
    @patch("app.core.job_runner.get_nodes", return_value=[
        {"host_id": "h1", "ip": "10.0.0.1", "x": 0, "y": 0, "manually_positioned": False}
    ])
    @patch("app.core.job_runner.replace_nodes")
    @patch("app.core.job_runner.bcast")
    def test_success(self, mock_bcast, mock_replace, mock_nodes, mock_edges, mock_layout, db, pid):
        net_id = new_id("net")
        db.add(models.Network(id=net_id, pid=pid))
        h_id = new_id("hst")
        db.add(models.Host(id=h_id, pid=pid, ip="10.0.0.1", hostname="", os="", status="up"))
        db.commit()
        job = _make_job(db, pid, connector_key="topology", operation="rebuild_layout")
        mark_job_running(db, job)
        token = CancellationToken()
        _run_topology_rebuild_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"
        assert job.result_json["nodes_repositioned"] == 1

    @patch("app.core.job_runner.get_nodes", return_value=[])
    @patch("app.core.job_runner.get_edges", return_value=[])
    def test_no_network(self, mock_edges, mock_nodes, db, pid):
        job = _make_job(db, pid, connector_key="topology", operation="rebuild_layout")
        mark_job_running(db, job)
        token = CancellationToken()
        _run_topology_rebuild_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "No network" in (job.error_output or "")

    @patch("app.routers.topology.compute_layout", return_value=[])
    @patch("app.core.job_runner.get_edges", return_value=[])
    @patch("app.core.job_runner.get_nodes", return_value=[
        {"host_id": "h1", "ip": "10.0.0.1", "x": 50, "y": 50, "manually_positioned": True}
    ])
    @patch("app.core.job_runner.replace_nodes")
    @patch("app.core.job_runner.bcast")
    def test_keeps_manual_positions(self, mock_bcast, mock_replace, mock_nodes, mock_edges, mock_layout, db, pid):
        net_id = new_id("net")
        db.add(models.Network(id=net_id, pid=pid))
        h_id = new_id("hst")
        db.add(models.Host(id=h_id, pid=pid, ip="10.0.0.1", hostname="", os="", status="up"))
        db.commit()
        job = _make_job(db, pid, connector_key="topology", operation="rebuild_layout",
                        request_json={"keep_manual_positions": True})
        mark_job_running(db, job)
        token = CancellationToken()
        _run_topology_rebuild_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"


class TestRunC2ExecJob:
    @pytest.mark.asyncio
    @patch("app.core.job_runner._c2_exec_resolve")
    @patch("app.routers.c2.resolve_c2_cred", new_callable=AsyncMock, return_value=None)
    @patch("app.routers.c2.perform_c2_command", new_callable=AsyncMock, return_value=(
        {"output": "result"}, MagicMock(id="act1"), "whoami"
    ))
    async def test_success(self, mock_cmd, mock_cred, mock_resolve, db, pid):
        h_id = new_id("hst")
        db.add(models.Host(id=h_id, pid=pid, ip="10.0.0.1"))
        db.commit()
        mock_host = db.query(models.Host).get(h_id)
        mock_resolve.return_value = (mock_host, {"id": "int1", "type": "adaptix"}, None)
        job = _make_job(db, pid, connector_key="c2", operation="exec",
                        request_json={
                            "integration_id": "int1", "agent_id": "ag1",
                            "host_id": h_id, "commandline": "whoami",
                        })
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_c2_exec_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"

    @pytest.mark.asyncio
    @patch("app.core.job_runner._c2_exec_resolve")
    async def test_resolve_failure(self, mock_resolve, db, pid):
        mock_resolve.return_value = (None, None, "missing fields")
        job = _make_job(db, pid, connector_key="c2", operation="exec", request_json={})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_c2_exec_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "missing fields" in job.error_output

    @pytest.mark.asyncio
    @patch("app.core.job_runner._c2_exec_resolve")
    @patch("app.routers.c2.resolve_c2_cred", new_callable=AsyncMock, side_effect=Exception("cred err"))
    async def test_c2_exception(self, mock_cred, mock_resolve, db, pid):
        h_id = new_id("hst")
        db.add(models.Host(id=h_id, pid=pid, ip="10.0.0.1"))
        db.commit()
        mock_host = db.query(models.Host).get(h_id)
        mock_resolve.return_value = (mock_host, {"id": "int1", "type": "adaptix"}, None)
        job = _make_job(db, pid, connector_key="c2", operation="exec",
                        request_json={"integration_id": "int1", "agent_id": "ag1",
                                      "host_id": h_id, "commandline": "whoami"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_c2_exec_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "C2 execution failed" in job.error_output


class TestRunDonpapiJob:
    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_donpapi_stdout", return_value=[])
    @patch("app.routers.scans._donpapi_build_command", return_value="donpapi ...")
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    @patch("app.core.job_runner.donpapi_fetch_loot", new_callable=AsyncMock, return_value="")
    async def test_success_no_target_host(self, mock_loot, mock_ssh, mock_cmd, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="donpapi", operation="scan",
                        request_json={"target": "10.0.0.1", "username": "admin", "password": "pass"},
                        target="10.0.0.1")
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_donpapi_job(db, job, token)
        db.refresh(job)
        assert job.status == "done"

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_missing_target(self, mock_ssh, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="donpapi", operation="scan", request_json={})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_donpapi_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "Missing target" in job.error_output

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": False
    })
    async def test_missing_credentials(self, mock_ssh, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="donpapi", operation="scan",
                        request_json={"target": "10.0.0.1"})
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_donpapi_job(db, job, token)
        db.refresh(job)
        assert job.status == "failed"
        assert "username" in (job.error_output or "")

    @pytest.mark.asyncio
    @patch("app.routers.scans._get_ssh_config", return_value={})
    @patch("app.routers.scans._parse_donpapi_stdout", return_value=[])
    @patch("app.routers.scans._donpapi_build_command", return_value="donpapi ...")
    @patch("app.core.job_runner.run_ssh_command_cancellable", return_value={
        "ok": True, "stdout": "", "stderr": "", "cancelled": True
    })
    async def test_cancelled(self, mock_ssh, mock_cmd, mock_parse, mock_cfg, db, pid):
        job = _make_job(db, pid, connector_key="donpapi", operation="scan",
                        request_json={"target": "10.0.0.1", "username": "admin", "password": "pass"},
                        target="10.0.0.1")
        mark_job_running(db, job)
        token = CancellationToken()
        await _run_donpapi_job(db, job, token)
        db.refresh(job)
        assert job.status == "cancelled"


class TestHandlerRegistration:
    def test_all_handlers_registered(self):
        expected = [
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
        ]
        for key in expected:
            assert key in _JOB_HANDLERS, f"Missing handler for {key}"

    @pytest.mark.asyncio
    async def test_async_handlers_are_coroutines(self):
        import asyncio
        async_handlers = [
            ("nmap", "scan"), ("nuclei", "scan"), ("netexec", "scan"),
            ("attacker_ssh", "exec"), ("httpx", "scan"), ("ffuf", "scan"),
            ("c2", "exec"), ("donpapi", "scan"),
        ]
        for key in async_handlers:
            assert asyncio.iscoroutinefunction(_JOB_HANDLERS[key]), f"{key} is not async"
