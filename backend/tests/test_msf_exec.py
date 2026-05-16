"""
Tests for Metasploit MSFRPC execution path (P1 of INTEGRATIONS_SCOPE).

The `_msf_execute` connector function is mocked at the httpx layer so we
don't need a real MSFRPC server. `perform_c2_command` is exercised
end-to-end for both supported C2 types to confirm dispatch by cfg.type.
"""
import pytest
from unittest.mock import AsyncMock, patch

from app import models
from app.core.utils import new_id
from app.routers.c2 import (
    _msf_execute, _msf_live_agents, _msf_fetch_session_tasks,
    perform_c2_command, SUPPORTED_EXEC_C2_TYPES, _LIVE_CONNECTORS,
)


# ── Supported types whitelist ────────────────────────────────────────

class TestSupportedTypes:
    def test_adaptix_and_msf_supported(self):
        assert "adaptix" in SUPPORTED_EXEC_C2_TYPES
        assert "metasploit" in SUPPORTED_EXEC_C2_TYPES

    @pytest.mark.asyncio
    async def test_unsupported_raises_in_perform(self, db):
        """perform_c2_command refuses unknown C2 type with a clear message."""
        project = models.Project(id=new_id("p"), name="t", added="2026-01-01")
        host = models.Host(id=new_id("hst"), pid=project.id, ip="10.0.0.1",
                           hostname="t1", os="", status="up", tags=[])
        db.add(project)
        db.flush()
        db.add(host)
        db.commit()

        cfg = {"id": "i1", "type": "cobalt_strike"}
        with pytest.raises(ValueError, match="not supported"):
            await perform_c2_command(
                db, project.id, host, cfg, "ag1", "whoami",
                "command", None, False, 5, "test",
            )


# ── _msf_execute mocked at httpx layer ───────────────────────────────

@pytest.fixture
def msf_cfg():
    return {
        "id": "msf1", "type": "metasploit",
        "url": "http://localhost:55553",
        "username": "msf", "password": "secret",
        "verify_ssl": False,
    }


@pytest.mark.asyncio
async def test_msf_execute_shell_session_returns_output(msf_cfg):
    """Shell session: shell_write succeeds, shell_read drains expected output.

    The mock checks the more-specific path (`shell_read`) before the generic
    `/sessions` listing so `/sessions/3/shell_read` doesn't accidentally
    return the session-list payload.
    """
    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, **kw):
            if "auth/login" in url:
                return AsyncMock(status_code=200, json=lambda: {"token": "TKN"})
            if "shell_write" in url:
                return AsyncMock(status_code=200, json=lambda: {"write_count": 7})
            return AsyncMock(status_code=404, json=lambda: {})
        async def get(self, url, **kw):
            if "shell_read" in url:
                return AsyncMock(status_code=200, json=lambda: {"data": "user1\n"})
            if url.endswith("/sessions"):
                return AsyncMock(status_code=200,
                                 json=lambda: {"sessions": {"3": {"type": "shell"}}})
            return AsyncMock(status_code=404, json=lambda: {})

    with patch("app.routers.c2.httpx.AsyncClient", return_value=FakeClient()):
        result = await _msf_execute(msf_cfg, "3", "whoami",
                                    wait_for_output=True, timeout_seconds=2)
    assert result["accepted"] is True
    assert result["session_type"] == "shell"
    assert "user1" in result.get("output", "")


@pytest.mark.asyncio
async def test_msf_execute_meterpreter_uses_meterpreter_endpoints(msf_cfg):
    """Meterpreter session: dispatches meterpreter_run_single / meterpreter_read."""
    called_paths = []

    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, **kw):
            called_paths.append(("POST", url))
            if "auth/login" in url:
                return AsyncMock(status_code=200, json=lambda: {"token": "T"})
            if "meterpreter_run_single" in url:
                return AsyncMock(status_code=200, json=lambda: {})
            return AsyncMock(status_code=404, json=lambda: {})
        async def get(self, url, **kw):
            called_paths.append(("GET", url))
            if "sessions" in url and "meterpreter_read" not in url:
                return AsyncMock(status_code=200,
                                 json=lambda: {"sessions": {"1": {"type": "meterpreter"}}})
            if "meterpreter_read" in url:
                return AsyncMock(status_code=200, json=lambda: {"data": "[meterp output]"})
            return AsyncMock(status_code=404, json=lambda: {})

    with patch("app.routers.c2.httpx.AsyncClient", return_value=FakeClient()):
        result = await _msf_execute(msf_cfg, "1", "getuid",
                                    wait_for_output=True, timeout_seconds=2)
    assert result["session_type"] == "meterpreter"
    assert any("meterpreter_run_single" in p[1] for p in called_paths)
    assert any("meterpreter_read" in p[1] for p in called_paths)
    assert "meterp output" in result.get("output", "")


@pytest.mark.asyncio
async def test_msf_execute_auth_failure_returns_error(msf_cfg):
    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, **kw):
            return AsyncMock(status_code=401, json=lambda: {"error": "bad creds"})
        async def get(self, url, **kw):
            return AsyncMock(status_code=200, json=lambda: {})

    with patch("app.routers.c2.httpx.AsyncClient", return_value=FakeClient()):
        result = await _msf_execute(msf_cfg, "1", "whoami",
                                    wait_for_output=False, timeout_seconds=2)
    assert result["accepted"] is False
    assert "auth failed" in result.get("error", "").lower()


@pytest.mark.asyncio
async def test_msf_execute_unknown_session_id(msf_cfg):
    class FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, **kw):
            return AsyncMock(status_code=200, json=lambda: {"token": "T"})
        async def get(self, url, **kw):
            return AsyncMock(status_code=200, json=lambda: {"sessions": {}})

    with patch("app.routers.c2.httpx.AsyncClient", return_value=FakeClient()):
        result = await _msf_execute(msf_cfg, "99", "whoami",
                                    wait_for_output=False, timeout_seconds=2)
    assert result["accepted"] is False
    assert "session 99" in result.get("error", "").lower()


# ── perform_c2_command dispatches by cfg.type ────────────────────────

@pytest.mark.asyncio
async def test_perform_dispatches_to_msf_when_cfg_type_metasploit(db, msf_cfg):
    project = models.Project(id=new_id("p"), name="t", added="2026-01-01")
    host = models.Host(id=new_id("hst"), pid=project.id, ip="10.0.0.5",
                       hostname="target", os="Windows", status="up", tags=[])
    db.add(project)
    db.flush()
    db.add(host)
    db.commit()

    with patch("app.routers.c2._msf_execute", new=AsyncMock(return_value={
        "accepted": True, "session_type": "shell",
        "output": "stub-output", "commandline": "whoami",
    })) as msf_mock, patch("app.routers.c2._adaptix_execute") as adaptix_mock:
        result, activity, rendered = await perform_c2_command(
            db, project.id, host, msf_cfg, "3", "whoami",
            "command", None, False, 5, "MSF whoami test",
        )
    msf_mock.assert_awaited_once()
    adaptix_mock.assert_not_called()
    assert result["output"] == "stub-output"
    # HostActivity persisted with MSF-specific summary
    assert "Metasploit" in (activity.summary or "")
    assert "session 3" in (activity.summary or "")


# ── _msf_live_agents — parity with Adaptix agent picker ─────────────

class TestMsfLiveAgents:
    def test_msf_registered_in_live_connectors(self):
        """The C2HostActionsPanel agent picker reads from _LIVE_CONNECTORS;
        MSF must be there so MSF sessions appear in the picker."""
        assert "metasploit" in _LIVE_CONNECTORS

    @pytest.mark.asyncio
    async def test_live_agents_returns_sessions_in_adaptix_shape(self, msf_cfg):
        """Returned dicts must carry ip / agent_id / username / os / alive — same
        fields the picker UI reads from Adaptix agents."""
        class FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, **kw):
                return AsyncMock(status_code=200, json=lambda: {"token": "TKN"})
            async def get(self, url, **kw):
                if "/sessions" in url:
                    return AsyncMock(status_code=200, json=lambda: {"sessions": {
                        "2": {
                            "type": "meterpreter", "info": "NT AUTHORITY\\SYSTEM @ DC01",
                            "platform": "windows/x64", "arch": "x64",
                            "tunnel_peer": "10.0.0.10:49152",
                        },
                        "5": {
                            "type": "shell", "info": "root @ webserver",
                            "platform": "linux/x64",
                            "tunnel_peer": "10.0.0.20:4444",
                        },
                    }})
                return AsyncMock(status_code=404, json=lambda: {})

        with patch("app.routers.c2.httpx.AsyncClient", return_value=FakeClient()):
            agents = await _msf_live_agents(msf_cfg)

        assert len(agents) == 2
        meterp = next(a for a in agents if a["agent_id"] == "2")
        assert meterp["ip"] == "10.0.0.10"
        assert meterp["username"] == "NT AUTHORITY\\SYSTEM"
        assert meterp["hostname"] == "DC01"
        assert meterp["os"] == "Windows"
        assert meterp["session_type"] == "meterpreter"
        assert meterp["alive"] is True

        shell = next(a for a in agents if a["agent_id"] == "5")
        assert shell["ip"] == "10.0.0.20"
        assert shell["username"] == "root"
        assert shell["hostname"] == "webserver"
        assert shell["os"] == "Linux"
        assert shell["session_type"] == "shell"

    @pytest.mark.asyncio
    async def test_live_agents_returns_empty_on_auth_failure(self, msf_cfg):
        class FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, **kw):
                return AsyncMock(status_code=401, json=lambda: {})
            async def get(self, url, **kw):
                return AsyncMock(status_code=200, json=lambda: {})

        with patch("app.routers.c2.httpx.AsyncClient", return_value=FakeClient()):
            agents = await _msf_live_agents(msf_cfg)
        assert agents == []


# ── _msf_fetch_session_tasks — task history parity ──────────────────

class TestMsfSessionTasks:
    @pytest.mark.asyncio
    async def test_returns_meta_row_plus_pending_buffer(self, msf_cfg):
        class FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, **kw):
                return AsyncMock(status_code=200, json=lambda: {"token": "T"})
            async def get(self, url, **kw):
                if url.endswith("/sessions"):
                    return AsyncMock(status_code=200, json=lambda: {"sessions": {
                        "1": {"type": "shell", "info": "root @ box", "session_host": "10.0.0.5"},
                    }})
                if "shell_read" in url:
                    return AsyncMock(status_code=200, json=lambda: {"data": "ls -la\n"})
                return AsyncMock(status_code=404, json=lambda: {})

        with patch("app.routers.c2.httpx.AsyncClient", return_value=FakeClient()):
            items = await _msf_fetch_session_tasks(msf_cfg, "1", limit=10)

        assert len(items) == 2
        meta, buffer = items
        assert meta["msg_type"] == "meta"
        assert meta["user"] == "root"
        assert meta["computer"] == "box"
        assert meta["raw"]["session_type"] == "shell"
        assert buffer["msg_type"] == "buffer"
        assert "ls -la" in buffer["text"]

    @pytest.mark.asyncio
    async def test_unknown_session_returns_empty(self, msf_cfg):
        class FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def post(self, url, **kw):
                return AsyncMock(status_code=200, json=lambda: {"token": "T"})
            async def get(self, url, **kw):
                return AsyncMock(status_code=200, json=lambda: {"sessions": {}})

        with patch("app.routers.c2.httpx.AsyncClient", return_value=FakeClient()):
            items = await _msf_fetch_session_tasks(msf_cfg, "999")
        assert items == []


@pytest.mark.asyncio
async def test_perform_dispatches_to_adaptix_when_cfg_type_adaptix(db):
    project = models.Project(id=new_id("p"), name="t", added="2026-01-01")
    host = models.Host(id=new_id("hst"), pid=project.id, ip="10.0.0.6",
                       hostname="target", os="Windows", status="up", tags=[])
    db.add(project)
    db.flush()
    db.add(host)
    db.commit()

    adaptix_cfg = {"id": "ad1", "type": "adaptix", "url": "http://x", "endpoint": "/endpoint"}
    with patch("app.routers.c2._adaptix_execute", new=AsyncMock(return_value={
        "accepted": True, "output": "stub-adaptix", "commandline": "ipconfig",
    })) as adaptix_mock, patch("app.routers.c2._msf_execute") as msf_mock:
        result, activity, _ = await perform_c2_command(
            db, project.id, host, adaptix_cfg, "ag1", "ipconfig",
            "command", None, False, 5, "Adaptix test",
        )
    adaptix_mock.assert_awaited_once()
    msf_mock.assert_not_called()
    assert result["output"] == "stub-adaptix"
    assert "Adaptix" in (activity.summary or "")
