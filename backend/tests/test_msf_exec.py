"""
Tests for Metasploit MSFRPC integration (msgpack RPC protocol).

The wire-format helpers (_msf_login / _msf_rpc) are mocked at the
function boundary rather than at the httpx layer — much cleaner than
hand-rolling msgpack-encoded HTTP responses.

Live verification against an actual msfrpcd is documented in
docs/modules/HANDS_ON.md under "Metasploit P1".
"""
import pytest
from unittest.mock import AsyncMock, patch

from app import models
from app.core.utils import new_id
from app.routers.c2 import (
    _msf_execute, _msf_live_agents, _msf_fetch_session_tasks,
    _msf_bytes_to_str, _msf_classify_session, _msf_session_id_key,
    perform_c2_command, SUPPORTED_EXEC_C2_TYPES, _LIVE_CONNECTORS,
)


# ── Helpers ─────────────────────────────────────────────────────────

class TestBytesToStrDecoder:
    def test_bytes_decoded(self):
        assert _msf_bytes_to_str(b"hello") == "hello"

    def test_nested_dict_keys_and_values(self):
        src = {b"key": b"val", b"int": 1}
        assert _msf_bytes_to_str(src) == {"key": "val", "int": 1}

    def test_nested_list(self):
        assert _msf_bytes_to_str([b"a", {b"k": b"v"}]) == ["a", {"k": "v"}]

    def test_passes_through_non_bytes(self):
        assert _msf_bytes_to_str(42) == 42
        assert _msf_bytes_to_str(None) is None


class TestSessionIdKey:
    def test_string_key_present(self):
        assert _msf_session_id_key("3", {"3": {}}) == "3"

    def test_int_key_when_string_passed(self):
        """MSFRPC returns session ids as ints; UI passes them as strings."""
        assert _msf_session_id_key("3", {3: {}}) == 3

    def test_missing(self):
        assert _msf_session_id_key("9", {1: {}, 2: {}}) is None


class TestSessionClassifier:
    def test_meterpreter_windows(self):
        ip, host, user, os_, type_ = _msf_classify_session({
            "type": "meterpreter", "info": "NT AUTHORITY\\SYSTEM @ DC01",
            "platform": "windows/x64", "tunnel_peer": "10.0.0.10:49152",
        })
        assert ip == "10.0.0.10"
        assert host == "DC01"
        assert user == "NT AUTHORITY\\SYSTEM"
        assert os_ == "Windows"
        assert type_ == "meterpreter"

    def test_shell_linux(self):
        ip, host, user, os_, type_ = _msf_classify_session({
            "type": "shell", "info": "root @ web",
            "platform": "linux/x64", "tunnel_peer": "10.0.0.20:4444",
        })
        assert ip == "10.0.0.20"
        assert user == "root"
        assert os_ == "Linux"
        assert type_ == "shell"

    def test_tunnel_peer_with_arrow(self):
        ip, *_ = _msf_classify_session({
            "tunnel_peer": "10.0.0.30:443 -> 10.0.0.99:4444",
            "platform": "windows", "info": "",
        })
        assert ip == "10.0.0.30"


# ── Supported types whitelist ────────────────────────────────────────

class TestSupportedTypes:
    def test_adaptix_and_msf_supported(self):
        assert "adaptix" in SUPPORTED_EXEC_C2_TYPES
        assert "metasploit" in SUPPORTED_EXEC_C2_TYPES

    @pytest.mark.asyncio
    async def test_unsupported_raises_in_perform(self, db):
        project = models.Project(id=new_id("p"), name="t", added="2026-01-01")
        host = models.Host(id=new_id("hst"), pid=project.id, ip="10.0.0.1",
                           hostname="t1", os="", status="up", tags=[])
        db.add(project)
        db.flush()
        db.add(host)
        db.commit()
        with pytest.raises(ValueError, match="not supported"):
            await perform_c2_command(
                db, project.id, host, {"id": "i1", "type": "cobalt_strike"},
                "ag1", "whoami", "command", None, False, 5, "test",
            )


# ── _msf_execute via mocked RPC ─────────────────────────────────────

@pytest.fixture
def msf_cfg():
    return {
        "id": "msf1", "type": "metasploit",
        "url": "http://localhost:55553",
        "username": "msf", "password": "secret",
        "verify_ssl": False,
    }


def _make_rpc_mock(*, sessions, write_method, write_response,
                   read_method, read_chunks):
    """
    Build a stateful AsyncMock side_effect that returns:
      - session.list → `sessions`
      - <write_method> → `write_response`
      - <read_method> → successive items from `read_chunks` (cycles)
    Other methods raise RuntimeError so tests fail loudly on unexpected
    calls.
    """
    read_iter = iter(read_chunks)
    async def _rpc(client, base, method, *args):
        if method == "session.list":
            return sessions
        if method == write_method:
            return write_response
        if method == read_method:
            try:
                return next(read_iter)
            except StopIteration:
                return {"data": ""}
        raise RuntimeError(f"unexpected RPC: {method}")
    return _rpc


@pytest.mark.asyncio
async def test_msf_execute_shell_session_returns_output(msf_cfg):
    sessions = {3: {"type": "shell", "info": "root @ box",
                    "tunnel_peer": "10.0.0.5:4444", "platform": "linux"}}
    rpc = _make_rpc_mock(
        sessions=sessions,
        write_method="session.shell_write", write_response={"write_count": 7},
        read_method="session.shell_read",
        read_chunks=[{"data": "user1\n"}],
    )
    with patch("app.routers.c2._msf_login", new=AsyncMock(return_value="TKN")), \
         patch("app.routers.c2._msf_rpc", new=AsyncMock(side_effect=rpc)):
        result = await _msf_execute(msf_cfg, "3", "whoami",
                                    wait_for_output=True, timeout_seconds=2)
    assert result["accepted"] is True
    assert result["session_type"] == "shell"
    assert "user1" in result.get("output", "")


@pytest.mark.asyncio
async def test_msf_execute_meterpreter_uses_meterpreter_endpoints(msf_cfg):
    sessions = {1: {"type": "meterpreter", "info": "SYSTEM @ DC01",
                    "platform": "windows", "tunnel_peer": "10.0.0.1:4444"}}
    called = []
    async def rpc(client, base, method, *args):
        called.append(method)
        if method == "session.list":
            return sessions
        if method == "session.meterpreter_run_single":
            return {"result": "success"}
        if method == "session.meterpreter_read":
            return {"data": "[meterp]"}
        raise RuntimeError(f"unexpected: {method}")
    with patch("app.routers.c2._msf_login", new=AsyncMock(return_value="TKN")), \
         patch("app.routers.c2._msf_rpc", new=AsyncMock(side_effect=rpc)):
        result = await _msf_execute(msf_cfg, "1", "getuid",
                                    wait_for_output=True, timeout_seconds=2)
    assert "session.meterpreter_run_single" in called
    assert "session.meterpreter_read" in called
    assert "session.shell_write" not in called
    assert result["session_type"] == "meterpreter"
    assert "[meterp]" in result.get("output", "")


@pytest.mark.asyncio
async def test_msf_execute_auth_failure_surfaces_error(msf_cfg):
    with patch("app.routers.c2._msf_login",
               new=AsyncMock(side_effect=RuntimeError("MSFRPC: Invalid User ID or Password"))):
        result = await _msf_execute(msf_cfg, "1", "whoami",
                                    wait_for_output=False, timeout_seconds=1)
    assert result["accepted"] is False
    assert "invalid user" in result.get("error", "").lower()


@pytest.mark.asyncio
async def test_msf_execute_unknown_session_id(msf_cfg):
    async def rpc(client, base, method, *args):
        if method == "session.list":
            return {}
        raise RuntimeError(f"unexpected: {method}")
    with patch("app.routers.c2._msf_login", new=AsyncMock(return_value="TKN")), \
         patch("app.routers.c2._msf_rpc", new=AsyncMock(side_effect=rpc)):
        result = await _msf_execute(msf_cfg, "99", "whoami",
                                    wait_for_output=False, timeout_seconds=1)
    assert result["accepted"] is False
    assert "session 99" in result.get("error", "").lower()


# ── _msf_live_agents ─────────────────────────────────────────────────

class TestMsfLiveAgents:
    def test_registered_in_live_connectors(self):
        assert "metasploit" in _LIVE_CONNECTORS

    @pytest.mark.asyncio
    async def test_returns_sessions_in_adaptix_shape(self, msf_cfg):
        sessions = {
            2: {"type": "meterpreter", "info": "NT AUTHORITY\\SYSTEM @ DC01",
                "platform": "windows/x64", "arch": "x64",
                "tunnel_peer": "10.0.0.10:49152"},
            5: {"type": "shell", "info": "root @ web",
                "platform": "linux/x64", "tunnel_peer": "10.0.0.20:4444"},
        }
        async def rpc(client, base, method, *args):
            return sessions if method == "session.list" else {}
        with patch("app.routers.c2._msf_login", new=AsyncMock(return_value="TKN")), \
             patch("app.routers.c2._msf_rpc", new=AsyncMock(side_effect=rpc)):
            agents = await _msf_live_agents(msf_cfg)
        assert len(agents) == 2
        meterp = next(a for a in agents if a["agent_id"] == "2")
        assert meterp["ip"] == "10.0.0.10"
        assert meterp["session_type"] == "meterpreter"
        assert meterp["os"] == "Windows"
        shell = next(a for a in agents if a["agent_id"] == "5")
        assert shell["os"] == "Linux"
        assert shell["session_type"] == "shell"

    @pytest.mark.asyncio
    async def test_returns_empty_on_auth_failure(self, msf_cfg):
        with patch("app.routers.c2._msf_login",
                   new=AsyncMock(side_effect=RuntimeError("auth failed"))):
            agents = await _msf_live_agents(msf_cfg)
        assert agents == []


# ── _msf_fetch_session_tasks ─────────────────────────────────────────

class TestMsfSessionTasks:
    @pytest.mark.asyncio
    async def test_returns_meta_row_plus_pending_buffer(self, msf_cfg):
        sessions = {1: {"type": "shell", "info": "root @ box",
                        "session_host": "10.0.0.5"}}
        async def rpc(client, base, method, *args):
            if method == "session.list":
                return sessions
            if method == "session.shell_read":
                return {"data": "ls -la\n"}
            raise RuntimeError(f"unexpected: {method}")
        with patch("app.routers.c2._msf_login", new=AsyncMock(return_value="TKN")), \
             patch("app.routers.c2._msf_rpc", new=AsyncMock(side_effect=rpc)):
            items = await _msf_fetch_session_tasks(msf_cfg, "1", limit=10)
        assert len(items) == 2
        meta, buf = items
        assert meta["msg_type"] == "meta"
        assert meta["user"] == "root"
        assert meta["computer"] == "box"
        assert buf["msg_type"] == "buffer"
        assert "ls -la" in buf["text"]

    @pytest.mark.asyncio
    async def test_unknown_session_returns_empty(self, msf_cfg):
        async def rpc(client, base, method, *args):
            return {} if method == "session.list" else {}
        with patch("app.routers.c2._msf_login", new=AsyncMock(return_value="TKN")), \
             patch("app.routers.c2._msf_rpc", new=AsyncMock(side_effect=rpc)):
            items = await _msf_fetch_session_tasks(msf_cfg, "999")
        assert items == []


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
    assert "Metasploit" in (activity.summary or "")
    assert "session 3" in (activity.summary or "")


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
