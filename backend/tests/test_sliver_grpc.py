"""
Tests for the Sliver C2 connector (gRPC multiplayer via sliver-py).

We mock sliver-py's SliverClient / SliverClientConfig and exercise the
parsing/formatting/dispatch code. No real teamserver needed.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.routers.c2 import (
    _sliver_format_host,
    _sliver_format_live,
    _sliver_parse_config,
    _sliver_sync,
    _sliver_live_agents,
    _sliver_execute,
    _sliver_fetch_agent_tasks,
    _CONNECTORS,
    _LIVE_CONNECTORS,
    SUPPORTED_EXEC_C2_TYPES,
)


# ── Registration ───────────────────────────────────────────────────────

def test_sliver_registered():
    assert "sliver" in _CONNECTORS
    assert "sliver" in _LIVE_CONNECTORS
    assert "sliver" in SUPPORTED_EXEC_C2_TYPES


# ── Config parsing ────────────────────────────────────────────────────

def test_parse_config_empty_blob_raises():
    with pytest.raises(HTTPException) as exc:
        _sliver_parse_config({"token": ""})
    assert exc.value.status_code == 400
    assert "empty" in str(exc.value.detail).lower()


def test_parse_config_invalid_json_raises():
    with pytest.raises(HTTPException) as exc:
        _sliver_parse_config({"token": "not valid json {{"})
    assert exc.value.status_code == 400


# ── Format helpers (synchronous, no mocking needed) ───────────────────

def test_format_host_for_session():
    s = SimpleNamespace(
        ID="sess-1", Name="EVIL-AGENT",
        Hostname="WORKSTATION-01", Username="CORP\\admin",
        OS="windows", Arch="amd64", PID=4242, Filename="powershell.exe",
        RemoteAddress="10.0.0.5:443", IsDead=False,
    )
    out = _sliver_format_host(s, is_beacon=False)
    assert out["ip"] == "10.0.0.5"
    assert out["hostname"] == "WORKSTATION-01"
    assert out["os"] == "windows amd64"
    assert out["beacon_id"] == "sess-1"
    assert out["alive"] is True
    assert out["source"] == "sliver"
    assert "Session:" in out["note"]


def test_format_host_for_beacon_marks_note():
    b = SimpleNamespace(
        ID="bcn-9", Name="DAY-BEACON", Hostname="DC01", Username="SYSTEM",
        OS="windows", Arch="amd64", PID=0, Filename="",
        RemoteAddress="10.0.0.1:0", IsDead=False,
    )
    out = _sliver_format_host(b, is_beacon=True)
    assert "Beacon:" in out["note"]


def test_format_live_dead_session():
    s = SimpleNamespace(
        ID="sess-2", Name="OLD", Hostname="OFFLINE",
        Username="", OS="linux", Arch="amd64", Filename="",
        RemoteAddress="", IsDead=True, LastCheckin=None, ActiveC2="",
    )
    out = _sliver_format_live(s, is_beacon=False)
    assert out["alive"] is False
    assert out["mark"] == "dead"


# ── sync / live_agents via mocked SliverClient ────────────────────────

def _mock_sliver_client(sessions=None, beacons=None):
    """Build a MagicMock that emulates a SliverClient instance."""
    client = MagicMock()
    client.connect = AsyncMock()
    client.close = AsyncMock()
    client.sessions = AsyncMock(return_value=sessions or [])
    client.beacons = AsyncMock(return_value=beacons or [])
    return client


@pytest.mark.asyncio
async def test_sync_combines_sessions_and_beacons():
    fake_session = SimpleNamespace(
        ID="s1", Name="A", Hostname="H1", Username="u",
        OS="linux", Arch="amd64", PID=1, Filename="bash",
        RemoteAddress="10.0.0.5:443", IsDead=False,
    )
    fake_beacon = SimpleNamespace(
        ID="b1", Name="B", Hostname="H2", Username="u2",
        OS="windows", Arch="x86", PID=0, Filename="",
        RemoteAddress="10.0.0.6:0", IsDead=False,
    )
    sliver_client = _mock_sliver_client(sessions=[fake_session], beacons=[fake_beacon])
    cfg = {"token": '{"operator":"x"}'}

    with patch("app.routers.c2._sliver_connect", new=AsyncMock(return_value=sliver_client)):
        out = await _sliver_sync(cfg)

    assert len(out["hosts"]) == 2
    ids = {h["beacon_id"] for h in out["hosts"]}
    assert ids == {"s1", "b1"}
    assert out["creds"] == []  # Sliver has no cred store
    sliver_client.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_live_agents_marks_session_vs_beacon():
    fake_session = SimpleNamespace(
        ID="s1", Hostname="H1", Username="u", OS="linux", Arch="amd64",
        Filename="bash", RemoteAddress="10.0.0.5:443", IsDead=False,
        LastCheckin=None, ActiveC2="mtls",
    )
    fake_beacon = SimpleNamespace(
        ID="b1", Hostname="H2", Username="u2", OS="windows", Arch="x86",
        Filename="", RemoteAddress="10.0.0.6:0", IsDead=False,
        LastCheckin=None, ActiveC2="http",
    )
    sliver_client = _mock_sliver_client(sessions=[fake_session], beacons=[fake_beacon])
    cfg = {"token": '{"operator":"x"}'}

    with patch("app.routers.c2._sliver_connect", new=AsyncMock(return_value=sliver_client)):
        out = await _sliver_live_agents(cfg)

    types = {a["session_type"] for a in out}
    assert types == {"session", "beacon"}


# ── Execute ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_execute_runs_on_session_when_agent_id_matches_session():
    fake_session = SimpleNamespace(ID="s1", RemoteAddress="10.0.0.5:443", IsDead=False,
                                   Hostname="", Username="", OS="", Arch="", PID=0, Filename="", Name="")
    exec_result = SimpleNamespace(Stdout=b"user1\n", Stderr=b"", Status=0)
    interact = MagicMock()
    interact.execute = AsyncMock(return_value=exec_result)

    sliver_client = _mock_sliver_client(sessions=[fake_session])
    sliver_client.interact_session = MagicMock(return_value=interact)

    cfg = {"token": '{"operator":"x"}'}
    with patch("app.routers.c2._sliver_connect", new=AsyncMock(return_value=sliver_client)):
        out = await _sliver_execute(cfg, "s1", "whoami", wait_for_output=True, timeout_seconds=5)

    assert out["kind"] == "session"
    assert out["output"] == "user1\n"
    interact.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_execute_routes_to_beacon_when_no_matching_session():
    fake_beacon = SimpleNamespace(ID="b1", RemoteAddress="10.0.0.6:0", IsDead=False,
                                  Hostname="", Username="", OS="", Arch="", PID=0, Filename="", Name="")
    task_proto = SimpleNamespace(ID="task-uuid-77")
    interact = MagicMock()
    interact.execute = AsyncMock(return_value=task_proto)

    sliver_client = _mock_sliver_client(sessions=[], beacons=[fake_beacon])
    sliver_client.interact_beacon = MagicMock(return_value=interact)

    cfg = {"token": '{"operator":"x"}'}
    with patch("app.routers.c2._sliver_connect", new=AsyncMock(return_value=sliver_client)):
        out = await _sliver_execute(cfg, "b1", "ls /tmp")

    assert out["kind"] == "beacon"
    assert out["task_id"] == "task-uuid-77"


@pytest.mark.asyncio
async def test_execute_unknown_agent_raises_404():
    sliver_client = _mock_sliver_client(sessions=[], beacons=[])
    cfg = {"token": '{"operator":"x"}'}
    with patch("app.routers.c2._sliver_connect", new=AsyncMock(return_value=sliver_client)):
        with pytest.raises(HTTPException) as exc:
            await _sliver_execute(cfg, "missing", "whoami")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_execute_empty_command_raises():
    cfg = {"token": '{"operator":"x"}'}
    with pytest.raises(HTTPException) as exc:
        await _sliver_execute(cfg, "s1", "   ")
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_execute_malformed_quoting_raises():
    cfg = {"token": '{"operator":"x"}'}
    with pytest.raises(HTTPException) as exc:
        await _sliver_execute(cfg, "s1", 'ls "unclosed')
    assert exc.value.status_code == 400


# ── Beacon task history ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_agent_tasks_returns_beacon_history():
    fake_beacon = SimpleNamespace(ID="b1")
    task_a = SimpleNamespace(ID="t1", Description="execute whoami",
                             State="completed", CreatedAt="2026-05-16T10:00:00Z",
                             CompletedAt="2026-05-16T10:00:05Z")
    task_b = SimpleNamespace(ID="t2", Description="execute ls",
                             State="pending", CreatedAt="2026-05-16T10:01:00Z",
                             CompletedAt="")
    interact = MagicMock()
    interact.tasks = AsyncMock(return_value=[task_a, task_b])

    sliver_client = _mock_sliver_client(sessions=[], beacons=[fake_beacon])
    sliver_client.interact_beacon = MagicMock(return_value=interact)

    cfg = {"token": '{"operator":"x"}'}
    with patch("app.routers.c2._sliver_connect", new=AsyncMock(return_value=sliver_client)):
        out = await _sliver_fetch_agent_tasks(cfg, "b1")

    assert len(out) == 2
    assert out[0]["task_id"] == "t1"
    assert out[0]["completed"] is True
    assert out[1]["completed"] is False
    assert out[0]["cmdline"] == "execute whoami"


@pytest.mark.asyncio
async def test_fetch_agent_tasks_for_session_returns_empty():
    """Sessions don't have task history — output is immediate; we return []."""
    fake_session = SimpleNamespace(ID="s1")
    sliver_client = _mock_sliver_client(sessions=[fake_session], beacons=[])
    cfg = {"token": '{"operator":"x"}'}
    with patch("app.routers.c2._sliver_connect", new=AsyncMock(return_value=sliver_client)):
        out = await _sliver_fetch_agent_tasks(cfg, "s1")
    assert out == []
