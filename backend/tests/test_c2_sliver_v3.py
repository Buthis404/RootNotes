import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException

from app.routers.c2._sliver import (
    _sliver_format_host,
    _sliver_raise_compat,
    _sliver_format_live,
    _sliver_parse_config,
    _sliver_sync,
    _sliver_exec_session,
    _sliver_execute,
    _sliver_live_agents,
    _sliver_fetch_agent_tasks,
)


class TestSliverSync:
    @pytest.mark.asyncio
    async def test_basic(self):
        mock_client = AsyncMock()
        session = MagicMock()
        session.RemoteAddress = "10.0.0.1:4444"
        session.ActiveC2 = ""
        session.OS = "Linux"
        session.Arch = "x64"
        session.Hostname = "srv"
        session.Username = "root"
        session.Filename = "implant"
        session.PID = 123
        session.IsDead = False
        session.ID = "s1"
        session.Name = "sess1"
        mock_client.sessions = AsyncMock(return_value=[session])
        mock_client.beacons = AsyncMock(return_value=[])
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            r = await _sliver_sync({"token": "test"})
            assert len(r["hosts"]) == 1
            assert r["hosts"][0]["ip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_with_beacons(self):
        mock_client = AsyncMock()
        beacon = MagicMock()
        beacon.RemoteAddress = "10.0.0.2:4444"
        beacon.ActiveC2 = ""
        beacon.OS = "Win"
        beacon.Arch = ""
        beacon.Hostname = "dc"
        beacon.Username = "admin"
        beacon.Filename = ""
        beacon.PID = None
        beacon.IsDead = True
        beacon.ID = "b1"
        beacon.Name = "beac1"
        mock_client.sessions = AsyncMock(return_value=[])
        mock_client.beacons = AsyncMock(return_value=[beacon])
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            r = await _sliver_sync({"token": "test"})
            assert len(r["hosts"]) == 1
            assert "Beacon:" in r["hosts"][0]["note"]


class TestSliverExecSession:
    @pytest.mark.asyncio
    async def test_basic(self):
        interact = AsyncMock()
        exec_result = MagicMock()
        exec_result.Stdout = b"root\n"
        exec_result.Stderr = b""
        exec_result.Status = 0
        interact.execute = AsyncMock(return_value=exec_result)
        r = await _sliver_exec_session(interact, "/bin/sh", ["-c", "id"], True, 30, "s1", "id")
        assert r["output"] == "root\n"
        assert r["accepted"] is True

    @pytest.mark.asyncio
    async def test_with_stderr(self):
        interact = AsyncMock()
        exec_result = MagicMock()
        exec_result.Stdout = b"out"
        exec_result.Stderr = b"err"
        exec_result.Status = 1
        interact.execute = AsyncMock(return_value=exec_result)
        r = await _sliver_exec_session(interact, "cmd", [], True, 30, "s1", "cmd")
        assert "err" in r["output"]
        assert r["status"] == 1

    @pytest.mark.asyncio
    async def test_none_result(self):
        interact = AsyncMock()
        exec_result = MagicMock()
        exec_result.Stdout = b""
        exec_result.Stderr = b""
        exec_result.Status = 0
        interact.execute = AsyncMock(return_value=None)
        r = await _sliver_exec_session(interact, "cmd", [], True, 30, "s1", "cmd")
        assert r["output"] == ""

    @pytest.mark.asyncio
    async def test_compat_error(self):
        interact = AsyncMock()
        interact.execute = AsyncMock(side_effect=Exception("NOT_FOUND"))
        with pytest.raises(HTTPException) as exc_info:
            await _sliver_exec_session(interact, "cmd", [], True, 30, "s1", "cmd")
        assert exc_info.value.status_code == 502


class TestSliverExecute:
    @pytest.mark.asyncio
    async def test_malformed_command(self):
        with pytest.raises(HTTPException) as exc_info:
            await _sliver_execute({"token": "t"}, "a1", "cmd 'unclosed", True, 12)
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_empty_command(self):
        with pytest.raises(HTTPException) as exc_info:
            await _sliver_execute({"token": "t"}, "a1", "", True, 12)
        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_session_found(self):
        mock_client = AsyncMock()
        session = MagicMock()
        session.ID = "s1"
        mock_client.sessions = AsyncMock(return_value=[session])
        mock_client.interact_session = AsyncMock(return_value=AsyncMock())
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            with patch("app.routers.c2._sliver._sliver_exec_session",
                       new_callable=AsyncMock, return_value={"accepted": True, "output": "root"}):
                r = await _sliver_execute({"token": "t"}, "s1", "id", True, 12)
                assert r["accepted"] is True

    @pytest.mark.asyncio
    async def test_beacon_found(self):
        mock_client = AsyncMock()
        mock_client.sessions = AsyncMock(return_value=[])
        beacon = MagicMock()
        beacon.ID = "b1"
        mock_client.beacons = AsyncMock(return_value=[beacon])
        mock_interact = AsyncMock()
        task = MagicMock()
        task.ID = "t1"
        mock_interact.execute = AsyncMock(return_value=task)
        mock_client.interact_beacon = AsyncMock(return_value=mock_interact)
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            r = await _sliver_execute({"token": "t"}, "b1", "id", True, 12)
            assert r["accepted"] is True
            assert r["kind"] == "beacon"

    @pytest.mark.asyncio
    async def test_agent_not_found(self):
        mock_client = AsyncMock()
        mock_client.sessions = AsyncMock(return_value=[])
        mock_client.beacons = AsyncMock(return_value=[])
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            with pytest.raises(HTTPException) as exc_info:
                await _sliver_execute({"token": "t"}, "x1", "id", True, 12)
            assert exc_info.value.status_code == 404


class TestSliverLiveAgents:
    @pytest.mark.asyncio
    async def test_basic(self):
        mock_client = AsyncMock()
        session = MagicMock()
        session.RemoteAddress = "10.0.0.1:4444"
        session.Hostname = "srv"
        session.Username = "root"
        session.OS = "Linux"
        session.Arch = "x64"
        session.Filename = "imp"
        session.ID = "s1"
        session.ActiveC2 = ""
        session.IsDead = False
        session.LastCheckin = "now"
        mock_client.sessions = AsyncMock(return_value=[session])
        mock_client.beacons = AsyncMock(return_value=[])
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            r = await _sliver_live_agents({"token": "t"})
            assert len(r) == 1
            assert r[0]["alive"] is True


class TestSliverFetchAgentTasks:
    @pytest.mark.asyncio
    async def test_basic(self):
        mock_client = AsyncMock()
        beacon = MagicMock()
        beacon.ID = "b1"
        mock_client.beacons = AsyncMock(return_value=[beacon])
        mock_interact = AsyncMock()
        task = MagicMock()
        task.ID = "t1"
        task.Description = "shell whoami"
        task.State = "completed"
        task.CreatedAt = "2024-01-01"
        task.CompletedAt = "2024-01-01"
        mock_interact.tasks = AsyncMock(return_value=[task])
        mock_client.interact_beacon = AsyncMock(return_value=mock_interact)
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            r = await _sliver_fetch_agent_tasks({"token": "t"}, "b1", limit=10)
            assert len(r) == 1
            assert r[0]["completed"] is True

    @pytest.mark.asyncio
    async def test_no_beacon(self):
        mock_client = AsyncMock()
        mock_client.beacons = AsyncMock(return_value=[])
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            r = await _sliver_fetch_agent_tasks({"token": "t"}, "x1", limit=10)
            assert r == []

    @pytest.mark.asyncio
    async def test_interact_none(self):
        mock_client = AsyncMock()
        beacon = MagicMock()
        beacon.ID = "b1"
        mock_client.beacons = AsyncMock(return_value=[beacon])
        mock_client.interact_beacon = AsyncMock(return_value=None)
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            r = await _sliver_fetch_agent_tasks({"token": "t"}, "b1", limit=10)
            assert r == []

    @pytest.mark.asyncio
    async def test_tasks_exception(self):
        mock_client = AsyncMock()
        beacon = MagicMock()
        beacon.ID = "b1"
        mock_client.beacons = AsyncMock(return_value=[beacon])
        mock_interact = AsyncMock()
        mock_interact.tasks = AsyncMock(side_effect=Exception("rpc error"))
        mock_client.interact_beacon = AsyncMock(return_value=mock_interact)
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            r = await _sliver_fetch_agent_tasks({"token": "t"}, "b1", limit=10)
            assert r == []
