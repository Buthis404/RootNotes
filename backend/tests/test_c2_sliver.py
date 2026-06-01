"""Consolidated tests for test_c2_sliver (merged variant files)."""

# ════════ from test_c2_sliver_api.py ════════
import pytest
from unittest.mock import MagicMock
from fastapi import HTTPException

from app.routers.c2._sliver import (
    _sliver_format_host,
    _sliver_raise_compat,
    _sliver_format_live,
    _SLIVER_MIN_COMPAT,
    _SLIVER_MAX_COMPAT,
)


def _make_item(**kw):
    obj = MagicMock()
    for k, v in kw.items():
        setattr(obj, k, v)
    return obj


class TestSliverFormatHost_api:
    def test_session_host(self):
        item = _make_item(
            RemoteAddress="10.0.0.1:4444",
            Hostname="srv1",
            OS="Linux",
            Arch="amd64",
            Username="root",
            Filename="implant",
            PID=123,
            IsDead=False,
            ID="sess1",
            Name="session-name",
            ActiveC2="",
        )
        result = _sliver_format_host(item, is_beacon=False)
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "srv1"
        assert result["alive"] is True
        assert result["beacon_id"] == "sess1"
        assert "Session:" in result["note"]
        assert result["source"] == "sliver"

    def test_beacon_host(self):
        item = _make_item(
            RemoteAddress="10.0.0.2:8080",
            Hostname="beacon-pc",
            OS="Windows",
            Arch="",
            Username="",
            Filename="",
            PID=None,
            IsDead=False,
            ID="beac1",
            Name="beacon-name",
            ActiveC2="",
        )
        result = _sliver_format_host(item, is_beacon=True)
        assert "Beacon:" in result["note"]
        assert result["os"] == "Windows"

    def test_no_remote_address_uses_active_c2(self):
        item = _make_item(
            RemoteAddress="",
            ActiveC2="10.1.1.1",
            Hostname="",
            OS="",
            Arch="",
            Username="",
            Filename="",
            PID=None,
            IsDead=True,
            ID="",
            Name="",
        )
        result = _sliver_format_host(item, is_beacon=False)
        assert result["ip"] == "10.1.1.1"
        assert result["alive"] is False

    def test_empty_all_fields(self):
        item = _make_item(
            RemoteAddress="",
            ActiveC2="",
            Hostname="",
            OS="",
            Arch="",
            Username="",
            Filename="",
            PID=None,
            IsDead=False,
            ID="",
            Name="",
        )
        result = _sliver_format_host(item, is_beacon=False)
        assert result["ip"] == ""
        assert result["domain"] == ""


class TestSliverRaiseCompat_api:
    def test_not_found_raises_502(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_raise_compat(Exception("StatusCode.NOT_FOUND"), "test op")
        assert exc_info.value.status_code == 502
        assert "NOT_FOUND" in exc_info.value.detail

    def test_not_found_case_insensitive(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_raise_compat(Exception("got not_found error"), "op")
        assert exc_info.value.status_code == 502

    def test_404_in_message(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_raise_compat(Exception("404 not found"), "op")
        assert exc_info.value.status_code == 502

    def test_other_error_raises_502(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_raise_compat(Exception("connection refused"), "session execute")
        assert exc_info.value.status_code == 502
        assert "connection refused" in exc_info.value.detail


class TestSliverFormatLive_api:
    def test_alive_session(self):
        item = _make_item(
            RemoteAddress="10.0.0.1:4444",
            Hostname="pc1",
            Username="admin",
            OS="Windows",
            Arch="x64",
            Filename="implant.exe",
            ID="s1",
            ActiveC2="http",
            IsDead=False,
            LastCheckin="2025-01-01",
        )
        result = _sliver_format_live(item, is_beacon=False)
        assert result["ip"] == "10.0.0.1"
        assert result["alive"] is True
        assert result["mark"] == "alive"
        assert result["session_type"] == "session"
        assert result["last_seen"] == "2025-01-01"

    def test_dead_beacon(self):
        item = _make_item(
            RemoteAddress="10.0.0.2",
            Hostname="",
            Username="",
            OS="",
            Arch="",
            Filename="",
            ID="b1",
            ActiveC2="",
            IsDead=True,
            LastCheckin=None,
        )
        result = _sliver_format_live(item, is_beacon=True)
        assert result["alive"] is False
        assert result["mark"] == "dead"
        assert result["session_type"] == "beacon"
        assert result["last_seen"] == ""

    def test_os_with_arch(self):
        item = _make_item(
            RemoteAddress="10.0.0.3",
            Hostname="",
            Username="",
            OS="Linux",
            Arch="amd64",
            Filename="",
            ID="",
            ActiveC2="",
            IsDead=False,
            LastCheckin=None,
        )
        result = _sliver_format_live(item, is_beacon=False)
        assert result["os"] == "Linux amd64"

    def test_os_without_arch(self):
        item = _make_item(
            RemoteAddress="",
            Hostname="",
            Username="",
            OS="Windows",
            Arch="",
            Filename="",
            ID="",
            ActiveC2="",
            IsDead=False,
            LastCheckin=None,
        )
        result = _sliver_format_live(item, is_beacon=False)
        assert result["os"] == "Windows"


class TestSliverConstants:
    def test_compat_range(self):
        assert _SLIVER_MIN_COMPAT == (1, 0, 0)
        assert _SLIVER_MAX_COMPAT == (1, 6, 99)


# ════════ from test_c2_sliver_extended.py ════════
import pytest
from unittest.mock import MagicMock

from app.routers.c2._sliver import (
    _sliver_format_host,
    _sliver_format_live,
    _sliver_raise_compat,
    _sliver_parse_config,
)


class TestSliverParseConfig_extended:
    def test_empty_token(self):
        with pytest.raises(Exception, match="empty"):
            _sliver_parse_config({"token": ""})

    def test_invalid_config(self):
        with pytest.raises(Exception, match="Invalid"):
            _sliver_parse_config({"token": "not-json"})


class TestSliverFormatHost_extended:
    def test_basic(self):
        item = MagicMock()
        item.RemoteAddress = "10.0.0.1:4444"
        item.ActiveC2 = ""
        item.OS = "Linux"
        item.Arch = "amd64"
        item.Hostname = "web01"
        item.Username = "root"
        item.Filename = "implant"
        item.PID = 1234
        item.IsDead = False
        item.ID = "sid-1"
        item.Name = "session1"
        result = _sliver_format_host(item, is_beacon=False)
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "web01"
        assert result["alive"] is True
        assert result["source"] == "sliver"
        assert "Session" in result["note"]

    def test_beacon(self):
        item = MagicMock()
        item.RemoteAddress = ""
        item.ActiveC2 = "10.0.0.5"
        item.OS = "Windows"
        item.Arch = ""
        item.Hostname = ""
        item.Username = ""
        item.Filename = ""
        item.PID = None
        item.IsDead = True
        item.ID = "bid-1"
        item.Name = ""
        result = _sliver_format_host(item, is_beacon=True)
        assert result["ip"] == "10.0.0.5"
        assert result["alive"] is False
        assert "Beacon" in result["note"]


class TestSliverFormatLive_extended:
    def test_alive_session(self):
        item = MagicMock()
        item.RemoteAddress = "10.0.0.1:4444"
        item.Hostname = "dc01"
        item.Username = "admin"
        item.OS = "Windows"
        item.Arch = "x64"
        item.Filename = "beacon.exe"
        item.ID = "sid-1"
        item.ActiveC2 = "tcp"
        item.IsDead = False
        item.LastCheckin = "2025-01-01"
        result = _sliver_format_live(item, is_beacon=False)
        assert result["alive"] is True
        assert result["mark"] == "alive"
        assert result["session_type"] == "session"

    def test_dead_beacon(self):
        item = MagicMock()
        item.RemoteAddress = ""
        item.Hostname = ""
        item.Username = ""
        item.OS = ""
        item.Arch = ""
        item.Filename = ""
        item.ID = "bid-1"
        item.ActiveC2 = ""
        item.IsDead = True
        item.LastCheckin = None
        result = _sliver_format_live(item, is_beacon=True)
        assert result["alive"] is False
        assert result["mark"] == "dead"
        assert result["session_type"] == "beacon"


class TestSliverRaiseCompat_extended:
    def test_not_found(self):
        with pytest.raises(Exception, match="NOT_FOUND"):
            _sliver_raise_compat(Exception("rpc error: NOT_FOUND"), "test")

    def test_generic_error(self):
        with pytest.raises(Exception, match="Sliver test error"):
            _sliver_raise_compat(Exception("connection refused"), "test")


# ════════ from test_c2_sliver_final.py ════════
import pytest

from app.routers.c2._sliver import (
    _sliver_format_host,
    _sliver_format_live,
    _sliver_raise_compat,
    _sliver_parse_config,
)


class TestSliverFormatHost_final:
    def test_basic_session(self):
        item = type("Item", (), {
            "RemoteAddress": "10.0.0.1:4444",
            "ActiveC2": "",
            "OS": "Windows",
            "Arch": "amd64",
            "Hostname": "DESKTOP",
            "Username": "admin",
            "Filename": "implant.exe",
            "PID": 1234,
            "IsDead": False,
            "ID": "sess-1",
            "Name": "session-1",
        })()
        result = _sliver_format_host(item, is_beacon=False)
        assert result["ip"] == "10.0.0.1"
        assert result["hostname"] == "DESKTOP"
        assert result["alive"] is True
        assert result["source"] == "sliver"
        assert "Session:" in result["note"]

    def test_beacon(self):
        item = type("Item", (), {
            "RemoteAddress": "",
            "ActiveC2": "10.0.0.5",
            "OS": "",
            "Arch": "",
            "Hostname": "",
            "Username": "",
            "Filename": "",
            "PID": None,
            "IsDead": True,
            "ID": "beacon-1",
            "Name": "beacon-1",
        })()
        result = _sliver_format_host(item, is_beacon=True)
        assert result["ip"] == "10.0.0.5"
        assert result["alive"] is False
        assert "Beacon:" in result["note"]

    def test_no_ip_uses_active_c2(self):
        item = type("Item", (), {
            "RemoteAddress": "",
            "ActiveC2": "192.168.1.1",
            "OS": "", "Arch": "", "Hostname": "", "Username": "",
            "Filename": "", "PID": None, "IsDead": False, "ID": "x", "Name": "x",
        })()
        result = _sliver_format_host(item, is_beacon=False)
        assert result["ip"] == "192.168.1.1"


class TestSliverFormatLive_final:
    def test_basic(self):
        item = type("Item", (), {
            "IsDead": False,
            "RemoteAddress": "10.0.0.1:4444",
            "LastCheckin": "2025-01-01",
            "Hostname": "SRV1",
            "Username": "admin",
            "OS": "Linux",
            "Arch": "x64",
            "Filename": "implant",
            "ID": "sess-1",
            "ActiveC2": "",
        })()
        result = _sliver_format_live(item, is_beacon=False)
        assert result["ip"] == "10.0.0.1"
        assert result["alive"] is True
        assert result["mark"] == "alive"
        assert result["session_type"] == "session"

    def test_dead_beacon(self):
        item = type("Item", (), {
            "IsDead": True, "RemoteAddress": "10.0.0.2:80",
            "LastCheckin": None, "Hostname": "", "Username": "",
            "OS": "", "Arch": "", "Filename": "", "ID": "b1", "ActiveC2": "",
        })()
        result = _sliver_format_live(item, is_beacon=True)
        assert result["alive"] is False
        assert result["mark"] == "dead"
        assert result["session_type"] == "beacon"


class TestSliverRaiseCompat_final:
    def test_not_found_compat(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _sliver_raise_compat(Exception("rpc NOT_FOUND error"), "execute")
        assert exc.value.status_code == 502
        assert "NOT_FOUND" in str(exc.value.detail)

    def test_generic_error(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _sliver_raise_compat(Exception("connection refused"), "sync")
        assert exc.value.status_code == 502
        assert "connection refused" in str(exc.value.detail)


class TestSliverParseConfigEmpty:
    def test_empty_token_raises(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _sliver_parse_config({"token": ""})
        assert exc.value.status_code == 400


# ════════ from test_c2_sliver_final2.py ════════
import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

from app.routers.c2._sliver import (
    _sliver_format_host,
    _sliver_raise_compat,
    _sliver_format_live,
    _sliver_parse_config,
)


class TestSliverFormatHost_final2:
    def test_session(self):
        item = MagicMock()
        item.RemoteAddress = "10.0.0.1:4444"
        item.ActiveC2 = ""
        item.OS = "Linux"
        item.Arch = "x64"
        item.Hostname = "srv"
        item.Username = "root"
        item.Filename = "implant"
        item.PID = 123
        item.IsDead = False
        item.ID = "s1"
        item.Name = "session1"
        r = _sliver_format_host(item, is_beacon=False)
        assert r["ip"] == "10.0.0.1"
        assert r["hostname"] == "srv"
        assert r["alive"] is True
        assert r["source"] == "sliver"
        assert "Session:" in r["note"]

    def test_beacon(self):
        item = MagicMock()
        item.RemoteAddress = ""
        item.ActiveC2 = "10.0.0.2"
        item.OS = "Windows"
        item.Arch = ""
        item.Hostname = ""
        item.Username = ""
        item.Filename = ""
        item.PID = None
        item.IsDead = True
        item.ID = "b1"
        item.Name = "beacon1"
        r = _sliver_format_host(item, is_beacon=True)
        assert r["ip"] == "10.0.0.2"
        assert r["alive"] is False
        assert "Beacon:" in r["note"]

    def test_no_ip(self):
        item = MagicMock()
        item.RemoteAddress = ""
        item.ActiveC2 = ""
        r = _sliver_format_host(item, is_beacon=False)
        assert r["ip"] == ""


class TestSliverRaiseCompat_final2:
    def test_not_found(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_raise_compat(Exception("NOT_FOUND error"), "test")
        assert exc_info.value.status_code == 502

    def test_statuscode_not_found(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_raise_compat(Exception("StatusCode.NOT_FOUND"), "test")
        assert exc_info.value.status_code == 502

    def test_404_error(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_raise_compat(Exception("404 not found"), "test")
        assert exc_info.value.status_code == 502

    def test_other_error(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_raise_compat(Exception("connection refused"), "test")
        assert exc_info.value.status_code == 502
        assert "connection refused" in str(exc_info.value.detail)


class TestSliverFormatLive_final2:
    def test_alive(self):
        item = MagicMock()
        item.RemoteAddress = "10.0.0.1:4444"
        item.Hostname = "srv"
        item.Username = "root"
        item.OS = "Linux"
        item.Arch = "x64"
        item.Filename = "implant"
        item.ID = "s1"
        item.ActiveC2 = ""
        item.IsDead = False
        item.LastCheckin = "now"
        r = _sliver_format_live(item, is_beacon=False)
        assert r["alive"] is True
        assert r["mark"] == "alive"
        assert r["session_type"] == "session"

    def test_dead(self):
        item = MagicMock()
        item.RemoteAddress = "10.0.0.1:4444"
        item.Hostname = ""
        item.Username = ""
        item.OS = ""
        item.Arch = ""
        item.Filename = ""
        item.ID = "b1"
        item.ActiveC2 = ""
        item.IsDead = True
        item.LastCheckin = None
        r = _sliver_format_live(item, is_beacon=True)
        assert r["alive"] is False
        assert r["mark"] == "dead"
        assert r["session_type"] == "beacon"
        assert r["last_seen"] == ""

    def test_has_checkin(self):
        from datetime import datetime
        item = MagicMock()
        item.RemoteAddress = "10.0.0.1:4444"
        item.IsDead = False
        item.LastCheckin = datetime(2024, 1, 1)
        r = _sliver_format_live(item, is_beacon=False)
        assert r["last_seen"] != ""


class TestSliverParseConfig_final2:
    def test_empty_token(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_parse_config({"token": ""})
        assert exc_info.value.status_code == 400

    def test_invalid_config(self):
        with patch("app.routers.c2._sliver.SliverClientConfig", create=True):
            with pytest.raises(HTTPException) as exc_info:
                _sliver_parse_config({"token": "invalid json"})
            assert exc_info.value.status_code == 400


# ════════ from test_c2_sliver_v3.py ════════
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


# ════════ from test_c2_sliver_v4.py ════════
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException

from app.routers.c2._sliver import (
    _sliver_parse_config,
    _sliver_connect,
    _sliver_format_host,
    _sliver_raise_compat,
)


class TestSliverConnect:
    @pytest.mark.asyncio
    async def test_version_warning(self):
        mock_client = AsyncMock()
        ver = MagicMock()
        ver.Major = 1
        ver.Minor = 7
        ver.Patch = 0
        mock_client.version = AsyncMock(return_value=ver)
        mock_client.close = AsyncMock()
        mock_sliver_class = MagicMock(return_value=mock_client)
        with patch("app.routers.c2._sliver._sliver_parse_config", return_value=MagicMock()):
            with patch("sliver.SliverClient", mock_sliver_class):
                r = await _sliver_connect({"token": "test"})
                assert r == mock_client

    @pytest.mark.asyncio
    async def test_version_compat(self):
        mock_client = AsyncMock()
        ver = MagicMock()
        ver.Major = 1
        ver.Minor = 6
        ver.Patch = 0
        mock_client.version = AsyncMock(return_value=ver)
        mock_client.close = AsyncMock()
        mock_sliver_class = MagicMock(return_value=mock_client)
        with patch("app.routers.c2._sliver._sliver_parse_config", return_value=MagicMock()):
            with patch("sliver.SliverClient", mock_sliver_class):
                r = await _sliver_connect({"token": "test"})
                assert r == mock_client

    @pytest.mark.asyncio
    async def test_version_exception(self):
        mock_client = AsyncMock()
        mock_client.version = AsyncMock(side_effect=Exception("rpc error"))
        mock_client.close = AsyncMock()
        mock_sliver_class = MagicMock(return_value=mock_client)
        with patch("app.routers.c2._sliver._sliver_parse_config", return_value=MagicMock()):
            with patch("sliver.SliverClient", mock_sliver_class):
                r = await _sliver_connect({"token": "test"})
                assert r == mock_client


class TestSliverSessions:
    @pytest.mark.asyncio
    async def test_interact_none(self):
        mock_client = AsyncMock()
        session = MagicMock()
        session.ID = "s1"
        mock_client.sessions = AsyncMock(return_value=[session])
        mock_client.interact_session = AsyncMock(return_value=None)
        mock_client.beacons = AsyncMock(return_value=[])
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            from app.routers.c2._sliver import _sliver_execute
            with pytest.raises(HTTPException) as exc_info:
                await _sliver_execute({"token": "t"}, "s1", "id", True, 12)
            assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_beacon_interact_none(self):
        mock_client = AsyncMock()
        mock_client.sessions = AsyncMock(return_value=[])
        beacon = MagicMock()
        beacon.ID = "b1"
        mock_client.beacons = AsyncMock(return_value=[beacon])
        mock_client.interact_beacon = AsyncMock(return_value=None)
        mock_client.close = AsyncMock()
        with patch("app.routers.c2._sliver._sliver_connect", return_value=mock_client):
            from app.routers.c2._sliver import _sliver_execute
            with pytest.raises(HTTPException) as exc_info:
                await _sliver_execute({"token": "t"}, "b1", "id", True, 12)
            assert exc_info.value.status_code == 404
