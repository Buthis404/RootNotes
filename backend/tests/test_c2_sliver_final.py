import pytest

from app.routers.c2._sliver import (
    _sliver_format_host,
    _sliver_format_live,
    _sliver_raise_compat,
    _sliver_parse_config,
)


class TestSliverFormatHost:
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


class TestSliverFormatLive:
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


class TestSliverRaiseCompat:
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
