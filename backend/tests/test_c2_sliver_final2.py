import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

from app.routers.c2._sliver import (
    _sliver_format_host,
    _sliver_raise_compat,
    _sliver_format_live,
    _sliver_parse_config,
)


class TestSliverFormatHost:
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


class TestSliverRaiseCompat:
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


class TestSliverFormatLive:
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


class TestSliverParseConfig:
    def test_empty_token(self):
        with pytest.raises(HTTPException) as exc_info:
            _sliver_parse_config({"token": ""})
        assert exc_info.value.status_code == 400

    def test_invalid_config(self):
        with patch("app.routers.c2._sliver.SliverClientConfig", create=True):
            with pytest.raises(HTTPException) as exc_info:
                _sliver_parse_config({"token": "invalid json"})
            assert exc_info.value.status_code == 400
