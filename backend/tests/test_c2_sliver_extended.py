"""Extended tests for app.routers.c2._sliver — helper functions."""
import pytest
from unittest.mock import MagicMock

from app.routers.c2._sliver import (
    _sliver_format_host,
    _sliver_format_live,
    _sliver_raise_compat,
    _sliver_parse_config,
)


class TestSliverParseConfig:
    def test_empty_token(self):
        with pytest.raises(Exception, match="empty"):
            _sliver_parse_config({"token": ""})

    def test_invalid_config(self):
        with pytest.raises(Exception, match="Invalid"):
            _sliver_parse_config({"token": "not-json"})


class TestSliverFormatHost:
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


class TestSliverFormatLive:
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


class TestSliverRaiseCompat:
    def test_not_found(self):
        with pytest.raises(Exception, match="NOT_FOUND"):
            _sliver_raise_compat(Exception("rpc error: NOT_FOUND"), "test")

    def test_generic_error(self):
        with pytest.raises(Exception, match="Sliver test error"):
            _sliver_raise_compat(Exception("connection refused"), "test")
