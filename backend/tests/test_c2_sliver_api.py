"""Tests for C2 Sliver helper functions."""
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


class TestSliverFormatHost:
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


class TestSliverRaiseCompat:
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


class TestSliverFormatLive:
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
