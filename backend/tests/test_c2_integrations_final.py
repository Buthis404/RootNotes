import pytest
from unittest.mock import patch, MagicMock

from app.routers.c2._integrations import (
    _normalize_host_status,
    _has_live_session_signal,
    _classify_privilege,
    _status_from_c2_host,
    _c2_owns_host_status,
    _visible_integrations_for_pid,
    _encrypt_integration,
    _decrypt_integration,
    _safe_integration,
)


class TestNormalizeHostStatus:
    def test_owned(self):
        assert _normalize_host_status("owned") == "owned"

    def test_compromised(self):
        assert _normalize_host_status("compromised") == "pwned"

    def test_unknown_value(self):
        assert _normalize_host_status("custom") == ""

    def test_empty(self):
        assert _normalize_host_status("") == ""

    def test_whitespace(self):
        assert _normalize_host_status("  up  ") == "up"


class TestHasLiveSessionSignal:
    def test_beacon_id(self):
        assert _has_live_session_signal({"beacon_id": "abc"}) is True

    def test_agent_id(self):
        assert _has_live_session_signal({"agent_id": "x"}) is True

    def test_process(self):
        assert _has_live_session_signal({"process": "implant"}) is True

    def test_pid(self):
        assert _has_live_session_signal({"pid": "123"}) is True

    def test_empty(self):
        assert _has_live_session_signal({}) is False


class TestClassifyPrivilege:
    def test_system_dollar(self):
        assert _classify_privilege("COMPUTER$") == "system"

    def test_system_literal(self):
        assert _classify_privilege("SYSTEM") == "system"

    def test_root(self):
        assert _classify_privilege("root") == "system"

    def test_nt_authority(self):
        assert _classify_privilege("NT AUTHORITY\\SYSTEM") == "system"

    def test_admin(self):
        assert _classify_privilege("Administrator") == "admin"

    def test_user(self):
        assert _classify_privilege("john") == "user"


class TestStatusFromC2Host:
    def test_explicit_status_upgrade(self):
        result = _status_from_c2_host("up", {"status": "pwned"})
        assert result == "pwned"

    def test_explicit_no_downgrade(self):
        result = _status_from_c2_host("pwned", {"status": "up"})
        assert result == "pwned"

    def test_live_session_system(self):
        result = _status_from_c2_host("", {"alive": True, "beacon_id": "x", "username": "SYSTEM"})
        assert result == "owned"

    def test_live_session_admin(self):
        result = _status_from_c2_host("", {"alive": True, "beacon_id": "x", "username": "admin"})
        assert result == "pwned"

    def test_live_session_user(self):
        result = _status_from_c2_host("", {"alive": True, "beacon_id": "x", "username": "user1"})
        assert result == "access"

    def test_no_signal_alive(self):
        result = _status_from_c2_host("", {"alive": True})
        assert result == "up"

    def test_dead(self):
        result = _status_from_c2_host("", {"alive": False})
        assert result == "unknown"


class TestC2OwnsHostStatus:
    def test_import_source_match(self):
        host = MagicMock()
        host.import_source = "sliver"
        host.tags = []
        assert _c2_owns_host_status(host, "sliver") is True

    def test_tag_match(self):
        host = MagicMock()
        host.import_source = ""
        host.tags = ["c2", "mythic"]
        assert _c2_owns_host_status(host, "mythic") is True

    def test_no_match(self):
        host = MagicMock()
        host.import_source = "nmap"
        host.tags = ["nmap"]
        assert _c2_owns_host_status(host, "sliver") is False


class TestVisibleIntegrationsForPid:
    def test_enabled_no_filter(self):
        integrations = [{"enabled": True, "project_ids": []}]
        result = _visible_integrations_for_pid(integrations, "p1")
        assert len(result) == 1

    def test_enabled_matching_pid(self):
        integrations = [{"enabled": True, "project_ids": ["p1"]}]
        result = _visible_integrations_for_pid(integrations, "p1")
        assert len(result) == 1

    def test_disabled(self):
        integrations = [{"enabled": False}]
        result = _visible_integrations_for_pid(integrations, "p1")
        assert len(result) == 0

    def test_wrong_pid(self):
        integrations = [{"enabled": True, "project_ids": ["p2"]}]
        result = _visible_integrations_for_pid(integrations, "p1")
        assert len(result) == 0


class TestSafeIntegration:
    def test_masks_secrets(self):
        cfg = {"id": "c2_1", "name": "test", "token": "secret123", "password": "pass"}
        result = _safe_integration(cfg)
        assert result["token"] == ""
        assert result["password"] == ""
        assert result["has_token"] is True
        assert result["has_password"] is True
