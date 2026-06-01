"""Extended tests for app.routers.c2._integrations — helper functions."""
import pytest
from unittest.mock import MagicMock

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
    def test_known_statuses(self):
        for s in ("owned", "pwned", "access", "up", "alive", "unknown"):
            assert _normalize_host_status(s) == s

    def test_compromised(self):
        assert _normalize_host_status("compromised") == "pwned"

    def test_compromise(self):
        assert _normalize_host_status("compromise") == "pwned"

    def test_unknown_returns_empty(self):
        assert _normalize_host_status("weird") == ""

    def test_empty(self):
        assert _normalize_host_status("") == ""

    def test_case_insensitive(self):
        assert _normalize_host_status("OWNED") == "owned"


class TestHasLiveSessionSignal:
    def test_with_beacon_id(self):
        assert _has_live_session_signal({"beacon_id": "b1"}) is True

    def test_with_pid(self):
        assert _has_live_session_signal({"pid": 123}) is True

    def test_with_process(self):
        assert _has_live_session_signal({"process": "implant"}) is True

    def test_empty(self):
        assert _has_live_session_signal({}) is False


class TestClassifyPrivilege:
    def test_system(self):
        assert _classify_privilege("SYSTEM") == "system"
        assert _classify_privilege("NT AUTHORITY\\SYSTEM") == "system"
        assert _classify_privilege("root") == "system"
        assert _classify_privilege("COMPUTER$") == "system"

    def test_admin(self):
        assert _classify_privilege("Administrator") == "admin"
        assert _classify_privilege("admin") == "admin"

    def test_user(self):
        assert _classify_privilege("jdoe") == "user"

    def test_empty(self):
        assert _classify_privilege("") == "user"


class TestStatusFromC2Host:
    def test_explicit_status_upgrade(self):
        result = _status_from_c2_host("up", {"status": "pwned"})
        assert result == "pwned"

    def test_live_session_admin(self):
        result = _status_from_c2_host("", {"alive": True, "beacon_id": "b1", "username": "Administrator"})
        assert result == "pwned"

    def test_live_session_system(self):
        result = _status_from_c2_host("", {"alive": True, "beacon_id": "b1", "username": "SYSTEM"})
        assert result == "owned"

    def test_dead_default(self):
        result = _status_from_c2_host("", {"alive": False})
        assert result == "unknown"

    def test_alive_default(self):
        result = _status_from_c2_host("", {"alive": True})
        assert result == "up"


class TestC2OwnsHostStatus:
    def test_from_import_source(self):
        host = MagicMock()
        host.import_source = "sliver"
        host.tags = []
        assert _c2_owns_host_status(host, "sliver") is True

    def test_from_tags(self):
        host = MagicMock()
        host.import_source = ""
        host.tags = ["c2", "sliver"]
        assert _c2_owns_host_status(host, "sliver") is True

    def test_not_owned(self):
        host = MagicMock()
        host.import_source = "nmap"
        host.tags = ["nmap"]
        assert _c2_owns_host_status(host, "sliver") is False


class TestVisibleIntegrationsForPid:
    def test_enabled_no_project_ids(self):
        integrations = [{"enabled": True, "project_ids": []}]
        assert _visible_integrations_for_pid(integrations, "p1") == integrations

    def test_disabled(self):
        integrations = [{"enabled": False, "project_ids": []}]
        assert _visible_integrations_for_pid(integrations, "p1") == []

    def test_matching_project_id(self):
        i = [{"enabled": True, "project_ids": ["p1"]}]
        assert len(_visible_integrations_for_pid(i, "p1")) == 1

    def test_non_matching_project_id(self):
        i = [{"enabled": True, "project_ids": ["p2"]}]
        assert _visible_integrations_for_pid(i, "p1") == []


class TestEncryptDecryptIntegration:
    def test_roundtrip(self):
        from app.core.crypto import encrypt_str, decrypt_str
        cfg = {"token": "tok", "password": "pass", "name": "test"}
        encrypted = _encrypt_integration(cfg)
        assert encrypted["token"] != "tok"
        assert encrypted["password"] != "pass"
        decrypted = _decrypt_integration(encrypted)
        assert decrypted["token"] == "tok"
        assert decrypted["password"] == "pass"

    def test_no_sensitive_fields(self):
        cfg = {"name": "test", "url": "http://x"}
        encrypted = _encrypt_integration(cfg)
        assert encrypted["name"] == "test"


class TestSafeIntegration:
    def test_masks_secrets(self):
        cfg = {"token": "secret", "password": "pass", "name": "test"}
        safe = _safe_integration(cfg)
        assert safe["token"] == ""
        assert safe["password"] == ""
        assert safe["has_token"] is True
        assert safe["has_password"] is True
        assert safe["name"] == "test"
