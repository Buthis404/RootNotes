"""Extended tests for C2 integrations helper functions."""
import pytest
from unittest.mock import MagicMock, patch

from app.routers.c2._integrations import (
    _normalize_host_status,
    _has_live_session_signal,
    _classify_privilege,
    _status_from_c2_host,
    _c2_owns_host_status,
    _visible_integrations_for_pid,
    _safe_integration,
    _encrypt_integration,
    _decrypt_integration,
    _C2_STATUS_RANK,
    _C2_SETTING_KEY,
    _MSG_INTEGRATION_NOT_FOUND,
    _MSG_INSUFFICIENT_PERMS,
    _C2_ENDPOINT_PATH,
)


class TestNormalizeHostStatus:
    def test_known_statuses(self):
        for s in ("owned", "pwned", "access", "up", "alive", "unknown"):
            assert _normalize_host_status(s) == s

    def test_case_insensitive(self):
        assert _normalize_host_status("OWNED") == "owned"
        assert _normalize_host_status("Pwned") == "pwned"
        assert _normalize_host_status("UP") == "up"

    def test_compromised_maps_to_pwned(self):
        assert _normalize_host_status("compromised") == "pwned"

    def test_compromise_maps_to_pwned(self):
        assert _normalize_host_status("compromise") == "pwned"

    def test_unknown_returns_empty(self):
        assert _normalize_host_status("random") == ""

    def test_empty_returns_empty(self):
        assert _normalize_host_status("") == ""

    def test_none_returns_empty(self):
        assert _normalize_host_status(None) == ""

    def test_whitespace(self):
        assert _normalize_host_status("  owned  ") == "owned"


class TestHasLiveSessionSignal:
    def test_with_beacon_id(self):
        assert _has_live_session_signal({"beacon_id": "abc"}) is True

    def test_with_agent_id(self):
        assert _has_live_session_signal({"agent_id": "x"}) is True

    def test_with_process(self):
        assert _has_live_session_signal({"process": "cmd.exe"}) is True

    def test_with_pid(self):
        assert _has_live_session_signal({"pid": 42}) is True

    def test_empty_all(self):
        assert _has_live_session_signal({}) is False

    def test_whitespace_strings(self):
        assert _has_live_session_signal({"beacon_id": "  "}) is False


class TestClassifyPrivilege:
    def test_system_variants(self):
        for u in ("SYSTEM", "system", "ROOT", "root", "NT AUTHORITY\\SYSTEM", "COMPUTER$"):
            assert _classify_privilege(u) == "system"

    def test_admin_variants(self):
        for u in ("Administrator", "ADMIN", "admin"):
            assert _classify_privilege(u) == "admin"

    def test_user(self):
        assert _classify_privilege("john") == "user"
        assert _classify_privilege("") == "user"
        assert _classify_privilege(None) == "user"


class TestStatusFromC2Host:
    def test_explicit_higher_status(self):
        result = _status_from_c2_host("up", {"status": "pwned"})
        assert result == "pwned"

    def test_explicit_lower_status_keeps_existing(self):
        result = _status_from_c2_host("pwned", {"status": "up"})
        assert result == "pwned"

    def test_live_session_with_system_user(self):
        result = _status_from_c2_host("up", {"beacon_id": "x", "alive": True, "username": "SYSTEM"})
        assert result == "owned"

    def test_live_session_with_admin_user(self):
        result = _status_from_c2_host("up", {"beacon_id": "x", "alive": True, "username": "Administrator"})
        assert result == "pwned"

    def test_live_session_with_normal_user(self):
        result = _status_from_c2_host("up", {"beacon_id": "x", "alive": True, "username": "john"})
        assert result == "access"

    def test_alive_no_existing(self):
        result = _status_from_c2_host("", {"alive": True})
        assert result == "up"

    def test_dead_no_existing(self):
        result = _status_from_c2_host("", {"alive": False})
        assert result == "unknown"

    def test_no_signals_keeps_existing(self):
        result = _status_from_c2_host("pwned", {"alive": True})
        assert result == "pwned"


class TestC2OwnsHostStatus:
    def test_owns_by_import_source(self):
        host = MagicMock(import_source="adaptix", tags=["c2"])
        assert _c2_owns_host_status(host, "adaptix") is True

    def test_owns_by_tags(self):
        host = MagicMock(import_source="", tags=["c2", "sliver"])
        assert _c2_owns_host_status(host, "sliver") is True

    def test_does_not_own(self):
        host = MagicMock(import_source="nmap", tags=["nmap"])
        assert _c2_owns_host_status(host, "adaptix") is False

    def test_case_insensitive(self):
        host = MagicMock(import_source="Adaptix", tags=[])
        assert _c2_owns_host_status(host, "adaptix") is True


class TestVisibleIntegrationsForPid:
    def test_enabled_matching_pid(self):
        integrations = [{"id": "1", "enabled": True, "project_ids": ["p1"]}]
        result = _visible_integrations_for_pid(integrations, "p1")
        assert len(result) == 1

    def test_disabled_excluded(self):
        integrations = [{"id": "1", "enabled": False, "project_ids": ["p1"]}]
        result = _visible_integrations_for_pid(integrations, "p1")
        assert len(result) == 0

    def test_no_project_ids_visible_to_all(self):
        integrations = [{"id": "1", "enabled": True, "project_ids": []}]
        result = _visible_integrations_for_pid(integrations, "p1")
        assert len(result) == 1

    def test_wrong_pid_excluded(self):
        integrations = [{"id": "1", "enabled": True, "project_ids": ["p2"]}]
        result = _visible_integrations_for_pid(integrations, "p1")
        assert len(result) == 0


class TestSafeIntegration:
    def test_masks_secrets(self):
        cfg = {"id": "1", "token": "secret123", "password": "pass456", "name": "test"}
        result = _safe_integration(cfg)
        assert result["token"] == ""
        assert result["password"] == ""
        assert result["has_token"] is True
        assert result["has_password"] is True
        assert result["name"] == "test"

    def test_no_secrets(self):
        cfg = {"id": "1", "name": "test"}
        result = _safe_integration(cfg)
        assert result["has_token"] is False
        assert result["has_password"] is False


class TestEncryptDecryptIntegration:
    def test_roundtrip(self):
        cfg = {"id": "1", "token": "mytoken", "password": "mypass", "name": "test"}
        with patch("app.routers.c2._integrations.encrypt_str", side_effect=lambda x: "enc_" + x):
            encrypted = _encrypt_integration(cfg)
        assert encrypted["token"] == "enc_mytoken"
        assert encrypted["password"] == "enc_mypass"
        assert encrypted["name"] == "test"

        with patch("app.routers.c2._integrations.decrypt_str", side_effect=lambda x: x.replace("enc_", "")):
            decrypted = _decrypt_integration(encrypted)
        assert decrypted["token"] == "mytoken"
        assert decrypted["password"] == "mypass"

    def test_no_secrets_unchanged(self):
        cfg = {"id": "1", "name": "test"}
        with patch("app.routers.c2._integrations.encrypt_str") as m_enc:
            _encrypt_integration(cfg)
            m_enc.assert_not_called()


class TestConstants:
    def test_status_rank_ordering(self):
        assert _C2_STATUS_RANK["unknown"] < _C2_STATUS_RANK["up"]
        assert _C2_STATUS_RANK["up"] == _C2_STATUS_RANK["alive"]
        assert _C2_STATUS_RANK["alive"] < _C2_STATUS_RANK["access"]
        assert _C2_STATUS_RANK["access"] < _C2_STATUS_RANK["pwned"]
        assert _C2_STATUS_RANK["pwned"] < _C2_STATUS_RANK["owned"]

    def test_setting_key(self):
        assert _C2_SETTING_KEY == "c2_integrations"

    def test_endpoint_path(self):
        assert _C2_ENDPOINT_PATH == "/endpoint"

    def test_messages(self):
        assert "not found" in _MSG_INTEGRATION_NOT_FOUND.lower()
        assert "insufficient" in _MSG_INSUFFICIENT_PERMS.lower() or "permissions" in _MSG_INSUFFICIENT_PERMS.lower()
