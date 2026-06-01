"""Consolidated tests for test_c2_integrations (merged variant files)."""

# ════════ from test_c2_integrations_extended.py ════════
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


class TestNormalizeHostStatus_extended:
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


class TestHasLiveSessionSignal_extended:
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


class TestClassifyPrivilege_extended:
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


class TestStatusFromC2Host_extended:
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


class TestC2OwnsHostStatus_extended:
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


class TestVisibleIntegrationsForPid_extended:
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


class TestSafeIntegration_extended:
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


class TestEncryptDecryptIntegration_extended:
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


# ════════ from test_c2_integrations_extra.py ════════
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


class TestNormalizeHostStatus_extra:
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


class TestHasLiveSessionSignal_extra:
    def test_with_beacon_id(self):
        assert _has_live_session_signal({"beacon_id": "b1"}) is True

    def test_with_pid(self):
        assert _has_live_session_signal({"pid": 123}) is True

    def test_with_process(self):
        assert _has_live_session_signal({"process": "implant"}) is True

    def test_empty(self):
        assert _has_live_session_signal({}) is False


class TestClassifyPrivilege_extra:
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


class TestStatusFromC2Host_extra:
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


class TestC2OwnsHostStatus_extra:
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


class TestVisibleIntegrationsForPid_extra:
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


class TestEncryptDecryptIntegration_extra:
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


class TestSafeIntegration_extra:
    def test_masks_secrets(self):
        cfg = {"token": "secret", "password": "pass", "name": "test"}
        safe = _safe_integration(cfg)
        assert safe["token"] == ""
        assert safe["password"] == ""
        assert safe["has_token"] is True
        assert safe["has_password"] is True
        assert safe["name"] == "test"


# ════════ from test_c2_integrations_final.py ════════
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


class TestNormalizeHostStatus_final:
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


class TestHasLiveSessionSignal_final:
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


class TestClassifyPrivilege_final:
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


class TestStatusFromC2Host_final:
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


class TestC2OwnsHostStatus_final:
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


class TestVisibleIntegrationsForPid_final:
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


class TestSafeIntegration_final:
    def test_masks_secrets(self):
        cfg = {"id": "c2_1", "name": "test", "token": "secret123", "password": "pass"}
        result = _safe_integration(cfg)
        assert result["token"] == ""
        assert result["password"] == ""
        assert result["has_token"] is True
        assert result["has_password"] is True


# ════════ from test_c2_integrations_final2.py ════════
import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

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
    _is_owner_of,
    _can_manage_integration,
    _visible_to_user,
    _C2_STATUS_RANK,
)


class TestNormalizeHostStatus_final2:
    def test_known(self):
        for s in ("owned", "pwned", "access", "up", "alive", "unknown"):
            assert _normalize_host_status(s) == s

    def test_compromised(self):
        assert _normalize_host_status("compromised") == "pwned"

    def test_compromise(self):
        assert _normalize_host_status("compromise") == "pwned"

    def test_empty(self):
        assert _normalize_host_status("") == ""

    def test_unknown_val(self):
        assert _normalize_host_status("foobar") == ""


class TestHasLiveSessionSignal_final2:
    def test_beacon(self):
        assert _has_live_session_signal({"beacon_id": "b1"}) is True

    def test_agent(self):
        assert _has_live_session_signal({"agent_id": "a1"}) is True

    def test_process(self):
        assert _has_live_session_signal({"process": "p"}) is True

    def test_pid(self):
        assert _has_live_session_signal({"pid": 1}) is True

    def test_empty(self):
        assert _has_live_session_signal({}) is False


class TestClassifyPrivilege_final2:
    def test_system_variants(self):
        for u in ("SYSTEM", "root", "COMPUTER$", "NT AUTHORITY\\SYSTEM"):
            assert _classify_privilege(u) == "system"

    def test_admin(self):
        for u in ("ADMINISTRATOR", "admin"):
            assert _classify_privilege(u) == "admin"

    def test_user(self):
        assert _classify_privilege("user1") == "user"

    def test_empty(self):
        assert _classify_privilege("") == "user"


class TestStatusFromC2Host_final2:
    def test_explicit_better(self):
        r = _status_from_c2_host("unknown", {"status": "pwned"})
        assert r == "pwned"

    def test_explicit_worse(self):
        r = _status_from_c2_host("pwned", {"status": "up"})
        assert r == "pwned"

    def test_live_session_admin(self):
        r = _status_from_c2_host("", {"alive": True, "beacon_id": "b1", "username": "admin"})
        assert r == "pwned"

    def test_live_session_system(self):
        r = _status_from_c2_host("", {"alive": True, "beacon_id": "b1", "username": "SYSTEM"})
        assert r == "owned"

    def test_live_session_user(self):
        r = _status_from_c2_host("", {"alive": True, "beacon_id": "b1", "username": "user"})
        assert r == "access"

    def test_dead_default(self):
        r = _status_from_c2_host("", {"alive": False})
        assert r == "unknown"

    def test_alive_default(self):
        r = _status_from_c2_host("", {"alive": True})
        assert r == "up"

    def test_keep_existing(self):
        r = _status_from_c2_host("up", {"alive": False})
        assert r == "up"


class TestC2OwnsHostStatus_final2:
    def test_import_source_match(self):
        host = MagicMock()
        host.import_source = "sliver"
        host.tags = []
        assert _c2_owns_host_status(host, "sliver") is True

    def test_tag_match(self):
        host = MagicMock()
        host.import_source = ""
        host.tags = ["c2", "sliver"]
        assert _c2_owns_host_status(host, "sliver") is True

    def test_no_match(self):
        host = MagicMock()
        host.import_source = "mythic"
        host.tags = ["c2", "mythic"]
        assert _c2_owns_host_status(host, "sliver") is False


class TestVisibleIntegrationsForPid_final2:
    def test_enabled_no_filter(self):
        i = {"enabled": True, "project_ids": []}
        assert _visible_integrations_for_pid([i], "p1") == [i]

    def test_enabled_with_pid(self):
        i = {"enabled": True, "project_ids": ["p1"]}
        assert _visible_integrations_for_pid([i], "p1") == [i]

    def test_wrong_pid(self):
        i = {"enabled": True, "project_ids": ["p2"]}
        assert _visible_integrations_for_pid([i], "p1") == []

    def test_disabled(self):
        i = {"enabled": False, "project_ids": []}
        assert _visible_integrations_for_pid([i], "p1") == []


class TestSafeIntegration_final2:
    def test_masks(self):
        cfg = {"token": "secret", "password": "pass", "name": "test"}
        r = _safe_integration(cfg)
        assert r["token"] == ""
        assert r["password"] == ""
        assert r["has_token"] is True
        assert r["has_password"] is True

    def test_empty(self):
        r = _safe_integration({"token": "", "password": ""})
        assert r["has_token"] is False
        assert r["has_password"] is False


class TestEncryptDecryptIntegration_final2:
    def test_roundtrip(self):
        with patch("app.routers.c2._integrations.encrypt_str", side_effect=lambda x: f"enc:{x}"):
            enc = _encrypt_integration({"token": "t", "password": "p", "name": "n"})
        assert enc["token"] == "enc:t"
        assert enc["password"] == "enc:p"
        assert enc["name"] == "n"

    def test_no_sensitive(self):
        with patch("app.routers.c2._integrations.encrypt_str", side_effect=lambda x: f"enc:{x}"):
            enc = _encrypt_integration({"token": "", "name": "n"})
        assert enc["name"] == "n"


class TestCanManageIntegration_final2:
    def test_admin(self):
        user = MagicMock()
        user.role = MagicMock(value="admin")
        with patch("app.routers.c2._integrations.is_admin", return_value=True):
            assert _can_manage_integration(MagicMock(), user, {}) is True

    def test_non_admin_no_pids(self):
        user = MagicMock()
        with patch("app.routers.c2._integrations.is_admin", return_value=False):
            assert _can_manage_integration(MagicMock(), user, {"project_ids": []}) is False


class TestVisibleToUser:
    def test_admin(self):
        with patch("app.routers.c2._integrations.is_admin", return_value=True):
            assert _visible_to_user(MagicMock(), MagicMock(), {}) is True

    def test_non_admin_no_pids(self):
        with patch("app.routers.c2._integrations.is_admin", return_value=False):
            assert _visible_to_user(MagicMock(), MagicMock(), {"project_ids": []}) is False


class TestStatusRank:
    def test_ordering(self):
        assert _C2_STATUS_RANK["unknown"] < _C2_STATUS_RANK["up"]
        assert _C2_STATUS_RANK["up"] < _C2_STATUS_RANK["access"]
        assert _C2_STATUS_RANK["access"] < _C2_STATUS_RANK["pwned"]
        assert _C2_STATUS_RANK["pwned"] < _C2_STATUS_RANK["owned"]


# ════════ from test_c2_integrations_v3.py ════════
import pytest
from unittest.mock import MagicMock, patch

from app.routers.c2._integrations import (
    _c2_owns_host_status,
    _visible_integrations_for_pid,
    _encrypt_integration,
    _decrypt_integration,
    _safe_integration,
    _is_owner_of,
    _can_manage_integration,
    _require_c2,
    _C2_SETTING_KEY,
)


class TestC2OwnsHostStatus_v3:
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


class TestVisibleIntegrationsForPid_v3:
    def test_enabled_no_filter(self):
        integrations = [{"id": "1", "enabled": True, "project_ids": []}]
        r = _visible_integrations_for_pid(integrations, "p1")
        assert len(r) == 1

    def test_disabled(self):
        integrations = [{"id": "1", "enabled": False, "project_ids": []}]
        r = _visible_integrations_for_pid(integrations, "p1")
        assert len(r) == 0

    def test_project_filter_match(self):
        integrations = [{"id": "1", "enabled": True, "project_ids": ["p1"]}]
        r = _visible_integrations_for_pid(integrations, "p1")
        assert len(r) == 1

    def test_project_filter_no_match(self):
        integrations = [{"id": "1", "enabled": True, "project_ids": ["p2"]}]
        r = _visible_integrations_for_pid(integrations, "p1")
        assert len(r) == 0


class TestEncryptIntegration:
    def test_with_secrets(self):
        with patch("app.routers.c2._integrations.encrypt_str", return_value="enc"):
            r = _encrypt_integration({"token": "t", "password": "p", "url": "http://x"})
            assert r["token"] == "enc"
            assert r["password"] == "enc"
            assert r["url"] == "http://x"

    def test_no_secrets(self):
        r = _encrypt_integration({"url": "http://x"})
        assert "url" in r


class TestDecryptIntegration:
    def test_with_secrets(self):
        with patch("app.routers.c2._integrations.decrypt_str", return_value="dec"):
            r = _decrypt_integration({"token": "enc", "password": "enc"})
            assert r["token"] == "dec"
            assert r["password"] == "dec"


class TestRequireC2:
    def test_disabled(self):
        with patch("app.routers.c2._integrations.registry") as mock_reg:
            mock_reg.get.return_value = None
            from fastapi import HTTPException
            with pytest.raises(HTTPException):
                _require_c2()


class TestIsOwnerOf:
    def test_owner(self):
        db = MagicMock()
        m = MagicMock()
        from app.core.enums import MemberRole
        m.role = MemberRole.OWNER
        with patch("app.core.permissions.get_membership", return_value=m):
            user = MagicMock()
            user.id = "u1"
            r = _is_owner_of(db, "p1", user)
            assert r is True

    def test_not_owner(self):
        db = MagicMock()
        m = MagicMock()
        from app.core.enums import MemberRole
        m.role = MemberRole.VIEWER
        with patch("app.core.permissions.get_membership", return_value=m):
            user = MagicMock()
            user.id = "u1"
            r = _is_owner_of(db, "p1", user)
            assert r is False


class TestCanManageIntegration_v3:
    def test_admin(self):
        with patch("app.routers.c2._integrations.is_admin", return_value=True):
            user = MagicMock()
            r = _can_manage_integration(MagicMock(), user, {"project_ids": []})
            assert r is True

    def test_non_admin_project_match(self):
        with patch("app.routers.c2._integrations.is_admin", return_value=False):
            with patch("app.routers.c2._integrations._is_owner_of", return_value=True):
                user = MagicMock()
                r = _can_manage_integration(MagicMock(), user, {"project_ids": ["p1"]})
                assert r is True

    def test_no_projects(self):
        with patch("app.routers.c2._integrations.is_admin", return_value=False):
            user = MagicMock()
            r = _can_manage_integration(MagicMock(), user, {"project_ids": []})
            assert r is False
