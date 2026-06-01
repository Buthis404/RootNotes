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


class TestNormalizeHostStatus:
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


class TestHasLiveSessionSignal:
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


class TestClassifyPrivilege:
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


class TestStatusFromC2Host:
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


class TestC2OwnsHostStatus:
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


class TestVisibleIntegrationsForPid:
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


class TestSafeIntegration:
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


class TestEncryptDecryptIntegration:
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


class TestCanManageIntegration:
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
