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


class TestCanManageIntegration:
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
