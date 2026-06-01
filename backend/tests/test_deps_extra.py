import pytest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException

from app.core.deps import is_admin, is_global_viewer


class TestIsAdmin:
    def test_admin(self):
        user = MagicMock()
        from app.core.enums import UserRole
        user.role = UserRole.ADMIN.value
        assert is_admin(user) is True

    def test_non_admin(self):
        user = MagicMock()
        user.role = "user"
        assert is_admin(user) is False

    def test_none(self):
        assert is_admin(None) is False


class TestIsGlobalViewer:
    def test_viewer(self):
        user = MagicMock()
        from app.core.enums import UserRole
        user.role = UserRole.VIEWER.value
        assert is_global_viewer(user) is True

    def test_non_viewer(self):
        user = MagicMock()
        user.role = "user"
        assert is_global_viewer(user) is False

    def test_none(self):
        assert is_global_viewer(None) is False
