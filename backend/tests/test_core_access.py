"""Tests for app.core.access — permission checks and evaluation."""
from unittest.mock import MagicMock, patch

from app.core.access import (
    _evaluate,
    check_pid_access,
    check_object_access,
    get_user_member_pids,
    user_has_permission,
)
from app.core.errors import AppError


class TestEvaluate:
    def test_admin_grants_access(self):
        user = MagicMock()
        with patch("app.core.access.is_admin", return_value=True):
            membership, err = _evaluate(MagicMock(), "p1", user, None)
            assert err is None
            assert membership is None

    def test_not_member_returns_not_member(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=None):
            membership, err = _evaluate(db, "p1", user, "hosts.read")
            assert err == "not_member"

    def test_member_with_permission_grants(self):
        user = MagicMock()
        membership = MagicMock()
        membership.role = "operator"
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value=["hosts.read"]):
            m, err = _evaluate(db, "p1", user, "hosts.read")
            assert err is None
            assert m == membership

    def test_member_without_permission(self):
        user = MagicMock()
        membership = MagicMock()
        membership.role = "viewer"
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value=["hosts.read"]):
            m, err = _evaluate(db, "p1", user, "hosts.delete")
            assert err == "no_permission"

    def test_no_permission_required(self):
        user = MagicMock()
        membership = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=membership):
            m, err = _evaluate(db, "p1", user, None)
            assert err is None


class TestCheckPidAccess:
    def test_raises_404_not_member(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=None):
            try:
                check_pid_access(db, "p1", user, "hosts.read")
                assert False, "Should have raised"
            except AppError as e:
                assert e.status_code == 404

    def test_raises_403_no_permission(self):
        user = MagicMock()
        membership = MagicMock()
        membership.role = "viewer"
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value=[]):
            try:
                check_pid_access(db, "p1", user, "hosts.delete")
                assert False, "Should have raised"
            except AppError as e:
                assert e.status_code == 403

    def test_returns_membership_on_success(self):
        user = MagicMock()
        membership = MagicMock()
        membership.role = "operator"
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value=["hosts.read"]):
            result = check_pid_access(db, "p1", user, "hosts.read")
            assert result == membership


class TestCheckObjectAccess:
    def test_raises_404_no_pid(self):
        user = MagicMock()
        db = MagicMock()
        try:
            check_object_access(db, None, user, "hosts.read")
            assert False
        except AppError as e:
            assert e.status_code == 404

    def test_delegates_to_check_pid(self):
        user = MagicMock()
        membership = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=membership), \
             patch("app.core.access.get_permissions_for_role", return_value=["hosts.read"]):
            result = check_object_access(db, "p1", user, "hosts.read")
            assert result == membership


class TestUserHasPermission:
    def test_returns_true(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=MagicMock()), \
             patch("app.core.access.get_permissions_for_role", return_value=["hosts.read"]):
            assert user_has_permission(db, "p1", user, "hosts.read") is True

    def test_returns_false(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.core.access.is_admin", return_value=False), \
             patch("app.core.access.get_membership", return_value=None):
            assert user_has_permission(db, "p1", user, "hosts.read") is False


class TestGetUserMemberPids:
    def test_returns_project_ids(self):
        user = MagicMock()
        user.id = "u1"
        m1 = MagicMock()
        m1.project_id = "p1"
        m2 = MagicMock()
        m2.project_id = "p2"
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [m1, m2]
        result = get_user_member_pids(db, user)
        assert result == ["p1", "p2"]
