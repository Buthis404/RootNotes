import pytest
from unittest.mock import MagicMock, patch

from app.routers.members import (
    _get_project_or_404,
    _require_manage_members,
    _upsert_member,
    MemberOut,
    AddMemberBody,
    BulkAddMembersBody,
    UpdateRoleBody,
    TransferOwnershipBody,
)


class TestGetProjectOr404:
    def test_found(self):
        db = MagicMock()
        proj = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = proj
        assert _get_project_or_404("p1", db) == proj

    def test_not_found(self):
        from fastapi import HTTPException
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with pytest.raises(HTTPException) as exc:
            _get_project_or_404("p1", db)
        assert exc.value.status_code == 404


class TestRequireManageMembers:
    def test_admin_passes(self):
        user = MagicMock()
        db = MagicMock()
        with patch("app.routers.members.is_admin", return_value=True):
            _require_manage_members("p1", user, db)

    def test_non_admin_with_perm(self):
        from fastapi import HTTPException
        user = MagicMock()
        db = MagicMock()
        with patch("app.routers.members.is_admin", return_value=False), \
             patch("app.routers.members.user_has_permission", return_value=True):
            _require_manage_members("p1", user, db)

    def test_non_admin_no_perm(self):
        from fastapi import HTTPException
        user = MagicMock()
        db = MagicMock()
        with patch("app.routers.members.is_admin", return_value=False), \
             patch("app.routers.members.user_has_permission", return_value=False):
            with pytest.raises(HTTPException) as exc:
                _require_manage_members("p1", user, db)
            assert exc.value.status_code == 403


class TestUpsertMember:
    def test_new(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = _upsert_member("p1", "u1", "viewer", "admin", db)
        db.add.assert_called_once()

    def test_existing(self):
        db = MagicMock()
        existing = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing
        result = _upsert_member("p1", "u1", "editor", "admin", db)
        assert existing.role == "editor"
        assert existing.is_active is True


class TestModels:
    def test_member_out(self):
        m = MemberOut(user_id="u1", username="admin", role="owner", created_at="2025-01-01", is_active=True)
        assert m.user_id == "u1"

    def test_add_member_body(self):
        b = AddMemberBody(user_id="u1")
        assert b.role == "viewer"

    def test_bulk_add(self):
        b = BulkAddMembersBody(user_ids=["u1", "u2"])
        assert b.role == "viewer"

    def test_update_role(self):
        b = UpdateRoleBody(role="editor")
        assert b.role == "editor"

    def test_transfer(self):
        b = TransferOwnershipBody(user_id="u1")
        assert b.user_id == "u1"
