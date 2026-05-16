"""
Tests for app.core.access — the enforcement layer with shared `_evaluate`.

Verifies admin-bypass + membership + permission rules and confirms that
the raise-form (check_pid_access) and the boolean-form (user_has_permission)
agree on every input.
"""
import pytest
from fastapi import HTTPException

from app import models
from app.core import access
from app.core.permissions import add_project_owner
from app.core.utils import new_id


@pytest.fixture
def admin_user(db):
    u = models.User(id=new_id("u"), username="admin1", password_hash="x",
                    role="admin", active=True, created_at="2026-01-01")
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def normal_user(db):
    u = models.User(id=new_id("u"), username="op1", password_hash="x",
                    role="user", active=True, created_at="2026-01-01")
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def project(db, admin_user):
    p = models.Project(id=new_id("p"), name="Test", added="2026-01-01")
    db.add(p)
    db.commit()
    return p


@pytest.fixture
def viewer_membership(db, project, normal_user):
    m = models.ProjectMember(
        id=new_id("pm"), project_id=project.id, user_id=normal_user.id,
        role="viewer", created_at="2026-01-01", is_active=True,
    )
    db.add(m)
    db.commit()
    return m


@pytest.fixture
def editor_membership(db, project, normal_user):
    m = models.ProjectMember(
        id=new_id("pm"), project_id=project.id, user_id=normal_user.id,
        role="editor", created_at="2026-01-01", is_active=True,
    )
    db.add(m)
    db.commit()
    return m


# ── Global admin bypass ──────────────────────────────────────────────

class TestAdminBypass:
    def test_admin_passes_without_membership(self, db, admin_user, project):
        """Global admin doesn't need to be a project member."""
        assert access.user_has_permission(db, project.id, admin_user, "hosts.delete") is True
        # Raise form returns None for admin (no membership row)
        result = access.check_pid_access(db, project.id, admin_user, "hosts.delete")
        assert result is None

    def test_admin_bypasses_unknown_project(self, db, admin_user):
        """Admin's bypass doesn't check that the project exists at all."""
        assert access.user_has_permission(db, "p-does-not-exist", admin_user, "x") is True


# ── Non-admin requires membership ────────────────────────────────────

class TestMembershipRequired:
    def test_no_membership_returns_false(self, db, normal_user, project):
        assert access.user_has_permission(db, project.id, normal_user, "hosts.read") is False

    def test_no_membership_raises_404(self, db, normal_user, project):
        with pytest.raises(HTTPException) as exc:
            access.check_pid_access(db, project.id, normal_user, "hosts.read")
        assert exc.value.status_code == 404

    def test_check_object_access_none_pid_raises_404(self, db, normal_user):
        with pytest.raises(HTTPException) as exc:
            access.check_object_access(db, None, normal_user, "hosts.read")
        assert exc.value.status_code == 404

    def test_check_object_access_empty_pid_raises_404(self, db, normal_user):
        with pytest.raises(HTTPException) as exc:
            access.check_object_access(db, "", normal_user, "hosts.read")
        assert exc.value.status_code == 404


# ── Permission check ─────────────────────────────────────────────────

class TestPermissionCheck:
    def test_viewer_can_read_hosts(self, db, normal_user, project, viewer_membership):
        assert access.user_has_permission(db, project.id, normal_user, "hosts.read") is True

    def test_viewer_cannot_delete_hosts(self, db, normal_user, project, viewer_membership):
        assert access.user_has_permission(db, project.id, normal_user, "hosts.delete") is False

    def test_viewer_delete_raises_403(self, db, normal_user, project, viewer_membership):
        with pytest.raises(HTTPException) as exc:
            access.check_pid_access(db, project.id, normal_user, "hosts.delete")
        assert exc.value.status_code == 403

    def test_editor_can_delete_hosts(self, db, normal_user, project, editor_membership):
        assert access.user_has_permission(db, project.id, normal_user, "hosts.delete") is True

    def test_no_permission_arg_only_checks_membership(self, db, normal_user, project, viewer_membership):
        """Without a permission string, any active member is OK."""
        result = access.check_pid_access(db, project.id, normal_user, None)
        assert result is not None  # returns membership row
        assert result.role == "viewer"

    def test_returns_membership_on_success(self, db, normal_user, project, editor_membership):
        result = access.check_pid_access(db, project.id, normal_user, "hosts.delete")
        assert result is not None
        assert result.user_id == normal_user.id


# ── Both forms must agree ────────────────────────────────────────────

class TestRaiseAndBoolAgreement:
    """check_pid_access (raises) and user_has_permission (bool) must agree
    on every input — they share _evaluate so a behaviour drift would mean
    the refactor regressed."""

    @pytest.mark.parametrize("permission", [
        "hosts.read", "hosts.delete", "credentials.read_secret",
        "project.delete", "project.transfer_ownership",
    ])
    def test_admin_matches(self, db, admin_user, project, permission):
        bool_ok = access.user_has_permission(db, project.id, admin_user, permission)
        try:
            access.check_pid_access(db, project.id, admin_user, permission)
            raise_ok = True
        except HTTPException:
            raise_ok = False
        assert bool_ok == raise_ok

    @pytest.mark.parametrize("permission", [
        "hosts.read", "hosts.delete", "credentials.read_secret",
        "notes.create", "project.manage_members",
    ])
    def test_viewer_matches(self, db, normal_user, project, viewer_membership, permission):
        bool_ok = access.user_has_permission(db, project.id, normal_user, permission)
        try:
            access.check_pid_access(db, project.id, normal_user, permission)
            raise_ok = True
        except HTTPException:
            raise_ok = False
        assert bool_ok == raise_ok


# ── get_user_member_pids ─────────────────────────────────────────────

class TestGetUserMemberPids:
    def test_returns_active_memberships(self, db, normal_user, project, viewer_membership):
        pids = access.get_user_member_pids(db, normal_user)
        assert project.id in pids

    def test_empty_for_user_with_no_memberships(self, db, normal_user):
        pids = access.get_user_member_pids(db, normal_user)
        assert pids == []

    def test_excludes_inactive_memberships(self, db, normal_user, project, viewer_membership):
        viewer_membership.is_active = False
        db.commit()
        pids = access.get_user_member_pids(db, normal_user)
        assert project.id not in pids
