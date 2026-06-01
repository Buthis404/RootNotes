"""Tests for project-level RBAC permission matrix."""
from app.core.permissions import get_permissions_for_role


def has_permission(role: str, permission: str) -> bool:
    return permission in get_permissions_for_role(role)


class TestOwnerPermissions:
    def test_owner_can_read_secret(self):
        assert has_permission("owner", "credentials.read_secret")

    def test_owner_can_manage_members(self):
        assert has_permission("owner", "project.manage_members")

    def test_owner_can_delete_project(self):
        assert has_permission("owner", "project.delete")

    def test_owner_can_transfer_ownership(self):
        assert has_permission("owner", "project.transfer_ownership")

    def test_owner_can_delete_findings(self):
        assert has_permission("owner", "findings.delete")


class TestAdminPermissions:
    def test_admin_can_read_secret(self):
        assert has_permission("admin", "credentials.read_secret")

    def test_admin_can_manage_members(self):
        assert has_permission("admin", "project.manage_members")

    def test_admin_cannot_delete_project(self):
        assert not has_permission("admin", "project.delete")

    def test_admin_cannot_transfer_ownership(self):
        assert not has_permission("admin", "project.transfer_ownership")


class TestEditorPermissions:
    def test_editor_can_create_hosts(self):
        assert has_permission("editor", "hosts.create")

    def test_editor_can_read_secret(self):
        assert has_permission("editor", "credentials.read_secret")

    def test_editor_cannot_manage_members(self):
        assert not has_permission("editor", "project.manage_members")


class TestOperatorPermissions:
    def test_operator_can_create_notes(self):
        assert has_permission("operator", "notes.create")

    def test_operator_cannot_delete_hosts(self):
        assert not has_permission("operator", "hosts.delete")

    def test_operator_can_read_secret(self):
        assert has_permission("operator", "credentials.read_secret")


class TestViewerPermissions:
    def test_viewer_can_read_notes(self):
        assert has_permission("viewer", "notes.read")

    def test_viewer_cannot_create_notes(self):
        assert not has_permission("viewer", "notes.create")

    def test_viewer_cannot_read_secret(self):
        assert not has_permission("viewer", "credentials.read_secret")

    def test_viewer_cannot_delete_anything(self):
        for entity in ("hosts", "findings", "notes", "loot"):
            assert not has_permission("viewer", f"{entity}.delete"), f"viewer should not delete {entity}"


class TestAuditorPermissions:
    def test_auditor_can_read_findings(self):
        assert has_permission("auditor", "findings.read")

    def test_auditor_can_export_reports(self):
        assert has_permission("auditor", "reports.export")

    def test_auditor_cannot_update_notes(self):
        assert not has_permission("auditor", "notes.update")

    def test_auditor_cannot_read_secret(self):
        assert not has_permission("auditor", "credentials.read_secret")

    def test_auditor_cannot_read_creds(self):
        assert not has_permission("auditor", "credentials.read")


class TestRoleHierarchy:
    """Owner should be a strict superset of all other roles."""

    def test_owner_has_all_admin_permissions(self):
        owner_perms = get_permissions_for_role("owner")
        admin_perms = get_permissions_for_role("admin")
        missing = admin_perms - owner_perms
        assert not missing, f"Owner missing admin perms: {missing}"

    def test_owner_has_all_editor_permissions(self):
        owner_perms = get_permissions_for_role("owner")
        editor_perms = get_permissions_for_role("editor")
        missing = editor_perms - owner_perms
        assert not missing, f"Owner missing editor perms: {missing}"
