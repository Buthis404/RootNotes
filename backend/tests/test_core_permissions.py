"""Unit tests for app.core.permissions — RBAC matrix and membership."""
from unittest.mock import MagicMock, patch

from app.core.enums import MemberRole
from app.core.permissions import (
    PERM_CREDENTIALS_READ,
    PERM_CREDENTIALS_READ_SECRET,
    PERM_HOSTS_CREATE,
    PERM_HOSTS_DELETE,
    PERM_HOSTS_READ,
    PERM_PROJECT_DELETE,
    PERM_PROJECT_MANAGE_MEMBERS,
    PERM_PROJECT_TRANSFER_OWNERSHIP,
    PROJECT_ROLES,
    ROLE_PERMISSIONS,
    add_project_owner,
    get_membership,
    get_permissions_for_role,
)


class TestProjectRoles:
    def test_all_roles_listed(self):
        assert set(PROJECT_ROLES) == {"owner", "admin", "editor", "operator", "viewer", "auditor"}


class TestGetPermissionsForRole:
    def test_known_role(self):
        perms = get_permissions_for_role("owner")
        assert isinstance(perms, set)
        assert len(perms) > 0

    def test_unknown_role_empty(self):
        assert get_permissions_for_role("nonexistent") == set()

    def test_empty_string(self):
        assert get_permissions_for_role("") == set()


class TestRolePermissionCounts:
    """Higher roles should have more permissions."""

    def test_owner_most_permissions(self):
        assert len(ROLE_PERMISSIONS["owner"]) > len(ROLE_PERMISSIONS["admin"])

    def test_admin_more_than_editor(self):
        assert len(ROLE_PERMISSIONS["admin"]) >= len(ROLE_PERMISSIONS["editor"])

    def test_editor_more_than_operator(self):
        assert len(ROLE_PERMISSIONS["editor"]) > len(ROLE_PERMISSIONS["operator"])

    def test_operator_more_than_viewer(self):
        assert len(ROLE_PERMISSIONS["operator"]) > len(ROLE_PERMISSIONS["viewer"])

    def test_viewer_subset_of_operator(self):
        assert ROLE_PERMISSIONS["viewer"].issubset(ROLE_PERMISSIONS["operator"])


class TestSpecificPermissions:
    def test_auditor_no_credential_read(self):
        assert PERM_CREDENTIALS_READ not in ROLE_PERMISSIONS["auditor"]

    def test_auditor_no_credential_secret(self):
        assert PERM_CREDENTIALS_READ_SECRET not in ROLE_PERMISSIONS["auditor"]

    def test_operator_no_host_delete(self):
        assert PERM_HOSTS_DELETE not in ROLE_PERMISSIONS["operator"]

    def test_viewer_no_create_anything(self):
        viewer = ROLE_PERMISSIONS["viewer"]
        for perm in viewer:
            assert not perm.endswith(".create")

    def test_all_roles_have_read(self):
        for role in PROJECT_ROLES:
            assert PERM_HOSTS_READ in ROLE_PERMISSIONS[role]

    def test_only_owner_can_delete_project(self):
        for role in PROJECT_ROLES:
            if role == "owner":
                assert PERM_PROJECT_DELETE in ROLE_PERMISSIONS[role]
            else:
                assert PERM_PROJECT_DELETE not in ROLE_PERMISSIONS[role]

    def test_only_owner_can_transfer(self):
        for role in PROJECT_ROLES:
            if role == "owner":
                assert PERM_PROJECT_TRANSFER_OWNERSHIP in ROLE_PERMISSIONS[role]
            else:
                assert PERM_PROJECT_TRANSFER_OWNERSHIP not in ROLE_PERMISSIONS[role]


class TestGetMembership:
    def test_returns_member(self):
        db = MagicMock()
        member = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = member
        result = get_membership(db, "proj1", "user1")
        assert result == member

    def test_returns_none(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        result = get_membership(db, "proj1", "user1")
        assert result is None


class TestAddProjectOwner:
    def test_new_member(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        add_project_owner(db, "proj1", "user1", created_by="admin1")
        db.add.assert_called_once()

    def test_upgrade_existing(self):
        db = MagicMock()
        existing = MagicMock(role=MemberRole.VIEWER, is_active=True)
        db.query.return_value.filter.return_value.first.return_value = existing
        add_project_owner(db, "proj1", "user1")
        assert existing.role == MemberRole.OWNER
        assert existing.is_active is True
        db.add.assert_not_called()

    def test_reactivate_inactive(self):
        db = MagicMock()
        existing = MagicMock(role=MemberRole.VIEWER, is_active=False)
        db.query.return_value.filter.return_value.first.return_value = existing
        add_project_owner(db, "proj1", "user1")
        assert existing.is_active is True


class TestEditorPermissionGaps:
    def test_editor_cannot_manage_members(self):
        assert PERM_PROJECT_MANAGE_MEMBERS not in ROLE_PERMISSIONS["editor"]

    def test_editor_has_kb_export(self):
        from app.core.permissions import PERM_KB_EXPORT
        assert PERM_KB_EXPORT in ROLE_PERMISSIONS["editor"]

    def test_editor_has_playbooks_create(self):
        from app.core.permissions import PERM_PLAYBOOKS_CREATE
        assert PERM_PLAYBOOKS_CREATE in ROLE_PERMISSIONS["editor"]


class TestOperatorPermissions:
    def test_operator_has_scans_run(self):
        from app.core.permissions import PERM_SCANS_RUN
        assert PERM_SCANS_RUN in ROLE_PERMISSIONS["operator"]

    def test_operator_has_pivots_manage(self):
        from app.core.permissions import PERM_PIVOTS_MANAGE
        assert PERM_PIVOTS_MANAGE in ROLE_PERMISSIONS["operator"]

    def test_operator_no_webhooks(self):
        from app.core.permissions import PERM_WEBHOOKS_MANAGE
        assert PERM_WEBHOOKS_MANAGE not in ROLE_PERMISSIONS["operator"]

    def test_operator_no_loot_delete(self):
        from app.core.permissions import PERM_LOOT_DELETE
        assert PERM_LOOT_DELETE not in ROLE_PERMISSIONS["operator"]
