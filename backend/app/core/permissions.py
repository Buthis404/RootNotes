"""
Project-level RBAC — role→permission data layer.

Global roles (User.role):
  admin  — super_admin: sees all projects, bypasses project checks
  user   — normal user: sees only member projects
  viewer — legacy read-only: same scope as user but blocked from writes
           at middleware level

Project roles: owner > admin > editor > operator > viewer > auditor

Runtime enforcement (check_pid_access / user_has_permission) lives in
`access.py` — this module is pure data + membership lookup + the
add_project_owner mutation helper.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from .. import models
from .utils import new_id, ts_now

# ── Permission strings ────────────────────────────────────────────────
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {
        "project.read", "project.update", "project.delete",
        "project.manage_members", "project.export", "project.import",
        "project.transfer_ownership",
        "hosts.read", "hosts.create", "hosts.update", "hosts.delete",
        "credentials.read", "credentials.read_secret", "credentials.create",
        "credentials.update", "credentials.delete",
        "findings.read", "findings.create", "findings.update", "findings.delete",
        "notes.read", "notes.create", "notes.update", "notes.delete",
        "loot.read", "loot.create", "loot.update", "loot.delete",
        "network.read", "network.update", "network.manage_nodes", "network.manage_links",
        "topology.read", "topology.generate_commands", "topology.preview", "topology.apply",
        "reports.read", "reports.generate", "reports.update_templates", "reports.export",
        "timeline.read", "timeline.create",
        "scopes.read", "scopes.update",
        "attack_paths.read", "attack_paths.update",
        "command_outputs.read", "command_outputs.create", "command_outputs.update", "command_outputs.delete",
        "checklist.read", "checklist.update",
        "objectives.read", "objectives.create", "objectives.update", "objectives.delete",
        "search.read",
        "kb.read", "kb.create", "kb.update", "kb.delete", "kb.export",
    },
    "admin": {
        "project.read", "project.update",
        "project.manage_members", "project.export", "project.import",
        "hosts.read", "hosts.create", "hosts.update", "hosts.delete",
        "credentials.read", "credentials.read_secret", "credentials.create",
        "credentials.update", "credentials.delete",
        "findings.read", "findings.create", "findings.update", "findings.delete",
        "notes.read", "notes.create", "notes.update", "notes.delete",
        "loot.read", "loot.create", "loot.update", "loot.delete",
        "network.read", "network.update", "network.manage_nodes", "network.manage_links",
        "topology.read", "topology.generate_commands", "topology.preview", "topology.apply",
        "reports.read", "reports.generate", "reports.update_templates", "reports.export",
        "timeline.read", "timeline.create",
        "scopes.read", "scopes.update",
        "attack_paths.read", "attack_paths.update",
        "command_outputs.read", "command_outputs.create", "command_outputs.update", "command_outputs.delete",
        "checklist.read", "checklist.update",
        "objectives.read", "objectives.create", "objectives.update", "objectives.delete",
        "search.read",
        "kb.read", "kb.create", "kb.update", "kb.delete", "kb.export",
    },
    "editor": {
        "project.read", "project.export",
        "hosts.read", "hosts.create", "hosts.update", "hosts.delete",
        "credentials.read", "credentials.read_secret", "credentials.create", "credentials.update", "credentials.delete",
        "findings.read", "findings.create", "findings.update", "findings.delete",
        "notes.read", "notes.create", "notes.update", "notes.delete",
        "loot.read", "loot.create", "loot.update", "loot.delete",
        "network.read", "network.update", "network.manage_nodes", "network.manage_links",
        "topology.read", "topology.generate_commands", "topology.preview", "topology.apply",
        "reports.read", "reports.generate", "reports.update_templates",
        "timeline.read", "timeline.create",
        "scopes.read", "scopes.update",
        "attack_paths.read", "attack_paths.update",
        "command_outputs.read", "command_outputs.create", "command_outputs.update", "command_outputs.delete",
        "checklist.read", "checklist.update",
        "objectives.read", "objectives.create", "objectives.update", "objectives.delete",
        "search.read",
        "kb.read", "kb.create", "kb.update", "kb.export",
    },
    "operator": {
        "project.read",
        "hosts.read", "hosts.create", "hosts.update",
        "credentials.read", "credentials.read_secret", "credentials.create", "credentials.update",
        "findings.read", "findings.create", "findings.update",
        "notes.read", "notes.create", "notes.update",
        "loot.read", "loot.create", "loot.update",
        "network.read",
        "topology.read", "topology.preview",
        "reports.read",
        "timeline.read", "timeline.create",
        "scopes.read",
        "attack_paths.read",
        "command_outputs.read", "command_outputs.create", "command_outputs.update",
        "checklist.read", "checklist.update",
        "objectives.read", "objectives.update",
        "search.read",
        "kb.read", "kb.create", "kb.update",
    },
    "viewer": {
        "project.read",
        "hosts.read",
        "credentials.read",
        "findings.read",
        "notes.read",
        "loot.read",
        "network.read",
        "topology.read",
        "reports.read",
        "timeline.read",
        "scopes.read",
        "attack_paths.read",
        "command_outputs.read",
        "checklist.read",
        "objectives.read",
        "search.read",
        "kb.read",
    },
    "auditor": {
        "project.read",
        "hosts.read",
        "findings.read",
        "notes.read",
        "loot.read",
        "network.read",
        "reports.read", "reports.export",
        "timeline.read",
        "attack_paths.read",
        "command_outputs.read",
        "checklist.read",
        "objectives.read",
        "search.read",
        "kb.read",
    },
}

PROJECT_ROLES = list(ROLE_PERMISSIONS.keys())


def get_permissions_for_role(role: str) -> set[str]:
    return ROLE_PERMISSIONS.get(role, set())


def get_membership(db: Session, project_id: str, user_id: str) -> Optional[models.ProjectMember]:
    return (
        db.query(models.ProjectMember)
        .filter(
            models.ProjectMember.project_id == project_id,
            models.ProjectMember.user_id == user_id,
            models.ProjectMember.is_active == True,
        )
        .first()
    )


def add_project_owner(db: Session, project_id: str, user_id: str, created_by: Optional[str] = None):
    """Add user as owner of a project (or upgrade existing membership)."""
    existing = get_membership(db, project_id, user_id)
    if existing:
        existing.role = "owner"
        existing.is_active = True
    else:
        member = models.ProjectMember(
            id=new_id("pm"),
            project_id=project_id,
            user_id=user_id,
            role="owner",
            created_at=ts_now(),
            created_by=created_by,
            is_active=True,
        )
        db.add(member)
