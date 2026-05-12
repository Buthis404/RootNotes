"""
Project-level RBAC.

Global roles (User.role):
  admin  — super_admin: sees all projects, bypasses project checks
  user   — normal user: sees only member projects
  viewer — legacy read-only: same scope as user but blocked from writes at middleware level

Project roles: owner > admin > editor > operator > viewer > auditor
"""
from typing import Optional
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from .deps import get_current_user
from .utils import new_id
from datetime import datetime

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


def user_has_permission(db: Session, project_id: str, user: models.User, permission: str) -> bool:
    """Check if user has permission on project. Super-admin bypasses all checks."""
    if user.role == "admin":  # global admin = super_admin
        return True
    membership = get_membership(db, project_id, user.id)
    if not membership:
        return False
    return permission in get_permissions_for_role(membership.role)


def require_project_permission(permission: str):
    """Factory that returns a FastAPI dependency checking project permission."""
    def dependency(
        pid: str,
        request: Request,
        db: Session = Depends(get_db),
        user: models.User = Depends(get_current_user),
    ) -> models.User:
        if user.role == "admin":
            return user
        membership = get_membership(db, pid, user.id)
        if not membership:
            raise HTTPException(404, "Project not found")
        if permission not in get_permissions_for_role(membership.role):
            raise HTTPException(403, "Insufficient project permissions")
        return user
    return dependency


def require_project_member(pid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)) -> tuple[models.User, Optional[models.ProjectMember]]:
    """Check that user is a member of the project (or global admin). Returns (user, membership)."""
    if user.role == "admin":
        return user, None
    membership = get_membership(db, pid, user.id)
    if not membership:
        raise HTTPException(404, "Project not found")
    return user, membership


def get_object_project_id(db: Session, model_class, object_id: str, id_field: str = "id") -> Optional[str]:
    """Get project_id (pid) for a project-scoped object."""
    obj = db.query(model_class).filter(getattr(model_class, id_field) == object_id).first()
    if not obj:
        return None
    return getattr(obj, "pid", None)


def require_object_permission(model_class, object_id_param: str, permission: str):
    """Dependency that loads object, checks project membership and permission."""
    def dependency(
        request: Request,
        db: Session = Depends(get_db),
        user: models.User = Depends(get_current_user),
    ):
        object_id = request.path_params.get(object_id_param)
        if not object_id:
            raise HTTPException(400, "Missing object id")
        obj = db.query(model_class).filter(getattr(model_class, "id") == object_id).first()
        if not obj:
            raise HTTPException(404, "Not found")
        pid = getattr(obj, "pid", None)
        if not pid:
            raise HTTPException(404, "Not found")
        if user.role == "admin":
            return user
        membership = get_membership(db, pid, user.id)
        if not membership:
            raise HTTPException(404, "Not found")
        if permission not in get_permissions_for_role(membership.role):
            raise HTTPException(403, "Insufficient permissions")
        return user
    return dependency


def add_project_owner(db: Session, project_id: str, user_id: str, created_by: Optional[str] = None):
    """Add user as owner of a project."""
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
            created_at=datetime.utcnow().isoformat(),
            created_by=created_by,
            is_active=True,
        )
        db.add(member)
