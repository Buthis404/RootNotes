"""
Helpers for resource routers to check project membership via object pid.
Usage in routers:
    user = check_object_access(db, host.pid, current_user, "hosts.update")
"""
from fastapi import HTTPException
from sqlalchemy.orm import Session
from .. import models
from .permissions import get_membership, get_permissions_for_role


def check_pid_access(db: Session, pid: str, user: models.User, permission: str | None = None) -> models.ProjectMember | None:
    """
    Check that user has access to a project (by pid).
    Returns membership or None (if super_admin).
    Raises 404 if not member, 403 if no permission.
    """
    if user.role == "admin":
        return None
    membership = get_membership(db, pid, user.id)
    if not membership:
        raise HTTPException(404, "Not found")
    if permission and permission not in get_permissions_for_role(membership.role):
        raise HTTPException(403, "Insufficient permissions")
    return membership


def check_object_access(db: Session, pid: str | None, user: models.User, permission: str | None = None) -> models.ProjectMember | None:
    """Same as check_pid_access but also handles None pid gracefully."""
    if not pid:
        raise HTTPException(404, "Not found")
    return check_pid_access(db, pid, user, permission)


def get_user_member_pids(db: Session, user: models.User) -> list[str]:
    """Get list of project_ids the user is a member of."""
    return [
        m.project_id for m in
        db.query(models.ProjectMember).filter(
            models.ProjectMember.user_id == user.id,
            models.ProjectMember.is_active == True,
        ).all()
    ]
