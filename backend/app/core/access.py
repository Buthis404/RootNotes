"""
Project-access enforcement for routers.

Single source of truth for runtime checks:
  - check_pid_access / check_object_access — raise 404/403
  - user_has_permission — bool predicate (same logic, no raise)
  - get_user_member_pids — list pids the user can see

All three share `_evaluate` so admin-bypass + membership + permission rules
can't drift apart. The role→permission mapping lives in `permissions.py`.
"""
from fastapi import HTTPException
from sqlalchemy.orm import Session

from .. import models
from .deps import is_admin
from .permissions import get_membership, get_permissions_for_role


def _evaluate(
    db: Session,
    pid: str,
    user: models.User,
    permission: str | None,
) -> tuple[models.ProjectMember | None, str | None]:
    """
    Return (membership, error_reason). error_reason is one of:
        None           — access granted (membership may be None for admin)
        "not_member"   — user is not a member of the project (→ 404)
        "no_permission" — user is a member but lacks the permission (→ 403)
    """
    if is_admin(user):
        return None, None
    membership = get_membership(db, pid, user.id)
    if not membership:
        return None, "not_member"
    if permission and permission not in get_permissions_for_role(membership.role):
        return membership, "no_permission"
    return membership, None


def check_pid_access(
    db: Session,
    pid: str,
    user: models.User,
    permission: str | None = None,
) -> models.ProjectMember | None:
    """
    Raise HTTPException if user can't access the project / lacks permission.
    Returns membership (or None for global admin) on success.
    """
    membership, err = _evaluate(db, pid, user, permission)
    if err == "not_member":
        from .errors import AppError
        raise AppError("not_member", "Not found", status=404)
    if err == "no_permission":
        from .errors import AppError
        raise AppError(
            "insufficient_permissions",
            "Insufficient permissions",
            status=403,
            details={"required": permission} if permission else None,
        )
    return membership


def check_object_access(
    db: Session,
    pid: str | None,
    user: models.User,
    permission: str | None = None,
) -> models.ProjectMember | None:
    """Same as check_pid_access but treats a missing pid as 404."""
    if not pid:
        from .errors import AppError
        raise AppError("not_found", "Not found", status=404)
    return check_pid_access(db, pid, user, permission)


def user_has_permission(
    db: Session,
    pid: str,
    user: models.User,
    permission: str,
) -> bool:
    """Predicate form: same logic as check_pid_access, no exception."""
    _, err = _evaluate(db, pid, user, permission)
    return err is None


def get_user_member_pids(db: Session, user: models.User) -> list[str]:
    """Project ids the user is an active member of (excludes admin global view)."""
    return [
        m.project_id
        for m in db.query(models.ProjectMember).filter(
            models.ProjectMember.user_id == user.id,
            models.ProjectMember.is_active == True,
        ).all()
    ]
