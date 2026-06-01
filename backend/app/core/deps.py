from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from .enums import UserRole
from .errors import AppError
from .security import decode_token


def is_admin(user: "models.User | None") -> bool:
    """Return True if user has the global admin role (bypasses all project-level checks)."""
    return bool(user is not None and user.role == UserRole.ADMIN.value)


def is_global_viewer(user: "models.User | None") -> bool:
    """Return True if user has the legacy global viewer role.

    The global viewer (UserRole.VIEWER) is blocked from all non-GET requests
    in middleware. It is distinct from MemberRole.VIEWER, which is a per-project
    role granting read-only access within a specific project. Prefer assigning
    MemberRole.VIEWER at the project level over this global role for new accounts.
    """
    return bool(user is not None and user.role == UserRole.VIEWER.value)


def get_current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> models.User:
    uid = getattr(request.state, "uid", None)
    if not uid:
        raise AppError("unauthenticated", "Not authenticated", status=401)
    user = db.query(models.User).filter(models.User.id == uid, models.User.active).first()
    if not user:
        raise AppError("user_inactive", "User not found or inactive", status=401)
    return user


def require_admin(user: Annotated[models.User, Depends(get_current_user)]) -> models.User:
    if not is_admin(user):
        raise AppError("admin_required", "Admin access required", status=403)
    return user


def decode_ws_token(token: str, db: Session) -> models.User | None:
    payload = decode_token(token)
    if not payload:
        return None
    uid = payload.get("sub")
    return db.query(models.User).filter(models.User.id == uid, models.User.active).first()
