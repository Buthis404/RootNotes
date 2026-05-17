from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from .errors import AppError
from .security import decode_token


def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    uid = getattr(request.state, "uid", None)
    if not uid:
        raise AppError("unauthenticated", "Not authenticated", status=401)
    user = db.query(models.User).filter(models.User.id == uid, models.User.active == True).first()
    if not user:
        raise AppError("user_inactive", "User not found or inactive", status=401)
    return user


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "admin":
        raise AppError("admin_required", "Admin access required", status=403)
    return user


def decode_ws_token(token: str, db: Session) -> models.User | None:
    payload = decode_token(token)
    if not payload:
        return None
    uid = payload.get("sub")
    return db.query(models.User).filter(models.User.id == uid, models.User.active == True).first()
