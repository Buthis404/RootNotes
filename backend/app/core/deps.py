from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from .security import decode_token


def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    uid = getattr(request.state, "uid", None)
    if not uid:
        raise HTTPException(401, "Not authenticated")
    user = db.query(models.User).filter(models.User.id == uid, models.User.active == True).first()
    if not user:
        raise HTTPException(401, "User not found or inactive")
    return user


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user


def decode_ws_token(token: str, db: Session) -> models.User | None:
    payload = decode_token(token)
    if not payload:
        return None
    uid = payload.get("sub")
    return db.query(models.User).filter(models.User.id == uid, models.User.active == True).first()
