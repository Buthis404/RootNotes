from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.deps import require_admin
from ..core.enums import UserRole
from ..core.security import hash_password
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(
    prefix="/api/admin", tags=["admin"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
        409: {"description": "Conflict"},
    },
)


@router.get("/users")
def admin_list_users(
    admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    return [
        schemas.UserOut.model_validate(u)
        for u in db.query(models.User).order_by(models.User.created_at).all()
    ]


@router.post("/users", status_code=201, responses={409: {"description": "Conflict"}})
def admin_create_user(
    body: schemas.CreateUserRequest,
    admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    if db.query(models.User).filter(models.User.username == body.username.strip()).first():
        raise HTTPException(409, "Пользователь с таким логином уже существует")
    user = models.User(
        id=new_id("u"),
        username=body.username.strip(),
        display_name=(body.display_name or body.username).strip(),
        password_hash=hash_password(body.password),
        role=body.role,
        created_at=ts_now(),
        active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return schemas.UserOut.model_validate(user)


@router.patch("/users/{uid}", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
def admin_update_user(
    uid: str,
    body: schemas.UpdateUserRequest,
    admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    user = db.query(models.User).filter(models.User.id == uid).first()
    if not user:
        raise HTTPException(404, "User not found")
    if body.role is not None:
        if uid == admin.id and body.role != UserRole.ADMIN.value:
            raise HTTPException(400, "Нельзя снять с себя роль администратора")
        user.role = body.role
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
    if body.active is not None:
        if uid == admin.id and not body.active:
            raise HTTPException(400, "Нельзя деактивировать себя")
        user.active = body.active
    if body.password:
        user.password_hash = hash_password(body.password)
    db.commit()
    db.refresh(user)
    return schemas.UserOut.model_validate(user)


@router.delete("/users/{uid}", status_code=204, responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
def admin_delete_user(
    uid: str,
    admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    if uid == admin.id:
        raise HTTPException(400, "Нельзя удалить себя")
    user = db.query(models.User).filter(models.User.id == uid).first()
    if not user:
        raise HTTPException(404, "User not found")
    db.delete(user)
    db.commit()
