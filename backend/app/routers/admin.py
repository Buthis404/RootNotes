from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.deps import require_admin
from ..core.security import hash_password
from ..core.utils import new_id

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/users")
def admin_list_users(
    admin: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return [schemas.UserOut.model_validate(u) for u in db.query(models.User).order_by(models.User.created_at).all()]


@router.post("/users", status_code=201)
def admin_create_user(
    body: schemas.CreateUserRequest,
    admin: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if db.query(models.User).filter(models.User.username == body.username.strip()).first():
        raise HTTPException(409, "Пользователь с таким логином уже существует")
    user = models.User(
        id=new_id("u"),
        username=body.username.strip(),
        password_hash=hash_password(body.password),
        role=body.role,
        created_at=datetime.utcnow().isoformat()[:16],
        active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return schemas.UserOut.model_validate(user)


@router.patch("/users/{uid}")
def admin_update_user(
    uid: str,
    body: schemas.UpdateUserRequest,
    admin: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.id == uid).first()
    if not user:
        raise HTTPException(404, "User not found")
    if body.role is not None:
        if uid == admin.id and body.role != "admin":
            raise HTTPException(400, "Нельзя снять с себя роль администратора")
        user.role = body.role
    if body.active is not None:
        if uid == admin.id and not body.active:
            raise HTTPException(400, "Нельзя деактивировать себя")
        user.active = body.active
    if body.password:
        user.password_hash = hash_password(body.password)
    db.commit()
    db.refresh(user)
    return schemas.UserOut.model_validate(user)


@router.delete("/users/{uid}", status_code=204)
def admin_delete_user(
    uid: str,
    admin: models.User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if uid == admin.id:
        raise HTTPException(400, "Нельзя удалить себя")
    user = db.query(models.User).filter(models.User.id == uid).first()
    if not user:
        raise HTTPException(404, "User not found")
    db.delete(user)
    db.commit()
