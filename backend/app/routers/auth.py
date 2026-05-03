from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.security import hash_password, verify_password, token_response
from ..core.deps import get_current_user
from ..core.limiter import limiter
from ..core.utils import new_id
from datetime import datetime

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/status")
def auth_status(db: Session = Depends(get_db)):
    return {"initialized": db.query(models.User).count() > 0}


@router.post("/setup", status_code=201)
def auth_setup(body: schemas.SetupRequest, db: Session = Depends(get_db)):
    if db.query(models.User).count() > 0:
        raise HTTPException(403, "Already initialized — use login")
    user = models.User(
        id=new_id("u"),
        username=body.username.strip(),
        display_name=body.username.strip(),
        password_hash=hash_password(body.password),
        role="admin",
        created_at=datetime.utcnow().isoformat()[:16],
        active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return token_response(user)


@router.post("/login")
@limiter.limit("5/minute")
def auth_login(request: Request, body: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = (
        db.query(models.User)
        .filter(models.User.username == body.username.strip(), models.User.active == True)
        .first()
    )
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Неверный логин или пароль")
    return token_response(user)


@router.get("/me")
def auth_me(user: models.User = Depends(get_current_user)):
    return schemas.UserOut.model_validate(user)


@router.patch("/me")
def auth_update_me(body: schemas.UpdateProfileRequest, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    display_name = body.display_name.strip()
    if not display_name:
        raise HTTPException(400, "Display name cannot be empty")

    db_user = db.query(models.User).filter(models.User.id == user.id, models.User.active == True).first()
    if not db_user:
        raise HTTPException(404, "User not found")

    db_user.display_name = display_name
    db.commit()
    db.refresh(db_user)
    return schemas.UserOut.model_validate(db_user)


@router.post("/change-password", status_code=204)
def auth_change_password(body: schemas.ChangePasswordRequest, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    if len(body.new_password) < 4:
        raise HTTPException(400, "New password must be at least 4 characters")
    if body.current_password == body.new_password:
        raise HTTPException(400, "New password must be different from the current password")

    db_user = db.query(models.User).filter(models.User.id == user.id, models.User.active == True).first()
    if not db_user:
        raise HTTPException(404, "User not found")

    db_user.password_hash = hash_password(body.new_password)
    db.commit()
