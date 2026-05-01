from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.security import hash_password, verify_password, token_response
from ..core.deps import get_current_user
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
def auth_login(body: schemas.LoginRequest, db: Session = Depends(get_db)):
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
