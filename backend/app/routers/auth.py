import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.config import COOKIE_NAME, COOKIE_SECURE, JWT_EXPIRE_HOURS
from ..core.crypto import decrypt_str, encrypt_str
from ..core.deps import get_current_user
from ..core.enums import UserRole
from ..core.limiter import limiter
from ..core.security import decode_token, hash_password, make_token, verify_password
from ..core.token_blacklist import blacklist_token
from ..core.totp import (
    decode_mfa_pending_token,
    generate_secret,
    make_mfa_pending_token,
    provisioning_uri,
    verify_code,
)
from ..core.utils import new_id, ts_now
from ..database import get_db

_audit = logging.getLogger("app.audit")

router = APIRouter(prefix="/api/auth", tags=["auth"])

_COOKIE_MAX_AGE = JWT_EXPIRE_HOURS * 3600


def _set_auth_cookie(response: Response, user: models.User) -> dict:
    token = make_token(user)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="strict",
        secure=COOKIE_SECURE,
        path="/",
        max_age=_COOKIE_MAX_AGE,
    )
    return {
        "user": schemas.UserOut.model_validate(user).model_dump(),
    }


@router.get("/status", responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def auth_status(db: Annotated[Session, Depends(get_db)]):
    return {"initialized": db.query(models.User).count() > 0}


@router.post("/setup", status_code=201, responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def auth_setup(body: schemas.SetupRequest, response: Response, db: Annotated[Session, Depends(get_db)]):
    if db.query(models.User).count() > 0:
        raise HTTPException(403, "Already initialized — use login")
    user = models.User(
        id=new_id("u"),
        username=body.username.strip(),
        display_name=body.username.strip(),
        password_hash=hash_password(body.password),
        role=UserRole.ADMIN,
        created_at=ts_now(),
        active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _set_auth_cookie(response, user)


@router.post("/login", responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
@limiter.limit("5/minute")
def auth_login(
    request: Request,
    body: schemas.LoginRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    user = (
        db.query(models.User)
        .filter(models.User.username == body.username.strip(), models.User.active)
        .first()
    )
    ip = request.client.host if request.client else "unknown"
    if not user or not verify_password(body.password, user.password_hash):
        _audit.warning("AUTH login_failed username=%s ip=%s", body.username.strip(), ip)
        raise HTTPException(401, "Неверный логин или пароль")
    if user.mfa_enabled and user.totp_secret:
        _audit.info("AUTH login_mfa_required user=%s ip=%s", user.username, ip)
        return {"mfa_required": True, "mfa_token": make_mfa_pending_token(user.id)}
    _audit.info("AUTH login user=%s ip=%s", user.username, ip)
    return _set_auth_cookie(response, user)


@router.post("/mfa/verify", responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
@limiter.limit("10/minute")
def auth_mfa_verify(
    request: Request,
    body: schemas.MfaVerifyRequest,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
):
    user_id = decode_mfa_pending_token(body.mfa_token)
    if not user_id:
        raise HTTPException(401, "Invalid or expired MFA token")
    user = db.query(models.User).filter(models.User.id == user_id, models.User.active).first()
    if not user or not user.mfa_enabled or not user.totp_secret:
        raise HTTPException(401, "MFA not configured for this account")
    secret = decrypt_str(user.totp_secret)
    if not verify_code(secret, body.code.strip()):
        ip = request.client.host if request.client else "unknown"
        _audit.warning("AUTH mfa_failed user=%s ip=%s", user.username, ip)
        raise HTTPException(401, "Invalid TOTP code")
    ip = request.client.host if request.client else "unknown"
    _audit.info("AUTH login user=%s ip=%s (mfa)", user.username, ip)
    return _set_auth_cookie(response, user)


@router.post("/mfa/setup", responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def auth_mfa_setup(user: Annotated[models.User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]):
    """Generate a new TOTP secret and return the provisioning URI. Does not enable MFA yet."""
    if user.mfa_enabled:
        raise HTTPException(400, "MFA is already enabled. Disable it first.")
    secret = generate_secret()
    uri = provisioning_uri(secret, user.username)
    # Store encrypted pending secret (not yet enabled until verify)
    db_user = db.query(models.User).filter(models.User.id == user.id).first()
    db_user.totp_secret = encrypt_str(secret)
    db.commit()
    return {"uri": uri, "secret": secret}


@router.post("/mfa/enable", status_code=204, responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def auth_mfa_enable(
    body: schemas.MfaEnableRequest,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Confirm TOTP code and activate MFA on the account."""
    if user.mfa_enabled:
        raise HTTPException(400, "MFA is already enabled")
    db_user = db.query(models.User).filter(models.User.id == user.id).first()
    if not db_user.totp_secret:
        raise HTTPException(400, "Call /mfa/setup first")
    secret = decrypt_str(db_user.totp_secret)
    if not verify_code(secret, body.code.strip()):
        raise HTTPException(400, "Invalid TOTP code — check your authenticator app")
    db_user.mfa_enabled = True
    db.commit()
    _audit.info("AUTH mfa_enabled user=%s", user.username)


@router.post("/mfa/disable", status_code=204, responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def auth_mfa_disable(
    body: schemas.MfaDisableRequest,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Verify TOTP code and disable MFA."""
    if not user.mfa_enabled:
        raise HTTPException(400, "MFA is not enabled")
    db_user = db.query(models.User).filter(models.User.id == user.id).first()
    secret = decrypt_str(db_user.totp_secret)
    if not verify_code(secret, body.code.strip()):
        raise HTTPException(400, "Invalid TOTP code")
    db_user.mfa_enabled = False
    db_user.totp_secret = None
    db.commit()
    _audit.info("AUTH mfa_disabled user=%s", user.username)


@router.post("/logout", status_code=204, responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
async def auth_logout(
    request: Request,
    response: Response,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    ip = request.client.host if request.client else "unknown"
    _audit.info("AUTH logout user=%s ip=%s", user.username, ip)
    response.delete_cookie(key=COOKIE_NAME, path="/", samesite="strict")
    # Revoke the token so it cannot be replayed before natural expiry.
    raw = request.cookies.get(COOKIE_NAME, "")
    if not raw:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            raw = auth_hdr[7:]
    if raw:
        payload = decode_token(raw)
        if payload and payload.get("jti") and payload.get("exp"):
            await blacklist_token(payload["jti"], int(payload["exp"]))


@router.get("/me", responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def auth_me(user: Annotated[models.User, Depends(get_current_user)]):
    return schemas.UserOut.model_validate(user)


@router.patch("/me", responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def auth_update_me(
    body: schemas.UpdateProfileRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    display_name = body.display_name.strip()
    if not display_name:
        raise HTTPException(400, "Display name cannot be empty")

    db_user = db.query(models.User).filter(models.User.id == user.id, models.User.active).first()
    if not db_user:
        raise HTTPException(404, "User not found")

    db_user.display_name = display_name
    db.commit()
    db.refresh(db_user)
    return schemas.UserOut.model_validate(db_user)


@router.post("/change-password", status_code=204, responses={400: {"description": "Bad request"}, 401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def auth_change_password(
    body: schemas.ChangePasswordRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    if len(body.new_password) < 4:
        raise HTTPException(400, "New password must be at least 4 characters")
    if body.current_password == body.new_password:
        raise HTTPException(400, "New password must be different from the current password")

    db_user = db.query(models.User).filter(models.User.id == user.id, models.User.active).first()
    if not db_user:
        raise HTTPException(404, "User not found")

    db_user.password_hash = hash_password(body.new_password)
    db.commit()
    _audit.info("AUTH password_changed user=%s", user.username)
