import secrets
import string
from datetime import datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import JWT_SECRET, JWT_ALGO, JWT_EXPIRE_HOURS
from .. import models

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

_ALPHABET = string.ascii_letters + string.digits


def gen_password(length: int = 12) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def make_token(user: models.User) -> str:
    exp = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode(
        {"sub": user.id, "username": user.username, "role": user.role, "exp": exp},
        JWT_SECRET,
        algorithm=JWT_ALGO,
    )


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except JWTError:
        return None


def token_response(user: models.User) -> dict:
    from .. import schemas
    return {
        "access_token": make_token(user),
        "token_type": "bearer",
        "user": schemas.UserOut.model_validate(user).model_dump(),
    }
