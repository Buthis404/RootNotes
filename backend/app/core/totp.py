"""TOTP helpers for MFA (B8-11)."""

from __future__ import annotations

import secrets
from datetime import timedelta

import pyotp
import jwt

from .config import JWT_ALGO, JWT_SECRET
from .utils import utcnow

_ISSUER = "RootNotes"
_MFA_TOKEN_TTL_MINUTES = 5


def generate_secret() -> str:
    """Return a new base32 TOTP secret."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    """Return an otpauth:// URI for QR code generation."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=_ISSUER)


def verify_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code (±1 window tolerance)."""
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def make_mfa_pending_token(user_id: str) -> str:
    """Return a short-lived JWT that allows only the MFA verify step."""
    exp = utcnow() + timedelta(minutes=_MFA_TOKEN_TTL_MINUTES)
    return jwt.encode(
        {"sub": user_id, "type": "mfa_pending", "exp": exp, "jti": secrets.token_hex(8)},
        JWT_SECRET,
        algorithm=JWT_ALGO,
    )


def decode_mfa_pending_token(token: str) -> str | None:
    """Return user_id if the token is a valid mfa_pending token, else None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        if payload.get("type") != "mfa_pending":
            return None
        return payload.get("sub")
    except jwt.PyJWTError:
        return None
