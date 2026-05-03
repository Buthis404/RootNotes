import base64
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_SENTINEL = "__enc__:"
_fernet_instance: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is not None:
        return _fernet_instance

    key = os.environ.get("ENCRYPTION_KEY", "").strip()
    if not key:
        # Exactly 32 bytes → valid Fernet key, deterministic across restarts
        key = base64.urlsafe_b64encode(b"rootnotes-insecure-fallback-key!").decode()
        logger.warning(
            "ENCRYPTION_KEY is not set — using insecure built-in key. "
            "Set ENCRYPTION_KEY to a base64url Fernet key in production."
        )
    try:
        _fernet_instance = Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        logger.error(
            "ENCRYPTION_KEY has invalid format; falling back to insecure built-in key. "
            "Fix ENCRYPTION_KEY env variable."
        )
        fallback = base64.urlsafe_b64encode(b"rootnotes-insecure-fallback-key!").decode()
        _fernet_instance = Fernet(fallback.encode())
    return _fernet_instance


def encrypt_str(plaintext: str) -> str:
    """Encrypt plaintext and prefix with sentinel so we can detect encrypted values."""
    if not plaintext:
        return plaintext
    # Don't double-encrypt
    if plaintext.startswith(_SENTINEL):
        return plaintext
    encrypted = _get_fernet().encrypt(plaintext.encode()).decode()
    return f"{_SENTINEL}{encrypted}"


def decrypt_str(value: str) -> str:
    """Decrypt a value encrypted with encrypt_str; returns original if not encrypted."""
    if not value or not value.startswith(_SENTINEL):
        return value  # legacy unencrypted value — return as-is
    try:
        return _get_fernet().decrypt(value[len(_SENTINEL):].encode()).decode()
    except (InvalidToken, Exception):
        logger.warning("Failed to decrypt value — returning raw (may be stale or corrupt)")
        return value
