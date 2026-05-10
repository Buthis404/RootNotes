import base64
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_SENTINEL = "__enc__:"
_fernet_instance: Fernet | None = None

# Persist auto-generated key alongside uploaded data so it survives container restarts
_KEY_FILE = Path(os.environ.get("UPLOAD_ROOT", "/data/uploads")).parent / "secret.key"


def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is not None:
        return _fernet_instance

    key = os.environ.get("ENCRYPTION_KEY", "").strip()

    if not key:
        # Try to load from the persisted key file
        try:
            if _KEY_FILE.exists():
                key = _KEY_FILE.read_text().strip()
        except Exception:
            pass

    if not key:
        # Generate a fresh random key and persist it for this deployment
        key = Fernet.generate_key().decode()
        try:
            _KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
            _KEY_FILE.write_text(key)
            _KEY_FILE.chmod(0o600)
            logger.info("ENCRYPTION_KEY not set — generated unique key, saved to %s", _KEY_FILE)
        except Exception as exc:
            logger.warning("Could not persist encryption key to %s: %s", _KEY_FILE, exc)

    try:
        _fernet_instance = Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        logger.error("ENCRYPTION_KEY has invalid format — generating a fresh in-memory key (data encrypted this session cannot be decrypted after restart)")
        _fernet_instance = Fernet(Fernet.generate_key())
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
