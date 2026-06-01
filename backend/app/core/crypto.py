import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_SENTINEL = "__enc__:"
_fernet_instance: Fernet | None = None
CONFIDENTIAL_NOTE_TAGS = {"confidential", "secret", "sensitive", "opsec", "restricted"}

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
        except Exception as e:
            logger.debug("could not read persisted encryption key file: %s", e)

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
        logger.error(
            "ENCRYPTION_KEY has invalid format — generating a fresh in-memory key (data encrypted this session cannot be decrypted after restart)"
        )
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


def is_encrypted(value: str) -> bool:
    return bool(value) and value.startswith(_SENTINEL)


def decrypt_str(value: str) -> str:
    """Decrypt a value encrypted with encrypt_str; returns original if not encrypted."""
    if not value or not value.startswith(_SENTINEL):
        return value  # legacy unencrypted value — return as-is
    try:
        return _get_fernet().decrypt(value[len(_SENTINEL) :].encode()).decode()
    except (InvalidToken, Exception):
        logger.warning("Failed to decrypt value — returning raw (may be stale or corrupt)")
        return value


def validate_encryption_config() -> None:
    """Fail fast at startup if ENCRYPTION_KEY is missing in non-dev mode.

    Call once from the application lifespan before accepting requests.
    In dev/test mode the auto-generated key is accepted so local runs stay
    frictionless.  In production an explicit key is mandatory — otherwise a
    container restart silently rotates the key and all encrypted data
    (credentials, confidential notes) becomes unreadable.
    """
    app_env = os.environ.get("APP_ENV", "dev").strip().lower()
    if app_env in ("dev", "development", "test"):
        return
    if not os.environ.get("ENCRYPTION_KEY", "").strip():
        raise RuntimeError(
            f"ENCRYPTION_KEY must be explicitly set when APP_ENV={app_env!r}. "
            "Generate one with: "
            'python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" '
            "then add ENCRYPTION_KEY=<value> to your .env file. "
            "Without an explicit key every container restart creates a new key and "
            "all stored credentials and confidential notes become unreadable."
        )


def encrypt_bytes(data: bytes) -> bytes:
    """Encrypt raw bytes with Fernet; result is also bytes."""
    return _get_fernet().encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    """Decrypt Fernet-encrypted bytes; raises InvalidToken on failure."""
    return _get_fernet().decrypt(data)


def note_content_is_confidential(tags: list[str] | None) -> bool:
    lowered = {str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()}
    return bool(lowered & CONFIDENTIAL_NOTE_TAGS)


def loot_value_is_sensitive(
    loot_type: str = "",
    artifact_type: str = "",
    filename: str = "",
    storage_path: str = "",
    public_url: str = "",
) -> bool:
    if storage_path or public_url or filename:
        return False
    artifact = str(artifact_type or "").strip().lower()
    ltype = str(loot_type or "").strip().lower()
    return artifact != "file" and ltype != "file"
