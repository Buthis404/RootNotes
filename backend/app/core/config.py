import logging
import os
import re
import secrets
from pathlib import Path

_logger = logging.getLogger(__name__)

_WEAK_SECRETS = {
    "", "change-me-in-production", "redteam-notes-change-me-in-production",
    "change-me-to-a-long-random-string", "dev-rootnotes-secret-change-me",
    "change_me_run_openssl_rand_hex_32",
}

_SECRET_FILE = Path(os.environ.get("UPLOAD_ROOT", "/data/uploads")).parent / ".jwt_secret"


def _load_jwt_secret() -> str:
    raw = os.environ.get("JWT_SECRET", "")

    # If a strong secret is provided via env, use it
    if raw and raw not in _WEAK_SECRETS and len(raw) >= 16:
        return raw

    # Try to read a previously auto-generated secret from persistent storage
    if _SECRET_FILE.exists():
        try:
            stored = _SECRET_FILE.read_text().strip()
            if stored:
                if raw and raw not in _WEAK_SECRETS:
                    pass  # env wins over file only if env is non-weak
                else:
                    _logger.warning(
                        "JWT_SECRET not set or weak — using auto-generated secret from %s. "
                        "Set JWT_SECRET in .env for production.", _SECRET_FILE
                    )
                    return stored
        except OSError:
            pass

    if not raw or raw in _WEAK_SECRETS:
        # Generate and persist a new secret
        generated = secrets.token_hex(32)
        try:
            _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
            _SECRET_FILE.write_text(generated)
            _logger.warning(
                "JWT_SECRET not set or is a known weak default. "
                "Auto-generated a secure secret and saved to %s. "
                "Add JWT_SECRET=%s to your .env to make this permanent.",
                _SECRET_FILE, generated,
            )
        except OSError as e:
            _logger.error("Could not persist auto-generated JWT_SECRET: %s", e)
        return generated

    _logger.warning(
        "JWT_SECRET appears weak (length < 16). Consider setting a stronger secret."
    )
    return raw


JWT_SECRET = _load_jwt_secret()
JWT_ALGO = "HS256"
JWT_EXPIRE_HOURS = 24 * 7

_raw_origins = os.environ.get("CORS_ORIGINS", "")
CORS_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

COOKIE_NAME = "rt_auth"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

WEBHOOK_HMAC_SECRET: str = os.environ.get("WEBHOOK_HMAC_SECRET", "")

UPLOAD_ROOT = Path(os.environ.get("UPLOAD_ROOT", "/data/uploads"))
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

SAFE_UPLOAD_RE = re.compile(r"[^A-Za-z0-9._-]+")
DEFAULT_CATALOG_PATH = Path(__file__).parent.parent / "default_catalog.json"
