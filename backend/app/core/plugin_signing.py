"""
Plugin module signing — HMAC-SHA256 over file content.

When PLUGIN_SIGNING_KEY is set in the environment, the upload endpoint can
require a valid signature so only admin-signed modules are accepted.

Signature format: "sha256=<hex-digest>"
"""

from __future__ import annotations

import hashlib
import hmac
import os

_SIGNING_KEY = os.environ.get("PLUGIN_SIGNING_KEY", "")
_REQUIRE_SIGNATURE = os.environ.get("PLUGIN_REQUIRE_SIGNATURE", "false").lower() in (
    "1",
    "true",
    "yes",
)


def signing_enabled() -> bool:
    return bool(_SIGNING_KEY)


def require_signature() -> bool:
    return _REQUIRE_SIGNATURE and signing_enabled()


def sign_content(content: bytes | str) -> str:
    """Return 'sha256=<hex>' HMAC signature for the given content."""
    if not _SIGNING_KEY:
        raise ValueError("PLUGIN_SIGNING_KEY is not configured")
    raw = content if isinstance(content, bytes) else content.encode()
    digest = hmac.new(_SIGNING_KEY.encode(), raw, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(content: bytes | str, signature: str) -> bool:
    """Return True if the signature is valid for the given content."""
    if not _SIGNING_KEY:
        return False
    expected = sign_content(content)
    return hmac.compare_digest(expected, signature)
