"""
JWT revocation via Redis.

On logout the token's `jti` claim is stored with a TTL equal to the
remaining token lifetime.  The auth middleware checks this before
admitting the request.  If Redis is unreachable the check is skipped
(fail-open): tokens still expire naturally at their `exp` time.
"""

import logging
import os
from datetime import UTC, datetime

_REDIS_URL = os.environ.get("REDIS_URL", "")
_logger = logging.getLogger(__name__)

_KEY_PREFIX = "jwt:bl:"
_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    if not _REDIS_URL:
        return None
    try:
        import redis.asyncio as aioredis  # already a dep via ws.py

        _client = aioredis.from_url(_REDIS_URL, decode_responses=True)
        return _client
    except Exception as exc:
        _logger.warning("token_blacklist: Redis unavailable: %s", exc)
        return None


async def blacklist_token(jti: str, exp: int) -> None:
    """Revoke *jti* until its natural expiry at Unix timestamp *exp*."""
    client = _get_client()
    if not client:
        return
    try:
        ttl = max(1, exp - int(datetime.now(UTC).timestamp()))
        await client.setex(f"{_KEY_PREFIX}{jti}", ttl, "1")
    except Exception as exc:
        _logger.warning("token_blacklist: could not revoke jti=%s: %s", jti, exc)


async def is_blacklisted(jti: str) -> bool:
    """Return True if *jti* has been explicitly revoked."""
    if not jti:
        return False
    client = _get_client()
    if not client:
        return False
    try:
        return bool(await client.exists(f"{_KEY_PREFIX}{jti}"))
    except Exception:
        return False
