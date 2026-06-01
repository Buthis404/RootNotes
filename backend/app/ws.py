"""
WebSocket connection manager with Redis pub/sub backend.

Architecture:
  - Each backend instance tracks its own live WebSocket connections in memory.
  - Data events (entity changes) are published to Redis channel `ws:{pid}` and
    forwarded to all local subscribers.  This allows horizontal scaling: any
    instance that holds connections for a project will receive the broadcast.
  - Presence (who is online, which note they have open) is stored in a Redis
    hash `presence:{pid}` keyed by a per-connection UUID so all instances share
    the same view.
  - If Redis is unavailable the manager falls back to in-process broadcast only
    (single-instance behaviour identical to the previous implementation).

Authorization at the WS layer
  - Each connection records the user's effective permission set at connect
    time. _local_broadcast consults _ENTITY_POLICY to decide whether the
    connection should receive an event AND whether sensitive fields in the
    payload (e.g. cred.secret) must be redacted to "" for that recipient.
  - This complements REST-level permission checks: a viewer who lacks
    credentials.read_secret never sees a plaintext secret arrive via WS
    even if the actor who created the cred had that permission.

Data events:  { pid, entity, action, data }
Presence:     { type: "presence", users: [{name, note_id}] }
"""

import asyncio
import json
import logging
import os
import uuid
from typing import Any

from fastapi import WebSocket

from .core.permissions import PERM_CREDENTIALS_READ_SECRET, PERM_NETWORK_READ

logger = logging.getLogger(__name__)

_REDIS_URL = os.environ.get("REDIS_URL", "")

# Presence entry is considered stale if not touched within this window.
# Frontend pings every 25s (PING_INTERVAL in useSync.js); 90s gives ~3
# missed pings before lazy-cleanup wipes the ghost from the online list.
_PRESENCE_STALE_SECONDS = 90


# ── Broadcast policy ──────────────────────────────────────────────────────────
#
# For each entity type:
#   "read"   — permission required to receive the event at all
#   "redact" — list of (field_name, permission) — if the recipient lacks
#              `permission`, the field is replaced with "" before send
#   "public" — bypass policy (presence, errors, etc.)
#
# Entities not listed default to: deliver to any project member (admin pass
# through too). This is permissive on purpose — adding entities to the table
# is opt-in narrowing, while existing event types keep their current behaviour
# until explicitly classified.

_ENTITY_POLICY: dict[str, dict[str, Any]] = {
    "cred": {"read": "credentials.read", "redact": [("secret", PERM_CREDENTIALS_READ_SECRET)]},
    "host": {"read": "hosts.read"},
    # host_activity carries `command` (impacket/netexec with substituted secrets)
    # and `output` (which can include dumped hashes / harvested creds). Hide
    # both from operators who lack credentials.read_secret.
    "host_activity": {
        "read": "hosts.read",
        "redact": [
            ("command", PERM_CREDENTIALS_READ_SECRET),
            ("output", PERM_CREDENTIALS_READ_SECRET),
        ],
    },
    "finding": {"read": "findings.read"},
    "note": {"read": "notes.read"},
    "loot": {"read": "loot.read"},
    "scope": {"read": "scopes.read"},
    "attack_path": {"read": "attack_paths.read"},
    "objective": {"read": "objectives.read"},
    "checklist": {"read": "checklist.read"},
    "timeline": {"read": "timeline.read"},
    "command_output": {"read": "command_outputs.read"},
    # `command` may include substituted credentials; `request_json.password` /
    # `.hash` likewise. Recursive scrub kicks in for the request_json blob.
    "job": {
        "read": "command_outputs.read",
        "redact": [
            ("command", PERM_CREDENTIALS_READ_SECRET),
            ("output", PERM_CREDENTIALS_READ_SECRET),
        ],
        "scrub_keys": True,
    },
    "playbook_run": {
        "redact": [("request_json", PERM_CREDENTIALS_READ_SECRET)],
        "scrub_keys": True,
    },
    "network_node": {"read": PERM_NETWORK_READ},
    "network_link": {"read": PERM_NETWORK_READ},
    "network": {"read": PERM_NETWORK_READ},
}


# Keys whose values are scrubbed (set to "") in nested dict payloads when the
# recipient lacks `credentials.read_secret`. Names are matched case-insensitively
# on substring so "user_password", "ldap_password" etc. are all caught.
_SENSITIVE_KEY_SUBSTRINGS = ("password", "secret", "api_key", "apikey", "_hash", "credential_text")


def _policy_for(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Return the policy entry for a message, or None for default-open."""
    if msg.get("type") == "presence":
        return {"public": True}
    entity = (msg.get("entity") or "").strip()
    return _ENTITY_POLICY.get(entity)


def _scrub_sensitive_keys(value: Any) -> Any:
    """Walk a JSON-ish structure replacing values for sensitive key names with ''."""
    if isinstance(value, dict):
        return {
            k: (
                ""
                if any(s in k.lower() for s in _SENSITIVE_KEY_SUBSTRINGS)
                else _scrub_sensitive_keys(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub_sensitive_keys(item) for item in value]
    return value


def _scrub_data_keys(redacted_data: dict) -> None:
    for k, v in list(redacted_data.items()):
        if any(s in k.lower() for s in _SENSITIVE_KEY_SUBSTRINGS):
            redacted_data[k] = ""
        elif isinstance(v, (dict, list)):
            redacted_data[k] = _scrub_sensitive_keys(v)


def _redact_payload(
    msg: dict[str, Any], policy: dict[str, Any], permissions: frozenset[str]
) -> dict[str, Any]:
    """Return a (possibly shallow-copied) message with sensitive fields stripped."""
    redact = policy.get("redact") or []
    scrub_keys = bool(policy.get("scrub_keys"))
    if "data" not in msg or not isinstance(msg["data"], dict):
        return msg
    can_read_secret = PERM_CREDENTIALS_READ_SECRET in permissions
    needs_redact = any(perm not in permissions for _, perm in redact)
    needs_scrub = scrub_keys and not can_read_secret
    if not needs_redact and not needs_scrub:
        return msg
    redacted_data = dict(msg["data"])
    for field, perm in redact:
        if perm not in permissions and field in redacted_data:
            redacted_data[field] = ""
    if needs_scrub:
        _scrub_data_keys(redacted_data)
    return {**msg, "data": redacted_data}


def _resolve_send_msg(
    msg: dict[str, Any],
    policy: dict[str, Any] | None,
    permissions: frozenset[str],
    is_global_admin: bool,
) -> dict[str, Any] | None:
    """Return the message to send (possibly redacted) or None to skip this recipient."""
    if not policy or policy.get("public") or is_global_admin:
        return msg
    required = policy.get("read")
    if required and required not in permissions:
        return None
    return _redact_payload(msg, policy, permissions)


def _get_ws_text(send_msg: dict[str, Any], msg: dict[str, Any], plain_cache: list) -> str:
    """Serialize send_msg; uses plain_cache[0] to avoid re-serialising unchanged msg."""
    if send_msg is msg:
        if plain_cache[0] is None:
            plain_cache[0] = json.dumps(msg)
        return plain_cache[0]
    return json.dumps(send_msg)


def _parse_presence_raw(raw: dict, cutoff: float) -> tuple[list, list[str]]:
    """Parse raw Redis presence hash; return (entries, stale_keys)."""
    result: list = []
    stale: list[str] = []
    for conn_id, v in raw.items():
        try:
            item = json.loads(v)
        except Exception:
            stale.append(conn_id)
            continue
        if item.get("last_seen", 0) and item["last_seen"] < cutoff:
            stale.append(conn_id)
            continue
        result.append({k: val for k, val in item.items() if k != "last_seen"})
    return result, stale


# ── Redis helpers ─────────────────────────────────────────────────────────────


def _get_redis():
    """Return a redis.asyncio client or None if unavailable."""
    if not _REDIS_URL:
        return None
    try:
        import redis.asyncio as aioredis

        return aioredis.from_url(_REDIS_URL, decode_responses=True)
    except Exception as exc:
        logger.warning("Redis unavailable — falling back to in-process WS broadcast: %s", exc)
        return None


class ConnectionManager:
    def __init__(self):
        self._rooms: dict[str, set[WebSocket]] = {}
        # ws → {name, note_id, pid, conn_id}
        self._users: dict[WebSocket, dict] = {}
        self._redis = None
        self._subscriber_task: asyncio.Task | None = None
        self._subscribed_pids: set[str] = set()
        self._sub_lock = asyncio.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def startup(self):
        self._redis = _get_redis()
        if self._redis:
            try:
                await self._redis.ping()
                logger.info("WebSocket manager connected to Redis at %s", _REDIS_URL)
                self._subscriber_task = asyncio.create_task(self._redis_listener())
            except Exception as exc:
                logger.warning("Redis ping failed — in-process only: %s", exc)
                self._redis = None

    async def shutdown(self):
        if self._subscriber_task:
            self._subscriber_task.cancel()
        if self._redis:
            await self._redis.aclose()

    # ── Connection lifecycle ──────────────────────────────────────────────────

    async def connect(
        self,
        ws: WebSocket,
        pid: str,
        name: str,
        permissions: frozenset[str] | None = None,
        is_global_admin: bool = False,
    ):
        await ws.accept()
        conn_id = str(uuid.uuid4())
        self._rooms.setdefault(pid, set()).add(ws)
        self._users[ws] = {
            "name": name or "Anonymous",
            "note_id": None,
            "pid": pid,
            "conn_id": conn_id,
            "permissions": permissions or frozenset(),
            "is_global_admin": is_global_admin,
        }
        await self._ensure_subscribed(pid)
        await self._presence_add(pid, conn_id, name or "Anonymous", None)

    async def disconnect(self, ws: WebSocket, pid: str):
        info = self._users.pop(ws, {})
        conn_id = info.get("conn_id")
        room = self._rooms.get(pid, set())
        room.discard(ws)
        if not room:
            self._rooms.pop(pid, None)
        if conn_id:
            await self._presence_remove(pid, conn_id)

    async def set_focus(self, ws: WebSocket, note_id: str | None):
        info = self._users.get(ws)
        if not info:
            return
        info["note_id"] = note_id
        await self._presence_add(info["pid"], info["conn_id"], info["name"], note_id)

    # ── Presence ──────────────────────────────────────────────────────────────

    async def get_presence(self, pid: str) -> list:
        if self._redis:
            try:
                import time as _time

                raw = await self._redis.hgetall(f"presence:{pid}")
                cutoff = _time.time() - _PRESENCE_STALE_SECONDS
                # Lazy cleanup: stale entries are ghosts from previous restarts
                # or abrupt disconnects that never triggered _presence_remove.
                result, stale_fields = _parse_presence_raw(raw, cutoff)
                if stale_fields:
                    try:
                        await self._redis.hdel(f"presence:{pid}", *stale_fields)
                    except Exception as e:
                        logger.debug("presence stale-cleanup hdel failed (pid=%s): %s", pid, e)
                return result
            except Exception as e:
                logger.debug("redis get_presence failed (pid=%s), using local: %s", pid, e)
        # fallback: local only
        return [
            {"name": u["name"], "note_id": u["note_id"]}
            for u in self._users.values()
            if u["pid"] == pid
        ]

    def get_all_online(self) -> list[str]:
        return list({u["name"] for u in self._users.values()})

    async def _presence_add(self, pid: str, conn_id: str, name: str, note_id: str | None):
        if self._redis:
            try:
                import time as _time

                payload = json.dumps(
                    {
                        "name": name,
                        "note_id": note_id,
                        "last_seen": _time.time(),
                    }
                )
                await self._redis.hset(f"presence:{pid}", conn_id, payload)
                await self._redis.expire(f"presence:{pid}", 3600)
            except Exception as e:
                logger.debug("redis presence_add failed (pid=%s): %s", pid, e)

    async def _presence_remove(self, pid: str, conn_id: str):
        if self._redis:
            try:
                await self._redis.hdel(f"presence:{pid}", conn_id)
            except Exception as e:
                logger.debug("redis presence_remove failed (pid=%s): %s", pid, e)

    async def touch_presence(self, ws: WebSocket):
        """Refresh last_seen on the keepalive ping — drives lazy cleanup."""
        info = self._users.get(ws)
        if not info:
            return
        await self._presence_add(info["pid"], info["conn_id"], info["name"], info.get("note_id"))

    # ── Broadcast ─────────────────────────────────────────────────────────────

    async def broadcast(self, pid: str, msg: dict[str, Any], exclude: WebSocket | None = None):
        """Publish to Redis (all instances) and also deliver locally."""
        if self._redis:
            try:
                await self._redis.publish(f"ws:{pid}", json.dumps(msg))
                return  # _redis_listener will deliver locally
            except Exception as e:
                logger.debug("redis publish failed (pid=%s), broadcasting locally: %s", pid, e)
        # fallback or Redis publish failed — deliver in-process
        await self._local_broadcast(pid, msg, exclude)

    async def broadcast_presence(self, pid: str):
        presence = await self.get_presence(pid)
        await self.broadcast(pid, {"type": "presence", "users": presence})

    async def _local_broadcast(
        self, pid: str, msg: dict[str, Any], exclude: WebSocket | None = None
    ):
        dead: set[WebSocket] = set()
        policy = _policy_for(msg)
        # plain_cache[0] lazily holds serialized msg for recipients who get
        # the unredacted payload — avoids re-serializing on every iteration.
        plain_cache: list = [None]
        for ws in self._rooms.get(pid, set()):
            if ws is exclude:
                continue
            info = self._users.get(ws) or {}
            permissions: frozenset[str] = info.get("permissions") or frozenset()
            is_global_admin: bool = bool(info.get("is_global_admin"))
            send_msg = _resolve_send_msg(msg, policy, permissions, is_global_admin)
            if send_msg is None:
                continue
            try:
                await ws.send_text(_get_ws_text(send_msg, msg, plain_cache))
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._rooms.get(pid, set()).discard(ws)
            info = self._users.pop(ws, {})
            conn_id = info.get("conn_id")
            if conn_id:
                await self._presence_remove(pid, conn_id)

    # ── Redis subscription listener ───────────────────────────────────────────

    async def _ensure_subscribed(self, pid: str):
        """Subscribe to Redis channel for this pid if not already subscribed."""
        if not self._redis:
            return
        async with self._sub_lock:
            self._subscribed_pids.add(pid)

    async def _handle_pubsub_message(self, message: dict) -> None:
        if message["type"] != "pmessage":
            return
        channel: str = message["channel"]
        pid = channel.removeprefix("ws:")
        if pid not in self._rooms:
            return
        try:
            msg = json.loads(message["data"])
        except Exception:
            return
        await self._local_broadcast(pid, msg)

    async def _redis_listener(self):
        """Long-running task: listen on Redis pub/sub and forward to local WS.

        Restarts automatically on any connection error using exponential backoff
        (1 s → 2 s → … → 60 s cap) so a transient Redis blip doesn't silence
        WebSocket broadcasts permanently.
        """
        if not self._redis:
            return

        import redis.asyncio as aioredis

        backoff = 1.0
        while True:
            sub_client = None
            try:
                sub_client = aioredis.from_url(_REDIS_URL, decode_responses=True)
                pubsub = sub_client.pubsub()
                await pubsub.psubscribe("ws:*")
                logger.info("Redis pub/sub listener started (pattern ws:*)")
                backoff = 1.0

                async for message in pubsub.listen():
                    await self._handle_pubsub_message(message)

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "Redis pub/sub listener crashed: %s — restarting in %.0fs", exc, backoff
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
            finally:
                if sub_client is not None:
                    try:
                        await sub_client.aclose()
                    except Exception as e:
                        logger.debug("redis sub_client close failed: %s", e)


manager = ConnectionManager()
