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

logger = logging.getLogger(__name__)

_REDIS_URL = os.environ.get("REDIS_URL", "")


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
    "cred":           {"read": "credentials.read", "redact": [("secret", "credentials.read_secret")]},
    "host":           {"read": "hosts.read"},
    "host_activity":  {"read": "hosts.read"},
    "finding":        {"read": "findings.read"},
    "note":           {"read": "notes.read"},
    "loot":           {"read": "loot.read"},
    "scope":          {"read": "scopes.read"},
    "attack_path":    {"read": "attack_paths.read"},
    "objective":      {"read": "objectives.read"},
    "checklist":      {"read": "checklist.read"},
    "timeline":       {"read": "timeline.read"},
    "command_output": {"read": "command_outputs.read"},
    "job":            {"read": "command_outputs.read"},
    "network_node":   {"read": "network.read"},
    "network_link":   {"read": "network.read"},
    "network":        {"read": "network.read"},
}


def _policy_for(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Return the policy entry for a message, or None for default-open."""
    if msg.get("type") == "presence":
        return {"public": True}
    entity = (msg.get("entity") or "").strip()
    return _ENTITY_POLICY.get(entity)


def _redact_payload(msg: dict[str, Any], policy: dict[str, Any], permissions: frozenset[str]) -> dict[str, Any]:
    """Return a (possibly shallow-copied) message with sensitive fields stripped."""
    redact = policy.get("redact") or []
    if not redact or "data" not in msg or not isinstance(msg["data"], dict):
        return msg
    needs_redact = any(perm not in permissions for _, perm in redact)
    if not needs_redact:
        return msg
    redacted_data = dict(msg["data"])
    for field, perm in redact:
        if perm not in permissions and field in redacted_data:
            redacted_data[field] = ""
    return {**msg, "data": redacted_data}


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

    async def connect(self, ws: WebSocket, pid: str, name: str, permissions: frozenset[str] | None = None, is_global_admin: bool = False):
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
                raw = await self._redis.hgetall(f"presence:{pid}")
                result = []
                for v in raw.values():
                    try:
                        result.append(json.loads(v))
                    except Exception:
                        pass
                return result
            except Exception:
                pass
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
                payload = json.dumps({"name": name, "note_id": note_id})
                await self._redis.hset(f"presence:{pid}", conn_id, payload)
                await self._redis.expire(f"presence:{pid}", 3600)
            except Exception:
                pass

    async def _presence_remove(self, pid: str, conn_id: str):
        if self._redis:
            try:
                await self._redis.hdel(f"presence:{pid}", conn_id)
            except Exception:
                pass

    # ── Broadcast ─────────────────────────────────────────────────────────────

    async def broadcast(self, pid: str, msg: dict[str, Any], exclude: WebSocket | None = None):
        """Publish to Redis (all instances) and also deliver locally."""
        if self._redis:
            try:
                await self._redis.publish(f"ws:{pid}", json.dumps(msg))
                return  # _redis_listener will deliver locally
            except Exception:
                pass
        # fallback or Redis publish failed — deliver in-process
        await self._local_broadcast(pid, msg, exclude)

    async def broadcast_presence(self, pid: str):
        presence = await self.get_presence(pid)
        await self.broadcast(pid, {"type": "presence", "users": presence})

    async def _local_broadcast(self, pid: str, msg: dict[str, Any], exclude: WebSocket | None = None):
        dead: set[WebSocket] = set()
        policy = _policy_for(msg)
        plain_text: str | None = None  # cache the unredacted serialization
        for ws in list(self._rooms.get(pid, set())):
            if ws is exclude:
                continue
            info = self._users.get(ws) or {}
            permissions: frozenset[str] = info.get("permissions") or frozenset()
            is_global_admin: bool = bool(info.get("is_global_admin"))

            if policy and not policy.get("public") and not is_global_admin:
                required = policy.get("read")
                if required and required not in permissions:
                    continue  # recipient lacks the entity read permission
                send_msg = _redact_payload(msg, policy, permissions)
            else:
                send_msg = msg

            try:
                # Serialize lazily — most recipients get the same payload, redaction
                # is only different for those missing a redact-permission.
                if send_msg is msg:
                    if plain_text is None:
                        plain_text = json.dumps(msg)
                    text = plain_text
                else:
                    text = json.dumps(send_msg)
                await ws.send_text(text)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._rooms.get(pid, set()).discard(ws)

    # ── Redis subscription listener ───────────────────────────────────────────

    async def _ensure_subscribed(self, pid: str):
        """Subscribe to Redis channel for this pid if not already subscribed."""
        if not self._redis:
            return
        async with self._sub_lock:
            self._subscribed_pids.add(pid)

    async def _redis_listener(self):
        """Long-running task: listen on Redis pub/sub and forward to local WS."""
        if not self._redis:
            return
        # Use a dedicated connection for pub/sub
        try:
            import redis.asyncio as aioredis
            sub_client = aioredis.from_url(_REDIS_URL, decode_responses=True)
            pubsub = sub_client.pubsub()

            # Subscribe to a pattern covering all project channels
            await pubsub.psubscribe("ws:*")
            logger.info("Redis pub/sub listener started (pattern ws:*)")

            async for message in pubsub.listen():
                if message["type"] != "pmessage":
                    continue
                channel: str = message["channel"]  # e.g. "ws:proj-abc"
                pid = channel.removeprefix("ws:")
                # Only forward if this instance has connections for this pid
                if pid not in self._rooms:
                    continue
                try:
                    msg = json.loads(message["data"])
                except Exception:
                    continue
                await self._local_broadcast(pid, msg)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Redis pub/sub listener crashed: %s", exc)


manager = ConnectionManager()
