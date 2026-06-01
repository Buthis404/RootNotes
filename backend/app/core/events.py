import asyncio
import logging

from sqlalchemy.orm import Session

from .. import models
from ..ws import manager
from .audit_log import compute_integrity
from .audit_log import persist as _audit_persist
from .utils import new_id, ts_now

logger = logging.getLogger(__name__)


def log_event(
    db: Session,
    pid: str,
    username: str | None,
    entity: str,
    action: str,
    label: str,
    meta: dict | None = None,
):
    eid = new_id("evt")
    ts = ts_now()
    event_dict = {
        "id": eid,
        "pid": pid,
        "username": username,
        "entity": entity,
        "action": action,
        "label": label,
        "meta": meta or {},
        "ts": ts,
    }
    integrity = compute_integrity(event_dict)
    if integrity:
        event_dict["integrity"] = integrity

    db.add(models.TimelineEvent(**event_dict))

    # Persist to secondary channels (append-only file + optional S3).
    # Best-effort: never raise so a logging failure can't abort a DB transaction.
    try:
        _audit_persist(event_dict)
    except Exception as e:
        logger.debug("audit persist (secondary channel) failed for event %s: %s", eid, e)


def bcast(pid: str, entity: str, action: str, data: dict, ws=None):
    """Fire-and-forget WebSocket broadcast from sync endpoints."""
    msg = {"pid": pid, "entity": entity, "action": action, "data": data}
    try:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(asyncio.ensure_future, manager.broadcast(pid, msg, exclude=ws))
    except RuntimeError:
        # No running event loop (pure-sync context) — broadcast is best-effort,
        # the REST response already carries the authoritative state.
        logger.debug("bcast skipped: no running event loop (pid=%s entity=%s)", pid, entity)


def bcast_batch(pid: str, events: list[tuple[str, str, dict]], ws=None):
    """Coalesce many per-entity broadcasts into one envelope.

    Bulk imports / smart-build / batch_exec used to fire one bcast() per
    row, which means N Redis publish() round-trips + N per-connection
    iterations. Most callers don't need per-event ordering inside the
    batch — they just need everyone to learn about the same set of new
    rows. This API sends a single `{type:'batch', events:[{entity,action,data}, …]}`
    message; the frontend dispatch loop unwraps it.

    No-ops on empty input. Falls back to one bcast per event if loop is
    unavailable so writeback paths still publish even in sync contexts.
    """
    if not events:
        return
    msg = {
        "pid": pid,
        "type": "batch",
        "events": [{"entity": e, "action": a, "data": d} for (e, a, d) in events],
    }
    try:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(asyncio.ensure_future, manager.broadcast(pid, msg, exclude=ws))
    except RuntimeError:
        for e, a, d in events:
            bcast(pid, e, a, d, ws=ws)
