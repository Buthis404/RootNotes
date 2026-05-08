import asyncio
from datetime import datetime
from sqlalchemy.orm import Session

from .. import models
from .utils import new_id
from ..ws import manager


def log_event(
    db: Session,
    pid: str,
    username: str | None,
    entity: str,
    action: str,
    label: str,
    meta: dict | None = None,
):
    db.add(models.TimelineEvent(
        id=new_id("evt"),
        pid=pid,
        username=username,
        entity=entity,
        action=action,
        label=label,
        meta=meta or {},
        ts=datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
    ))


def bcast(pid: str, entity: str, action: str, data: dict, ws=None):
    """Fire-and-forget WebSocket broadcast from sync endpoints."""
    msg = {"pid": pid, "entity": entity, "action": action, "data": data}
    try:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(asyncio.ensure_future, manager.broadcast(pid, msg, exclude=ws))
    except RuntimeError:
        pass
