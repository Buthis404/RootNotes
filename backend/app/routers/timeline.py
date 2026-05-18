from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.deps import get_current_user, is_admin
from ..core.access import check_pid_access
from ..core.events import bcast, log_event

router = APIRouter(prefix="/api/timeline", tags=["timeline"])


@router.get("", response_model=list[schemas.TimelineEvent])
def get_timeline(pid: str, entity: str | None = None, limit: int = 200, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, pid, user, "timeline.read")
    q = db.query(models.TimelineEvent).filter(models.TimelineEvent.pid == pid)
    if entity:
        q = q.filter(models.TimelineEvent.entity == entity)
    return q.order_by(models.TimelineEvent.ts.desc()).limit(limit).all()


# ── Reversible event undo (P8) ────────────────────────────────────────────

# Supported undo entity types and the fields the user is allowed to patch
# back via the undo endpoint. Tight allow-list so a forged event payload
# can't be used to flip arbitrary columns.
_UNDO_ALLOWED_PATCH_FIELDS: dict[str, set[str]] = {
    "host": {"status", "role", "hostname", "os", "is_attacker"},
}


@router.post("/{event_id}/undo")
def undo_event(event_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Reverse a TimelineEvent whose meta carries a reversible undo payload.

    Currently supports `host` patches — restoring the prior status/role/etc.
    Writes a new TimelineEvent marking the undo (not itself undoable) so
    the audit trail captures who reversed what.
    """
    event = db.query(models.TimelineEvent).filter(models.TimelineEvent.id == event_id).first()
    if not event:
        raise HTTPException(404, "Timeline event not found")

    check_pid_access(db, event.pid, user, "hosts.update")

    meta = dict(event.meta or {})
    if not meta.get("reversible"):
        raise HTTPException(400, "This event is not marked reversible")
    if meta.get("undone_at"):
        raise HTTPException(400, "This event has already been undone")

    undo = meta.get("undo") or {}
    entity = (undo.get("entity") or "").lower()
    undo_type = (undo.get("type") or "").lower()
    target_id = undo.get("id")
    patch = undo.get("patch") or {}

    if undo_type != "patch":
        raise HTTPException(400, f"Unsupported undo type: {undo_type!r}")
    if entity not in _UNDO_ALLOWED_PATCH_FIELDS:
        raise HTTPException(400, f"Undo not supported for entity {entity!r}")
    if not target_id or not isinstance(patch, dict) or not patch:
        raise HTTPException(400, "Undo payload missing id / patch fields")

    allowed = _UNDO_ALLOWED_PATCH_FIELDS[entity]
    bad = [k for k in patch if k not in allowed]
    if bad:
        raise HTTPException(400, f"Undo patch carries forbidden fields: {bad}")

    if entity == "host":
        host = db.query(models.Host).filter(
            models.Host.id == target_id, models.Host.pid == event.pid
        ).first()
        if not host:
            raise HTTPException(404, "Target host not found in project")
        # Apply the patch
        before = {k: getattr(host, k) for k in patch.keys()}
        for k, v in patch.items():
            setattr(host, k, v)

        # Mark the original event as consumed so it can't be replayed
        meta["undone_at"] = _now_str()
        meta["undone_by"] = getattr(user, "username", "") or ""
        event.meta = meta

        # New audit entry for the undo itself — intentionally NOT reversible
        log_event(
            db, event.pid, getattr(user, "username", None),
            "audit", "timeline_undo",
            f"Undid host status change on {host.ip or host.id}",
            {
                "source_event_id": event.id, "entity": entity,
                "target_id": target_id, "applied_patch": patch, "before": before,
            },
        )
        db.commit()
        db.refresh(host)

        # Broadcast updated entity
        bcast(event.pid, "host", "update", schemas.Host.model_validate(host).model_dump())
        bcast(event.pid, "timeline", "update", schemas.TimelineEvent.model_validate(event).model_dump())

        return {"ok": True, "entity": entity, "id": target_id, "patch": patch}

    raise HTTPException(400, f"Undo for entity {entity!r} reached the catch-all branch")


def _now_str() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
