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
    "cred": {"username", "domain", "service"},
    "finding": {"status", "severity"},
}

# Entity types whose newly-created rows can be undone by delete.
_UNDO_DELETABLE_ENTITIES: set[str] = {
    "host_activity",  # batch-created by bulk_exec
    "cred",           # enriched creds picked up from bulk_exec output
    "host",           # rare: newly discovered hosts during bulk_exec
}

# Soft cap on operations per batch — prevents pathological undo payloads from
# bloating TimelineEvent.meta and timing out the rollback transaction.
_BATCH_UNDO_MAX_OPERATIONS = 1000


def _apply_undo_op(db: Session, pid: str, op: dict) -> dict:
    """Apply one undo operation. Returns a small audit-trail entry."""
    entity = (op.get("entity") or "").lower()
    op_type = (op.get("type") or "").lower()
    target_id = op.get("id")
    if not target_id:
        raise HTTPException(400, f"Undo op missing id: {op}")

    model_map = {
        "host": models.Host,
        "host_activity": models.HostActivity,
        "cred": models.Cred,
        "finding": models.Finding,
    }
    model_cls = model_map.get(entity)
    if not model_cls:
        raise HTTPException(400, f"Undo op references unsupported entity {entity!r}")

    if op_type == "delete":
        if entity not in _UNDO_DELETABLE_ENTITIES:
            raise HTTPException(400, f"Undo delete not allowed for {entity!r}")
        row = db.query(model_cls).filter(model_cls.id == target_id, model_cls.pid == pid).first()
        if row is not None:
            db.delete(row)
            bcast(pid, entity, "delete", {"id": target_id})
            return {"entity": entity, "id": target_id, "action": "deleted"}
        return {"entity": entity, "id": target_id, "action": "missing"}

    if op_type == "patch":
        allowed = _UNDO_ALLOWED_PATCH_FIELDS.get(entity)
        if not allowed:
            raise HTTPException(400, f"Undo patch not allowed for {entity!r}")
        patch = op.get("patch") or {}
        bad = [k for k in patch if k not in allowed]
        if bad:
            raise HTTPException(400, f"Undo patch forbidden fields for {entity!r}: {bad}")
        row = db.query(model_cls).filter(model_cls.id == target_id, model_cls.pid == pid).first()
        if row is None:
            return {"entity": entity, "id": target_id, "action": "missing"}
        before = {k: getattr(row, k) for k in patch.keys()}
        for k, v in patch.items():
            setattr(row, k, v)
        bcast(pid, entity, "update", {"id": target_id, **{k: getattr(row, k) for k in patch.keys()}})
        return {"entity": entity, "id": target_id, "action": "patched", "before": before, "patch": patch}

    raise HTTPException(400, f"Unsupported undo op type: {op_type!r}")


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
    undo_type = (undo.get("type") or "").lower()

    if undo_type in ("patch", "delete"):
        # Single-op undo (host status change, etc.)
        applied = [_apply_undo_op(db, event.pid, undo)]
    elif undo_type == "batch":
        operations = undo.get("operations") or []
        if not isinstance(operations, list) or not operations:
            raise HTTPException(400, "Batch undo payload missing operations[]")
        if len(operations) > _BATCH_UNDO_MAX_OPERATIONS:
            raise HTTPException(400, f"Batch too large: {len(operations)} > {_BATCH_UNDO_MAX_OPERATIONS}")
        applied = [_apply_undo_op(db, event.pid, op) for op in operations]
    else:
        raise HTTPException(400, f"Unsupported undo type: {undo_type!r}")

    # Mark the source event as consumed so it can't be replayed
    meta["undone_at"] = _now_str()
    meta["undone_by"] = getattr(user, "username", "") or ""
    event.meta = meta

    # New audit entry — intentionally NOT reversible
    log_event(
        db, event.pid, getattr(user, "username", None),
        "audit", "timeline_undo",
        f"Reverted {len(applied)} change(s) from event {event.id}",
        {
            "source_event_id": event.id, "undo_type": undo_type,
            "operations_applied": len(applied),
            "applied": applied[:50],  # cap echo in audit meta
        },
    )
    db.commit()
    bcast(event.pid, "timeline", "update", schemas.TimelineEvent.model_validate(event).model_dump())

    return {"ok": True, "undo_type": undo_type, "operations_applied": len(applied)}


def _now_str() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
