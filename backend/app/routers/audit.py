"""
Audit log integrity verification (B9-4).

GET /api/admin/audit/verify   — scan timeline_events and compare HMAC
                                 fingerprints; report tampered / unverified rows
                                 and cross-reference against the JSONL file.
GET /api/admin/audit/status   — quick summary: key configured, counts, log file
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import models
from ..core.audit_log import (
    _INTEGRITY_KEY,
    _LOG_DIR,
    _S3_BUCKET,
    verify_integrity,
)
from ..core.deps import require_admin
from ..database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/admin/audit", tags=["audit"])

_UPLOAD_ROOT = os.environ.get("UPLOAD_ROOT", "/data/uploads")


def _parse_audit_log_line(line: str) -> dict | None:
    stripped = line.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _cross_reference_file_ids(log_path: Path, pid: str | None, db_ids: set[str]) -> list[str]:
    file_only: list[str] = []
    try:
        with open(log_path, encoding="utf-8") as fh:
            for line in fh:
                rec = _parse_audit_log_line(line)
                if rec is None:
                    continue
                if pid and rec.get("pid", "") != pid:
                    continue
                rec_id = rec.get("id", "")
                if rec_id and rec_id not in db_ids:
                    file_only.append(rec_id)
    except Exception as exc:
        logger.error("audit verify: failed to read JSONL file: %s", exc)
    return file_only


@router.get("/status")
def audit_status(admin: Annotated[models.User, Depends(require_admin)], db: Annotated[Session, Depends(get_db)]):
    """Return current audit hardening configuration and quick counts."""
    log_path = Path(_LOG_DIR) / "timeline.jsonl"
    file_lines: int | None = None
    if log_path.exists():
        try:
            with open(log_path, encoding="utf-8") as fh:
                file_lines = sum(1 for _ in fh)
        except Exception:
            file_lines = -1

    db_count: int = db.query(models.TimelineEvent).count()
    signed_count: int = (
        db.query(models.TimelineEvent).filter(models.TimelineEvent.integrity.isnot(None)).count()
    )

    return {
        "integrity_key_configured": bool(_INTEGRITY_KEY),
        "s3_bucket_configured": bool(_S3_BUCKET),
        "s3_bucket": _S3_BUCKET or None,
        "log_file": str(log_path),
        "log_file_exists": log_path.exists(),
        "log_file_lines": file_lines,
        "db_event_count": db_count,
        "db_signed_event_count": signed_count,
        "db_unsigned_event_count": db_count - signed_count,
    }


@router.get("/verify")
def audit_verify(
    admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
    pid: Annotated[str | None, Query(description="Limit to a project; omit for all")] = None,
    limit: Annotated[int, Query(ge=1, le=50000)] = 1000,
):
    """
    Scan timeline_events rows and verify HMAC integrity fingerprints.

    Returns:
      ok           — True if every checked row passes (or no key is configured)
      checked      — number of rows examined
      tampered     — list of event IDs whose stored hash doesn't match computed value
      unverified   — count of rows with no integrity field (created before B9-4)
      file_only    — event IDs present in the JSONL file but missing from the DB
                     (indicates a row was deleted after the event was logged)
    """
    if not _INTEGRITY_KEY:
        return {
            "ok": True,
            "note": "AUDIT_INTEGRITY_KEY is not configured — integrity verification is disabled",
            "checked": 0,
            "tampered": [],
            "unverified": 0,
            "file_only": [],
        }

    q = db.query(models.TimelineEvent)
    if pid:
        q = q.filter(models.TimelineEvent.pid == pid)
    events = q.order_by(models.TimelineEvent.ts.desc()).limit(limit).all()

    tampered: list[str] = []
    unverified = 0
    db_ids: set[str] = set()

    for evt in events:
        db_ids.add(evt.id)
        ev_dict: dict[str, Any] = {
            "id": evt.id,
            "pid": evt.pid,
            "entity": evt.entity,
            "action": evt.action,
            "label": evt.label,
            "ts": evt.ts,
            "integrity": evt.integrity,
        }
        result = verify_integrity(ev_dict)
        if result is None:
            unverified += 1
        elif result is False:
            tampered.append(evt.id)

    log_path = Path(_LOG_DIR) / "timeline.jsonl"
    file_only = _cross_reference_file_ids(log_path, pid, db_ids) if log_path.exists() else []

    return {
        "ok": len(tampered) == 0 and len(file_only) == 0,
        "checked": len(events),
        "tampered": tampered,
        "unverified": unverified,
        "file_only": file_only[:200],  # cap list size in response
        "file_only_count": len(file_only),
    }
