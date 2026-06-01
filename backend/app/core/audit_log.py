"""
Audit log hardening (B9-4).

Three independent persistence channels for timeline_events:

1. DB row (existing) — mutable by DB admin; primary query source.
2. Append-only JSONL file — written with O_APPEND; survives DB row deletion
   and produces a paper trail that can be compared against live DB rows.
3. Optional S3/Minio forward — enabled by AUDIT_S3_BUCKET; uploads each
   event as an individual object.  With S3 Object Lock (WORM mode) on the
   bucket the objects become immutable.

HMAC integrity:
  When AUDIT_INTEGRITY_KEY is set, every event gets a sha256= fingerprint
  over its canonical fields (id, pid, entity, action, label, ts).  The
  /api/admin/audit/verify endpoint uses this to detect in-DB tampering.

Environment variables
  AUDIT_INTEGRITY_KEY      — HMAC secret; generate with: openssl rand -hex 32
  AUDIT_LOG_DIR            — directory for the JSONL file (default: UPLOAD_ROOT/audit)
  AUDIT_S3_BUCKET          — S3/Minio bucket name; enables S3 forwarding when set
  AUDIT_S3_PREFIX          — object key prefix (default: "timeline/")
  AWS_ACCESS_KEY_ID        — standard boto3 credentials
  AWS_SECRET_ACCESS_KEY    — standard boto3 credentials
  AWS_DEFAULT_REGION       — standard boto3 region
  AUDIT_S3_ENDPOINT_URL    — override for Minio / S3-compatible stores
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_INTEGRITY_KEY = os.environ.get("AUDIT_INTEGRITY_KEY", "")
_UPLOAD_ROOT = os.environ.get("UPLOAD_ROOT", "/data/uploads")
_LOG_DIR = os.environ.get("AUDIT_LOG_DIR", str(Path(_UPLOAD_ROOT) / "audit"))
_S3_BUCKET = os.environ.get("AUDIT_S3_BUCKET", "")
_S3_PREFIX = os.environ.get("AUDIT_S3_PREFIX", "timeline/")
_S3_ENDPOINT = os.environ.get("AUDIT_S3_ENDPOINT_URL", "")

_file_lock = threading.Lock()

# Canonical fields included in the integrity hash — order matters.
_INTEGRITY_FIELDS = ("id", "pid", "entity", "action", "label", "ts")


# ── HMAC integrity ────────────────────────────────────────────────────────────


def compute_integrity(event: dict[str, Any]) -> str | None:
    """Return 'sha256=<hex>' HMAC or None if AUDIT_INTEGRITY_KEY is unset."""
    if not _INTEGRITY_KEY:
        return None
    canonical = "|".join(str(event.get(f, "")) for f in _INTEGRITY_FIELDS)
    digest = hmac.new(_INTEGRITY_KEY.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_integrity(event: dict[str, Any]) -> bool | None:
    """
    Return True if stored integrity matches computed value.
    Return None if AUDIT_INTEGRITY_KEY is unset or event has no integrity field.
    Return False if tampering is detected.
    """
    if not _INTEGRITY_KEY:
        return None
    stored = event.get("integrity")
    if not stored:
        return None
    expected = compute_integrity(event)
    return hmac.compare_digest(stored, expected) if expected else None


# ── Append-only file log ──────────────────────────────────────────────────────


def _ensure_log_dir() -> Path:
    d = Path(_LOG_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def append_to_file(event: dict[str, Any]) -> None:
    """Append one JSON line to the audit log file (thread-safe, O_APPEND)."""
    try:
        log_dir = _ensure_log_dir()
        log_path = log_dir / "timeline.jsonl"
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        with _file_lock:
            # 'a' mode → O_WRONLY|O_CREAT|O_APPEND on POSIX
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception as exc:
        logger.error("audit_log: failed to write to file: %s", exc)


# ── S3 / Minio forward ────────────────────────────────────────────────────────


def _get_s3_client():
    """Return a boto3 S3 client, or None if boto3 is not installed."""
    try:
        import boto3  # type: ignore[import]

        kwargs: dict[str, Any] = {}
        if _S3_ENDPOINT:
            kwargs["endpoint_url"] = _S3_ENDPOINT
        return boto3.client("s3", **kwargs)
    except ImportError:
        logger.warning(
            "AUDIT_S3_BUCKET is set but boto3 is not installed — S3 audit forwarding disabled. Install boto3 to enable."
        )
        return None
    except Exception as exc:
        logger.error("audit_log: failed to create S3 client: %s", exc)
        return None


_s3_client = None
_s3_init_lock = threading.Lock()


def _s3() -> Any:
    global _s3_client
    if _s3_client is None:
        with _s3_init_lock:
            if _s3_client is None:
                _s3_client = _get_s3_client()
    return _s3_client


def forward_to_s3(event: dict[str, Any]) -> None:
    """Upload event as a JSON object to S3/Minio (best-effort, never raises)."""
    if not _S3_BUCKET:
        return
    try:
        client = _s3()
        if client is None:
            return
        eid = event.get("id", "unknown")
        ts = (event.get("ts") or "")[:10]  # YYYY-MM-DD
        key = f"{_S3_PREFIX}{ts}/{eid}.json"
        body = json.dumps(event, ensure_ascii=False, indent=2).encode()
        client.put_object(
            Bucket=_S3_BUCKET,
            Key=key,
            Body=body,
            ContentType="application/json",
        )
    except Exception as exc:
        logger.error("audit_log: S3 forward failed for event %s: %s", event.get("id"), exc)


# ── Public entry point ────────────────────────────────────────────────────────


def persist(event: dict[str, Any]) -> None:
    """Write event to all configured channels (file always; S3 if configured)."""
    append_to_file(event)
    if _S3_BUCKET:
        forward_to_s3(event)
