"""
C2 webhook receiver. Each project gets a unique token.
POST /api/webhooks/{token} accepts events from Cobalt Strike, Sliver, Havoc, etc.
and auto-creates hosts/creds/findings.
"""

import hashlib
import hmac
import secrets
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.config import WEBHOOK_HMAC_SECRET
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast, log_event
from ..core.limiter import limiter
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(tags=["webhooks"])


# ── Project token management ──────────────────────────────────────────


@router.get("/api/projects/{pid}/webhook", responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def get_project_webhook(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    token = getattr(project, "webhook_token", None) or ""
    return {
        "token": token,
        "url": f"/api/webhooks/{token}" if token else "",
        "hmac_required": bool(WEBHOOK_HMAC_SECRET),
    }


@router.post("/api/projects/{pid}/webhook/regenerate", responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def regenerate_webhook_token(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if not is_admin(user):
        from ..core.access import check_pid_access

        check_pid_access(db, pid, user, "webhooks.manage")
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    token = secrets.token_urlsafe(24)
    project.webhook_token = token
    log_event(
        db,
        pid,
        user.username,
        "audit",
        "webhook_token_regenerated",
        f"Webhook token regenerated for project {pid}",
        {"pid": pid},
    )
    db.commit()
    return {"token": token, "url": f"/api/webhooks/{token}"}


# ── Event ingestion ───────────────────────────────────────────────────


class WebhookEvent(BaseModel):
    type: str = "beacon"
    computer: str | None = None
    hostname: str | None = None
    ip: str | None = None
    internal_ip: str | None = None
    os: str | None = None
    username: str | None = None
    domain: str | None = None
    process: str | None = None
    arch: str | None = None
    pid: int | None = None
    note: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    secret: str | None = None
    service: str | None = None
    hash: str | None = None
    source: str | None = "c2"
    meta: Any | None = None


def _find_project(db: Session, token: str) -> models.Project | None:
    return db.query(models.Project).filter(models.Project.webhook_token == token).first()


def _verify_hmac(request: Request, body: bytes) -> bool:
    """Verify X-Hub-Signature-256 if WEBHOOK_HMAC_SECRET is configured."""
    if not WEBHOOK_HMAC_SECRET:
        return True
    sig_header = request.headers.get("X-Hub-Signature-256", "")
    if not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(WEBHOOK_HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)


def _maybe_create_beacon_cred(
    db: "Session", pid: str, ip: str, host_id: str, event: "WebhookEvent", results: dict
) -> None:
    if not event.username:
        return
    domain = event.domain or ""
    existing = db.query(models.Cred).filter(
        models.Cred.pid == pid, models.Cred.username == event.username, models.Cred.domain == domain,
    ).first()
    if not existing:
        db.add(models.Cred(
            id=new_id("crd"), pid=pid, username=event.username,
            secret=event.secret or event.hash or "", type="hash" if event.hash else "plain",
            domain=domain, service=event.service or "", host=ip, host_ids=[host_id], tags=["c2"],
        ))
        results["cred"] = "created"


def _handle_beacon_event(db: "Session", pid: str, ip: str, hostname: str, event: "WebhookEvent", results: dict) -> None:
    from ..core.db_upsert import upsert_host_by_ip

    host, created = upsert_host_by_ip(
        db, pid=pid, ip=ip,
        defaults={
            "hostname": hostname, "os": event.os or "", "status": "pwned",
            "tags": ["c2", event.source or "beacon"],
            "notes": f"C2 beacon — {event.source or 'unknown'}\nProcess: {event.process or ''}\nArch: {event.arch or ''}",
        },
        update_on_conflict={"status": "pwned"},
    )
    if not created:
        if hostname and not host.hostname:
            host.hostname = hostname
        if event.os and (not host.os or host.os == "Linux"):
            host.os = event.os
    results["host"] = "created" if created else "updated"
    log_event(db, pid, None, "host", "c2_beacon", f"C2 beacon: {ip} ({hostname})", {"ip": ip, "source": event.source})
    db.flush()
    _maybe_create_beacon_cred(db, pid, ip, host.id, event, results)


def _handle_cred_event(db: "Session", pid: str, ip: str, event: "WebhookEvent", results: dict) -> None:
    domain = event.domain or ""
    existing = db.query(models.Cred).filter(
        models.Cred.pid == pid, models.Cred.username == event.username, models.Cred.domain == domain,
    ).first()
    if not existing:
        db.add(models.Cred(
            id=new_id("crd"), pid=pid, username=event.username,
            secret=event.secret or event.hash or "", type="hash" if event.hash else "plain",
            domain=domain, service=event.service or "", host=ip, tags=["c2"],
        ))
        results["cred"] = "created"
    else:
        results["cred"] = "exists"


def _handle_finding_event(db: "Session", pid: str, ip: str, hostname: str, event: "WebhookEvent", results: dict, ts: str) -> None:
    title = event.title or event.note or "C2 Finding"
    severity = event.severity or "high"
    db.add(models.Finding(
        id=new_id("fnd"), pid=pid, title=title, severity=severity,
        description=event.description or event.note or "",
        proof=f"Source: {event.source or 'c2'}\nHost: {ip or hostname}",
        status="open", ts=ts,
    ))
    results["finding"] = "created"
    log_event(db, pid, None, "finding", "c2_finding", f"C2 finding: {title}", {"severity": severity})


def _broadcast_webhook_results(db: "Session", pid: str, ip: str, event: "WebhookEvent", results: dict, node_payloads: list) -> None:
    if "host" in results:
        host_obj = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
        if host_obj:
            bcast(pid, "host", "upsert", schemas.Host.model_validate(host_obj).model_dump())
    for payload in node_payloads:
        bcast(pid, "network", "node_updated", {"network_id": payload.pop("network_id", ""), "node": payload})
    if "cred" in results and results["cred"] == "created":
        cred_obj = db.query(models.Cred).filter(
            models.Cred.pid == pid, models.Cred.username == event.username,
        ).order_by(models.Cred.id.desc()).first()
        if cred_obj:
            bcast(pid, "cred", "create", schemas.Cred.model_validate(cred_obj).model_dump())


@router.post("/api/webhooks/{token}", status_code=200, responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
@limiter.limit("120/minute")
async def receive_webhook(
    request: Request,
    token: str,
    event: WebhookEvent,
    db: Annotated[Session, Depends(get_db)],
):
    body = await request.body()
    if not _verify_hmac(request, body):
        raise HTTPException(403, "Invalid webhook signature")

    project = _find_project(db, token)
    if not project:
        raise HTTPException(404, "Invalid webhook token")

    pid = project.id
    ts = ts_now()
    results: dict = {}

    ip = (event.internal_ip or event.ip or "").strip()
    hostname = (event.computer or event.hostname or "").strip()

    if event.type in ("beacon", "implant", "session", "checkin") and ip:
        _handle_beacon_event(db, pid, ip, hostname, event, results)
    elif event.type in ("cred", "credential", "hash") and event.username:
        _handle_cred_event(db, pid, ip, event, results)
    elif event.type in ("finding", "vuln", "vulnerability"):
        _handle_finding_event(db, pid, ip, hostname, event, results, ts)

    from ..core.network_data import sync_host_to_nodes as _sync_nodes
    from ..core.utils import ts_now as _ts_now

    node_payloads: list[dict] = []
    if "host" in results:
        host_obj_pre = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
        if host_obj_pre:
            node_payloads = _sync_nodes(host_obj_pre, db, ts=_ts_now())

    db.commit()
    _broadcast_webhook_results(db, pid, ip, event, results, node_payloads)
    return {"ok": True, "project_id": pid, "results": results}


@router.get("/api/webhooks/{token}", responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def check_webhook_token(token: str, db: Annotated[Session, Depends(get_db)]):
    project = _find_project(db, token)
    if not project:
        raise HTTPException(404, "Invalid token")
    return {"ok": True, "project": project.name}
