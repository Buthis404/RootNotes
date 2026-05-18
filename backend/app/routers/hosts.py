import ipaddress
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Optional

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.network_data import sync_host_to_nodes
from ..core.utils import new_id, normalize_domain, ts_now
from ..core.deps import get_current_user, is_admin
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


@router.get("", response_model=list[schemas.Host])
def list_hosts(
    response: Response,
    pid: str | None = None,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        check_pid_access(db, pid, user, "hosts.read")
        q = db.query(models.Host).filter(models.Host.pid == pid)
    elif is_admin(user):
        q = db.query(models.Host)
    else:
        member_pids = get_user_member_pids(db, user)
        q = db.query(models.Host).filter(models.Host.pid.in_(member_pids))
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    hosts = q.offset(offset).limit(limit).all()
    return [schemas.Host.model_validate(h) for h in hosts]


@router.post("", response_model=schemas.Host, status_code=201)
def create_host(body: schemas.HostCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "hosts.create")
    payload = body.model_dump()
    payload["domain"] = normalize_domain(payload.get("domain", ""))
    payload["role"] = payload.get("role") or "unknown"
    payload["is_attacker"] = bool(payload.get("is_attacker")) or payload["role"] == "attacker"
    if payload["is_attacker"]:
        payload["status"] = "attacker"
    host = models.Host(id=new_id("hst"), **payload)
    db.add(host)
    label = f"Host added: {host.ip}" + (f" ({host.hostname})" if host.hostname else "")
    log_event(db, host.pid, getattr(request.state, "username", None), "host", "create", label, {"ip": host.ip})
    db.commit()
    db.refresh(host)
    h = schemas.Host.model_validate(host)
    bcast(host.pid, "host", "create", h.model_dump())
    return host


@router.patch("/{hid}", response_model=schemas.Host)
def update_host(hid: str, body: schemas.HostUpdate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_object_access(db, host.pid, user, "hosts.update")
    old_status = host.status
    updates = body.model_dump(exclude_none=True)
    if "domain" in updates:
        updates["domain"] = normalize_domain(updates.get("domain", ""))
    if "role" in updates and updates["role"] == "attacker":
        updates["is_attacker"] = True
        updates["status"] = "attacker"
    if updates.get("is_attacker") is True:
        updates["role"] = "attacker"
        updates["status"] = "attacker"
    for k, v in updates.items():
        setattr(host, k, v)
    if body.status is not None and body.status != old_status:
        # Reversible event — Timeline UI surfaces an "Undo" button.
        log_event(
            db, host.pid, getattr(request.state, "username", None), "host", "status",
            f"Host {host.ip} status → {host.status}",
            {
                "ip": host.ip, "old": old_status, "new": host.status,
                "reversible": True,
                "undo": {"entity": "host", "id": host.id, "type": "patch", "patch": {"status": old_status}},
            },
        )
    ts = ts_now()
    node_payloads = sync_host_to_nodes(host, db, ts=ts)
    db.commit()
    db.refresh(host)
    h = schemas.Host.model_validate(host)
    bcast(host.pid, "host", "update", h.model_dump())
    # Live-update mirrored network nodes (status badges, role icons, etc.)
    for payload in node_payloads:
        bcast(host.pid, "network", "node_updated", {"network_id": payload.pop("network_id", ""), "node": payload})
    return host


@router.delete("/{hid}", status_code=204)
def delete_host(hid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_object_access(db, host.pid, user, "hosts.delete")
    pid = host.pid
    log_event(db, pid, getattr(request.state, "username", None), "host", "delete", f"Host deleted: {host.ip}", {"ip": host.ip})
    db.delete(host)
    db.commit()
    bcast(pid, "host", "delete", {"id": hid})


class BulkHostImportBody(BaseModel):
    pid: str
    text: str
    tags: List[str] = []
    os: str = "Linux"
    status: str = "unknown"


def _expand_ips(text: str) -> list[str]:
    ips = []
    seen = set()
    for token in re.split(r"[\s,;]+", text):
        token = token.strip()
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            for addr in net.hosts():
                s = str(addr)
                if s not in seen:
                    seen.add(s)
                    ips.append(s)
        except ValueError:
            # Try plain IP
            try:
                ipaddress.ip_address(token)
                if token not in seen:
                    seen.add(token)
                    ips.append(token)
            except ValueError:
                pass
    return ips



@router.post("/bulk", status_code=201)
def bulk_import_hosts(body: BulkHostImportBody, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "hosts.create")
    ips = _expand_ips(body.text)
    if not ips:
        raise HTTPException(400, "No valid IPs or CIDR ranges found in input")

    existing_ips = {h.ip for h in db.query(models.Host).filter(models.Host.pid == body.pid).all()}
    username = getattr(request.state, "username", None)
    created = []
    skipped = 0

    from datetime import datetime
    ts = ts_now()

    for ip in ips:
        if ip in existing_ips:
            skipped += 1
            continue
        host = models.Host(
            id=new_id("hst"),
            pid=body.pid,
            ip=ip,
            os=body.os,
            status=body.status,
            tags=body.tags,
        )
        db.add(host)
        existing_ips.add(ip)
        created.append(host)

    if created:
        log_event(db, body.pid, username, "host", "bulk_import", f"Bulk import: {len(created)} hosts added", {"count": len(created)})
    db.commit()

    result = []
    for host in created:
        db.refresh(host)
        h = schemas.Host.model_validate(host)
        bcast(body.pid, "host", "create", h.model_dump())
        result.append(h.model_dump())

    return {"created": len(created), "skipped": skipped, "hosts": result}
