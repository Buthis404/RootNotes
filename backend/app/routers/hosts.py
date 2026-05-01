from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.utils import new_id, normalize_domain
from ..core.deps import get_current_user
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


@router.get("", response_model=list[schemas.Host])
def list_hosts(
    pid: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        check_pid_access(db, pid, user, "hosts.read")
        return [schemas.Host.model_validate(h) for h in db.query(models.Host).filter(models.Host.pid == pid).all()]
    if user.role == "admin":
        return [schemas.Host.model_validate(h) for h in db.query(models.Host).all()]
    member_pids = get_user_member_pids(db, user)
    return [schemas.Host.model_validate(h) for h in db.query(models.Host).filter(models.Host.pid.in_(member_pids)).all()]


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
        log_event(
            db, host.pid, getattr(request.state, "username", None), "host", "status",
            f"Host {host.ip} status → {host.status}", {"ip": host.ip, "old": old_status, "new": host.status},
        )
    db.commit()
    db.refresh(host)
    h = schemas.Host.model_validate(host)
    bcast(host.pid, "host", "update", h.model_dump())
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
