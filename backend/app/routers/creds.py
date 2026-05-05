from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.utils import new_id, normalize_domain, domains_match
from ..core.deps import get_current_user
from ..core.access import check_pid_access, check_object_access, get_user_member_pids
from ..core.permissions import get_membership, get_permissions_for_role

router = APIRouter(prefix="/api/creds", tags=["creds"])


def _can_read_secret(user: models.User, pid: str, db: Session) -> bool:
    if user.role == "admin":
        return True
    membership = get_membership(db, pid, user.id)
    if not membership:
        return False
    return "credentials.read_secret" in get_permissions_for_role(membership.role)


def _cred_out(cred: models.Cred, user: models.User, db: Session) -> dict:
    data = schemas.Cred.model_validate(cred).model_dump()
    if not _can_read_secret(user, cred.pid, db):
        data["secret"] = ""
    return data


def _validate_domain_host_links(pid: str, domain: str, host_ids: list[str], db: Session):
    normalized_domain = normalize_domain(domain)
    if not normalized_domain or not host_ids:
        return
    hosts = db.query(models.Host).filter(models.Host.pid == pid, models.Host.id.in_(host_ids)).all()
    by_id = {host.id: host for host in hosts}
    missing = [hid for hid in host_ids if hid not in by_id]
    if missing:
        raise HTTPException(404, f"Host not found: {missing[0]}")
    mismatched = [host for host in hosts if not domains_match(host.domain or '', normalized_domain)]
    if mismatched:
        labels = ", ".join((host.hostname or host.ip or host.id) for host in mismatched[:5])
        raise HTTPException(400, f"Domain credential cannot be linked to hosts from another domain: {labels}")


@router.get("", response_model=list[schemas.Cred])
def list_creds(
    pid: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        check_pid_access(db, pid, user, "credentials.read")
        creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    elif user.role == "admin":
        creds = db.query(models.Cred).all()
    else:
        member_pids = get_user_member_pids(db, user)
        creds = db.query(models.Cred).filter(models.Cred.pid.in_(member_pids)).all()
    return [_cred_out(c, user, db) for c in creds]


@router.post("", response_model=schemas.Cred, status_code=201)
def create_cred(body: schemas.CredCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "credentials.create")
    payload = body.model_dump()
    payload["domain"] = normalize_domain(payload.get("domain", ""))
    if payload.get("is_domain") and not payload["domain"]:
        username = payload.get("username", "") or ""
        if "@" in username:
            extracted = username.split("@", 1)[1]
            payload["domain"] = normalize_domain(extracted)
    cred = models.Cred(id=new_id("c"), **payload)
    if payload.get("is_domain"):
        _validate_domain_host_links(payload["pid"], payload.get("domain", ""), payload.get("host_ids") or [], db)
    db.add(cred)
    label = f"Cred added: {cred.username}" + (f"@{cred.host}" if cred.host else "")
    log_event(db, cred.pid, getattr(request.state, "username", None), "cred", "create", label, {"username": cred.username})
    db.commit()
    db.refresh(cred)
    bcast(cred.pid, "cred", "create", _cred_out(cred, user, db))
    return _cred_out(cred, user, db)


@router.patch("/{cid}", response_model=schemas.Cred)
def update_cred(cid: str, body: schemas.CredUpdate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
    if not cred:
        raise HTTPException(404, "Cred not found")
    check_object_access(db, cred.pid, user, "credentials.update")
    old_cracked = cred.cracked
    updates = body.model_dump(exclude_none=True)
    if "domain" in updates:
        updates["domain"] = normalize_domain(updates.get("domain", ""))
    is_becoming_domain = updates.get("is_domain", False) and not cred.is_domain
    if is_becoming_domain and "domain" not in updates and not (cred.domain or "").strip():
        username = updates.get("username") or cred.username or ""
        if "@" in username:
            extracted = username.split("@", 1)[1]
            updates["domain"] = normalize_domain(extracted)
    for k, v in updates.items():
        setattr(cred, k, v)
    if cred.is_domain:
        _validate_domain_host_links(cred.pid, cred.domain or '', cred.host_ids or [], db)
    if body.cracked is not None and body.cracked and not old_cracked:
        log_event(
            db, cred.pid, getattr(request.state, "username", None), "cred", "cracked",
            f"Cred cracked: {cred.username}", {"username": cred.username},
        )
    db.commit()
    db.refresh(cred)
    bcast(cred.pid, "cred", "update", _cred_out(cred, user, db))
    return _cred_out(cred, user, db)


@router.delete("/{cid}", status_code=204)
def delete_cred(cid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
    if not cred:
        raise HTTPException(404, "Cred not found")
    check_object_access(db, cred.pid, user, "credentials.delete")
    pid = cred.pid
    log_event(db, pid, getattr(request.state, "username", None), "cred", "delete", f"Cred deleted: {cred.username}", {"username": cred.username})
    db.delete(cred)
    db.commit()
    bcast(pid, "cred", "delete", {"id": cid})
