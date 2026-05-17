from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.utils import new_id
from ..core.deps import get_current_user, is_admin
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(prefix="/api/host-activities", tags=["host-activities"])


@router.get("", response_model=list[schemas.HostActivity])
def list_host_activities(pid: str | None = None, host_id: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if pid:
        check_pid_access(db, pid, user, "command_outputs.read")
        q = db.query(models.HostActivity).filter(models.HostActivity.pid == pid)
    elif is_admin(user):
        q = db.query(models.HostActivity)
    else:
        member_pids = get_user_member_pids(db, user)
        q = db.query(models.HostActivity).filter(models.HostActivity.pid.in_(member_pids))
    if host_id:
        q = q.filter(models.HostActivity.host_id == host_id)
    return q.order_by(models.HostActivity.ts.desc()).all()


@router.post("", response_model=schemas.HostActivity, status_code=201)
def create_host_activity(body: schemas.HostActivityCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "command_outputs.create")
    item = models.HostActivity(id=new_id("ha"), **body.model_dump())
    db.add(item)
    host = db.query(models.Host).filter(models.Host.id == item.host_id).first()
    host_label = host.hostname or host.ip if host else item.host_id
    log_event(db, item.pid, getattr(request.state, "username", None), "host_activity", "create",
              f"Host activity added: {host_label} / {item.title or item.activity_type}",
              {"host_id": item.host_id, "type": item.activity_type})
    db.commit()
    db.refresh(item)
    bcast(item.pid, "host_activity", "create", schemas.HostActivity.model_validate(item).model_dump())
    return item


@router.patch("/{aid}", response_model=schemas.HostActivity)
def update_host_activity(aid: str, body: schemas.HostActivityUpdate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    item = db.query(models.HostActivity).filter(models.HostActivity.id == aid).first()
    if not item:
        raise HTTPException(404, "Host activity not found")
    check_object_access(db, item.pid, user, "command_outputs.update")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(item, k, v)
    db.commit()
    db.refresh(item)
    bcast(item.pid, "host_activity", "update", schemas.HostActivity.model_validate(item).model_dump())
    return item


@router.delete("/{aid}", status_code=204)
def delete_host_activity(aid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    item = db.query(models.HostActivity).filter(models.HostActivity.id == aid).first()
    if not item:
        raise HTTPException(404, "Host activity not found")
    check_object_access(db, item.pid, user, "command_outputs.delete")
    pid = item.pid
    db.delete(item)
    db.commit()
    bcast(pid, "host_activity", "delete", {"id": aid})
