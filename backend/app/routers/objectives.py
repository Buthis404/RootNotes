from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.utils import new_id, ts_now
from ..core.deps import get_current_user, is_admin
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(prefix="/api/objectives", tags=["objectives"])


@router.get("", response_model=list[schemas.Objective])
def list_objectives(pid: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if pid:
        check_pid_access(db, pid, user, "objectives.read")
        return db.query(models.Objective).filter(models.Objective.pid == pid).order_by(models.Objective.ts.desc()).all()
    if is_admin(user):
        return db.query(models.Objective).order_by(models.Objective.ts.desc()).all()
    member_pids = get_user_member_pids(db, user)
    return db.query(models.Objective).filter(models.Objective.pid.in_(member_pids)).order_by(models.Objective.ts.desc()).all()


@router.post("", response_model=schemas.Objective)
def create_objective(body: schemas.ObjectiveCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "objectives.create")
    obj = models.Objective(**body.model_dump(), id=new_id("obj"), ts=ts_now())
    db.add(obj)
    log_event(db, obj.pid, getattr(request.state, "username", None), "objective", "create",
              f"Objective added: {obj.title}", {"category": obj.category})
    db.commit()
    db.refresh(obj)
    bcast(obj.pid, "objective", "create", schemas.Objective.model_validate(obj).model_dump())
    return obj


@router.patch("/{oid}", response_model=schemas.Objective)
def update_objective(oid: str, body: schemas.ObjectiveUpdate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    obj = db.query(models.Objective).filter(models.Objective.id == oid).first()
    if not obj:
        raise HTTPException(404)
    check_object_access(db, obj.pid, user, "objectives.update")
    old_status = obj.status
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    if body.status == "captured" and not obj.captured_at:
        obj.captured_at = ts_now()
    if body.status is not None and body.status != old_status:
        log_event(db, obj.pid, getattr(request.state, "username", None), "objective", "status",
                  f"Objective «{obj.title}» → {obj.status}", {"old": old_status, "new": obj.status})
    db.commit()
    db.refresh(obj)
    bcast(obj.pid, "objective", "update", schemas.Objective.model_validate(obj).model_dump())
    return obj


@router.delete("/{oid}")
def delete_objective(oid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    obj = db.query(models.Objective).filter(models.Objective.id == oid).first()
    if not obj:
        raise HTTPException(404)
    check_object_access(db, obj.pid, user, "objectives.delete")
    pid = obj.pid
    log_event(db, pid, getattr(request.state, "username", None), "objective", "delete", f"Objective deleted: {obj.title}")
    db.delete(obj)
    db.commit()
    bcast(pid, "objective", "delete", {"id": oid})
    return {"ok": True}
