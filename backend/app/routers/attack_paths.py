from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.utils import new_id, ts_now
from ..core.deps import get_current_user
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(tags=["attack-paths"])


@router.get("/api/attack-paths", response_model=list[schemas.AttackPath])
def list_attack_paths(pid: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if pid:
        check_pid_access(db, pid, user, "attack_paths.read")
        return db.query(models.AttackPath).filter(models.AttackPath.pid == pid).order_by(models.AttackPath.ts).all()
    if user.role == "admin":
        return db.query(models.AttackPath).order_by(models.AttackPath.ts).all()
    member_pids = get_user_member_pids(db, user)
    return db.query(models.AttackPath).filter(models.AttackPath.pid.in_(member_pids)).order_by(models.AttackPath.ts).all()


@router.post("/api/attack-paths", response_model=schemas.AttackPath)
def create_attack_path(body: schemas.AttackPathCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "attack_paths.update")
    ap = models.AttackPath(**body.model_dump(), id=new_id("ap"), ts=ts_now())
    db.add(ap)
    log_event(db, ap.pid, getattr(request.state, "username", None), "attack_path", "create", f"Attack path created: {ap.name}")
    db.commit()
    db.refresh(ap)
    bcast(ap.pid, "attack_path", "create", schemas.AttackPath.model_validate(ap).model_dump())
    return ap


@router.patch("/api/attack-paths/{ap_id}", response_model=schemas.AttackPath)
def update_attack_path(ap_id: str, body: schemas.AttackPathUpdate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == ap_id).first()
    if not ap:
        raise HTTPException(404)
    check_object_access(db, ap.pid, user, "attack_paths.update")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(ap, k, v)
    db.commit()
    db.refresh(ap)
    bcast(ap.pid, "attack_path", "update", schemas.AttackPath.model_validate(ap).model_dump())
    return ap


@router.delete("/api/attack-paths/{ap_id}")
def delete_attack_path(ap_id: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == ap_id).first()
    if not ap:
        raise HTTPException(404)
    check_object_access(db, ap.pid, user, "attack_paths.update")
    pid = ap.pid
    log_event(db, pid, getattr(request.state, "username", None), "attack_path", "delete", f"Attack path deleted: {ap.name}")
    db.delete(ap)
    db.commit()
    bcast(pid, "attack_path", "delete", {"id": ap_id})
    return {"ok": True}


@router.get("/api/attack-steps", response_model=list[schemas.AttackStep])
def list_attack_steps(path_id: str | None = None, pid: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if path_id:
        ap = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
        if not ap:
            return []
        check_object_access(db, ap.pid, user, "attack_paths.read")
        return db.query(models.AttackStep).filter(models.AttackStep.path_id == path_id).order_by(models.AttackStep.step_order).all()
    if pid:
        check_pid_access(db, pid, user, "attack_paths.read")
        return db.query(models.AttackStep).filter(models.AttackStep.pid == pid).order_by(models.AttackStep.step_order).all()
    if user.role == "admin":
        return db.query(models.AttackStep).order_by(models.AttackStep.step_order).all()
    member_pids = get_user_member_pids(db, user)
    return db.query(models.AttackStep).filter(models.AttackStep.pid.in_(member_pids)).order_by(models.AttackStep.step_order).all()


@router.post("/api/attack-steps", response_model=schemas.AttackStep)
def create_attack_step(body: schemas.AttackStepCreate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "attack_paths.update")
    step = models.AttackStep(**body.model_dump(), id=new_id("as"), ts=ts_now())
    db.add(step)
    db.commit()
    db.refresh(step)
    bcast(step.pid, "attack_step", "create", schemas.AttackStep.model_validate(step).model_dump())
    return step


@router.patch("/api/attack-steps/{step_id}", response_model=schemas.AttackStep)
def update_attack_step(step_id: str, body: schemas.AttackStepUpdate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    step = db.query(models.AttackStep).filter(models.AttackStep.id == step_id).first()
    if not step:
        raise HTTPException(404)
    check_object_access(db, step.pid, user, "attack_paths.update")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(step, k, v)
    db.commit()
    db.refresh(step)
    bcast(step.pid, "attack_step", "update", schemas.AttackStep.model_validate(step).model_dump())
    return step


@router.delete("/api/attack-steps/{step_id}")
def delete_attack_step(step_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    step = db.query(models.AttackStep).filter(models.AttackStep.id == step_id).first()
    if not step:
        raise HTTPException(404)
    check_object_access(db, step.pid, user, "attack_paths.update")
    pid = step.pid
    db.delete(step)
    db.commit()
    bcast(pid, "attack_step", "delete", {"id": step_id})
    return {"ok": True}
