from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access, get_user_member_pids
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast, log_event
from ..core.permissions import PERM_ATTACK_PATHS_READ, PERM_ATTACK_PATHS_UPDATE
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(
    tags=["attack-paths"],
    responses={
        404: {"description": "Not found"},
    },
)


@router.get("/api/attack-paths", response_model=list[schemas.AttackPath])
def list_attack_paths(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
):
    if pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        return (
            db.query(models.AttackPath)
            .filter(models.AttackPath.pid == pid)
            .order_by(models.AttackPath.ts)
            .all()
        )
    if is_admin(user):
        return db.query(models.AttackPath).order_by(models.AttackPath.ts).all()
    member_pids = get_user_member_pids(db, user)
    return (
        db.query(models.AttackPath)
        .filter(models.AttackPath.pid.in_(member_pids))
        .order_by(models.AttackPath.ts)
        .all()
    )


@router.post("/api/attack-paths", response_model=schemas.AttackPath)
def create_attack_path(
    body: schemas.AttackPathCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    ap = models.AttackPath(**body.model_dump(), id=new_id("ap"), ts=ts_now())
    db.add(ap)
    log_event(
        db,
        ap.pid,
        getattr(request.state, "username", None),
        "attack_path",
        "create",
        f"Attack path created: {ap.name}",
    )
    db.commit()
    db.refresh(ap)
    bcast(ap.pid, "attack_path", "create", schemas.AttackPath.model_validate(ap).model_dump())
    return ap


@router.patch("/api/attack-paths/{ap_id}", response_model=schemas.AttackPath, responses={404: {"description": "Not found"}})
def update_attack_path(
    ap_id: str,
    body: schemas.AttackPathUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == ap_id).first()
    if not ap:
        raise HTTPException(404)
    check_object_access(db, ap.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(ap, k, v)
    db.commit()
    db.refresh(ap)
    bcast(ap.pid, "attack_path", "update", schemas.AttackPath.model_validate(ap).model_dump())
    return ap


@router.delete("/api/attack-paths/{ap_id}", responses={404: {"description": "Not found"}})
def delete_attack_path(
    ap_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == ap_id).first()
    if not ap:
        raise HTTPException(404)
    check_object_access(db, ap.pid, user, PERM_ATTACK_PATHS_UPDATE)
    pid = ap.pid
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "attack_path",
        "delete",
        f"Attack path deleted: {ap.name}",
    )
    db.delete(ap)
    db.commit()
    bcast(pid, "attack_path", "delete", {"id": ap_id})
    return {"ok": True}


@router.get("/api/attack-steps", response_model=list[schemas.AttackStep])
def list_attack_steps(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    path_id: str | None = None,
    pid: str | None = None,
):
    if path_id:
        ap = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
        if not ap:
            return []
        check_object_access(db, ap.pid, user, PERM_ATTACK_PATHS_READ)
        return (
            db.query(models.AttackStep)
            .filter(models.AttackStep.path_id == path_id)
            .order_by(models.AttackStep.step_order)
            .all()
        )
    if pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        return (
            db.query(models.AttackStep)
            .filter(models.AttackStep.pid == pid)
            .order_by(models.AttackStep.step_order)
            .all()
        )
    if is_admin(user):
        return db.query(models.AttackStep).order_by(models.AttackStep.step_order).all()
    member_pids = get_user_member_pids(db, user)
    return (
        db.query(models.AttackStep)
        .filter(models.AttackStep.pid.in_(member_pids))
        .order_by(models.AttackStep.step_order)
        .all()
    )


@router.post("/api/attack-steps", response_model=schemas.AttackStep)
def create_attack_step(
    body: schemas.AttackStepCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    step = models.AttackStep(**body.model_dump(), id=new_id("as"), ts=ts_now())
    db.add(step)
    db.commit()
    db.refresh(step)
    bcast(step.pid, "attack_step", "create", schemas.AttackStep.model_validate(step).model_dump())
    return step


@router.patch("/api/attack-steps/{step_id}", response_model=schemas.AttackStep, responses={404: {"description": "Not found"}})
def update_attack_step(
    step_id: str,
    body: schemas.AttackStepUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    step = db.query(models.AttackStep).filter(models.AttackStep.id == step_id).first()
    if not step:
        raise HTTPException(404)
    check_object_access(db, step.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(step, k, v)
    db.commit()
    db.refresh(step)
    bcast(step.pid, "attack_step", "update", schemas.AttackStep.model_validate(step).model_dump())
    return step


@router.delete("/api/attack-steps/{step_id}", responses={404: {"description": "Not found"}})
def delete_attack_step(
    step_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    step = db.query(models.AttackStep).filter(models.AttackStep.id == step_id).first()
    if not step:
        raise HTTPException(404)
    check_object_access(db, step.pid, user, PERM_ATTACK_PATHS_UPDATE)
    pid = step.pid
    db.delete(step)
    db.commit()
    bcast(pid, "attack_step", "delete", {"id": step_id})
    return {"ok": True}
