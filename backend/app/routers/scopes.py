from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.utils import new_id, sync_project_ip_from_scopes
from ..core.deps import get_current_user
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(prefix="/api/scopes", tags=["scopes"])


@router.get("", response_model=list[schemas.Scope])
def list_scopes(pid: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if pid:
        check_pid_access(db, pid, user, "scopes.read")
        return db.query(models.Scope).filter(models.Scope.pid == pid).all()
    if user.role == "admin":
        return db.query(models.Scope).all()
    member_pids = get_user_member_pids(db, user)
    return db.query(models.Scope).filter(models.Scope.pid.in_(member_pids)).all()


@router.post("", response_model=schemas.Scope, status_code=201)
def create_scope(body: schemas.ScopeCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "scopes.update")
    scope = models.Scope(**body.model_dump(), id=new_id("sc"))
    db.add(scope)
    sync_project_ip_from_scopes(db, scope.pid)
    log_event(db, scope.pid, getattr(request.state, "username", None), "scope", "create",
              f"Scope {'added' if scope.in_scope else 'excluded'}: {scope.value}", {"type": scope.scope_type})
    db.commit()
    db.refresh(scope)
    bcast(scope.pid, "scope", "create", schemas.Scope.model_validate(scope).model_dump())
    return scope


@router.patch("/{sid}", response_model=schemas.Scope)
def update_scope(sid: str, body: schemas.ScopeUpdate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scope = db.query(models.Scope).filter(models.Scope.id == sid).first()
    if not scope:
        raise HTTPException(404)
    check_object_access(db, scope.pid, user, "scopes.update")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(scope, k, v)
    sync_project_ip_from_scopes(db, scope.pid)
    db.commit()
    db.refresh(scope)
    bcast(scope.pid, "scope", "update", schemas.Scope.model_validate(scope).model_dump())
    return scope


@router.delete("/{sid}", status_code=204)
def delete_scope(sid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    scope = db.query(models.Scope).filter(models.Scope.id == sid).first()
    if not scope:
        raise HTTPException(404)
    check_object_access(db, scope.pid, user, "scopes.update")
    pid = scope.pid
    log_event(db, pid, getattr(request.state, "username", None), "scope", "delete", f"Scope removed: {scope.value}")
    db.delete(scope)
    sync_project_ip_from_scopes(db, pid)
    db.commit()
    bcast(pid, "scope", "delete", {"id": sid})
