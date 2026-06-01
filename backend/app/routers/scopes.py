from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access, get_user_member_pids
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast, log_event
from ..core.permissions import PERM_SCOPES_UPDATE
from ..core.utils import new_id, sync_project_ip_from_scopes
from ..database import get_db

router = APIRouter(prefix="/api/scopes", tags=["scopes"])


@router.get("", response_model=list[schemas.Scope], responses={404: {"description": "Not found"}})
def list_scopes(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
):
    if pid:
        check_pid_access(db, pid, user, "scopes.read")
        return db.query(models.Scope).filter(models.Scope.pid == pid).all()
    if is_admin(user):
        return db.query(models.Scope).all()
    member_pids = get_user_member_pids(db, user)
    return db.query(models.Scope).filter(models.Scope.pid.in_(member_pids)).all()


@router.post("", response_model=schemas.Scope, status_code=201, responses={404: {"description": "Not found"}})
def create_scope(
    body: schemas.ScopeCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_SCOPES_UPDATE)
    if body.is_entry:
        db.query(models.Scope).filter(
            models.Scope.pid == body.pid,
            models.Scope.is_entry,
        ).update({"is_entry": False})
    scope = models.Scope(**body.model_dump(), id=new_id("sc"))
    db.add(scope)
    sync_project_ip_from_scopes(db, scope.pid)
    log_event(
        db,
        scope.pid,
        getattr(request.state, "username", None),
        "scope",
        "create",
        f"Scope {'added' if scope.in_scope else 'excluded'}: {scope.value}",
        {"type": scope.scope_type},
    )
    db.commit()
    db.refresh(scope)
    bcast(scope.pid, "scope", "create", schemas.Scope.model_validate(scope).model_dump())
    return scope


@router.patch("/{sid}", response_model=schemas.Scope, responses={404: {"description": "Not found"}})
def update_scope(
    sid: str,
    body: schemas.ScopeUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    scope = db.query(models.Scope).filter(models.Scope.id == sid).first()
    if not scope:
        raise HTTPException(404)
    check_object_access(db, scope.pid, user, PERM_SCOPES_UPDATE)
    if body.is_entry is True:
        db.query(models.Scope).filter(
            models.Scope.pid == scope.pid,
            models.Scope.id != sid,
            models.Scope.is_entry,
        ).update({"is_entry": False})
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(scope, k, v)
    sync_project_ip_from_scopes(db, scope.pid)
    db.commit()
    db.refresh(scope)
    bcast(scope.pid, "scope", "update", schemas.Scope.model_validate(scope).model_dump())
    return scope


@router.delete("/{sid}", status_code=204, responses={404: {"description": "Not found"}})
def delete_scope(
    sid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    scope = db.query(models.Scope).filter(models.Scope.id == sid).first()
    if not scope:
        raise HTTPException(404)
    check_object_access(db, scope.pid, user, PERM_SCOPES_UPDATE)
    pid = scope.pid
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "scope",
        "delete",
        f"Scope removed: {scope.value}",
    )
    db.delete(scope)
    sync_project_ip_from_scopes(db, pid)
    db.commit()
    bcast(pid, "scope", "delete", {"id": sid})
