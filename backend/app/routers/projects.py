from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Annotated
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.config import UPLOAD_ROOT
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast, log_event
from ..core.permissions import add_project_owner, get_membership, get_permissions_for_role
from ..core.secure_delete import secure_delete_tree
from ..core.utils import new_id, sync_project_ip_from_scopes, sync_scopes_from_project_ip
from ..database import get_db

router = APIRouter(
    prefix="/api/projects", tags=["projects"],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        500: {"description": "Internal server error"},
    },
)

_MSG_PROJECT_NOT_FOUND = "Project not found"


class ProjectPurgeBody(BaseModel):
    confirm: str


@router.get("", response_model=list[schemas.Project])
def list_projects(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if is_admin(user):
        return db.query(models.Project).all()
    member_pids = [
        m.project_id
        for m in db.query(models.ProjectMember)
        .filter(
            models.ProjectMember.user_id == user.id,
            models.ProjectMember.is_active,
        )
        .all()
    ]
    return db.query(models.Project).filter(models.Project.id.in_(member_pids)).all()


@router.post("", response_model=schemas.Project, status_code=201)
def create_project(
    body: schemas.ProjectCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = models.Project(id=new_id("p"), **body.model_dump())
    db.add(project)
    db.flush()
    sync_scopes_from_project_ip(db, project.id)
    add_project_owner(db, project.id, user.id, created_by=user.id)
    db.commit()
    db.refresh(project)
    log_event(
        db,
        project.id,
        user.username,
        "project",
        "create",
        f"Project created: {project.name}",
        {"project_id": project.id},
    )
    db.commit()
    return project


@router.patch("/{pid}", response_model=schemas.Project, responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def update_project(
    pid: str,
    body: schemas.ProjectUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
    if not is_admin(user):
        membership = get_membership(db, pid, user.id)
        if not membership:
            raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
        if "project.update" not in get_permissions_for_role(membership.role):
            raise HTTPException(403, "Insufficient permissions")
    ip_changed = body.ip is not None
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(project, k, v)
    if ip_changed:
        sync_scopes_from_project_ip(db, pid)
        sync_project_ip_from_scopes(db, pid)
    db.commit()
    db.refresh(project)
    p = schemas.Project.model_validate(project)
    log_event(
        db,
        pid,
        user.username,
        "project",
        "update",
        f"Project updated: {project.name}",
        {"project_id": pid},
    )
    db.commit()
    bcast(pid, "project", "update", p.model_dump())
    return project


@router.delete("/{pid}", status_code=204, responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}})
def delete_project(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
    if not is_admin(user):
        membership = get_membership(db, pid, user.id)
        if not membership:
            raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
        if "project.delete" not in get_permissions_for_role(membership.role):
            raise HTTPException(403, "Only project owners can delete projects")
    db.delete(project)
    db.commit()
    bcast(pid, "project", "delete", {"id": pid})


@router.post("/{pid}/purge", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 500: {"description": "Internal server error"}})
def purge_project(
    pid: str,
    body: ProjectPurgeBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
    if not is_admin(user):
        membership = get_membership(db, pid, user.id)
        if not membership:
            raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
        if "project.delete" not in get_permissions_for_role(membership.role):
            raise HTTPException(403, "Only project owners can purge projects")
    if body.confirm.strip() not in {pid, project.name, "PURGE"}:
        raise HTTPException(400, "Confirmation must match project id, project name, or PURGE")

    project_upload_dir = UPLOAD_ROOT / pid
    try:
        secure_delete_tree(project_upload_dir)
    except Exception as exc:
        raise HTTPException(500, f"Failed to remove project files: {exc}")

    db.query(models.TimelineEvent).filter(models.TimelineEvent.pid == pid).delete(
        synchronize_session=False
    )
    db.delete(project)
    db.commit()

    bcast(
        pid, "project", "purge", {"id": pid, "purged_by": getattr(request.state, "username", None)}
    )
    return {"ok": True, "purged": pid}
