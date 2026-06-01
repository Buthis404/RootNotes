from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access
from ..core.deps import get_current_user
from ..core.events import log_event
from ..core.permissions import PERM_CHECKLIST_UPDATE
from ..core.utils import new_id
from ..database import get_db

router = APIRouter(prefix="/api/checklist", tags=["checklist"])


@router.get("", response_model=list[schemas.ChecklistItem], responses={404: {"description": "Not found"}})
def list_checklist(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    phase: str | None = None,
):
    check_pid_access(db, pid, user, "checklist.read")
    q = db.query(models.ChecklistItem).filter(models.ChecklistItem.pid == pid)
    if phase:
        q = q.filter(models.ChecklistItem.phase == phase)
    return q.order_by(models.ChecklistItem.order_idx).all()


@router.post("", response_model=list[schemas.ChecklistItem], status_code=201, responses={404: {"description": "Not found"}})
def bulk_create_checklist(
    body: list[schemas.ChecklistItemCreate],
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if body:
        # Check access for all unique pids
        pids = {item.pid for item in body}
        for pid in pids:
            check_pid_access(db, pid, user, PERM_CHECKLIST_UPDATE)
    items = [models.ChecklistItem(id=new_id("cl"), **item.model_dump()) for item in body]
    db.add_all(items)
    db.commit()
    for item in items:
        db.refresh(item)
    return items


@router.patch("/{cid}", response_model=schemas.ChecklistItem, responses={404: {"description": "Not found"}})
def update_checklist_item(
    cid: str,
    body: schemas.ChecklistItemUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    item = db.query(models.ChecklistItem).filter(models.ChecklistItem.id == cid).first()
    if not item:
        raise HTTPException(404, "Checklist item not found")
    check_object_access(db, item.pid, user, PERM_CHECKLIST_UPDATE)
    old_done = item.done
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(item, k, v)
    if body.done is not None and body.done != old_done:
        action = "checked" if item.done else "unchecked"
        log_event(
            db,
            item.pid,
            getattr(request.state, "username", None),
            "checklist",
            action,
            f"Checklist [{item.phase}]: {item.text}",
            {"phase": item.phase},
        )
    db.commit()
    db.refresh(item)
    return item


@router.delete("/{cid}", status_code=204, responses={404: {"description": "Not found"}})
def delete_checklist_item(
    cid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    item = db.query(models.ChecklistItem).filter(models.ChecklistItem.id == cid).first()
    if not item:
        raise HTTPException(404, "Checklist item not found")
    check_object_access(db, item.pid, user, PERM_CHECKLIST_UPDATE)
    db.delete(item)
    db.commit()
