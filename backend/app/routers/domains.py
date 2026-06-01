from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access, check_object_access
from ..core.deps import get_current_user
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/domains", tags=["domains"])


@router.get("", response_model=list[schemas.Domain])
def list_domains(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
):
    if pid:
        check_pid_access(db, pid, user, "domains.read")
        return db.query(models.Domain).filter(models.Domain.pid == pid).all()
    return []


@router.post("", response_model=schemas.Domain, status_code=201)
def create_domain(
    body: schemas.DomainCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, "domains.update")
    domain = models.Domain(
        id=new_id("dom"),
        pid=body.pid,
        name=body.name,
        aliases=body.aliases,
        notes=body.notes,
        created_at=ts_now(),
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain


@router.patch("/{did}", response_model=schemas.Domain)
def update_domain(
    did: str,
    body: schemas.DomainUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    domain = db.query(models.Domain).filter(models.Domain.id == did).first()
    if not domain:
        raise HTTPException(404, "Domain not found")
    check_object_access(db, domain.pid, user, "domains.update")
    if body.name is not None:
        domain.name = body.name
    if body.aliases is not None:
        domain.aliases = body.aliases
    if body.notes is not None:
        domain.notes = body.notes
    db.commit()
    db.refresh(domain)
    return domain


@router.delete("/{did}", status_code=204)
def delete_domain(
    did: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    domain = db.query(models.Domain).filter(models.Domain.id == did).first()
    if not domain:
        raise HTTPException(404, "Domain not found")
    check_object_access(db, domain.pid, user, "domains.update")
    db.delete(domain)
    db.commit()
