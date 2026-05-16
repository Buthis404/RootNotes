"""
Project domain inventory — track domains/subdomains per project.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/domains", tags=["domains"])


def _now() -> str:
    return ts_now()


@router.get("", response_model=list[schemas.ProjectDomain])
def list_domains(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, pid, user, "notes.read")
    return db.query(models.ProjectDomain).filter(models.ProjectDomain.pid == pid).all()


@router.post("", response_model=schemas.ProjectDomain, status_code=201)
def create_domain(body: schemas.ProjectDomainCreate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "notes.write")
    domain = models.ProjectDomain(
        id=new_id("dom"),
        pid=body.pid,
        name=body.name,
        aliases=body.aliases,
        notes=body.notes,
        created_at=_now(),
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain


@router.patch("/{did}", response_model=schemas.ProjectDomain)
def update_domain(did: str, body: schemas.ProjectDomainUpdate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    domain = db.query(models.ProjectDomain).filter(models.ProjectDomain.id == did).first()
    if not domain:
        raise HTTPException(404, "Domain not found")
    check_pid_access(db, domain.pid, user, "notes.write")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(domain, k, v)
    db.commit()
    db.refresh(domain)
    return domain


@router.delete("/{did}", status_code=204)
def delete_domain(did: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    domain = db.query(models.ProjectDomain).filter(models.ProjectDomain.id == did).first()
    if not domain:
        raise HTTPException(404, "Domain not found")
    check_pid_access(db, domain.pid, user, "notes.write")
    db.delete(domain)
    db.commit()
