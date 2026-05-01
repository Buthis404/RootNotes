from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.utils import new_id
from ..core.deps import get_current_user
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=list[schemas.Finding])
def list_findings(pid: str | None = None, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if pid:
        check_pid_access(db, pid, user, "findings.read")
        return db.query(models.Finding).filter(models.Finding.pid == pid).all()
    if user.role == "admin":
        return db.query(models.Finding).all()
    member_pids = get_user_member_pids(db, user)
    return db.query(models.Finding).filter(models.Finding.pid.in_(member_pids)).all()


@router.post("", response_model=schemas.Finding, status_code=201)
def create_finding(body: schemas.FindingCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "findings.create")
    finding = models.Finding(id=new_id("f"), **body.model_dump())
    db.add(finding)
    log_event(db, finding.pid, getattr(request.state, "username", None), "finding", "create",
              f"Finding [{finding.severity.upper()}]: {finding.title}", {"severity": finding.severity})
    db.commit()
    db.refresh(finding)
    f = schemas.Finding.model_validate(finding)
    bcast(finding.pid, "finding", "create", f.model_dump())
    return finding


@router.patch("/{fid}", response_model=schemas.Finding)
def update_finding(fid: str, body: schemas.FindingUpdate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    finding = db.query(models.Finding).filter(models.Finding.id == fid).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    check_object_access(db, finding.pid, user, "findings.update")
    old_status = finding.status
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(finding, k, v)
    if body.status is not None and body.status != old_status:
        log_event(db, finding.pid, getattr(request.state, "username", None), "finding", "status",
                  f"Finding «{finding.title}» status → {finding.status}", {"old": old_status, "new": finding.status})
    db.commit()
    db.refresh(finding)
    f = schemas.Finding.model_validate(finding)
    bcast(finding.pid, "finding", "update", f.model_dump())
    return finding


@router.delete("/{fid}", status_code=204)
def delete_finding(fid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    finding = db.query(models.Finding).filter(models.Finding.id == fid).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    check_object_access(db, finding.pid, user, "findings.delete")
    pid = finding.pid
    log_event(db, pid, getattr(request.state, "username", None), "finding", "delete", f"Finding deleted: «{finding.title}»")
    db.delete(finding)
    db.commit()
    bcast(pid, "finding", "delete", {"id": fid})
