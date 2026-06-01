from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access, get_user_member_pids
from ..core.deps import get_current_user, is_admin
from ..core.enums import Severity
from ..core.events import bcast, log_event
from ..core.utils import new_id
from ..database import get_db

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=list[schemas.Finding], responses={404: {"description": "Not found"}})
def list_findings(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    status: str | None = None,
    source: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, "findings.read")
        q = db.query(models.Finding).filter(models.Finding.pid == pid)
        if status:
            q = q.filter(models.Finding.status == status)
        if source:
            q = q.filter(models.Finding.source == source)
    elif is_admin(user):
        q = db.query(models.Finding)
    else:
        member_pids = get_user_member_pids(db, user)
        q = db.query(models.Finding).filter(models.Finding.pid.in_(member_pids))
    q = q.order_by(models.Finding.ts.desc())
    response.headers["X-Total-Count"] = str(q.count())
    return q.offset(offset).limit(limit).all()


@router.post("/scan-candidates", status_code=200, responses={404: {"description": "Not found"}})
def scan_candidates(
    pid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Run project-wide candidate scanner and create/update Finding records with status='candidate'."""
    check_pid_access(db, pid, user, "findings.create")
    from ..core.candidate_scanner import run_scan

    result = run_scan(db, pid)
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "finding",
        "scan",
        f"Candidate scan: {result.created} new, {result.skipped} already known",
        {"created": result.created, "skipped": result.skipped},
    )
    return {
        "created": result.created,
        "skipped": result.skipped,
        "candidates": result.candidates,
    }


@router.post("", response_model=schemas.Finding, status_code=201, responses={404: {"description": "Not found"}})
def create_finding(
    body: schemas.FindingCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, "findings.create")
    finding = models.Finding(id=new_id("f"), **body.model_dump())
    db.add(finding)
    log_event(
        db,
        finding.pid,
        getattr(request.state, "username", None),
        "finding",
        "create",
        f"Finding [{finding.severity.upper()}]: {finding.title}",
        {"severity": finding.severity},
    )
    db.commit()
    db.refresh(finding)
    f = schemas.Finding.model_validate(finding)
    bcast(finding.pid, "finding", "create", f.model_dump())
    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
        from ..core.notifications import dispatch_sync

        icon = "🔴" if finding.severity == Severity.CRITICAL else "🟠"
        dispatch_sync(
            db,
            "finding_critical",
            f"{icon} New {finding.severity.upper()} finding: {finding.title}",
            finding.description[:300] if finding.description else "No description",
            {"finding_id": finding.id, "severity": finding.severity, "pid": finding.pid},
        )
    return finding


@router.patch("/{fid}", response_model=schemas.Finding, responses={404: {"description": "Not found"}})
def update_finding(
    fid: str,
    body: schemas.FindingUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    finding = db.query(models.Finding).filter(models.Finding.id == fid).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    check_object_access(db, finding.pid, user, "findings.update")
    old_status = finding.status
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(finding, k, v)
    if body.status is not None and body.status != old_status:
        log_event(
            db,
            finding.pid,
            getattr(request.state, "username", None),
            "finding",
            "status",
            f"Finding «{finding.title}» status → {finding.status}",
            {"old": old_status, "new": finding.status},
        )
    db.commit()
    db.refresh(finding)
    f = schemas.Finding.model_validate(finding)
    bcast(finding.pid, "finding", "update", f.model_dump())
    return finding


@router.delete("/{fid}", status_code=204, responses={404: {"description": "Not found"}})
def delete_finding(
    fid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    finding = db.query(models.Finding).filter(models.Finding.id == fid).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    check_object_access(db, finding.pid, user, "findings.delete")
    pid = finding.pid
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "finding",
        "delete",
        f"Finding deleted: «{finding.title}»",
    )
    db.delete(finding)
    db.commit()
    bcast(pid, "finding", "delete", {"id": fid})
