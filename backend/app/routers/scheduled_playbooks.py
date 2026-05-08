"""
Scheduled playbooks — cron-based automatic playbook execution.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access
from ..core.cron_utils import next_run, validate_cron
from ..core.deps import get_current_user
from ..core.utils import new_id
from ..database import get_db

router = APIRouter(prefix="/api/scheduled-playbooks", tags=["scheduled-playbooks"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@router.get("", response_model=list[schemas.ScheduledPlaybook])
def list_schedules(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, pid, user, "playbooks.read")
    return db.query(models.ScheduledPlaybook).filter(models.ScheduledPlaybook.pid == pid).all()


@router.post("", response_model=schemas.ScheduledPlaybook, status_code=201)
def create_schedule(body: schemas.ScheduledPlaybookCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "playbooks.create")
    if not validate_cron(body.cron_expr):
        raise HTTPException(400, f"Invalid cron expression: {body.cron_expr!r}")
    nr = next_run(body.cron_expr)
    sched = models.ScheduledPlaybook(
        id=new_id("sp"),
        pid=body.pid,
        playbook_id=body.playbook_id,
        title=body.title,
        cron_expr=body.cron_expr,
        enabled=body.enabled,
        body_json=body.body_json,
        last_run_at="",
        next_run_at=nr.strftime("%Y-%m-%d %H:%M:%S"),
        created_by=getattr(request.state, "username", ""),
        created_at=_now(),
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched


@router.patch("/{sid}", response_model=schemas.ScheduledPlaybook)
def update_schedule(sid: str, body: schemas.ScheduledPlaybookUpdate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    sched = db.query(models.ScheduledPlaybook).filter(models.ScheduledPlaybook.id == sid).first()
    if not sched:
        raise HTTPException(404, "Schedule not found")
    check_pid_access(db, sched.pid, user, "playbooks.create")
    if body.cron_expr is not None and not validate_cron(body.cron_expr):
        raise HTTPException(400, f"Invalid cron expression: {body.cron_expr!r}")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(sched, k, v)
    # Recompute next_run if cron changed or schedule re-enabled
    if body.cron_expr is not None or body.enabled:
        sched.next_run_at = next_run(sched.cron_expr).strftime("%Y-%m-%d %H:%M:%S")
    db.commit()
    db.refresh(sched)
    return sched


@router.delete("/{sid}", status_code=204)
def delete_schedule(sid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    sched = db.query(models.ScheduledPlaybook).filter(models.ScheduledPlaybook.id == sid).first()
    if not sched:
        raise HTTPException(404, "Schedule not found")
    check_pid_access(db, sched.pid, user, "playbooks.create")
    db.delete(sched)
    db.commit()


@router.post("/{sid}/trigger", status_code=202)
async def trigger_schedule(sid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Manually fire a scheduled playbook immediately."""
    import asyncio
    sched = db.query(models.ScheduledPlaybook).filter(models.ScheduledPlaybook.id == sid).first()
    if not sched:
        raise HTTPException(404, "Schedule not found")
    check_pid_access(db, sched.pid, user, "playbooks.create")
    from ..routers.playbooks import _launch_playbook_run
    asyncio.create_task(_launch_playbook_run(
        pid=sched.pid,
        playbook_id=sched.playbook_id,
        body_dict=sched.body_json or {},
        created_by=getattr(request.state, "username", "scheduler"),
    ))
    return {"ok": True, "message": "Playbook triggered"}
