from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast
from ..database import get_db

router = APIRouter(prefix="/api/projects/{pid}/jobs", tags=["jobs"])


def _job_dict(job: models.Job) -> dict:
    return {
        "id": job.id,
        "pid": job.pid,
        "type": job.type,
        "status": job.status,
        "title": job.title,
        "target": job.target,
        "command": job.command,
        "output": job.output,
        "error_output": job.error_output,
        "created_by": job.created_by,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "result_json": job.result_json or {},
    }


@router.get("")
def list_jobs(
    pid: str,
    type: str | None = None,
    status: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.read")
    q = db.query(models.Job).filter(models.Job.pid == pid)
    if type:
        q = q.filter(models.Job.type == type)
    if status:
        q = q.filter(models.Job.status == status)
    jobs = q.order_by(models.Job.created_at.desc()).limit(limit).all()
    return [_job_dict(j) for j in jobs]


@router.get("/{job_id}")
def get_job(
    pid: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.read")
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, "Job not found")
    return _job_dict(job)


@router.delete("/{job_id}", status_code=204)
def delete_job(
    pid: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, "Job not found")
    db.delete(job)
    db.commit()
    bcast(pid, "job", "delete", {"id": job_id})


@router.patch("/{job_id}/cancel", status_code=200)
def cancel_job(
    pid: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status not in ("queued", "running"):
        raise HTTPException(400, "Job is already in a terminal state")
    job.status = "cancelled"
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "update", _job_dict(job))
    return _job_dict(job)
