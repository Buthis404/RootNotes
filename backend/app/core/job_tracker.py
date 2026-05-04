"""
Lightweight job tracking helpers.
Each job represents one tool invocation (nmap, nuclei, cme, exec, etc.)
with a status lifecycle: queued → running → done | failed | cancelled.
"""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .. import models
from ..core.events import bcast
from ..core.utils import new_id


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


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


def start_job(
    db: Session,
    pid: str,
    job_type: str,
    title: str,
    *,
    target: str = "",
    command: str = "",
    created_by: str = "",
) -> models.Job:
    """Create a job record in 'running' status and broadcast."""
    now = _now()
    job = models.Job(
        id=new_id("job"),
        pid=pid,
        type=job_type,
        status="running",
        title=title,
        target=target,
        command=command,
        created_by=created_by,
        created_at=now,
        started_at=now,
        finished_at="",
        output="",
        error_output="",
        result_json={},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "create", _job_dict(job))
    return job


def finish_job(
    db: Session,
    job: models.Job,
    *,
    status: str = "done",
    output: str = "",
    error_output: str = "",
    result: dict | None = None,
) -> models.Job:
    """Update job to terminal status and broadcast."""
    job.status = status
    job.output = output
    job.error_output = error_output
    job.result_json = result or {}
    job.finished_at = _now()
    db.commit()
    db.refresh(job)
    bcast(job.pid, "job", "update", _job_dict(job))
    return job
