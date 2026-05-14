import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core import job_streams
from ..core.events import bcast
from ..core.job_runner import schedule_job_run, supports_queued_execution
from ..core.job_tracker import queue_job
from ..database import get_db

router = APIRouter(prefix="/api/projects/{pid}/jobs", tags=["jobs"])


def _job_dict(job: models.Job) -> dict:
    return {
        "id": job.id,
        "pid": job.pid,
        "type": job.type,
        "connector_key": job.connector_key,
        "operation": job.operation,
        "status": job.status,
        "title": job.title,
        "target": job.target,
        "command": job.command,
        "output": job.output,
        "error_output": job.error_output,
        "created_by": job.created_by,
        "scope_type": job.scope_type,
        "scope_id": job.scope_id,
        "related_entity_type": job.related_entity_type,
        "related_entity_id": job.related_entity_id,
        "retry_of_job_id": job.retry_of_job_id,
        "priority": getattr(job, "priority", 0) or 0,
        "retry_count": getattr(job, "retry_count", 0) or 0,
        "max_retries": getattr(job, "max_retries", 0) or 0,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "request_json": job.request_json or {},
        "result_json": job.result_json or {},
    }


def _clone_job_for_queue(db: Session, source: models.Job, *, created_by: str, retry_of_job_id: str = "") -> models.Job:
    return queue_job(
        db,
        source.pid,
        source.type,
        source.title,
        target=source.target,
        command=source.command,
        created_by=created_by,
        connector_key=source.connector_key,
        operation=source.operation,
        scope_type=source.scope_type,
        scope_id=source.scope_id,
        related_entity_type=source.related_entity_type,
        related_entity_id=source.related_entity_id,
        request_json=source.request_json or {},
        retry_of_job_id=retry_of_job_id,
        priority=getattr(source, "priority", 0) or 0,
        max_retries=getattr(source, "max_retries", 0) or 0,
    )


@router.get("")
def list_jobs(
    pid: str,
    type: str | None = None,
    status: str | None = None,
    connector_key: str | None = None,
    playbook_run_id: str | None = None,
    output_search: str | None = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.read")
    q = db.query(models.Job).filter(models.Job.pid == pid)
    if type:
        q = q.filter(models.Job.type == type)
    if status:
        q = q.filter(models.Job.status == status)
    if connector_key:
        q = q.filter(models.Job.connector_key == connector_key)
    if playbook_run_id:
        q = q.filter(models.Job.request_json["playbook_run_id"].astext == playbook_run_id)
    if output_search:
        pattern = f"%{output_search}%"
        q = q.filter(or_(
            models.Job.output.ilike(pattern),
            models.Job.error_output.ilike(pattern),
        ))
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
    # Signal worker to stop (kills subprocess if running)
    from ..core.worker_pool import get_pool
    get_pool().cancel_job(job_id)
    # For queued jobs that haven't started yet: mark cancelled immediately
    if job.status == "queued":
        job.status = "cancelled"
        db.commit()
        db.refresh(job)
    bcast(pid, "job", "update", _job_dict(job))
    return _job_dict(job)


@router.post("/{job_id}/rerun", status_code=201)
async def rerun_job(
    pid: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    source = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not source:
        raise HTTPException(404, "Job not found")
    if source.status in ("queued", "running"):
        raise HTTPException(400, "Cannot rerun an active job")
    if not source.request_json:
        raise HTTPException(400, "This job cannot be rerun because no orchestration payload was stored")
    if not supports_queued_execution(source.connector_key, source.operation):
        raise HTTPException(400, "Queued rerun is not supported for this connector/operation")
    cloned = _clone_job_for_queue(db, source, created_by=getattr(user, "username", "") or "")
    schedule_job_run(cloned.id, pid=pid, priority=10)
    return _job_dict(cloned)


@router.post("/{job_id}/retry", status_code=201)
async def retry_job(
    pid: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    source = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not source:
        raise HTTPException(404, "Job not found")
    if source.status not in ("failed", "cancelled"):
        raise HTTPException(400, "Retry is only available for failed or cancelled jobs")
    if not source.request_json:
        raise HTTPException(400, "This job cannot be retried because no orchestration payload was stored")
    if not supports_queued_execution(source.connector_key, source.operation):
        raise HTTPException(400, "Queued retry is not supported for this connector/operation")
    cloned = _clone_job_for_queue(db, source, created_by=getattr(user, "username", "") or "", retry_of_job_id=source.id)
    schedule_job_run(cloned.id, pid=pid, priority=10)
    return _job_dict(cloned)


@router.get("/{job_id}/output-stream")
async def stream_job_output(
    pid: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """SSE endpoint streaming live job output line by line."""
    check_pid_access(db, pid, user, "command_outputs.read")
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, "Job not found")

    async def generate():
        cursor = 0
        # Yield existing lines from live buffer (running job)
        while True:
            lines = job_streams.get_lines(job_id, cursor)
            for line in lines:
                yield f"data: {json.dumps({'line': line})}\n\n"
                cursor += 1

            closed = job_streams.is_closed(job_id)

            # Check DB for terminal status
            db.expire(job)
            db.refresh(job)
            terminal = job.status in ("done", "failed", "cancelled")

            if closed or terminal:
                # Drain any remaining lines
                remaining = job_streams.get_lines(job_id, cursor)
                for line in remaining:
                    yield f"data: {json.dumps({'line': line})}\n\n"
                # For completed jobs with no live stream, stream stored output
                if not job_streams.get_lines(job_id) and job.output:
                    for line in job.output.splitlines():
                        yield f"data: {json.dumps({'line': line})}\n\n"
                yield f"data: {json.dumps({'done': True, 'status': job.status})}\n\n"
                job_streams.cleanup_expired()
                return

            await asyncio.sleep(0.3)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{job_id}/artifacts")
def list_job_artifacts(
    pid: str,
    job_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """Return all Loot records auto-extracted or linked to this job."""
    check_pid_access(db, pid, user, "loot.read")
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, "Job not found")
    loots = db.query(models.Loot).filter(
        models.Loot.pid == pid,
        models.Loot.job_id == job_id,
    ).order_by(models.Loot.ts.desc()).all()
    from .. import schemas
    return [schemas.Loot.model_validate(l).model_dump() for l in loots]
