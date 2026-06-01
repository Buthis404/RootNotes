import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Response
from typing import Annotated
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .. import models
from ..core import job_streams
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast
from ..core.job_runner import schedule_job_run, supports_queued_execution
from ..core.job_tracker import queue_job
from ..core.permissions import PERM_COMMAND_OUTPUTS_CREATE, PERM_COMMAND_OUTPUTS_READ
from ..database import get_db

router = APIRouter(
    prefix="/api/projects/{pid}/jobs", tags=["jobs"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
    },
)

_MSG_JOB_NOT_FOUND = "Job not found"


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


def _clone_job_for_queue(
    db: Session, source: models.Job, *, created_by: str, retry_of_job_id: str = ""
) -> models.Job:
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
        scope=(source.scope_type, source.scope_id),
        related_entity=(source.related_entity_type, source.related_entity_id),
        request_json=source.request_json or {},
        retry_opts={
            "retry_of_job_id": retry_of_job_id,
            "priority": getattr(source, "priority", 0) or 0,
            "max_retries": getattr(source, "max_retries", 0) or 0,
        },
    )


@router.get("")
def list_jobs(
    pid: str,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    type: str | None = None,
    status: str | None = None,
    connector_key: str | None = None,
    playbook_run_id: str | None = None,
    output_search: str | None = None,
    limit: int = 200,
    offset: int = 0,
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_READ)
    q = db.query(models.Job).filter(models.Job.pid == pid)
    if type:
        q = q.filter(models.Job.type == type)
    if status:
        q = q.filter(models.Job.status == status)
    if connector_key:
        q = q.filter(models.Job.connector_key == connector_key)
    if playbook_run_id:
        # Use jsonb @> (contains) instead of ->>'key' = value so the
        # jsonb_path_ops GIN index in migration 008 actually kicks in.
        q = q.filter(models.Job.request_json.contains({"playbook_run_id": playbook_run_id}))
    if output_search:
        pattern = f"%{output_search}%"
        q = q.filter(
            or_(
                models.Job.output.ilike(pattern),
                models.Job.error_output.ilike(pattern),
            )
        )
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
    jobs = (
        q.order_by(models.Job.created_at.desc())
        .offset(max(0, offset))
        .limit(min(max(1, limit), 1000))
        .all()
    )
    return [_job_dict(j) for j in jobs]


@router.get("/{job_id}", responses={404: {"description": "Not found"}})
def get_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_READ)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    return _job_dict(job)


@router.delete("/{job_id}", status_code=204, responses={404: {"description": "Not found"}})
def delete_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_CREATE)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    db.delete(job)
    db.commit()
    bcast(pid, "job", "delete", {"id": job_id})


@router.patch("/{job_id}/cancel", status_code=200, responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def cancel_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_CREATE)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    if job.status not in ("queued", "running"):
        raise HTTPException(400, "Job is already in a terminal state")
    # Signal in-process worker to stop (no-op when WORKER_BACKEND=arq)
    from ..core.worker_pool import get_pool

    get_pool().cancel_job(job_id)
    # When running in arq mode, signal the worker process via Redis cancel key.
    import os as _os

    if _os.environ.get("WORKER_BACKEND", "").lower() == "arq":
        from ..core.arq_pool import get_arq_pool
        from ..core.arq_worker import CANCEL_KEY_PREFIX

        arq_pool = get_arq_pool()
        if arq_pool is not None:
            await arq_pool.set(f"{CANCEL_KEY_PREFIX}{job_id}", "1", ex=3600)
    # Optimistically mark cancelled in DB for both queued and running jobs.
    # finish_job() will skip overwriting if it sees "cancelled" already set.
    job.status = "cancelled"
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "update", _job_dict(job))
    return _job_dict(job)


@router.post("/{job_id}/rerun", status_code=201, responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def rerun_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_CREATE)
    source = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not source:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    if source.status in ("queued", "running"):
        raise HTTPException(400, "Cannot rerun an active job")
    if not source.request_json:
        raise HTTPException(
            400, "This job cannot be rerun because no orchestration payload was stored"
        )
    if not supports_queued_execution(source.connector_key, source.operation):
        raise HTTPException(400, "Queued rerun is not supported for this connector/operation")
    cloned = _clone_job_for_queue(db, source, created_by=getattr(user, "username", "") or "")
    schedule_job_run(cloned.id, pid=pid, priority=10)
    return _job_dict(cloned)


@router.post("/{job_id}/retry", status_code=201, responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def retry_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_CREATE)
    source = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not source:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    if source.status not in ("failed", "cancelled"):
        raise HTTPException(400, "Retry is only available for failed or cancelled jobs")
    if not source.request_json:
        raise HTTPException(
            400, "This job cannot be retried because no orchestration payload was stored"
        )
    if not supports_queued_execution(source.connector_key, source.operation):
        raise HTTPException(400, "Queued retry is not supported for this connector/operation")
    cloned = _clone_job_for_queue(
        db, source, created_by=getattr(user, "username", "") or "", retry_of_job_id=source.id
    )
    schedule_job_run(cloned.id, pid=pid, priority=10)
    return _job_dict(cloned)


async def _drain_job_stream(job, job_id: str, cursor: int):
    remaining = job_streams.get_lines(job_id, cursor)
    for line in remaining:
        yield f"data: {json.dumps({'line': line})}\n\n"
    if not job_streams.get_lines(job_id) and job.output:
        for line in job.output.splitlines():
            yield f"data: {json.dumps({'line': line})}\n\n"
    yield f"data: {json.dumps({'done': True, 'status': job.status})}\n\n"
    job_streams.cleanup_expired()


async def _generate_job_stream(job, job_id: str, db):
    cursor = 0
    while True:
        lines = job_streams.get_lines(job_id, cursor)
        for line in lines:
            yield f"data: {json.dumps({'line': line})}\n\n"
            cursor += 1
        db.expire(job)
        db.refresh(job)
        closed = job_streams.is_closed(job_id)
        terminal = job.status in ("done", "failed", "cancelled")
        if closed or terminal:
            async for item in _drain_job_stream(job, job_id, cursor):
                yield item
            return
        await asyncio.sleep(0.3)


@router.get("/{job_id}/output-stream", responses={404: {"description": "Not found"}})
async def stream_job_output(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """SSE endpoint streaming live job output line by line."""
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_READ)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)

    return StreamingResponse(
        _generate_job_stream(job, job_id, db),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{job_id}/artifacts", responses={404: {"description": "Not found"}})
def list_job_artifacts(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Return all Loot records auto-extracted or linked to this job."""
    check_pid_access(db, pid, user, "loot.read")
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    loots = (
        db.query(models.Loot)
        .filter(
            models.Loot.pid == pid,
            models.Loot.job_id == job_id,
        )
        .order_by(models.Loot.ts.desc())
        .all()
    )
    from .. import schemas

    return [schemas.Loot.model_validate(loot).model_dump() for loot in loots]
