"""
Lightweight job tracking helpers.
Each job represents one tool invocation (nmap, nuclei, cme, exec, etc.)
with a status lifecycle: queued → running → done | failed | cancelled.
"""

import logging

from sqlalchemy.orm import Session

from .. import models
from ..core.events import bcast
from ..core.utils import new_id, ts_now

logger = logging.getLogger(__name__)


def _now() -> str:
    return ts_now()


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
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "request_json": job.request_json or {},
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
    connector_key: str = "",
    operation: str = "",
    scope_type: str = "project",
    scope_id: str = "",
    related_entity: tuple | None = None,
    request_json: dict | None = None,
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
        connector_key=connector_key,
        operation=operation,
        scope_type=scope_type,
        scope_id=scope_id or pid,
        related_entity_type=(related_entity[0] if related_entity else ""),
        related_entity_id=(related_entity[1] if related_entity else ""),
        retry_of_job_id="",
        created_at=now,
        started_at=now,
        finished_at="",
        request_json=request_json or {},
        output="",
        error_output="",
        result_json={},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "create", _job_dict(job))
    return job


def queue_job(
    db: Session,
    pid: str,
    job_type: str,
    title: str,
    *,
    target: str = "",
    command: str = "",
    created_by: str = "",
    connector_key: str = "",
    operation: str = "",
    scope: tuple[str, str] | None = None,
    related_entity: tuple | None = None,
    request_json: dict | None = None,
    retry_opts: dict | None = None,
) -> models.Job:
    _scope_type = scope[0] if scope else "project"
    _scope_id = (scope[1] if scope else "") or pid
    now = _now()
    job = models.Job(
        id=new_id("job"),
        pid=pid,
        type=job_type,
        status="queued",
        title=title,
        target=target,
        command=command,
        created_by=created_by,
        connector_key=connector_key,
        operation=operation,
        scope_type=_scope_type,
        scope_id=_scope_id,
        related_entity_type=(related_entity[0] if related_entity else ""),
        related_entity_id=(related_entity[1] if related_entity else ""),
        retry_of_job_id=retry_opts.get("retry_of_job_id", "") if retry_opts else "",
        priority=retry_opts.get("priority", 0) if retry_opts else 0,
        retry_count=retry_opts.get("retry_count", 0) if retry_opts else 0,
        max_retries=retry_opts.get("max_retries", 0) if retry_opts else 0,
        created_at=now,
        started_at="",
        finished_at="",
        request_json=request_json or {},
        output="",
        error_output="",
        result_json={},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "create", _job_dict(job))
    return job


def mark_job_running(db: Session, job: models.Job) -> models.Job:
    job.status = "running"
    if not job.started_at:
        job.started_at = _now()
    db.commit()
    db.refresh(job)
    bcast(job.pid, "job", "update", _job_dict(job))
    return job


def _notify_job_terminal(db: Session, job: "models.Job", status: str, error_output: str) -> None:
    try:
        from ..core.notifications import dispatch_sync

        title = f"Job {status}: {job.title or job.type}"
        body_text = f"Target: {job.target}" if job.target else f"Project: {job.pid}"
        if status == "failed" and error_output:
            body_text += f"\nError: {error_output[:200]}"
        dispatch_sync(db, f"job_{status}", title, body_text, {"job_id": job.id, "pid": job.pid})
    except Exception as e:
        logger.debug("job-terminal notification dispatch failed (job=%s): %s", job.id, e)


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
    # Re-read from DB to detect external cancel that raced with job completion
    db.refresh(job)
    if job.status == "cancelled" and status in ("done", "failed"):
        return job  # Cancel took priority; don't overwrite with done/failed
    job.status = status
    job.output = output
    job.error_output = error_output
    job.result_json = result or {}
    job.finished_at = _now()
    db.commit()
    db.refresh(job)
    bcast(job.pid, "job", "update", _job_dict(job))

    # Auto-retry on failure if max_retries allows
    retry_count = getattr(job, "retry_count", 0) or 0
    max_retries = getattr(job, "max_retries", 0) or 0
    if status == "failed" and retry_count < max_retries:
        _schedule_auto_retry(db, job, retry_count)
        return job

    if status in ("done", "failed"):
        _notify_job_terminal(db, job, status, error_output)

    return job


def _schedule_auto_retry(db: Session, job: models.Job, current_retry_count: int) -> None:
    """Clone a failed job and re-queue it with exponential backoff."""
    import asyncio

    next_count = current_retry_count + 1
    backoff_seconds = min(30 * (2**current_retry_count), 300)  # 30s, 60s, 120s … max 5min

    retry_job = queue_job(
        db,
        job.pid,
        job.type,
        job.title,
        target=job.target,
        command=job.command,
        created_by=job.created_by,
        connector_key=job.connector_key,
        operation=job.operation,
        scope=(job.scope_type, job.scope_id),
        related_entity=(job.related_entity_type, job.related_entity_id),
        request_json=job.request_json or {},
        retry_opts={"retry_of_job_id": job.id, "priority": getattr(job, "priority", 0) or 0, "retry_count": next_count, "max_retries": getattr(job, "max_retries", 0) or 0},
    )

    async def _delayed_submit(job_id: str, pid: str, priority: int, delay: float) -> None:
        await asyncio.sleep(delay)
        from .job_runner import schedule_job_run

        schedule_job_run(job_id, pid=pid, priority=priority)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(
            _delayed_submit(
                retry_job.id, job.pid, getattr(job, "priority", 0) or 0, float(backoff_seconds)
            )
        )
    except RuntimeError:
        # No running loop (e.g. tests) — submit immediately
        from .job_runner import schedule_job_run

        schedule_job_run(retry_job.id, pid=job.pid, priority=getattr(job, "priority", 0) or 0)

    import logging

    logging.getLogger(__name__).info(
        "Auto-retry %d/%d for job %s → new job %s (backoff %ds)",
        next_count,
        getattr(job, "max_retries", 0),
        job.id,
        retry_job.id,
        backoff_seconds,
    )
