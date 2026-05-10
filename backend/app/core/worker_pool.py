"""
Worker pool — bounded asyncio task pool for queued job execution.

Replaces unbounded asyncio.create_task() with a controlled concurrency model:
- max_workers slots running simultaneously
- internal asyncio.Queue for pending jobs
- startup recovery: re-queues any persisted 'queued' jobs
- graceful shutdown: drains queue on stop()
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_DEFAULT_MAX_WORKERS = 5


class WorkerPool:
    def __init__(self, max_workers: int = _DEFAULT_MAX_WORKERS):
        self._max_workers = max_workers
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._worker_tasks: list[asyncio.Task] = []
        self._running = False
        self._active_job_ids: set[str] = set()
        self._cancel_tokens: dict[str, object] = {}  # job_id → CancellationToken

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        for _ in range(self._max_workers):
            t = asyncio.create_task(self._worker_loop())
            self._worker_tasks.append(t)
        logger.info("WorkerPool started: max_workers=%d", self._max_workers)

    def submit(self, job_id: str) -> None:
        self._queue.put_nowait(job_id)

    def cancel_job(self, job_id: str) -> bool:
        """Signal a running job to stop. Returns True if the token was found and fired."""
        token = self._cancel_tokens.get(job_id)
        if token is not None:
            token.cancel()
            return True
        return False

    async def stop(self) -> None:
        self._running = False
        for t in self._worker_tasks:
            t.cancel()
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        self._worker_tasks.clear()
        logger.info("WorkerPool stopped")

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def active_count(self) -> int:
        return len(self._active_job_ids)

    @property
    def active_jobs(self) -> list[str]:
        return list(self._active_job_ids)

    async def _worker_loop(self) -> None:
        while self._running:
            try:
                job_id = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            self._active_job_ids.add(job_id)
            from .transport import CancellationToken
            token = CancellationToken()
            self._cancel_tokens[job_id] = token
            try:
                from .job_runner import run_queued_job
                await run_queued_job(job_id, token)
            except Exception as exc:
                logger.exception("Worker error running job %s: %s", job_id, exc)
            finally:
                self._cancel_tokens.pop(job_id, None)
                self._active_job_ids.discard(job_id)
                self._queue.task_done()


# Module-level singleton
_pool: WorkerPool | None = None


def get_pool() -> WorkerPool:
    global _pool
    if _pool is None:
        _pool = WorkerPool(max_workers=_DEFAULT_MAX_WORKERS)
    return _pool


async def startup_recovery(db) -> int:
    """Re-queue any persisted 'queued' jobs on startup. Mark interrupted 'running' jobs as failed."""
    from .. import models
    from ..core.job_tracker import finish_job

    pool = get_pool()
    recovered = 0

    # Mark interrupted running jobs as failed
    running_jobs = db.query(models.Job).filter(models.Job.status == "running").all()
    for job in running_jobs:
        finish_job(db, job, status="failed", error_output="[interrupted] Worker restarted while job was running")
        logger.warning("Marked interrupted job %s as failed", job.id)

    # Re-queue persisted queued jobs
    queued_jobs = db.query(models.Job).filter(models.Job.status == "queued").order_by(models.Job.created_at).all()
    for job in queued_jobs:
        from .job_runner import supports_queued_execution
        if supports_queued_execution(job.connector_key, job.operation):
            pool.submit(job.id)
            recovered += 1
            logger.info("Re-queued job %s (%s/%s)", job.id, job.connector_key, job.operation)
        else:
            finish_job(db, job, status="failed", error_output="[interrupted] Job type cannot be re-queued after restart")

    db.commit()
    if recovered:
        logger.info("WorkerPool recovery: re-queued %d jobs", recovered)
    return recovered
