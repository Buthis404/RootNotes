"""
Worker pool — bounded asyncio task pool for queued job execution.

Concurrency model:
- max_workers total slots running simultaneously
- max_per_project slots per project (prevents one project starving others)
- PriorityQueue: lower priority_key = runs first
  priority_key = (-job.priority, monotonic counter) so high-priority jobs come first
  and within same priority, FIFO order is preserved
- Startup recovery: re-queues persisted 'queued' jobs
- Graceful shutdown: drains on stop()

Backend modes (WORKER_BACKEND env var)
---------------------------------------
  internal (default) — jobs run as asyncio tasks inside the API process
  arq                — jobs are forwarded to the arq worker process via Redis;
                       the pool still enforces per-project concurrency limits
                       before forwarding so the API process remains idle
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING

_WORKER_BACKEND = os.environ.get("WORKER_BACKEND", "internal").lower()

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        v = int(raw)
        return v if v > 0 else default
    except ValueError:
        return default


# Most queued jobs are SSH-bound (nmap, nuclei, donpapi) and spend the
# vast majority of their wallclock waiting on network I/O. We can run
# many more in parallel than CPU cores. Tunable via env so operators
# can dial it to their attacker-box capacity.
_DEFAULT_MAX_WORKERS = _env_int("WORKER_POOL_MAX_WORKERS", 8)
_DEFAULT_MAX_PER_PROJECT = _env_int("WORKER_POOL_MAX_PER_PROJECT", 3)


class WorkerPool:
    def __init__(
        self,
        max_workers: int = _DEFAULT_MAX_WORKERS,
        max_per_project: int = _DEFAULT_MAX_PER_PROJECT,
    ):
        self._max_workers = max_workers
        self._max_per_project = max_per_project
        # PriorityQueue items: (priority_key, counter, job_id, pid)
        self._queue: asyncio.PriorityQueue[tuple[int, int, str, str]] = asyncio.PriorityQueue()
        self._counter = 0  # monotonic, for FIFO within same priority
        self._worker_tasks: list[asyncio.Task] = []
        self._running = False
        self._active_job_ids: set[str] = set()
        self._active_per_project: dict[str, int] = {}
        self._cancel_tokens: dict[str, object] = {}  # job_id → CancellationToken

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        for _ in range(self._max_workers):
            t = asyncio.create_task(self._worker_loop())
            self._worker_tasks.append(t)
        logger.info(
            "WorkerPool started: max_workers=%d max_per_project=%d",
            self._max_workers,
            self._max_per_project,
        )

    def submit(self, job_id: str, *, pid: str = "", priority: int = 0) -> None:
        """Enqueue a job. Higher priority int = runs sooner."""
        self._counter += 1
        # negate priority so that higher int = lower queue key = dequeued first
        self._queue.put_nowait((-priority, self._counter, job_id, pid))

    def cancel_job(self, job_id: str) -> bool:
        token = self._cancel_tokens.get(job_id)
        if token is not None:
            token.cancel()
            return True
        return False

    async def _forward_to_arq(self, job_id: str) -> None:
        """Forward job to arq Redis queue; falls back to in-process on error."""
        from .arq_pool import get_arq_pool
        from .arq_worker import ARQ_QUEUE_NAME

        arq_pool = get_arq_pool()
        if arq_pool is None:
            logger.warning(
                "WORKER_BACKEND=arq but arq pool not initialised — "
                "falling back to in-process execution for job %s",
                job_id,
            )
            from .job_runner import run_queued_job
            from .transport import CancellationToken

            await run_queued_job(job_id, CancellationToken())
            return
        try:
            await arq_pool.enqueue_job(
                "run_queued_job_arq",
                job_id,
                _queue_name=ARQ_QUEUE_NAME,
            )
            logger.info("Forwarded job %s to arq queue", job_id)
        except Exception as exc:
            logger.exception("Failed to enqueue job %s to arq: %s", job_id, exc)
            from .job_runner import run_queued_job
            from .transport import CancellationToken

            await run_queued_job(job_id, CancellationToken())

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

    @property
    def per_project_counts(self) -> dict[str, int]:
        return dict(self._active_per_project)

    async def _worker_loop(self) -> None:
        while self._running:
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except TimeoutError:
                continue
            _, _, job_id, pid = item

            # Per-project concurrency check — if over limit, re-queue and yield
            if pid and self._active_per_project.get(pid, 0) >= self._max_per_project:
                # Put back, let other workers drain different projects first
                await asyncio.sleep(0.5)
                self._queue.put_nowait(item)
                self._queue.task_done()
                continue

            self._active_job_ids.add(job_id)
            if pid:
                self._active_per_project[pid] = self._active_per_project.get(pid, 0) + 1

            from .transport import CancellationToken

            token = CancellationToken()
            self._cancel_tokens[job_id] = token
            try:
                if _WORKER_BACKEND == "arq":
                    await self._forward_to_arq(job_id)
                else:
                    from .job_runner import run_queued_job

                    await run_queued_job(job_id, token)
            except Exception as exc:
                logger.exception("Worker error running job %s: %s", job_id, exc)
            finally:
                self._cleanup_job_slot(job_id, pid)

    def _cleanup_job_slot(self, job_id: str, pid: str) -> None:
        self._cancel_tokens.pop(job_id, None)
        self._active_job_ids.discard(job_id)
        if pid:
            count = self._active_per_project.get(pid, 1) - 1
            if count <= 0:
                self._active_per_project.pop(pid, None)
            else:
                self._active_per_project[pid] = count
        self._queue.task_done()


# Module-level singleton
_pool: WorkerPool | None = None


def get_pool() -> WorkerPool:
    global _pool
    if _pool is None:
        _pool = WorkerPool(
            max_workers=_DEFAULT_MAX_WORKERS, max_per_project=_DEFAULT_MAX_PER_PROJECT
        )
    return _pool


def startup_recovery(db) -> int:
    """Re-queue persisted 'queued' jobs on startup. Mark interrupted 'running' jobs as failed."""
    from .. import models
    from ..core.job_tracker import finish_job

    pool = get_pool()
    recovered = 0

    # Mark interrupted running jobs as failed
    running_jobs = db.query(models.Job).filter(models.Job.status == "running").all()
    for job in running_jobs:
        finish_job(
            db,
            job,
            status="failed",
            error_output="[interrupted] Worker restarted while job was running",
        )
        logger.warning("Marked interrupted job %s as failed", job.id)

    # Re-queue persisted queued jobs (ordered by priority desc, then created_at asc)
    queued_jobs = (
        db.query(models.Job)
        .filter(models.Job.status == "queued")
        .order_by(models.Job.priority.desc(), models.Job.created_at)
        .all()
    )
    for job in queued_jobs:
        from .job_runner import supports_queued_execution

        if supports_queued_execution(job.connector_key, job.operation):
            pool.submit(job.id, pid=job.pid, priority=getattr(job, "priority", 0) or 0)
            recovered += 1
            logger.info(
                "Re-queued job %s (%s/%s) priority=%d",
                job.id,
                job.connector_key,
                job.operation,
                getattr(job, "priority", 0) or 0,
            )
        else:
            finish_job(
                db,
                job,
                status="failed",
                error_output="[interrupted] Job type cannot be re-queued after restart",
            )

    db.commit()
    if recovered:
        logger.info("WorkerPool recovery: re-queued %d jobs", recovered)
    return recovered
