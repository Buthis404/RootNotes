"""
arq worker entry point.

Start the worker process with:
    arq app.core.arq_worker.WorkerSettings

Environment variables (same as the API container):
    DATABASE_URL   — PostgreSQL connection string
    REDIS_URL      — Redis connection string
    ENCRYPTION_KEY — Fernet key (required if APP_ENV=production)
    UPLOAD_ROOT    — path for loot file storage

Cancellation protocol
---------------------
When a user cancels a running job via the REST API, the API sets the Redis
key  ``rtnotes:cancel:<job_id>``  to ``"1"``.  The worker polls that key
every 0.5 s while the job is running and propagates the signal to the
CancellationToken used by SSH/subprocess calls.
"""

from __future__ import annotations

import asyncio
import logging
import os
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

CANCEL_KEY_PREFIX = "rtnotes:cancel:"
ARQ_QUEUE_NAME = "rtnotes:jobs"


def _redis_settings_from_url(url: str | None = None):
    """Parse REDIS_URL into arq RedisSettings."""
    from arq.connections import RedisSettings

    raw = url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    p = urlparse(raw)
    return RedisSettings(
        host=p.hostname or "localhost",
        port=p.port or 6379,
        password=p.password or None,
        database=int((p.path or "/0").lstrip("/") or 0),
    )


async def run_queued_job_arq(ctx: dict, job_id: str) -> dict:
    """arq job function.

    Wraps the internal ``run_queued_job`` coroutine with Redis-based
    cancel signal polling so jobs can be aborted across processes.
    """
    from .job_runner import run_queued_job
    from .transport import CancellationToken

    redis = ctx["redis"]
    token = CancellationToken()
    cancel_event = asyncio.Event()

    async def _poll_cancel() -> None:
        while not cancel_event.is_set():
            flag = await redis.get(f"{CANCEL_KEY_PREFIX}{job_id}")
            if flag:
                token.cancel()
                await redis.delete(f"{CANCEL_KEY_PREFIX}{job_id}")
                cancel_event.set()
                break
            try:
                await asyncio.wait_for(cancel_event.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass

    poll_task = asyncio.create_task(_poll_cancel())
    try:
        await run_queued_job(job_id, token)
    finally:
        poll_task.cancel()
        await asyncio.gather(poll_task, return_exceptions=True)

    return {"job_id": job_id}


async def _on_startup(ctx: dict) -> None:
    logger.info("arq worker started (queue=%s)", ARQ_QUEUE_NAME)
    await asyncio.sleep(0)


async def _on_shutdown(ctx: dict) -> None:
    logger.info("arq worker shutting down")
    await asyncio.sleep(0)


class WorkerSettings:
    """arq WorkerSettings — referenced by the docker-compose worker service."""

    functions = [run_queued_job_arq]
    redis_settings = _redis_settings_from_url()
    max_jobs = int(os.environ.get("WORKER_POOL_MAX_WORKERS", "8"))
    job_timeout = 3600  # 1 h hard limit; individual jobs enforce their own timeout
    health_check_interval = 30
    queue_name = ARQ_QUEUE_NAME
    on_startup = _on_startup
    on_shutdown = _on_shutdown
