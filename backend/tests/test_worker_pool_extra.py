import pytest
from unittest.mock import patch, MagicMock
import asyncio

from app.core.worker_pool import WorkerPool, get_pool


class TestWorkerPool:
    def test_queue_size(self):
        pool = WorkerPool(max_workers=2, max_per_project=2)
        assert pool.queue_size == 0

    def test_active_count(self):
        pool = WorkerPool(max_workers=2, max_per_project=2)
        assert pool.active_count == 0

    def test_active_jobs(self):
        pool = WorkerPool(max_workers=2, max_per_project=2)
        assert pool.active_jobs == []

    def test_per_project_counts(self):
        pool = WorkerPool(max_workers=2, max_per_project=2)
        assert pool.per_project_counts == {}

    @pytest.mark.asyncio
    async def test_stop(self):
        pool = WorkerPool(max_workers=2, max_per_project=2)
        pool._running = True
        await pool.stop()
        assert pool._running is False


class TestGetPool:
    def test_singleton(self):
        import app.core.worker_pool as mod
        old = mod._pool
        mod._pool = None
        pool = get_pool()
        assert pool is not None
        pool2 = get_pool()
        assert pool is pool2
        mod._pool = old
