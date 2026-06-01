import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.worker_pool import WorkerPool, _env_int, get_pool, startup_recovery


class TestEnvInt:
    def test_valid(self):
        with patch.dict("os.environ", {"TEST_VAL": "42"}):
            assert _env_int("TEST_VAL", 0) == 42

    def test_missing(self):
        assert _env_int("NONEXISTENT_VAR_XYZ", 10) == 10

    def test_zero_returns_default(self):
        with patch.dict("os.environ", {"TEST_VAL": "0"}):
            assert _env_int("TEST_VAL", 10) == 10

    def test_invalid(self):
        with patch.dict("os.environ", {"TEST_VAL": "abc"}):
            assert _env_int("TEST_VAL", 10) == 10


class TestWorkerPool:
    def test_init(self):
        pool = WorkerPool(max_workers=4, max_per_project=2)
        assert pool._max_workers == 4
        assert pool._max_per_project == 2
        assert pool.queue_size == 0
        assert pool.active_count == 0
        assert pool.active_jobs == []

    def test_submit(self):
        pool = WorkerPool()
        pool.submit("job1", pid="p1", priority=5)
        assert pool.queue_size == 1

    def test_submit_priority(self):
        pool = WorkerPool()
        pool.submit("j1", priority=10)
        pool.submit("j2", priority=1)
        assert pool.queue_size == 2

    def test_cancel_job_no_token(self):
        pool = WorkerPool()
        assert pool.cancel_job("nonexistent") is False

    def test_cancel_job_with_token(self):
        pool = WorkerPool()
        token = MagicMock()
        pool._cancel_tokens["j1"] = token
        assert pool.cancel_job("j1") is True
        token.cancel.assert_called_once()

    def test_per_project_counts(self):
        pool = WorkerPool()
        pool._active_per_project["p1"] = 2
        assert pool.per_project_counts == {"p1": 2}

    def test_cleanup_job_slot(self):
        pool = WorkerPool()
        pool._active_job_ids.add("j1")
        pool._active_per_project["p1"] = 1
        pool._cancel_tokens["j1"] = MagicMock()
        pool._queue.put_nowait((0, 0, "j1", "p1"))
        pool._cleanup_job_slot("j1", "p1")
        assert "j1" not in pool._active_job_ids
        assert "p1" not in pool._active_per_project

    def test_cleanup_job_slot_zero_count(self):
        pool = WorkerPool()
        pool._active_per_project["p1"] = 1
        pool._queue.put_nowait((0, 0, "j1", "p1"))
        pool._cleanup_job_slot("j1", "p1")
        assert "p1" not in pool._active_per_project

    @pytest.mark.asyncio
    async def test_start_stop(self):
        pool = WorkerPool(max_workers=2)
        pool.start()
        assert pool._running is True
        assert len(pool._worker_tasks) == 2
        await pool.stop()
        assert pool._running is False
        assert len(pool._worker_tasks) == 0

    @pytest.mark.asyncio
    async def test_start_idempotent(self):
        pool = WorkerPool(max_workers=2)
        pool.start()
        pool.start()
        assert len(pool._worker_tasks) == 2
        await pool.stop()

    @pytest.mark.asyncio
    async def test_forward_to_arq_no_pool(self):
        pool = WorkerPool()
        mock_coro = AsyncMock()
        with patch("app.core.arq_pool.get_arq_pool", return_value=None), \
             patch("app.core.job_runner.run_queued_job", new=mock_coro):
            await pool._forward_to_arq("j1")
            mock_coro.assert_called_once()


class TestGetPool:
    def test_singleton(self):
        import app.core.worker_pool as wp
        old = wp._pool
        wp._pool = None
        pool1 = get_pool()
        pool2 = get_pool()
        assert pool1 is pool2
        wp._pool = old


class TestStartupRecovery:
    def test_no_jobs(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = []
        db.query.return_value.order_by.return_value.all.return_value = []
        with patch("app.core.worker_pool.get_pool") as mock_pool:
            result = startup_recovery(db)
            assert result == 0
