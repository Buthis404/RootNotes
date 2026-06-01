"""Tests for app.core.worker_pool — pool lifecycle, submit, cancel."""
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from app.core.worker_pool import WorkerPool, _env_int


class TestEnvInt:
    def test_default_when_unset(self):
        with patch.dict("os.environ", {}, clear=True):
            assert _env_int("NONEXISTENT_VAR", 42) == 42

    def test_parses_valid_int(self):
        with patch.dict("os.environ", {"TEST_VAR": "10"}):
            assert _env_int("TEST_VAR", 5) == 10

    def test_returns_default_on_zero(self):
        with patch.dict("os.environ", {"TEST_VAR": "0"}):
            assert _env_int("TEST_VAR", 5) == 5

    def test_returns_default_on_negative(self):
        with patch.dict("os.environ", {"TEST_VAR": "-1"}):
            assert _env_int("TEST_VAR", 5) == 5

    def test_returns_default_on_invalid(self):
        with patch.dict("os.environ", {"TEST_VAR": "abc"}):
            assert _env_int("TEST_VAR", 5) == 5


class TestWorkerPoolInit:
    def test_initial_state(self):
        pool = WorkerPool(max_workers=2, max_per_project=1)
        assert pool.queue_size == 0
        assert pool.active_count == 0
        assert pool.active_jobs == []
        assert pool.per_project_counts == {}


class TestWorkerPoolSubmit:
    def test_submit_increments_queue(self):
        pool = WorkerPool(max_workers=2)
        pool.submit("job1", pid="p1", priority=1)
        assert pool.queue_size == 1

    def test_submit_multiple(self):
        pool = WorkerPool(max_workers=2)
        pool.submit("j1")
        pool.submit("j2")
        pool.submit("j3")
        assert pool.queue_size == 3


class TestWorkerPoolCancel:
    def test_cancel_nonexistent_returns_false(self):
        pool = WorkerPool(max_workers=2)
        assert pool.cancel_job("nonexistent") is False

    def test_cancel_existing_token(self):
        pool = WorkerPool(max_workers=2)
        token = MagicMock()
        pool._cancel_tokens["j1"] = token
        assert pool.cancel_job("j1") is True
        token.cancel.assert_called_once()


class TestWorkerPoolStartStop:
    @pytest.mark.asyncio
    async def test_start_and_stop(self):
        pool = WorkerPool(max_workers=2, max_per_project=1)
        pool.start()
        assert pool._running is True
        assert len(pool._worker_tasks) == 2
        await pool.stop()
        assert pool._running is False
        assert len(pool._worker_tasks) == 0

    @pytest.mark.asyncio
    async def test_start_idempotent(self):
        pool = WorkerPool(max_workers=1)
        pool.start()
        pool.start()
        assert len(pool._worker_tasks) == 1
        await pool.stop()


class TestWorkerPoolCleanup:
    def test_cleanup_removes_job(self):
        pool = WorkerPool(max_workers=2)
        pool._active_job_ids.add("j1")
        pool._active_per_project["p1"] = 1
        pool._cancel_tokens["j1"] = MagicMock()
        import asyncio
        pool._queue.put_nowait(None)
        pool._cleanup_job_slot("j1", "p1")
        assert "j1" not in pool._active_job_ids
        assert "p1" not in pool._active_per_project
        assert "j1" not in pool._cancel_tokens

    def test_cleanup_decrements_project_count(self):
        pool = WorkerPool(max_workers=2)
        pool._active_per_project["p1"] = 3
        import asyncio
        pool._queue.put_nowait(None)
        pool._cleanup_job_slot("j1", "p1")
        assert pool._active_per_project["p1"] == 2

    def test_cleanup_no_pid(self):
        pool = WorkerPool(max_workers=2)
        pool._active_job_ids.add("j1")
        import asyncio
        pool._queue.put_nowait(None)
        pool._cleanup_job_slot("j1", "")
        assert "j1" not in pool._active_job_ids


class TestGetPool:
    def test_creates_singleton(self):
        with patch("app.core.worker_pool._pool", None):
            from app.core.worker_pool import get_pool
            pool = get_pool()
            assert pool is not None
            assert isinstance(pool, WorkerPool)


class TestStartupRecovery:
    def test_marks_interrupted_running_as_failed(self):
        mock_db = MagicMock()
        job = MagicMock()
        job.id = "j_interrupted"
        job.status = "running"
        mock_db.query.return_value.filter.return_value.all.return_value = [job]
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []

        mock_pool = MagicMock()
        with patch("app.core.worker_pool.get_pool", return_value=mock_pool), \
             patch("app.core.worker_pool._pool", MagicMock()), \
             patch("app.core.job_tracker.finish_job") as mock_finish:
            from app.core.worker_pool import startup_recovery
            result = startup_recovery(mock_db)
            mock_finish.assert_called()
            mock_db.commit.assert_called()
