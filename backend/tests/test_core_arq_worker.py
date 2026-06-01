"""Tests for app.core.arq_worker — Redis settings parsing and worker functions."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.arq_worker import (
    _redis_settings_from_url,
    run_queued_job_arq,
    _on_startup,
    _on_shutdown,
    WorkerSettings,
    CANCEL_KEY_PREFIX,
    ARQ_QUEUE_NAME,
)


class TestRedisSettingsFromUrl:
    def test_default_url(self):
        with patch.dict("os.environ", {"REDIS_URL": "redis://myhost:6380/2"}):
            s = _redis_settings_from_url()
            assert s.host == "myhost"
            assert s.port == 6380
            assert s.database == 2

    def test_explicit_url(self):
        s = _redis_settings_from_url("redis://custom:9999/5")
        assert s.host == "custom"
        assert s.port == 9999
        assert s.database == 5

    def test_defaults(self):
        with patch.dict("os.environ", {}, clear=True):
            s = _redis_settings_from_url()
            assert s.host == "localhost"
            assert s.port == 6379
            assert s.database == 0

    def test_with_password(self):
        s = _redis_settings_from_url("redis://:secret@host:6379/1")
        assert s.password == "secret"


class TestRunQueuedJobArq:
    @pytest.mark.asyncio
    async def test_cancellation_signal(self):
        mock_redis = AsyncMock()
        mock_redis.get.return_value = b"1"
        mock_redis.delete = AsyncMock()
        ctx = {"redis": mock_redis}
        with patch("app.core.job_runner.run_queued_job", new_callable=AsyncMock) as mock_run:
            mock_run.side_effect = asyncio.CancelledError
            with pytest.raises(asyncio.CancelledError):
                await run_queued_job_arq(ctx, "job_123")

    @pytest.mark.asyncio
    async def test_normal_execution(self):
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        ctx = {"redis": mock_redis}
        with patch("app.core.job_runner.run_queued_job", new_callable=AsyncMock):
            result = await run_queued_job_arq(ctx, "job_abc")
            assert result == {"job_id": "job_abc"}

    @pytest.mark.asyncio
    async def test_cancel_key_prefix(self):
        assert CANCEL_KEY_PREFIX == "rtnotes:cancel:"

    @pytest.mark.asyncio
    async def test_queue_name(self):
        assert ARQ_QUEUE_NAME == "rtnotes:jobs"


class TestWorkerSettings:
    def test_functions_registered(self):
        assert run_queued_job_arq in WorkerSettings.functions

    def test_on_startup(self):
        assert WorkerSettings.on_startup == _on_startup

    def test_on_shutdown(self):
        assert WorkerSettings.on_shutdown == _on_shutdown

    @pytest.mark.asyncio
    async def test_startup_coroutine(self):
        await _on_startup({})

    @pytest.mark.asyncio
    async def test_shutdown_coroutine(self):
        await _on_shutdown({})
