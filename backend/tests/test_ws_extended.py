"""Extended tests for WS — ConnectionManager edge cases."""
import json
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import WebSocket

from app.ws import ConnectionManager


class TestConnectionManagerBroadcastPresence:
    @pytest.mark.asyncio
    async def test_broadcast_presence(self):
        mgr = ConnectionManager()
        mgr.get_presence = AsyncMock(return_value=[{"name": "alice"}])
        mgr.broadcast = AsyncMock()
        await mgr.broadcast_presence("p1")
        mgr.broadcast.assert_called_once()
        msg = mgr.broadcast.call_args[0][1]
        assert msg["type"] == "presence"


class TestConnectionManagerEnsureSubscribed:
    @pytest.mark.asyncio
    async def test_no_redis(self):
        mgr = ConnectionManager()
        mgr._redis = None
        await mgr._ensure_subscribed("p1")

    @pytest.mark.asyncio
    async def test_with_redis(self):
        mgr = ConnectionManager()
        mgr._redis = MagicMock()
        await mgr._ensure_subscribed("p1")
        assert "p1" in mgr._subscribed_pids


class TestConnectionManagerRedisListener:
    @pytest.mark.asyncio
    async def test_listener_no_redis(self):
        mgr = ConnectionManager()
        mgr._redis = None
        await mgr._redis_listener()


class TestConnectionManagerPresenceRedis:
    @pytest.mark.asyncio
    async def test_presence_add_redis(self):
        mgr = ConnectionManager()
        mock_redis = AsyncMock()
        mgr._redis = mock_redis
        await mgr._presence_add("p1", "c1", "alice", None)
        mock_redis.hset.assert_called_once()

    @pytest.mark.asyncio
    async def test_presence_remove_redis(self):
        mgr = ConnectionManager()
        mock_redis = AsyncMock()
        mgr._redis = mock_redis
        await mgr._presence_remove("p1", "c1")
        mock_redis.hdel.assert_called_once()

    @pytest.mark.asyncio
    async def test_presence_add_no_redis(self):
        mgr = ConnectionManager()
        mgr._redis = None
        await mgr._presence_add("p1", "c1", "alice", None)

    @pytest.mark.asyncio
    async def test_presence_remove_no_redis(self):
        mgr = ConnectionManager()
        mgr._redis = None
        await mgr._presence_remove("p1", "c1")


class TestConnectionManagerShutdown:
    @pytest.mark.asyncio
    async def test_shutdown_with_redis(self):
        mgr = ConnectionManager()
        mgr._redis = AsyncMock()
        mgr._subscriber_task = None
        await mgr.shutdown()
        mgr._redis.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_with_task(self):
        mgr = ConnectionManager()
        mgr._redis = None
        mock_task = MagicMock()
        mock_task.cancel = MagicMock()
        mgr._subscriber_task = mock_task
        await mgr.shutdown()
        mock_task.cancel.assert_called_once()
