"""Tests for app.core.token_blacklist — JWT revocation via Redis."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.token_blacklist import (
    blacklist_token,
    is_blacklisted,
    _KEY_PREFIX,
    _get_client,
)


class TestGetClient:
    def test_returns_none_when_no_redis_url(self):
        import app.core.token_blacklist as mod
        mod._client = None
        with patch.dict("os.environ", {"REDIS_URL": ""}), \
             patch.object(mod, "_REDIS_URL", ""):
            result = _get_client()
            assert result is None

    def test_caches_client(self):
        import app.core.token_blacklist as mod
        mock_client = MagicMock()
        mod._client = mock_client
        result = _get_client()
        assert result is mock_client
        mod._client = None


class TestBlacklistToken:
    @pytest.mark.asyncio
    async def test_noop_when_no_client(self):
        import app.core.token_blacklist as mod
        mod._client = None
        with patch.dict("os.environ", {"REDIS_URL": ""}), \
             patch("app.core.token_blacklist._get_client", return_value=None):
            await blacklist_token("jti123", exp=9999999999)

    @pytest.mark.asyncio
    async def test_sets_key_with_ttl(self):
        mock_redis = AsyncMock()
        import app.core.token_blacklist as mod
        mod._client = mock_redis
        with patch("app.core.token_blacklist._get_client", return_value=mock_redis), \
             patch("app.core.token_blacklist.datetime") as mock_dt:
            mock_dt.now.return_value.timestamp.return_value = 1000
            mock_dt.UTC = MagicMock()
            await blacklist_token("jti123", exp=1100)
            mock_redis.setex.assert_called_once()
            call_args = mock_redis.setex.call_args
            assert call_args[0][0] == f"{_KEY_PREFIX}jti123"
            assert call_args[0][1] == 100
        mod._client = None

    @pytest.mark.asyncio
    async def test_handles_redis_error(self):
        mock_redis = AsyncMock()
        mock_redis.setex.side_effect = Exception("connection error")
        import app.core.token_blacklist as mod
        mod._client = mock_redis
        with patch("app.core.token_blacklist._get_client", return_value=mock_redis), \
             patch("app.core.token_blacklist.datetime") as mock_dt:
            mock_dt.now.return_value.timestamp.return_value = 1000
            mock_dt.UTC = MagicMock()
            await blacklist_token("jti123", exp=1100)
        mod._client = None


class TestIsBlacklisted:
    @pytest.mark.asyncio
    async def test_returns_false_empty_jti(self):
        assert await is_blacklisted("") is False

    @pytest.mark.asyncio
    async def test_returns_false_no_client(self):
        import app.core.token_blacklist as mod
        mod._client = None
        with patch("app.core.token_blacklist._get_client", return_value=None):
            assert await is_blacklisted("jti123") is False

    @pytest.mark.asyncio
    async def test_returns_true_when_exists(self):
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = 1
        import app.core.token_blacklist as mod
        mod._client = mock_redis
        with patch("app.core.token_blacklist._get_client", return_value=mock_redis):
            result = await is_blacklisted("jti123")
            assert result is True
            mock_redis.exists.assert_called_once_with(f"{_KEY_PREFIX}jti123")
        mod._client = None

    @pytest.mark.asyncio
    async def test_returns_false_when_not_exists(self):
        mock_redis = AsyncMock()
        mock_redis.exists.return_value = 0
        import app.core.token_blacklist as mod
        mod._client = mock_redis
        with patch("app.core.token_blacklist._get_client", return_value=mock_redis):
            result = await is_blacklisted("jti123")
            assert result is False
        mod._client = None

    @pytest.mark.asyncio
    async def test_handles_exception(self):
        mock_redis = AsyncMock()
        mock_redis.exists.side_effect = Exception("error")
        import app.core.token_blacklist as mod
        mod._client = mock_redis
        with patch("app.core.token_blacklist._get_client", return_value=mock_redis):
            result = await is_blacklisted("jti123")
            assert result is False
        mod._client = None
