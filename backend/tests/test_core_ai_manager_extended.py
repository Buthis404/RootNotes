"""Tests for app.core.ai_manager — provider call logic with mocked httpx."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.ai_manager import (
    _RateLimitError,
    _attempt_provider,
    _call_anthropic,
    _call_openai_compat,
    _call_provider,
    _parse_anthropic_response,
    _parse_openai_response,
    _try_provider,
    _try_without_tools,
    call_llm,
    mark_429,
)


class TestCallProvider:
    @pytest.mark.asyncio
    async def test_openai_compat_call(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "hi", "tool_calls": []}}]
        }
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.core.ai_manager.httpx.AsyncClient", return_value=mock_client):
            provider = {"provider": "openai", "api_key": "key", "model": "gpt-4", "base_url": "https://api.openai.com"}
            result = await _call_provider(provider, [{"role": "user", "content": "hi"}], None)
            assert result["content"] == "hi"

    @pytest.mark.asyncio
    async def test_anthropic_call(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "content": [{"type": "text", "text": "hello"}]
        }
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.core.ai_manager.httpx.AsyncClient", return_value=mock_client):
            provider = {"provider": "anthropic", "api_key": "key", "model": "claude-3", "base_url": "https://api.anthropic.com"}
            result = await _call_provider(provider, [{"role": "user", "content": "hello"}], None)
            assert result["content"] == "hello"


class TestCallOpenaiCompat:
    @pytest.mark.asyncio
    async def test_429_raises_rate_limit(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        with pytest.raises(_RateLimitError):
            await _call_openai_compat(mock_client, "key", "gpt-4", "https://api.openai.com", [], None)

    @pytest.mark.asyncio
    async def test_success_with_tools(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "result", "tool_calls": [{"id": "tc1", "type": "function", "function": {"name": "fn", "arguments": "{}"}}]}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        result = await _call_openai_compat(mock_client, "key", "gpt-4", "https://api.openai.com", [], [{"type": "function", "function": {"name": "fn"}}])
        assert result["content"] == "result"
        assert len(result["tool_calls"]) == 1


class TestCallAnthropic:
    @pytest.mark.asyncio
    async def test_429_raises_rate_limit(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        with pytest.raises(_RateLimitError):
            await _call_anthropic(mock_client, "key", "claude-3", "https://api.anthropic.com", [], None)

    @pytest.mark.asyncio
    async def test_tool_use_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "content": [
                {"type": "text", "text": "thinking"},
                {"type": "tool_use", "id": "tu1", "name": "list_hosts", "input": {"q": "test"}},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)

        result = await _call_anthropic(mock_client, "key", "claude-3", "https://api.anthropic.com", [{"role": "user", "content": "list"}], [{"type": "function", "function": {"name": "list_hosts"}}])
        assert "tool_calls" in result
        assert len(result["tool_calls"]) == 1


class TestTryProvider:
    @pytest.mark.asyncio
    async def test_returns_result_with_provider_id(self):
        with patch("app.core.ai_manager._call_provider", new_callable=AsyncMock, return_value={"content": "ok", "tool_calls": []}):
            result = await _try_provider({}, [], None, "p1")
            assert result["provider_id"] == "p1"


class TestTryWithoutTools:
    @pytest.mark.asyncio
    async def test_returns_none_on_error(self):
        with patch("app.core.ai_manager._call_provider", new_callable=AsyncMock, side_effect=Exception("fail")):
            result = await _try_without_tools({}, [], "p1")
            assert result is None


class TestAttemptProvider:
    @pytest.mark.asyncio
    async def test_rate_limit_marks_and_returns_none(self):
        db = MagicMock()
        with patch("app.core.ai_manager._try_provider", new_callable=AsyncMock, side_effect=_RateLimitError()), \
             patch("app.core.ai_manager.mark_429") as mock_mark:
            result = await _attempt_provider({}, [], None, "p1", db)
            assert result is None
            mock_mark.assert_called_once_with(db, "p1")

    @pytest.mark.asyncio
    async def test_error_retries_without_tools(self):
        db = MagicMock()
        with patch("app.core.ai_manager._try_provider", new_callable=AsyncMock, side_effect=Exception("err")), \
             patch("app.core.ai_manager._try_without_tools", new_callable=AsyncMock, return_value={"content": "ok"}) as mock_retry:
            result = await _attempt_provider({}, [], ["tool1"], "p1", db)
            assert result is not None
            mock_retry.assert_called_once()


class TestCallLlm:
    @pytest.mark.asyncio
    async def test_no_providers_raises(self):
        db = MagicMock()
        row = MagicMock()
        row.value = {"providers": []}
        db.query.return_value.filter.return_value.first.return_value = row
        with pytest.raises(Exception) as exc_info:
            await call_llm(db, [{"role": "user", "content": "hi"}])
        assert exc_info.value.status_code == 503


class TestMark429:
    def test_updates_provider_timestamp(self):
        db = MagicMock()
        row = MagicMock()
        row.value = {"providers": [{"id": "p1", "enabled": True}]}
        db.query.return_value.filter.return_value.first.return_value = row
        mark_429(db, "p1")
        assert row.value["providers"][0]["last_429_at"] is not None
        db.commit.assert_called()
