"""Consolidated tests for test_core_ai_manager (merged variant files)."""

# ════════ from test_core_ai_manager.py ════════
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from app.core.ai_manager import (
    _build_assistant_tool_call_blocks,
    _convert_messages_to_anthropic,
    _convert_tools_to_anthropic,
    _is_rate_limited,
    _parse_anthropic_response,
    _parse_openai_response,
    get_next_provider,
)


class TestBuildAssistantToolCallBlocks:
    def test_text_only(self):
        msg = {"content": "hello"}
        blocks = _build_assistant_tool_call_blocks(msg)
        assert blocks == [{"type": "text", "text": "hello"}]

    def test_tool_call_only(self):
        msg = {
            "content": "",
            "tool_calls": [
                {"id": "tc1", "function": {"name": "list_hosts", "arguments": '{"q": "test"}'}}
            ],
        }
        blocks = _build_assistant_tool_call_blocks(msg)
        assert len(blocks) == 1
        assert blocks[0]["type"] == "tool_use"
        assert blocks[0]["name"] == "list_hosts"
        assert blocks[0]["input"] == {"q": "test"}

    def test_tool_call_string_args_parsed(self):
        msg = {
            "content": "",
            "tool_calls": [
                {"id": "tc1", "function": {"name": "test", "arguments": '{"key": "val"}'}}
            ],
        }
        blocks = _build_assistant_tool_call_blocks(msg)
        assert blocks[0]["input"] == {"key": "val"}

    def test_tool_call_invalid_json_args(self):
        msg = {
            "content": "",
            "tool_calls": [
                {"id": "tc1", "function": {"name": "test", "arguments": "not-json"}}
            ],
        }
        blocks = _build_assistant_tool_call_blocks(msg)
        assert blocks[0]["input"] == {}

    def test_tool_call_dict_args(self):
        msg = {
            "content": "",
            "tool_calls": [
                {"id": "tc1", "function": {"name": "test", "arguments": {"key": "val"}}}
            ],
        }
        blocks = _build_assistant_tool_call_blocks(msg)
        assert blocks[0]["input"] == {"key": "val"}

    def test_empty_content_no_text_block(self):
        msg = {"content": "", "tool_calls": []}
        blocks = _build_assistant_tool_call_blocks(msg)
        assert blocks == []

    def test_mixed_content_and_tool_calls(self):
        msg = {
            "content": "thinking",
            "tool_calls": [{"id": "tc1", "function": {"name": "fn", "arguments": {}}}],
        }
        blocks = _build_assistant_tool_call_blocks(msg)
        assert len(blocks) == 2
        assert blocks[0]["type"] == "text"
        assert blocks[1]["type"] == "tool_use"

    def test_default_id(self):
        msg = {"content": "", "tool_calls": [{"function": {"name": "fn", "arguments": {}}}]}
        blocks = _build_assistant_tool_call_blocks(msg)
        assert blocks[0]["id"] == "call_0"


class TestConvertMessagesToAnthropic:
    def test_system_extracted(self):
        messages = [
            {"role": "system", "content": "You are helpful"},
            {"role": "user", "content": "hello"},
        ]
        system, result = _convert_messages_to_anthropic(messages)
        assert system == "You are helpful"
        assert len(result) == 1
        assert result[0]["role"] == "user"

    def test_tool_message(self):
        messages = [
            {"role": "tool", "content": "result data", "tool_call_id": "tc1"},
        ]
        system, result = _convert_messages_to_anthropic(messages)
        assert result[0]["role"] == "user"
        assert result[0]["content"][0]["type"] == "tool_result"
        assert result[0]["content"][0]["tool_use_id"] == "tc1"

    def test_assistant_with_tool_calls(self):
        messages = [
            {"role": "assistant", "content": "let me check", "tool_calls": [
                {"id": "tc1", "function": {"name": "fn", "arguments": {}}}
            ]},
        ]
        system, result = _convert_messages_to_anthropic(messages)
        assert result[0]["role"] == "assistant"
        assert any(b["type"] == "tool_use" for b in result[0]["content"])

    def test_regular_message(self):
        messages = [{"role": "user", "content": "hi"}]
        system, result = _convert_messages_to_anthropic(messages)
        assert result[0] == {"role": "user", "content": "hi"}

    def test_empty_messages(self):
        system, result = _convert_messages_to_anthropic([])
        assert system == ""
        assert result == []


class TestConvertToolsToAnthropic:
    def test_function_tool(self):
        tools = [{"type": "function", "function": {
            "name": "list_hosts",
            "description": "List hosts",
            "parameters": {"type": "object", "properties": {}},
        }}]
        result = _convert_tools_to_anthropic(tools)
        assert len(result) == 1
        assert result[0]["name"] == "list_hosts"
        assert "input_schema" in result[0]

    def test_already_anthropic_format(self):
        tools = [{"name": "list_hosts", "description": "List", "input_schema": {"type": "object"}}]
        result = _convert_tools_to_anthropic(tools)
        assert result == tools

    def test_empty(self):
        assert _convert_tools_to_anthropic([]) == []


class TestParseAnthropicResponse:
    def test_text_only(self):
        data = {"content": [{"type": "text", "text": "Hello!"}]}
        result = _parse_anthropic_response(data)
        assert result["content"] == "Hello!"
        assert result["tool_calls"] == []

    def test_tool_use(self):
        data = {"content": [
            {"type": "text", "text": "Let me check"},
            {"type": "tool_use", "id": "tu1", "name": "fn", "input": {"key": "val"}},
        ]}
        result = _parse_anthropic_response(data)
        assert "Let me check" in result["content"]
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["function"]["name"] == "fn"

    def test_empty_content(self):
        result = _parse_anthropic_response({})
        assert result["content"] == ""
        assert result["tool_calls"] == []


class TestParseOpenAIResponse:
    def test_basic(self):
        data = {"choices": [{"message": {"content": "Hi there", "tool_calls": []}}]}
        result = _parse_openai_response(data)
        assert result["content"] == "Hi there"
        assert result["tool_calls"] == []

    def test_tool_calls(self):
        data = {"choices": [{"message": {
            "content": None,
            "tool_calls": [{"id": "tc1", "function": {"name": "fn", "arguments": "{}"}}],
        }}]}
        result = _parse_openai_response(data)
        assert len(result["tool_calls"]) == 1

    def test_empty_choices(self):
        result = _parse_openai_response({})
        assert result["content"] == ""
        assert result["tool_calls"] == []

    def test_reasoning_content_not_used_as_answer(self):
        """reasoning_content is the model's internal chain-of-thought and must
        never be surfaced as the answer — empty content stays empty."""
        data = {"choices": [{"message": {"content": None, "reasoning_content": "thought process"}}]}
        result = _parse_openai_response(data)
        assert result["content"] == ""

    def test_think_tags_stripped(self):
        """<think>...</think> blocks are stripped from content for models that
        embed chain-of-thought inline."""
        data = {"choices": [{"message": {"content": "<think>reasoning here</think>Final answer"}}]}
        result = _parse_openai_response(data)
        assert result["content"] == "Final answer"


class TestIsRateLimited:
    def test_no_last_429(self):
        assert _is_rate_limited({}, datetime.now(UTC)) is False

    def test_recent_429(self):
        now = datetime.now(UTC)
        provider = {"last_429_at": now.isoformat()}
        assert _is_rate_limited(provider, now) is True

    def test_old_429(self):
        old = datetime.now(UTC) - timedelta(seconds=120)
        provider = {"last_429_at": old.isoformat()}
        assert _is_rate_limited(provider, datetime.now(UTC)) is False

    def test_invalid_timestamp(self):
        provider = {"last_429_at": "not-a-timestamp"}
        assert _is_rate_limited(provider, datetime.now(UTC)) is False

    def test_z_suffix(self):
        now = datetime.now(UTC)
        ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        provider = {"last_429_at": ts}
        assert _is_rate_limited(provider, now) is True


class TestGetNextProvider:
    def test_no_providers(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert get_next_provider(db) is None

    def test_returns_lowest_priority(self):
        db = MagicMock()
        cfg_row = MagicMock(value={
            "providers": [
                {"id": "p1", "enabled": True, "priority": 2},
                {"id": "p2", "enabled": True, "priority": 1},
            ]
        })
        db.query.return_value.filter.return_value.first.return_value = cfg_row
        result = get_next_provider(db)
        assert result["id"] == "p2"

    def test_skips_disabled(self):
        db = MagicMock()
        cfg_row = MagicMock(value={
            "providers": [
                {"id": "p1", "enabled": False, "priority": 1},
                {"id": "p2", "enabled": True, "priority": 2},
            ]
        })
        db.query.return_value.filter.return_value.first.return_value = cfg_row
        result = get_next_provider(db)
        assert result["id"] == "p2"

    def test_skips_rate_limited(self):
        now = datetime.now(UTC)
        db = MagicMock()
        cfg_row = MagicMock(value={
            "providers": [
                {"id": "p1", "enabled": True, "priority": 1, "last_429_at": now.isoformat()},
                {"id": "p2", "enabled": True, "priority": 2},
            ]
        })
        db.query.return_value.filter.return_value.first.return_value = cfg_row
        result = get_next_provider(db)
        assert result["id"] == "p2"


# ════════ from test_core_ai_manager_extended.py ════════
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
