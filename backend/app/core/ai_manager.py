"""
Multi-provider AI manager with failover.

Config is stored in global_settings key "ai_config" as JSONB.
"""

import json
import logging
from datetime import UTC, datetime

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from .utils import ts_now

logger = logging.getLogger(__name__)

_SETTING_KEY = "ai_config"

_DEFAULT_BASE_URLS = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "groq": "https://api.groq.com/openai",
    "mistral": "https://api.mistral.ai",
    "openrouter": "https://openrouter.ai/api",
    "ollama": "http://localhost:11434",
    "litellm": "http://localhost:4000",
}

_RATE_LIMIT_WINDOW_SECONDS = 90


def _load_config(db: Session) -> dict:
    from ..models import GlobalSetting

    row = db.query(GlobalSetting).filter(GlobalSetting.key == _SETTING_KEY).first()
    return row.value if row else {}


def _save_config(db: Session, cfg: dict) -> None:
    from ..models import GlobalSetting

    row = db.query(GlobalSetting).filter(GlobalSetting.key == _SETTING_KEY).first()
    if row:
        row.value = cfg
    else:
        db.add(GlobalSetting(key=_SETTING_KEY, value=cfg))
    db.commit()


def get_config(db: Session) -> dict:
    return _load_config(db)


def save_config(db: Session, cfg: dict) -> None:
    _save_config(db, cfg)


def get_next_provider(db: Session) -> dict | None:
    """Return the enabled provider with lowest priority, skipping rate-limited ones."""
    cfg = _load_config(db)
    providers = cfg.get("providers", [])
    now = datetime.now(UTC)
    candidates = []
    for p in providers:
        if not p.get("enabled", False):
            continue
        last_429 = p.get("last_429_at")
        if last_429:
            try:
                dt = datetime.fromisoformat(last_429.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                if (now - dt).total_seconds() < _RATE_LIMIT_WINDOW_SECONDS:
                    continue
            except Exception as e:
                logger.debug("could not parse last_429_at %r: %s", last_429, e)
        candidates.append(p)
    if not candidates:
        return None
    candidates.sort(key=lambda x: x.get("priority", 999))
    return candidates[0]


def mark_429(db: Session, provider_id: str) -> None:
    """Record a rate-limit hit for a provider."""
    cfg = _load_config(db)
    now_str = ts_now()
    for p in cfg.get("providers", []):
        if p.get("id") == provider_id:
            p["last_429_at"] = now_str
            break
    _save_config(db, cfg)


def _build_assistant_tool_call_blocks(msg: dict) -> list:
    content = msg.get("content", "")
    blocks = []
    if content:
        blocks.append({"type": "text", "text": content})
    for tc in msg.get("tool_calls", []):
        fn = tc.get("function", {})
        input_data = fn.get("arguments", {})
        if isinstance(input_data, str):
            try:
                input_data = json.loads(input_data)
            except Exception:
                input_data = {}
        blocks.append({
            "type": "tool_use",
            "id": tc.get("id", "call_0"),
            "name": fn.get("name", ""),
            "input": input_data,
        })
    return blocks


def _convert_messages_to_anthropic(messages: list) -> tuple[str, list]:
    """Convert OpenAI-format messages to Anthropic format. Returns (system, messages)."""
    system = ""
    anthropic_messages = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if role == "system":
            system = content
        elif role == "tool":
            tool_call_id = msg.get("tool_call_id", "")
            anthropic_messages.append({
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": tool_call_id, "content": str(content)}],
            })
        elif role == "assistant" and msg.get("tool_calls"):
            anthropic_messages.append({"role": "assistant", "content": _build_assistant_tool_call_blocks(msg)})
        else:
            anthropic_messages.append({"role": role, "content": content})
    return system, anthropic_messages


def _convert_tools_to_anthropic(tools: list) -> list:
    """Convert OpenAI tool format to Anthropic tool format."""
    result = []
    for t in tools:
        if t.get("type") == "function":
            fn = t["function"]
            result.append(
                {
                    "name": fn["name"],
                    "description": fn.get("description", ""),
                    "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
                }
            )
        else:
            # Already in Anthropic format
            result.append(t)
    return result


def _parse_anthropic_response(data: dict) -> dict:
    """Parse Anthropic response into unified format."""
    content_text = ""
    tool_calls = []
    for block in data.get("content", []):
        if block.get("type") == "text":
            content_text += block.get("text", "")
        elif block.get("type") == "tool_use":
            tool_calls.append(
                {
                    "id": block.get("id", ""),
                    "type": "function",
                    "function": {
                        "name": block.get("name", ""),
                        "arguments": json.dumps(block.get("input", {})),
                    },
                }
            )
    return {"content": content_text, "tool_calls": tool_calls}


def _parse_openai_response(data: dict) -> dict:
    """Parse OpenAI-compatible response into unified format."""
    import re

    choices = data.get("choices", [])
    if not choices:
        return {"content": "", "tool_calls": []}
    msg = choices[0].get("message", {})
    # Use only `content` — never fall back to `reasoning_content` which is the
    # model's internal chain-of-thought and must not be surfaced to the user.
    content = msg.get("content") or ""
    # Some thinking models embed CoT in content wrapped with <think> tags.
    # Strip those blocks so only the final answer reaches the user.
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
    return {
        "content": content,
        "tool_calls": msg.get("tool_calls") or [],
    }


def _is_rate_limited(provider: dict, now: "datetime") -> bool:
    last_429 = provider.get("last_429_at")
    if not last_429:
        return False
    try:
        dt = datetime.fromisoformat(last_429.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return (now - dt).total_seconds() < _RATE_LIMIT_WINDOW_SECONDS
    except Exception:
        return False


async def _try_provider(provider, messages, tools, pid):
    result = await _call_provider(provider, messages, tools)
    result["provider_id"] = pid
    return result


async def _try_without_tools(provider, messages, pid):
    try:
        result = await _call_provider(provider, messages, None)
        result["provider_id"] = pid
        return result
    except Exception as e2:
        logger.warning("[ai_manager] Provider %s error without tools: %s", pid, e2)
        return None


async def _attempt_provider(provider, messages, tools, pid, db):
    try:
        return await _try_provider(provider, messages, tools, pid)
    except _RateLimitError:
        mark_429(db, pid)
        logger.warning("[ai_manager] Provider %s rate limited, trying next", pid)
        return None
    except Exception as e:
        logger.warning("[ai_manager] Provider %s error with tools: %s", pid, e)
        if tools:
            return await _try_without_tools(provider, messages, pid)
        return None


async def call_llm(db: Session, messages: list, tools: list | None = None) -> dict:
    cfg = _load_config(db)
    all_providers = sorted(
        [p for p in cfg.get("providers", []) if p.get("enabled", False)],
        key=lambda x: x.get("priority", 999),
    )
    if not all_providers:
        raise HTTPException(503, "No AI providers configured")

    now = datetime.now(UTC)
    tried = set()

    for provider in all_providers:
        pid = provider.get("id")
        if pid in tried or _is_rate_limited(provider, now):
            continue

        tried.add(pid)
        result = await _attempt_provider(provider, messages, tools, pid, db)
        if result:
            return result

    raise HTTPException(503, "All AI providers are unavailable or rate limited")


class _RateLimitError(Exception):
    pass


async def _call_provider(provider: dict, messages: list, tools: list | None = None) -> dict:
    """Call a specific provider and return unified response."""
    ptype = provider.get("provider", "openai")
    api_key = provider.get("api_key", "")
    model = provider.get("model", "")
    base_url = provider.get("base_url") or _DEFAULT_BASE_URLS.get(ptype, "")

    # Thinking / reasoning models (Qwen3, DeepSeek-R1, etc.) typically don't
    # support function calling. skip_tools bypasses tools entirely so the
    # first call succeeds instead of failing with 500 → double round-trip.
    if provider.get("skip_tools"):
        tools = None

    async with httpx.AsyncClient(timeout=300.0) as client:
        if ptype == "anthropic":
            return await _call_anthropic(client, api_key, model, base_url, messages, tools)
        else:
            return await _call_openai_compat(client, api_key, model, base_url, messages, tools)


async def _call_anthropic(
    client: httpx.AsyncClient,
    api_key: str,
    model: str,
    base_url: str,
    messages: list,
    tools: list | None,
) -> dict:
    system, anthropic_messages = _convert_messages_to_anthropic(messages)
    body = {
        "model": model,
        "messages": anthropic_messages,
        "max_tokens": 4096,
    }
    if system:
        body["system"] = system
    if tools:
        body["tools"] = _convert_tools_to_anthropic(tools)

    url = f"{base_url.rstrip('/')}/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    resp = await client.post(url, json=body, headers=headers)
    if resp.status_code == 429:
        raise _RateLimitError()
    resp.raise_for_status()
    return _parse_anthropic_response(resp.json())


async def _call_openai_compat(
    client: httpx.AsyncClient,
    api_key: str,
    model: str,
    base_url: str,
    messages: list,
    tools: list | None,
) -> dict:
    # Filter out system messages into a single system string for providers that support it
    body = {
        "model": model,
        "messages": messages,
        "max_tokens": 4096,
    }
    if tools:
        body["tools"] = tools

    url = f"{base_url.rstrip('/')}/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    resp = await client.post(url, json=body, headers=headers)
    if resp.status_code == 429:
        raise _RateLimitError()
    resp.raise_for_status()
    return _parse_openai_response(resp.json())
