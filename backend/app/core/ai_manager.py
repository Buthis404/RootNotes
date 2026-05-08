"""
Multi-provider AI manager with failover.

Config is stored in global_settings key "ai_config" as JSONB.
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

_SETTING_KEY = "ai_config"

_DEFAULT_BASE_URLS = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "groq": "https://api.groq.com/openai",
    "mistral": "https://api.mistral.ai",
    "openrouter": "https://openrouter.ai/api",
    "ollama": "http://localhost:11434",
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


def get_next_provider(db: Session) -> Optional[dict]:
    """Return the enabled provider with lowest priority, skipping rate-limited ones."""
    cfg = _load_config(db)
    providers = cfg.get("providers", [])
    now = datetime.now(timezone.utc)
    candidates = []
    for p in providers:
        if not p.get("enabled", False):
            continue
        last_429 = p.get("last_429_at")
        if last_429:
            try:
                dt = datetime.fromisoformat(last_429.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if (now - dt).total_seconds() < _RATE_LIMIT_WINDOW_SECONDS:
                    continue
            except Exception:
                pass
        candidates.append(p)
    if not candidates:
        return None
    candidates.sort(key=lambda x: x.get("priority", 999))
    return candidates[0]


def mark_429(db: Session, provider_id: str) -> None:
    """Record a rate-limit hit for a provider."""
    cfg = _load_config(db)
    now_str = datetime.now(timezone.utc).isoformat()
    for p in cfg.get("providers", []):
        if p.get("id") == provider_id:
            p["last_429_at"] = now_str
            break
    _save_config(db, cfg)


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
            # Tool results become user messages in Anthropic format
            tool_call_id = msg.get("tool_call_id", "")
            anthropic_messages.append({
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_call_id,
                        "content": str(content),
                    }
                ],
            })
        elif role == "assistant" and msg.get("tool_calls"):
            # Assistant message with tool calls
            content_blocks = []
            if content:
                content_blocks.append({"type": "text", "text": content})
            for tc in msg["tool_calls"]:
                fn = tc.get("function", {})
                input_data = fn.get("arguments", {})
                if isinstance(input_data, str):
                    try:
                        input_data = json.loads(input_data)
                    except Exception:
                        input_data = {}
                content_blocks.append({
                    "type": "tool_use",
                    "id": tc.get("id", "call_0"),
                    "name": fn.get("name", ""),
                    "input": input_data,
                })
            anthropic_messages.append({"role": "assistant", "content": content_blocks})
        else:
            anthropic_messages.append({"role": role, "content": content})
    return system, anthropic_messages


def _convert_tools_to_anthropic(tools: list) -> list:
    """Convert OpenAI tool format to Anthropic tool format."""
    result = []
    for t in tools:
        if t.get("type") == "function":
            fn = t["function"]
            result.append({
                "name": fn["name"],
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
            })
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
            tool_calls.append({
                "id": block.get("id", ""),
                "type": "function",
                "function": {
                    "name": block.get("name", ""),
                    "arguments": json.dumps(block.get("input", {})),
                },
            })
    return {"content": content_text, "tool_calls": tool_calls}


def _parse_openai_response(data: dict) -> dict:
    """Parse OpenAI-compatible response into unified format."""
    choices = data.get("choices", [])
    if not choices:
        return {"content": "", "tool_calls": []}
    msg = choices[0].get("message", {})
    return {
        "content": msg.get("content") or "",
        "tool_calls": msg.get("tool_calls") or [],
    }


async def call_llm(db: Session, messages: list, tools: Optional[list] = None) -> dict:
    """
    Try providers in priority order with rate-limit failover.
    Returns {"content": str, "tool_calls": list, "provider_id": str}.
    Raises HTTPException 503 if all providers exhausted.
    """
    cfg = _load_config(db)
    all_providers = sorted(
        [p for p in cfg.get("providers", []) if p.get("enabled", False)],
        key=lambda x: x.get("priority", 999),
    )
    if not all_providers:
        raise HTTPException(503, "No AI providers configured")

    now = datetime.now(timezone.utc)
    tried = set()

    for provider in all_providers:
        pid = provider.get("id")
        if pid in tried:
            continue

        # Check rate limit window
        last_429 = provider.get("last_429_at")
        if last_429:
            try:
                dt = datetime.fromisoformat(last_429.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if (now - dt).total_seconds() < _RATE_LIMIT_WINDOW_SECONDS:
                    continue
            except Exception:
                pass

        tried.add(pid)
        try:
            result = await _call_provider(provider, messages, tools)
            result["provider_id"] = pid
            return result
        except _RateLimitError:
            mark_429(db, pid)
            logger.warning("[ai_manager] Provider %s rate limited, trying next", pid)
            # Re-read config to get updated last_429_at
            cfg = _load_config(db)
            continue
        except Exception as e:
            logger.warning("[ai_manager] Provider %s error: %s", pid, e)
            continue

    raise HTTPException(503, "All AI providers are unavailable or rate limited")


class _RateLimitError(Exception):
    pass


async def _call_provider(provider: dict, messages: list, tools: Optional[list] = None) -> dict:
    """Call a specific provider and return unified response."""
    ptype = provider.get("provider", "openai")
    api_key = provider.get("api_key", "")
    model = provider.get("model", "")
    base_url = provider.get("base_url") or _DEFAULT_BASE_URLS.get(ptype, "")

    async with httpx.AsyncClient(timeout=120.0) as client:
        if ptype == "anthropic":
            return await _call_anthropic(client, api_key, model, base_url, messages, tools)
        else:
            return await _call_openai_compat(client, api_key, model, base_url, messages, tools)


async def _call_anthropic(client: httpx.AsyncClient, api_key: str, model: str,
                           base_url: str, messages: list, tools: Optional[list]) -> dict:
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


async def _call_openai_compat(client: httpx.AsyncClient, api_key: str, model: str,
                               base_url: str, messages: list, tools: Optional[list]) -> dict:
    # Filter out system messages into a single system string for providers that support it
    body = {
        "model": model,
        "messages": messages,
        "max_tokens": 4096,
    }
    if tools:
        body["tools"] = tools

    url = f"{base_url.rstrip('/')}/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    resp = await client.post(url, json=body, headers=headers)
    if resp.status_code == 429:
        raise _RateLimitError()
    resp.raise_for_status()
    return _parse_openai_response(resp.json())
