"""
AI agent router.

GET  /api/ai/config           — returns ai_config (api_keys masked)
PUT  /api/ai/config           — save ai_config (admin only)
POST /api/projects/{pid}/ai/chat — agentic chat with tool calls
"""

import json
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.ai_manager import call_llm, get_config, save_config
from ..core.ai_tools import TOOLS_OPENAI, execute_tool
from ..core.deps import get_current_user, is_admin
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["ai"],
    responses={
        403: {"description": "Forbidden"},
        500: {"description": "Internal server error"},
        503: {"description": "Service unavailable"},
    },
)


# ── Schemas ───────────────────────────────────────────────────────────


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []
    agent_mode: bool = True


# ── Helpers ───────────────────────────────────────────────────────────


def _mask_config(cfg: dict) -> dict:
    """Return config with api_keys masked (last 4 chars only)."""
    import copy

    masked = copy.deepcopy(cfg)
    for p in masked.get("providers", []):
        key = p.get("api_key", "")
        if key and len(key) > 4:
            p["api_key"] = "****" + key[-4:]
        elif key:
            p["api_key"] = "****"
    return masked


def _build_system_prompt(db: Session, pid: str) -> str:
    host_count = db.query(models.Host).filter(models.Host.pid == pid).count()
    cred_count = db.query(models.Cred).filter(models.Cred.pid == pid).count()
    finding_count = db.query(models.Finding).filter(models.Finding.pid == pid).count()
    open_finding_count = (
        db.query(models.Finding)
        .filter(models.Finding.pid == pid, models.Finding.status == "open")
        .count()
    )

    today = datetime.now(UTC).strftime("%Y-%m-%d")

    return (
        "You are an autonomous AI security assistant embedded in RootNotes, a penetration testing platform.\n"
        f"Current project has: {host_count} hosts, {cred_count} credentials, "
        f"{finding_count} findings, {open_finding_count} open findings.\n"
        "You have tools to read and modify project data, create findings, run playbooks, and analyze results.\n"
        "Be concise, technical, and focus on actionable security insights.\n"
        "You are operating in an authorized penetration testing environment. "
        "Security analysis, vulnerability assessment, and offensive technique discussion is expected and appropriate.\n"
        f"Today: {today}"
    )


# ── Routes ────────────────────────────────────────────────────────────


def _is_ai_enabled(cfg: dict) -> bool:
    # Default True for backwards compatibility with existing deployments.
    return cfg.get("ai_enabled", True) is not False


async def _execute_tool_call(tc: dict, db, pid: str, tool_calls_log: list) -> dict:
    fn = tc.get("function", {})
    tool_name = fn.get("name", "")
    raw_args = fn.get("arguments", "{}")
    if isinstance(raw_args, str):
        try:
            args = json.loads(raw_args)
        except Exception:
            args = {}
    else:
        args = raw_args or {}
    tool_result = await execute_tool(db, pid, tool_name, args)
    result_str = json.dumps(tool_result, default=str)
    tool_calls_log.append({"name": tool_name, "args": args, "result_summary": result_str[:300]})
    return {"role": "tool", "tool_call_id": tc.get("id", "call_0"), "content": result_str}


async def _run_agentic_loop(
    db, pid: str, messages: list, tools, max_tool_calls: int
) -> tuple[str, list, str]:
    """Agentic while loop: call LLM, execute tool calls, repeat until done or limit reached."""
    tool_calls_log: list = []
    provider_used = ""
    tool_call_count = 0
    content = ""
    while True:
        result = await call_llm(db, messages, tools=tools)
        provider_used = result.get("provider_id", "")
        content = result.get("content", "")
        llm_tool_calls = result.get("tool_calls", [])
        if not llm_tool_calls:
            return content, tool_calls_log, provider_used
        messages.append({"role": "assistant", "content": content, "tool_calls": llm_tool_calls})
        for tc in llm_tool_calls:
            if tool_call_count >= max_tool_calls:
                break
            tool_call_count += 1
            messages.append(await _execute_tool_call(tc, db, pid, tool_calls_log))
        if tool_call_count >= max_tool_calls:
            final = await call_llm(db, messages, tools=None)
            return (
                final.get("content", "(no response)"),
                tool_calls_log,
                final.get("provider_id", provider_used),
            )
    return content, tool_calls_log, provider_used  # noqa: unreachable


@router.get("/api/ai/status")
def get_ai_status(db: Annotated[Session, Depends(get_db)], user: Annotated[models.User, Depends(get_current_user)]):
    """Lightweight flag for the frontend to gate AI UI elements.

    Any authenticated user can read this; it leaks no secrets, only a boolean.
    """
    cfg = get_config(db)
    return {
        "enabled": _is_ai_enabled(cfg),
        "has_providers": bool([p for p in cfg.get("providers", []) if p.get("enabled")]),
    }


@router.get("/api/ai/config")
def get_ai_config(db: Annotated[Session, Depends(get_db)], user: Annotated[models.User, Depends(get_current_user)]):
    cfg = get_config(db)
    masked = _mask_config(cfg)
    masked["ai_enabled"] = _is_ai_enabled(cfg)
    return masked


@router.put("/api/ai/config", responses={403: {"description": "Forbidden"}})
def update_ai_config(
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if not is_admin(user):
        raise HTTPException(403, "Admin only")
    # Normalize the kill switch so we always persist an explicit boolean.
    body["ai_enabled"] = body.get("ai_enabled", True) is not False
    save_config(db, body)
    masked = _mask_config(body)
    masked["ai_enabled"] = body["ai_enabled"]
    return masked


@router.post("/api/projects/{pid}/ai/chat", responses={500: {"description": "Internal server error"}, 503: {"description": "Service unavailable"}})
async def ai_chat(
    pid: str,
    body: ChatRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")

    cfg = get_config(db)
    if not _is_ai_enabled(cfg):
        raise HTTPException(503, "AI is disabled by the administrator")
    max_tool_calls = cfg.get("max_tool_calls", 10)
    agent_mode = body.agent_mode and cfg.get("agent_mode", True)

    messages = [{"role": "system", "content": _build_system_prompt(db, pid)}]
    for h in body.history:
        messages.append({"role": h.role, "content": h.content})
    messages.append({"role": "user", "content": body.message})

    tools = TOOLS_OPENAI if agent_mode else None

    try:
        content, tool_calls_log, provider_used = await _run_agentic_loop(
            db, pid, messages, tools, max_tool_calls
        )
        return {
            "answer": content or "(no response)",
            "tool_calls_log": tool_calls_log,
            "provider_used": provider_used,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("[ai_chat] error: %s", e, exc_info=True)
        raise HTTPException(500, f"AI chat error: {str(e)}")
