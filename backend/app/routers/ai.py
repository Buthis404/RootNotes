"""
AI agent router.

GET  /api/ai/config           — returns ai_config (api_keys masked)
PUT  /api/ai/config           — save ai_config (admin only)
POST /api/projects/{pid}/ai/chat — agentic chat with tool calls
"""
import json
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..core.deps import get_current_user
from ..core.access import check_pid_access
from ..core.ai_manager import get_config, save_config, call_llm
from ..core.ai_tools import TOOLS_OPENAI, execute_tool

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ai"])


# ── Schemas ───────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: List[ChatMessage] = []
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
    open_finding_count = db.query(models.Finding).filter(
        models.Finding.pid == pid, models.Finding.status == "open"
    ).count()

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

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


@router.get("/api/ai/status")
def get_ai_status(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Lightweight flag for the frontend to gate AI UI elements.

    Any authenticated user can read this; it leaks no secrets, only a boolean.
    """
    cfg = get_config(db)
    return {
        "enabled": _is_ai_enabled(cfg),
        "has_providers": bool([p for p in cfg.get("providers", []) if p.get("enabled")]),
    }


@router.get("/api/ai/config")
def get_ai_config(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    cfg = get_config(db)
    masked = _mask_config(cfg)
    masked["ai_enabled"] = _is_ai_enabled(cfg)
    return masked


@router.put("/api/ai/config")
def update_ai_config(body: dict, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Admin only")
    # Normalize the kill switch so we always persist an explicit boolean.
    body["ai_enabled"] = body.get("ai_enabled", True) is not False
    save_config(db, body)
    masked = _mask_config(body)
    masked["ai_enabled"] = body["ai_enabled"]
    return masked


@router.post("/api/projects/{pid}/ai/chat")
async def ai_chat(
    pid: str,
    body: ChatRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "findings.read")

    cfg = get_config(db)
    if not _is_ai_enabled(cfg):
        raise HTTPException(503, "AI is disabled by the administrator")
    max_tool_calls = cfg.get("max_tool_calls", 10)
    agent_mode = body.agent_mode and cfg.get("agent_mode", True)

    system_prompt = _build_system_prompt(db, pid)

    # Build initial message list
    messages = [{"role": "system", "content": system_prompt}]
    for h in body.history:
        messages.append({"role": h.role, "content": h.content})
    messages.append({"role": "user", "content": body.message})

    tools = TOOLS_OPENAI if agent_mode else None
    tool_calls_log = []
    provider_used = ""

    try:
        tool_call_count = 0

        while True:
            result = await call_llm(db, messages, tools=tools)
            provider_used = result.get("provider_id", "")
            content = result.get("content", "")
            llm_tool_calls = result.get("tool_calls", [])

            if not llm_tool_calls or not agent_mode:
                # Final response
                return {
                    "answer": content or "(no response)",
                    "tool_calls_log": tool_calls_log,
                    "provider_used": provider_used,
                }

            # Execute tool calls
            # Add assistant message with tool calls
            messages.append({
                "role": "assistant",
                "content": content,
                "tool_calls": llm_tool_calls,
            })

            for tc in llm_tool_calls:
                if tool_call_count >= max_tool_calls:
                    break
                tool_call_count += 1

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

                tool_calls_log.append({
                    "name": tool_name,
                    "args": args,
                    "result_summary": result_str[:300],
                })

                # Add tool result message
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", "call_0"),
                    "content": result_str,
                })

            if tool_call_count >= max_tool_calls:
                # Force final answer
                messages.append({
                    "role": "user",
                    "content": "Please provide your final answer based on the tool results above.",
                })
                final = await call_llm(db, messages, tools=None)
                return {
                    "answer": final.get("content", "(no response)"),
                    "tool_calls_log": tool_calls_log,
                    "provider_used": final.get("provider_id", provider_used),
                }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("[ai_chat] error: %s", e, exc_info=True)
        raise HTTPException(500, f"AI chat error: {str(e)}")
