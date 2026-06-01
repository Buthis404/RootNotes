from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..core.deps import get_current_user
from ..core.notifications import dispatch, get_config, save_config
from .. import models
from ..database import get_db

router = APIRouter(
    prefix="/api/notifications", tags=["notifications"],
    responses={
        400: {"description": "Bad request"},
        502: {"description": "Bad gateway"},
    },
)


class NotificationConfig(BaseModel):
    telegram: dict = {}
    slack: dict = {}
    webhook: dict = {}
    events: dict = {}


@router.get("/config")
def get_notification_config(db: Annotated[Session, Depends(get_db)], user: Annotated[models.User, Depends(get_current_user)]):
    return get_config(db)


@router.put("/config")
def update_notification_config(
    body: NotificationConfig, db: Annotated[Session, Depends(get_db)], user: Annotated[models.User, Depends(get_current_user)]
):
    save_config(db, body.model_dump())
    return {"ok": True}


@router.post("/test")
async def test_notification(db: Annotated[Session, Depends(get_db)], user: Annotated[models.User, Depends(get_current_user)]):
    await dispatch(
        db,
        "test",
        "RootNotes — Test Notification",
        f"Sent by {user.username}. Notifications are working.",
    )
    return {"ok": True}


@router.get("/telegram/chat-id", responses={400: {"description": "Bad request"}, 502: {"description": "Bad gateway"}})
async def get_telegram_chat_id(db: Annotated[Session, Depends(get_db)], user: Annotated[models.User, Depends(get_current_user)]):
    """Call getUpdates on the configured bot token to discover chat IDs from recent messages."""
    cfg = get_config(db)
    token = (cfg.get("telegram") or {}).get("token", "").strip()
    if not token:
        raise HTTPException(400, "Telegram bot token not configured")

    import asyncio
    import json
    import urllib.request

    url = f"https://api.telegram.org/bot{token}/getUpdates?limit=20&timeout=0"
    try:
        loop = asyncio.get_running_loop()
        raw = await loop.run_in_executor(
            None, lambda: urllib.request.urlopen(url, timeout=10).read()
        )
        data = json.loads(raw)
    except Exception as e:
        raise HTTPException(502, f"Telegram API error: {e}")

    if not data.get("ok"):
        raise HTTPException(
            502, f"Telegram API returned error: {data.get('description', 'unknown')}"
        )

    chats: list[dict] = []
    seen = set()
    for upd in data.get("result", []):
        msg = upd.get("message") or upd.get("channel_post") or {}
        chat = msg.get("chat", {})
        cid = chat.get("id")
        if cid and cid not in seen:
            seen.add(cid)
            chats.append(
                {
                    "id": str(cid),
                    "type": chat.get("type", ""),
                    "title": chat.get("title")
                    or chat.get("first_name")
                    or chat.get("username")
                    or str(cid),
                }
            )

    return {"chats": chats, "hint": "Send any message to your bot first if list is empty"}
