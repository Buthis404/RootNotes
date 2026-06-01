from typing import Any

from pydantic import BaseModel


class ScheduledPlaybookCreate(BaseModel):
    pid: str
    playbook_id: str
    title: str = ""
    cron_expr: str = "0 * * * *"
    enabled: bool = True
    body_json: Any = {}


class ScheduledPlaybookUpdate(BaseModel):
    title: str | None = None
    cron_expr: str | None = None
    enabled: bool | None = None
    body_json: Any | None = None


class ScheduledPlaybook(BaseModel):
    id: str
    pid: str
    playbook_id: str
    title: str
    cron_expr: str
    enabled: bool
    body_json: Any
    last_run_at: str
    next_run_at: str
    created_by: str
    created_at: str
    model_config = {"from_attributes": True}
