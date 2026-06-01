from typing import Any

from pydantic import BaseModel


class TimelineEvent(BaseModel):
    id: str
    pid: str
    username: str | None = None
    entity: str
    action: str
    label: str
    meta: Any = {}
    ts: str
    integrity: str | None = None
    model_config = {"from_attributes": True}
