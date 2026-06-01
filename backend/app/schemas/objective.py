from pydantic import BaseModel


class ObjectiveBase(BaseModel):
    title: str
    description: str = ""
    category: str = "flag"
    points: int = 0
    status: str = "not_started"
    flag_value: str = ""
    host_id: str | None = None
    captured_by: str = ""
    captured_at: str = ""


class ObjectiveCreate(ObjectiveBase):
    pid: str


class ObjectiveUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    points: int | None = None
    status: str | None = None
    flag_value: str | None = None
    host_id: str | None = None
    captured_by: str | None = None
    captured_at: str | None = None


class Objective(ObjectiveBase):
    id: str
    pid: str
    ts: str
    model_config = {"from_attributes": True}
