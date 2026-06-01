from pydantic import BaseModel, Field


class DomainCreate(BaseModel):
    pid: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    notes: str = ""


class DomainUpdate(BaseModel):
    name: str | None = None
    aliases: list[str] | None = None
    notes: str | None = None


class Domain(BaseModel):
    id: str
    pid: str
    name: str
    aliases: list[str]
    notes: str
    created_at: str

    model_config = {"from_attributes": True}
