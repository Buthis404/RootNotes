from pydantic import BaseModel, Field


class ProjectBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=500)
    status: str = "active"
    ip: str = ""
    os: str = "Linux"
    added: str
    description: str = ""


class ProjectCreate(ProjectBase):
    pass


class ProjectUpdate(BaseModel):
    name: str | None = None
    status: str | None = None
    ip: str | None = None
    os: str | None = None
    description: str | None = None


class Project(ProjectBase):
    id: str
    model_config = {"from_attributes": True}
