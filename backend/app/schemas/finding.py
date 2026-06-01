from pydantic import BaseModel, Field, field_validator

from ._common import _FINDING_STATUSES, _SEVERITIES, _FindingInputMixin


class FindingBase(BaseModel):
    pid: str
    host_id: str | None = None
    title: str = Field(..., min_length=1, max_length=500)
    severity: str = "medium"
    cvss: str = ""
    cve: str = ""
    description: str = ""
    proof: str = ""
    recommendation: str = ""
    status: str = "open"
    source: str = "manual"
    ts: str


class FindingCreate(FindingBase, _FindingInputMixin):
    pass


class FindingUpdate(BaseModel):
    host_id: str | None = None
    title: str | None = Field(None, min_length=1, max_length=500)
    severity: str | None = None
    cvss: str | None = None
    cve: str | None = None
    description: str | None = None
    proof: str | None = None
    recommendation: str | None = None
    status: str | None = None
    source: str | None = None
    ts: str | None = None

    @field_validator("severity", mode="before")
    @classmethod
    def _val_severity(cls, v):
        if v and v not in _SEVERITIES:
            raise ValueError(
                f"Invalid severity: {v!r}. Must be one of: {', '.join(sorted(_SEVERITIES))}"
            )
        return v

    @field_validator("status", mode="before")
    @classmethod
    def _val_finding_status(cls, v):
        if v and v not in _FINDING_STATUSES:
            raise ValueError(
                f"Invalid finding status: {v!r}. Must be one of: {', '.join(sorted(_FINDING_STATUSES))}"
            )
        return v


class Finding(FindingBase):
    id: str
    model_config = {"from_attributes": True}


class FindingTemplateBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    severity: str = "medium"
    cvss: str = ""
    cve: str = ""
    description: str = ""
    proof: str = ""
    recommendation: str = ""


class FindingTemplateCreate(FindingTemplateBase, _FindingInputMixin):
    pass


class FindingTemplate(FindingTemplateBase):
    id: str
    created_at: str = ""
    is_custom: bool = False
    model_config = {"from_attributes": True}


class ChecklistItemBase(BaseModel):
    pid: str
    phase: str
    text: str
    done: bool = False
    order_idx: int = 0


class ChecklistItemCreate(ChecklistItemBase):
    pass


class ChecklistItemUpdate(BaseModel):
    text: str | None = None
    done: bool | None = None
    order_idx: int | None = None


class ChecklistItem(ChecklistItemBase):
    id: str
    model_config = {"from_attributes": True}
