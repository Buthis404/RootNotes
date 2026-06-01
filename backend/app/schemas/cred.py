from pydantic import BaseModel, Field, field_validator

from ._common import _CRED_TYPES, _CredInputMixin, _Tags


class CredBase(BaseModel):
    pid: str
    username: str = Field(..., max_length=256)
    secret: str = ""
    type: str = "plain"
    service: str = ""
    host: str = ""
    domain: str = ""
    cracked: bool = False
    notes: str = ""
    tags: _Tags = []
    host_ids: list[str] = []
    is_domain: bool = False


class CredCreate(CredBase, _CredInputMixin):
    pass


class CredUpdate(BaseModel):
    username: str | None = Field(None, max_length=256)
    secret: str | None = None
    type: str | None = None
    service: str | None = None
    host: str | None = None
    domain: str | None = None
    cracked: bool | None = None
    notes: str | None = None
    tags: _Tags | None = None
    host_ids: list[str] | None = None
    is_domain: bool | None = None

    @field_validator("type", mode="before")
    @classmethod
    def _val_cred_type(cls, v):
        if v and v not in _CRED_TYPES:
            raise ValueError(
                f"Invalid credential type: {v!r}. Must be one of: {', '.join(sorted(_CRED_TYPES))}"
            )
        return v


class Cred(CredBase):
    id: str
    model_config = {"from_attributes": True}


class CredHostNoteCreate(BaseModel):
    cred_id: str
    host_id: str
    pid: str
    notes: str = ""
    access: list[str] = []


class CredHostNoteUpdate(BaseModel):
    notes: str | None = None
    access: list[str] | None = None


class CredHostNote(BaseModel):
    id: str
    cred_id: str
    host_id: str
    pid: str
    notes: str
    access: list[str]
    model_config = {"from_attributes": True}
