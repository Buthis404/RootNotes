from pydantic import BaseModel, Field

from ._common import _Tags


class NoteBase(BaseModel):
    pid: str
    title: str = Field(..., min_length=1, max_length=500)
    phase: str = "recon"
    tags: _Tags = []
    content: str = ""
    ts: str
    starred: bool = False


class NoteCreate(NoteBase):
    pass


class NoteUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=500)
    phase: str | None = None
    tags: _Tags | None = None
    content: str | None = None
    ts: str | None = None
    starred: bool | None = None
    client_version: int | None = None


class Note(NoteBase):
    id: str
    version: int = 0
    model_config = {"from_attributes": True}


class NoteAttachment(BaseModel):
    id: str
    note_id: str
    pid: str
    filename: str
    content_type: str
    file_size: int
    public_url: str
    ts: str
    model_config = {"from_attributes": True}
