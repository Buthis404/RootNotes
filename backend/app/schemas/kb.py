from pydantic import BaseModel, Field

from ._common import _Tags


class CustomSnippetBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    category: str = ""
    command: str = ""
    tags: _Tags = []
    opsec: str = ""


class CustomSnippetCreate(CustomSnippetBase):
    pass


class CustomSnippetUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=500)
    category: str | None = None
    command: str | None = None
    tags: _Tags | None = None
    opsec: str | None = None


class CustomSnippet(CustomSnippetBase):
    id: str
    created_at: str = ""
    is_custom: bool = False
    model_config = {"from_attributes": True}


class KBArticleCreate(BaseModel):
    pid: str | None = None
    title: str = Field(..., min_length=1, max_length=500)
    content: str = ""
    category: str = ""
    tags: _Tags = []


class KBArticleUpdate(BaseModel):
    title: str | None = Field(None, min_length=1, max_length=500)
    content: str | None = None
    category: str | None = None
    tags: _Tags | None = None


class KBArticle(BaseModel):
    id: str
    pid: str | None = None
    title: str
    content: str
    category: str
    tags: list[str]
    created_by: str
    created_at: str
    updated_at: str
    model_config = {"from_attributes": True}
