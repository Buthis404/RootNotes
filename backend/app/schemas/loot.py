from pydantic import BaseModel

from ._common import _Tags


class LootBase(BaseModel):
    pid: str
    host_id: str | None = None
    loot_type: str = "file"
    value: str = ""
    description: str = ""
    source_path: str = ""
    filename: str = ""
    content_type: str = ""
    file_size: int = 0
    public_url: str = ""
    job_id: str = ""
    cred_id: str = ""
    finding_id: str = ""
    playbook_run_id: str = ""
    sha256: str = ""
    artifact_type: str = "file"
    tags: _Tags = []
    file_encrypted: bool = False


class LootCreate(LootBase):
    pass


class LootUpdate(BaseModel):
    host_id: str | None = None
    loot_type: str | None = None
    value: str | None = None
    description: str | None = None
    source_path: str | None = None
    filename: str | None = None
    content_type: str | None = None
    file_size: int | None = None
    public_url: str | None = None
    job_id: str | None = None
    cred_id: str | None = None
    finding_id: str | None = None
    playbook_run_id: str | None = None
    sha256: str | None = None
    artifact_type: str | None = None
    tags: _Tags | None = None


class Loot(LootBase):
    id: str
    ts: str
    model_config = {"from_attributes": True}
