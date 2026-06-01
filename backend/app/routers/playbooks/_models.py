from pydantic import BaseModel, Field

_NMAP_DEFAULT_FLAGS = "-sV -sC -T4 --open"
_NUCLEI_DEFAULT_SEVERITY = "critical,high,medium"


class PlaybookStepBody(BaseModel):
    title: str
    connector_key: str
    operation: str
    params: dict = Field(default_factory=dict)
    on_success: str = "next"
    on_success_step: int | None = None
    on_failure: str = "stop"
    on_failure_step: int | None = None
    result_conditions: list[dict] = Field(default_factory=list)
    depends_on: list[int] = Field(default_factory=list)
    retry_count: int = 0
    retry_delay_seconds: int = 5
    retry_on: list[str] = Field(default_factory=lambda: ["failed"])
    precondition: dict | None = None


class PlaybookBody(BaseModel):
    title: str
    description: str = ""
    steps: list[PlaybookStepBody] = Field(default_factory=list)


class PlaybookRunBody(BaseModel):
    target: str = ""
    target_url: str = ""
    target_id: str | None = None
    flags: str = _NMAP_DEFAULT_FLAGS
    severity: str = _NUCLEI_DEFAULT_SEVERITY
    keep_manual_positions: bool = True
    create_missing_networks: bool = True
    username: str = ""
    password: str = ""
    domain: str = ""
    hash: str = ""


class BatchRunBody(BaseModel):
    host_ids: list[str] = []
    host_tags: list[str] = []
    host_status: str = ""
    parallelism: int = 3
    target_url: str = ""
    flags: str = _NMAP_DEFAULT_FLAGS
    severity: str = _NUCLEI_DEFAULT_SEVERITY
    keep_manual_positions: bool = True
    create_missing_networks: bool = True
    username: str = ""
    password: str = ""
    domain: str = ""
    hash: str = ""


class OperationPackCreate(BaseModel):
    name: str
    description: str = ""
    steps: list = []
    tags: list[str] = []
