from pydantic import BaseModel, Field, field_validator

from ._common import _HOST_ROLES, _HOST_STATUSES, _HostInputMixin, _Tags


class HostBase(BaseModel):
    pid: str
    ip: str
    ips: list[str] = []
    hostname: str = ""
    os: str = ""
    status: str = "unknown"
    ports: list[str] = Field(default=[], max_length=500)
    services: list[str] = Field(default=[], max_length=500)
    tags: _Tags = []
    notes: str = ""
    domain: str = ""
    role: str = "unknown"
    is_attacker: bool = False
    import_source: str = ""


class HostCreate(HostBase, _HostInputMixin):
    pass


class HostUpdate(BaseModel):
    ip: str | None = None
    ips: list[str] | None = None
    hostname: str | None = None
    os: str | None = None
    status: str | None = None
    ports: list[str] | None = None
    services: list[str] | None = None
    tags: _Tags | None = None
    notes: str | None = None
    domain: str | None = None
    role: str | None = None
    is_attacker: bool | None = None

    @field_validator("status", mode="before")
    @classmethod
    def _val_host_status(cls, v):
        if v and v not in _HOST_STATUSES:
            raise ValueError(
                f"Invalid host status: {v!r}. Must be one of: {', '.join(sorted(_HOST_STATUSES))}"
            )
        return v

    @field_validator("role", mode="before")
    @classmethod
    def _val_host_role(cls, v):
        if v and v not in _HOST_ROLES:
            raise ValueError(
                f"Invalid host role: {v!r}. Must be one of: {', '.join(sorted(_HOST_ROLES))}"
            )
        return v


class Host(HostBase):
    id: str
    model_config = {"from_attributes": True}


class HostActivityBase(BaseModel):
    pid: str
    host_id: str
    title: str = ""
    activity_type: str = "recon"
    command: str = ""
    summary: str = ""
    output: str = ""
    status: str = "done"
    ts: str = ""


class HostActivityCreate(HostActivityBase):
    pass


class HostActivityUpdate(BaseModel):
    title: str | None = None
    activity_type: str | None = None
    command: str | None = None
    summary: str | None = None
    output: str | None = None
    status: str | None = None
    ts: str | None = None


class HostActivity(HostActivityBase):
    id: str
    model_config = {"from_attributes": True}


class PivotObservationBase(BaseModel):
    source_host_id: str = ""
    pivot_host_id: str
    target_host_id: str = ""
    tool: str = ""
    pivot_type: str = "route"
    label: str = ""
    route_cidr: str = ""
    bind_address: str = ""
    status: str = "active"
    notes: str = ""


class PivotObservationCreate(PivotObservationBase):
    pid: str


class PivotObservationUpdate(BaseModel):
    source_host_id: str | None = None
    pivot_host_id: str | None = None
    target_host_id: str | None = None
    tool: str | None = None
    pivot_type: str | None = None
    label: str | None = None
    route_cidr: str | None = None
    bind_address: str | None = None
    status: str | None = None
    notes: str | None = None
    last_seen: str | None = None


class PivotObservation(PivotObservationBase):
    id: str
    pid: str
    collector_target_id: str = ""
    fingerprint: str = ""
    ts: str
    last_seen: str = ""
    model_config = {"from_attributes": True}
