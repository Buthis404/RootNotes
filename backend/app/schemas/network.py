from typing import Any

from pydantic import BaseModel


class NetworkData(BaseModel):
    regions: list[Any] = []
    nodes: list[Any] = []
    edges: list[Any] = []


class NetworkCreate(BaseModel):
    pid: str
    name: str = "Network"
    background: str = "#07080b"


class NetworkUpdate(BaseModel):
    name: str | None = None
    background: str | None = None
    regions: list[Any] | None = None
    nodes: list[Any] | None = None
    edges: list[Any] | None = None
    meta: dict[str, Any] | None = None


class Network(BaseModel):
    id: str
    pid: str
    name: str
    background: str = "#07080b"
    regions: list[Any] = []
    nodes: list[Any] = []
    edges: list[Any] = []
    meta: dict[str, Any] = {}
    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_obj(cls, obj):
        import json as _json

        meta = getattr(obj, "meta_json", {}) or {}
        if isinstance(meta, str):
            try:
                meta = _json.loads(meta)
            except Exception:
                meta = {}
        return cls(
            id=obj.id,
            pid=obj.pid,
            name=obj.name,
            background=getattr(obj, "background", "#07080b"),
            meta=meta,
        )


class NetworkNodeCreate(BaseModel):
    network_id: str
    host_id: str | None = None
    x: float
    y: float
    label: str = ""
    ip: str = ""
    ips: list[str] = []
    type: str = "server"
    status: str = "unknown"
    ports: list[str] = []
    notes: str = ""
    role: str | None = None
    os: str | None = None
    tags: list[str] | None = None
    is_attacker: bool | None = None
    manually_positioned: bool = True
    auto_positioned: bool = False
    client_mutation_id: str | None = None


class NetworkNodeUpdate(BaseModel):
    label: str | None = None
    ip: str | None = None
    ips: list[str] | None = None
    x: float | None = None
    y: float | None = None
    type: str | None = None
    status: str | None = None
    ports: list[str] | None = None
    notes: str | None = None
    role: str | None = None
    os: str | None = None
    tags: list[str] | None = None
    is_attacker: bool | None = None
    host_id: str | None = None
    manually_positioned: bool | None = None
    auto_positioned: bool | None = None
    client_mutation_id: str | None = None


class NetworkNodePositionUpdate(BaseModel):
    x: float
    y: float
    manually_positioned: bool = True
    client_mutation_id: str | None = None


class NetworkLinkCreate(BaseModel):
    network_id: str
    from_node_id: str
    to_node_id: str
    style: str = "normal"
    type: str | None = None
    label: str = ""
    confidence: float | None = None
    source: str | None = None
    reason: str | None = None
    state: str | None = None
    verified: bool | None = None
    client_mutation_id: str | None = None


class NetworkLinkUpdate(BaseModel):
    style: str | None = None
    type: str | None = None
    label: str | None = None
    confidence: float | None = None
    source: str | None = None
    reason: str | None = None
    state: str | None = None
    verified: bool | None = None
    from_node_id: str | None = None
    to_node_id: str | None = None
    client_mutation_id: str | None = None


class NetworkRegionCreate(BaseModel):
    network_id: str
    x: float
    y: float
    w: float
    h: float
    label: str = ""
    note: str = ""
    fill: str | None = None
    stroke: str | None = None
    zone_type: str | None = None
    client_mutation_id: str | None = None


class NetworkRegionUpdate(BaseModel):
    x: float | None = None
    y: float | None = None
    w: float | None = None
    h: float | None = None
    label: str | None = None
    note: str | None = None
    fill: str | None = None
    stroke: str | None = None
    zone_type: str | None = None
    client_mutation_id: str | None = None
