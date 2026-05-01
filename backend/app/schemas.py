from pydantic import BaseModel
from typing import List, Optional, Any


# ── Auth / Users ──────────────────────────────────────────────────────
class UserOut(BaseModel):
    id: str
    username: str
    role: str
    created_at: str
    active: bool
    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    username: str
    password: str


class SetupRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"


class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None


# ── Projects ──────────────────────────────────────────────────────────
class ProjectBase(BaseModel):
    name: str
    status: str = "active"
    ip: str = ""
    os: str = "Linux"
    added: str
    description: str = ""


class ProjectCreate(ProjectBase):
    pass


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    ip: Optional[str] = None
    os: Optional[str] = None
    description: Optional[str] = None


class Project(ProjectBase):
    id: str
    model_config = {"from_attributes": True}


# ── Notes ─────────────────────────────────────────────────────────────
class NoteBase(BaseModel):
    pid: str
    title: str
    phase: str = "recon"
    tags: List[str] = []
    content: str = ""
    ts: str
    starred: bool = False


class NoteCreate(NoteBase):
    pass


class NoteUpdate(BaseModel):
    title: Optional[str] = None
    phase: Optional[str] = None
    tags: Optional[List[str]] = None
    content: Optional[str] = None
    ts: Optional[str] = None
    starred: Optional[bool] = None
    client_version: Optional[int] = None


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


# ── Hosts ─────────────────────────────────────────────────────────────
class HostBase(BaseModel):
    pid: str
    ip: str
    ips: List[str] = []
    hostname: str = ""
    os: str = "Linux"
    status: str = "unknown"
    ports: List[str] = []
    services: List[str] = []
    tags: List[str] = []
    notes: str = ""
    domain: str = ""
    role: str = "unknown"
    is_attacker: bool = False


class HostCreate(HostBase):
    pass


class HostUpdate(BaseModel):
    ip: Optional[str] = None
    ips: Optional[List[str]] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    status: Optional[str] = None
    ports: Optional[List[str]] = None
    services: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    domain: Optional[str] = None
    role: Optional[str] = None
    is_attacker: Optional[bool] = None


class Host(HostBase):
    id: str
    model_config = {"from_attributes": True}


# ── Creds ─────────────────────────────────────────────────────────────
class CredBase(BaseModel):
    pid: str
    username: str
    secret: str = ""
    type: str = "plain"
    service: str = ""
    host: str = ""
    domain: str = ""
    cracked: bool = False
    notes: str = ""
    tags: List[str] = []
    host_ids: List[str] = []
    is_domain: bool = False


class CredCreate(CredBase):
    pass


class CredUpdate(BaseModel):
    username: Optional[str] = None
    secret: Optional[str] = None
    type: Optional[str] = None
    service: Optional[str] = None
    host: Optional[str] = None
    domain: Optional[str] = None
    cracked: Optional[bool] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    host_ids: Optional[List[str]] = None
    is_domain: Optional[bool] = None


class Cred(CredBase):
    id: str
    model_config = {"from_attributes": True}


# ── Network ───────────────────────────────────────────────────────────
class NetworkData(BaseModel):
    regions: List[Any] = []
    nodes: List[Any] = []
    edges: List[Any] = []


class NetworkCreate(BaseModel):
    pid: str
    name: str = "Network"
    background: str = "#07080b"


class NetworkUpdate(BaseModel):
    name: Optional[str] = None
    background: Optional[str] = None
    regions: Optional[List[Any]] = None
    nodes: Optional[List[Any]] = None
    edges: Optional[List[Any]] = None


class Network(BaseModel):
    id: str
    pid: str
    name: str
    background: str = "#07080b"
    regions: List[Any] = []
    nodes: List[Any] = []
    edges: List[Any] = []
    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_obj(cls, obj):
        import json as _json

        def _parse(val):
            if isinstance(val, str):
                try:
                    return _json.loads(val)
                except Exception:
                    return []
            return val or []

        return cls(
            id=obj.id, pid=obj.pid, name=obj.name,
            background=getattr(obj, 'background', '#07080b'),
            regions=_parse(getattr(obj, 'regions_json', [])),
            nodes=_parse(obj.nodes_json),
            edges=_parse(obj.edges_json),
        )


class NetworkNodeCreate(BaseModel):
    network_id: str
    host_id: Optional[str] = None
    x: float
    y: float
    label: str = ""
    ip: str = ""
    ips: List[str] = []
    type: str = "server"
    status: str = "unknown"
    ports: List[str] = []
    notes: str = ""
    role: Optional[str] = None
    os: Optional[str] = None
    tags: Optional[List[str]] = None
    is_attacker: Optional[bool] = None
    manually_positioned: bool = True
    auto_positioned: bool = False
    client_mutation_id: Optional[str] = None


class NetworkNodeUpdate(BaseModel):
    label: Optional[str] = None
    ip: Optional[str] = None
    ips: Optional[List[str]] = None
    x: Optional[float] = None
    y: Optional[float] = None
    type: Optional[str] = None
    status: Optional[str] = None
    ports: Optional[List[str]] = None
    notes: Optional[str] = None
    role: Optional[str] = None
    os: Optional[str] = None
    tags: Optional[List[str]] = None
    is_attacker: Optional[bool] = None
    host_id: Optional[str] = None
    manually_positioned: Optional[bool] = None
    auto_positioned: Optional[bool] = None
    client_mutation_id: Optional[str] = None


class NetworkNodePositionUpdate(BaseModel):
    x: float
    y: float
    manually_positioned: bool = True
    client_mutation_id: Optional[str] = None


class NetworkLinkCreate(BaseModel):
    network_id: str
    from_node_id: str
    to_node_id: str
    style: str = "normal"
    type: Optional[str] = None
    label: str = ""
    confidence: Optional[float] = None
    source: Optional[str] = None
    client_mutation_id: Optional[str] = None


class NetworkLinkUpdate(BaseModel):
    style: Optional[str] = None
    type: Optional[str] = None
    label: Optional[str] = None
    confidence: Optional[float] = None
    source: Optional[str] = None
    from_node_id: Optional[str] = None
    to_node_id: Optional[str] = None
    client_mutation_id: Optional[str] = None


class NetworkRegionCreate(BaseModel):
    network_id: str
    x: float
    y: float
    w: float
    h: float
    label: str = ""
    note: str = ""
    fill: Optional[str] = None
    stroke: Optional[str] = None
    client_mutation_id: Optional[str] = None


class NetworkRegionUpdate(BaseModel):
    x: Optional[float] = None
    y: Optional[float] = None
    w: Optional[float] = None
    h: Optional[float] = None
    label: Optional[str] = None
    note: Optional[str] = None
    fill: Optional[str] = None
    stroke: Optional[str] = None
    client_mutation_id: Optional[str] = None


# ── Findings ──────────────────────────────────────────────────────────
class FindingBase(BaseModel):
    pid: str
    host_id: Optional[str] = None
    title: str
    severity: str = "medium"
    cvss: str = ""
    cve: str = ""
    description: str = ""
    proof: str = ""
    recommendation: str = ""
    status: str = "open"
    ts: str


class FindingCreate(FindingBase):
    pass


class FindingUpdate(BaseModel):
    host_id: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    cvss: Optional[str] = None
    cve: Optional[str] = None
    description: Optional[str] = None
    proof: Optional[str] = None
    recommendation: Optional[str] = None
    status: Optional[str] = None
    ts: Optional[str] = None


class Finding(FindingBase):
    id: str
    model_config = {"from_attributes": True}


# ── Checklist ─────────────────────────────────────────────────────────
class ChecklistItemBase(BaseModel):
    pid: str
    phase: str
    text: str
    done: bool = False
    order_idx: int = 0


class ChecklistItemCreate(ChecklistItemBase):
    pass


class ChecklistItemUpdate(BaseModel):
    text: Optional[str] = None
    done: Optional[bool] = None
    order_idx: Optional[int] = None


class ChecklistItem(ChecklistItemBase):
    id: str
    model_config = {"from_attributes": True}


# ── Attack Paths ──────────────────────────────────────────────────────
class AttackPathCreate(BaseModel):
    pid: str
    name: str = "Attack Path"
    description: str = ""

class AttackPathUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class AttackPath(BaseModel):
    id: str
    pid: str
    name: str
    description: str
    ts: str
    model_config = {"from_attributes": True}

class AttackStepCreate(BaseModel):
    path_id: str
    pid: str
    step_order: int = 0
    node_type: str = "host"
    label: str = ""
    sublabel: str = ""
    technique: str = ""
    mitre_id: str = ""
    notes: str = ""

class AttackStepUpdate(BaseModel):
    step_order: Optional[int] = None
    node_type: Optional[str] = None
    label: Optional[str] = None
    sublabel: Optional[str] = None
    technique: Optional[str] = None
    mitre_id: Optional[str] = None
    notes: Optional[str] = None

class AttackStep(BaseModel):
    id: str
    path_id: str
    pid: str
    step_order: int
    node_type: str
    label: str
    sublabel: str
    technique: str
    mitre_id: str
    notes: str
    ts: str
    model_config = {"from_attributes": True}


# ── Loot ──────────────────────────────────────────────────────────────
class LootBase(BaseModel):
    pid: str
    host_id: Optional[str] = None
    loot_type: str = "file"
    value: str = ""
    description: str = ""
    source_path: str = ""
    filename: str = ""
    content_type: str = ""
    file_size: int = 0
    public_url: str = ""

class LootCreate(LootBase):
    pass

class LootUpdate(BaseModel):
    host_id: Optional[str] = None
    loot_type: Optional[str] = None
    value: Optional[str] = None
    description: Optional[str] = None
    source_path: Optional[str] = None
    filename: Optional[str] = None
    content_type: Optional[str] = None
    file_size: Optional[int] = None
    public_url: Optional[str] = None

class Loot(LootBase):
    id: str
    ts: str
    model_config = {"from_attributes": True}


# ── Scope ──────────────────────────────────────────────────────────────
class ScopeBase(BaseModel):
    pid: str
    value: str
    scope_type: str = "cidr"
    in_scope: bool = True
    description: str = ""

class ScopeCreate(ScopeBase):
    pass

class ScopeUpdate(BaseModel):
    value: Optional[str] = None
    scope_type: Optional[str] = None
    in_scope: Optional[bool] = None
    description: Optional[str] = None

class Scope(ScopeBase):
    id: str
    model_config = {"from_attributes": True}


# ── Objectives ────────────────────────────────────────────────────────
class ObjectiveBase(BaseModel):
    title: str
    description: str = ""
    category: str = "flag"
    points: int = 0
    status: str = "not_started"
    flag_value: str = ""
    host_id: Optional[str] = None
    captured_by: str = ""
    captured_at: str = ""

class ObjectiveCreate(ObjectiveBase):
    pid: str

class ObjectiveUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    points: Optional[int] = None
    status: Optional[str] = None
    flag_value: Optional[str] = None
    host_id: Optional[str] = None
    captured_by: Optional[str] = None
    captured_at: Optional[str] = None

class Objective(ObjectiveBase):
    id: str
    pid: str
    ts: str
    model_config = {"from_attributes": True}


# ── Host Activities ────────────────────────────────────────────────────
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
    title: Optional[str] = None
    activity_type: Optional[str] = None
    command: Optional[str] = None
    summary: Optional[str] = None
    output: Optional[str] = None
    status: Optional[str] = None
    ts: Optional[str] = None


class HostActivity(HostActivityBase):
    id: str
    model_config = {"from_attributes": True}


# ── CredHostNote ──────────────────────────────────────────────────────
class CredHostNoteCreate(BaseModel):
    cred_id: str
    host_id: str
    pid: str
    notes: str = ""
    access: List[str] = []

class CredHostNoteUpdate(BaseModel):
    notes: Optional[str] = None
    access: Optional[List[str]] = None

class CredHostNote(BaseModel):
    id: str
    cred_id: str
    host_id: str
    pid: str
    notes: str
    access: List[str]
    model_config = {"from_attributes": True}


# ── Timeline ──────────────────────────────────────────────────────────
class TimelineEvent(BaseModel):
    id: str
    pid: str
    username: Optional[str] = None
    entity: str
    action: str
    label: str
    meta: Any = {}
    ts: str
    model_config = {"from_attributes": True}


# ── Custom Finding Templates ───────────────────────────────────────────
class FindingTemplateBase(BaseModel):
    title: str
    severity: str = "medium"
    cvss: str = ""
    cve: str = ""
    description: str = ""
    proof: str = ""
    recommendation: str = ""


class FindingTemplateCreate(FindingTemplateBase):
    pass


class FindingTemplate(FindingTemplateBase):
    id: str
    created_at: str = ""
    is_custom: bool = False
    model_config = {"from_attributes": True}


# ── Custom Snippets ────────────────────────────────────────────────────
class CustomSnippetBase(BaseModel):
    title: str
    category: str = "Misc"
    command: str = ""
    tags: List[str] = []
    opsec: str = ""


class CustomSnippetCreate(CustomSnippetBase):
    pass


class CustomSnippetUpdate(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    command: Optional[str] = None
    tags: Optional[List[str]] = None
    opsec: Optional[str] = None


class CustomSnippet(CustomSnippetBase):
    id: str
    created_at: str = ""
    is_custom: bool = False
    model_config = {"from_attributes": True}
