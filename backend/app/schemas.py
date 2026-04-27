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
    cracked: bool = False
    notes: str = ""
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
    cracked: Optional[bool] = None
    notes: Optional[str] = None
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
        return cls(id=obj.id, pid=obj.pid, name=obj.name, background=getattr(obj, 'background', '#07080b'), regions=getattr(obj, 'regions_json', []) or [], nodes=obj.nodes_json or [], edges=obj.edges_json or [])


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

class LootCreate(LootBase):
    pass

class LootUpdate(BaseModel):
    host_id: Optional[str] = None
    loot_type: Optional[str] = None
    value: Optional[str] = None
    description: Optional[str] = None
    source_path: Optional[str] = None

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
