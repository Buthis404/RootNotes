from pydantic import BaseModel


class AttackPathCreate(BaseModel):
    pid: str
    name: str = "Attack Path"
    description: str = ""


class AttackPathUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


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
    host_id: str | None = None
    step_order: int = 0
    node_type: str = "host"
    label: str = ""
    sublabel: str = ""
    technique: str = ""
    mitre_id: str = ""
    notes: str = ""


class AttackStepUpdate(BaseModel):
    host_id: str | None = None
    step_order: int | None = None
    node_type: str | None = None
    label: str | None = None
    sublabel: str | None = None
    technique: str | None = None
    mitre_id: str | None = None
    notes: str | None = None


class AttackStep(BaseModel):
    id: str
    path_id: str
    pid: str
    host_id: str | None = None
    step_order: int
    node_type: str
    label: str
    sublabel: str
    technique: str
    mitre_id: str
    notes: str
    ts: str
    model_config = {"from_attributes": True}
