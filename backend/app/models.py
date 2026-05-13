from sqlalchemy import Column, String, Boolean, Text, ARRAY, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    display_name = Column(String, nullable=False, default="")
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")   # "admin" | "user"
    created_at = Column(String, nullable=False)
    active = Column(Boolean, nullable=False, default=True)


class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    status = Column(String, nullable=False, default="active")
    ip = Column(String, nullable=False, default="")
    os = Column(String, nullable=False, default="Linux")
    added = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    webhook_token = Column(String, nullable=False, default="")


class Note(Base):
    __tablename__ = "notes"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    title = Column(String, nullable=False)
    phase = Column(String, nullable=False, default="recon")
    tags = Column(ARRAY(String), nullable=False, default=[])
    content = Column(Text, nullable=False, default="")
    ts = Column(String, nullable=False)
    starred = Column(Boolean, nullable=False, default=False)
    version = Column(Integer, nullable=False, default=0)


class NoteAttachment(Base):
    __tablename__ = "note_attachments"

    id = Column(String, primary_key=True)
    note_id = Column(String, ForeignKey("notes.id", ondelete="CASCADE"), nullable=False)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String, nullable=False)
    content_type = Column(String, nullable=False, default="application/octet-stream")
    file_size = Column(Integer, nullable=False, default=0)
    storage_path = Column(Text, nullable=False)
    public_url = Column(Text, nullable=False)
    ts = Column(String, nullable=False)


class Host(Base):
    __tablename__ = "hosts"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    ip = Column(String, nullable=False)
    ips = Column(ARRAY(String), nullable=False, default=[])
    hostname = Column(String, nullable=False, default="")
    os = Column(String, nullable=False, default="Linux")
    status = Column(String, nullable=False, default="unknown")
    ports = Column(ARRAY(String), nullable=False, default=[])
    services = Column(ARRAY(String), nullable=False, default=[])
    tags = Column(ARRAY(String), nullable=False, default=[])
    notes = Column(Text, nullable=False, default="")
    domain = Column(String, nullable=False, default="")
    role = Column(String, nullable=False, default="unknown")
    is_attacker = Column(Boolean, nullable=False, default=False)
    import_source = Column(String, nullable=False, default="")


class Cred(Base):
    __tablename__ = "creds"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    username = Column(String, nullable=False)
    secret = Column(Text, nullable=False, default="")
    type = Column(String, nullable=False, default="plain")
    service = Column(String, nullable=False, default="")
    host = Column(String, nullable=False, default="")
    domain = Column(String, nullable=False, default="")
    cracked = Column(Boolean, nullable=False, default=False)
    notes = Column(Text, nullable=False, default="")
    tags = Column(ARRAY(String), nullable=False, default=[])
    host_ids = Column(ARRAY(String), nullable=False, default=[])
    is_domain = Column(Boolean, nullable=False, default=False)


class Network(Base):
    __tablename__ = "networks"

    id = Column(String, primary_key=True)  # UUID string
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False, default="Network")
    background = Column(String, nullable=False, default="#07080b")
    regions_json = Column(JSONB, nullable=False, default=[])
    nodes_json = Column(JSONB, nullable=False, default=[])
    edges_json = Column(JSONB, nullable=False, default=[])
    meta_json = Column(JSONB, nullable=False, default={})


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String, nullable=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="medium")
    cvss = Column(String, nullable=False, default="")
    cve = Column(String, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    proof = Column(Text, nullable=False, default="")
    recommendation = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="open")
    source = Column(String, nullable=False, default="manual")
    ts = Column(String, nullable=False)


class ChecklistItem(Base):
    __tablename__ = "checklist_items"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    phase = Column(String, nullable=False)
    text = Column(String, nullable=False)
    done = Column(Boolean, nullable=False, default=False)
    order_idx = Column(Integer, nullable=False, default=0)


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String, primary_key=True)
    pid = Column(String, nullable=False)
    username = Column(String, nullable=True)
    entity = Column(String, nullable=False)
    action = Column(String, nullable=False)
    label = Column(String, nullable=False)
    meta = Column(JSONB, nullable=False, default=dict)
    ts = Column(String, nullable=False)


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False, default="Attack Path")
    description = Column(Text, nullable=False, default="")
    ts = Column(String, nullable=False)


class AttackStep(Base):
    __tablename__ = "attack_steps"

    id = Column(String, primary_key=True)
    path_id = Column(String, ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False)
    pid = Column(String, nullable=False)
    step_order = Column(Integer, nullable=False, default=0)
    node_type = Column(String, nullable=False, default="host")
    label = Column(String, nullable=False, default="")
    sublabel = Column(String, nullable=False, default="")
    technique = Column(String, nullable=False, default="")
    mitre_id = Column(String, nullable=False, default="")
    notes = Column(Text, nullable=False, default="")
    ts = Column(String, nullable=False)


class Loot(Base):
    __tablename__ = "loots"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String, nullable=True)
    loot_type = Column(String, nullable=False, default="file")
    value = Column(Text, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    source_path = Column(String, nullable=False, default="")
    filename = Column(String, nullable=False, default="")
    content_type = Column(String, nullable=False, default="")
    file_size = Column(Integer, nullable=False, default=0)
    storage_path = Column(Text, nullable=False, default="")
    public_url = Column(Text, nullable=False, default="")
    ts = Column(String, nullable=False)
    # Evidence pipeline linkage
    job_id = Column(String, nullable=False, default="")
    cred_id = Column(String, nullable=False, default="")
    finding_id = Column(String, nullable=False, default="")
    playbook_run_id = Column(String, nullable=False, default="")
    sha256 = Column(String, nullable=False, default="")
    artifact_type = Column(String, nullable=False, default="file")
    tags = Column(ARRAY(String), nullable=False, default=[])


class Scope(Base):
    __tablename__ = "scopes"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    value = Column(String, nullable=False)
    scope_type = Column(String, nullable=False, default="cidr")
    in_scope = Column(Boolean, nullable=False, default=True)
    description = Column(String, nullable=False, default="")
    gateway_ip = Column(String, nullable=False, default="")
    is_entry = Column(Boolean, nullable=False, default=False)


class CredHostNote(Base):
    __tablename__ = "cred_host_notes"

    id = Column(String, primary_key=True)
    cred_id = Column(String, ForeignKey("creds.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    notes = Column(Text, nullable=False, default="")
    access = Column(ARRAY(String), nullable=False, default=[])


class Objective(Base):
    __tablename__ = "objectives"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String, nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    category = Column(String, nullable=False, default="flag")   # flag | bas | objective
    points = Column(Integer, nullable=False, default=0)
    status = Column(String, nullable=False, default="not_started")  # not_started | in_progress | captured | submitted
    flag_value = Column(String, nullable=False, default="")
    captured_by = Column(String, nullable=False, default="")
    captured_at = Column(String, nullable=False, default="")
    ts = Column(String, nullable=False)


class HostActivity(Base):
    __tablename__ = "host_activities"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    title = Column(String, nullable=False, default="")
    activity_type = Column(String, nullable=False, default="recon")
    command = Column(Text, nullable=False, default="")
    summary = Column(Text, nullable=False, default="")
    output = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="done")
    ts = Column(String, nullable=False)
    job_id = Column(String, nullable=False, default="")


class PivotObservation(Base):
    __tablename__ = "pivot_observations"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    source_host_id = Column(String, nullable=False, default="")
    pivot_host_id = Column(String, nullable=False, default="")
    target_host_id = Column(String, nullable=False, default="")
    tool = Column(String, nullable=False, default="")
    pivot_type = Column(String, nullable=False, default="route")
    label = Column(String, nullable=False, default="")
    route_cidr = Column(String, nullable=False, default="")
    bind_address = Column(String, nullable=False, default="")
    status = Column(String, nullable=False, default="active")
    notes = Column(Text, nullable=False, default="")
    collector_target_id = Column(String, nullable=False, default="")
    fingerprint = Column(String, nullable=False, default="")
    ts = Column(String, nullable=False)
    last_seen = Column(String, nullable=False, default="")


class FindingTemplate(Base):
    __tablename__ = "finding_templates_custom"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="medium")
    cvss = Column(String, nullable=False, default="")
    cve = Column(String, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    proof = Column(Text, nullable=False, default="")
    recommendation = Column(Text, nullable=False, default="")
    created_at = Column(String, nullable=False)


class CustomSnippet(Base):
    __tablename__ = "custom_snippets"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    category = Column(String, nullable=False, default="Misc")
    command = Column(Text, nullable=False, default="")
    tags = Column(ARRAY(String), nullable=False, default=[])
    opsec = Column(Text, nullable=False, default="")
    created_at = Column(String, nullable=False)


class ProjectMember(Base):
    __tablename__ = "project_members"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String, nullable=False, default="viewer")  # owner|admin|editor|operator|viewer|auditor
    created_at = Column(String, nullable=False)
    created_by = Column(String, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)


class GlobalSetting(Base):
    __tablename__ = "global_settings"

    key = Column(String, primary_key=True)
    value = Column(JSONB, nullable=False, default=dict)


class Job(Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    type = Column(String, nullable=False)          # nmap|nuclei|cme|exec|c2_sync|topology
    status = Column(String, nullable=False, default="queued")  # queued|running|done|failed|cancelled
    title = Column(String, nullable=False, default="")
    target = Column(String, nullable=False, default="")
    command = Column(Text, nullable=False, default="")
    output = Column(Text, nullable=False, default="")
    error_output = Column(Text, nullable=False, default="")
    created_by = Column(String, nullable=False, default="")
    connector_key = Column(String, nullable=False, default="")
    operation = Column(String, nullable=False, default="")
    scope_type = Column(String, nullable=False, default="project")
    scope_id = Column(String, nullable=False, default="")
    related_entity_type = Column(String, nullable=False, default="")
    related_entity_id = Column(String, nullable=False, default="")
    retry_of_job_id = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
    started_at = Column(String, nullable=False, default="")
    finished_at = Column(String, nullable=False, default="")
    request_json = Column(JSONB, nullable=False, default=dict)
    result_json = Column(JSONB, nullable=False, default=dict)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    playbook_id = Column(String, nullable=False, default="")
    title = Column(String, nullable=False, default="")
    status = Column(String, nullable=False, default="queued")  # queued|running|done|failed|cancelled
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
    started_at = Column(String, nullable=False, default="")
    finished_at = Column(String, nullable=False, default="")
    target = Column(String, nullable=False, default="")
    error_output = Column(Text, nullable=False, default="")
    jobs_json = Column(JSONB, nullable=False, default=list)
    request_json = Column(JSONB, nullable=False, default=dict)
    result_json = Column(JSONB, nullable=False, default=dict)


class CustomPlaybook(Base):
    __tablename__ = "custom_playbooks"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    steps_json = Column(JSONB, nullable=False, default=list)
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)


class ScheduledPlaybook(Base):
    __tablename__ = "scheduled_playbooks"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    playbook_id = Column(String, nullable=False)
    title = Column(String, nullable=False, default="")
    cron_expr = Column(String, nullable=False, default="0 * * * *")
    enabled = Column(Boolean, nullable=False, default=True)
    body_json = Column(JSONB, nullable=False, default=dict)
    last_run_at = Column(String, nullable=False, default="")
    next_run_at = Column(String, nullable=False, default="")
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)


class ProjectDomain(Base):
    __tablename__ = "project_domains"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    aliases = Column(ARRAY(String), nullable=False, default=[])
    notes = Column(Text, nullable=False, default="")
    created_at = Column(String, nullable=False)


class KBArticle(Base):
    __tablename__ = "kb_articles"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)  # null = global
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False, default="")
    category = Column(String, nullable=False, default="General")
    tags = Column(ARRAY(String), nullable=False, default=[])
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)


class HostCollection(Base):
    __tablename__ = "host_collections"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    color = Column(String, nullable=False, default="#4f8ef7")
    filters_json = Column(JSONB, nullable=False, default=dict)
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)
