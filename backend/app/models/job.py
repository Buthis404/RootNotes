from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text

from ..database import Base
from ._types import pg_array as ARRAY, JSONB

_FK_PROJECTS_ID = "projects.id"


class Job(Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
    type = Column(String, nullable=False)
    status = Column(String, nullable=False, default="queued")
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
    priority = Column(Integer, nullable=False, default=0)
    retry_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=0)
    created_at = Column(String, nullable=False)
    started_at = Column(String, nullable=False, default="")
    finished_at = Column(String, nullable=False, default="")
    request_json = Column(JSONB, nullable=False, default=dict)
    result_json = Column(JSONB, nullable=False, default=dict)


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
    playbook_id = Column(String, nullable=False, default="")
    title = Column(String, nullable=False, default="")
    status = Column(String, nullable=False, default="queued")
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
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
    playbook_id = Column(String, nullable=False)
    title = Column(String, nullable=False, default="")
    cron_expr = Column(String, nullable=False, default="0 * * * *")
    enabled = Column(Boolean, nullable=False, default=True)
    body_json = Column(JSONB, nullable=False, default=dict)
    last_run_at = Column(String, nullable=False, default="")
    next_run_at = Column(String, nullable=False, default="")
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)


class OperationPack(Base):
    __tablename__ = "operation_packs"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    steps = Column(JSONB, nullable=False, default=list)
    tags = Column(ARRAY(String), nullable=False, default=list)
    is_builtin = Column(Boolean, nullable=False, default=False)
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
