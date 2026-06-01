from sqlalchemy import Boolean, Column, ForeignKey, String, Text

from ..database import Base
from ._types import pg_array as ARRAY, JSONB

_FK_PROJECTS_ID = "projects.id"


class Host(Base):
    __tablename__ = "hosts"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
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


class HostActivity(Base):
    __tablename__ = "host_activities"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
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
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
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


class HostCollection(Base):
    __tablename__ = "host_collections"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    color = Column(String, nullable=False, default="#4f8ef7")
    filters_json = Column(JSONB, nullable=False, default=dict)
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)
