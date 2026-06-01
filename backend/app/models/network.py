from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String, Text

from ..database import Base
from ._types import pg_array as ARRAY, JSONB

_FK_PROJECTS_ID = "projects.id"
_FK_NETWORKS_ID = "networks.id"


class Network(Base):
    __tablename__ = "networks"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False, default="Network")
    background = Column(String, nullable=False, default="#07080b")
    meta_json = Column(JSONB, nullable=False, default={})


class NetworkNode(Base):
    __tablename__ = "network_nodes"

    id = Column(String, primary_key=True)
    network_id = Column(String, ForeignKey(_FK_NETWORKS_ID, ondelete="CASCADE"), nullable=False)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
    host_id = Column(String, nullable=True)
    x = Column(Float, nullable=False, default=0)
    y = Column(Float, nullable=False, default=0)
    label = Column(String, nullable=False, default="")
    ip = Column(String, nullable=False, default="")
    ips = Column(ARRAY(String), nullable=False, default=list)
    type = Column(String, nullable=False, default="host")
    status = Column(String, nullable=False, default="unknown")
    ports = Column(ARRAY(String), nullable=False, default=list)
    notes = Column(Text, nullable=False, default="")
    role = Column(String, nullable=False, default="")
    os = Column(String, nullable=False, default="")
    tags = Column(ARRAY(String), nullable=False, default=list)
    is_attacker = Column(Boolean, nullable=False, default=False)
    manually_positioned = Column(Boolean, nullable=False, default=False)
    auto_positioned = Column(Boolean, nullable=False, default=False)
    updated_at = Column(String, nullable=False, default="")
    version = Column(Integer, nullable=False, default=1)
    extra_json = Column(JSONB, nullable=False, default=dict)


class NetworkEdge(Base):
    __tablename__ = "network_edges"

    id = Column(String, primary_key=True)
    network_id = Column(String, ForeignKey(_FK_NETWORKS_ID, ondelete="CASCADE"), nullable=False)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
    from_node_id = Column(String, nullable=False)
    to_node_id = Column(String, nullable=False)
    style = Column(String, nullable=False, default="solid")
    type = Column(String, nullable=False, default="network")
    label = Column(String, nullable=False, default="")
    confidence = Column(Float, nullable=False, default=1.0)
    source = Column(String, nullable=False, default="manual")
    reason = Column(String, nullable=False, default="")
    state = Column(String, nullable=False, default="manual")
    verified = Column(Boolean, nullable=False, default=False)
    is_manual = Column(Boolean, nullable=False, default=True)
    manual_override = Column(Boolean, nullable=False, default=False)
    updated_at = Column(String, nullable=False, default="")
    version = Column(Integer, nullable=False, default=1)
    extra_json = Column(JSONB, nullable=False, default=dict)


class NetworkRegion(Base):
    __tablename__ = "network_regions"

    id = Column(String, primary_key=True)
    network_id = Column(String, ForeignKey(_FK_NETWORKS_ID, ondelete="CASCADE"), nullable=False)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False)
    x = Column(Float, nullable=False, default=0)
    y = Column(Float, nullable=False, default=0)
    w = Column(Float, nullable=False, default=200)
    h = Column(Float, nullable=False, default=100)
    label = Column(String, nullable=False, default="")
    note = Column(Text, nullable=False, default="")
    fill = Column(String, nullable=False, default="")
    stroke = Column(String, nullable=False, default="")
    zone_type = Column(String, nullable=False, default="")
    updated_at = Column(String, nullable=False, default="")
    version = Column(Integer, nullable=False, default=1)
    extra_json = Column(JSONB, nullable=False, default=dict)
