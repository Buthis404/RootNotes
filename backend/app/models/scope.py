from sqlalchemy import Boolean, Column, ForeignKey, String

from ..database import Base


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
    via_host_id = Column(String, nullable=False, default="")


class SavedSearch(Base):
    __tablename__ = "saved_searches"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    query = Column(String, nullable=False)
    pid = Column(String, nullable=True)
    created_at = Column(String, nullable=False)
