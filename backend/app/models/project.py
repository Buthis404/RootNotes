from sqlalchemy import Boolean, Column, ForeignKey, String, Text

from ..database import Base


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


class ProjectMember(Base):
    __tablename__ = "project_members"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String, nullable=False, default="viewer")
    created_at = Column(String, nullable=False)
    created_by = Column(String, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
