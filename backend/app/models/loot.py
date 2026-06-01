from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text

from ..database import Base
from ._types import pg_array as ARRAY


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
    job_id = Column(String, nullable=False, default="")
    cred_id = Column(String, nullable=False, default="")
    finding_id = Column(String, nullable=False, default="")
    playbook_run_id = Column(String, nullable=False, default="")
    sha256 = Column(String, nullable=False, default="")
    artifact_type = Column(String, nullable=False, default="file")
    tags = Column(ARRAY(String), nullable=False, default=[])
    file_encrypted = Column(Boolean, nullable=False, default=False)
