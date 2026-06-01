from sqlalchemy import Column, ForeignKey, String, Text

from ..database import Base
from ._types import pg_array as ARRAY


class Domain(Base):
    __tablename__ = "project_domains"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    aliases = Column(ARRAY(String), nullable=False, default=[])
    notes = Column(Text, nullable=False, default="")
    created_at = Column(String, nullable=False)
