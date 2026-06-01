from sqlalchemy import Boolean, Column, ForeignKey, String, Text

from ..database import Base
from ._types import pg_array as ARRAY


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


class CredHostNote(Base):
    __tablename__ = "cred_host_notes"

    id = Column(String, primary_key=True)
    cred_id = Column(String, ForeignKey("creds.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    notes = Column(Text, nullable=False, default="")
    access = Column(ARRAY(String), nullable=False, default=[])
