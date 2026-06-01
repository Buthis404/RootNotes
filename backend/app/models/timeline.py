from sqlalchemy import Column, String

from ..database import Base
from ._types import JSONB


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
    # HMAC-SHA256 fingerprint computed when AUDIT_INTEGRITY_KEY is set (B9-4).
    # NULL on events created before the integrity feature was enabled.
    integrity = Column(String, nullable=True)
