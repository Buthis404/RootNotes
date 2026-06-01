from sqlalchemy import Column, ForeignKey, Integer, String, Text

from ..database import Base


class Objective(Base):
    __tablename__ = "objectives"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String, nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    category = Column(String, nullable=False, default="flag")
    points = Column(Integer, nullable=False, default=0)
    status = Column(String, nullable=False, default="not_started")
    flag_value = Column(String, nullable=False, default="")
    captured_by = Column(String, nullable=False, default="")
    captured_at = Column(String, nullable=False, default="")
    ts = Column(String, nullable=False)
