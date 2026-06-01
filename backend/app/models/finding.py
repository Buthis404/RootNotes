from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text

from ..database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    host_id = Column(String, nullable=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="medium")
    cvss = Column(String, nullable=False, default="")
    cve = Column(String, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    proof = Column(Text, nullable=False, default="")
    recommendation = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="open")
    source = Column(String, nullable=False, default="manual")
    ts = Column(String, nullable=False)


class FindingTemplate(Base):
    __tablename__ = "finding_templates_custom"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="medium")
    cvss = Column(String, nullable=False, default="")
    cve = Column(String, nullable=False, default="")
    description = Column(Text, nullable=False, default="")
    proof = Column(Text, nullable=False, default="")
    recommendation = Column(Text, nullable=False, default="")
    created_at = Column(String, nullable=False)


class ChecklistItem(Base):
    __tablename__ = "checklist_items"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    phase = Column(String, nullable=False)
    text = Column(String, nullable=False)
    done = Column(Boolean, nullable=False, default=False)
    order_idx = Column(Integer, nullable=False, default=0)
