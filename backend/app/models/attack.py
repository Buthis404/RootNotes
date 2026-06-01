from sqlalchemy import Column, ForeignKey, Integer, String, Text

from ..database import Base


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False, default="Attack Path")
    description = Column(Text, nullable=False, default="")
    ts = Column(String, nullable=False)


class AttackStep(Base):
    __tablename__ = "attack_steps"

    id = Column(String, primary_key=True)
    path_id = Column(String, ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False)
    pid = Column(String, nullable=False)
    host_id = Column(String, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    step_order = Column(Integer, nullable=False, default=0)
    node_type = Column(String, nullable=False, default="host")
    label = Column(String, nullable=False, default="")
    sublabel = Column(String, nullable=False, default="")
    technique = Column(String, nullable=False, default="")
    mitre_id = Column(String, nullable=False, default="")
    notes = Column(Text, nullable=False, default="")
    ts = Column(String, nullable=False)
