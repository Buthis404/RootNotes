from sqlalchemy import Column, ForeignKey, String, Text

from ..database import Base
from ._types import pg_array as ARRAY


class KBArticle(Base):
    __tablename__ = "kb_articles"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False, default="")
    category = Column(String, nullable=False, default="General")
    tags = Column(ARRAY(String), nullable=False, default=[])
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)


class CustomSnippet(Base):
    __tablename__ = "custom_snippets"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    category = Column(String, nullable=False, default="Misc")
    command = Column(Text, nullable=False, default="")
    tags = Column(ARRAY(String), nullable=False, default=[])
    opsec = Column(Text, nullable=False, default="")
    created_at = Column(String, nullable=False)
