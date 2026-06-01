from sqlalchemy import Boolean, Column, String

from ..database import Base
from ._types import JSONB


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    display_name = Column(String, nullable=False, default="")
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")
    created_at = Column(String, nullable=False)
    active = Column(Boolean, nullable=False, default=True)
    totp_secret = Column(String, nullable=True)
    mfa_enabled = Column(Boolean, nullable=False, default=False)


class GlobalSetting(Base):
    __tablename__ = "global_settings"

    key = Column(String, primary_key=True)
    value = Column(JSONB, nullable=False, default=dict)
