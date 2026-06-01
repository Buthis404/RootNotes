"""Conditional column types: JSONB/ARRAY use SQLite-safe fallbacks in test mode."""

import os

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import ARRAY as _PG_ARRAY
from sqlalchemy.dialects.postgresql import JSONB as _PG_JSONB

_is_test = os.environ.get("APP_ENV", "dev").lower() in ("test", "testing")
JSONB = JSON if _is_test else _PG_JSONB


def pg_array(item_type=None):
    return JSON if _is_test else _PG_ARRAY(item_type)
