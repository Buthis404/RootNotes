"""Add integrity column to timeline_events

Revision ID: 011
Revises: 010
Create Date: 2026-05-21

Adds `integrity` VARCHAR column to timeline_events.  When AUDIT_INTEGRITY_KEY
is set, every new event has a HMAC-SHA256 fingerprint stored here so the
/api/admin/audit/verify endpoint can detect if any rows have been tampered
with or silently deleted (via the append-only JSONL mirror).  Existing rows
get NULL — they appear as "unverified" (not "tampered") in the report.
"""

import sqlalchemy as sa

from alembic import op

revision = "011"
down_revision = "010"


def upgrade():
    op.add_column("timeline_events", sa.Column("integrity", sa.String(), nullable=True))


def downgrade():
    op.drop_column("timeline_events", "integrity")
