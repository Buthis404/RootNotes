"""Fix network_nodes.ports column type from JSONB to TEXT[]

Revision ID: 004
Revises: 003
Create Date: 2026-05-14
"""

from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade():
    # PostgreSQL doesn't allow subqueries in ALTER COLUMN ... USING.
    # Use a temp column swap instead.
    op.execute("ALTER TABLE network_nodes ADD COLUMN ports_new TEXT[] NOT NULL DEFAULT '{}'")
    op.execute("UPDATE network_nodes SET ports_new = array(SELECT jsonb_array_elements_text(ports))")
    op.execute("ALTER TABLE network_nodes DROP COLUMN ports")
    op.execute("ALTER TABLE network_nodes RENAME COLUMN ports_new TO ports")


def downgrade():
    op.execute("ALTER TABLE network_nodes ADD COLUMN ports_jsonb JSONB NOT NULL DEFAULT '[]'")
    op.execute("UPDATE network_nodes SET ports_jsonb = to_jsonb(ports)")
    op.execute("ALTER TABLE network_nodes DROP COLUMN ports")
    op.execute("ALTER TABLE network_nodes RENAME COLUMN ports_jsonb TO ports")
