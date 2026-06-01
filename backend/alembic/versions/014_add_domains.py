"""re-add project_domains table

Revision ID: 014
Revises: 013
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "project_domains",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("pid", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["pid"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("project_domains")
