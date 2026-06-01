"""drop project_domains table

Revision ID: 013
Revises: 012
Create Date: 2026-05-29
"""
from alembic import op

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table("project_domains")


def downgrade():
    import sqlalchemy as sa
    from sqlalchemy.dialects import postgresql
    op.create_table(
        "project_domains",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("pid", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("aliases", postgresql.ARRAY(sa.String()), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["pid"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
