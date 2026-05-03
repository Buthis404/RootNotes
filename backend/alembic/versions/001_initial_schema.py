"""Initial schema — documents the baseline state of the database.

This migration reflects the schema already created via SQLAlchemy create_all()
and inline ALTER TABLE statements in main.py. Running upgrade() on a fresh DB
produces the same result as the inline bootstrap. The inline bootstrap in
main.py remains in place for backward compatibility.

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("display_name", sa.String(), nullable=False, server_default=""),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="user"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )

    op.create_table(
        "projects",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("ip", sa.String(), nullable=False, server_default=""),
        sa.Column("os", sa.String(), nullable=False, server_default="Linux"),
        sa.Column("added", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "notes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("pid", sa.String(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("phase", sa.String(), nullable=False, server_default="recon"),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column("ts", sa.String(), nullable=False),
        sa.Column("starred", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "hosts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("pid", sa.String(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip", sa.String(), nullable=False),
        sa.Column("ips", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("hostname", sa.String(), nullable=False, server_default=""),
        sa.Column("os", sa.String(), nullable=False, server_default="Linux"),
        sa.Column("status", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("ports", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("services", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("domain", sa.String(), nullable=False, server_default=""),
        sa.Column("role", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("is_attacker", sa.Boolean(), nullable=False, server_default="false"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "creds",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("pid", sa.String(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("secret", sa.Text(), nullable=False, server_default=""),
        sa.Column("type", sa.String(), nullable=False, server_default="plain"),
        sa.Column("service", sa.String(), nullable=False, server_default=""),
        sa.Column("host", sa.String(), nullable=False, server_default=""),
        sa.Column("domain", sa.String(), nullable=False, server_default=""),
        sa.Column("cracked", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("host_ids", postgresql.ARRAY(sa.String()), nullable=False, server_default="{}"),
        sa.Column("is_domain", sa.Boolean(), nullable=False, server_default="false"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "global_settings",
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.PrimaryKeyConstraint("key"),
    )

    op.create_table(
        "project_members",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_pm_project_id", "project_members", ["project_id"])
    op.create_index("idx_pm_user_id", "project_members", ["user_id"])
    op.create_index("idx_pm_project_user", "project_members", ["project_id", "user_id"], unique=True)


def downgrade() -> None:
    op.drop_index("idx_pm_project_user", table_name="project_members")
    op.drop_index("idx_pm_user_id", table_name="project_members")
    op.drop_index("idx_pm_project_id", table_name="project_members")
    op.drop_table("project_members")
    op.drop_table("global_settings")
    op.drop_table("creds")
    op.drop_table("hosts")
    op.drop_table("notes")
    op.drop_table("projects")
    op.drop_table("users")
