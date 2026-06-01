"""Add MFA/TOTP columns to users table (B8-11)."""

import sqlalchemy as sa

from alembic import op

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("totp_secret", sa.String(), nullable=True))
    op.add_column(
        "users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default="false")
    )


def downgrade():
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "totp_secret")
