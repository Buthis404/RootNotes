"""Add file_encrypted flag to loots table

Revision ID: 010
Revises: 009
Create Date: 2026-05-21

Adds `file_encrypted` boolean column (default FALSE) so the download
endpoint knows whether to run Fernet decryption before streaming the
file.  Existing rows keep FALSE — they were uploaded before encryption
was enabled and their files remain in plaintext on disk.
"""

from alembic import op

revision = "010"
down_revision = "009"


def upgrade():
    conn = op.get_bind()
    conn.exec_driver_sql(
        "ALTER TABLE loots ADD COLUMN IF NOT EXISTS file_encrypted BOOLEAN NOT NULL DEFAULT FALSE"
    )


def downgrade():
    conn = op.get_bind()
    conn.exec_driver_sql("ALTER TABLE loots DROP COLUMN IF EXISTS file_encrypted")
