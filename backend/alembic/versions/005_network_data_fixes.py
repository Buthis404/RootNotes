"""Fix network_edges.confidence type + add extra_json to network_regions

Revision ID: 005
Revises: 004
Create Date: 2026-05-14
"""

from alembic import op

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade():
    # confidence was INTEGER but topology code uses 0.0-1.0 floats
    # int(0.9) = 0, so all inferred edges had confidence=0
    op.execute("""
        ALTER TABLE network_edges
        ALTER COLUMN confidence TYPE DOUBLE PRECISION
        USING confidence::double precision;
    """)
    # Fix existing values: 0 means it came from a float like 0.9 that was truncated.
    # Reset them to 1.0 (will be recalculated on next smart build).
    # Keep 100 (= was already integer 100 from default) → convert to 1.0
    op.execute("""
        UPDATE network_edges
        SET confidence = CASE
            WHEN confidence = 100 THEN 1.0
            WHEN confidence = 0   THEN 1.0
            ELSE confidence / 100.0
        END;
    """)
    op.execute("""
        ALTER TABLE network_edges ALTER COLUMN confidence SET DEFAULT 1.0;
    """)

    # Add extra_json to network_regions so custom fields (via_host_id, etc.) aren't lost
    op.execute("""
        ALTER TABLE network_regions
        ADD COLUMN IF NOT EXISTS extra_json JSONB NOT NULL DEFAULT '{}';
    """)


def downgrade():
    op.execute("ALTER TABLE network_regions DROP COLUMN IF EXISTS extra_json;")
    op.execute(
        "ALTER TABLE network_edges ALTER COLUMN confidence TYPE INTEGER USING (confidence * 100)::integer;"
    )
    op.execute("ALTER TABLE network_edges ALTER COLUMN confidence SET DEFAULT 100;")
