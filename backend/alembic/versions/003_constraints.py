"""Add unique webhook_token index and timeline_events FK

Revision ID: 003
Revises: 002
Create Date: 2026-05-14
"""

from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade():
    # Make webhook_token partial unique (replace non-unique index)
    op.execute("DROP INDEX IF EXISTS idx_projects_webhook_token;")
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_webhook_token_uniq
        ON projects (webhook_token)
        WHERE webhook_token != '';
    """)

    # FK: timeline_events.pid → projects.id CASCADE (NOT VALID = skip existing rows)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.table_constraints
                WHERE constraint_name = 'timeline_events_pid_fkey'
                  AND table_name = 'timeline_events'
            ) THEN
                ALTER TABLE timeline_events
                    ADD CONSTRAINT timeline_events_pid_fkey
                    FOREIGN KEY (pid) REFERENCES projects(id) ON DELETE CASCADE
                    NOT VALID;
            END IF;
        END $$;
    """)

    # FK: findings.host_id → hosts.id SET NULL (NOT VALID = skip existing rows)
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.table_constraints
                WHERE constraint_name = 'findings_host_id_fkey'
                  AND table_name = 'findings'
            ) THEN
                ALTER TABLE findings
                    ADD CONSTRAINT findings_host_id_fkey
                    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL
                    NOT VALID;
            END IF;
        END $$;
    """)

    # FK: loots.host_id → hosts.id SET NULL
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.table_constraints
                WHERE constraint_name = 'loots_host_id_fkey'
                  AND table_name = 'loots'
            ) THEN
                ALTER TABLE loots
                    ADD CONSTRAINT loots_host_id_fkey
                    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL
                    NOT VALID;
            END IF;
        END $$;
    """)

    # FK: objectives.host_id → hosts.id SET NULL
    op.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.table_constraints
                WHERE constraint_name = 'objectives_host_id_fkey'
                  AND table_name = 'objectives'
            ) THEN
                ALTER TABLE objectives
                    ADD CONSTRAINT objectives_host_id_fkey
                    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL
                    NOT VALID;
            END IF;
        END $$;
    """)


def downgrade():
    op.execute("ALTER TABLE objectives DROP CONSTRAINT IF EXISTS objectives_host_id_fkey;")
    op.execute("ALTER TABLE loots DROP CONSTRAINT IF EXISTS loots_host_id_fkey;")
    op.execute("ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_host_id_fkey;")
    op.execute("ALTER TABLE timeline_events DROP CONSTRAINT IF EXISTS timeline_events_pid_fkey;")
    op.execute("DROP INDEX IF EXISTS idx_projects_webhook_token_uniq;")
    op.execute("""
        CREATE INDEX IF NOT EXISTS idx_projects_webhook_token
        ON projects (webhook_token)
        WHERE webhook_token != '';
    """)
