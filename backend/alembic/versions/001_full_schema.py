"""Full schema — idempotent baseline covering all tables, columns and indexes.

All statements use IF NOT EXISTS / ADD COLUMN IF NOT EXISTS so this migration
is safe to apply against both a fresh database and an existing one that was
bootstrapped via the legacy create_all + raw-SQL path in main.py.

Revision ID: 001
Revises:
Create Date: 2026-05-14 00:00:00.000000
"""

from sqlalchemy import text

from alembic import op

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Core tables ──────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL,
            active BOOLEAN NOT NULL DEFAULT TRUE
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            ip TEXT NOT NULL DEFAULT '',
            os TEXT NOT NULL DEFAULT 'Linux',
            added TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            webhook_token TEXT NOT NULL DEFAULT ''
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS project_members (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT NOT NULL,
            created_by TEXT,
            is_active BOOLEAN NOT NULL DEFAULT TRUE
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS global_settings (
            key TEXT PRIMARY KEY,
            value JSONB NOT NULL DEFAULT '{}'
        )
    """))

    # ── Notes ────────────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            phase TEXT NOT NULL DEFAULT 'recon',
            tags TEXT[] NOT NULL DEFAULT '{}',
            content TEXT NOT NULL DEFAULT '',
            ts TEXT NOT NULL,
            starred BOOLEAN NOT NULL DEFAULT FALSE,
            version INTEGER NOT NULL DEFAULT 0
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS note_attachments (
            id TEXT PRIMARY KEY,
            note_id TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
            file_size INTEGER NOT NULL DEFAULT 0,
            storage_path TEXT NOT NULL,
            public_url TEXT NOT NULL,
            ts TEXT NOT NULL
        )
    """))

    # ── Hosts ────────────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            ips TEXT[] NOT NULL DEFAULT '{}',
            hostname TEXT NOT NULL DEFAULT '',
            os TEXT NOT NULL DEFAULT 'Linux',
            status TEXT NOT NULL DEFAULT 'unknown',
            ports TEXT[] NOT NULL DEFAULT '{}',
            services TEXT[] NOT NULL DEFAULT '{}',
            tags TEXT[] NOT NULL DEFAULT '{}',
            notes TEXT NOT NULL DEFAULT '',
            domain TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT 'unknown',
            is_attacker BOOLEAN NOT NULL DEFAULT FALSE,
            import_source TEXT NOT NULL DEFAULT ''
        )
    """))

    # ── Credentials ──────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS creds (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            username TEXT NOT NULL,
            secret TEXT NOT NULL DEFAULT '',
            type TEXT NOT NULL DEFAULT 'plain',
            service TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL DEFAULT '',
            domain TEXT NOT NULL DEFAULT '',
            cracked BOOLEAN NOT NULL DEFAULT FALSE,
            notes TEXT NOT NULL DEFAULT '',
            tags TEXT[] NOT NULL DEFAULT '{}',
            host_ids TEXT[] NOT NULL DEFAULT '{}',
            is_domain BOOLEAN NOT NULL DEFAULT FALSE
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS cred_host_notes (
            id TEXT PRIMARY KEY,
            cred_id TEXT NOT NULL REFERENCES creds(id) ON DELETE CASCADE,
            host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            notes TEXT NOT NULL DEFAULT '',
            access TEXT[] NOT NULL DEFAULT '{}'
        )
    """))

    # ── Network map ──────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS networks (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL DEFAULT 'Network',
            background TEXT NOT NULL DEFAULT '#07080b',
            regions_json JSONB NOT NULL DEFAULT '[]',
            nodes_json JSONB NOT NULL DEFAULT '[]',
            edges_json JSONB NOT NULL DEFAULT '[]',
            meta_json JSONB NOT NULL DEFAULT '{}'
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS pivot_observations (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            source_host_id TEXT NOT NULL DEFAULT '',
            pivot_host_id TEXT NOT NULL DEFAULT '',
            target_host_id TEXT NOT NULL DEFAULT '',
            tool TEXT NOT NULL DEFAULT '',
            pivot_type TEXT NOT NULL DEFAULT 'route',
            label TEXT NOT NULL DEFAULT '',
            route_cidr TEXT NOT NULL DEFAULT '',
            bind_address TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            notes TEXT NOT NULL DEFAULT '',
            collector_target_id TEXT NOT NULL DEFAULT '',
            fingerprint TEXT NOT NULL DEFAULT '',
            ts TEXT NOT NULL,
            last_seen TEXT NOT NULL DEFAULT ''
        )
    """))

    # ── Findings ─────────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            host_id TEXT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            cvss TEXT NOT NULL DEFAULT '',
            cve TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            proof TEXT NOT NULL DEFAULT '',
            recommendation TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            source TEXT NOT NULL DEFAULT 'manual',
            ts TEXT NOT NULL
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS finding_templates_custom (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            cvss TEXT NOT NULL DEFAULT '',
            cve TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            proof TEXT NOT NULL DEFAULT '',
            recommendation TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS checklist_items (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            phase TEXT NOT NULL,
            text TEXT NOT NULL,
            done BOOLEAN NOT NULL DEFAULT FALSE,
            order_idx INTEGER NOT NULL DEFAULT 0
        )
    """))

    # ── Loot ─────────────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS loots (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            host_id TEXT,
            loot_type TEXT NOT NULL DEFAULT 'file',
            value TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            source_path TEXT NOT NULL DEFAULT '',
            filename TEXT NOT NULL DEFAULT '',
            content_type TEXT NOT NULL DEFAULT '',
            file_size INTEGER NOT NULL DEFAULT 0,
            storage_path TEXT NOT NULL DEFAULT '',
            public_url TEXT NOT NULL DEFAULT '',
            ts TEXT NOT NULL,
            job_id TEXT NOT NULL DEFAULT '',
            cred_id TEXT NOT NULL DEFAULT '',
            finding_id TEXT NOT NULL DEFAULT '',
            playbook_run_id TEXT NOT NULL DEFAULT '',
            sha256 TEXT NOT NULL DEFAULT '',
            artifact_type TEXT NOT NULL DEFAULT 'file',
            tags TEXT[] NOT NULL DEFAULT '{}'
        )
    """))

    # ── Scope ────────────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS scopes (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            value TEXT NOT NULL,
            scope_type TEXT NOT NULL DEFAULT 'cidr',
            in_scope BOOLEAN NOT NULL DEFAULT TRUE,
            description TEXT NOT NULL DEFAULT '',
            gateway_ip TEXT NOT NULL DEFAULT '',
            is_entry BOOLEAN NOT NULL DEFAULT FALSE,
            via_host_id TEXT NOT NULL DEFAULT ''
        )
    """))

    # ── Objectives ───────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS objectives (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            host_id TEXT,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'flag',
            points INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'not_started',
            flag_value TEXT NOT NULL DEFAULT '',
            captured_by TEXT NOT NULL DEFAULT '',
            captured_at TEXT NOT NULL DEFAULT '',
            ts TEXT NOT NULL
        )
    """))

    # ── Timeline ─────────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS timeline_events (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL,
            username TEXT,
            entity TEXT NOT NULL,
            action TEXT NOT NULL,
            label TEXT NOT NULL,
            meta JSONB NOT NULL DEFAULT '{}',
            ts TEXT NOT NULL
        )
    """))

    # ── Attack paths ─────────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS attack_paths (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL DEFAULT 'Attack Path',
            description TEXT NOT NULL DEFAULT '',
            ts TEXT NOT NULL
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS attack_steps (
            id TEXT PRIMARY KEY,
            path_id TEXT NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE,
            pid TEXT NOT NULL,
            host_id TEXT REFERENCES hosts(id) ON DELETE SET NULL,
            step_order INTEGER NOT NULL DEFAULT 0,
            node_type TEXT NOT NULL DEFAULT 'host',
            label TEXT NOT NULL DEFAULT '',
            sublabel TEXT NOT NULL DEFAULT '',
            technique TEXT NOT NULL DEFAULT '',
            mitre_id TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            ts TEXT NOT NULL
        )
    """))

    # ── Host activities ───────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS host_activities (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
            title TEXT NOT NULL DEFAULT '',
            activity_type TEXT NOT NULL DEFAULT 'recon',
            command TEXT NOT NULL DEFAULT '',
            summary TEXT NOT NULL DEFAULT '',
            output TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'done',
            ts TEXT NOT NULL,
            job_id TEXT NOT NULL DEFAULT ''
        )
    """))

    # ── Jobs / Playbooks ─────────────────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            title TEXT NOT NULL DEFAULT '',
            target TEXT NOT NULL DEFAULT '',
            command TEXT NOT NULL DEFAULT '',
            output TEXT NOT NULL DEFAULT '',
            error_output TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            connector_key TEXT NOT NULL DEFAULT '',
            operation TEXT NOT NULL DEFAULT '',
            scope_type TEXT NOT NULL DEFAULT 'project',
            scope_id TEXT NOT NULL DEFAULT '',
            related_entity_type TEXT NOT NULL DEFAULT '',
            related_entity_id TEXT NOT NULL DEFAULT '',
            retry_of_job_id TEXT NOT NULL DEFAULT '',
            priority INTEGER NOT NULL DEFAULT 0,
            retry_count INTEGER NOT NULL DEFAULT 0,
            max_retries INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '',
            request_json JSONB NOT NULL DEFAULT '{}',
            result_json JSONB NOT NULL DEFAULT '{}'
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS playbook_runs (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            playbook_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'queued',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '',
            target TEXT NOT NULL DEFAULT '',
            error_output TEXT NOT NULL DEFAULT '',
            jobs_json JSONB NOT NULL DEFAULT '[]',
            request_json JSONB NOT NULL DEFAULT '{}',
            result_json JSONB NOT NULL DEFAULT '{}'
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS custom_playbooks (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            steps_json JSONB NOT NULL DEFAULT '[]',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS scheduled_playbooks (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            playbook_id TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            cron_expr TEXT NOT NULL DEFAULT '0 * * * *',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            body_json JSONB NOT NULL DEFAULT '{}',
            last_run_at TEXT NOT NULL DEFAULT '',
            next_run_at TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """))

    # ── KB / Snippets / Collections ───────────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS kb_articles (
            id TEXT PRIMARY KEY,
            pid TEXT REFERENCES projects(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            content TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'General',
            tags TEXT[] NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS custom_snippets (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'Misc',
            command TEXT NOT NULL DEFAULT '',
            tags TEXT[] NOT NULL DEFAULT '{}',
            opsec TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS host_collections (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            color TEXT NOT NULL DEFAULT '#4f8ef7',
            filters_json JSONB NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """))

    # ── Domains / Packs / Saved searches ─────────────────────────────────────
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS project_domains (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            aliases TEXT[] NOT NULL DEFAULT '{}',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS operation_packs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            steps JSONB NOT NULL DEFAULT '[]',
            tags TEXT[] NOT NULL DEFAULT '{}',
            is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """))

    op.execute(text("""
        CREATE TABLE IF NOT EXISTS saved_searches (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            query TEXT NOT NULL,
            pid TEXT,
            created_at TEXT NOT NULL
        )
    """))

    # ── Indexes ───────────────────────────────────────────────────────────────
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_pm_project_id ON project_members(project_id)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_pm_user_id ON project_members(user_id)"))
    op.execute(
        text(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_pm_project_user ON project_members(project_id, user_id)"
        )
    )
    op.execute(
        text(
            "CREATE INDEX IF NOT EXISTS idx_projects_webhook_token ON projects(webhook_token) WHERE webhook_token <> ''"
        )
    )
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_hosts_pid ON hosts(pid)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_creds_pid ON creds(pid)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_notes_pid ON notes(pid)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_notes_ts ON notes(ts DESC)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_pid ON findings(pid)"))
    op.execute(
        text(
            "CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(pid, source) WHERE source <> 'manual'"
        )
    )
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_loots_pid ON loots(pid)"))
    op.execute(
        text("CREATE INDEX IF NOT EXISTS idx_loots_job_id ON loots(job_id) WHERE job_id <> ''")
    )
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_jobs_pid ON jobs(pid)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_playbook_runs_pid ON playbook_runs(pid)"))
    op.execute(
        text("CREATE INDEX IF NOT EXISTS idx_scheduled_playbooks_pid ON scheduled_playbooks(pid)")
    )
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_project_domains_pid ON project_domains(pid)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_kb_articles_pid ON kb_articles(pid)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_host_collections_pid ON host_collections(pid)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_host_activities_pid ON host_activities(pid)"))
    op.execute(
        text("CREATE INDEX IF NOT EXISTS idx_host_activities_host_id ON host_activities(host_id)")
    )
    op.execute(
        text("CREATE INDEX IF NOT EXISTS idx_cred_host_notes_cred_id ON cred_host_notes(cred_id)")
    )
    op.execute(
        text("CREATE INDEX IF NOT EXISTS idx_cred_host_notes_host_id ON cred_host_notes(host_id)")
    )
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_attack_steps_path_id ON attack_steps(path_id)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_timeline_events_pid ON timeline_events(pid)"))
    op.execute(
        text("CREATE INDEX IF NOT EXISTS idx_timeline_events_ts ON timeline_events(ts DESC)")
    )
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_checklist_items_pid ON checklist_items(pid)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_scopes_pid ON scopes(pid)"))
    op.execute(text("CREATE INDEX IF NOT EXISTS idx_objectives_pid ON objectives(pid)"))

    # ── FTS GIN indexes ───────────────────────────────────────────────────────
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_hosts_fts ON hosts
        USING GIN (to_tsvector('english',
            coalesce(ip,'') || ' ' || coalesce(hostname,'') || ' ' ||
            coalesce(os,'') || ' ' || coalesce(notes,'')
        ))
    """))
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_creds_fts ON creds
        USING GIN (to_tsvector('english',
            coalesce(username,'') || ' ' || coalesce(service,'') || ' ' ||
            coalesce(host,'') || ' ' || coalesce(notes,'')
        ))
    """))
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_notes_fts ON notes
        USING GIN (to_tsvector('english',
            coalesce(title,'') || ' ' || coalesce(content,'')
        ))
    """))
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_findings_fts ON findings
        USING GIN (to_tsvector('english',
            coalesce(title,'') || ' ' || coalesce(description,'') || ' ' || coalesce(cve,'')
        ))
    """))
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_kb_articles_fts ON kb_articles
        USING GIN (to_tsvector('english',
            coalesce(title,'') || ' ' || coalesce(content,'')
        ))
    """))
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_custom_snippets_fts ON custom_snippets
        USING GIN (to_tsvector('english',
            coalesce(title,'') || ' ' || coalesce(command,'') || ' ' || coalesce(opsec,'')
        ))
    """))


def downgrade() -> None:
    # Drop in reverse dependency order
    op.execute(text("DROP TABLE IF EXISTS saved_searches"))
    op.execute(text("DROP TABLE IF EXISTS operation_packs"))
    op.execute(text("DROP TABLE IF EXISTS project_domains"))
    op.execute(text("DROP TABLE IF EXISTS host_collections"))
    op.execute(text("DROP TABLE IF EXISTS custom_snippets"))
    op.execute(text("DROP TABLE IF EXISTS kb_articles"))
    op.execute(text("DROP TABLE IF EXISTS scheduled_playbooks"))
    op.execute(text("DROP TABLE IF EXISTS custom_playbooks"))
    op.execute(text("DROP TABLE IF EXISTS playbook_runs"))
    op.execute(text("DROP TABLE IF EXISTS jobs"))
    op.execute(text("DROP TABLE IF EXISTS host_activities"))
    op.execute(text("DROP TABLE IF EXISTS attack_steps"))
    op.execute(text("DROP TABLE IF EXISTS attack_paths"))
    op.execute(text("DROP TABLE IF EXISTS timeline_events"))
    op.execute(text("DROP TABLE IF EXISTS objectives"))
    op.execute(text("DROP TABLE IF EXISTS scopes"))
    op.execute(text("DROP TABLE IF EXISTS loots"))
    op.execute(text("DROP TABLE IF EXISTS checklist_items"))
    op.execute(text("DROP TABLE IF EXISTS finding_templates_custom"))
    op.execute(text("DROP TABLE IF EXISTS findings"))
    op.execute(text("DROP TABLE IF EXISTS pivot_observations"))
    op.execute(text("DROP TABLE IF EXISTS networks"))
    op.execute(text("DROP TABLE IF EXISTS cred_host_notes"))
    op.execute(text("DROP TABLE IF EXISTS creds"))
    op.execute(text("DROP TABLE IF EXISTS host_activities"))
    op.execute(text("DROP TABLE IF EXISTS hosts"))
    op.execute(text("DROP TABLE IF EXISTS note_attachments"))
    op.execute(text("DROP TABLE IF EXISTS notes"))
    op.execute(text("DROP TABLE IF EXISTS project_members"))
    op.execute(text("DROP TABLE IF EXISTS global_settings"))
    op.execute(text("DROP TABLE IF EXISTS projects"))
    op.execute(text("DROP TABLE IF EXISTS users"))
