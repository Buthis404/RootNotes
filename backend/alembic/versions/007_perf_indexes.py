"""Performance — composite indexes on hot query columns

Revision ID: 007
Revises: 006
Create Date: 2026-05-18

Adds composite btree indexes covering the WHERE/ORDER BY shapes that
list endpoints actually use. Single-column indexes on `pid` already
exist for most tables; this migration adds the multi-column variants
PostgreSQL needs to satisfy `pid = ? AND status = ?` /
`ORDER BY ts DESC` without a sort.

Tables / index rationale:

- jobs (pid, status)              — JobsView list filters by status
- jobs (pid, created_at DESC)     — JobsView default ordering
- jobs (pid, connector_key)       — search.py + scoped job lists
- jobs (related_entity_type,
        related_entity_id)        — "jobs for this playbook run" lookup
- host_activities (host_id, ts DESC)
                                  — per-host activity feed
- host_activities (pid, ts DESC)  — project-wide activity feed
- hosts (pid, status)             — HostsView filtered list
- findings (pid, status)          — FindingsView filtered list
- timeline_events (pid, ts DESC)  — already exists; skipped

All indexes are CREATE IF NOT EXISTS so re-running on a partial state
is safe. CONCURRENTLY is omitted: this runs under alembic's
transactional DDL and our tables are small (low thousands). On a
production-scale dataset use `op.execute("COMMIT")` first or break
this into a non-transactional migration.
"""

from alembic import op

_IDX_PID_STATUS = "(pid, status)"


revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


_INDEXES = [
    ("idx_jobs_pid_status", "jobs", _IDX_PID_STATUS),
    ("idx_jobs_pid_created_desc", "jobs", "(pid, created_at DESC)"),
    ("idx_jobs_pid_connector", "jobs", "(pid, connector_key)"),
    ("idx_jobs_related_entity", "jobs", "(related_entity_type, related_entity_id)"),
    ("idx_host_activities_host_ts", "host_activities", "(host_id, ts DESC)"),
    ("idx_host_activities_pid_ts", "host_activities", "(pid, ts DESC)"),
    ("idx_hosts_pid_status", "hosts", _IDX_PID_STATUS),
    ("idx_findings_pid_status", "findings", _IDX_PID_STATUS),
]


def upgrade():
    conn = op.get_bind()
    for name, table, cols in _INDEXES:
        conn.exec_driver_sql(f"CREATE INDEX IF NOT EXISTS {name} ON {table} {cols}")


def downgrade():
    conn = op.get_bind()
    for name, _table, _cols in _INDEXES:
        conn.exec_driver_sql(f"DROP INDEX IF EXISTS {name}")
