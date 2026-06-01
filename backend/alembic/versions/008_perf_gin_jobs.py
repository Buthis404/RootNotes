"""Performance — GIN index on jobs.request_json + jobs.result_json

Revision ID: 008
Revises: 007
Create Date: 2026-05-18

`jobs.request_json["playbook_run_id"].astext == X` is the filter
behind /api/projects/{pid}/jobs?playbook_run_id=… (run-view expansion,
DAG-graph payload, "Open Jobs" deeplink). Without a GIN index Postgres
falls back to a seq scan of the full jobs table on every request.

`jobs.result_json` is read on every rollup aggregate (P4 DAG step
transitions) — but those filter by id, so indexing the JSON isn't
critical for the rollup. We still add a small jsonb_path_ops GIN for
future contains-style queries (e.g. "find jobs whose result has X").

GIN on jsonb_path_ops is much smaller and faster for the @> /
->>'key' = value access pattern than the default jsonb_ops opclass.
"""

from alembic import op

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


_INDEXES = [
    ("idx_jobs_request_gin", "jobs", "USING GIN (request_json jsonb_path_ops)"),
    ("idx_jobs_result_gin", "jobs", "USING GIN (result_json jsonb_path_ops)"),
]


def upgrade():
    conn = op.get_bind()
    for name, table, defn in _INDEXES:
        conn.exec_driver_sql(f"CREATE INDEX IF NOT EXISTS {name} ON {table} {defn}")


def downgrade():
    conn = op.get_bind()
    for name, _table, _defn in _INDEXES:
        conn.exec_driver_sql(f"DROP INDEX IF EXISTS {name}")
