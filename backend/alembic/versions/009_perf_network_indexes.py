"""Performance — indexes on network_nodes / network_edges

Revision ID: 009
Revises: 008
Create Date: 2026-05-18

`network_nodes` and `network_edges` had no btree on `network_id`
despite every read (get_nodes, get_edges, replace_*, sync_host_to_nodes)
filtering by it. Postgres was full-scanning these tables on every map
open. On a 1000-host project (~500 nodes / 800 edges) the cost was
small but on a 5k-host engagement it dominates.

Also adds `network_nodes(host_id)` — used by `sync_host_to_nodes()`
which fires on every host PATCH and currently seq-scans to find the
nodes mirroring a given host.
"""

from alembic import op

revision = "009"

_IDX_NETWORK_ID = "(network_id)"
down_revision = "008"
branch_labels = None
depends_on = None


_INDEXES = [
    ("idx_network_nodes_network_id", "network_nodes", _IDX_NETWORK_ID),
    ("idx_network_nodes_host_id", "network_nodes", "(host_id)"),
    ("idx_network_edges_network_id", "network_edges", _IDX_NETWORK_ID),
    ("idx_network_regions_network_id", "network_regions", _IDX_NETWORK_ID),
]


def upgrade():
    conn = op.get_bind()
    for name, table, cols in _INDEXES:
        conn.exec_driver_sql(f"CREATE INDEX IF NOT EXISTS {name} ON {table} {cols}")


def downgrade():
    conn = op.get_bind()
    for name, _table, _cols in _INDEXES:
        conn.exec_driver_sql(f"DROP INDEX IF EXISTS {name}")
