"""
002 — Dedicated network_nodes / network_edges / network_regions tables.

Migrates existing JSONB blobs (nodes_json / edges_json / regions_json) into
row-per-entity tables, then drops the legacy JSONB columns.
"""
revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None

import json
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, ARRAY


def upgrade():
    conn = op.get_bind()

    # ── 1. Create new tables ─────────────────────────────────────────────────
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS network_nodes (
            id          TEXT PRIMARY KEY,
            network_id  TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
            pid         TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            host_id     TEXT,
            x           DOUBLE PRECISION NOT NULL DEFAULT 0,
            y           DOUBLE PRECISION NOT NULL DEFAULT 0,
            label       TEXT NOT NULL DEFAULT '',
            ip          TEXT NOT NULL DEFAULT '',
            ips         TEXT[] NOT NULL DEFAULT '{}',
            type        TEXT NOT NULL DEFAULT 'host',
            status      TEXT NOT NULL DEFAULT 'unknown',
            ports       JSONB NOT NULL DEFAULT '[]',
            notes       TEXT NOT NULL DEFAULT '',
            role        TEXT NOT NULL DEFAULT '',
            os          TEXT NOT NULL DEFAULT '',
            tags        TEXT[] NOT NULL DEFAULT '{}',
            is_attacker BOOLEAN NOT NULL DEFAULT FALSE,
            manually_positioned BOOLEAN NOT NULL DEFAULT FALSE,
            auto_positioned     BOOLEAN NOT NULL DEFAULT FALSE,
            updated_at  TEXT NOT NULL DEFAULT '',
            version     INTEGER NOT NULL DEFAULT 1,
            extra_json  JSONB
        )
    """))

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS network_edges (
            id           TEXT PRIMARY KEY,
            network_id   TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
            pid          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            from_node_id TEXT NOT NULL DEFAULT '',
            to_node_id   TEXT NOT NULL DEFAULT '',
            style        TEXT NOT NULL DEFAULT 'solid',
            type         TEXT NOT NULL DEFAULT 'network',
            label        TEXT NOT NULL DEFAULT '',
            confidence   INTEGER NOT NULL DEFAULT 100,
            source       TEXT NOT NULL DEFAULT 'manual',
            reason       TEXT NOT NULL DEFAULT '',
            state        TEXT NOT NULL DEFAULT 'manual',
            verified     BOOLEAN NOT NULL DEFAULT FALSE,
            is_manual    BOOLEAN NOT NULL DEFAULT TRUE,
            manual_override BOOLEAN NOT NULL DEFAULT FALSE,
            updated_at   TEXT NOT NULL DEFAULT '',
            version      INTEGER NOT NULL DEFAULT 1,
            extra_json   JSONB
        )
    """))

    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS network_regions (
            id         TEXT PRIMARY KEY,
            network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
            pid        TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            x          DOUBLE PRECISION NOT NULL DEFAULT 0,
            y          DOUBLE PRECISION NOT NULL DEFAULT 0,
            w          DOUBLE PRECISION NOT NULL DEFAULT 200,
            h          DOUBLE PRECISION NOT NULL DEFAULT 100,
            label      TEXT NOT NULL DEFAULT '',
            note       TEXT NOT NULL DEFAULT '',
            fill       TEXT NOT NULL DEFAULT '',
            stroke     TEXT NOT NULL DEFAULT '',
            zone_type  TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT '',
            version    INTEGER NOT NULL DEFAULT 1
        )
    """))

    # ── 2. Migrate existing JSONB data ───────────────────────────────────────
    networks = conn.execute(sa.text(
        "SELECT id, pid, nodes_json, edges_json, regions_json FROM networks"
    )).fetchall()

    for net_id, pid, nodes_raw, edges_raw, regions_raw in networks:
        nodes = _parse(nodes_raw)
        edges = _parse(edges_raw)
        regions = _parse(regions_raw)

        for n in nodes:
            nid = n.get("id")
            if not nid:
                continue
            extra = {k: v for k, v in n.items() if k not in {
                "id", "host_id", "x", "y", "label", "ip", "ips", "type", "status",
                "ports", "notes", "role", "os", "tags", "is_attacker",
                "manually_positioned", "auto_positioned", "updated_at", "version",
            }}
            conn.execute(sa.text("""
                INSERT INTO network_nodes
                    (id, network_id, pid, host_id, x, y, label, ip, ips, type,
                     status, ports, notes, role, os, tags, is_attacker,
                     manually_positioned, auto_positioned, updated_at, version, extra_json)
                VALUES
                    (:id, :nid, :pid, :host_id, :x, :y, :label, :ip, :ips, :type,
                     :status, :ports, :notes, :role, :os, :tags, :is_attacker,
                     :manually_positioned, :auto_positioned, :updated_at, :version, :extra_json)
                ON CONFLICT (id) DO NOTHING
            """), {
                "id": nid, "nid": net_id, "pid": pid,
                "host_id": n.get("host_id"),
                "x": float(n.get("x") or 0),
                "y": float(n.get("y") or 0),
                "label": n.get("label") or "",
                "ip": n.get("ip") or "",
                "ips": n.get("ips") or [],
                "type": n.get("type") or "host",
                "status": n.get("status") or "unknown",
                "ports": json.dumps(n.get("ports") or []),
                "notes": n.get("notes") or "",
                "role": n.get("role") or "",
                "os": n.get("os") or "",
                "tags": n.get("tags") or [],
                "is_attacker": bool(n.get("is_attacker")),
                "manually_positioned": bool(n.get("manually_positioned")),
                "auto_positioned": bool(n.get("auto_positioned")),
                "updated_at": n.get("updated_at") or "",
                "version": int(n.get("version") or 1),
                "extra_json": json.dumps(extra) if extra else None,
            })

        for e in edges:
            eid = e.get("id")
            if not eid:
                continue
            extra = {k: v for k, v in e.items() if k not in {
                "id", "from", "to", "from_node_id", "to_node_id", "style", "type",
                "label", "confidence", "source", "reason", "state", "verified",
                "is_manual", "manual_override", "updated_at", "version",
            }}
            conn.execute(sa.text("""
                INSERT INTO network_edges
                    (id, network_id, pid, from_node_id, to_node_id, style, type,
                     label, confidence, source, reason, state, verified,
                     is_manual, manual_override, updated_at, version, extra_json)
                VALUES
                    (:id, :nid, :pid, :from_node_id, :to_node_id, :style, :type,
                     :label, :confidence, :source, :reason, :state, :verified,
                     :is_manual, :manual_override, :updated_at, :version, :extra_json)
                ON CONFLICT (id) DO NOTHING
            """), {
                "id": eid, "nid": net_id, "pid": pid,
                "from_node_id": e.get("from") or e.get("from_node_id") or "",
                "to_node_id": e.get("to") or e.get("to_node_id") or "",
                "style": e.get("style") or "solid",
                "type": e.get("type") or "network",
                "label": e.get("label") or "",
                "confidence": int(e.get("confidence") or 100),
                "source": e.get("source") or "manual",
                "reason": e.get("reason") or "",
                "state": e.get("state") or "manual",
                "verified": bool(e.get("verified")),
                "is_manual": bool(e.get("is_manual", True)),
                "manual_override": bool(e.get("manual_override")),
                "updated_at": e.get("updated_at") or "",
                "version": int(e.get("version") or 1),
                "extra_json": json.dumps(extra) if extra else None,
            })

        for r in regions:
            rid = r.get("id")
            if not rid:
                continue
            conn.execute(sa.text("""
                INSERT INTO network_regions
                    (id, network_id, pid, x, y, w, h, label, note, fill, stroke,
                     zone_type, updated_at, version)
                VALUES
                    (:id, :nid, :pid, :x, :y, :w, :h, :label, :note, :fill, :stroke,
                     :zone_type, :updated_at, :version)
                ON CONFLICT (id) DO NOTHING
            """), {
                "id": rid, "nid": net_id, "pid": pid,
                "x": float(r.get("x") or 0),
                "y": float(r.get("y") or 0),
                "w": float(r.get("w") or 200),
                "h": float(r.get("h") or 100),
                "label": r.get("label") or "",
                "note": r.get("note") or "",
                "fill": r.get("fill") or "",
                "stroke": r.get("stroke") or "",
                "zone_type": r.get("zone_type") or "",
                "updated_at": r.get("updated_at") or "",
                "version": int(r.get("version") or 1),
            })

    # ── 3. Drop legacy JSONB columns ─────────────────────────────────────────
    for col in ("nodes_json", "edges_json", "regions_json"):
        conn.execute(sa.text(f"ALTER TABLE networks DROP COLUMN IF EXISTS {col}"))


def downgrade():
    conn = op.get_bind()
    conn.execute(sa.text("DROP TABLE IF EXISTS network_regions"))
    conn.execute(sa.text("DROP TABLE IF EXISTS network_edges"))
    conn.execute(sa.text("DROP TABLE IF EXISTS network_nodes"))
    conn.execute(sa.text("ALTER TABLE networks ADD COLUMN IF NOT EXISTS nodes_json JSONB NOT NULL DEFAULT '[]'"))
    conn.execute(sa.text("ALTER TABLE networks ADD COLUMN IF NOT EXISTS edges_json JSONB NOT NULL DEFAULT '[]'"))
    conn.execute(sa.text("ALTER TABLE networks ADD COLUMN IF NOT EXISTS regions_json JSONB NOT NULL DEFAULT '[]'"))


def _parse(val):
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except Exception:
            return []
    return []
