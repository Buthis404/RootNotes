"""
Abstraction layer for network node/edge/region storage.

All callers use get_nodes / get_edges / get_regions / save_* helpers.
Internally data is stored in network_nodes / network_edges / network_regions
tables instead of the legacy JSONB blobs (nodes_json / edges_json / regions_json).

Dict format is kept identical to the old JSONB shape so all business logic
in routers (network_map.py, topology.py, etc.) works without changes.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .. import models
from .edge_semantics import classify_edge

# ── Columns tracked in dedicated columns (not in extra_json) ─────────────────

_NODE_COLS = {
    "id", "host_id", "x", "y", "label", "ip", "ips", "type", "status",
    "ports", "notes", "role", "os", "tags", "is_attacker",
    "manually_positioned", "auto_positioned", "updated_at", "version",
}

_EDGE_COLS = {
    "id", "from_node_id", "to_node_id", "style", "type", "label",
    "confidence", "source", "reason", "state", "verified", "is_manual",
    "manual_override", "updated_at", "version",
}

_REGION_COLS = {
    "id", "x", "y", "w", "h", "label", "note", "fill", "stroke",
    "zone_type", "updated_at", "version", "extra_json",
}


# ── Dict ↔ ORM converters ────────────────────────────────────────────────────

def _node_to_dict(n: models.NetworkNode) -> dict:
    d = {
        "id": n.id,
        "host_id": n.host_id,
        "x": n.x,
        "y": n.y,
        "label": n.label,
        "ip": n.ip,
        "ips": list(n.ips or []),
        "type": n.type,
        "status": n.status,
        "ports": list(n.ports or []),
        "notes": n.notes,
        "role": n.role,
        "os": n.os,
        "tags": list(n.tags or []),
        "is_attacker": n.is_attacker,
        "manually_positioned": n.manually_positioned,
        "auto_positioned": n.auto_positioned,
        "updated_at": n.updated_at,
        "version": n.version,
    }
    if n.extra_json:
        d.update(n.extra_json)
    return d


def _edge_to_dict(e: models.NetworkEdge) -> dict:
    d = {
        "id": e.id,
        "from": e.from_node_id,
        "to": e.to_node_id,
        "style": e.style,
        "type": e.type,
        "label": e.label,
        "confidence": e.confidence,
        "source": e.source,
        "reason": e.reason,
        "state": e.state,
        "verified": e.verified,
        "is_manual": e.is_manual,
        "manual_override": e.manual_override,
        "updated_at": e.updated_at,
        "version": e.version,
    }
    if e.extra_json:
        d.update(e.extra_json)
    # Derived route semantics (P5): transport + kind, computed at read time
    # so the classifier stays the single source of truth (no migration on
    # classifier changes). User-set values in extra_json take precedence.
    transport, kind = classify_edge(d)
    d.setdefault("transport", transport)
    d.setdefault("kind", kind)
    return d


def _region_to_dict(r: models.NetworkRegion) -> dict:
    d = {
        "id": r.id,
        "x": r.x,
        "y": r.y,
        "w": r.w,
        "h": r.h,
        "label": r.label,
        "note": r.note,
        "fill": r.fill,
        "stroke": r.stroke,
        "zone_type": r.zone_type,
        "updated_at": r.updated_at,
        "version": r.version,
    }
    if r.extra_json:
        d.update(r.extra_json)
    return d


# ── Read helpers ─────────────────────────────────────────────────────────────

def get_nodes(network_id: str, db: Session) -> list[dict]:
    rows = db.query(models.NetworkNode).filter(
        models.NetworkNode.network_id == network_id
    ).all()
    return [_node_to_dict(n) for n in rows]


def get_edges(network_id: str, db: Session) -> list[dict]:
    rows = db.query(models.NetworkEdge).filter(
        models.NetworkEdge.network_id == network_id
    ).all()
    return [_edge_to_dict(e) for e in rows]


def get_regions(network_id: str, db: Session) -> list[dict]:
    rows = db.query(models.NetworkRegion).filter(
        models.NetworkRegion.network_id == network_id
    ).all()
    return [_region_to_dict(r) for r in rows]


# ── Single-row write helpers (used by network_map.py) ────────────────────────

def upsert_node(network_id: str, pid: str, d: dict, db: Session) -> None:
    """Insert or replace a single node row from a dict."""
    extra = {k: v for k, v in d.items() if k not in _NODE_COLS and k != "network_id" and k != "pid"}
    row = db.query(models.NetworkNode).filter(models.NetworkNode.id == d["id"]).first()
    if row is None:
        row = models.NetworkNode(id=d["id"], network_id=network_id, pid=pid)
        db.add(row)
    row.host_id = d.get("host_id")
    row.x = float(d.get("x") or 0)
    row.y = float(d.get("y") or 0)
    row.label = d.get("label") or ""
    row.ip = d.get("ip") or ""
    row.ips = d.get("ips") or []
    row.type = d.get("type") or "host"
    row.status = d.get("status") or "unknown"
    row.ports = d.get("ports") or []
    row.notes = d.get("notes") or ""
    row.role = d.get("role") or ""
    row.os = d.get("os") or ""
    row.tags = d.get("tags") or []
    row.is_attacker = bool(d.get("is_attacker"))
    row.manually_positioned = bool(d.get("manually_positioned"))
    row.auto_positioned = bool(d.get("auto_positioned"))
    row.updated_at = d.get("updated_at") or ""
    row.version = int(d.get("version") or 1)
    row.extra_json = extra


_HOST_TO_NODE_FIELDS = (
    "status",
    "role",
    "os",
    "is_attacker",
    # label/ip/ports come from the host record but the network node is
    # allowed to override (e.g. operator-renamed pivot). We only touch them
    # if they currently match the previous host value — see sync_host_to_nodes.
)


def sync_host_to_nodes(host: "models.Host", db: Session, *, ts: str | None = None) -> list[dict]:
    """Push relevant fields from a Host onto every NetworkNode mirroring it.

    Returns the list of node payloads that actually changed (suitable for
    bcast `network.node_updated`). x/y/manually_positioned are never touched —
    a status update from the host must not move the node on the canvas.
    Label/ip/ports are denormalised but the operator may have overridden them
    on the map; we only refresh those fields when they look stale (empty or
    obvious mirror of the host's prior value).
    """
    if host is None:
        return []
    nodes = db.query(models.NetworkNode).filter(models.NetworkNode.host_id == host.id).all()
    if not nodes:
        return []
    updated_payloads: list[dict] = []
    for node in nodes:
        changed = False
        # Strict mirrors: always overwrite — these have no real meaning beyond
        # "what does the host look like right now".
        if node.status != (host.status or ""):
            node.status = host.status or "unknown"
            changed = True
        if node.role != (host.role or ""):
            node.role = host.role or ""
            changed = True
        if node.os != (host.os or ""):
            node.os = host.os or ""
            changed = True
        if node.is_attacker != bool(host.is_attacker):
            node.is_attacker = bool(host.is_attacker)
            changed = True
        # Soft mirrors: only update if the operator hasn't customised them.
        host_ip = host.ip or ""
        if host_ip and not node.ip:
            node.ip = host_ip
            changed = True
        host_ips = list(host.ips or []) if getattr(host, "ips", None) else ([host_ip] if host_ip else [])
        node_ips = list(node.ips or [])
        if host_ips and host_ips != node_ips and (not node_ips or all(ip in host_ips or ip == host_ip for ip in node_ips)):
            node.ips = host_ips
            changed = True
        host_ports = list(host.ports or [])
        node_ports = list(node.ports or [])
        if host_ports and host_ports != node_ports and (not node_ports or set(node_ports).issubset(set(host_ports))):
            node.ports = host_ports
            changed = True
        # label is intentionally NOT auto-synced — operators frequently
        # rename map nodes to short call-signs that should outlive hostname
        # rewrites coming from import or AD enumeration.
        if changed:
            node.version = (node.version or 0) + 1
            if ts:
                node.updated_at = ts
            payload = _node_to_dict(node)
            payload["network_id"] = node.network_id  # needed by frontend WS router
            updated_payloads.append(payload)
    return updated_payloads


def delete_node(node_id: str, db: Session) -> None:
    row = db.query(models.NetworkNode).filter(models.NetworkNode.id == node_id).first()
    if row:
        db.delete(row)
    # cascade: delete edges referencing this node
    db.query(models.NetworkEdge).filter(
        (models.NetworkEdge.from_node_id == node_id) |
        (models.NetworkEdge.to_node_id == node_id)
    ).delete(synchronize_session=False)


def upsert_edge(network_id: str, pid: str, d: dict, db: Session) -> None:
    extra = {k: v for k, v in d.items() if k not in _EDGE_COLS
             and k not in {"from", "to", "network_id", "pid"}}
    row = db.query(models.NetworkEdge).filter(models.NetworkEdge.id == d["id"]).first()
    if row is None:
        row = models.NetworkEdge(id=d["id"], network_id=network_id, pid=pid)
        db.add(row)
    row.from_node_id = d.get("from") or d.get("from_node_id") or ""
    row.to_node_id = d.get("to") or d.get("to_node_id") or ""
    row.style = d.get("style") or "solid"
    row.type = d.get("type") or "network"
    row.label = d.get("label") or ""
    raw_conf = d.get("confidence")
    row.confidence = float(raw_conf) if raw_conf is not None else 1.0
    row.source = d.get("source") or "manual"
    row.reason = d.get("reason") or ""
    row.state = d.get("state") or "manual"
    row.verified = bool(d.get("verified"))
    row.is_manual = bool(d.get("is_manual", True))
    row.manual_override = bool(d.get("manual_override"))
    row.updated_at = d.get("updated_at") or ""
    row.version = int(d.get("version") or 1)
    row.extra_json = extra


def delete_edge(edge_id: str, db: Session) -> None:
    row = db.query(models.NetworkEdge).filter(models.NetworkEdge.id == edge_id).first()
    if row:
        db.delete(row)


def delete_edges_by_node(node_id: str, db: Session) -> list[str]:
    rows = db.query(models.NetworkEdge).filter(
        (models.NetworkEdge.from_node_id == node_id) |
        (models.NetworkEdge.to_node_id == node_id)
    ).all()
    ids = [r.id for r in rows]
    for r in rows:
        db.delete(r)
    return ids


def upsert_region(network_id: str, pid: str, d: dict, db: Session) -> None:
    extra = {k: v for k, v in d.items() if k not in _REGION_COLS and k not in {"network_id", "pid"}}
    row = db.query(models.NetworkRegion).filter(models.NetworkRegion.id == d["id"]).first()
    if row is None:
        row = models.NetworkRegion(id=d["id"], network_id=network_id, pid=pid)
        db.add(row)
    row.x = float(d.get("x") or 0)
    row.y = float(d.get("y") or 0)
    row.w = float(d.get("w") or 200)
    row.h = float(d.get("h") or 100)
    row.label = d.get("label") or ""
    row.note = d.get("note") or ""
    row.fill = d.get("fill") or ""
    row.stroke = d.get("stroke") or ""
    row.zone_type = d.get("zone_type") or ""
    row.updated_at = d.get("updated_at") or ""
    row.version = int(d.get("version") or 1)
    row.extra_json = extra


def delete_region(region_id: str, db: Session) -> None:
    row = db.query(models.NetworkRegion).filter(models.NetworkRegion.id == region_id).first()
    if row:
        db.delete(row)


# ── Bulk write helpers (used by topology/bulk_actions/etc.) ──────────────────

def replace_nodes(network_id: str, pid: str, nodes: list[dict], db: Session) -> None:
    """Delete all nodes for this network and insert from list."""
    db.query(models.NetworkNode).filter(
        models.NetworkNode.network_id == network_id
    ).delete(synchronize_session=False)
    for d in nodes:
        upsert_node(network_id, pid, d, db)


def replace_edges(network_id: str, pid: str, edges: list[dict], db: Session) -> None:
    """Delete all edges for this network and insert from list."""
    db.query(models.NetworkEdge).filter(
        models.NetworkEdge.network_id == network_id
    ).delete(synchronize_session=False)
    for d in edges:
        upsert_edge(network_id, pid, d, db)


def replace_regions(network_id: str, pid: str, regions: list[dict], db: Session) -> None:
    db.query(models.NetworkRegion).filter(
        models.NetworkRegion.network_id == network_id
    ).delete(synchronize_session=False)
    for d in regions:
        upsert_region(network_id, pid, d, db)
