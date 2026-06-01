from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast
from ..core.network_data import (
    delete_edge,
    delete_edges_by_node,
    delete_node,
    delete_region,
    get_edges,
    get_nodes,
    get_regions,
    upsert_edge,
    upsert_node,
    upsert_region,
)
from ..core.utils import new_id, ts_now
from ..database import get_db

AUTO_LINK_SUPPRESSIONS_KEY = "suppressed_auto_links"

router = APIRouter(
    prefix="/api/projects/{pid}/network", tags=["network-map"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
        409: {"description": "Conflict"},
    },
)

_MSG_NETWORK_ID_REQUIRED = "network_id is required"


def require_node_perm(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
) -> models.User:
    check_pid_access(db, pid, user, "network.manage_nodes")
    return user


def require_link_perm(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
) -> models.User:
    check_pid_access(db, pid, user, "network.manage_links")
    return user


def require_region_perm(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
) -> models.User:
    check_pid_access(db, pid, user, "network.update")
    return user


def _now() -> str:
    return ts_now()


def _get_network(pid: str, network_id: str, db: Session) -> models.Network:
    net = (
        db.query(models.Network)
        .filter(models.Network.id == network_id, models.Network.pid == pid)
        .first()
    )
    if not net:
        raise HTTPException(404, "Network not found")
    return net


def _get_host(pid: str, host_id: str | None, db: Session) -> models.Host | None:
    if not host_id:
        return None
    host = db.query(models.Host).filter(models.Host.id == host_id, models.Host.pid == pid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    return host


def _find_node(nodes: list[dict], node_id: str) -> tuple[int, dict]:
    for idx, node in enumerate(nodes):
        if node.get("id") == node_id:
            return idx, node
    raise HTTPException(404, "Node not found")


def _find_edge(edges: list[dict], edge_id: str) -> tuple[int, dict]:
    for idx, edge in enumerate(edges):
        if edge.get("id") == edge_id:
            return idx, edge
    raise HTTPException(404, "Link not found")


def _node_version(node: dict) -> int:
    return int(node.get("version") or 0) + 1


def _edge_version(edge: dict) -> int:
    return int(edge.get("version") or 0) + 1


def _region_version(region: dict) -> int:
    return int(region.get("version") or 0) + 1


def _node_ref(node: dict | None) -> str:
    if not node:
        return ""
    return str(node.get("host_id") or node.get("ip") or node.get("id") or "").strip()


def _edge_ref(from_node: dict | None, to_node: dict | None) -> str:
    left = _node_ref(from_node)
    right = _node_ref(to_node)
    if not left or not right:
        return ""
    a, b = sorted([left, right])
    return f"{a}::{b}"


def _clear_suppressed_auto_link(meta: dict, edge_ref: str):
    if not edge_ref:
        return
    suppressed = [item for item in (meta.get(AUTO_LINK_SUPPRESSIONS_KEY) or []) if item != edge_ref]
    if suppressed:
        meta[AUTO_LINK_SUPPRESSIONS_KEY] = suppressed
    else:
        meta.pop(AUTO_LINK_SUPPRESSIONS_KEY, None)


def _add_suppressed_auto_link(meta: dict, edge_ref: str):
    if not edge_ref:
        return
    suppressed = set(meta.get(AUTO_LINK_SUPPRESSIONS_KEY) or [])
    suppressed.add(edge_ref)
    meta[AUTO_LINK_SUPPRESSIONS_KEY] = sorted(suppressed)


def _sync_host_defaults(node: dict, host: models.Host | None):
    if not host:
        return node
    if not node.get("label"):
        node["label"] = host.hostname or host.ip
    if not node.get("ip"):
        node["ip"] = host.ip
    if not node.get("ips"):
        node["ips"] = host.ips or [host.ip]
    if not node.get("ports"):
        node["ports"] = host.ports or []
    if not node.get("status") or node.get("status") == "unknown":
        node["status"] = host.status
    if not node.get("notes"):
        node["notes"] = host.notes or ""
    if not node.get("role"):
        node["role"] = host.role
    if node.get("is_attacker") is None:
        node["is_attacker"] = host.is_attacker
    return node


@router.post("/nodes", dependencies=[Depends(require_node_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def create_network_node(
    pid: str,
    body: schemas.NetworkRegionCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    net = _get_network(pid, body.network_id, db)
    host = _get_host(pid, body.host_id, db)
    node = {
        "id": new_id("n"),
        "host_id": body.host_id,
        "x": body.x,
        "y": body.y,
        "label": body.label,
        "ip": body.ip,
        "ips": body.ips,
        "type": body.type,
        "status": body.status,
        "ports": body.ports,
        "notes": body.notes,
        "role": body.role,
        "os": body.os,
        "tags": body.tags or [],
        "is_attacker": body.is_attacker,
        "manually_positioned": body.manually_positioned,
        "auto_positioned": body.auto_positioned,
        "updated_at": _now(),
        "version": 1,
    }
    node = _sync_host_defaults(node, host)
    upsert_node(net.id, pid, node, db)
    db.commit()
    payload = {
        "network_id": net.id,
        "node": node,
        "updated_at": node["updated_at"],
        "actor_id": getattr(request.state, "uid", None),
        "_lid": body.client_mutation_id,
    }
    bcast(pid, "network", "node_created", payload)
    return payload


@router.patch("/nodes/{node_id}", dependencies=[Depends(require_node_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def update_network_node(
    pid: str,
    node_id: str,
    body: schemas.NetworkNodeUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, _MSG_NETWORK_ID_REQUIRED)
    net = _get_network(pid, network_id, db)
    host = _get_host(pid, body.host_id, db) if body.host_id is not None else None
    nodes = get_nodes(net.id, db)
    _idx, node = _find_node(nodes, node_id)
    updates = body.model_dump(exclude_none=True, exclude={"client_mutation_id"})
    for key, value in updates.items():
        node[key] = value
    if body.host_id is not None:
        node["host_id"] = body.host_id
    node = _sync_host_defaults(node, host)
    node["updated_at"] = _now()
    node["version"] = _node_version(node)
    upsert_node(net.id, pid, node, db)
    db.commit()
    payload = {
        "network_id": net.id,
        "node": node,
        "updated_at": node["updated_at"],
        "actor_id": getattr(request.state, "uid", None),
        "_lid": body.client_mutation_id,
    }
    bcast(pid, "network", "node_updated", payload)
    return payload


@router.patch("/nodes/{node_id}/position", dependencies=[Depends(require_node_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def update_network_node_position(
    pid: str,
    node_id: str,
    body: schemas.NetworkNodePositionUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, _MSG_NETWORK_ID_REQUIRED)
    net = _get_network(pid, network_id, db)
    nodes = get_nodes(net.id, db)
    _idx, node = _find_node(nodes, node_id)
    node["x"] = body.x
    node["y"] = body.y
    node["manually_positioned"] = body.manually_positioned
    node["auto_positioned"] = not body.manually_positioned
    node["updated_at"] = _now()
    node["version"] = _node_version(node)
    upsert_node(net.id, pid, node, db)
    db.commit()
    payload = {
        "network_id": net.id,
        "node_id": node["id"],
        "host_id": node.get("host_id"),
        "position": {"x": node["x"], "y": node["y"]},
        "manually_positioned": node.get("manually_positioned", True),
        "updated_at": node["updated_at"],
        "version": node["version"],
        "actor_id": getattr(request.state, "uid", None),
        "_lid": body.client_mutation_id,
    }
    bcast(pid, "network", "node_position_updated", payload)
    return payload


@router.delete("/nodes/{node_id}", dependencies=[Depends(require_node_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def delete_network_node(pid: str, node_id: str, request: Request, db: Annotated[Session, Depends(get_db)]):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, _MSG_NETWORK_ID_REQUIRED)
    net = _get_network(pid, network_id, db)
    nodes = get_nodes(net.id, db)
    _idx, node = _find_node(nodes, node_id)
    deleted_edge_ids = delete_edges_by_node(node_id, db)
    delete_node(node_id, db)
    db.commit()
    actor_id = getattr(request.state, "uid", None)
    bcast(
        pid,
        "network",
        "node_deleted",
        {
            "network_id": net.id,
            "node_id": node_id,
            "host_id": node.get("host_id"),
            "deleted_edge_ids": deleted_edge_ids,
            "updated_at": _now(),
            "actor_id": actor_id,
        },
    )
    for edge_id in deleted_edge_ids:
        bcast(
            pid,
            "network",
            "link_deleted",
            {
                "network_id": net.id,
                "link_id": edge_id,
                "updated_at": _now(),
                "actor_id": actor_id,
            },
        )
    return {"ok": True, "deleted_edge_ids": deleted_edge_ids}


@router.post("/links", dependencies=[Depends(require_link_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def create_network_link(
    pid: str,
    body: schemas.NetworkLinkCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    net = _get_network(pid, body.network_id, db)
    nodes = get_nodes(net.id, db)
    meta = dict(net.meta_json or {})
    node_ids = {node.get("id") for node in nodes}
    if body.from_node_id not in node_ids or body.to_node_id not in node_ids:
        raise HTTPException(400, "Both link endpoints must belong to the same project map")
    if body.from_node_id == body.to_node_id:
        raise HTTPException(400, "Self links are not allowed")
    edges = get_edges(net.id, db)
    for edge in edges:
        if edge.get("from") == body.from_node_id and edge.get("to") == body.to_node_id:
            raise HTTPException(409, "Link already exists")
    edge = {
        "id": new_id("edg"),
        "from": body.from_node_id,
        "to": body.to_node_id,
        "style": body.style,
        "type": body.type,
        "label": body.label,
        "confidence": body.confidence,
        "source": body.source or "manual",
        "reason": body.reason or "",
        "state": body.state or ("manual" if (body.source or "manual") == "manual" else "inferred"),
        "verified": bool(body.verified) if body.verified is not None else False,
        "is_manual": True,
        "updated_at": _now(),
        "version": 1,
    }
    nodes_by_id = {node.get("id"): node for node in nodes}
    _clear_suppressed_auto_link(
        meta, _edge_ref(nodes_by_id.get(body.from_node_id), nodes_by_id.get(body.to_node_id))
    )
    upsert_edge(net.id, pid, edge, db)
    net.meta_json = meta
    db.commit()
    payload = {
        "network_id": net.id,
        "link": edge,
        "updated_at": edge["updated_at"],
        "actor_id": getattr(request.state, "uid", None),
        "_lid": body.client_mutation_id,
    }
    bcast(pid, "network", "link_created", payload)
    return payload


@router.patch("/links/{link_id}", dependencies=[Depends(require_link_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def update_network_link(
    pid: str,
    link_id: str,
    body: schemas.NetworkLinkUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, _MSG_NETWORK_ID_REQUIRED)
    net = _get_network(pid, network_id, db)
    edges = get_edges(net.id, db)
    nodes = get_nodes(net.id, db)
    meta = dict(net.meta_json or {})
    node_ids = {node.get("id") for node in nodes}
    nodes_by_id = {node.get("id"): node for node in nodes}
    _idx, edge = _find_edge(edges, link_id)
    prev_edge_ref = _edge_ref(nodes_by_id.get(edge.get("from")), nodes_by_id.get(edge.get("to")))
    updates = body.model_dump(exclude_none=True, exclude={"client_mutation_id"})
    if "from_node_id" in updates:
        if updates["from_node_id"] not in node_ids:
            raise HTTPException(400, "Source node is outside this project")
        edge["from"] = updates.pop("from_node_id")
    if "to_node_id" in updates:
        if updates["to_node_id"] not in node_ids:
            raise HTTPException(400, "Target node is outside this project")
        edge["to"] = updates.pop("to_node_id")
    for key, value in updates.items():
        edge[key] = value
    if updates and edge.get("source") == "auto":
        edge["source"] = "manual"
        edge["is_manual"] = True
        edge["manual_override"] = True
    _clear_suppressed_auto_link(meta, prev_edge_ref)
    _clear_suppressed_auto_link(
        meta, _edge_ref(nodes_by_id.get(edge.get("from")), nodes_by_id.get(edge.get("to")))
    )
    edge["updated_at"] = _now()
    edge["version"] = _edge_version(edge)
    upsert_edge(net.id, pid, edge, db)
    net.meta_json = meta
    db.commit()
    payload = {
        "network_id": net.id,
        "link": edge,
        "updated_at": edge["updated_at"],
        "actor_id": getattr(request.state, "uid", None),
        "_lid": body.client_mutation_id,
    }
    bcast(pid, "network", "link_updated", payload)
    return payload


@router.delete("/links/{link_id}", dependencies=[Depends(require_link_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def delete_network_link(pid: str, link_id: str, request: Request, db: Annotated[Session, Depends(get_db)]):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, _MSG_NETWORK_ID_REQUIRED)
    net = _get_network(pid, network_id, db)
    edges = get_edges(net.id, db)
    nodes = get_nodes(net.id, db)
    meta = dict(net.meta_json or {})
    nodes_by_id = {node.get("id"): node for node in nodes}
    _idx, edge = _find_edge(edges, link_id)
    _add_suppressed_auto_link(
        meta, _edge_ref(nodes_by_id.get(edge.get("from")), nodes_by_id.get(edge.get("to")))
    )
    delete_edge(link_id, db)
    net.meta_json = meta
    db.commit()
    payload = {
        "network_id": net.id,
        "link_id": link_id,
        "updated_at": _now(),
        "actor_id": getattr(request.state, "uid", None),
    }
    bcast(pid, "network", "link_deleted", payload)
    return {"ok": True}


@router.post("/regions", dependencies=[Depends(require_region_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def create_network_region(
    pid: str,
    body: schemas.NetworkRegionCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    net = _get_network(pid, body.network_id, db)
    region = {
        "id": new_id("r"),
        "x": body.x,
        "y": body.y,
        "w": body.w,
        "h": body.h,
        "label": body.label,
        "note": body.note,
        "fill": body.fill,
        "stroke": body.stroke,
        "zone_type": body.zone_type,
        "updated_at": _now(),
        "version": 1,
    }
    upsert_region(net.id, pid, region, db)
    db.commit()
    payload = {
        "network_id": net.id,
        "region": region,
        "updated_at": region["updated_at"],
        "actor_id": getattr(request.state, "uid", None),
        "_lid": body.client_mutation_id,
    }
    bcast(pid, "network", "region_created", payload)
    return payload


@router.patch("/regions/{region_id}", dependencies=[Depends(require_region_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def update_network_region(
    pid: str,
    region_id: str,
    body: schemas.NetworkRegionUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, _MSG_NETWORK_ID_REQUIRED)
    net = _get_network(pid, network_id, db)
    regions = get_regions(net.id, db)
    idx = next((i for i, r in enumerate(regions) if r.get("id") == region_id), None)
    if idx is None:
        raise HTTPException(404, "Region not found")
    region = regions[idx]
    updates = body.model_dump(exclude_none=True, exclude={"client_mutation_id"})
    for key, value in updates.items():
        region[key] = value
    region["updated_at"] = _now()
    region["version"] = _region_version(region)
    upsert_region(net.id, pid, region, db)
    db.commit()
    payload = {
        "network_id": net.id,
        "region": region,
        "updated_at": region["updated_at"],
        "actor_id": getattr(request.state, "uid", None),
        "_lid": body.client_mutation_id,
    }
    bcast(pid, "network", "region_updated", payload)
    return payload


@router.delete("/regions/{region_id}", dependencies=[Depends(require_region_perm)], responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 409: {"description": "Conflict"}})
def delete_network_region(
    pid: str,
    region_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, _MSG_NETWORK_ID_REQUIRED)
    net = _get_network(pid, network_id, db)
    regions = get_regions(net.id, db)
    if not any(r.get("id") == region_id for r in regions):
        raise HTTPException(404, "Region not found")
    delete_region(region_id, db)
    db.commit()
    payload = {
        "network_id": net.id,
        "region_id": region_id,
        "updated_at": _now(),
        "actor_id": getattr(request.state, "uid", None),
    }
    bcast(pid, "network", "region_deleted", payload)
    return {"ok": True}
