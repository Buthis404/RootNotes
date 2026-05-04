from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.events import bcast
from ..core.utils import new_id
from ..core.deps import get_current_user
from ..core.access import check_pid_access
from ..database import get_db


router = APIRouter(prefix="/api/projects/{pid}/network", tags=["network-map"])


def require_node_perm(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)) -> models.User:
    check_pid_access(db, pid, user, "network.manage_nodes")
    return user


def require_link_perm(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)) -> models.User:
    check_pid_access(db, pid, user, "network.manage_links")
    return user


def require_region_perm(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)) -> models.User:
    check_pid_access(db, pid, user, "network.update")
    return user


def _now() -> str:
    return datetime.utcnow().isoformat()


def _get_network(pid: str, network_id: str, db: Session) -> models.Network:
    net = db.query(models.Network).filter(models.Network.id == network_id, models.Network.pid == pid).first()
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


@router.post("/nodes", dependencies=[Depends(require_node_perm)])
def create_network_node(pid: str, body: schemas.NetworkNodeCreate, request: Request, db: Session = Depends(get_db)):
    net = _get_network(pid, body.network_id, db)
    host = _get_host(pid, body.host_id, db)
    nodes = list(net.nodes_json or [])
    edges = list(net.edges_json or [])
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
    nodes.append(node)
    net.nodes_json = nodes
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


@router.patch("/nodes/{node_id}", dependencies=[Depends(require_node_perm)])
def update_network_node(pid: str, node_id: str, body: schemas.NetworkNodeUpdate, request: Request, db: Session = Depends(get_db)):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, "network_id is required")
    net = _get_network(pid, network_id, db)
    host = _get_host(pid, body.host_id, db) if body.host_id is not None else None
    nodes = list(net.nodes_json or [])
    idx, node = _find_node(nodes, node_id)
    updates = body.model_dump(exclude_none=True, exclude={"client_mutation_id"})
    for key, value in updates.items():
        node[key] = value
    if body.host_id is not None:
        node["host_id"] = body.host_id
    node = _sync_host_defaults(node, host)
    node["updated_at"] = _now()
    node["version"] = _node_version(node)
    nodes[idx] = node
    net.nodes_json = nodes
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


@router.patch("/nodes/{node_id}/position", dependencies=[Depends(require_node_perm)])
def update_network_node_position(pid: str, node_id: str, body: schemas.NetworkNodePositionUpdate, request: Request, db: Session = Depends(get_db)):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, "network_id is required")
    net = _get_network(pid, network_id, db)
    nodes = list(net.nodes_json or [])
    idx, node = _find_node(nodes, node_id)
    node["x"] = body.x
    node["y"] = body.y
    node["manually_positioned"] = body.manually_positioned
    node["auto_positioned"] = not body.manually_positioned
    node["updated_at"] = _now()
    node["version"] = _node_version(node)
    nodes[idx] = node
    net.nodes_json = nodes
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


@router.delete("/nodes/{node_id}", dependencies=[Depends(require_node_perm)])
def delete_network_node(pid: str, node_id: str, request: Request, db: Session = Depends(get_db)):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, "network_id is required")
    net = _get_network(pid, network_id, db)
    nodes = list(net.nodes_json or [])
    edges = list(net.edges_json or [])
    _idx, node = _find_node(nodes, node_id)
    next_nodes = [item for item in nodes if item.get("id") != node_id]
    deleted_edge_ids = [edge.get("id") for edge in edges if edge.get("from") == node_id or edge.get("to") == node_id]
    next_edges = [edge for edge in edges if edge.get("id") not in deleted_edge_ids]
    net.nodes_json = next_nodes
    net.edges_json = next_edges
    db.commit()
    actor_id = getattr(request.state, "uid", None)
    bcast(pid, "network", "node_deleted", {
        "network_id": net.id,
        "node_id": node_id,
        "host_id": node.get("host_id"),
        "deleted_edge_ids": deleted_edge_ids,
        "updated_at": _now(),
        "actor_id": actor_id,
    })
    for edge_id in deleted_edge_ids:
        bcast(pid, "network", "link_deleted", {
            "network_id": net.id,
            "link_id": edge_id,
            "updated_at": _now(),
            "actor_id": actor_id,
        })
    return {"ok": True, "deleted_edge_ids": deleted_edge_ids}


@router.post("/links", dependencies=[Depends(require_link_perm)])
def create_network_link(pid: str, body: schemas.NetworkLinkCreate, request: Request, db: Session = Depends(get_db)):
    net = _get_network(pid, body.network_id, db)
    nodes = list(net.nodes_json or [])
    node_ids = {node.get("id") for node in nodes}
    if body.from_node_id not in node_ids or body.to_node_id not in node_ids:
        raise HTTPException(400, "Both link endpoints must belong to the same project map")
    if body.from_node_id == body.to_node_id:
        raise HTTPException(400, "Self links are not allowed")
    edges = list(net.edges_json or [])
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
    edges.append(edge)
    net.edges_json = edges
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


@router.patch("/links/{link_id}", dependencies=[Depends(require_link_perm)])
def update_network_link(pid: str, link_id: str, body: schemas.NetworkLinkUpdate, request: Request, db: Session = Depends(get_db)):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, "network_id is required")
    net = _get_network(pid, network_id, db)
    edges = list(net.edges_json or [])
    nodes = list(net.nodes_json or [])
    node_ids = {node.get("id") for node in nodes}
    idx, edge = _find_edge(edges, link_id)
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
    edge["updated_at"] = _now()
    edge["version"] = _edge_version(edge)
    edges[idx] = edge
    net.edges_json = edges
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


@router.delete("/links/{link_id}", dependencies=[Depends(require_link_perm)])
def delete_network_link(pid: str, link_id: str, request: Request, db: Session = Depends(get_db)):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, "network_id is required")
    net = _get_network(pid, network_id, db)
    edges = list(net.edges_json or [])
    _idx, _edge = _find_edge(edges, link_id)
    net.edges_json = [edge for edge in edges if edge.get("id") != link_id]
    db.commit()
    payload = {
        "network_id": net.id,
        "link_id": link_id,
        "updated_at": _now(),
        "actor_id": getattr(request.state, "uid", None),
    }
    bcast(pid, "network", "link_deleted", payload)
    return {"ok": True}


@router.post("/regions", dependencies=[Depends(require_region_perm)])
def create_network_region(pid: str, body: schemas.NetworkRegionCreate, request: Request, db: Session = Depends(get_db)):
    net = _get_network(pid, body.network_id, db)
    regions = list(net.regions_json or [])
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
        "updated_at": _now(),
        "version": 1,
    }
    regions.append(region)
    net.regions_json = regions
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


@router.patch("/regions/{region_id}", dependencies=[Depends(require_region_perm)])
def update_network_region(pid: str, region_id: str, body: schemas.NetworkRegionUpdate, request: Request, db: Session = Depends(get_db)):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, "network_id is required")
    net = _get_network(pid, network_id, db)
    regions = list(net.regions_json or [])
    idx = next((i for i, region in enumerate(regions) if region.get("id") == region_id), None)
    if idx is None:
        raise HTTPException(404, "Region not found")
    region = regions[idx]
    updates = body.model_dump(exclude_none=True, exclude={"client_mutation_id"})
    for key, value in updates.items():
        region[key] = value
    region["updated_at"] = _now()
    region["version"] = _region_version(region)
    regions[idx] = region
    net.regions_json = regions
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


@router.delete("/regions/{region_id}", dependencies=[Depends(require_region_perm)])
def delete_network_region(pid: str, region_id: str, request: Request, db: Session = Depends(get_db)):
    network_id = request.query_params.get("network_id")
    if not network_id:
        raise HTTPException(400, "network_id is required")
    net = _get_network(pid, network_id, db)
    regions = list(net.regions_json or [])
    if not any(region.get("id") == region_id for region in regions):
        raise HTTPException(404, "Region not found")
    net.regions_json = [region for region in regions if region.get("id") != region_id]
    db.commit()
    payload = {
        "network_id": net.id,
        "region_id": region_id,
        "updated_at": _now(),
        "actor_id": getattr(request.state, "uid", None),
    }
    bcast(pid, "network", "region_deleted", payload)
    return {"ok": True}
