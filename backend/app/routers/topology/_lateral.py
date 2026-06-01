from fastapi import Depends
from typing import Annotated
from sqlalchemy.orm import Session

from ... import models
from ...core.network_data import get_edges, get_nodes
from ...database import get_db

from .routes import require_topo_apply, router

_ACCESS_EDGE_TYPES = frozenset(
    {
        "ssh",
        "winrm",
        "smb_admin",
        "local_admin",
        "shell",
        "c2_session",
        "lateral",
        "pivot",
        "auth_path",
    }
)


def _find_lateral_start_node(nodes: list, from_host_id: str) -> str | None:
    for n in nodes:
        if n.get("host_id") == from_host_id or n.get("id") == from_host_id:
            return n["id"]
    return None


def _build_access_adjacency(edges: list) -> dict:
    adjacency: dict = {}
    for edge in edges:
        if edge.get("type") not in _ACCESS_EDGE_TYPES:
            continue
        src = edge.get("from")
        dst = edge.get("to")
        if not src or not dst:
            continue
        adjacency.setdefault(src, []).append({"to": dst, "edge": edge})
        if edge.get("type") in ("lateral", "pivot"):
            adjacency.setdefault(dst, []).append({"to": src, "edge": edge})
    return adjacency


def _bfs_lateral_paths(adjacency: dict, start_nid: str, node_map: dict, depth: int) -> list:
    visited = {start_nid}
    queue = [(start_nid, [])]
    paths: list = []
    seen_targets: set = set()
    while queue:
        cur, path_edges = queue.pop(0)
        if len(path_edges) >= depth:
            continue
        for hop in adjacency.get(cur, []):
            nxt = hop["to"]
            if nxt in visited:
                continue
            visited.add(nxt)
            new_path = path_edges + [hop["edge"]]
            target_node = node_map.get(nxt, {})
            target_host_id = target_node.get("host_id")
            if target_host_id and target_host_id not in seen_targets:
                seen_targets.add(target_host_id)
                paths.append({
                    "target_node_id": nxt,
                    "target_host_id": target_host_id,
                    "target_label": target_node.get("label") or target_node.get("ip") or nxt,
                    "target_role": target_node.get("role"),
                    "target_zone": target_node.get("zone_type"),
                    "distance": len(new_path),
                    "techniques": list({e.get("type") for e in new_path}),
                    "path_node_ids": [start_nid] + [e.get("to") for e in new_path],
                    "confidence": min(e.get("confidence", 0.5) for e in new_path),
                    "verified": all(e.get("verified", False) for e in new_path),
                })
            queue.append((nxt, new_path))
    return paths


@router.get("/lateral-paths", dependencies=[Depends(require_topo_apply)])
def topology_lateral_paths(
    pid: str,
    from_host_id: str,
    db: Annotated[Session, Depends(get_db)],
    depth: int = 3,
):
    depth = max(1, min(depth, 5))

    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network:
        return {"paths": [], "unreachable_count": 0}

    edges = get_edges(network.id, db)
    nodes = get_nodes(network.id, db)
    node_map = {n["id"]: n for n in nodes}

    start_nid = _find_lateral_start_node(nodes, from_host_id)
    if not start_nid:
        return {"paths": [], "unreachable_count": 0}

    adjacency = _build_access_adjacency(edges)
    paths = _bfs_lateral_paths(adjacency, start_nid, node_map, depth)
    paths.sort(key=lambda p: (p["distance"], -p["confidence"]))

    reachable = {p["target_node_id"] for p in paths} | {start_nid}
    unreachable = len([n for n in nodes if n.get("host_id") and n["id"] not in reachable])

    return {
        "from_node_id": start_nid,
        "from_host_id": from_host_id,
        "paths": paths,
        "unreachable_count": unreachable,
    }
