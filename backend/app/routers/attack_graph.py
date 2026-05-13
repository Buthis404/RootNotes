"""
Attack graph endpoint.

GET /api/projects/{pid}/attack-graph
Returns nodes and edges for visualization.

The graph combines credential links, persisted access edges from the network graph,
analyst-defined attack-path steps, privilege escalation paths, and pivot route edges.
"""
import ipaddress
import logging
from collections import deque
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..core.deps import get_current_user
from ..core.access import check_pid_access

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attack_graph"])

_ACCESS_EDGE_TYPES = {
    "ssh", "winrm", "smb", "smb_admin", "local_admin", "domain_admin",
    "shell", "c2_session", "lateral", "pivot", "auth_path", "ldap",
    "mssql", "mssql_admin", "rdp", "wmi", "psexec", "read", "user",
}

_ACCESS_EDGE_SOURCES = {"cred_validation", "bulk_exec", "host_activity"}
_BIDIRECTIONAL_ACCESS_EDGE_TYPES = {"lateral", "pivot"}
_ACCESS_EDGE_STYLES = {"exploit", "lateral", "tunnel"}

_DA_EDGE_TYPES = {"domain_admin", "da", "krb_ticket_da"}
_HIGH_PRIV_EDGE_TYPES = {"local_admin", "smb_admin", "domain_admin", "da", "psexec", "wmi"}


def _is_access_edge(edge: dict) -> bool:
    edge_type = str(edge.get("type") or "").strip().lower()
    edge_source = str(edge.get("source") or "").strip().lower()
    edge_style = str(edge.get("style") or "").strip().lower()
    return (
        edge_type in _ACCESS_EDGE_TYPES
        or edge_source in _ACCESS_EDGE_SOURCES
        or edge_style in _ACCESS_EDGE_STYLES
    )


def _is_dc(host: models.Host) -> bool:
    role = (host.role or "").lower()
    if role in ("domain_controller", "dc"):
        return True
    if "dc" in {t.lower() for t in (host.tags or [])}:
        return True
    ports = set(host.ports or [])
    return "88/tcp" in ports and "389/tcp" in ports


def _build_reachability(access_edges: list[dict], root_host_ids: set[str]) -> tuple[dict[str, int], dict[str, int]]:
    def walk(verified_only: bool) -> dict[str, int]:
        adjacency: dict[str, list[str]] = {}
        for edge in access_edges:
            if verified_only and not edge.get("verified"):
                continue
            src = str(edge.get("from") or "").strip()
            dst = str(edge.get("to") or "").strip()
            if not src or not dst:
                continue
            adjacency.setdefault(src, []).append(dst)
            if str(edge.get("access_type") or "").strip().lower() in _BIDIRECTIONAL_ACCESS_EDGE_TYPES:
                adjacency.setdefault(dst, []).append(src)

        dist: dict[str, int] = {host_id: 0 for host_id in root_host_ids}
        queue = deque(root_host_ids)
        while queue:
            current = queue.popleft()
            for nxt in adjacency.get(current, []):
                if nxt in dist:
                    continue
                dist[nxt] = dist[current] + 1
                queue.append(nxt)
        return dist

    return walk(False), walk(True)


def _build_privilege_paths(
    access_edges: list[dict],
    attacker_host_ids: set[str],
    da_host_ids: set[str],
) -> list[list[str]]:
    """
    BFS from attacker nodes to DA-capable hosts through access edges.
    Returns shortest privilege path for each reachable DA host.
    """
    if not attacker_host_ids or not da_host_ids:
        return []

    adjacency: dict[str, list[str]] = {}
    for edge in access_edges:
        src = str(edge.get("from") or "").strip()
        dst = str(edge.get("to") or "").strip()
        if not src or not dst:
            continue
        adjacency.setdefault(src, []).append(dst)
        if str(edge.get("access_type") or "").lower() in _BIDIRECTIONAL_ACCESS_EDGE_TYPES:
            adjacency.setdefault(dst, []).append(src)

    paths: list[list[str]] = []
    for da_id in da_host_ids:
        parent: dict[str, str | None] = {hid: None for hid in attacker_host_ids}
        queue: deque[str] = deque(attacker_host_ids)
        found = False
        while queue and not found:
            current = queue.popleft()
            if current == da_id:
                found = True
                break
            for nxt in adjacency.get(current, []):
                if nxt not in parent:
                    parent[nxt] = current
                    queue.append(nxt)
        if found:
            path: list[str] = []
            cur: str | None = da_id
            while cur is not None:
                path.append(cur)
                cur = parent.get(cur)
            path.reverse()
            paths.append(path)

    return paths


@router.get("/api/projects/{pid}/attack-graph")
def get_attack_graph(
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "findings.read")

    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    attack_paths = db.query(models.AttackPath).filter(models.AttackPath.pid == pid).all()
    pivot_observations = db.query(models.PivotObservation).filter(models.PivotObservation.pid == pid).all()
    network = db.query(models.Network).filter(models.Network.pid == pid).order_by(models.Network.id).first()
    network_nodes = list(network.nodes_json or []) if network else []
    network_edges = list(network.edges_json or []) if network else []
    network_node_by_host_id = {
        str(node.get("host_id")): node
        for node in network_nodes
        if node.get("host_id")
    }
    network_node_by_id = {
        str(node.get("id")): node
        for node in network_nodes
        if node.get("id")
    }

    # Build nodes
    nodes = []
    attacker_host_ids: set[str] = set()
    host_by_id: dict[str, models.Host] = {}
    dc_host_ids: set[str] = set()

    for h in hosts:
        host_by_id[h.id] = h
        node_type = "attacker" if h.is_attacker else "host"
        net_node = network_node_by_host_id.get(h.id, {})
        if h.is_attacker:
            attacker_host_ids.add(h.id)
        if _is_dc(h):
            dc_host_ids.add(h.id)
        nodes.append({
            "id": h.id,
            "type": node_type,
            "label": h.hostname or h.ip,
            "ip": h.ip,
            "status": h.status,
            "is_attacker": h.is_attacker,
            "tags": h.tags or [],
            "os": h.os,
            "ports": h.ports or [],
            "role": h.role,
            "zone_type": net_node.get("zone_type") or "",
            "network_node_id": net_node.get("id") or None,
        })

    virtual_attacker_id = "attacker_virtual"
    has_attacker_node = bool(attacker_host_ids)
    if not has_attacker_node:
        nodes.append({
            "id": virtual_attacker_id,
            "type": "attacker",
            "label": "Attacker",
            "ip": "",
            "status": "attacker",
            "is_attacker": True,
            "tags": [],
            "os": "",
        })

    default_source = next(iter(attacker_host_ids)) if attacker_host_ids else virtual_attacker_id

    # Build edges
    edges = []
    edge_id_counter = 0
    stats = {
        "credential_edges": 0,
        "access_edges": 0,
        "verified_access_edges": 0,
        "path_edges": 0,
        "pivot_route_edges": 0,
    }

    for cred in creds:
        target_host_ids = cred.host_ids or []
        if not target_host_ids:
            continue
        label = cred.username
        if cred.domain:
            label = f"{cred.domain}\\{cred.username}"
        for target_hid in target_host_ids:
            if target_hid not in host_by_id:
                continue
            edge_id_counter += 1
            edges.append({
                "id": f"cred_edge_{edge_id_counter}",
                "from": default_source,
                "to": target_hid,
                "label": label,
                "cred_id": cred.id,
                "cred_type": cred.type,
                "kind": "credential",
            })
            stats["credential_edges"] += 1

    # Access edges from network graph
    da_host_ids: set[str] = set(dc_host_ids)
    seen_access_edges: set = set()
    for edge in network_edges:
        if not _is_access_edge(edge):
            continue
        from_node = network_node_by_id.get(str(edge.get("from") or ""), {})
        to_node = network_node_by_id.get(str(edge.get("to") or ""), {})
        from_host_id = from_node.get("host_id")
        to_host_id = to_node.get("host_id")
        if not from_host_id or not to_host_id:
            continue
        if from_host_id not in host_by_id or to_host_id not in host_by_id:
            continue
        dedupe_key = (from_host_id, to_host_id, str(edge.get("type") or ""), str(edge.get("source") or ""))
        if dedupe_key in seen_access_edges:
            continue
        seen_access_edges.add(dedupe_key)
        edge_id_counter += 1
        access_type = str(edge.get("type") or edge.get("style") or "access")
        verified = bool(edge.get("verified")) or str(edge.get("style") or "") in ("exploit", "lateral")
        edges.append({
            "id": edge.get("id") or f"access_edge_{edge_id_counter}",
            "from": from_host_id,
            "to": to_host_id,
            "label": str(edge.get("label") or access_type.replace("_", " ")).strip(),
            "kind": "access",
            "access_type": access_type,
            "verified": verified,
            "confidence": edge.get("confidence"),
            "state": edge.get("state") or "",
            "source": edge.get("source") or "",
            "reason": edge.get("reason") or "",
        })
        stats["access_edges"] += 1
        if verified:
            stats["verified_access_edges"] += 1
        # Track DA-capable hosts: any node that an attacker reaches with domain_admin
        if access_type.lower() in _DA_EDGE_TYPES:
            da_host_ids.add(to_host_id)

    # Pivot route edges — hosts reachable via pivot route CIDRs
    seen_pivot_route_pairs: set = set()
    for obs in pivot_observations:
        route_cidr = (obs.route_cidr or "").strip()
        pivot_hid = obs.pivot_host_id or ""
        source_hid = obs.source_host_id or default_source
        if not pivot_hid or pivot_hid not in host_by_id:
            continue

        # Edge: source → pivot host (if not already in access edges)
        pair_sp = (source_hid, pivot_hid)
        if pair_sp not in seen_pivot_route_pairs and source_hid != pivot_hid:
            seen_pivot_route_pairs.add(pair_sp)
            edge_id_counter += 1
            edges.append({
                "id": f"pivot_src_{edge_id_counter}",
                "from": source_hid,
                "to": pivot_hid,
                "label": obs.tool or "pivot",
                "kind": "pivot",
                "pivot_tool": obs.tool or "",
                "pivot_type": obs.pivot_type or "",
                "verified": obs.status == "active",
            })

        # Explicit target host
        if obs.target_host_id and obs.target_host_id in host_by_id:
            pair = (pivot_hid, obs.target_host_id)
            if pair not in seen_pivot_route_pairs and obs.target_host_id != pivot_hid:
                seen_pivot_route_pairs.add(pair)
                edge_id_counter += 1
                edges.append({
                    "id": f"pivot_tgt_{edge_id_counter}",
                    "from": pivot_hid,
                    "to": obs.target_host_id,
                    "label": "pivot target",
                    "kind": "pivot",
                    "pivot_tool": obs.tool or "",
                    "pivot_type": obs.pivot_type or "",
                    "verified": obs.status == "active",
                })

        if not route_cidr:
            continue
        try:
            net_obj = ipaddress.ip_network(route_cidr, strict=False)
        except ValueError:
            continue
        for h in hosts:
            if not h.ip or h.id == pivot_hid:
                continue
            try:
                if ipaddress.ip_address(h.ip) not in net_obj:
                    continue
            except ValueError:
                continue
            pair = (pivot_hid, h.id)
            if pair in seen_pivot_route_pairs:
                continue
            seen_pivot_route_pairs.add(pair)
            edge_id_counter += 1
            edges.append({
                "id": f"pivot_route_{edge_id_counter}",
                "from": pivot_hid,
                "to": h.id,
                "label": route_cidr,
                "kind": "pivot_route",
                "pivot_tool": obs.tool or "",
                "route_cidr": route_cidr,
                "verified": obs.status == "active",
            })
            stats["pivot_route_edges"] += 1

    # Reachability BFS
    access_only = [e for e in edges if e.get("kind") == "access"]
    reachable_dist, verified_reachable_dist = _build_reachability(access_only, attacker_host_ids)
    stats["reachable_hosts"] = len([hid for hid, d in reachable_dist.items() if d > 0])
    stats["verified_reachable_hosts"] = len([hid for hid, d in verified_reachable_dist.items() if d > 0])

    # Privilege path analysis
    privilege_paths = _build_privilege_paths(access_only, attacker_host_ids, da_host_ids)
    stats["privilege_paths"] = len(privilege_paths)
    stats["da_capable_hosts"] = len(da_host_ids)

    da_path_nodes: set[str] = set()
    for path in privilege_paths:
        for node_id in path:
            da_path_nodes.add(node_id)

    for node in nodes:
        node_id = node.get("id") or ""
        any_distance = reachable_dist.get(node_id)
        verified_distance = verified_reachable_dist.get(node_id)
        node["reachability"] = {
            "is_root": node_id in attacker_host_ids,
            "reachable": any_distance is not None,
            "reachable_via_verified_path": verified_distance is not None,
            "distance": any_distance,
            "verified_distance": verified_distance,
        }
        node["privilege_info"] = {
            "is_da_capable": node_id in da_host_ids,
            "is_dc": node_id in dc_host_ids,
            "on_da_path": node_id in da_path_nodes,
            "da_path_distance": next(
                (i for path in privilege_paths for i, pid in enumerate(path) if pid == node_id),
                None,
            ),
        }

    # Attack path step edges
    for path in attack_paths:
        steps = db.query(models.AttackStep).filter(
            models.AttackStep.path_id == path.id
        ).order_by(models.AttackStep.step_order).all()
        for i in range(len(steps) - 1):
            src_step = steps[i]
            dst_step = steps[i + 1]
            edge_id_counter += 1
            edges.append({
                "id": f"path_edge_{edge_id_counter}",
                "from": src_step.id,
                "to": dst_step.id,
                "label": dst_step.technique or dst_step.label or "",
                "cred_id": None,
                "cred_type": None,
                "kind": "path",
            })
            stats["path_edges"] += 1
            _ensure_step_node(nodes, src_step)
            _ensure_step_node(nodes, dst_step)

    compromised_count = sum(1 for h in hosts if h.status in ("pwned", "owned"))

    return {
        "nodes": nodes,
        "edges": edges,
        "privilege_paths": privilege_paths,
        "stats": {
            "hosts": len(hosts),
            "edges": len(edges),
            "compromised": compromised_count,
            **stats,
        },
    }


def _ensure_step_node(nodes: list, step: models.AttackStep):
    existing_ids = {n["id"] for n in nodes}
    if step.id not in existing_ids:
        nodes.append({
            "id": step.id,
            "type": "step",
            "label": step.label or step.technique or f"Step {step.step_order}",
            "ip": "",
            "status": "",
            "is_attacker": False,
            "tags": [],
            "os": "",
        })
