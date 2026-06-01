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
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.network_data import get_edges, get_nodes
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attack_graph"])

_ACCESS_EDGE_TYPES = {
    "ssh",
    "winrm",
    "smb",
    "smb_admin",
    "local_admin",
    "domain_admin",
    "shell",
    "c2_session",
    "lateral",
    "pivot",
    "auth_path",
    "ldap",
    "mssql",
    "mssql_admin",
    "rdp",
    "wmi",
    "psexec",
    "read",
    "user",
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


def _bfs_dist(adjacency: dict, root_ids) -> dict[str, int]:
    dist: dict[str, int] = dict.fromkeys(root_ids, 0)
    queue = deque(root_ids)
    while queue:
        current = queue.popleft()
        for nxt in adjacency.get(current, []):
            if nxt in dist:
                continue
            dist[nxt] = dist[current] + 1
            queue.append(nxt)
    return dist


def _reachability_walk(
    access_edges: list[dict], root_host_ids: set[str], verified_only: bool
) -> dict[str, int]:
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
    return _bfs_dist(adjacency, root_host_ids)


def _build_reachability(
    access_edges: list[dict], root_host_ids: set[str]
) -> tuple[dict[str, int], dict[str, int]]:
    return (
        _reachability_walk(access_edges, root_host_ids, False),
        _reachability_walk(access_edges, root_host_ids, True),
    )


def _build_access_adjacency(access_edges: list[dict]) -> dict[str, list[tuple[str, str]]]:
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for edge in access_edges:
        src = str(edge.get("from") or "").strip()
        dst = str(edge.get("to") or "").strip()
        if not src or not dst:
            continue
        tech = str(edge.get("access_type") or edge.get("label") or "").strip()
        adjacency.setdefault(src, []).append((dst, tech))
        if tech.lower() in _BIDIRECTIONAL_ACCESS_EDGE_TYPES:
            adjacency.setdefault(dst, []).append((src, tech))
    return adjacency


def _bfs_to_da(
    attacker_host_ids: set[str], da_id: str, adjacency: dict
) -> dict[str, str | None] | None:
    """BFS from attacker nodes; return parent map if da_id is reached, else None."""
    parent: dict[str, str | None] = dict.fromkeys(attacker_host_ids)
    queue: deque[str] = deque(attacker_host_ids)
    while queue:
        current = queue.popleft()
        if current == da_id:
            return parent
        for nxt, _ in adjacency.get(current, []):
            if nxt not in parent:
                parent[nxt] = current
                queue.append(nxt)
    return None


def _build_privilege_paths(
    access_edges: list[dict],
    attacker_host_ids: set[str],
    da_host_ids: set[str],
) -> tuple[list[list[str]], set[tuple[str, str]]]:
    """
    BFS from attacker nodes to DA-capable hosts through access edges.
    Returns (paths, path_edge_pairs) where path_edge_pairs is the set of
    (from_host_id, to_host_id) tuples forming privilege path edges.
    """
    if not attacker_host_ids or not da_host_ids:
        return [], set()

    adjacency = _build_access_adjacency(access_edges)
    paths: list[list[str]] = []
    path_edge_pairs: set[tuple[str, str]] = set()

    for da_id in da_host_ids:
        parent_map = _bfs_to_da(attacker_host_ids, da_id, adjacency)
        if parent_map is None:
            continue
        path: list[str] = []
        cur: str | None = da_id
        while cur is not None:
            path.append(cur)
            cur = parent_map.get(cur)
        path.reverse()
        paths.append(path)
        for i in range(len(path) - 1):
            path_edge_pairs.add((path[i], path[i + 1]))

    return paths, path_edge_pairs


def _collect_relay_chains(obs, target_to_obs: dict, seen: set) -> list[list[str]]:
    chains: list[list[str]] = []
    relay = obs.pivot_host_id
    dst = obs.target_host_id
    for upstream_obs in target_to_obs.get(relay, []):
        src = upstream_obs.source_host_id or upstream_obs.pivot_host_id
        if dst and src != dst and relay != dst:
            chain_key = (src, relay, dst)
            if chain_key not in seen:
                seen.add(chain_key)
                chains.append([src, relay, dst])
    return chains


def _detect_pivot_chains(pivot_observations: list) -> list[list[str]]:
    target_to_obs: dict[str, list] = {}
    for obs in pivot_observations:
        if obs.target_host_id:
            target_to_obs.setdefault(obs.target_host_id, []).append(obs)

    chains: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()

    for obs in pivot_observations:
        if obs.pivot_host_id not in target_to_obs:
            continue
        chains.extend(_collect_relay_chains(obs, target_to_obs, seen))

    return chains


def _build_host_nodes(
    hosts: list, network_node_by_host_id: dict
) -> tuple[list, set, dict, set, str]:
    nodes: list = []
    attacker_host_ids: set[str] = set()
    host_by_id: dict = {}
    dc_host_ids: set[str] = set()
    for h in hosts:
        host_by_id[h.id] = h
        net_node = network_node_by_host_id.get(h.id, {})
        if h.is_attacker:
            attacker_host_ids.add(h.id)
        if _is_dc(h):
            dc_host_ids.add(h.id)
        nodes.append({
            "id": h.id,
            "type": "attacker" if h.is_attacker else "host",
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
    if not attacker_host_ids:
        nodes.append({"id": virtual_attacker_id, "type": "attacker", "label": "Attacker",
                      "ip": "", "status": "attacker", "is_attacker": True, "tags": [], "os": ""})
    default_source = next(iter(attacker_host_ids)) if attacker_host_ids else virtual_attacker_id
    return nodes, attacker_host_ids, host_by_id, dc_host_ids, default_source


def _build_cred_edges(creds: list, host_by_id: dict, default_source: str, ctr: list) -> tuple[list, int]:
    edges: list = []
    count = 0
    for cred in creds:
        target_host_ids = cred.host_ids or []
        if not target_host_ids:
            continue
        label = f"{cred.domain}\\{cred.username}" if cred.domain else cred.username
        for target_hid in target_host_ids:
            if target_hid not in host_by_id:
                continue
            ctr[0] += 1
            edges.append({"id": f"cred_edge_{ctr[0]}", "from": default_source, "to": target_hid,
                          "label": label, "cred_id": cred.id, "cred_type": cred.type, "kind": "credential"})
            count += 1
    return edges, count


def _make_access_edge(edge: dict, from_host_id: str, to_host_id: str, ctr: list) -> tuple[dict, bool, bool]:
    """Return (edge_dict, is_da_edge, verified)."""
    ctr[0] += 1
    access_type = str(edge.get("type") or edge.get("style") or "access")
    edge_style = str(edge.get("style") or "")
    verified = bool(edge.get("verified")) or edge_style in ("exploit", "lateral")
    return (
        {
            "id": edge.get("id") or f"access_edge_{ctr[0]}",
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
        },
        access_type.lower() in _DA_EDGE_TYPES,
        verified,
    )


def _process_network_edge(
    edge: dict, network_node_by_id: dict, host_by_id: dict, da_host_ids: set, seen: set, ctr: list
) -> tuple[dict | None, bool]:
    """Return (edge_dict, verified) or (None, False) if edge should be skipped."""
    if not _is_access_edge(edge):
        return None, False
    from_node = network_node_by_id.get(str(edge.get("from") or ""), {})
    to_node = network_node_by_id.get(str(edge.get("to") or ""), {})
    from_host_id = from_node.get("host_id") or str(edge.get("from_host_id") or "")
    to_host_id = to_node.get("host_id") or str(edge.get("to_host_id") or "")
    if not from_host_id or not to_host_id:
        return None, False
    if from_host_id not in host_by_id or to_host_id not in host_by_id:
        return None, False
    dedupe_key = (from_host_id, to_host_id, str(edge.get("type") or ""), str(edge.get("source") or ""))
    if dedupe_key in seen:
        return None, False
    seen.add(dedupe_key)
    edge_dict, is_da, verified = _make_access_edge(edge, from_host_id, to_host_id, ctr)
    if is_da:
        da_host_ids.add(to_host_id)
    return edge_dict, verified


def _build_network_access_edges(
    network_edges: list, network_node_by_id: dict, host_by_id: dict, dc_host_ids: set, ctr: list
) -> tuple[list, set, int, int]:
    edges: list = []
    da_host_ids: set[str] = set(dc_host_ids)
    seen: set = set()
    access_count = verified_count = 0
    for edge in network_edges:
        edge_dict, verified = _process_network_edge(edge, network_node_by_id, host_by_id, da_host_ids, seen, ctr)
        if edge_dict is None:
            continue
        edges.append(edge_dict)
        access_count += 1
        if verified:
            verified_count += 1
    return edges, da_host_ids, access_count, verified_count


def _collect_cidr_route_edges(
    route_cidr: str, net_obj, pivot_hid: str, hosts: list,
    obs_tool: str, obs_verified: bool, seen_pairs: set, ctr: list
) -> tuple[list, int]:
    edges: list = []
    count = 0
    for h in hosts:
        if not h.ip or h.id == pivot_hid:
            continue
        try:
            if ipaddress.ip_address(h.ip) not in net_obj:
                continue
        except ValueError:
            continue
        pair = (pivot_hid, h.id)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        ctr[0] += 1
        edges.append({"id": f"pivot_route_{ctr[0]}", "from": pivot_hid, "to": h.id,
                      "label": route_cidr, "kind": "pivot_route",
                      "pivot_tool": obs_tool, "route_cidr": route_cidr,
                      "verified": obs_verified})
        count += 1
    return edges, count


def _append_pivot_src_edge(
    edges: list, seen_pairs: set, source_hid: str, pivot_hid: str,
    obs_tool: str, obs_ptype: str, obs_verified: bool, ctr: list,
) -> None:
    pair_sp = (source_hid, pivot_hid)
    if pair_sp in seen_pairs or source_hid == pivot_hid:
        return
    seen_pairs.add(pair_sp)
    ctr[0] += 1
    edges.append({
        "id": f"pivot_src_{ctr[0]}", "from": source_hid, "to": pivot_hid,
        "label": obs_tool or "pivot", "kind": "pivot",
        "pivot_tool": obs_tool, "pivot_type": obs_ptype,
        "verified": obs_verified,
    })


def _append_pivot_tgt_edge(
    edges: list, seen_pairs: set, pivot_hid: str, target_host_id: str,
    host_by_id: dict, obs_tool: str, obs_pivot_type: str, obs_verified: bool, ctr: list,
) -> None:
    if not target_host_id or target_host_id not in host_by_id:
        return
    pair = (pivot_hid, target_host_id)
    if pair in seen_pairs or target_host_id == pivot_hid:
        return
    seen_pairs.add(pair)
    ctr[0] += 1
    edges.append({
        "id": f"pivot_tgt_{ctr[0]}", "from": pivot_hid, "to": target_host_id,
        "label": "pivot target", "kind": "pivot",
        "pivot_tool": obs_tool, "pivot_type": obs_pivot_type,
        "verified": obs_verified,
    })


def _collect_pivot_obs_edges(
    obs, hosts: list, host_by_id: dict, seen_pairs: set, default_source: str, ctr: list
) -> tuple[list, int]:
    edges: list = []
    route_count = 0
    route_cidr = (obs.route_cidr or "").strip()
    pivot_hid = obs.pivot_host_id or ""
    source_hid = obs.source_host_id or default_source
    obs_tool = obs.tool or ""
    obs_ptype = obs.pivot_type or ""
    obs_verified = obs.status == "active"
    if not pivot_hid or pivot_hid not in host_by_id:
        return edges, route_count
    _append_pivot_src_edge(edges, seen_pairs, source_hid, pivot_hid, obs_tool, obs_ptype, obs_verified, ctr)
    _append_pivot_tgt_edge(edges, seen_pairs, pivot_hid, obs.target_host_id, host_by_id, obs_tool, obs_ptype, obs_verified, ctr)
    if route_cidr:
        try:
            net_obj = ipaddress.ip_network(route_cidr, strict=False)
        except ValueError:
            return edges, route_count
        route_edges, route_count = _collect_cidr_route_edges(
            route_cidr, net_obj, pivot_hid, hosts, obs_tool, obs_verified, seen_pairs, ctr
        )
        edges.extend(route_edges)
    return edges, route_count


def _build_attack_path_step_edges(attack_paths: list, db: "Session", nodes: list, ctr: list) -> tuple[list, int]:
    from .. import models as _m
    edges: list = []
    count = 0
    for path in attack_paths:
        steps = db.query(_m.AttackStep).filter(_m.AttackStep.path_id == path.id).order_by(_m.AttackStep.step_order).all()
        for i in range(len(steps) - 1):
            src_step = steps[i]
            dst_step = steps[i + 1]
            ctr[0] += 1
            edges.append({"id": f"path_edge_{ctr[0]}", "from": src_step.id, "to": dst_step.id,
                          "label": dst_step.technique or dst_step.label or "",
                          "cred_id": None, "cred_type": None, "kind": "path", "on_priv_path": False})
            count += 1
            _ensure_step_node(nodes, src_step)
            _ensure_step_node(nodes, dst_step)
    return edges, count


def _find_edge_tech(access_only: list, from_id: str, to_id: str) -> str:
    for e in access_only:
        if e.get("from") == from_id and e.get("to") == to_id:
            return e.get("access_type") or e.get("label") or ""
    return ""


def _build_privilege_path_details(
    privilege_paths: list, host_label: dict, access_only: list
) -> list:
    details = []
    for path in privilege_paths:
        steps_detail = []
        for i, hid in enumerate(path):
            label = host_label.get(hid, hid[:12])
            edge_tech = ""
            if i < len(path) - 1:
                edge_tech = _find_edge_tech(access_only, hid, path[i + 1])
            steps_detail.append({"id": hid, "label": label, "edge_to_next": edge_tech})
        details.append(steps_detail)
    return details


def _annotate_edges_priv_path(edges: list, priv_path_edge_pairs: set) -> None:
    for edge in edges:
        if edge.get("kind") not in ("access", "pivot"):
            edge["on_priv_path"] = False
            continue
        fh = str(edge.get("from") or "")
        th = str(edge.get("to") or "")
        edge["on_priv_path"] = (fh, th) in priv_path_edge_pairs or (th, fh) in priv_path_edge_pairs


def _da_path_distance(node_id: str, privilege_paths: list) -> int | None:
    for path in privilege_paths:
        for i, nid in enumerate(path):
            if nid == node_id:
                return i
    return None


def _annotate_nodes(
    nodes: list, attacker_host_ids: set, reachable_dist: dict, verified_reachable_dist: dict,
    da_host_ids: set, dc_host_ids: set, da_path_nodes: set, privilege_paths: list,
) -> None:
    for node in nodes:
        node_id = node.get("id") or ""
        node["reachability"] = {
            "is_root": node_id in attacker_host_ids,
            "reachable": reachable_dist.get(node_id) is not None,
            "reachable_via_verified_path": verified_reachable_dist.get(node_id) is not None,
            "distance": reachable_dist.get(node_id),
            "verified_distance": verified_reachable_dist.get(node_id),
        }
        node["privilege_info"] = {
            "is_da_capable": node_id in da_host_ids,
            "is_dc": node_id in dc_host_ids,
            "on_da_path": node_id in da_path_nodes,
            "da_path_distance": _da_path_distance(node_id, privilege_paths),
        }


@router.get("/api/projects/{pid}/attack-graph")
def get_attack_graph(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")

    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    attack_paths = db.query(models.AttackPath).filter(models.AttackPath.pid == pid).all()
    pivot_observations = (
        db.query(models.PivotObservation).filter(models.PivotObservation.pid == pid).all()
    )
    network = (
        db.query(models.Network)
        .filter(models.Network.pid == pid)
        .order_by(models.Network.id)
        .first()
    )
    network_nodes = get_nodes(network.id, db) if network else []
    network_edges = get_edges(network.id, db) if network else []
    network_node_by_host_id = {
        str(node.get("host_id")): node for node in network_nodes if node.get("host_id")
    }
    network_node_by_id = {str(node.get("id")): node for node in network_nodes if node.get("id")}

    nodes, attacker_host_ids, host_by_id, dc_host_ids, default_source = _build_host_nodes(
        hosts, network_node_by_host_id
    )

    ctr = [0]
    stats = {"credential_edges": 0, "access_edges": 0, "verified_access_edges": 0,
             "path_edges": 0, "pivot_route_edges": 0}

    cred_edges, stats["credential_edges"] = _build_cred_edges(creds, host_by_id, default_source, ctr)
    net_acc_edges, da_host_ids, stats["access_edges"], stats["verified_access_edges"] = (
        _build_network_access_edges(network_edges, network_node_by_id, host_by_id, dc_host_ids, ctr)
    )
    seen_pivot: set = set()
    pivot_edges_list = []
    for obs in pivot_observations:
        obs_edges, rc = _collect_pivot_obs_edges(obs, hosts, host_by_id, seen_pivot, default_source, ctr)
        pivot_edges_list.extend(obs_edges)
        stats["pivot_route_edges"] += rc

    edges = cred_edges + net_acc_edges + pivot_edges_list

    access_only = [e for e in edges if e.get("kind") == "access"]
    reachable_dist, verified_reachable_dist = _build_reachability(access_only, attacker_host_ids)
    stats["reachable_hosts"] = len([hid for hid, d in reachable_dist.items() if d > 0])
    stats["verified_reachable_hosts"] = len([hid for hid, d in verified_reachable_dist.items() if d > 0])

    privilege_paths, priv_path_edge_pairs = _build_privilege_paths(access_only, attacker_host_ids, da_host_ids)
    stats["privilege_paths"] = len(privilege_paths)
    stats["da_capable_hosts"] = len(da_host_ids)
    da_path_nodes: set[str] = {node_id for path in privilege_paths for node_id in path}

    _annotate_edges_priv_path(edges, priv_path_edge_pairs)
    _annotate_nodes(nodes, attacker_host_ids, reachable_dist, verified_reachable_dist,
                    da_host_ids, dc_host_ids, da_path_nodes, privilege_paths)

    pivot_chains = _detect_pivot_chains(pivot_observations)
    stats["pivot_chains"] = len(pivot_chains)

    path_step_edges, stats["path_edges"] = _build_attack_path_step_edges(attack_paths, db, nodes, ctr)
    edges.extend(path_step_edges)

    compromised_count = sum(1 for h in hosts if h.status in ("pwned", "owned"))
    host_label = {h.id: (h.hostname or h.ip or h.id) for h in hosts}
    privilege_path_details = _build_privilege_path_details(privilege_paths, host_label, access_only)

    return {
        "nodes": nodes,
        "edges": edges,
        "privilege_paths": privilege_paths,
        "privilege_path_details": privilege_path_details,
        "pivot_chains": pivot_chains,
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
        nodes.append(
            {
                "id": step.id,
                "type": "step",
                "label": step.label or step.technique or f"Step {step.step_order}",
                "ip": "",
                "status": "",
                "is_attacker": False,
                "tags": [],
                "os": "",
            }
        )
