import ipaddress
import logging
from copy import deepcopy

from fastapi import Depends, HTTPException, Request
from typing import Annotated
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ... import models, schemas
from ...core.events import bcast
from ...core.job_tracker import finish_job, start_job
from ...core.layout import compute_layout
from ...core.network_data import get_edges, get_nodes, replace_edges, replace_nodes
from ...core.utils import new_id, stable_edge_id, ts_now
from ...database import get_db

from ._infer import _get_subnet, infer_links_smart
from .routes import (
    AUTO_LINK_SUPPRESSIONS_KEY,
    _edge_ref,
    _MSG_NO_NETWORK_MAP,
    _MSG_PROJECT_NOT_FOUND,
    require_topo_apply,
    router,
)

logger = logging.getLogger(__name__)


def _node_type_for(host: dict) -> str:
    if host.get("is_attacker") or (host.get("role") or "").lower() == "attacker":
        return "attacker"
    dtype = (host.get("device_type") or "").lower()
    if dtype in ("router", "firewall", "switch"):
        return dtype
    tags = {t.lower() for t in (host.get("tags") or [])}
    if tags & {"router", "firewall", "fw", "gateway"}:
        return "router"
    os_low = (host.get("os") or "").lower()
    if any(kw in os_low for kw in ("cisco", "juniper", "pfsense", "fortinet", "vyos")):
        return "router"
    if "windows" in os_low and "server" not in os_low:
        return "workstation"
    return "server"


class AutoBuildRequest(BaseModel):
    keep_manual_positions: bool = True
    create_missing_networks: bool = True


def _annotate_ip_subnet(ip: str, scope_cidrs: list) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        matching = [n for n in scope_cidrs if addr in n]
        if matching:
            return str(max(matching, key=lambda n: n.prefixlen))
    except ValueError:
        pass
    return _get_subnet(ip)


def _load_scope_cidrs(db, pid: str) -> list:
    scope_cidrs: list = []
    try:
        scopes = db.query(models.Scope).filter(models.Scope.pid == pid).all()
        for s in scopes:
            val = (s.value or "").strip()
            if "/" in val:
                try:
                    scope_cidrs.append(ipaddress.ip_network(val, strict=False))
                except ValueError:
                    pass
    except Exception as e:
        logger.debug("loading scope CIDRs failed (pid=%s): %s", pid, e)
    return scope_cidrs


def _auto_build_upsert_nodes(
    positioned: list, node_by_hid: dict, node_by_ip: dict,
    existing_nodes: list, keep_manual_positions: bool,
) -> tuple[int, int]:
    nodes_added = 0
    nodes_repositioned = 0
    for p in positioned:
        h_id = p.get("id", "")
        h_ip = p.get("ip", "")
        existing = node_by_hid.get(h_id) or node_by_ip.get(h_ip)
        if existing:
            if not (existing.get("manually_positioned") and keep_manual_positions):
                existing["x"] = p["x"]
                existing["y"] = p["y"]
                existing["auto_positioned"] = True
                existing["manually_positioned"] = False
                nodes_repositioned += 1
        else:
            new_node = {
                "id": new_id("nd"),
                "host_id": h_id,
                "label": p.get("hostname") or h_ip,
                "ip": h_ip,
                "ips": [],
                "ports": p.get("ports", []),
                "services": p.get("services", []),
                "subnet": p.get("subnet") or _get_subnet(h_ip),
                "status": p.get("status", "unknown"),
                "role": "attacker" if p.get("is_attacker") else p.get("role", "unknown"),
                "type": _node_type_for(p),
                "notes": "",
                "is_attacker": bool(p.get("is_attacker")),
                "x": p["x"],
                "y": p["y"],
                "manually_positioned": False,
                "auto_positioned": True,
            }
            existing_nodes.append(new_node)
            node_by_hid[h_id] = new_node
            node_by_ip[h_ip] = new_node
            nodes_added += 1
    return nodes_added, nodes_repositioned


def _filter_new_auto_edges(
    inferred_links: list,
    ip_to_node_id: dict,
    node_by_id: dict,
    suppressed_auto_links: set,
    manual_edge_keys: set,
) -> list:
    new_auto_edges = []
    seen = set(manual_edge_keys)
    for link in inferred_links:
        src_nid = ip_to_node_id.get(link.source_ip)
        dst_nid = ip_to_node_id.get(link.target_ip)
        if not src_nid or not dst_nid:
            continue
        edge_ref = _edge_ref(node_by_id.get(src_nid), node_by_id.get(dst_nid))
        if edge_ref and edge_ref in suppressed_auto_links:
            continue
        key = (src_nid, dst_nid)
        if key in seen or (dst_nid, src_nid) in seen:
            continue
        seen.add(key)
        seen.add((dst_nid, src_nid))
        new_auto_edges.append({
            "id": stable_edge_id(src_nid, dst_nid, link.source or "auto", link.link_type or ""),
            "from": src_nid,
            "to": dst_nid,
            "type": link.link_type,
            "confidence": link.confidence,
            "source": link.source,
            "reason": link.reason,
            "state": "inferred",
            "verified": False,
        })
    return new_auto_edges


def _run_auto_build(
    pid: str, db: Session, keep_manual_positions: bool = True, create_missing_networks: bool = True
) -> dict:
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        return {"ok": False, "error": _MSG_PROJECT_NOT_FOUND}

    all_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    if not all_hosts:
        return {"ok": True, "nodes_total": 0, "nodes_added": 0, "repositioned": 0}

    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network:
        if not create_missing_networks:
            return {"ok": False, "error": _MSG_NO_NETWORK_MAP}
        network = models.Network(
            id=new_id("net"), pid=pid, name="Network", background="#07080b", meta_json={}
        )
        db.add(network)
        db.flush()

    existing_nodes: list = get_nodes(network.id, db)
    existing_edges: list = get_edges(network.id, db)
    existing_meta: dict = deepcopy(network.meta_json or {})

    scope_cidrs = _load_scope_cidrs(db, pid)
    hosts_for_layout = [
        {
            "id": h.id, "ip": h.ip, "hostname": h.hostname, "os": h.os,
            "status": h.status, "role": h.role, "is_attacker": h.is_attacker,
            "ports": h.ports or [], "services": h.services or [], "tags": h.tags or [],
            "subnet": _annotate_ip_subnet(h.ip or "", scope_cidrs),
        }
        for h in all_hosts
    ]

    positioned = compute_layout(hosts_for_layout, existing_nodes, keep_manual_positions, existing_edges)

    node_by_hid: dict = {n.get("host_id"): n for n in existing_nodes if n.get("host_id")}
    node_by_ip: dict = {n.get("ip"): n for n in existing_nodes if n.get("ip")}
    nodes_added, nodes_repositioned = _auto_build_upsert_nodes(
        positioned, node_by_hid, node_by_ip, existing_nodes, keep_manual_positions
    )

    inferred_links = infer_links_smart(hosts_for_layout)
    ip_to_node_id = {n.get("ip"): n.get("id") for n in existing_nodes if n.get("ip")}
    node_by_id = {n.get("id"): n for n in existing_nodes if n.get("id")}
    suppressed_auto_links = set(existing_meta.get(AUTO_LINK_SUPPRESSIONS_KEY) or [])
    manual_edges = [
        e for e in existing_edges
        if e.get("source") != "auto" or e.get("manual_override") or e.get("verified")
    ]
    manual_edge_keys: set = {(e.get("from"), e.get("to")) for e in manual_edges} | {
        (e.get("to"), e.get("from")) for e in manual_edges
    }
    new_auto_edges = _filter_new_auto_edges(
        inferred_links, ip_to_node_id, node_by_id, suppressed_auto_links, manual_edge_keys
    )

    replace_nodes(network.id, network.pid, existing_nodes, db)
    replace_edges(network.id, network.pid, manual_edges + new_auto_edges, db)
    network.meta_json = existing_meta
    db.commit()

    bcast(
        pid, "network", "layout_applied",
        {"network": schemas.Network.from_orm_obj(network).model_dump(), "updated_at": ts_now()}
    )
    return {
        "ok": True,
        "nodes_total": len(existing_nodes),
        "nodes_added": nodes_added,
        "repositioned": nodes_repositioned,
        "links_added": len(new_auto_edges),
    }


@router.post("/auto-build", dependencies=[Depends(require_topo_apply)], responses={404: {"description": "Not found"}})
def topology_auto_build(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    body: AutoBuildRequest = AutoBuildRequest(),
    request: Request = None,
):
    username = getattr(getattr(request, "state", None), "username", None) if request else None
    job = start_job(
        db,
        pid,
        "topology",
        "Topology auto-build",
        created_by=username or "",
        connector_key="topology",
        operation="auto_build",
        related_entity=("network", pid),
        request_json=body.model_dump(),
    )
    result = _run_auto_build(pid, db, body.keep_manual_positions, body.create_missing_networks)
    if not result.get("ok") and result.get("error") == _MSG_PROJECT_NOT_FOUND:
        finish_job(db, job, status="failed", error_output=_MSG_PROJECT_NOT_FOUND)
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
    if not result.get("ok") and result.get("error") == _MSG_NO_NETWORK_MAP:
        finish_job(db, job, status="failed", error_output=_MSG_NO_NETWORK_MAP)
        raise HTTPException(404, _MSG_NO_NETWORK_MAP)
    finish_job(db, job, status="done", result=result)
    return {**result, "job_id": job.id}
