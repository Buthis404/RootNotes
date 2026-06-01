import logging
import xml.etree.ElementTree as ET
from copy import deepcopy

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from typing import Annotated
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ... import models, schemas
from ...core.access import check_pid_access
from ...core.deps import get_current_user
from ...core.events import bcast, log_event
from ...core.job_tracker import finish_job, start_job
from ...core.layout import compute_layout
from ...core.network_data import (
    get_edges,
    get_nodes,
    replace_edges,
    replace_nodes,
)
from ...core.utils import new_id, normalize_domain, stable_edge_id, ts_now
from ...database import get_db
from ...plugins.registry import registry

from ._infer import TopologyLinkDiff, _get_subnet, infer_links, infer_links_smart

_log = logging.getLogger("app.topology")

AUTO_LINK_SUPPRESSIONS_KEY = "suppressed_auto_links"


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


router = APIRouter(
    prefix="/api/projects/{pid}/topology", tags=["topology"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
    },
)

_MSG_PROJECT_NOT_FOUND = "Project not found"
_MSG_NO_NETWORK_MAP = "No network map found"


def _require_topology_module_enabled():
    module = registry.get("topology")
    if not module or not module.enabled:
        raise HTTPException(404, "Topology module is disabled")


def require_topo_read(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
) -> models.User:
    _require_topology_module_enabled()
    check_pid_access(db, pid, user, "topology.read")
    return user


def require_topo_preview(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
) -> models.User:
    _require_topology_module_enabled()
    check_pid_access(db, pid, user, "topology.preview")
    return user


def require_topo_apply(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
) -> models.User:
    _require_topology_module_enabled()
    check_pid_access(db, pid, user, "topology.apply")
    return user


class TopologyOptions(BaseModel):
    keep_manual_positions: bool = True
    create_missing_networks: bool = True
    create_links: bool = True
    update_existing_hosts: bool = True
    confidence_threshold: float = 0.5
    source_type: str = "nmap"


class TopologyHostDiff(BaseModel):
    ip: str
    hostname: str = ""
    os: str = ""
    ports: list[str] = []
    services: list[str] = []
    tags: list[str] = []
    status: str = "alive"
    domain: str = ""
    is_new: bool = True
    existing_id: str | None = None
    changes: dict = {}


class TopologyPreview(BaseModel):
    new_hosts: list[TopologyHostDiff] = []
    updated_hosts: list[TopologyHostDiff] = []
    new_links: list[TopologyLinkDiff] = []
    conflicts: list[dict] = []
    scan_source: str = ""
    host_count: int = 0
    network_count: int = 0
    summary: str = ""


class ApplyRequest(BaseModel):
    preview: TopologyPreview
    options: TopologyOptions = TopologyOptions()


class RebuildLayoutRequest(BaseModel):
    keep_manual_positions: bool = True


def _parse_nmap_ports(host_el) -> tuple[list[str], list[str]]:
    ports: list[str] = []
    services: list[str] = []
    for port_el in host_el.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        proto = port_el.get("protocol", "tcp")
        portid = port_el.get("portid", "")
        ports.append(f"{portid}/{proto}")
        svc_el = port_el.find("service")
        if svc_el is not None:
            svc_name = svc_el.get("name", "")
            svc_product = svc_el.get("product", "")
            svc_str = f"{svc_name} ({svc_product})" if svc_product else svc_name
            if svc_str:
                services.append(svc_str)
    return ports, services


def _parse_nmap_hostname(host_el) -> str:
    for hn in host_el.findall(".//hostname"):
        if hn.get("type") in ("PTR", "user", ""):
            return hn.get("name", "")
    return ""


def _parse_nmap_os(os_el) -> str:
    if os_el is None:
        return ""
    matches = os_el.findall("osmatch")
    return matches[0].get("name", "") if matches else ""


def _parse_nmap_host_el(host_el) -> dict | None:
    status_el = host_el.find("status")
    if status_el is None or status_el.get("state") != "up":
        return None
    ip = ""
    for addr in host_el.findall("address"):
        if addr.get("addrtype") == "ipv4":
            ip = addr.get("addr", "")
    if not ip:
        return None
    hostname = _parse_nmap_hostname(host_el)
    os_name = _parse_nmap_os(host_el.find("os"))
    ports, services = _parse_nmap_ports(host_el)
    return {
        "ip": ip,
        "hostname": hostname,
        "os": os_name or "Unknown",
        "ports": ports,
        "services": services,
        "tags": [],
        "status": "alive",
        "domain": (
            normalize_domain(hostname.split(".", 1)[1])
            if hostname and hostname.count(".") >= 1
            else ""
        ),
    }


def parse_nmap_xml(xml_content: str) -> list[dict]:
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        raise HTTPException(400, f"Invalid Nmap XML: {e}")
    return [h for host_el in root.findall("host") if (h := _parse_nmap_host_el(host_el))]


@router.get("/sources", dependencies=[Depends(require_topo_read)])
def get_topology_sources():
    return {
        "sources": [
            {
                "id": "nmap",
                "name": "Nmap XML",
                "description": "Nmap scan output in XML format (-oX)",
                "file_types": [".xml"],
            },
            {"id": "manual", "name": "Manual", "description": "Manually specified host list"},
        ]
    }


@router.get("", dependencies=[Depends(require_topo_read)], responses={404: {"description": "Not found"}})
def get_topology(pid: str, db: Annotated[Session, Depends(get_db)]):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)

    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    networks = db.query(models.Network).filter(models.Network.pid == pid).all()

    total_nodes = sum(len(get_nodes(n.id, db)) for n in networks)
    total_edges = sum(len(get_edges(n.id, db)) for n in networks)

    return {
        "project_id": pid,
        "host_count": len(hosts),
        "network_count": len(networks),
        "node_count": total_nodes,
        "edge_count": total_edges,
    }


def _compute_host_changes(ph: dict, existing) -> dict:
    changes: dict = {}
    if ph.get("hostname") and not existing.hostname:
        changes["hostname"] = ph["hostname"]
    if ph.get("os") and ph["os"] != "Unknown" and (not existing.os or existing.os == "Unknown"):
        changes["os"] = ph["os"]
    new_ports = list(set(ph.get("ports", [])) - set(existing.ports or []))
    if new_ports:
        changes["ports_added"] = new_ports
    new_services = list(set(ph.get("services", [])) - set(existing.services or []))
    if new_services:
        changes["services_added"] = new_services
    return changes


def _ph_to_diff_kwargs(ph: dict, ip: str) -> dict:
    return {
        "ip": ip,
        "hostname": ph.get("hostname", ""),
        "os": ph.get("os", ""),
        "ports": ph.get("ports", []),
        "services": ph.get("services", []),
        "tags": ph.get("tags", []),
        "status": ph.get("status", "alive"),
        "domain": ph.get("domain", ""),
    }


def _compute_host_diffs(
    parsed_hosts: list, by_ip: dict, by_hostname: dict, update_existing_hosts: bool
) -> tuple[list, list, list]:
    new_hosts: list = []
    updated_hosts: list = []
    for ph in parsed_hosts:
        ip = ph.get("ip", "")
        hn = (ph.get("hostname") or "").lower()
        existing = by_ip.get(ip) or (by_hostname.get(hn) if hn else None)
        kw = _ph_to_diff_kwargs(ph, ip)
        if existing:
            if update_existing_hosts:
                changes = _compute_host_changes(ph, existing)
                if changes:
                    updated_hosts.append(TopologyHostDiff(**kw, is_new=False, existing_id=existing.id, changes=changes))
        else:
            new_hosts.append(TopologyHostDiff(**kw, is_new=True))
    return new_hosts, updated_hosts, []


def _preview_infer_links(new_hosts: list, existing_hosts: list, _db, confidence_threshold: float) -> list:
    existing_for_links = [
        {"ip": h.ip, "hostname": h.hostname, "os": h.os, "ports": h.ports or [], "tags": h.tags or [], "role": h.role}
        for h in existing_hosts
    ]
    new_for_links = [
        {"ip": h.ip, "hostname": h.hostname, "os": h.os, "ports": h.ports, "tags": h.tags}
        for h in new_hosts
    ]
    all_links = infer_links_smart(existing_for_links + new_for_links)
    return [lnk for lnk in all_links if lnk.confidence >= confidence_threshold]


@router.post(
    "/preview", response_model=TopologyPreview, dependencies=[Depends(require_topo_preview)],
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
async def topology_preview(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    file: Annotated[UploadFile | None, File()] = None,
    source_type: Annotated[str, Form()] = "nmap",
    keep_manual_positions: Annotated[bool, Form()] = True,
    create_links: Annotated[bool, Form()] = True,
    update_existing_hosts: Annotated[bool, Form()] = True,
    confidence_threshold: Annotated[float, Form()] = 0.5,
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)

    if not file:
        raise HTTPException(400, "No scan file provided")
    content = (await file.read()).decode("utf-8", errors="replace")
    if source_type == "nmap":
        parsed_hosts = parse_nmap_xml(content)
    else:
        raise HTTPException(400, f"Unsupported source type: {source_type}")

    existing_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    by_ip = {h.ip: h for h in existing_hosts if h.ip}
    by_hostname = {(h.hostname or "").lower(): h for h in existing_hosts if h.hostname}
    new_hosts, updated_hosts, conflicts = _compute_host_diffs(parsed_hosts, by_ip, by_hostname, update_existing_hosts)

    new_links: list[TopologyLinkDiff] = []
    if create_links:
        new_links = _preview_infer_links(new_hosts, existing_hosts, db, confidence_threshold)

    total = len(new_hosts) + len(updated_hosts)
    summary = f"Found {len(parsed_hosts)} hosts: {len(new_hosts)} new, {len(updated_hosts)} updates, {len(new_links)} links"

    return TopologyPreview(
        new_hosts=new_hosts,
        updated_hosts=updated_hosts,
        new_links=new_links,
        conflicts=conflicts,
        scan_source=source_type,
        host_count=total,
        summary=summary,
    )


def _topo_create_new_hosts(db, pid: str, new_host_diffs: list, by_ip: dict) -> tuple[list, int]:
    new_host_objects: list = []
    for diff in new_host_diffs:
        if diff.ip in by_ip:
            continue
        host = models.Host(
            id=new_id("hst"),
            pid=pid,
            ip=diff.ip,
            hostname=diff.hostname,
            os=diff.os,
            ports=diff.ports,
            services=diff.services,
            tags=diff.tags,
            status=diff.status,
            domain=diff.domain,
            role="unknown",
            is_attacker=False,
        )
        db.add(host)
        new_host_objects.append(host)
    return new_host_objects, len(new_host_objects)


def _topo_apply_host_changes(db, updated_host_diffs: list) -> int:
    count = 0
    for diff in updated_host_diffs:
        host = db.query(models.Host).filter(models.Host.id == diff.existing_id).first()
        if not host:
            continue
        changes = diff.changes
        if "hostname" in changes:
            host.hostname = changes["hostname"]
        if "os" in changes:
            host.os = changes["os"]
        if "ports_added" in changes:
            host.ports = list(set((host.ports or []) + changes["ports_added"]))
        if "services_added" in changes:
            host.services = list(set((host.services or []) + changes["services_added"]))
        count += 1
    return count


def _topo_collect_hosts_for_layout(all_project_hosts: list, existing_node_ips: set, existing_node_hids: set) -> list:
    result = []
    for h in all_project_hosts:
        if h.ip not in existing_node_ips and h.id not in existing_node_hids:
            result.append({
                "id": h.id,
                "ip": h.ip,
                "hostname": h.hostname,
                "os": h.os,
                "status": h.status,
                "role": h.role,
                "is_attacker": h.is_attacker,
                "ports": h.ports or [],
                "services": h.services or [],
            })
    return result


def _topo_node_from_positioned(node_data: dict) -> dict:
    role = node_data.get("role", "server")
    if node_data.get("is_attacker"):
        role = "attacker"
    return {
        "id": new_id("nd"),
        "host_id": node_data.get("id", ""),
        "label": node_data.get("hostname") or node_data.get("ip", ""),
        "ip": node_data.get("ip", ""),
        "ips": [],
        "ports": node_data.get("ports", []),
        "services": node_data.get("services", []),
        "subnet": node_data.get("subnet") or _get_subnet(node_data.get("ip", "")),
        "status": node_data.get("status", "unknown"),
        "role": role,
        "type": "server",
        "notes": "",
        "is_attacker": node_data.get("is_attacker", False),
        "x": node_data.get("x", 0),
        "y": node_data.get("y", 0),
        "manually_positioned": False,
        "auto_positioned": True,
    }


def _topo_apply_new_links(existing_nodes: list, existing_edges: list, new_links: list, suppressed_auto_links: set) -> None:
    ip_to_node_id = {n.get("ip"): n.get("id") for n in existing_nodes if n.get("ip")}
    node_by_id = {n.get("id"): n for n in existing_nodes if n.get("id")}
    existing_edge_keys = {(e.get("from"), e.get("to")) for e in existing_edges}
    for link in new_links:
        src_node = ip_to_node_id.get(link.source_ip)
        dst_node = ip_to_node_id.get(link.target_ip)
        if not src_node or not dst_node:
            continue
        edge_ref = _edge_ref(node_by_id.get(src_node), node_by_id.get(dst_node))
        if edge_ref and edge_ref in suppressed_auto_links:
            continue
        key = (src_node, dst_node)
        if key in existing_edge_keys or (dst_node, src_node) in existing_edge_keys:
            continue
        existing_edge_keys.add(key)
        existing_edges.append({
            "id": stable_edge_id(src_node, dst_node, link.source or "auto", link.link_type or ""),
            "from": src_node,
            "to": dst_node,
            "type": link.link_type,
            "label": link.label,
            "reason": link.reason,
            "confidence": link.confidence,
            "source": link.source,
            "state": "inferred",
            "verified": False,
        })


def _topo_update_network_map(network, db, pid: str, body) -> None:
    existing_nodes = get_nodes(network.id, db)
    existing_edges = get_edges(network.id, db)
    existing_meta = deepcopy(network.meta_json or {})
    suppressed_auto_links = set(existing_meta.get(AUTO_LINK_SUPPRESSIONS_KEY) or [])

    existing_node_ips = {n.get("ip") for n in existing_nodes if n.get("ip")}
    existing_node_hids = {n.get("host_id") for n in existing_nodes if n.get("host_id")}

    all_project_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    hosts_for_layout = _topo_collect_hosts_for_layout(all_project_hosts, existing_node_ips, existing_node_hids)

    positioned = compute_layout(
        hosts_for_layout,
        existing_nodes,
        body.options.keep_manual_positions,
        existing_edges,
    )
    for node_data in positioned:
        existing_nodes.append(_topo_node_from_positioned(node_data))

    if body.options.create_links:
        _topo_apply_new_links(existing_nodes, existing_edges, body.preview.new_links, suppressed_auto_links)

    replace_nodes(network.id, network.pid, existing_nodes, db)
    replace_edges(network.id, network.pid, existing_edges, db)
    network.meta_json = existing_meta


@router.post("/apply", dependencies=[Depends(require_topo_apply)], responses={404: {"description": "Not found"}})
def topology_apply(pid: str, body: ApplyRequest, request: Request, db: Annotated[Session, Depends(get_db)]):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)

    username = getattr(request.state, "username", None)
    job = start_job(
        db,
        pid,
        "topology",
        "Topology apply",
        created_by=username or "",
        connector_key="topology",
        operation="apply",
        related_entity=("network", pid),
        request_json=body.model_dump(),
    )

    existing_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    by_ip = {h.ip: h for h in existing_hosts}
    new_host_objects, hosts_created = _topo_create_new_hosts(db, pid, body.preview.new_hosts, by_ip)
    hosts_updated = _topo_apply_host_changes(db, body.preview.updated_hosts)
    db.flush()
    for h in new_host_objects:
        db.refresh(h)

    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network and body.options.create_missing_networks:
        network = models.Network(
            id=new_id("net"),
            pid=pid,
            name="Network",
            background="#07080b",
            meta_json={},
        )
        db.add(network)
        db.flush()

    if network:
        _topo_update_network_map(network, db, pid, body)

    db.commit()

    log_event(
        db,
        pid,
        username,
        "topology",
        "apply",
        f"Topology applied: {hosts_created} hosts created, {hosts_updated} updated",
        {"created": hosts_created, "updated": hosts_updated},
    )
    db.commit()

    for h in new_host_objects:
        db.refresh(h)
        bcast(pid, "host", "create", schemas.Host.model_validate(h).model_dump())

    if network:
        result = schemas.Network.from_orm_obj(network)
        bcast(
            pid,
            "network",
            "topology_rebuilt",
            {"network": result.model_dump(), "updated_at": ts_now()},
        )

    finish_job(
        db,
        job,
        status="done",
        result={
            "hosts_created": hosts_created,
            "hosts_updated": hosts_updated,
            "links_added": len(body.preview.new_links),
        },
    )

    return {
        "ok": True,
        "job_id": job.id,
        "hosts_created": hosts_created,
        "hosts_updated": hosts_updated,
        "links_added": len(body.preview.new_links),
    }


@router.post("/rebuild-layout", dependencies=[Depends(require_topo_apply)], responses={404: {"description": "Not found"}})
def topology_rebuild_layout(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    body: RebuildLayoutRequest = RebuildLayoutRequest(),
    request: Request = None,
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)

    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network:
        raise HTTPException(404, _MSG_NO_NETWORK_MAP)

    username = getattr(getattr(request, "state", None), "username", None) if request else None
    job = start_job(
        db,
        pid,
        "topology",
        "Topology rebuild layout",
        created_by=username or "",
        connector_key="topology",
        operation="rebuild_layout",
        related_entity=("network", network.id),
        request_json=body.model_dump(),
    )

    all_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    hosts_for_layout = [
        {
            "id": h.id,
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os,
            "status": h.status,
            "role": h.role,
            "is_attacker": h.is_attacker,
            "ports": h.ports or [],
            "services": h.services or [],
        }
        for h in all_hosts
    ]

    existing_nodes = get_nodes(network.id, db)
    existing_edges = get_edges(network.id, db)
    positioned = compute_layout(
        hosts_for_layout,
        existing_nodes,
        body.keep_manual_positions,
        existing_edges,
    )

    ip_to_new_pos = {n.get("ip"): (n.get("x", 0), n.get("y", 0)) for n in positioned}
    hid_to_new_pos = {n.get("id"): (n.get("x", 0), n.get("y", 0)) for n in positioned}

    for node in existing_nodes:
        if node.get("manually_positioned") and body.keep_manual_positions:
            continue
        new_pos = hid_to_new_pos.get(node.get("host_id")) or ip_to_new_pos.get(node.get("ip"))
        if new_pos:
            node["x"], node["y"] = new_pos
            node["auto_positioned"] = True
            node["manually_positioned"] = False

    replace_nodes(network.id, network.pid, existing_nodes, db)
    db.commit()

    result = schemas.Network.from_orm_obj(network)
    bcast(
        pid, "network", "layout_applied", {"network": result.model_dump(), "updated_at": ts_now()}
    )

    finish_job(
        db,
        job,
        status="done",
        result={"nodes_repositioned": len(positioned), "network_id": network.id},
    )

    return {"ok": True, "job_id": job.id, "nodes_repositioned": len(positioned)}
