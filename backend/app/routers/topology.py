"""
Topology builder — automatic network topology construction from scan data.

Endpoints:
  POST /api/projects/{pid}/topology/preview   — analyse scan, return diff
  POST /api/projects/{pid}/topology/apply     — apply confirmed preview
  POST /api/projects/{pid}/topology/rebuild-layout — recompute node positions
  GET  /api/projects/{pid}/topology           — current topology summary
  GET  /api/projects/{pid}/topology/sources   — supported scan source types
"""
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.job_tracker import start_job, finish_job
from ..core.utils import new_id, normalize_domain
from ..core.layout import compute_layout
from ..core.deps import get_current_user
from ..core.access import check_pid_access
from ..plugins.registry import registry

router = APIRouter(prefix="/api/projects/{pid}/topology", tags=["topology"])


def _require_topology_module_enabled():
    module = registry.get("topology")
    if not module or not module.enabled:
        raise HTTPException(404, "Topology module is disabled")


def require_topo_read(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)) -> models.User:
    _require_topology_module_enabled()
    check_pid_access(db, pid, user, "topology.read")
    return user


def require_topo_preview(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)) -> models.User:
    _require_topology_module_enabled()
    check_pid_access(db, pid, user, "topology.preview")
    return user


def require_topo_apply(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)) -> models.User:
    _require_topology_module_enabled()
    check_pid_access(db, pid, user, "topology.apply")
    return user


# ── Pydantic models ───────────────────────────────────────────────────

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
    existing_id: Optional[str] = None
    changes: dict = {}


class TopologyLinkDiff(BaseModel):
    source_ip: str
    target_ip: str
    link_type: str = "same_subnet"
    confidence: float = 1.0
    source: str = "nmap"
    label: str = ""
    reason: str = ""


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


# ── Nmap XML parser ───────────────────────────────────────────────────

def parse_nmap_xml(xml_content: str) -> list[dict]:
    """Parse Nmap XML and return list of host dicts."""
    hosts = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        raise HTTPException(400, f"Invalid Nmap XML: {e}")

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        ip = ""
        hostname = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                pass

        for hn in host_el.findall(".//hostname"):
            if hn.get("type") in ("PTR", "user", ""):
                hostname = hostname or hn.get("name", "")

        if not ip:
            continue

        os_name = ""
        os_el = host_el.find("os")
        if os_el is not None:
            matches = os_el.findall("osmatch")
            if matches:
                os_name = matches[0].get("name", "")

        ports = []
        services = []
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            proto = port_el.get("protocol", "tcp")
            portid = port_el.get("portid", "")
            port_str = f"{portid}/{proto}"
            ports.append(port_str)

            svc_el = port_el.find("service")
            if svc_el is not None:
                svc_name = svc_el.get("name", "")
                svc_product = svc_el.get("product", "")
                svc_str = f"{svc_name} ({svc_product})" if svc_product else svc_name
                if svc_str:
                    services.append(svc_str)

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "os": os_name or "Unknown",
            "ports": ports,
            "services": services,
            "tags": [],
            "status": "alive",
            "domain": normalize_domain(hostname.split(".", 1)[1]) if hostname and hostname.count(".") >= 1 else "",
        })

    return hosts


# ── Link inference ────────────────────────────────────────────────────

def _get_subnet(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "0.0.0.0/24"


def infer_links(hosts: list[dict]) -> list[TopologyLinkDiff]:
    """
    Basic link inference for scan data (mesh within /24 subnets).
    Used by topology/preview+apply where only scan IPs are known.
    """
    links = []
    subnet_hosts: dict[str, list[str]] = {}
    for h in hosts:
        ip = h.get("ip", "")
        if not ip:
            continue
        subnet = _get_subnet(ip)
        subnet_hosts.setdefault(subnet, []).append(ip)

    seen: set = set()
    for subnet, ips in subnet_hosts.items():
        if len(ips) < 2:
            continue
        for i, src in enumerate(ips[:8]):
            for dst in ips[i + 1:8]:
                key = tuple(sorted([src, dst]))
                if key in seen:
                    continue
                seen.add(key)
                links.append(TopologyLinkDiff(
                    source_ip=src, target_ip=dst,
                    link_type="same_subnet", confidence=0.9, source="nmap",
                ))
    return links


_GW_ROLES = {"router", "firewall", "network_device"}
_GW_TAGS  = {"router", "firewall", "fw", "gateway", "pivot", "border"}
_GW_OS    = ("cisco", "juniper", "pfsense", "opnsense", "fortinet", "vyos",
              "checkpoint", "mikrotik", "router", "fortigate")


def _is_gateway(host: dict) -> bool:
    if (host.get("role") or "").lower() in _GW_ROLES:
        return True
    if {t.lower() for t in (host.get("tags") or [])} & _GW_TAGS:
        return True
    os_l = (host.get("os") or "").lower()
    return any(kw in os_l for kw in _GW_OS)


_GW_IP_SUFFIXES = {1, 2, 254, 253, 252}


def _pick_gateway(group: list[dict]) -> dict:
    """
    Select the most likely gateway from a subnet group.
    Priority:
      1. Explicit gateway role / tag / OS keyword
      2. IP last-octet matching common gateway suffixes (.1, .2, .254, .253, .252)
      3. Most open ports (likely server/gateway)
      4. Lowest IP address (deterministic fallback)
    """
    # 1. Explicit role/tag/OS
    gw = next((h for h in group if _is_gateway(h)), None)
    if gw is not None:
        return gw

    # 2. IP suffix heuristic
    def _suffix_priority(h: dict) -> int:
        try:
            last = int((h.get("ip") or "").split(".")[-1])
            order = [1, 254, 253, 252, 2]
            return order.index(last) if last in order else len(order)
        except (ValueError, IndexError):
            return 999

    candidates_by_suffix = [h for h in group if _suffix_priority(h) < 999]
    if candidates_by_suffix:
        return min(candidates_by_suffix, key=_suffix_priority)

    # 3. Most open ports
    best_port_count = max(len(h.get("ports") or []) for h in group)
    if best_port_count > 0:
        port_candidates = [h for h in group if len(h.get("ports") or []) == best_port_count]
        # 4. Lowest IP as tiebreaker
        return min(port_candidates, key=lambda h: tuple(
            int(p) for p in (h.get("ip") or "0.0.0.0").split(".") if p.isdigit()
        ))

    # 4. Lowest IP
    return min(group, key=lambda h: tuple(
        int(p) for p in (h.get("ip") or "0.0.0.0").split(".") if p.isdigit()
    ))


def infer_links_smart(hosts: list[dict]) -> list[TopologyLinkDiff]:
    """
    Hub-and-spoke link inference using full host metadata.

    Within each subnet:
      - The gateway host (router/firewall, or best-heuristic candidate) is the hub.
      - Every other host in the subnet connects to the hub (spoke).

    Between subnets:
      - Gateway hosts of different subnets are connected to each other (LAN link).
    """
    if not hosts:
        return []

    subnet_hosts: dict[str, list[dict]] = {}
    for h in hosts:
        ip = h.get("ip", "")
        if not ip:
            continue
        subnet = h.get("subnet") or _get_subnet(ip)
        subnet_hosts.setdefault(subnet, []).append(h)

    links: list[TopologyLinkDiff] = []
    seen: set = set()

    def add(src: str, dst: str, link_type: str = "same_subnet",
            label: str = "", confidence: float = 0.9, reason: str = "") -> None:
        key = tuple(sorted([src, dst]))
        if key not in seen and src != dst:
            seen.add(key)
            links.append(TopologyLinkDiff(
                source_ip=src, target_ip=dst,
                link_type=link_type, confidence=confidence,
                source="auto", label=label, reason=reason,
            ))

    subnet_gw: dict[str, str] = {}

    # ── Intra-subnet: hub-and-spoke ───────────────────────────────────
    for subnet, group in subnet_hosts.items():
        if len(group) < 2:
            continue

        gw = _pick_gateway(group)
        gw_ip = gw.get("ip", "")
        gw_hostname = gw.get("hostname", "") or gw_ip

        if gw_ip:
            subnet_gw[subnet] = gw_ip

        # Explain why this host was chosen as gateway
        if _is_gateway(gw):
            gw_reason = f"gateway role/tag/OS on {gw_hostname}"
        else:
            last_octet = gw_ip.split(".")[-1] if gw_ip else ""
            if last_octet in ("1", "2", "254", "253", "252"):
                gw_reason = f"common gateway IP suffix (.{last_octet}) on {gw_hostname}"
            else:
                port_count = len(gw.get("ports") or [])
                gw_reason = f"most open ports ({port_count}) → hub heuristic on {gw_hostname}"

        for h in group:
            h_ip = h.get("ip", "")
            if h_ip and h_ip != gw_ip:
                add(gw_ip, h_ip, "same_subnet", confidence=0.9,
                    reason=f"same /{subnet} subnet; hub: {gw_reason}")

    # ── Inter-subnet: gateway ↔ gateway ───────────────────────────────
    gw_list = [(s, ip) for s, ip in subnet_gw.items()]
    for i, (sa, a) in enumerate(gw_list):
        for sb, b in gw_list[i + 1:]:
            add(a, b, "lan", confidence=0.7,
                reason=f"inter-subnet route between {sa} and {sb} (gateway heuristic)")

    return links


# ── Endpoints ─────────────────────────────────────────────────────────

@router.get("/sources", dependencies=[Depends(require_topo_read)])
def get_topology_sources():
    return {
        "sources": [
            {"id": "nmap", "name": "Nmap XML", "description": "Nmap scan output in XML format (-oX)", "file_types": [".xml"]},
            {"id": "manual", "name": "Manual", "description": "Manually specified host list"},
        ]
    }


@router.get("", dependencies=[Depends(require_topo_read)])
def get_topology(pid: str, db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")

    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    networks = db.query(models.Network).filter(models.Network.pid == pid).all()

    total_nodes = sum(len(n.nodes_json or []) for n in networks)
    total_edges = sum(len(n.edges_json or []) for n in networks)

    return {
        "project_id": pid,
        "host_count": len(hosts),
        "network_count": len(networks),
        "node_count": total_nodes,
        "edge_count": total_edges,
    }


@router.post("/preview", response_model=TopologyPreview, dependencies=[Depends(require_topo_preview)])
async def topology_preview(
    pid: str,
    file: Optional[UploadFile] = File(None),
    source_type: str = Form("nmap"),
    keep_manual_positions: bool = Form(True),
    create_links: bool = Form(True),
    update_existing_hosts: bool = Form(True),
    confidence_threshold: float = Form(0.5),
    db: Session = Depends(get_db),
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")

    # Parse scan data
    parsed_hosts: list[dict] = []
    if file:
        content = (await file.read()).decode("utf-8", errors="replace")
        if source_type == "nmap":
            parsed_hosts = parse_nmap_xml(content)
        else:
            raise HTTPException(400, f"Unsupported source type: {source_type}")
    else:
        raise HTTPException(400, "No scan file provided")

    # Match against existing hosts
    existing_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    by_ip = {h.ip: h for h in existing_hosts if h.ip}
    by_hostname = {(h.hostname or "").lower(): h for h in existing_hosts if h.hostname}

    new_hosts: list[TopologyHostDiff] = []
    updated_hosts: list[TopologyHostDiff] = []
    conflicts: list[dict] = []

    for ph in parsed_hosts:
        ip = ph.get("ip", "")
        hn = (ph.get("hostname") or "").lower()

        existing = by_ip.get(ip) or (by_hostname.get(hn) if hn else None)

        if existing:
            if update_existing_hosts:
                changes = {}
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

                if changes:
                    updated_hosts.append(TopologyHostDiff(
                        ip=ip, hostname=ph.get("hostname", ""),
                        os=ph.get("os", ""), ports=ph.get("ports", []),
                        services=ph.get("services", []), tags=ph.get("tags", []),
                        status=ph.get("status", "alive"), domain=ph.get("domain", ""),
                        is_new=False, existing_id=existing.id, changes=changes,
                    ))
        else:
            new_hosts.append(TopologyHostDiff(
                ip=ip, hostname=ph.get("hostname", ""),
                os=ph.get("os", ""), ports=ph.get("ports", []),
                services=ph.get("services", []), tags=ph.get("tags", []),
                status=ph.get("status", "alive"), domain=ph.get("domain", ""),
                is_new=True,
            ))

    # Infer links using smart hub-and-spoke inference with full host metadata
    new_links: list[TopologyLinkDiff] = []
    if create_links:
        existing_for_links = [
            {"ip": h.ip, "hostname": h.hostname, "os": h.os,
             "ports": h.ports or [], "tags": h.tags or [], "role": h.role}
            for h in existing_hosts
        ]
        new_for_links = [
            {"ip": h.ip, "hostname": h.hostname, "os": h.os,
             "ports": h.ports, "tags": h.tags}
            for h in new_hosts
        ]
        all_links = infer_links_smart(existing_for_links + new_for_links)
        # Filter by confidence threshold and deduplicate against existing edges
        existing_networks = db.query(models.Network).filter(models.Network.pid == pid).all()
        existing_edge_pairs: set = set()
        for net in existing_networks:
            for edge in (net.edges_json or []):
                existing_edge_pairs.add((edge.get("from"), edge.get("to")))
        new_links = [
            lnk for lnk in all_links
            if lnk.confidence >= confidence_threshold
        ]

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


@router.post("/apply", dependencies=[Depends(require_topo_apply)])
def topology_apply(pid: str, body: ApplyRequest, request: Request, db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")

    username = getattr(request.state, "username", None)
    job = start_job(
        db, pid, "topology", "Topology apply",
        created_by=username or "",
        connector_key="topology", operation="apply",
        related_entity_type="network", related_entity_id=pid,
        request_json=body.model_dump(),
    )

    hosts_created = 0
    hosts_updated = 0

    # Create new hosts
    existing_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    by_ip = {h.ip: h for h in existing_hosts}

    new_host_objects: list[models.Host] = []
    for diff in body.preview.new_hosts:
        if diff.ip in by_ip:
            continue
        host = models.Host(
            id=new_id("hst"), pid=pid,
            ip=diff.ip, hostname=diff.hostname, os=diff.os,
            ports=diff.ports, services=diff.services, tags=diff.tags,
            status=diff.status, domain=diff.domain,
            role="unknown", is_attacker=False,
        )
        db.add(host)
        new_host_objects.append(host)
        hosts_created += 1

    # Update existing hosts
    for diff in body.preview.updated_hosts:
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
        hosts_updated += 1

    db.flush()

    # Refresh to get IDs
    for h in new_host_objects:
        db.refresh(h)

    # Get or create network map
    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network and body.options.create_missing_networks:
        network = models.Network(
            id=new_id("net"), pid=pid, name="Network",
            background="#07080b", regions_json=[], nodes_json=[], edges_json=[], meta_json={},
        )
        db.add(network)
        db.flush()

    if network:
        existing_nodes = list(network.nodes_json or [])
        existing_edges = list(network.edges_json or [])
        existing_meta = deepcopy(network.meta_json or {})
        suppressed_auto_links = set(existing_meta.get(AUTO_LINK_SUPPRESSIONS_KEY) or [])

        # Build set of existing node IPs/host_ids
        existing_node_ips = {n.get("ip") for n in existing_nodes if n.get("ip")}
        existing_node_hids = {n.get("host_id") for n in existing_nodes if n.get("host_id")}

        # Prepare all hosts for layout
        all_project_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
        hosts_for_layout = []
        for h in all_project_hosts:
            if h.ip not in existing_node_ips and h.id not in existing_node_hids:
                hosts_for_layout.append({
                    "id": h.id, "ip": h.ip, "hostname": h.hostname,
                    "os": h.os, "status": h.status, "role": h.role,
                    "is_attacker": h.is_attacker, "ports": h.ports or [],
                    "services": h.services or [],
                })

        # Compute positions for new nodes
        positioned = compute_layout(
            hosts_for_layout, existing_nodes,
            body.options.keep_manual_positions, existing_edges,
        )

        # Build new nodes
        for node_data in positioned:
            node_id = new_id("nd")
            h_status = node_data.get("status", "unknown")
            role = node_data.get("role", "server")
            if node_data.get("is_attacker"):
                role = "attacker"
            existing_nodes.append({
                "id": node_id,
                "host_id": node_data.get("id", ""),
                "label": node_data.get("hostname") or node_data.get("ip", ""),
                "ip": node_data.get("ip", ""),
                "ips": [],
                "ports": node_data.get("ports", []),
                "services": node_data.get("services", []),
                "subnet": node_data.get("subnet") or _get_subnet(node_data.get("ip", "")),
                "status": h_status,
                "role": role,
                "type": "server",
                "notes": "",
                "is_attacker": node_data.get("is_attacker", False),
                "x": node_data.get("x", 0),
                "y": node_data.get("y", 0),
                "manually_positioned": False,
                "auto_positioned": True,
            })

        # Add new edges from links
        if body.options.create_links:
            # Build ip→node_id map
            ip_to_node_id = {n.get("ip"): n.get("id") for n in existing_nodes if n.get("ip")}
            node_by_id = {n.get("id"): n for n in existing_nodes if n.get("id")}
            existing_edge_keys = {(e.get("from"), e.get("to")) for e in existing_edges}

            for link in body.preview.new_links:
                src_node = ip_to_node_id.get(link.source_ip)
                dst_node = ip_to_node_id.get(link.target_ip)
                if not src_node or not dst_node:
                    continue
                edge_ref = _edge_ref(node_by_id.get(src_node), node_by_id.get(dst_node))
                if edge_ref and edge_ref in suppressed_auto_links:
                    continue
                key = (src_node, dst_node)
                rkey = (dst_node, src_node)
                if key in existing_edge_keys or rkey in existing_edge_keys:
                    continue
                existing_edge_keys.add(key)
                existing_edges.append({
                    "id": new_id("edg"),
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

        network.nodes_json = existing_nodes
        network.edges_json = existing_edges
        network.meta_json = existing_meta

    db.commit()

    # Log and broadcast
    log_event(db, pid, username, "topology", "apply",
              f"Topology applied: {hosts_created} hosts created, {hosts_updated} updated",
              {"created": hosts_created, "updated": hosts_updated})
    db.commit()

    # Broadcast updates
    for h in new_host_objects:
        db.refresh(h)
        bcast(pid, "host", "create", schemas.Host.model_validate(h).model_dump())

    if network:
        result = schemas.Network.from_orm_obj(network)
        bcast(pid, "network", "topology_rebuilt", {"network": result.model_dump(), "updated_at": datetime.utcnow().isoformat()})

    finish_job(
        db, job,
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


@router.post("/rebuild-layout", dependencies=[Depends(require_topo_apply)])
def topology_rebuild_layout(
    pid: str,
    body: RebuildLayoutRequest = RebuildLayoutRequest(),
    request: Request = None,
    db: Session = Depends(get_db),
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")

    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network:
        raise HTTPException(404, "No network map found")

    username = getattr(getattr(request, "state", None), "username", None) if request else None
    job = start_job(
        db, pid, "topology", "Topology rebuild layout",
        created_by=username or "",
        connector_key="topology", operation="rebuild_layout",
        related_entity_type="network", related_entity_id=network.id,
        request_json=body.model_dump(),
    )

    all_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    hosts_for_layout = [{
        "id": h.id, "ip": h.ip, "hostname": h.hostname,
        "os": h.os, "status": h.status, "role": h.role,
        "is_attacker": h.is_attacker, "ports": h.ports or [], "services": h.services or [],
    } for h in all_hosts]

    existing_nodes = list(network.nodes_json or [])
    existing_edges = list(network.edges_json or [])
    positioned = compute_layout(
        hosts_for_layout, existing_nodes,
        body.keep_manual_positions, existing_edges,
    )

    # Update positions in existing nodes
    pos_by_id = {n.get("id"): n for n in existing_nodes}
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

    network.nodes_json = existing_nodes
    network.edges_json = existing_edges
    db.commit()

    result = schemas.Network.from_orm_obj(network)
    bcast(pid, "network", "layout_applied", {"network": result.model_dump(), "updated_at": datetime.utcnow().isoformat()})

    finish_job(
        db, job,
        status="done",
        result={"nodes_repositioned": len(positioned), "network_id": network.id},
    )

    return {"ok": True, "job_id": job.id, "nodes_repositioned": len(positioned)}


# ── Helpers shared by auto-build ──────────────────────────────────────

def _node_type_for(host: dict) -> str:
    """Map host data to network-map node type string."""
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


def _run_auto_build(pid: str, db: Session, keep_manual_positions: bool = True, create_missing_networks: bool = True) -> dict:
    """Core topology auto-build logic. Callable from other modules (e.g. C2 sync)."""
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        return {"ok": False, "error": "Project not found"}

    all_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    if not all_hosts:
        return {"ok": True, "nodes_total": 0, "nodes_added": 0, "repositioned": 0}

    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network:
        if not create_missing_networks:
            return {"ok": False, "error": "No network map found"}
        network = models.Network(
            id=new_id("net"), pid=pid, name="Network",
            background="#07080b", regions_json=[], nodes_json=[], edges_json=[], meta_json={},
        )
        db.add(network)
        db.flush()

    existing_nodes: list = list(network.nodes_json or [])
    existing_edges: list = list(network.edges_json or [])
    existing_meta: dict = deepcopy(network.meta_json or {})

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
    except Exception:
        pass

    def _annotate_subnet(ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
            matching = [n for n in scope_cidrs if addr in n]
            if matching:
                return str(max(matching, key=lambda n: n.prefixlen))
        except ValueError:
            pass
        return _get_subnet(ip)

    hosts_for_layout = [
        {
            "id": h.id, "ip": h.ip, "hostname": h.hostname, "os": h.os,
            "status": h.status, "role": h.role, "is_attacker": h.is_attacker,
            "ports": h.ports or [], "services": h.services or [],
            "tags": h.tags or [],
            "subnet": _annotate_subnet(h.ip or ""),
        }
        for h in all_hosts
    ]

    positioned = compute_layout(hosts_for_layout, existing_nodes, keep_manual_positions, existing_edges)

    node_by_hid: dict = {n.get("host_id"): n for n in existing_nodes if n.get("host_id")}
    node_by_ip:  dict = {n.get("ip"):      n for n in existing_nodes if n.get("ip")}
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
                "id": new_id("nd"), "host_id": h_id,
                "label": p.get("hostname") or h_ip, "ip": h_ip, "ips": [],
                "ports": p.get("ports", []), "services": p.get("services", []),
                "subnet": p.get("subnet") or _get_subnet(h_ip),
                "status": p.get("status", "unknown"),
                "role": "attacker" if p.get("is_attacker") else p.get("role", "unknown"),
                "type": _node_type_for(p), "notes": "",
                "is_attacker": bool(p.get("is_attacker")),
                "x": p["x"], "y": p["y"],
                "manually_positioned": False, "auto_positioned": True,
            }
            existing_nodes.append(new_node)
            node_by_hid[h_id] = new_node
            node_by_ip[h_ip]  = new_node
            nodes_added += 1

    inferred_links = infer_links_smart(hosts_for_layout)
    ip_to_node_id: dict = {n.get("ip"): n.get("id") for n in existing_nodes if n.get("ip")}
    node_by_id: dict = {n.get("id"): n for n in existing_nodes if n.get("id")}
    suppressed_auto_links = set(existing_meta.get(AUTO_LINK_SUPPRESSIONS_KEY) or [])
    manual_edges = [e for e in existing_edges if e.get("source") != "auto" or e.get("manual_override")]
    manual_edge_keys: set = (
        {(e.get("from"), e.get("to")) for e in manual_edges} |
        {(e.get("to"), e.get("from")) for e in manual_edges}
    )
    new_auto_edges = []
    seen_auto_keys: set = set(manual_edge_keys)
    links_added = 0

    for link in inferred_links:
        src_nid = ip_to_node_id.get(link.source_ip)
        dst_nid = ip_to_node_id.get(link.target_ip)
        if not src_nid or not dst_nid:
            continue
        edge_ref = _edge_ref(node_by_id.get(src_nid), node_by_id.get(dst_nid))
        if edge_ref and edge_ref in suppressed_auto_links:
            continue
        key = (src_nid, dst_nid)
        if key in seen_auto_keys or (dst_nid, src_nid) in seen_auto_keys:
            continue
        seen_auto_keys.add(key)
        seen_auto_keys.add((dst_nid, src_nid))
        new_auto_edges.append({
            "id": new_id("edg"), "from": src_nid, "to": dst_nid,
            "type": link.link_type, "confidence": link.confidence, "source": link.source,
            "reason": link.reason, "state": "inferred", "verified": False,
        })
        links_added += 1

    network.nodes_json = existing_nodes
    network.edges_json = manual_edges + new_auto_edges
    network.meta_json = existing_meta
    db.commit()

    result = schemas.Network.from_orm_obj(network)
    bcast(pid, "network", "layout_applied", {"network": result.model_dump(), "updated_at": datetime.utcnow().isoformat()})

    return {"ok": True, "nodes_total": len(existing_nodes), "nodes_added": nodes_added,
            "repositioned": nodes_repositioned, "links_added": links_added}


@router.post("/auto-build", dependencies=[Depends(require_topo_apply)])
def topology_auto_build(
    pid: str,
    body: AutoBuildRequest = AutoBuildRequest(),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Build or update the network map from all existing project hosts."""
    username = getattr(getattr(request, "state", None), "username", None) if request else None
    job = start_job(
        db, pid, "topology", "Topology auto-build",
        created_by=username or "",
        connector_key="topology", operation="auto_build",
        related_entity_type="network", related_entity_id=pid,
        request_json=body.model_dump(),
    )
    result = _run_auto_build(pid, db, body.keep_manual_positions, body.create_missing_networks)
    if not result.get("ok") and result.get("error") == "Project not found":
        finish_job(db, job, status="failed", error_output="Project not found")
        raise HTTPException(404, "Project not found")
    if not result.get("ok") and result.get("error") == "No network map found":
        finish_job(db, job, status="failed", error_output="No network map found")
        raise HTTPException(404, "No network map found")
    finish_job(db, job, status="done", result=result)
    return {**result, "job_id": job.id}
