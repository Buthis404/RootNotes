import hashlib
import ipaddress
import re
from datetime import datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast, log_event
from ..core.ssh_exec import run_ssh_command
from ..core.utils import new_id
from ..database import get_db
from ..plugins.state import list_attacker_targets
from .c2 import _load_integrations, _visible_integrations_for_pid

router = APIRouter(prefix="/api/projects/{pid}/pivots", tags=["pivots"])

_TOOL_RE = re.compile(r"\b(chisel|ligolo|ligolo-ng|proxy|agent)\b", re.I)
_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
_BIND_RE = re.compile(r"(?:R:)?(?P<bind>(?:\d{1,3}\.){3}\d{1,3}:\d+|\d+)")


class PivotCollectBody(BaseModel):
    target_id: str = ""
    source_host_id: str = ""
    clear_existing: bool = True


def _observation_out(obs: models.PivotObservation) -> dict:
    return schemas.PivotObservation.model_validate(obs).model_dump()


def _default_source_host_id(pid: str, db: Session) -> str:
    attacker = db.query(models.Host).filter(models.Host.pid == pid).filter((models.Host.is_attacker == True) | (models.Host.role == "attacker")).order_by(models.Host.id).first()
    return attacker.id if attacker else ""


def _host_lookup_by_ip_or_name(pid: str, db: Session) -> tuple[dict[str, models.Host], dict[str, models.Host]]:
    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    ip_map = {h.ip: h for h in hosts if h.ip}
    host_map = {h.hostname.lower(): h for h in hosts if h.hostname}
    return ip_map, host_map


def _resolve_host_for_tunnel(pid: str, db: Session, ip_map: dict, host_map: dict, ip: str = "", hostname: str = "") -> models.Host | None:
    if ip and ip in ip_map:
        return ip_map[ip]
    if hostname and hostname.lower() in host_map:
        return host_map[hostname.lower()]
    return None


def _format_bind_address(interface: str, port: str) -> str:
    iface = (interface or "").strip()
    prt = str(port or "").strip()
    if not iface and not prt:
        return ""
    if not iface:
        return prt
    if not prt:
        return iface
    return f"{iface}:{prt}"


def normalize_pivot_proxy_type(value: str) -> str:
    raw = (value or "").strip().lower()
    if "socks5" in raw:
        return "socks5"
    if "socks4" in raw:
        return "socks4"
    return raw


def _adaptix_fetch_tunnels(cfg: dict) -> list[dict]:
    url = cfg["url"].rstrip("/")
    ep = cfg.get("endpoint", "/endpoint").rstrip("/") or "/endpoint"
    base = f"{url}{ep}"
    with httpx.Client(verify=cfg.get("verify_ssl", False), timeout=20) as client:
        token = cfg.get("token", "")
        if not token:
            login_r = client.post(
                f"{base}/login",
                json={"username": cfg.get("username") or "operator", "password": cfg.get("password", ""), "version": ""},
            )
            login_r.raise_for_status()
            token = login_r.json().get("access_token") or ""
        headers = {"Authorization": f"Bearer {token}"}
        agents_r = client.get(f"{base}/agent/list", headers=headers)
        agents_r.raise_for_status()
        tunnels_r = client.get(f"{base}/tunnel/list", headers=headers)
        tunnels_r.raise_for_status()
        agents = agents_r.json() if isinstance(agents_r.json(), list) else []
        tunnels = tunnels_r.json() if isinstance(tunnels_r.json(), list) else []
    agents_by_id = {a.get("a_id"): a for a in agents if a.get("a_id")}
    result = []
    for item in tunnels:
        if not isinstance(item, dict):
            continue
        agent = agents_by_id.get(item.get("p_agent_id")) or {}
        result.append({
            "tunnel_id": item.get("p_tunnel_id") or "",
            "agent_id": item.get("p_agent_id") or "",
            "computer": item.get("p_computer") or agent.get("a_computer") or "",
            "username": item.get("p_username") or agent.get("a_username") or "",
            "process": item.get("p_process") or agent.get("a_process") or "",
            "type": item.get("p_type") or "tunnel",
            "info": item.get("p_info") or "",
            "interface": item.get("p_interface") or "",
            "port": str(item.get("p_port") or ""),
            "client": item.get("p_client") or "",
            "forward_host": item.get("p_fhost") or "",
            "forward_port": str(item.get("p_fport") or ""),
            "internal_ip": agent.get("a_internal_ip") or "",
            "external_ip": agent.get("a_external_ip") or "",
            "listener": agent.get("a_listener") or "",
        })
    return result


def _adaptix_tunnel_observations(pid: str, db: Session) -> list[dict]:
    integrations = _visible_integrations_for_pid(_load_integrations(db), pid)
    adaptix = [cfg for cfg in integrations if cfg.get("type") == "adaptix" and cfg.get("enabled")]
    if not adaptix:
        return []
    ip_map, host_map = _host_lookup_by_ip_or_name(pid, db)
    source_host_id = _default_source_host_id(pid, db)
    items = []
    for cfg in adaptix:
        try:
            tunnels = _adaptix_fetch_tunnels(cfg)
        except Exception:
            continue
        for tunnel in tunnels:
            pivot_host = _resolve_host_for_tunnel(pid, db, ip_map, host_map, tunnel.get("internal_ip", "") or tunnel.get("external_ip", ""), tunnel.get("computer", ""))
            bind_address = _format_bind_address(tunnel.get("interface", ""), tunnel.get("port", ""))
            if not bind_address:
                continue
            target_host = _resolve_host_for_tunnel(pid, db, ip_map, host_map, tunnel.get("forward_host", ""), tunnel.get("forward_host", "")) if tunnel.get("forward_host") else None
            tunnel_type = str(tunnel.get("type") or "tunnel").strip().lower()
            tunnel_id = tunnel.get("tunnel_id") or ""
            items.append({
                "id": f"adaptix-tunnel:{cfg.get('id')}:{tunnel_id}",
                "pid": pid,
                "source_host_id": source_host_id,
                "pivot_host_id": pivot_host.id if pivot_host else "",
                "target_host_id": target_host.id if target_host else "",
                "tool": "adaptix",
                "pivot_type": tunnel_type,
                "label": tunnel.get("info") or f"Adaptix tunnel {tunnel_type}",
                "route_cidr": "",
                "bind_address": bind_address,
                "status": "active",
                "notes": f"listener={tunnel.get('listener','')} client={tunnel.get('client','')} forward={tunnel.get('forward_host','')}:{tunnel.get('forward_port','')}",
                "collector_target_id": cfg.get("id", ""),
                "fingerprint": hashlib.sha1(f"adaptix:{cfg.get('id')}:{tunnel_id}:{bind_address}".encode()).hexdigest(),
                "ts": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
                "last_seen": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            })
    return items


def get_all_pivot_items(pid: str, db: Session) -> list[dict]:
    observations = db.query(models.PivotObservation).filter(models.PivotObservation.pid == pid).order_by(models.PivotObservation.last_seen.desc(), models.PivotObservation.ts.desc()).all()
    items = [_observation_out(obs) for obs in observations]
    synthetic = _adaptix_tunnel_observations(pid, db)
    seen_ids = {item.get("id") for item in items}
    items.extend(item for item in synthetic if item.get("id") not in seen_ids)
    return items


def get_pivot_item(pid: str, pivot_id: str, db: Session) -> dict | None:
    for item in get_all_pivot_items(pid, db):
        if item.get("id") == pivot_id:
            return item
    return None


def _resolve_pivot_target(pid: str, target_id: str, db: Session) -> tuple[dict, models.Host | None]:
    targets = [target for target in list_attacker_targets() if target.get("enabled", True) and (not target.get("project_ids") or pid in target.get("project_ids", []))]
    if not targets:
        raise HTTPException(400, "No attacker SSH targets are configured for this project")
    target = next((item for item in targets if item.get("id") == target_id), None) if target_id else targets[0]
    if not target:
        raise HTTPException(404, "Attacker SSH target not found")
    pivot_host = db.query(models.Host).filter(models.Host.pid == pid).filter((models.Host.ip == target.get("host")) | (models.Host.hostname == target.get("host"))).first()
    return target, pivot_host


def _default_source_host(pid: str, source_host_id: str, db: Session) -> str:
    if source_host_id:
        host = db.query(models.Host).filter(models.Host.id == source_host_id, models.Host.pid == pid).first()
        if not host:
            raise HTTPException(404, "Source host not found")
        return host.id
    attacker = db.query(models.Host).filter(models.Host.pid == pid).filter((models.Host.is_attacker == True) | (models.Host.role == "attacker")).order_by(models.Host.id).first()
    return attacker.id if attacker else ""


def _parse_routes(route_lines: list[str]) -> list[str]:
    routes = []
    for line in route_lines:
        match = _CIDR_RE.search(line)
        if not match:
            continue
        cidr = match.group(0)
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.is_loopback or str(net) == "0.0.0.0/0":
            continue
        routes.append(str(net))
    seen = []
    for cidr in routes:
        if cidr not in seen:
            seen.append(cidr)
    return seen


def _parse_tool_observations(ps_lines: list[str], route_lines: list[str]) -> list[dict]:
    routes = _parse_routes(route_lines)
    observations = []
    for line in ps_lines:
        lowered = line.lower()
        if "chisel" in lowered:
            pivot_type = "socks5" if "socks" in lowered else "tunnel"
            bind_match = _BIND_RE.search(line)
            bind = bind_match.group("bind") if bind_match else ("1080" if pivot_type == "socks5" else "")
            obs_routes = routes or [""]
            for route_cidr in obs_routes:
                observations.append({
                    "tool": "chisel",
                    "pivot_type": pivot_type,
                    "label": f"chisel {pivot_type}",
                    "route_cidr": route_cidr,
                    "bind_address": bind,
                    "notes": line[:600],
                })
        elif "ligolo" in lowered or " proxy " in f" {lowered} " or " agent " in f" {lowered} ":
            bind = ""
            laddr_match = re.search(r"-laddr\s+(\S+)", line)
            if laddr_match:
                bind = laddr_match.group(1)
            obs_routes = routes or [""]
            for route_cidr in obs_routes:
                observations.append({
                    "tool": "ligolo",
                    "pivot_type": "route",
                    "label": "ligolo route",
                    "route_cidr": route_cidr,
                    "bind_address": bind,
                    "notes": line[:600],
                })
    return observations


def _collect_remote_pivots(target: dict) -> tuple[list[dict], str]:
    command = (
        "printf '__PS__\\n'; "
        "sh -lc \"ps -eo args= | grep -E '(chisel|ligolo|ligolo-ng|/proxy|/agent)' | grep -v grep || true\"; "
        "printf '__ROUTES__\\n'; "
        "sh -lc \"ip route show 2>/dev/null || route -n 2>/dev/null || true\""
    )
    result = run_ssh_command(target, command, 30)
    if not result.get("ok"):
        raise HTTPException(400, f"Pivot collector SSH failed: {result.get('stderr') or result.get('stdout') or 'unknown error'}")
    stdout = result.get("stdout") or ""
    section = None
    sections = {"PS": [], "ROUTES": []}
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if line == "__PS__":
            section = "PS"
            continue
        if line == "__ROUTES__":
            section = "ROUTES"
            continue
        if section and line:
            sections[section].append(line)
    return _parse_tool_observations(sections["PS"], sections["ROUTES"]), stdout


def _sync_pivot_edges(pid: str, db: Session):
    network = db.query(models.Network).filter(models.Network.pid == pid).order_by(models.Network.id).first()
    if not network:
        return
    nodes = list(network.nodes_json or [])
    node_by_host_id = {node.get("host_id"): node for node in nodes if node.get("host_id")}
    keep_edges = [edge for edge in list(network.edges_json or []) if edge.get("source") != "pivot_observation"]
    pivot_edges = []
    seen = set()
    observations = [item for item in get_all_pivot_items(pid, db) if item.get("status") == "active"]
    for obs in observations:
        source_node = node_by_host_id.get(obs.get("source_host_id"))
        pivot_node = node_by_host_id.get(obs.get("pivot_host_id"))
        if not pivot_node:
            continue
        if source_node and source_node.get("id") != pivot_node.get("id"):
            key = (source_node.get("id"), pivot_node.get("id"), obs.get("id"))
            if key not in seen:
                seen.add(key)
                pivot_edges.append({
                    "id": new_id("edg"),
                    "from": source_node.get("id"),
                    "to": pivot_node.get("id"),
                    "style": "tunnel",
                    "type": "pivot",
                    "label": obs.get("label") or obs.get("tool") or "pivot",
                    "confidence": 1.0,
                    "source": "pivot_observation",
                    "reason": f"{obs.get('tool')} {obs.get('pivot_type')}" + (f" route {obs.get('route_cidr')}" if obs.get('route_cidr') else "") + (f" bind {obs.get('bind_address')}" if obs.get('bind_address') else ""),
                    "state": "observed",
                    "verified": True,
                    "is_manual": False,
                    "pivot_observation_id": obs.get("id"),
                    "collector_target_id": obs.get("collector_target_id", ""),
                })
        if obs.get("target_host_id"):
            target_node = node_by_host_id.get(obs.get("target_host_id"))
            if target_node and pivot_node.get("id") != target_node.get("id"):
                key = (pivot_node.get("id"), target_node.get("id"), obs.get("id"))
                if key not in seen:
                    seen.add(key)
                    pivot_edges.append({
                        "id": new_id("edg"),
                        "from": pivot_node.get("id"),
                        "to": target_node.get("id"),
                        "style": "tunnel",
                        "type": "pivot",
                        "label": obs.get("route_cidr") or obs.get("label") or obs.get("tool") or "pivot",
                        "confidence": 1.0,
                        "source": "pivot_observation",
                        "reason": f"{obs.get('tool')} {obs.get('pivot_type')}" + (f" route {obs.get('route_cidr')}" if obs.get('route_cidr') else "") + (f" bind {obs.get('bind_address')}" if obs.get('bind_address') else ""),
                        "state": "observed",
                        "verified": True,
                        "is_manual": False,
                        "pivot_observation_id": obs.get("id"),
                        "collector_target_id": obs.get("collector_target_id", ""),
                    })
    network.edges_json = keep_edges + pivot_edges
    db.commit()
    bcast(pid, "network", "layout_applied", {"network": schemas.Network.from_orm_obj(network).model_dump(), "updated_at": datetime.utcnow().isoformat()})


@router.get("")
def list_pivots(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, pid, user, "network.read")
    return {"items": get_all_pivot_items(pid, db)}


@router.post("", status_code=201)
def create_pivot(pid: str, body: schemas.PivotObservationCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, pid, user, "network.manage_links")
    if body.pid != pid:
        raise HTTPException(400, "PID mismatch")
    source_host_id = body.source_host_id or _default_source_host(pid, "", db)
    fingerprint = hashlib.sha1(f"manual:{pid}:{source_host_id}:{body.pivot_host_id}:{body.target_host_id}:{body.tool}:{body.pivot_type}:{body.route_cidr}:{body.bind_address}".encode()).hexdigest()
    obs = models.PivotObservation(
        id=new_id("pvt"),
        pid=pid,
        source_host_id=source_host_id,
        pivot_host_id=body.pivot_host_id,
        target_host_id=body.target_host_id,
        tool=body.tool,
        pivot_type=body.pivot_type,
        label=body.label or f"{body.tool or 'pivot'} {body.pivot_type}",
        route_cidr=body.route_cidr,
        bind_address=body.bind_address,
        status=body.status,
        notes=body.notes,
        fingerprint=fingerprint,
        ts=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
        last_seen=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
    )
    db.add(obs)
    db.commit()
    db.refresh(obs)
    _sync_pivot_edges(pid, db)
    log_event(db, pid, getattr(request.state, "username", None), "pivot", "create", f"Pivot recorded: {obs.label}", {"pivot_id": obs.id, "pivot_host_id": obs.pivot_host_id, "route_cidr": obs.route_cidr})
    db.commit()
    return _observation_out(obs)


@router.patch("/{pivot_id}")
def update_pivot(pivot_id: str, pid: str, body: schemas.PivotObservationUpdate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    obs = db.query(models.PivotObservation).filter(models.PivotObservation.id == pivot_id, models.PivotObservation.pid == pid).first()
    if not obs:
        raise HTTPException(404, "Pivot observation not found")
    check_object_access(db, pid, user, "network.manage_links")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(obs, field, value)
    obs.last_seen = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    db.commit()
    db.refresh(obs)
    _sync_pivot_edges(pid, db)
    db.commit()
    return _observation_out(obs)


@router.delete("/{pivot_id}", status_code=204)
def delete_pivot(pivot_id: str, pid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    obs = db.query(models.PivotObservation).filter(models.PivotObservation.id == pivot_id, models.PivotObservation.pid == pid).first()
    if not obs:
        raise HTTPException(404, "Pivot observation not found")
    check_object_access(db, pid, user, "network.manage_links")
    db.delete(obs)
    db.commit()
    _sync_pivot_edges(pid, db)
    log_event(db, pid, getattr(request.state, "username", None), "pivot", "delete", f"Pivot removed: {obs.label}", {"pivot_id": pivot_id})
    db.commit()


@router.post("/collect")
def collect_pivots(pid: str, body: PivotCollectBody, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, pid, user, "network.manage_links")
    target, pivot_host = _resolve_pivot_target(pid, body.target_id, db)
    if not pivot_host:
        raise HTTPException(400, f"SSH collector target {target.get('host') or target.get('name')!r} is not mapped to a project host; add that host to the project first")
    source_host_id = _default_source_host(pid, body.source_host_id, db)
    observations, raw_stdout = _collect_remote_pivots(target)
    if body.clear_existing:
        db.query(models.PivotObservation).filter(models.PivotObservation.pid == pid, models.PivotObservation.collector_target_id == target.get("id", "")).delete(synchronize_session=False)
        db.commit()
    created = []
    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    for item in observations:
        fingerprint = hashlib.sha1(f"ssh:{pid}:{source_host_id}:{pivot_host.id if pivot_host else ''}:{item['tool']}:{item['pivot_type']}:{item['route_cidr']}:{item['bind_address']}".encode()).hexdigest()
        obs = models.PivotObservation(
            id=new_id("pvt"),
            pid=pid,
            source_host_id=source_host_id,
            pivot_host_id=pivot_host.id if pivot_host else "",
            target_host_id="",
            tool=item["tool"],
            pivot_type=item["pivot_type"],
            label=item["label"],
            route_cidr=item["route_cidr"],
            bind_address=item["bind_address"],
            status="active",
            notes=item["notes"],
            collector_target_id=target.get("id", ""),
            fingerprint=fingerprint,
            ts=now,
            last_seen=now,
        )
        db.add(obs)
        created.append(obs)
    db.commit()
    for obs in created:
        db.refresh(obs)
    _sync_pivot_edges(pid, db)
    log_event(db, pid, getattr(request.state, "username", None), "pivot", "collect", f"Pivot collection from SSH target: {target.get('name') or target.get('host')}", {"target_id": target.get("id", ""), "count": len(created), "pivot_host_id": pivot_host.id if pivot_host else "", "raw_preview": raw_stdout[:800]})
    db.commit()
    return {
        "ok": True,
        "target": {"id": target.get("id", ""), "name": target.get("name") or target.get("host", ""), "host": target.get("host", "")},
        "pivot_host_id": pivot_host.id if pivot_host else "",
        "count": len(created),
        "items": [_observation_out(obs) for obs in created],
    }
