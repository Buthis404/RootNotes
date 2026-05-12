import hashlib
import ipaddress
import re
from datetime import datetime

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
    observations = db.query(models.PivotObservation).filter(models.PivotObservation.pid == pid, models.PivotObservation.status == "active").all()
    for obs in observations:
        source_node = node_by_host_id.get(obs.source_host_id)
        pivot_node = node_by_host_id.get(obs.pivot_host_id)
        if not pivot_node:
            continue
        if source_node and source_node.get("id") != pivot_node.get("id"):
            key = (source_node.get("id"), pivot_node.get("id"), obs.id)
            if key not in seen:
                seen.add(key)
                pivot_edges.append({
                    "id": new_id("edg"),
                    "from": source_node.get("id"),
                    "to": pivot_node.get("id"),
                    "style": "tunnel",
                    "type": "pivot",
                    "label": obs.label or obs.tool or "pivot",
                    "confidence": 1.0,
                    "source": "pivot_observation",
                    "reason": f"{obs.tool} {obs.pivot_type}" + (f" route {obs.route_cidr}" if obs.route_cidr else "") + (f" bind {obs.bind_address}" if obs.bind_address else ""),
                    "state": "observed",
                    "verified": True,
                    "is_manual": False,
                    "pivot_observation_id": obs.id,
                    "collector_target_id": obs.collector_target_id,
                })
        if obs.target_host_id:
            target_node = node_by_host_id.get(obs.target_host_id)
            if target_node and pivot_node.get("id") != target_node.get("id"):
                key = (pivot_node.get("id"), target_node.get("id"), obs.id)
                if key not in seen:
                    seen.add(key)
                    pivot_edges.append({
                        "id": new_id("edg"),
                        "from": pivot_node.get("id"),
                        "to": target_node.get("id"),
                        "style": "tunnel",
                        "type": "pivot",
                        "label": obs.route_cidr or obs.label or obs.tool or "pivot",
                        "confidence": 1.0,
                        "source": "pivot_observation",
                        "reason": f"{obs.tool} {obs.pivot_type}" + (f" route {obs.route_cidr}" if obs.route_cidr else ""),
                        "state": "observed",
                        "verified": True,
                        "is_manual": False,
                        "pivot_observation_id": obs.id,
                        "collector_target_id": obs.collector_target_id,
                    })
    network.edges_json = keep_edges + pivot_edges
    db.commit()
    bcast(pid, "network", "layout_applied", {"network": schemas.Network.from_orm_obj(network).model_dump(), "updated_at": datetime.utcnow().isoformat()})


@router.get("")
def list_pivots(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, pid, user, "network.read")
    observations = db.query(models.PivotObservation).filter(models.PivotObservation.pid == pid).order_by(models.PivotObservation.last_seen.desc(), models.PivotObservation.ts.desc()).all()
    return {"items": [_observation_out(obs) for obs in observations]}


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
