import hashlib
import ipaddress
import re
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast, log_event
from ..core.network_data import get_edges, get_nodes, replace_edges
from ..core.permissions import PERM_NETWORK_MANAGE_LINKS
from ..core.ssh_exec import run_ssh_command
from ..core.utils import new_id, stable_edge_id, ts_now
from ..database import get_db
from ..plugins.state import list_attacker_targets, list_attacker_targets_for_pivot
from .c2 import _load_integrations, _visible_integrations_for_pid

router = APIRouter(
    prefix="/api/projects/{pid}/pivots", tags=["pivots"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
    },
)

_PARAMS_PREFIX = "#params: "

_TOOL_RE = re.compile(r"\b(chisel|ligolo|ligolo-ng|proxy|agent)\b", re.I)
_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
_BIND_RE = re.compile(r"(?:R:)?(?P<bind>(?:\d{1,3}\.){3}\d{1,3}:\d+|\d+)")

# chisel forward syntax: `R:1080:socks`, `R:127.0.0.1:8443:10.0.0.1:443`,
# `L:8080:internal.local:80`, etc. Direction R = reverse, L = local. Type
# `socks` means the special SOCKS5 listener; otherwise it's a TCP forward.
_CHISEL_FWD_RE = re.compile(
    r"(?:^|\s)(?P<dir>[RL]):(?P<spec>[^\s]+)",
    re.I,
)
# `chisel client https://attacker:8080 R:socks` — extract the server URL.
_CHISEL_SERVER_RE = re.compile(r"chisel\s+client\s+(?P<server>\S+)", re.I)

# ligolo-ng: `agent -connect 10.0.0.1:11601 [-ignore-cert]`,
# `proxy -selfcert -laddr 0.0.0.0:11601`, also `tunnel_start` interface
# names like `ligolo`, `ligolo0`, etc.
_LIGOLO_CONNECT_RE = re.compile(r"-connect\s+(?P<server>\S+)", re.I)
_LIGOLO_LADDR_RE = re.compile(r"-laddr\s+(?P<bind>\S+)", re.I)
_LIGOLO_IFACE_RE = re.compile(r"\bdev\s+(?P<iface>ligolo\w*)\b", re.I)


def _parse_one_chisel_forward(m) -> dict[str, Any]:
    spec = m.group("spec") or ""
    direction = "reverse" if m.group("dir").upper() == "R" else "local"
    is_socks = spec.lower() == "socks" or spec.lower().endswith(":socks")
    fwd: dict[str, Any] = {
        "direction": direction,
        "proxy_type": "socks" if is_socks else "tcp",
        "raw": f"{m.group('dir').upper()}:{spec}",
    }
    if not is_socks:
        parts = spec.split(":")
        if len(parts) >= 3:
            fwd["target_host"] = parts[-2]
            try:
                fwd["target_port"] = int(parts[-1])
            except ValueError:
                pass
    return fwd


def _parse_chisel_args(line: str) -> dict[str, Any]:
    """Extract structured fields from a chisel ps line."""
    lowered = line.lower()
    out: dict[str, Any] = {}
    if "server" in lowered and "--reverse" in lowered:
        out["mode"] = "server"
        out["direction"] = "reverse"
    elif "server" in lowered:
        out["mode"] = "server"
    elif "client" in lowered:
        out["mode"] = "client"
        srv = _CHISEL_SERVER_RE.search(line)
        if srv:
            out["server"] = srv.group("server")

    forwards = [_parse_one_chisel_forward(m) for m in _CHISEL_FWD_RE.finditer(line)]
    if forwards:
        out["forwards"] = forwards
        first = forwards[0]
        out.setdefault("direction", first["direction"])
        out["proxy_type"] = first["proxy_type"]
    return out


def _parse_ligolo_args(line: str) -> dict[str, Any]:
    """Extract structured fields from a ligolo/ligolo-ng ps line."""
    lowered = line.lower()
    out: dict[str, Any] = {}
    if "proxy" in lowered and "agent" not in lowered:
        out["mode"] = "proxy"
        laddr = _LIGOLO_LADDR_RE.search(line)
        if laddr:
            out["listen"] = laddr.group("bind")
    elif "agent" in lowered:
        out["mode"] = "agent"
        conn = _LIGOLO_CONNECT_RE.search(line)
        if conn:
            out["server"] = conn.group("server")
    iface = _LIGOLO_IFACE_RE.search(line)
    if iface:
        out["interface"] = iface.group("iface")
    return out


def _format_params_note(raw_line: str, params: dict[str, Any]) -> str:
    """Attach a JSON-encoded `#params:` trailer to the raw ps line so the
    UI / downstream code can recover the parsed fields without a DB
    migration."""
    import json as _json

    if not params:
        return raw_line[:600]
    trailer = _PARAMS_PREFIX + _json.dumps(params, separators=(",", ":"))
    # Keep total under ~1KB
    body = raw_line[:600]
    return f"{body}\n{trailer}"


def _load_project_scope_networks(pid: str, db: Session) -> list[ipaddress._BaseNetwork]:
    """All in-scope CIDR networks of a project, parsed and deduped.

    Domain / hostname / regex scopes are skipped — pivot routes are
    network-layer, so we only match against CIDR scopes. Returns an
    empty list if the project has no CIDR scopes defined.
    """
    networks: list[ipaddress._BaseNetwork] = []
    rows = (
        db.query(models.Scope)
        .filter(
            models.Scope.pid == pid,
            models.Scope.in_scope,
            models.Scope.scope_type == "cidr",
        )
        .all()
    )
    for row in rows:
        val = (row.value or "").strip()
        if not val:
            continue
        try:
            net = ipaddress.ip_network(val, strict=False)
        except ValueError:
            continue
        networks.append(net)
    return networks


def _cidr_in_any_scope(cidr_str: str, scope_networks) -> bool | None:
    """True if cidr_str overlaps any scope, False if not, None on parse error."""
    try:
        obs_net = ipaddress.ip_network(cidr_str, strict=False)
        for sn in scope_networks:
            if obs_net.subnet_of(sn) or obs_net.supernet_of(sn) or obs_net.overlaps(sn):
                return True
        return False
    except ValueError:
        return None


def _ip_in_any_scope(ip_str: str, scope_networks) -> bool | None:
    """True if ip_str is in any scope, False if not, None if not a valid IP."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in sn for sn in scope_networks)
    except ValueError:
        return None


def _forwards_scope_check(params: dict, scope_networks) -> tuple[bool, bool]:
    """Scan chisel forward targets. Returns (saw_ip_target, any_in_scope)."""
    saw = False
    for fwd in params.get("forwards") or []:
        target_host = fwd.get("target_host") or ""
        if not target_host:
            continue
        result = _ip_in_any_scope(target_host, scope_networks)
        if result is None:
            continue  # hostname — can't decide
        saw = True
        if result:
            return True, True
    return saw, False


def _observation_scope_decision(
    item: dict,
    scope_networks: list[ipaddress._BaseNetwork],
) -> str:
    """Return 'in_scope', 'out_of_scope', or 'ambiguous'.

    Empty scope_networks always yields 'in_scope' (no scope = no filter).
    """
    if not scope_networks:
        return "in_scope"
    saw_targeting_info = False
    rc = (item.get("route_cidr") or "").strip()
    if rc:
        saw_targeting_info = True
        if _cidr_in_any_scope(rc, scope_networks) is True:
            return "in_scope"
    params = _extract_params_from_notes(item.get("notes") or "")
    fwd_saw, fwd_in_scope = _forwards_scope_check(params, scope_networks)
    if fwd_in_scope:
        return "in_scope"
    if fwd_saw:
        saw_targeting_info = True
    return "out_of_scope" if saw_targeting_info else "ambiguous"


def _extract_params_from_notes(notes: str) -> dict:
    """Recover the JSON params trailer written by _format_params_note."""
    if _PARAMS_PREFIX not in notes:
        return {}
    try:
        import json as _json

        trailer = notes.rsplit(_PARAMS_PREFIX, 1)[1].splitlines()[0]
        return _json.loads(trailer)
    except Exception:
        return {}


def _parse_ss_lines(ss_lines: list[str]) -> dict[str, list[int]]:
    """Map process name → listening ports (TCP) from `ss -tnlp` output.

    The relevant column is `users:(("chisel",pid=1234,fd=3))`. We extract
    the binary name and the local port from the same row.
    """
    by_proc: dict[str, list[int]] = {}
    port_re = re.compile(r":(?P<port>\d+)\s")
    proc_re = re.compile(r'"(?P<name>[^"]+)"')
    for line in ss_lines:
        lowered = line.lower()
        if not any(t in lowered for t in ("chisel", "ligolo", "proxy", "agent")):
            continue
        proc_m = proc_re.search(line)
        port_m = port_re.search(line)
        if not proc_m or not port_m:
            continue
        name = proc_m.group("name").lower()
        try:
            port = int(port_m.group("port"))
        except ValueError:
            continue
        by_proc.setdefault(name, []).append(port)
    return by_proc


class PivotCollectBody(BaseModel):
    target_id: str = ""
    source_host_id: str = ""
    clear_existing: bool = True
    # When True (default), observations whose route_cidr or chisel-forward
    # target falls outside every Scope of the current project are dropped.
    # Use False to ingest everything seen on the box (debugging / shared
    # infrastructure with no formal scopes yet).
    strict_scope_filter: bool = True
    # Independently controls whether observations without any targeting
    # info (e.g. chisel client with SOCKS-only and no routes) are kept.
    # Defaults to keeping them — they're useful as "something is running
    # here" markers even if we can't decide project assignment.
    keep_ambiguous: bool = True


def _observation_out(obs: models.PivotObservation) -> dict:
    return schemas.PivotObservation.model_validate(obs).model_dump()


def _default_source_host_id(pid: str, db: Session) -> str:
    attacker = (
        db.query(models.Host)
        .filter(models.Host.pid == pid)
        .filter((models.Host.is_attacker) | (models.Host.role == "attacker"))
        .order_by(models.Host.id)
        .first()
    )
    return attacker.id if attacker else ""


def _host_lookup_by_ip_or_name(
    pid: str, db: Session
) -> tuple[dict[str, models.Host], dict[str, models.Host]]:
    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    ip_map = {h.ip: h for h in hosts if h.ip}
    host_map = {h.hostname.lower(): h for h in hosts if h.hostname}
    return ip_map, host_map


def _resolve_host_for_tunnel(
    _pid: str, _db: Session, ip_map: dict, host_map: dict, ip: str = "", hostname: str = ""
) -> models.Host | None:
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


def _tunnel_item_dict(item: dict, agent: dict) -> dict:
    return {
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
    }


def _adaptix_fetch_tunnels(cfg: dict) -> list[dict]:
    url = cfg["url"].rstrip("/")
    ep = cfg.get("endpoint", "/endpoint").rstrip("/") or "/endpoint"
    base = f"{url}{ep}"
    with httpx.Client(verify=cfg.get("verify_ssl", False), timeout=20) as client:
        token = cfg.get("token", "")
        if not token:
            login_r = client.post(
                f"{base}/login",
                json={
                    "username": cfg.get("username") or "operator",
                    "password": cfg.get("password", ""),
                    "version": "",
                },
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
        result.append(_tunnel_item_dict(item, agent))
    return result


def _build_adaptix_tunnel_item(
    pid: str, db: "Session", cfg: dict, ip_map: dict, host_map: dict,
    source_host_id: str, tunnel: dict,
) -> dict | None:
    pivot_host = _resolve_host_for_tunnel(
        pid, db, ip_map, host_map,
        tunnel.get("internal_ip", "") or tunnel.get("external_ip", ""),
        tunnel.get("computer", ""),
    )
    bind_address = _format_bind_address(tunnel.get("interface", ""), tunnel.get("port", ""))
    if not bind_address:
        return None
    target_host = (
        _resolve_host_for_tunnel(
            pid, db, ip_map, host_map,
            tunnel.get("forward_host", ""), tunnel.get("forward_host", ""),
        )
        if tunnel.get("forward_host")
        else None
    )
    tunnel_type = str(tunnel.get("type") or "tunnel").strip().lower()
    tunnel_id = tunnel.get("tunnel_id") or ""
    return {
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
        "notes": (
            f"listener={tunnel.get('listener','')} client={tunnel.get('client','')} "
            f"forward={tunnel.get('forward_host','')}:{tunnel.get('forward_port','')}"
        ),
        "collector_target_id": cfg.get("id", ""),
        "fingerprint": hashlib.sha256(
            f"adaptix:{cfg.get('id')}:{tunnel_id}:{bind_address}".encode()
        ).hexdigest(),
        "ts": ts_now(),
        "last_seen": ts_now(),
    }


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
            item = _build_adaptix_tunnel_item(pid, db, cfg, ip_map, host_map, source_host_id, tunnel)
            if item:
                items.append(item)
    return items


def get_all_pivot_items(pid: str, db: Session) -> list[dict]:
    observations = (
        db.query(models.PivotObservation)
        .filter(models.PivotObservation.pid == pid)
        .order_by(models.PivotObservation.last_seen.desc(), models.PivotObservation.ts.desc())
        .all()
    )
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
    # Pivot collector only polls hosts where chisel/ligolo can run.
    targets = [
        target
        for target in list_attacker_targets_for_pivot()
        if (not target.get("project_ids") or pid in target.get("project_ids", []))
    ]
    if not targets:
        raise HTTPException(
            400, "No pivot-capable attacker SSH targets configured for this project"
        )
    if target_id:
        # Explicit id — verify it's pivot-capable, otherwise fail with clear message
        explicit = next((t for t in list_attacker_targets() if t.get("id") == target_id), None)
        if not explicit:
            raise HTTPException(404, "Attacker SSH target not found")
        if not explicit.get("runs_pivot", True):
            raise HTTPException(
                400,
                "Selected target is operator-only — chisel/ligolo are not expected to run there",
            )
        target = explicit
    else:
        target = targets[0]
    if not target:
        raise HTTPException(404, "Attacker SSH target not found")
    pivot_host = (
        db.query(models.Host)
        .filter(models.Host.pid == pid)
        .filter(
            (models.Host.ip == target.get("host")) | (models.Host.hostname == target.get("host"))
        )
        .first()
    )
    return target, pivot_host


def _default_source_host(pid: str, source_host_id: str, db: Session) -> str:
    if source_host_id:
        host = (
            db.query(models.Host)
            .filter(models.Host.id == source_host_id, models.Host.pid == pid)
            .first()
        )
        if not host:
            raise HTTPException(404, "Source host not found")
        return host.id
    attacker = (
        db.query(models.Host)
        .filter(models.Host.pid == pid)
        .filter((models.Host.is_attacker) | (models.Host.role == "attacker"))
        .order_by(models.Host.id)
        .first()
    )
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


def _chisel_observations(line: str, routes: list[str], listen_by_proc: dict) -> list[dict]:
    params = _parse_chisel_args(line)
    lowered = line.lower()
    pivot_type = "socks5" if (params.get("proxy_type") == "socks" or "socks" in lowered) else "tunnel"
    bind_match = _BIND_RE.search(line)
    default_bind = "1080" if pivot_type == "socks5" else ""
    bind = bind_match.group("bind") if bind_match else default_bind
    listen_ports = listen_by_proc.get("chisel") or []
    if listen_ports:
        params["live_listen_ports"] = sorted(set(listen_ports))
    direction = params.get("direction") or ("reverse" if pivot_type == "socks5" else "")
    label_parts = ["chisel"]
    if params.get("mode"):
        label_parts.append(params["mode"])
    if direction:
        label_parts.append(direction)
    label_parts.append(pivot_type)
    label = " ".join(label_parts)
    return [
        {
            "tool": "chisel",
            "pivot_type": pivot_type,
            "label": label,
            "route_cidr": rc,
            "bind_address": params.get("server") or bind,
            "notes": _format_params_note(line, params),
        }
        for rc in (routes or [""])
    ]


def _ligolo_observations(line: str, routes: list[str], listen_by_proc: dict) -> list[dict]:
    params = _parse_ligolo_args(line)
    listen_ports = (
        listen_by_proc.get("ligolo") or listen_by_proc.get("proxy") or listen_by_proc.get("agent") or []
    )
    if listen_ports:
        params["live_listen_ports"] = sorted(set(listen_ports))
    mode = params.get("mode") or ""
    label_parts = ["ligolo"]
    if mode:
        label_parts.append(mode)
    if params.get("interface"):
        label_parts.append(f"({params['interface']})")
    label_parts.append("route")
    label = " ".join(label_parts)
    bind_addr = params.get("listen") or params.get("server") or ""
    return [
        {
            "tool": "ligolo",
            "pivot_type": "route",
            "label": label,
            "route_cidr": rc,
            "bind_address": bind_addr,
            "notes": _format_params_note(line, params),
        }
        for rc in (routes or [""])
    ]


def _parse_tool_observations(
    ps_lines: list[str],
    route_lines: list[str],
    ss_lines: list[str] | None = None,
) -> list[dict]:
    routes = _parse_routes(route_lines)
    listen_by_proc = _parse_ss_lines(ss_lines or [])
    observations = []
    for line in ps_lines:
        lowered = line.lower()
        if "chisel" in lowered:
            observations.extend(_chisel_observations(line, routes, listen_by_proc))
        elif "ligolo" in lowered or re.search(r"(?:^|[/\s])(?:proxy|agent)(?:\s|$)", lowered):
            observations.extend(_ligolo_observations(line, routes, listen_by_proc))
    return observations


def _collect_remote_pivots(target: dict) -> tuple[list[dict], str]:
    command = (
        "printf '__PS__\\n'; "
        "sh -lc \"ps -eo args= | grep -E '(chisel|ligolo|ligolo-ng|/proxy|/agent)' | grep -v grep || true\"; "
        "printf '__ROUTES__\\n'; "
        'sh -lc "ip route show 2>/dev/null || route -n 2>/dev/null || true"; '
        "printf '__SS__\\n'; "
        "sh -lc \"ss -tnlp 2>/dev/null | grep -E '(chisel|ligolo|proxy|agent)' || true\""
    )
    result = run_ssh_command(target, command, 30)
    if not result.get("ok"):
        raise HTTPException(
            400,
            f"Pivot collector SSH failed: {result.get('stderr') or result.get('stdout') or 'unknown error'}",
        )
    stdout = result.get("stdout") or ""
    section = None
    sections = {"PS": [], "ROUTES": [], "SS": []}
    for raw in stdout.splitlines():
        line = raw.rstrip()
        if line == "__PS__":
            section = "PS"
            continue
        if line == "__ROUTES__":
            section = "ROUTES"
            continue
        if line == "__SS__":
            section = "SS"
            continue
        if section and line:
            sections[section].append(line)
    return _parse_tool_observations(sections["PS"], sections["ROUTES"], sections["SS"]), stdout


def _pivot_edge_reason(obs: dict) -> str:
    reason = f"{obs.get('tool')} {obs.get('pivot_type')}"
    if obs.get("route_cidr"):
        reason += f" route {obs.get('route_cidr')}"
    if obs.get("bind_address"):
        reason += f" bind {obs.get('bind_address')}"
    return reason


def _maybe_add_pivot_edge(
    obs: dict, from_node: dict, to_node: dict, label: str, seen: set, edges: list
) -> None:
    key = (from_node.get("id"), to_node.get("id"), obs.get("id"))
    if key in seen:
        return
    seen.add(key)
    edges.append(
        {
            "id": stable_edge_id(
                from_node.get("id"), to_node.get("id"), "pivot_observation", obs.get("id") or ""
            ),
            "from": from_node.get("id"),
            "to": to_node.get("id"),
            "style": "tunnel",
            "type": "pivot",
            "label": label,
            "confidence": 1.0,
            "source": "pivot_observation",
            "reason": _pivot_edge_reason(obs),
            "state": "observed",
            "verified": True,
            "is_manual": False,
            "pivot_observation_id": obs.get("id"),
            "collector_target_id": obs.get("collector_target_id", ""),
        }
    )


def _sync_pivot_edges(pid: str, db: Session):
    network = (
        db.query(models.Network)
        .filter(models.Network.pid == pid)
        .order_by(models.Network.id)
        .first()
    )
    if not network:
        return
    nodes = get_nodes(network.id, db)
    node_by_host_id = {node.get("host_id"): node for node in nodes if node.get("host_id")}
    keep_edges = [
        edge for edge in get_edges(network.id, db) if edge.get("source") != "pivot_observation"
    ]
    pivot_edges: list = []
    seen: set = set()
    observations = [item for item in get_all_pivot_items(pid, db) if item.get("status") == "active"]
    for obs in observations:
        source_node = node_by_host_id.get(obs.get("source_host_id"))
        pivot_node = node_by_host_id.get(obs.get("pivot_host_id"))
        if not pivot_node:
            continue
        if source_node and source_node.get("id") != pivot_node.get("id"):
            _maybe_add_pivot_edge(
                obs, source_node, pivot_node,
                obs.get("label") or obs.get("tool") or "pivot",
                seen, pivot_edges,
            )
        if obs.get("target_host_id"):
            target_node = node_by_host_id.get(obs.get("target_host_id"))
            if target_node and pivot_node.get("id") != target_node.get("id"):
                _maybe_add_pivot_edge(
                    obs, pivot_node, target_node,
                    obs.get("route_cidr") or obs.get("label") or obs.get("tool") or "pivot",
                    seen, pivot_edges,
                )
    replace_edges(network.id, network.pid, keep_edges + pivot_edges, db)
    db.commit()
    bcast(
        pid,
        "network",
        "layout_applied",
        {"network": schemas.Network.from_orm_obj(network).model_dump(), "updated_at": ts_now()},
    )


@router.get("", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
def list_pivots(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "network.read")
    return {"items": get_all_pivot_items(pid, db)}


def _normalize_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network((value or "").strip(), strict=False))
    except (ValueError, TypeError):
        return ""


def _ensure_scope_for_pivot(
    pid: str,
    route_cidr: str,
    pivot_host_id: str,
    db: Session,
    username: str | None = None,
) -> models.Scope | None:
    """Create or update a Scope record reflecting that *route_cidr* is reachable
    only via *pivot_host_id*. Idempotent: if a CIDR-typed scope with the same
    normalized value already exists, only its via_host_id is updated (and only
    if currently empty, to avoid stomping manually set entries)."""
    norm = _normalize_cidr(route_cidr)
    if not norm or not pivot_host_id:
        return None
    existing = (
        db.query(models.Scope).filter(models.Scope.pid == pid, models.Scope.value == norm).first()
    )
    if existing:
        if not existing.via_host_id:
            existing.via_host_id = pivot_host_id
            db.flush()
            log_event(
                db,
                pid,
                username,
                "scope",
                "update",
                f"Scope {norm} linked to pivot host",
                {"scope_id": existing.id, "via_host_id": pivot_host_id},
            )
        return existing
    sc = models.Scope(
        id=new_id("sc"),
        pid=pid,
        value=norm,
        scope_type="cidr",
        in_scope=True,
        description=f"auto: via pivot {pivot_host_id[:8]}",
        gateway_ip="",
        is_entry=False,
        via_host_id=pivot_host_id,
    )
    db.add(sc)
    db.flush()
    log_event(
        db,
        pid,
        username,
        "scope",
        "create",
        f"Scope {norm} auto-created from pivot",
        {"scope_id": sc.id, "via_host_id": pivot_host_id},
    )
    return sc


@router.post("", status_code=201, responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
def create_pivot(
    pid: str,
    body: schemas.PivotObservationCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_NETWORK_MANAGE_LINKS)
    if body.pid != pid:
        raise HTTPException(400, "PID mismatch")
    source_host_id = body.source_host_id or _default_source_host(pid, "", db)
    fingerprint = hashlib.sha256(
        f"manual:{pid}:{source_host_id}:{body.pivot_host_id}:{body.target_host_id}:{body.tool}:{body.pivot_type}:{body.route_cidr}:{body.bind_address}".encode()
    ).hexdigest()
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
        ts=ts_now(),
        last_seen=ts_now(),
    )
    db.add(obs)
    db.flush()
    _ensure_scope_for_pivot(
        pid,
        obs.route_cidr,
        obs.pivot_host_id,
        db,
        username=getattr(request.state, "username", None),
    )
    db.commit()
    db.refresh(obs)
    _sync_pivot_edges(pid, db)
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "pivot",
        "create",
        f"Pivot recorded: {obs.label}",
        {"pivot_id": obs.id, "pivot_host_id": obs.pivot_host_id, "route_cidr": obs.route_cidr},
    )
    db.commit()
    return _observation_out(obs)


@router.patch("/{pivot_id}", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
def update_pivot(
    pivot_id: str,
    pid: str,
    body: schemas.PivotObservationUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    obs = (
        db.query(models.PivotObservation)
        .filter(models.PivotObservation.id == pivot_id, models.PivotObservation.pid == pid)
        .first()
    )
    if not obs:
        raise HTTPException(404, "Pivot observation not found")
    check_object_access(db, pid, user, PERM_NETWORK_MANAGE_LINKS)
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(obs, field, value)
    obs.last_seen = ts_now()
    db.flush()
    _ensure_scope_for_pivot(
        pid,
        obs.route_cidr,
        obs.pivot_host_id,
        db,
        username=getattr(request.state, "username", None),
    )
    db.commit()
    db.refresh(obs)
    _sync_pivot_edges(pid, db)
    db.commit()
    return _observation_out(obs)


@router.delete("/{pivot_id}", status_code=204, responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
def delete_pivot(
    pivot_id: str,
    pid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    obs = (
        db.query(models.PivotObservation)
        .filter(models.PivotObservation.id == pivot_id, models.PivotObservation.pid == pid)
        .first()
    )
    if not obs:
        raise HTTPException(404, "Pivot observation not found")
    check_object_access(db, pid, user, PERM_NETWORK_MANAGE_LINKS)
    removed_route = obs.route_cidr
    removed_pivot_host = obs.pivot_host_id
    db.delete(obs)
    db.flush()
    # If the auto-created scope is no longer backed by any remaining pivot
    # for the same (cidr, via_host_id) pair, and the scope description was
    # auto-generated, drop it. Manually edited scopes are preserved.
    norm = _normalize_cidr(removed_route)
    if norm and removed_pivot_host:
        still_used = (
            db.query(models.PivotObservation)
            .filter(
                models.PivotObservation.pid == pid,
                models.PivotObservation.pivot_host_id == removed_pivot_host,
                models.PivotObservation.route_cidr.in_([removed_route, norm]),
            )
            .first()
        )
        if not still_used:
            scope = (
                db.query(models.Scope)
                .filter(
                    models.Scope.pid == pid,
                    models.Scope.value == norm,
                    models.Scope.via_host_id == removed_pivot_host,
                )
                .first()
            )
            if scope and scope.description.startswith("auto: via pivot"):
                db.delete(scope)
                log_event(
                    db,
                    pid,
                    getattr(request.state, "username", None),
                    "scope",
                    "delete",
                    f"Auto-scope {norm} removed (last pivot deleted)",
                    {"scope_id": scope.id},
                )
    db.commit()
    _sync_pivot_edges(pid, db)
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "pivot",
        "delete",
        f"Pivot removed: {obs.label}",
        {"pivot_id": pivot_id},
    )
    db.commit()


def _filter_pivot_observations(
    observations: list[dict],
    scope_networks,
    strict_scope_filter: bool,
    keep_ambiguous: bool,
) -> tuple[list[dict], int, int]:
    filtered = []
    dropped_out_of_scope = 0
    dropped_ambiguous = 0
    for item in observations:
        decision = _observation_scope_decision(item, scope_networks)
        if decision == "in_scope":
            filtered.append(item)
        elif decision == "out_of_scope":
            if strict_scope_filter:
                dropped_out_of_scope += 1
            else:
                filtered.append(item)
        else:
            if keep_ambiguous:
                filtered.append(item)
            else:
                dropped_ambiguous += 1
    return filtered, dropped_out_of_scope, dropped_ambiguous


def _build_pivot_observation(
    pid: str, source_host_id: str, pivot_host, item: dict, target: dict, now: str
) -> models.PivotObservation:
    pivot_host_id = pivot_host.id if pivot_host else ""
    fingerprint = hashlib.sha256(
        f"ssh:{pid}:{source_host_id}:{pivot_host_id}:{item['tool']}:{item['pivot_type']}:{item['route_cidr']}:{item['bind_address']}".encode()
    ).hexdigest()
    return models.PivotObservation(
        id=new_id("pvt"),
        pid=pid,
        source_host_id=source_host_id,
        pivot_host_id=pivot_host_id,
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


@router.post("/collect", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
def collect_pivots(
    pid: str,
    body: PivotCollectBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_NETWORK_MANAGE_LINKS)
    target, pivot_host = _resolve_pivot_target(pid, body.target_id, db)
    if not pivot_host:
        raise HTTPException(
            400,
            f"SSH collector target {target.get('host') or target.get('name')!r} is not mapped to a project host; add that host to the project first",
        )
    source_host_id = _default_source_host(pid, body.source_host_id, db)
    observations, raw_stdout = _collect_remote_pivots(target)
    scope_networks = _load_project_scope_networks(pid, db)
    observations, dropped_out_of_scope, dropped_ambiguous = _filter_pivot_observations(
        observations, scope_networks, body.strict_scope_filter, body.keep_ambiguous
    )
    if body.clear_existing:
        db.query(models.PivotObservation).filter(
            models.PivotObservation.pid == pid,
            models.PivotObservation.collector_target_id == target.get("id", ""),
        ).delete(synchronize_session=False)
        db.commit()
    now = ts_now()
    username = getattr(request.state, "username", None)
    created = [_build_pivot_observation(pid, source_host_id, pivot_host, item, target, now) for item in observations]
    for obs in created:
        db.add(obs)
    db.flush()
    for obs in created:
        _ensure_scope_for_pivot(pid, obs.route_cidr, obs.pivot_host_id, db, username=username)
    db.commit()
    for obs in created:
        db.refresh(obs)
    _sync_pivot_edges(pid, db)
    log_event(
        db, pid, username, "pivot", "collect",
        f"Pivot collection from SSH target: {target.get('name') or target.get('host')}",
        {
            "target_id": target.get("id", ""),
            "count": len(created),
            "dropped_out_of_scope": dropped_out_of_scope,
            "dropped_ambiguous": dropped_ambiguous,
            "pivot_host_id": pivot_host.id if pivot_host else "",
            "raw_preview": raw_stdout[:800],
        },
    )
    db.commit()
    return {
        "ok": True,
        "target": {
            "id": target.get("id", ""),
            "name": target.get("name") or target.get("host", ""),
            "host": target.get("host", ""),
        },
        "pivot_host_id": pivot_host.id if pivot_host else "",
        "count": len(created),
        "dropped_out_of_scope": dropped_out_of_scope,
        "dropped_ambiguous": dropped_ambiguous,
        "scope_networks": [str(n) for n in scope_networks],
        "items": [_observation_out(obs) for obs in created],
    }
