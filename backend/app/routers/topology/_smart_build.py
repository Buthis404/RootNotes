import ipaddress
import logging
from copy import deepcopy
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from typing import Annotated
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ... import models, schemas
from ...core.events import bcast, log_event
from ...core.job_tracker import finish_job, start_job
from ...core.layout import compute_layout
from ...core.network_data import (
    get_edges,
    get_nodes,
    get_regions,
    replace_edges,
    replace_nodes,
    replace_regions,
)
from ...core.utils import new_id, stable_edge_id, ts_now
from ...database import get_db

from ._auto_build import _annotate_ip_subnet, _node_type_for
from ._edge_meta import (
    _PORT_88_TCP,
    _PORT_389_TCP,
    _auto_assign_host_role,
    _decay_confidence,
    _edge_action_tags,
    _find_pivot_host,
    _ip_in_network,
    _is_key_host,
    _is_rfc1918,
    _PUBLIC_TAGS,
)
from ._infer import (
    _get_subnet,
    _host_matches_gateway_ip,
    _host_scope_memberships,
    _place_between_regions,
    _place_on_region_edge,
    _region_center,
    _scope_region_colors,
    infer_links_smart,
)
from .routes import (
    AUTO_LINK_SUPPRESSIONS_KEY,
    _MSG_NO_NETWORK_MAP,
    _MSG_PROJECT_NOT_FOUND,
    _edge_ref,
    require_topo_apply,
    router,
)

_log = logging.getLogger("app.topology")

_STATUS_RANK = {
    "unknown": 0,
    "alive": 1,
    "up": 2,
    "scanned": 3,
    "access": 4,
    "owned": 5,
    "pwned": 5,
    "attacker": 6,
}

_TOPO_WEB_PORTS = frozenset({"80/tcp", "443/tcp", "8080/tcp", "8443/tcp"})
_TOPO_DB_PORTS = frozenset({"1433/tcp", "3306/tcp", "5432/tcp", "1521/tcp"})


def _is_dc_node(role: str, tags: set, ports) -> bool:
    return (
        role in ("domain_controller", "dc")
        or "dc" in tags
        or (_PORT_88_TCP in ports and _PORT_389_TCP in ports)
    )


def _is_router_node(role: str, tags: set) -> bool:
    return role in ("router", "firewall", "network_device") or bool(tags & {"router", "firewall", "gateway"})


def _is_jump_node(role: str, tags: set) -> bool:
    return role == "jump_host" or "jump" in tags


def _is_file_server_node(ports: list, os_low: str) -> bool:
    return "445/tcp" in ports and "server" in os_low


def _is_workstation_node(os_low: str) -> bool:
    return "windows" in os_low and "server" not in os_low


def _infer_node_role(h: dict) -> str:
    if h.get("is_attacker") or (h.get("role") or "").lower() == "attacker":
        return "attacker"
    tags = {t.lower() for t in (h.get("tags") or [])}
    role = (h.get("role") or "").lower()
    ports = h.get("ports") or []
    os_low = (h.get("os") or "").lower()
    ports_set = set(ports)

    if _is_dc_node(role, tags, ports):
        return "domain_controller"
    if _is_router_node(role, tags):
        return "router"
    if _is_jump_node(role, tags):
        return "jump_host"
    if _is_file_server_node(ports, os_low):
        return "file_server"
    if ports_set & _TOPO_WEB_PORTS:
        return "web_server"
    if ports_set & _TOPO_DB_PORTS:
        return "database"
    if _is_workstation_node(os_low):
        return "workstation"
    return role or "server"


def _h_in_any_cidr(h, cidrs: list) -> bool:
    try:
        addr = ipaddress.ip_address(h.ip or "")
        return any(addr in n for n in cidrs)
    except ValueError:
        return False


def _lookup_scope_for_ip(ip: str, scope_region_defs: list) -> dict | None:
    if not ip:
        return None
    for sr in scope_region_defs:
        if _ip_in_network(ip, sr["net_obj"]):
            return sr
    return None


def _host_is_dc(h: dict) -> bool:
    r = (h.get("role") or "").lower()
    if r in ("domain_controller", "dc"):
        return True
    if "dc" in {t.lower() for t in (h.get("tags") or [])}:
        return True
    p = h.get("ports") or []
    return _PORT_88_TCP in p and _PORT_389_TCP in p


class _EdgeAcc:
    __slots__ = ("seen_keys", "node_by_id", "suppressed", "edges_by_source", "new_auto_edges", "edges_stale")

    def __init__(self, seen_keys: set, node_by_id: dict, suppressed: set) -> None:
        self.seen_keys = seen_keys
        self.node_by_id = node_by_id
        self.suppressed = suppressed
        self.edges_by_source: dict[str, int] = {}
        self.new_auto_edges: list = []
        self.edges_stale: int = 0


def _add_smart_edge(acc: _EdgeAcc, from_nid: str, to_nid: str, edge_data: dict) -> bool:
    if not from_nid or not to_nid or from_nid == to_nid:
        return False
    key = (from_nid, to_nid)
    rkey = (to_nid, from_nid)
    if key in acc.seen_keys or rkey in acc.seen_keys:
        return False
    eref = _edge_ref(acc.node_by_id.get(from_nid), acc.node_by_id.get(to_nid))
    if eref and eref in acc.suppressed:
        return False
    acc.seen_keys.add(key)
    acc.seen_keys.add(rkey)
    src_key = str(edge_data.get("source") or "auto")
    acc.edges_by_source[src_key] = acc.edges_by_source.get(src_key, 0) + 1
    if edge_data.get("state") == "stale":
        acc.edges_stale += 1
    roles = edge_data.get("access_roles") or []
    kind = str(roles[0]) if roles else str(edge_data.get("type") or "")
    edge_id = stable_edge_id(from_nid, to_nid, str(edge_data.get("source") or "auto"), kind)
    acc.new_auto_edges.append({"id": edge_id, "from": from_nid, "to": to_nid, **edge_data})
    return True


class _SBCtx:
    __slots__ = (
        "pid", "db", "dry_run", "keep_manual_positions", "preserve_positions",
        "include_access_edges", "include_domain_edges", "include_subnet_edges",
        "include_internet_facing", "include_tier_zones", "include_service_graph",
        "include_regions", "confidence_decay_days",
        "all_hosts", "hosts_meta", "network", "existing_nodes", "existing_edges",
        "existing_meta", "manual_edges", "hid_to_nid", "ip_to_nid", "node_by_id",
        "_eacc", "attacker_hids", "attacker_nids", "scope_cidrs", "scope_region_defs",
        "p1_access_pairs", "edges_added", "nodes_added", "nodes_updated",
        "regions_added", "tier_counts", "roles_assigned", "auto_via_count", "role_undo_ops",
    )

    def __init__(self) -> None:
        self.pid = ""
        self.db = None
        self.dry_run = False
        self.keep_manual_positions = True
        self.preserve_positions = True
        self.include_access_edges = True
        self.include_domain_edges = True
        self.include_subnet_edges = True
        self.include_internet_facing = True
        self.include_tier_zones = True
        self.include_service_graph = False
        self.include_regions = True
        self.confidence_decay_days = 14.0
        self.all_hosts = []
        self.hosts_meta = []
        self.network = None
        self.existing_nodes = []
        self.existing_edges = []
        self.existing_meta = {}
        self.manual_edges = []
        self.hid_to_nid = {}
        self.ip_to_nid = {}
        self.node_by_id = {}
        self._eacc = None
        self.attacker_hids = set()
        self.attacker_nids = []
        self.scope_cidrs = []
        self.scope_region_defs = []
        self.p1_access_pairs = set()
        self.edges_added = 0
        self.nodes_added = 0
        self.nodes_updated = 0
        self.regions_added = 0
        self.tier_counts = {"tier_0": 0, "tier_1": 0, "tier_2": 0}
        self.roles_assigned = 0
        self.auto_via_count = 0
        self.role_undo_ops = []


def _sb_p1_resolve_from_nid(ctx: _SBCtx, cred, target_nid: str) -> str | None:
    if ctx.attacker_nids:
        return ctx.attacker_nids[0]
    if cred and cred.host_ids:
        for hid in cred.host_ids:
            nid = ctx.hid_to_nid.get(hid)
            if nid and nid != target_nid:
                return nid
    return None


def _sb_p1_cred_label(cred) -> str:
    if not cred:
        return ""
    prefix = f"{cred.domain}\\" if cred.domain else ""
    return prefix + (cred.username or "")


def _sb_p1_access_edges(ctx: _SBCtx) -> None:
    if not ctx.include_access_edges:
        return
    creds_map = {c.id: c for c in ctx.db.query(models.Cred).filter(models.Cred.pid == ctx.pid).all()}
    notes = ctx.db.query(models.CredHostNote).filter(models.CredHostNote.pid == ctx.pid).all()
    for note in notes:
        if not note.access:
            continue
        target_nid = ctx.hid_to_nid.get(note.host_id)
        if not target_nid:
            continue
        cred = creds_map.get(note.cred_id)
        cred_label = _sb_p1_cred_label(cred)
        from_nid = _sb_p1_resolve_from_nid(ctx, cred, target_nid)
        if not from_nid:
            continue
        roles = note.access
        primary = roles[0]
        if _add_smart_edge(ctx._eacc, from_nid, target_nid, {
            "type": primary, "label": primary.replace("_", " "),
            "confidence": 1.0, "source": "cred_validation",
            "reason": f"Credential validated: {cred_label} [{', '.join(roles)}]",
            "state": "observed", "verified": True, "is_manual": False,
            "access_roles": roles, **_edge_action_tags("cred_validation"),
        }):
            ctx.edges_added += 1
            ctx.p1_access_pairs.add((from_nid, target_nid, primary))


def _sb_p2_process_job(ctx: _SBCtx, job) -> None:
    rj = job.request_json or {}
    res = job.result_json or {}
    tgt_hid = job.related_entity_id
    att_hid = rj.get("attacker_host_id")
    role = res.get("access_role") or rj.get("access_role")
    if not (tgt_hid and att_hid and role):
        return
    from_nid = ctx.hid_to_nid.get(att_hid)
    to_nid = ctx.hid_to_nid.get(tgt_hid)
    if not from_nid or not to_nid:
        return
    decayed, stale = _decay_confidence(1.0, getattr(job, "finished_at", "") or "", ctx.confidence_decay_days)
    if _add_smart_edge(ctx._eacc, from_nid, to_nid, {
        "type": role, "label": role.replace("_", " "),
        "confidence": round(decayed, 3), "source": "bulk_exec",
        "reason": f"Bulk exec success: {job.title or 'exec'} via {role}",
        "state": "stale" if stale else "observed", "verified": True, "is_manual": False,
        "ts": getattr(job, "finished_at", "") or "", **_edge_action_tags("bulk_exec"),
    }):
        ctx.edges_added += 1


def _sb_p2_bulk_exec(ctx: _SBCtx) -> None:
    if not ctx.include_access_edges:
        return
    bulk_jobs = (
        ctx.db.query(models.Job)
        .filter(models.Job.pid == ctx.pid, models.Job.type == "exec",
                models.Job.status == "done", models.Job.operation == "bulk_exec")
        .all()
    )
    for job in bulk_jobs:
        _sb_p2_process_job(ctx, job)


def _sb_p3_find_nonentry(ctx: _SBCtx, act, target_nid: str, target_scope: dict,
                          sessions_by_scope: dict, auto_pivot_by_cidr: dict,
                          entry_gw_ips: set) -> tuple[str | None, str]:
    target_cidr = target_scope["cidr"]
    for prev in sessions_by_scope.get(target_cidr, []):
        if prev["host_id"] != act.host_id:
            return prev["target_nid"], f"via earlier session on {prev['hostname'] or prev['host_id']}"
    if target_scope.get("via_host_id"):
        via_nid = ctx.hid_to_nid.get(target_scope["via_host_id"])
        if via_nid and via_nid != target_nid:
            return via_nid, f"via scope.via_host {target_scope['via_host_id']}"
    cidr_key = target_scope["cidr"]
    if cidr_key not in auto_pivot_by_cidr:
        ph = _find_pivot_host(target_scope["net_obj"], ctx.scope_region_defs, ctx.hosts_meta, entry_gw_ips)
        auto_pivot_by_cidr[cidr_key] = ctx.hid_to_nid.get(ph["id"]) if ph else None
    auto_nid = auto_pivot_by_cidr[cidr_key]
    if auto_nid and auto_nid != target_nid:
        return auto_nid, "via auto-detected junction"
    return None, ""


def _sb_p3_find_from_nid(ctx: _SBCtx, act, target_nid: str, target_scope: dict | None,
                          sessions_by_scope: dict, auto_pivot_by_cidr: dict,
                          entry_gw_ips: set) -> tuple[str | None, str]:
    from_nid, route_reason = None, ""
    if target_scope and not target_scope.get("is_entry"):
        from_nid, route_reason = _sb_p3_find_nonentry(
            ctx, act, target_nid, target_scope, sessions_by_scope, auto_pivot_by_cidr, entry_gw_ips)
    if not from_nid:
        from_nid = ctx.attacker_nids[0]
        route_reason = route_reason or "direct from attacker"
    return from_nid, route_reason


def _sb_p3_track_session(act, target_nid: str, target_host, target_cidr: str,
                          sessions_by_scope: dict) -> None:
    if not target_cidr:
        return
    sessions_by_scope.setdefault(target_cidr, []).append({
        "host_id": act.host_id, "target_nid": target_nid,
        "ts": act.ts or "", "hostname": (target_host or {}).get("hostname", ""),
    })


def _sb_p3_add_edge(ctx: _SBCtx, act, etype: str, from_nid: str, target_nid: str,
                    route_reason: str) -> None:
    is_c2 = act.activity_type == "c2"
    decayed, stale = _decay_confidence(0.9, act.ts or "", ctx.confidence_decay_days)
    if stale:
        edge_state = "stale"
    elif is_c2:
        edge_state = "inferred"
    else:
        edge_state = "observed"
    if _add_smart_edge(ctx._eacc, from_nid, target_nid, {
        "type": etype, "label": etype.replace("_", " "),
        "confidence": round(decayed, 3),
        "source": "auto" if is_c2 else "host_activity",
        "reason": f"Host activity: {act.title or act.activity_type} [{act.ts}] — {route_reason}",
        "state": edge_state, "verified": not (is_c2 or stale), "is_manual": False,
        "ts": act.ts or "", **_edge_action_tags("host_activity", act.activity_type),
    }):
        ctx.edges_added += 1


def _sb_p3_host_activity(ctx: _SBCtx) -> None:
    if not (ctx.include_access_edges and ctx.attacker_nids):
        return
    _exec_types = {"exec", "postex", "lateral", "c2"}
    _type_map = {"exec": "shell", "postex": "shell", "lateral": "lateral", "c2": "c2_session"}
    acts = (
        ctx.db.query(models.HostActivity)
        .filter(models.HostActivity.pid == ctx.pid, models.HostActivity.status == "done",
                models.HostActivity.activity_type.in_(_exec_types))
        .order_by(models.HostActivity.ts.asc()).all()
    )
    entry_gw_ips: set[str] = {sr.get("gateway_ip", "") for sr in ctx.scope_region_defs if sr.get("is_entry")}
    auto_pivot_by_cidr: dict[str, str | None] = {}
    sessions_by_scope: dict[str, list[dict]] = {}
    for act in acts:
        target_nid = ctx.hid_to_nid.get(act.host_id)
        if not target_nid:
            continue
        etype = _type_map.get(act.activity_type, "shell")
        target_host = next((h for h in ctx.hosts_meta if h["id"] == act.host_id), None)
        target_scope = _lookup_scope_for_ip((target_host or {}).get("ip") or "", ctx.scope_region_defs)
        target_cidr = target_scope["cidr"] if target_scope else ""
        from_nid, route_reason = _sb_p3_find_from_nid(ctx, act, target_nid, target_scope,
                                                        sessions_by_scope, auto_pivot_by_cidr, entry_gw_ips)
        if from_nid == target_nid:
            continue
        if (from_nid, target_nid, etype) in ctx.p1_access_pairs:
            _sb_p3_track_session(act, target_nid, target_host, target_cidr, sessions_by_scope)
            continue
        _sb_p3_add_edge(ctx, act, etype, from_nid, target_nid, route_reason)
        _sb_p3_track_session(act, target_nid, target_host, target_cidr, sessions_by_scope)


def _sb_p4_build_dc_map(hosts_meta: list) -> dict:
    dc_by_domain: dict = {}
    for h in hosts_meta:
        if _host_is_dc(h):
            dom = (h.get("domain") or "").lower()
            if dom:
                dc_by_domain.setdefault(dom, []).append(h)
    return {
        dom: min(dcs, key=lambda d: (d.get("ip") or "", d.get("id") or ""))
        for dom, dcs in dc_by_domain.items()
    }


def _sb_p4_domain_edges(ctx: _SBCtx) -> None:
    if not ctx.include_domain_edges:
        return
    primary_dc_by_domain = _sb_p4_build_dc_map(ctx.hosts_meta)
    for h in ctx.hosts_meta:
        dom = (h.get("domain") or "").lower()
        if not dom:
            continue
        target_nid = ctx.hid_to_nid.get(h["id"])
        if not target_nid:
            continue
        dc_h = primary_dc_by_domain.get(dom)
        if not dc_h:
            continue
        dc_nid = ctx.hid_to_nid.get(dc_h["id"])
        if not dc_nid or dc_nid == target_nid:
            continue
        if _add_smart_edge(ctx._eacc, dc_nid, target_nid, {
            "type": "domain_member", "label": f"domain: {dom}",
            "confidence": 0.8, "source": "auto",
            "reason": f"host.domain={dom} matches DC {dc_h.get('hostname') or dc_h.get('ip', '')}",
            "state": "inferred", "verified": False, "is_manual": False,
        }):
            ctx.edges_added += 1


def _sb_sb6_web_db_pair(ctx: _SBCtx, w: dict, w_nid: str, w_subnet: str, db_hosts: list) -> None:
    for d in db_hosts:
        if d["id"] == w["id"] or _get_subnet(d.get("ip") or "") != w_subnet:
            continue
        d_nid = ctx.hid_to_nid.get(d["id"])
        if not d_nid or d_nid == w_nid:
            continue
        if _add_smart_edge(ctx._eacc, w_nid, d_nid, {
            "type": "service_dep", "label": "web→db", "confidence": 0.5,
            "source": "service_inference",
            "reason": (f"heuristic: web ports on {w.get('hostname') or w.get('ip','')} "
                       f"+ DB ports on {d.get('hostname') or d.get('ip','')} in same /24"),
            "state": "inferred", "verified": False, "is_manual": False, "style": "dashed",
        }):
            ctx.edges_added += 1


def _sb_sb6_web_db_edges(ctx: _SBCtx) -> None:
    web_hosts = [h for h in ctx.hosts_meta if _infer_node_role(h) == "web_server"]
    db_hosts = [h for h in ctx.hosts_meta if _infer_node_role(h) == "database"]
    for w in web_hosts:
        w_subnet = _get_subnet(w.get("ip") or "")
        if not w_subnet:
            continue
        w_nid = ctx.hid_to_nid.get(w["id"])
        if not w_nid:
            continue
        _sb_sb6_web_db_pair(ctx, w, w_nid, w_subnet, db_hosts)


def _sb_sb6_ldap_host_edges(ctx: _SBCtx, h_nid: str, dom: str, dc_by_dom: dict) -> None:
    for dc_h in dc_by_dom[dom]:
        dc_nid = ctx.hid_to_nid.get(dc_h["id"])
        if not dc_nid or dc_nid == h_nid:
            continue
        if _add_smart_edge(ctx._eacc, h_nid, dc_nid, {
            "type": "service_dep", "label": "ldap", "confidence": 0.5,
            "source": "service_inference",
            "reason": (f"heuristic: domain-joined host depends on DC "
                       f"{dc_h.get('hostname') or dc_h.get('ip','')} for {dom} (LDAP/Kerberos)"),
            "state": "inferred", "verified": False, "is_manual": False, "style": "dashed",
        }):
            ctx.edges_added += 1


def _sb_sb6_ldap_edges(ctx: _SBCtx) -> None:
    dc_by_dom_sg: dict = {}
    for h in ctx.hosts_meta:
        dom = (h.get("domain") or "").lower()
        if _host_is_dc(h) and dom:
            dc_by_dom_sg.setdefault(dom, []).append(h)
    for h in ctx.hosts_meta:
        if _host_is_dc(h):
            continue
        dom = (h.get("domain") or "").lower()
        if not dom or dom not in dc_by_dom_sg:
            continue
        h_nid = ctx.hid_to_nid.get(h["id"])
        if not h_nid:
            continue
        _sb_sb6_ldap_host_edges(ctx, h_nid, dom, dc_by_dom_sg)


def _sb_sb6_service_graph(ctx: _SBCtx) -> None:
    if not ctx.include_service_graph:
        return
    _sb_sb6_web_db_edges(ctx)
    _sb_sb6_ldap_edges(ctx)


def _sb_key_hids_from_gateways(ctx: _SBCtx, key_hids: set) -> None:
    for sr in ctx.scope_region_defs:
        gw_ip = (sr.get("gateway_ip") or "").strip()
        if not gw_ip:
            continue
        for h in ctx.hosts_meta:
            if _host_matches_gateway_ip(h, gw_ip):
                key_hids.add(h["id"])


def _sb_build_key_hids(ctx: _SBCtx) -> set:
    key_hids: set[str] = {h["id"] for h in ctx.hosts_meta if _is_key_host(h)}
    for ha in (ctx.db.query(models.HostActivity)
               .filter(models.HostActivity.pid == ctx.pid, models.HostActivity.activity_type == "c2",
                       models.HostActivity.status == "done").all()):
        if ha.host_id:
            key_hids.add(ha.host_id)
    for note in ctx.db.query(models.CredHostNote).filter(models.CredHostNote.pid == ctx.pid).all():
        if note.access and note.host_id:
            key_hids.add(note.host_id)
    _sb_key_hids_from_gateways(ctx, key_hids)
    return key_hids


def _sb_p5_process_link(ctx: _SBCtx, link, key_hids: set, nid_to_hid: dict) -> None:
    src_nid = ctx.ip_to_nid.get(link.source_ip)
    dst_nid = ctx.ip_to_nid.get(link.target_ip)
    if not src_nid or not dst_nid:
        return
    if nid_to_hid.get(src_nid) not in key_hids or nid_to_hid.get(dst_nid) not in key_hids:
        return
    if _add_smart_edge(ctx._eacc, src_nid, dst_nid, {
        "type": link.link_type, "label": link.label or "",
        "confidence": link.confidence, "source": "auto",
        "reason": link.reason, "state": "inferred", "verified": False, "is_manual": False,
    }):
        ctx.edges_added += 1


def _sb_p5_subnet_edges(ctx: _SBCtx, key_hids: set, nid_to_hid: dict) -> None:
    if not ctx.include_subnet_edges:
        return
    manual_gw_by_subnet = {
        item["cidr"]: item.get("gateway_ip", "") for item in ctx.scope_region_defs if item.get("gateway_ip")
    }
    isolated_subnets = {sr["cidr"] for sr in ctx.scope_region_defs if sr.get("via_host_id")}
    for link in infer_links_smart(ctx.hosts_meta, manual_gw_by_subnet, isolated_subnets):
        _sb_p5_process_link(ctx, link, key_hids, nid_to_hid)


def _sb_p6_via_scope_edges(ctx: _SBCtx, sr: dict, via_nid: str, via_hid: str) -> None:
    for h in ctx.hosts_meta:
        if h["id"] == via_hid or not h.get("ip") or not _ip_in_network(h["ip"], sr["net_obj"]):
            continue
        dst_nid = ctx.hid_to_nid.get(h["id"])
        if not dst_nid:
            continue
        if _add_smart_edge(ctx._eacc, via_nid, dst_nid, {
            "type": "pivot", "label": sr["cidr"], "confidence": 0.8,
            "source": "scope_via",
            "reason": f"network {sr['cidr']} reachable only via this host",
            "state": "inferred", "verified": False, "is_manual": False,
        }):
            ctx.edges_added += 1


def _sb_p6_via_host_edges(ctx: _SBCtx) -> None:
    for sr in ctx.scope_region_defs:
        via_hid = sr.get("via_host_id", "").strip()
        if not via_hid:
            continue
        via_nid = ctx.hid_to_nid.get(via_hid)
        if not via_nid:
            continue
        _sb_p6_via_scope_edges(ctx, sr, via_nid, via_hid)


def _sb_p6_5_scope_edges(ctx: _SBCtx, sr: dict, pivot_nid: str, pivot_label: str,
                           pivot_hid: str, key_hids: set) -> None:
    for h in ctx.hosts_meta:
        if (h["id"] == pivot_hid or not h.get("ip")
                or not _ip_in_network(h["ip"], sr["net_obj"]) or h["id"] not in key_hids):
            continue
        dst_nid = ctx.hid_to_nid.get(h["id"])
        if not dst_nid:
            continue
        if _add_smart_edge(ctx._eacc, pivot_nid, dst_nid, {
            "type": "pivot", "label": f"via {pivot_label}", "confidence": 0.75,
            "source": "auto_pivot",
            "reason": f"network {sr['cidr']} reachable via auto-detected junction device {pivot_label}",
            "state": "inferred", "verified": False, "is_manual": False,
        }):
            ctx.edges_added += 1


def _sb_p6_5_junction_edges(ctx: _SBCtx, key_hids: set) -> None:
    entry_gw_ips: set[str] = {sr.get("gateway_ip", "") for sr in ctx.scope_region_defs if sr.get("is_entry")}
    for sr in ctx.scope_region_defs:
        if sr.get("is_entry") or sr.get("via_host_id"):
            continue
        pivot_h = _find_pivot_host(sr["net_obj"], ctx.scope_region_defs, ctx.hosts_meta, entry_gw_ips)
        if not pivot_h:
            continue
        pivot_nid = ctx.hid_to_nid.get(pivot_h["id"])
        if not pivot_nid:
            continue
        pivot_label = pivot_h.get("hostname") or pivot_h.get("ip") or ""
        _sb_p6_5_scope_edges(ctx, sr, pivot_nid, pivot_label, pivot_h["id"], key_hids)


def _sb_p13_collect_public_hosts(hosts_meta: list) -> list:
    result = []
    for h in hosts_meta:
        tags = {t.lower() for t in (h.get("tags") or [])}
        ip = h.get("ip") or ""
        if not h.get("is_attacker") and (tags & _PUBLIC_TAGS or (ip and not _is_rfc1918(ip))):
            result.append(h)
    return result


def _sb_p13_ensure_inet_node(ctx: _SBCtx) -> dict:
    inet_node = next((n for n in ctx.existing_nodes if n.get("id") == "vn-internet"), None)
    if inet_node:
        return inet_node
    attacker_n = next((n for n in ctx.existing_nodes if n.get("is_attacker")), None)
    base_x = (attacker_n.get("x", 0) - 200.0) if attacker_n else -200.0
    base_y = (attacker_n.get("y", 0) - 180.0) if attacker_n else -120.0
    inet_node = {
        "id": "vn-internet", "host_id": "", "label": "Internet",
        "ip": "", "ips": [], "ports": [], "services": [], "subnet": "0.0.0.0/0",
        "status": "external", "role": "cloud", "type": "cloud", "notes": "",
        "is_attacker": False, "domain": "", "tags": ["virtual", "internet"],
        "x": base_x, "y": base_y, "manually_positioned": False, "auto_positioned": True, "virtual": True,
    }
    ctx.existing_nodes.append(inet_node)
    ctx.node_by_id[inet_node["id"]] = inet_node
    ctx.nodes_added += 1
    return inet_node


def _sb_p13_internet_facing(ctx: _SBCtx) -> None:
    if not ctx.include_internet_facing:
        return
    public_hosts = _sb_p13_collect_public_hosts(ctx.hosts_meta)
    if not public_hosts:
        return
    inet_nid = _sb_p13_ensure_inet_node(ctx)["id"]
    for h in public_hosts:
        dst_nid = ctx.hid_to_nid.get(h["id"])
        if not dst_nid:
            continue
        tags = {t.lower() for t in (h.get("tags") or [])}
        reason = ("tagged public/exposed" if tags & _PUBLIC_TAGS
                  else f"public IP {h.get('ip')} (not in RFC1918)")
        if _add_smart_edge(ctx._eacc, inet_nid, dst_nid, {
            "type": "internet_facing", "label": "internet", "confidence": 0.9,
            "source": "internet_facing", "reason": reason,
            "state": "inferred", "verified": False, "is_manual": False,
        }):
            ctx.edges_added += 1


_TIER0_TAGS = {"da", "ea", "krbtgt", "domain-admin", "enterprise-admin", "bh:dc", "bh:da-member", "dc"}
_TIER1_TAGS = {"bh:admin", "admin", "local-admin"}
_TIER1_EDGE_TYPES = {"smb_admin", "admin_to", "local_admin", "dcsync", "generic_all",
                     "write_dacl", "generic_write", "write_owner", "ext_rights", "allowed_to_delegate"}


def _sb_sb3_collect_tier1_hids(ctx: _SBCtx, manual_edges: list, nid_to_hid: dict) -> set:
    tier1_target_hids: set[str] = set()
    for e in manual_edges + ctx._eacc.new_auto_edges:
        if (e.get("type") or "").lower() not in _TIER1_EDGE_TYPES:
            continue
        to_hid = nid_to_hid.get(e.get("to")) or e.get("to_host_id")
        if to_hid:
            tier1_target_hids.add(to_hid)
    try:
        for act in ctx.db.query(models.HostActivity).filter(
            models.HostActivity.pid == ctx.pid, models.HostActivity.technique.ilike("T1003%")
        ).all():
            if act.host_id:
                tier1_target_hids.add(act.host_id)
    except Exception as e:
        _log.debug("tier1 credential-access activity lookup failed (pid=%s): %s", ctx.pid, e)
    return tier1_target_hids


def _sb_sb3_label_host(ctx: _SBCtx, h, tier1_target_hids: set) -> None:
    tags_lower = {(t or "").lower() for t in (h.tags or [])}
    role_lower = (h.role or "").lower()
    is_tier0 = role_lower == "domain_controller" or bool(tags_lower & _TIER0_TAGS)
    is_tier1 = h.id in tier1_target_hids or bool(tags_lower & _TIER1_TAGS)
    if is_tier0:
        tier = 0
    elif is_tier1:
        tier = 1
    else:
        tier = 2
    ctx.tier_counts[f"tier_{tier}"] += 1
    n = ctx.node_by_id.get(ctx.hid_to_nid.get(h.id))
    if n is not None:
        n["tier"] = tier
        node_tags = [t for t in (n.get("tags") or []) if not (isinstance(t, str) and t.startswith("tier:"))]
        node_tags.append(f"tier:{tier}")
        n["tags"] = node_tags


def _sb_sb3_tier_zones(ctx: _SBCtx, manual_edges: list) -> None:
    if not ctx.include_tier_zones:
        return
    nid_to_hid = {n.get("id"): n.get("host_id") for n in ctx.existing_nodes if n.get("id")}
    tier1_target_hids = _sb_sb3_collect_tier1_hids(ctx, manual_edges, nid_to_hid)
    for h in ctx.all_hosts:
        _sb_sb3_label_host(ctx, h, tier1_target_hids)


def _sb_region_node_positions(ctx: _SBCtx, net_obj) -> list:
    in_scope_hosts = [h for h in ctx.hosts_meta if h.get("ip") and _ip_in_network(h["ip"], net_obj)]
    positions = []
    for h in in_scope_hosts:
        n = ctx.node_by_id.get(ctx.hid_to_nid.get(h["id"]))
        if n:
            positions.append((n.get("x", 0), n.get("y", 0)))
    return positions


def _sb_process_scope_region(ctx: _SBCtx, sr: dict, existing_region_by_note: dict,
                               existing_regions: list) -> None:
    cidr_str = sr["cidr"]
    node_positions = _sb_region_node_positions(ctx, sr["net_obj"])
    if not node_positions:
        return
    pad = 60
    min_x = min(p[0] for p in node_positions) - pad
    min_y = min(p[1] for p in node_positions) - pad
    max_x = max(p[0] for p in node_positions) + 160 + pad
    max_y = max(p[1] for p in node_positions) + 100 + pad
    via_host_id = sr.get("via_host_id", "")
    scope_stroke, scope_fill = _scope_region_colors(cidr_str, sr["in_scope"], via_host_id)
    via_host_label = ""
    if via_host_id:
        via_h = next((h for h in ctx.hosts_meta if h["id"] == via_host_id), None)
        via_host_label = (via_h or {}).get("hostname") or (via_h or {}).get("ip") or via_host_id[:8]
    label = (f"{sr['description'] or cidr_str} (via {via_host_label})" if via_host_id
             else (sr["description"] or cidr_str))
    zone_type = "scope_pivot" if via_host_id else "scope"
    existing_r = existing_region_by_note.get(cidr_str)
    if existing_r:
        existing_r.update({"fill": scope_fill, "stroke": scope_stroke,
                           "zone_type": zone_type, "label": label, "updated_at": ts_now()})
        if via_host_id:
            existing_r["via_host_id"] = via_host_id
        elif "via_host_id" in existing_r:
            existing_r.pop("via_host_id", None)
        return
    region_entry: dict = {
        "id": new_id("r"), "x": min_x, "y": min_y, "w": max_x - min_x, "h": max_y - min_y,
        "label": label, "note": cidr_str, "fill": scope_fill, "stroke": scope_stroke,
        "zone_type": zone_type, "updated_at": ts_now(), "version": 1,
    }
    if via_host_id:
        region_entry["via_host_id"] = via_host_id
    existing_regions.append(region_entry)
    ctx.regions_added += 1


def _sb_build_regions(ctx: _SBCtx) -> None:
    if not (ctx.include_regions and ctx.scope_region_defs):
        return
    existing_regions = get_regions(ctx.network.id, ctx.db)
    existing_region_by_note = {(r.get("note") or "").strip(): r for r in existing_regions if r.get("note")}
    for sr in ctx.scope_region_defs:
        _sb_process_scope_region(ctx, sr, existing_region_by_note, existing_regions)
    replace_regions(ctx.network.id, ctx.network.pid, existing_regions, ctx.db)
    ctx.db.flush()


def _sb_regions_and_positioning(ctx: _SBCtx, preserve_positions: bool) -> None:
    _sb_build_regions(ctx)
    try:
        scope_gw_host_ids: dict[str, str] = {}
        for sr in ctx.scope_region_defs:
            gw_ip = (sr.get("gateway_ip") or "").strip()
            if not gw_ip:
                continue
            matched = next((h for h in ctx.hosts_meta if _host_matches_gateway_ip(h, gw_ip)), None)
            if matched:
                scope_gw_host_ids[sr["cidr"]] = matched["id"]
        _all_regions = get_regions(ctx.network.id, ctx.db)
        region_by_cidr = {str(r.get("note") or "").strip(): r for r in _all_regions if r.get("note")}
        gateway_scopes_by_host: dict[str, list[str]] = {}
        for cidr, host_id in scope_gw_host_ids.items():
            gateway_scopes_by_host.setdefault(host_id, []).append(cidr)
        transit_scopes_by_host: dict[str, list[str]] = {}
        for host in ctx.hosts_meta:
            memberships = _host_scope_memberships(host, ctx.scope_region_defs)
            if len(memberships) >= 2:
                transit_scopes_by_host[host["id"]] = memberships
        _sb_position_transit_nodes(ctx, region_by_cidr, gateway_scopes_by_host,
                                   transit_scopes_by_host, preserve_positions)
        _sb_attacker_uplink(ctx, region_by_cidr, scope_gw_host_ids, transit_scopes_by_host, _all_regions)
    except Exception as _exc:
        _log.warning("smart_build attacker/uplink positioning failed: %s", _exc, exc_info=True)


def _sb_place_on_single_scope(node: dict, region_by_cidr: dict, scope: str) -> None:
    region = region_by_cidr.get(scope)
    if not region:
        return
    centers = {cidr: _region_center(reg) for cidr, reg in region_by_cidr.items() if cidr != scope}
    if not centers:
        node["x"], node["y"] = _place_on_region_edge(region, "left")
        return
    own_cx, own_cy = _region_center(region)
    _, (other_cx, _) = min(
        centers.items(), key=lambda item: abs(item[1][0] - own_cx) + abs(item[1][1] - own_cy)
    )
    node["x"], node["y"] = _place_on_region_edge(region, "right" if other_cx >= own_cx else "left")


def _sb_position_single_node(node: dict, region_by_cidr: dict, gateway_scopes_by_host: dict,
                              transit_scopes_by_host: dict, preserve_positions: bool) -> None:
    if node.get("manually_positioned"):
        return
    if preserve_positions and node.get("x") is not None and node.get("y") is not None:
        return
    host_id = node.get("host_id") or ""
    related_scopes = transit_scopes_by_host.get(host_id) or gateway_scopes_by_host.get(host_id, [])
    if len(related_scopes) >= 2:
        region_a = region_by_cidr.get(related_scopes[0])
        region_b = region_by_cidr.get(related_scopes[1])
        if region_a and region_b:
            node["x"], node["y"] = _place_between_regions(region_a, region_b)
            return
    if len(related_scopes) == 1:
        _sb_place_on_single_scope(node, region_by_cidr, related_scopes[0])


def _sb_position_transit_nodes(ctx: _SBCtx, region_by_cidr: dict, gateway_scopes_by_host: dict,
                                transit_scopes_by_host: dict, preserve_positions: bool) -> None:
    for node in ctx.existing_nodes:
        _sb_position_single_node(node, region_by_cidr, gateway_scopes_by_host,
                                 transit_scopes_by_host, preserve_positions)


def _sb_attacker_uplink_edge(ctx: _SBCtx, anchor_scope_cidr: str, entry_gw_host_id: str | None,
                              transit_candidates: list) -> None:
    preferred_hid = entry_gw_host_id or (transit_candidates[0] if transit_candidates else None)
    if not (preferred_hid and ctx.attacker_nids):
        return
    preferred_nid = ctx.hid_to_nid.get(preferred_hid)
    if not preferred_nid:
        return
    is_gateway = preferred_hid == entry_gw_host_id
    is_transit = preferred_hid in transit_candidates
    if is_gateway:
        uplink_label = "entry"
    elif is_transit:
        uplink_label = "vpn access"
    else:
        uplink_label = "direct access"
    if is_gateway:
        uplink_reason = f"attacker enters {anchor_scope_cidr} via entry gateway"
    elif is_transit:
        uplink_reason = f"attacker reaches entry scope {anchor_scope_cidr} via transit host"
    else:
        uplink_reason = f"attacker reaches entry scope {anchor_scope_cidr} via configured gateway"
    if _add_smart_edge(ctx._eacc, ctx.attacker_nids[0], preferred_nid, {
        "type": "uplink", "label": uplink_label, "confidence": 0.9, "source": "auto",
        "reason": uplink_reason, "state": "inferred", "verified": False, "is_manual": False,
    }):
        ctx.edges_added += 1


def _sb_attacker_uplink(ctx: _SBCtx, region_by_cidr: dict, scope_gw_host_ids: dict,
                         transit_scopes_by_host: dict, all_regions: list) -> None:
    entry_scope_cidr = next((item["cidr"] for item in ctx.scope_region_defs if item.get("is_entry")), "")
    entry_region = region_by_cidr.get(entry_scope_cidr) if entry_scope_cidr else None
    leftmost_region = min(
        (r for r in all_regions if r.get("zone_type") == "scope"),
        key=lambda item: float(item.get("x") or 0), default=None,
    )
    anchor_region = entry_region or leftmost_region
    if not anchor_region:
        return
    attacker_nodes = [
        node for node in ctx.existing_nodes
        if node.get("is_attacker") and not node.get("manually_positioned")
        and not (ctx.preserve_positions and node.get("x") is not None and node.get("y") is not None)
    ]
    base_x, base_y = _place_on_region_edge(anchor_region, "left")
    for idx, node in enumerate(attacker_nodes):
        node["x"] = base_x - 120.0
        node["y"] = base_y + idx * 90.0
    anchor_scope_cidr = str(anchor_region.get("note") or "").strip()
    transit_candidates = [hid for hid, scopes in transit_scopes_by_host.items() if anchor_scope_cidr in scopes]
    _sb_attacker_uplink_edge(ctx, anchor_scope_cidr, scope_gw_host_ids.get(anchor_scope_cidr),
                             transit_candidates)


def _sb_zone_types(ctx: _SBCtx) -> None:
    regions_with_zone = [
        r for r in get_regions(ctx.network.id, ctx.db)
        if r.get("zone_type") and r.get("zone_type") != "scope"
    ]
    if not regions_with_zone:
        return
    for node in ctx.existing_nodes:
        nx, ny = node.get("x", 0), node.get("y", 0)
        for region in regions_with_zone:
            rx, ry = region.get("x", 0), region.get("y", 0)
            rw, rh = region.get("w", 1), region.get("h", 1)
            if rx <= nx <= rx + rw and ry <= ny <= ry + rh:
                node["zone_type"] = region.get("zone_type")
                break


def _sb_infer_entry_cidrs(scope_region_defs: list) -> list:
    result = []
    for item in scope_region_defs:
        if not item.get("is_entry"):
            continue
        try:
            result.append(ipaddress.ip_network(item["cidr"], strict=False))
        except ValueError:
            pass
    return result


def _sb_infer_via_single(sr: dict, scope_region_defs: list, junction_candidates: list,
                          all_hosts: list) -> bool:
    if sr.get("is_entry") or sr.get("via_host_id"):
        return False
    gw_ip = (sr.get("gateway_ip") or "").strip()
    gw_matches = any(
        gw_ip and ((h.ip or "") == gw_ip or gw_ip in {str(ip).strip() for ip in (h.ips or [])})
        for h in all_hosts
    )
    if gw_matches:
        return False
    entry_cidrs = _sb_infer_entry_cidrs(scope_region_defs)
    candidates_outside = [h for h in junction_candidates if h.ip and not _ip_in_network(h.ip, sr["net_obj"])]
    candidates_outside.sort(key=lambda h: (0 if _h_in_any_cidr(h, entry_cidrs) else 1))
    if candidates_outside:
        sr["via_host_id"] = candidates_outside[0].id
        sr["auto_via_host"] = True
        return True
    return False


def _sb_infer_via_hosts(scope_region_defs: list, junction_candidates: list, all_hosts: list) -> int:
    return sum(
        1 for sr in scope_region_defs
        if _sb_infer_via_single(sr, scope_region_defs, junction_candidates, all_hosts)
    )


def _sb_merge_existing_node(ctx: _SBCtx, en: dict, p: dict) -> None:
    is_pinned = en.get("manually_positioned") and ctx.keep_manual_positions
    has_pos = en.get("x") is not None and en.get("y") is not None
    if not is_pinned and not (ctx.preserve_positions and has_pos):
        en["x"] = p["x"]
        en["y"] = p["y"]
        en["auto_positioned"] = True
        en["manually_positioned"] = False
    if p.get("domain") and not en.get("domain"):
        en["domain"] = p["domain"]
    if p.get("tags"):
        en["tags"] = p["tags"]
    if p.get("ips"):
        en["ips"] = p["ips"]
    if p.get("status"):
        host_rank = _STATUS_RANK.get(p["status"], 0)
        node_rank = _STATUS_RANK.get(en.get("status") or "unknown", 0)
        if host_rank >= node_rank:
            en["status"] = p["status"]
    inferred_role = _infer_node_role(p)
    if inferred_role and inferred_role not in ("unknown", "server"):
        en["role"] = inferred_role
    ctx.nodes_updated += 1


def _sb_create_new_node(ctx: _SBCtx, p: dict, h_id: str, h_ip: str,
                         node_by_hid: dict, node_by_ip: dict) -> None:
    inferred_role = _infer_node_role(p)
    new_node = {
        "id": new_id("nd"), "host_id": h_id,
        "label": p.get("hostname") or h_ip, "ip": h_ip,
        "ips": p.get("ips") or [h_ip], "ports": p.get("ports", []),
        "services": p.get("services", []),
        "subnet": p.get("subnet") or _get_subnet(h_ip),
        "status": p.get("status") or "unknown", "role": inferred_role,
        "type": _node_type_for(p), "notes": "",
        "is_attacker": bool(p.get("is_attacker")), "domain": p.get("domain", ""),
        "tags": p.get("tags", []), "x": p["x"], "y": p["y"],
        "manually_positioned": False, "auto_positioned": True,
    }
    ctx.existing_nodes.append(new_node)
    node_by_hid[h_id] = new_node
    node_by_ip[h_ip] = new_node
    ctx.nodes_added += 1


def _sb_update_nodes(ctx: _SBCtx, positioned: list, node_by_hid: dict, node_by_ip: dict) -> None:
    for p in positioned:
        h_id = p.get("id", "")
        h_ip = p.get("ip", "")
        en = node_by_hid.get(h_id) or node_by_ip.get(h_ip)
        if en:
            _sb_merge_existing_node(ctx, en, p)
        else:
            _sb_create_new_node(ctx, p, h_id, h_ip, node_by_hid, node_by_ip)


_JUNCTION_ROLES = {"router", "firewall", "network_device", "pivot", "jump_host"}
_JUNCTION_TAGS = {"router", "firewall", "gateway", "vpn", "pivot"}
_JUNCTION_PREFIXES = ("VPN", "GW", "FW", "ROUTER", "EDGE", "PROXY")


def _is_junction_host(h) -> bool:
    if h.is_attacker:
        return False
    if (h.role or "").lower() in _JUNCTION_ROLES:
        return True
    if {(t or "").lower() for t in (h.tags or [])} & _JUNCTION_TAGS:
        return True
    hn = (h.hostname or "").upper()
    return any(hn.startswith(p) or hn.startswith(p + "-") or hn.startswith(p + "_")
               for p in _JUNCTION_PREFIXES)


def _sb_host_meta(h, scope_cidrs: list) -> dict:
    return {
        "id": h.id, "ip": h.ip, "hostname": h.hostname, "os": h.os,
        "status": h.status, "role": h.role, "is_attacker": h.is_attacker,
        "ips": h.ips or [], "ports": h.ports or [], "services": h.services or [],
        "tags": h.tags or [], "domain": h.domain or "",
        "subnet": _annotate_ip_subnet(h.ip or "", scope_cidrs),
    }


def _sb_find_junction_candidates(all_hosts: list) -> list:
    return [h for h in all_hosts if _is_junction_host(h)]


def _sb_init_roles(ctx: _SBCtx, auto_assign_roles: bool) -> None:
    if not auto_assign_roles:
        return
    for h in ctx.all_hosts:
        if (h.role or "").lower() not in ("", "unknown"):
            continue
        inferred = _auto_assign_host_role(h)
        if inferred and inferred != (h.role or ""):
            ctx.role_undo_ops.append({
                "entity": "host", "id": h.id, "type": "patch",
                "patch": {"role": h.role or ""},
            })
            h.role = inferred
            ctx.roles_assigned += 1
    if ctx.roles_assigned:
        ctx.db.flush()


def _sb_init_scope_defs(ctx: _SBCtx) -> None:
    try:
        for s in ctx.db.query(models.Scope).filter(models.Scope.pid == ctx.pid).all():
            val = (s.value or "").strip()
            if "/" not in val:
                continue
            try:
                net_obj = ipaddress.ip_network(val, strict=False)
                ctx.scope_cidrs.append(net_obj)
                ctx.scope_region_defs.append({
                    "cidr": val, "net_obj": net_obj,
                    "description": s.description or "",
                    "in_scope": s.in_scope,
                    "gateway_ip": (s.gateway_ip or "").strip(),
                    "is_entry": bool(getattr(s, "is_entry", False)),
                    "via_host_id": (getattr(s, "via_host_id", None) or "").strip(),
                })
            except ValueError:
                pass
    except Exception as e:
        _log.debug("scope-region definition build failed (pid=%s): %s", ctx.pid, e)


def _sb_init_manual_edges(ctx: _SBCtx) -> None:
    ctx.manual_edges = [
        e for e in ctx.existing_edges
        if e.get("source") != "auto" or e.get("is_manual") or e.get("manual_override") or e.get("verified")
    ]
    for _e in ctx.manual_edges:
        if _e.get("mitre_techniques"):
            continue
        _src = (_e.get("source") or "").lower()
        if _src in ("cred_validation", "bulk_exec", "host_activity", "pivot_observation"):
            _tags = _edge_action_tags(_src)
            if _tags:
                _e.update(_tags)
    suppressed = set(ctx.existing_meta.get(AUTO_LINK_SUPPRESSIONS_KEY) or [])
    manual_keys = {(e.get("from"), e.get("to")) for e in ctx.manual_edges} | {
        (e.get("to"), e.get("from")) for e in ctx.manual_edges
    }
    ctx._eacc = _EdgeAcc(set(manual_keys), ctx.node_by_id, suppressed)


@dataclass
class _SmartBuildOpts:
    keep_manual_positions: bool = True
    preserve_positions: bool = True
    create_missing_networks: bool = True
    include_access_edges: bool = True
    include_domain_edges: bool = True
    include_subnet_edges: bool = True
    include_regions: bool = True
    include_internet_facing: bool = True
    include_tier_zones: bool = True
    include_service_graph: bool = False
    auto_assign_roles: bool = True
    confidence_decay_days: float = 14.0
    dry_run: bool = False


def _run_smart_build(
    pid: str,
    db: Session,
    opts: _SmartBuildOpts = _SmartBuildOpts(),
) -> dict:
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        return {"ok": False, "error": _MSG_PROJECT_NOT_FOUND}

    all_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    if not all_hosts:
        return {"ok": True, "nodes_total": 0, "nodes_added": 0, "edges_added": 0, "regions_added": 0}

    ctx = _SBCtx()
    ctx.pid = pid
    ctx.db = db
    ctx.dry_run = opts.dry_run
    ctx.keep_manual_positions = opts.keep_manual_positions
    ctx.preserve_positions = opts.preserve_positions
    ctx.include_access_edges = opts.include_access_edges
    ctx.include_domain_edges = opts.include_domain_edges
    ctx.include_subnet_edges = opts.include_subnet_edges
    ctx.include_regions = opts.include_regions
    ctx.include_internet_facing = opts.include_internet_facing
    ctx.include_tier_zones = opts.include_tier_zones
    ctx.include_service_graph = opts.include_service_graph
    ctx.confidence_decay_days = opts.confidence_decay_days
    ctx.all_hosts = all_hosts

    _sb_init_roles(ctx, opts.auto_assign_roles)

    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network:
        if not opts.create_missing_networks:
            return {"ok": False, "error": _MSG_NO_NETWORK_MAP}
        network = models.Network(
            id=new_id("net"), pid=pid, name="Network", background="#07080b", meta_json={},
        )
        db.add(network)
        db.flush()
    ctx.network = network
    ctx.existing_nodes = get_nodes(network.id, db)
    ctx.existing_edges = get_edges(network.id, db)
    ctx.existing_meta = deepcopy(network.meta_json or {})

    _sb_init_scope_defs(ctx)

    ctx.auto_via_count = _sb_infer_via_hosts(
        ctx.scope_region_defs, _sb_find_junction_candidates(ctx.all_hosts), ctx.all_hosts)

    ctx.hosts_meta = [_sb_host_meta(h, ctx.scope_cidrs) for h in ctx.all_hosts]

    node_by_hid = {n.get("host_id"): n for n in ctx.existing_nodes if n.get("host_id")}
    node_by_ip = {n.get("ip"): n for n in ctx.existing_nodes if n.get("ip")}
    positioned = compute_layout(
        ctx.hosts_meta, ctx.existing_nodes, ctx.keep_manual_positions, ctx.existing_edges
    )
    _sb_update_nodes(ctx, positioned, node_by_hid, node_by_ip)

    ctx.ip_to_nid = {n.get("ip"): n.get("id") for n in ctx.existing_nodes if n.get("ip")}
    ctx.hid_to_nid = {n.get("host_id"): n.get("id") for n in ctx.existing_nodes if n.get("host_id")}
    ctx.node_by_id = {n.get("id"): n for n in ctx.existing_nodes if n.get("id")}

    _sb_init_manual_edges(ctx)

    ctx.attacker_hids = {
        h.id for h in ctx.all_hosts if h.is_attacker or (h.role or "").lower() == "attacker"
    }
    ctx.attacker_nids = list(dict.fromkeys(
        [ctx.hid_to_nid[hid] for hid in ctx.attacker_hids if ctx.hid_to_nid.get(hid)]
        + [n.get("id") for n in ctx.existing_nodes if n.get("is_attacker") and n.get("id")]
    ))

    _sb_p1_access_edges(ctx)
    _sb_p2_bulk_exec(ctx)
    _sb_p3_host_activity(ctx)
    _sb_p4_domain_edges(ctx)
    _sb_sb6_service_graph(ctx)
    key_hids = _sb_build_key_hids(ctx)
    nid_to_hid = {n.get("id"): n.get("host_id") for n in ctx.existing_nodes if n.get("id")}
    _sb_p5_subnet_edges(ctx, key_hids, nid_to_hid)
    _sb_p6_via_host_edges(ctx)
    _sb_p6_5_junction_edges(ctx, key_hids)
    _sb_p13_internet_facing(ctx)
    _sb_sb3_tier_zones(ctx, ctx.manual_edges)
    _sb_regions_and_positioning(ctx, ctx.preserve_positions)
    _sb_zone_types(ctx)

    build_ts = ts_now()
    ctx.existing_meta["last_smart_build"] = build_ts
    ctx.existing_meta["last_smart_build_breakdown"] = dict(ctx._eacc.edges_by_source)

    result = {
        "ok": True,
        "nodes_total": len(ctx.existing_nodes),
        "nodes_added": ctx.nodes_added,
        "nodes_updated": ctx.nodes_updated,
        "edges_added": ctx.edges_added,
        "edges_stale": ctx._eacc.edges_stale,
        "edges_by_source": dict(ctx._eacc.edges_by_source),
        "regions_added": ctx.regions_added,
        "tier_counts": ctx.tier_counts,
        "roles_assigned": ctx.roles_assigned,
        "auto_via_host_assigned": ctx.auto_via_count,
        "last_smart_build": build_ts,
        "dry_run": ctx.dry_run,
        "_role_undo_ops": ctx.role_undo_ops,
    }

    if ctx.dry_run:
        db.rollback()
        return result

    replace_nodes(network.id, network.pid, ctx.existing_nodes, db)
    replace_edges(network.id, network.pid, ctx.manual_edges + ctx._eacc.new_auto_edges, db)
    network.meta_json = ctx.existing_meta
    db.commit()

    result_net = schemas.Network.from_orm_obj(network)
    bcast(pid, "network", "layout_applied", {
        "network": result_net.model_dump(),
        "updated_at": build_ts,
    })

    return result


class SmartBuildRequest(BaseModel):
    keep_manual_positions: bool = True
    preserve_positions: bool = True
    create_missing_networks: bool = True
    include_access_edges: bool = True
    include_domain_edges: bool = True
    include_subnet_edges: bool = True
    include_regions: bool = True
    include_internet_facing: bool = True
    include_tier_zones: bool = True
    include_service_graph: bool = False
    auto_assign_roles: bool = True
    confidence_decay_days: float = 14.0
    dry_run: bool = False


@router.post("/smart-build", dependencies=[Depends(require_topo_apply)])
def topology_smart_build(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    body: SmartBuildRequest = SmartBuildRequest(),
    request: Request = None,
):
    username = getattr(getattr(request, "state", None), "username", None) if request else None
    job = start_job(
        db,
        pid,
        "topology",
        "Topology smart-build",
        created_by=username or "",
        connector_key="topology",
        operation="smart_build",
        related_entity=("network", pid),
        request_json=body.model_dump(),
    )
    result = _run_smart_build(
        pid,
        db,
        opts=_SmartBuildOpts(
            keep_manual_positions=body.keep_manual_positions,
            preserve_positions=body.preserve_positions,
            create_missing_networks=body.create_missing_networks,
            include_access_edges=body.include_access_edges,
            include_domain_edges=body.include_domain_edges,
            include_subnet_edges=body.include_subnet_edges,
            include_regions=body.include_regions,
            include_internet_facing=body.include_internet_facing,
            include_tier_zones=body.include_tier_zones,
            include_service_graph=body.include_service_graph,
            auto_assign_roles=body.auto_assign_roles,
            confidence_decay_days=body.confidence_decay_days,
            dry_run=body.dry_run,
        ),
    )
    if not result.get("ok"):
        err = result.get("error", "Smart build failed")
        finish_job(db, job, status="failed", error_output=err)
        raise HTTPException(404 if "not found" in err.lower() else 400, err)

    role_undo_ops = result.pop("_role_undo_ops", []) or []
    if role_undo_ops and not body.dry_run:
        log_event(
            db,
            pid,
            username,
            "audit",
            "smart_build_completed",
            f"Smart build: {result.get('roles_assigned', 0)} role(s) inferred, "
            f"{result.get('edges_added', 0)} edges, {result.get('regions_added', 0)} regions",
            {
                "roles_assigned": result.get("roles_assigned", 0),
                "edges_added": result.get("edges_added", 0),
                "regions_added": result.get("regions_added", 0),
                "tier_counts": result.get("tier_counts", {}),
                "reversible": True,
                "undo": {"type": "batch", "operations": role_undo_ops[:1000]},
                "undo_note": (
                    "Restores host.role for hosts that smart-build auto-inferred. "
                    "Network nodes / edges / regions are NOT reverted — re-run "
                    "smart-build without auto_assign_roles to regenerate the map."
                ),
            },
        )
        db.commit()

    finish_job(db, job, status="done", result=result)
    return {**result, "job_id": job.id}
