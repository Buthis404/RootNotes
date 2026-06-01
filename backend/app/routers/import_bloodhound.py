"""
BloodHound importer — POST /api/projects/{pid}/import/bloodhound

Accepts a ZIP file produced by SharpHound / bloodhound-python.
Parses:
  *_computers.json  → Hosts, AdminTo edges, Unconstrained Delegation tags
  *_users.json      → Creds, DA membership
  *_groups.json     → DA / EA group membership resolution
  *_sessions.json   → HasSession edges (informational access edges)

Stores access edges in network.edges_json with from_host_id/to_host_id fields
so attack_graph.py can read them even before a topology auto-build is run.
"""

import io
import json
import logging
import uuid
import zipfile
from collections import defaultdict

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import log_event
from ..core.network_data import get_edges, replace_edges
from ..core.utils import new_id, ts_now
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["import_bloodhound"])

_DA_GROUP_NAMES = {"domain admins", "enterprise admins", "schema admins", "administrators"}
_HIGH_PRIV_ACES = {"genericall", "genericwrite", "writedacl", "writeowner", "allextendedright"}
_DELEGATION_ACES = {"allowedtoactonbehalfofotheridentity", "allextendedright"}

_WELL_KNOWN_DA_RIDS = {"-512", "-519", "-518", "-544"}  # DA, EA, Schema, Administrators


def _now() -> str:
    return ts_now()


def _edge_id() -> str:
    return "bh_" + uuid.uuid4().hex[:10]


def _host_short(name: str) -> str:
    """SDOTSON.EDU.STF → SDOTSON"""
    return name.split(".")[0].upper() if name else ""


def _user_short(name: str) -> str:
    """S_DOTSON@EDU.STF → s_dotson"""
    return name.split("@")[0].lower() if name else name.lower()


def _get_items(data: dict) -> list:
    """Handle both old {computers:[...]} and new {data:[...]} formats."""
    return (
        data.get("data")
        or data.get("computers")
        or data.get("users")
        or data.get("groups")
        or data.get("sessions")
        or []
    )


# ── Main parser ─────────────────────────────────────────────────────────────


def parse_bloodhound_zip(pid: str, content: bytes, db: Session) -> dict:
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(400, "Invalid ZIP file")

    file_map: dict[str, dict] = {}
    for name in zf.namelist():
        lower = name.lower()
        for key in ("computers", "users", "groups", "sessions", "ous", "domains", "gpos"):
            if key in lower and lower.endswith(".json"):
                try:
                    file_map[key] = json.loads(zf.read(name))
                except Exception as e:
                    logger.debug("skipping unparseable BloodHound file %s (%s): %s", name, key, e)
                break

    if not file_map:
        raise HTTPException(400, "No recognisable BloodHound JSON files found in ZIP")

    return _process(pid, file_map, db)


def parse_bloodhound_json(pid: str, key: str, content: bytes, db: Session) -> dict:
    try:
        data = json.loads(content)
    except Exception:
        raise HTTPException(400, f"Invalid JSON in {key}")
    return _process(pid, {key: data}, db)


# ── Processing pipeline ──────────────────────────────────────────────────────


def _add_host_tag(host: models.Host, tag: str) -> bool:
    tags = list(host.tags or [])
    if tag in tags:
        return False
    tags.append(tag)
    host.tags = tags
    return True


def _bh_add_edge(
    seen_pairs: set, new_edges: list, from_hid: str, to_hid: str,
    edge_type: str, label: str, verified: bool = False, confidence: float = 0.7,
    reason: str = "", source: str = "bloodhound",
) -> bool:
    if not from_hid or not to_hid or from_hid == to_hid:
        return False
    key = (from_hid, to_hid, edge_type)
    if key in seen_pairs:
        return False
    seen_pairs.add(key)
    new_edges.append({
        "id": _edge_id(),
        "from_host_id": from_hid,
        "to_host_id": to_hid,
        "type": edge_type,
        "label": label,
        "verified": verified,
        "confidence": confidence,
        "state": "confirmed" if verified else "inferred",
        "source": source,
        "reason": reason,
        "is_manual": False,
    })
    return True


def _bh_dc_or_tag(h) -> bool:
    return h.role == "domain_controller" or "dc" in {(t or "").lower() for t in (h.tags or [])}


def _bh_build_index(existing_hosts: list, existing_creds: list) -> tuple[dict, dict]:
    host_by_hostname = {(h.hostname or "").upper(): h for h in existing_hosts if h.hostname}
    cred_by_username: dict = {}
    for c in existing_creds:
        key = (c.username or "").lower()
        if key not in cred_by_username or c.service in ("AD", "os"):
            cred_by_username[key] = c
    return host_by_hostname, cred_by_username


def _bh_upsert_computer(pid: str, db: Session, hostname: str, os_str: str, unconstrained: bool,
                         domain: str, host_by_hn: dict, stats: dict) -> object:
    host = host_by_hn.get(hostname)
    if host:
        if os_str and not host.os:
            host.os = os_str
        tags = list(host.tags or [])
        if "bloodhound" not in tags:
            tags.append("bloodhound")
        if unconstrained and "unconstrained-delegation" not in tags:
            tags.append("unconstrained-delegation")
        host.tags = tags
        stats["hosts_updated"] += 1
    else:
        host = models.Host(
            id=new_id("hst"), pid=pid, ip="", hostname=hostname,
            os=os_str or "Windows", status="scanned", ports=[], services=[],
            tags=["bloodhound"] + (["unconstrained-delegation"] if unconstrained else []),
            notes="", domain=domain.lower(), role="unknown",
            is_attacker=False, import_source="bloodhound",
        )
        db.add(host)
        db.flush()
        host_by_hn[hostname] = host
        stats["hosts_created"] += 1
    return host


def _bh_process_computers(
    pid: str, db: Session, computers_raw: list,
    host_by_hn: dict, sid_to_hid: dict, sid_to_name: dict,
    stats: dict, domain: str,
) -> str:
    for comp in computers_raw:
        props = comp.get("Properties", {})
        full_name: str = props.get("name", "")
        sid: str = props.get("objectid", "") or comp.get("ObjectIdentifier", "")
        hostname = _host_short(full_name)
        os_str: str = props.get("operatingsystem", "") or ""
        domain = domain or props.get("domain", "")
        unconstrained: bool = props.get("unconstraineddelegation", False)
        if not hostname:
            continue
        sid_to_name[sid] = hostname
        host = _bh_upsert_computer(pid, db, hostname, os_str, unconstrained, domain, host_by_hn, stats)
        sid_to_hid[sid] = host.id
    db.flush()
    return domain


def _bh_process_groups(
    groups_raw: list, sid_to_name: dict, da_sids: set, domain: str,
) -> str:
    group_members: dict[str, list[str]] = {}
    da_group_sids: set[str] = set()
    for grp in groups_raw:
        props = grp.get("Properties", {})
        name_raw: str = (props.get("name") or "").lower()
        sid: str = props.get("objectid", "") or grp.get("ObjectIdentifier", "")
        domain = domain or props.get("domain", "")
        sid_to_name[sid] = props.get("name", "")
        is_da = any(da in name_raw for da in _DA_GROUP_NAMES)
        is_da = is_da or any(sid.endswith(rid) for rid in _WELL_KNOWN_DA_RIDS)
        if is_da:
            da_group_sids.add(sid)
        members = [m.get("ObjectIdentifier", "") for m in grp.get("Members", [])]
        group_members[sid] = members
    for da_gsid in da_group_sids:
        for member_sid in group_members.get(da_gsid, []):
            da_sids.add(member_sid)
            for nested_sid in group_members.get(member_sid, []):
                da_sids.add(nested_sid)
    return domain


def _bh_update_cred_tags(cred, is_da_user: bool, spns: list, stats: dict) -> None:
    tags = list(cred.tags or [])
    if "bloodhound" not in tags:
        tags.append("bloodhound")
    if is_da_user and "da" not in tags:
        tags.append("da")
    if spns and "spn" not in tags:
        tags.append("spn")
    cred.tags = tags
    stats["creds_updated"] += 1


def _bh_upsert_user(pid: str, db: Session, username_short: str, full_name: str,
                    is_da_user: bool, spns: list, domain: str, cred_by_un: dict, stats: dict) -> object:
    cred = cred_by_un.get(username_short) or cred_by_un.get(full_name.lower())
    if cred:
        _bh_update_cred_tags(cred, is_da_user, spns, stats)
    else:
        cred = models.Cred(
            id=new_id("crd"), pid=pid, username=username_short, secret="", type="plain",
            service="AD", domain=domain.lower(),
            tags=(["bloodhound"] + (["da"] if is_da_user else []) + (["spn"] if spns else [])),
            host_ids=[], notes=full_name,
        )
        db.add(cred)
        db.flush()
        cred_by_un[username_short] = cred
        cred_by_un[full_name.lower()] = cred
        stats["creds_created"] += 1
    return cred


def _bh_process_users(
    pid: str, db: Session, users_raw: list, cred_by_un: dict,
    sid_to_cid: dict, sid_to_name: dict, da_sids: set, domain: str, stats: dict,
) -> str:
    for user in users_raw:
        props = user.get("Properties", {})
        full_name: str = props.get("name", "")
        sid: str = props.get("objectid", "") or user.get("ObjectIdentifier", "")
        domain = domain or props.get("domain", "") or (full_name.split("@")[1] if "@" in full_name else "")
        admincount: bool = props.get("admincount", False)
        spns: list = props.get("serviceprincipalnames", [])
        sam = props.get("samaccountname") or props.get("SamAccountName") or ""
        username_short = sam.lower() if sam else _user_short(full_name)
        sid_to_name[sid] = full_name
        is_da_user = sid in da_sids or admincount
        cred = _bh_upsert_user(pid, db, username_short, full_name, is_da_user, spns, domain, cred_by_un, stats)
        sid_to_cid[sid] = cred.id
        if is_da_user:
            stats["da_users"] += 1
    return domain


def _bh_identify_dcs(pid: str, db: Session, da_sids: set, sid_to_hid: dict, stats: dict) -> set:
    dc_host_ids: set[str] = set()
    for h in db.query(models.Host).filter(models.Host.pid == pid).all():
        if _bh_dc_or_tag(h):
            dc_host_ids.add(h.id)
    for sid in da_sids:
        if sid_to_hid.get(sid):
            stats["da_computers"] += 1
    return dc_host_ids


def _bh_link_cred_to_host(db: Session, cid: str, to_hid: str) -> None:
    cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
    if cred and to_hid not in (cred.host_ids or []):
        cred.host_ids = list(cred.host_ids or []) + [to_hid]


def _bh_edges_6a(db: Session, computers_raw: list, sid_to_hid: dict, sid_to_cid: dict,
                  seen_pairs: set, new_edges: list) -> None:
    for comp in computers_raw:
        sid = comp.get("Properties", {}).get("objectid", "") or comp.get("ObjectIdentifier", "")
        to_hid = sid_to_hid.get(sid)
        if not to_hid:
            continue
        for la in comp.get("LocalAdmins", {}).get("Results", []):
            la_sid = la.get("ObjectIdentifier", "")
            from_hid = sid_to_hid.get(la_sid)
            if not from_hid:
                cid = sid_to_cid.get(la_sid)
                if cid:
                    _bh_link_cred_to_host(db, cid, to_hid)
                continue
            _bh_add_edge(seen_pairs, new_edges, from_hid, to_hid, "smb_admin", "LocalAdmin",
                         verified=True, confidence=0.9, reason="BloodHound: AdminTo relationship")


def _bh_edges_6b(computers_raw: list, da_sids: set, sid_to_hid: dict, sid_to_name: dict,
                  default_src: str | None, seen_pairs: set, new_edges: list) -> None:
    for comp in computers_raw:
        sid = comp.get("Properties", {}).get("objectid", "") or comp.get("ObjectIdentifier", "")
        to_hid = sid_to_hid.get(sid)
        if not to_hid:
            continue
        for sess in comp.get("Sessions", {}).get("Results", []):
            sess_sid = sess.get("ObjectIdentifier", "")
            if sess_sid in da_sids and default_src:
                _bh_add_edge(seen_pairs, new_edges, default_src, to_hid, "lateral", "DA session",
                             verified=False, confidence=0.6,
                             reason=f"BloodHound: DA user {sid_to_name.get(sess_sid, sess_sid)} has session here")


def _bh_edges_6c(db: Session, users_raw: list, da_sids: set,
                  sid_to_cid: dict, dc_host_ids: set) -> None:
    for user in users_raw:
        sid = user.get("Properties", {}).get("objectid", "") or user.get("ObjectIdentifier", "")
        if sid not in da_sids:
            continue
        cid = sid_to_cid.get(sid)
        if not cid:
            continue
        cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
        if not cred:
            continue
        updated_host_ids = list(cred.host_ids or [])
        for dc_hid in dc_host_ids:
            if dc_hid not in updated_host_ids:
                updated_host_ids.append(dc_hid)
        cred.host_ids = updated_host_ids


_ACL_EDGE_MAP = {
    "genericall": ("generic_all", "GenericAll", 0.95),
    "writedacl": ("write_dacl", "WriteDACL", 0.85),
    "genericwrite": ("generic_write", "GenericWrite", 0.8),
    "writeowner": ("write_owner", "WriteOwner", 0.8),
    "allextendedright": ("ext_rights", "AllExtRights", 0.75),
    "dcsyncrights": ("dcsync", "DCSync", 1.0),
}


def _bh_process_ace(db: Session, ace: dict, to_hid: str, sid_to_hid: dict, sid_to_cid: dict,
                    seen_pairs: set, new_edges: list, stats: dict) -> None:
    right = (ace.get("RightName") or "").lower()
    principal_sid = ace.get("PrincipalSID", "")
    if right not in _ACL_EDGE_MAP:
        return
    from_hid = sid_to_hid.get(principal_sid)
    if not from_hid:
        cid = sid_to_cid.get(principal_sid)
        if cid:
            _bh_link_cred_to_host(db, cid, to_hid)
        return
    edge_type, label, conf = _ACL_EDGE_MAP[right]
    _bh_add_edge(seen_pairs, new_edges, from_hid, to_hid, edge_type, label,
                 verified=True, confidence=conf, reason=f"BloodHound ACL: {label}")
    stats["acl_edges"] += 1


def _bh_edges_6d(db: Session, computers_raw: list, sid_to_hid: dict, sid_to_cid: dict,
                  seen_pairs: set, new_edges: list, stats: dict) -> None:
    for comp in computers_raw:
        sid = comp.get("Properties", {}).get("objectid", "") or comp.get("ObjectIdentifier", "")
        to_hid = sid_to_hid.get(sid)
        if not to_hid:
            continue
        for ace in comp.get("Aces", []):
            _bh_process_ace(db, ace, to_hid, sid_to_hid, sid_to_cid, seen_pairs, new_edges, stats)


def _bh_edges_6e(_db: Session, sessions_raw: list, da_sids: set, sid_to_hid: dict,
                  default_src: str | None, seen_pairs: set, new_edges: list) -> None:
    for sess in sessions_raw:
        comp_sid = sess.get("ComputerSID", "")
        user_sid = sess.get("UserSID", "")
        comp_hid = sid_to_hid.get(comp_sid)
        if not comp_hid or user_sid not in da_sids:
            continue
        if default_src:
            _bh_add_edge(seen_pairs, new_edges, default_src, comp_hid, "lateral", "DA session",
                         verified=False, confidence=0.55,
                         reason="BloodHound: DA user session on this host")


def _bh_6f_process_principal(db: Session, principal: dict, to_hid: str,
                              sid_to_hid: dict, sid_to_cid: dict,
                              seen_pairs: set, new_edges: list, stats: dict) -> None:
    principal_sid = principal.get("ObjectIdentifier") or principal.get("SID") or ""
    from_hid = sid_to_hid.get(principal_sid)
    if not from_hid:
        cid = sid_to_cid.get(principal_sid)
        if cid:
            _bh_link_cred_to_host(db, cid, to_hid)
        return
    if _bh_add_edge(seen_pairs, new_edges, from_hid, to_hid, "can_rdp", "CanRDP",
                    verified=False, confidence=0.8, reason="BloodHound: CanRDP"):
        stats["can_rdp_edges"] += 1


def _bh_edges_6f(db: Session, computers_raw: list, sid_to_hid: dict, sid_to_cid: dict,
                  seen_pairs: set, new_edges: list, stats: dict) -> None:
    for comp in computers_raw:
        sid = comp.get("Properties", {}).get("objectid", "") or comp.get("ObjectIdentifier", "")
        to_hid = sid_to_hid.get(sid)
        if not to_hid:
            continue
        for principal in comp.get("CanRDP", []) or []:
            _bh_6f_process_principal(db, principal, to_hid, sid_to_hid, sid_to_cid,
                                     seen_pairs, new_edges, stats)


def _bh_edges_6g(computers_raw: list, sid_to_hid: dict,
                  seen_pairs: set, new_edges: list, stats: dict) -> None:
    for comp in computers_raw:
        sid = comp.get("Properties", {}).get("objectid", "") or comp.get("ObjectIdentifier", "")
        to_hid = sid_to_hid.get(sid)
        if not to_hid:
            continue
        for principal in comp.get("AllowedToDelegate", []) or []:
            principal_sid = principal.get("ObjectIdentifier") or principal.get("SID") or ""
            from_hid = sid_to_hid.get(principal_sid)
            if not from_hid:
                continue
            if _bh_add_edge(seen_pairs, new_edges, from_hid, to_hid, "allowed_to_delegate",
                            "AllowedToDelegate", verified=False, confidence=0.85,
                            reason="BloodHound: AllowedToDelegate (constrained delegation)"):
                stats["allowed_to_delegate_edges"] += 1


def _bh_edges_6fg(db: Session, computers_raw: list, sid_to_hid: dict, sid_to_cid: dict,
                   seen_pairs: set, new_edges: list, stats: dict) -> None:
    _bh_edges_6f(db, computers_raw, sid_to_hid, sid_to_cid, seen_pairs, new_edges, stats)
    _bh_edges_6g(computers_raw, sid_to_hid, seen_pairs, new_edges, stats)


_TRUST_TYPE_MAP = {0: "ParentChild", 1: "CrossLink", 2: "Forest", 3: "External", 4: "Unknown"}
_TRUST_DIR_MAP = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}


def _bh_trust_type_dir(trust: dict) -> tuple[str, str]:
    t_type_raw = trust.get("TrustType")
    t_dir_raw = trust.get("TrustDirection")
    t_type = _TRUST_TYPE_MAP.get(t_type_raw, str(t_type_raw)) if isinstance(t_type_raw, int) else (t_type_raw or "Unknown")
    t_dir = _TRUST_DIR_MAP.get(t_dir_raw, str(t_dir_raw)) if isinstance(t_dir_raw, int) else (t_dir_raw or "Bidirectional")
    return t_type, t_dir


def _bh_add_trust_edges(from_hids: list, to_hids: list, seen_pairs: set,
                         new_edges: list, stats: dict, label: str, reason: str) -> None:
    for src_hid in from_hids:
        for tgt_hid in to_hids:
            if _bh_add_edge(seen_pairs, new_edges, src_hid, tgt_hid, "trust", label,
                            verified=True, confidence=0.95, reason=reason):
                stats["trust_edges"] += 1


def _bh_process_domain_trusts(dom: dict, domain_to_dc_hids: dict, seen_pairs: set,
                               new_edges: list, stats: dict) -> None:
    props = dom.get("Properties", {})
    src_domain = (props.get("name") or props.get("domain") or "").lower()
    if not src_domain:
        return
    for trust in dom.get("Trusts", []) or []:
        target_domain = (trust.get("TargetDomainName") or "").lower()
        if not target_domain or target_domain == src_domain:
            continue
        t_type, t_dir = _bh_trust_type_dir(trust)
        label = f"trust:{t_type}/{t_dir}"
        reason = f"BloodHound: {t_type} trust {src_domain} → {target_domain} ({t_dir})"
        _bh_add_trust_edges(domain_to_dc_hids.get(src_domain, []),
                            domain_to_dc_hids.get(target_domain, []),
                            seen_pairs, new_edges, stats, label, reason)


def _bh_edges_6h(db: Session, pid: str, domains_raw: list, _dc_host_ids: set,
                  seen_pairs: set, new_edges: list, stats: dict) -> None:
    domain_to_dc_hids: dict[str, list[str]] = defaultdict(list)
    for h in db.query(models.Host).filter(models.Host.pid == pid).all():
        if _bh_dc_or_tag(h) and h.domain:
            domain_to_dc_hids[h.domain.lower()].append(h.id)
    for dom in domains_raw:
        _bh_process_domain_trusts(dom, domain_to_dc_hids, seen_pairs, new_edges, stats)


def _bh_enrich_tags(pid: str, db: Session, dc_host_ids: set, new_edges: list,
                    da_sids: set, sid_to_hid: dict, stats: dict) -> None:
    bh_admin_source_hids: set[str] = {
        e["from_host_id"] for e in new_edges
        if e["type"] in {"smb_admin"} or e["type"] in {ev[0] for ev in _ACL_EDGE_MAP.values()}
    }
    bh_da_member_hids: set[str] = {sid_to_hid[s] for s in da_sids if sid_to_hid.get(s)}
    for h in db.query(models.Host).filter(models.Host.pid == pid).all():
        if h.id in dc_host_ids and _add_host_tag(h, "bh:dc"):
            stats["bh_dc_tagged"] += 1
        if h.id in bh_admin_source_hids and _add_host_tag(h, "bh:admin"):
            stats["bh_admin_tagged"] += 1
        if h.id in bh_da_member_hids and _add_host_tag(h, "bh:da-member"):
            stats["bh_da_member_tagged"] += 1


def _bh_store_edges(pid: str, db: Session, new_edges: list) -> int:
    network = (
        db.query(models.Network).filter(models.Network.pid == pid)
        .order_by(models.Network.id).first()
    )
    if not network:
        network = models.Network(
            id=new_id("net"), pid=pid, name="Network Map",
            background="#07080b", meta_json={},
        )
        db.add(network)
        db.flush()
    existing_edges = get_edges(network.id, db)
    existing_pairs = {
        (e.get("from_host_id"), e.get("to_host_id"), e.get("type"))
        for e in existing_edges if e.get("from_host_id")
    }
    added = 0
    for e in new_edges:
        key = (e["from_host_id"], e["to_host_id"], e["type"])
        if key not in existing_pairs:
            existing_edges.append(e)
            existing_pairs.add(key)
            added += 1
    replace_edges(network.id, pid, existing_edges, db)
    db.commit()
    return added


def _process(pid: str, file_map: dict, db: Session) -> dict:
    stats = {
        "hosts_created": 0, "hosts_updated": 0, "creds_created": 0, "creds_updated": 0,
        "edges_added": 0, "da_users": 0, "da_computers": 0, "acl_edges": 0,
        "can_rdp_edges": 0, "allowed_to_delegate_edges": 0, "trust_edges": 0,
        "bh_dc_tagged": 0, "bh_admin_tagged": 0, "bh_da_member_tagged": 0,
    }

    # ── Step 1: build SID → host / cred index from existing data ─────────────
    existing_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    existing_creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    host_by_hn, cred_by_un = _bh_build_index(existing_hosts, existing_creds)

    sid_to_hid: dict[str, str] = {}
    sid_to_cid: dict[str, str] = {}
    sid_to_name: dict[str, str] = {}
    da_sids: set[str] = set()
    domain: str = ""

    # ── Steps 2-4: parse raw BH data into DB objects ─────────────────────────
    computers_raw = _get_items(file_map.get("computers", {}))
    groups_raw = _get_items(file_map.get("groups", {}))
    users_raw = _get_items(file_map.get("users", {}))

    domain = _bh_process_computers(pid, db, computers_raw, host_by_hn, sid_to_hid, sid_to_name, stats, domain)
    domain = _bh_process_groups(groups_raw, sid_to_name, da_sids, domain)
    domain = _bh_process_users(pid, db, users_raw, cred_by_un, sid_to_cid, sid_to_name, da_sids, domain, stats)
    db.flush()

    # ── Step 5: identify DC hosts ─────────────────────────────────────────────
    dc_host_ids = _bh_identify_dcs(pid, db, da_sids, sid_to_hid, stats)

    # ── Step 6: build access edges ────────────────────────────────────────────
    new_edges: list[dict] = []
    seen_pairs: set[tuple] = set()
    attacker_hosts = [h for h in existing_hosts if h.is_attacker]
    default_src = attacker_hosts[0].id if attacker_hosts else None

    _bh_edges_6a(db, computers_raw, sid_to_hid, sid_to_cid, seen_pairs, new_edges)
    _bh_edges_6b(computers_raw, da_sids, sid_to_hid, sid_to_name, default_src, seen_pairs, new_edges)
    _bh_edges_6c(db, users_raw, da_sids, sid_to_cid, dc_host_ids)
    _bh_edges_6d(db, computers_raw, sid_to_hid, sid_to_cid, seen_pairs, new_edges, stats)
    _bh_edges_6e(db, _get_items(file_map.get("sessions", {})), da_sids, sid_to_hid, default_src, seen_pairs, new_edges)
    _bh_edges_6fg(db, computers_raw, sid_to_hid, sid_to_cid, seen_pairs, new_edges, stats)
    _bh_edges_6h(db, pid, _get_items(file_map.get("domains", {})), dc_host_ids, seen_pairs, new_edges, stats)

    # ── Step 6.5: enrich tags + Step 7: store edges ───────────────────────────
    _bh_enrich_tags(pid, db, dc_host_ids, new_edges, da_sids, sid_to_hid, stats)
    stats["edges_added"] = _bh_store_edges(pid, db, new_edges)

    return stats


# ── FastAPI endpoint ─────────────────────────────────────────────────────────


@router.post("/api/projects/{pid}/import/bloodhound", responses={400: {"description": "Bad request"}})
async def import_bloodhound_zip(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
):
    """Import a SharpHound/BloodHound ZIP or single JSON file."""
    check_pid_access(db, pid, user, "findings.create")
    content = await file.read()
    filename = (file.filename or "").lower()

    if filename.endswith(".zip"):
        result = parse_bloodhound_zip(pid, content, db)
    elif filename.endswith(".json"):
        # Guess key from filename: *_computers.json → "computers"
        key = "computers"
        for k in ("computers", "users", "groups", "sessions", "ous", "domains", "gpos"):
            if k in filename:
                key = k
                break
        result = parse_bloodhound_json(pid, key, content, db)
    else:
        raise HTTPException(400, "Unsupported file type — upload a .zip or .json")

    log_event(
        db,
        pid,
        getattr(user, "username", None),
        "import",
        "bloodhound",
        f"BloodHound import: {result.get('hosts_created', 0)} hosts, "
        f"{result.get('creds_created', 0)} creds, {result.get('edges_added', 0)} edges",
        result,
    )
    db.commit()
    return result
