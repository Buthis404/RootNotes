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
import re
import uuid
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import log_event
from ..core.utils import new_id
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["import_bloodhound"])

_DA_GROUP_NAMES = {"domain admins", "enterprise admins", "schema admins", "administrators"}
_HIGH_PRIV_ACES = {"genericall", "genericwrite", "writedacl", "writeowner", "allextendedright"}
_DELEGATION_ACES = {"allowedtoactonbehalfofotheridentity", "allextendedright"}

_WELL_KNOWN_DA_RIDS = {"-512", "-519", "-518", "-544"}  # DA, EA, Schema, Administrators


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


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
    return data.get("data") or data.get("computers") or data.get("users") or \
           data.get("groups") or data.get("sessions") or []


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
                except Exception:
                    pass
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

def _process(pid: str, file_map: dict, db: Session) -> dict:
    stats = {
        "hosts_created": 0, "hosts_updated": 0,
        "creds_created": 0, "creds_updated": 0,
        "edges_added": 0,
        "da_users": 0, "da_computers": 0,
        "acl_edges": 0,
    }

    # ── Step 1: build SID → host / cred index from existing data ─────────────
    existing_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    existing_creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()

    # hostname (upper) → Host
    host_by_hostname: dict[str, models.Host] = {
        (h.hostname or "").upper(): h for h in existing_hosts if h.hostname
    }
    # username (lower) → Cred  (prefer AD type)
    cred_by_username: dict[str, models.Cred] = {}
    for c in existing_creds:
        key = (c.username or "").lower()
        if key not in cred_by_username or c.service in ("AD", "os"):
            cred_by_username[key] = c

    # SID maps (built as we parse)
    sid_to_host_id: dict[str, str] = {}   # SID → our host.id
    sid_to_cred_id: dict[str, str] = {}   # SID → our cred.id
    sid_to_name: dict[str, str] = {}      # SID → display name
    da_sids: set[str] = set()             # SIDs that are DA-capable
    domain: str = ""

    # ── Step 2: computers ────────────────────────────────────────────────────
    computers_raw = _get_items(file_map.get("computers", {}))
    for comp in computers_raw:
        props = comp.get("Properties", {})
        full_name: str = props.get("name", "")
        sid: str = props.get("objectid", "") or comp.get("ObjectIdentifier", "")
        hostname = _host_short(full_name)
        os_str: str = props.get("operatingsystem", "") or ""
        enabled: bool = props.get("enabled", True)
        domain = domain or props.get("domain", "")
        unconstrained: bool = props.get("unconstraineddelegation", False)

        if not hostname:
            continue

        sid_to_name[sid] = hostname

        host = host_by_hostname.get(hostname)
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
                id=new_id("hst"), pid=pid,
                ip="", hostname=hostname,
                os=os_str or "Windows", status="scanned",
                ports=[], services=[],
                tags=["bloodhound"] + (["unconstrained-delegation"] if unconstrained else []),
                notes="", domain=domain.lower(),
                role="unknown", is_attacker=False,
                import_source="bloodhound",
            )
            db.add(host)
            db.flush()
            host_by_hostname[hostname] = host
            stats["hosts_created"] += 1

        sid_to_host_id[sid] = host.id

        # DC detection: check if this SID ends with well-known DC RID or is the computer for domain
        if any(sid.endswith(rid) for rid in ("-502", "-500")):
            pass  # krbtgt / Administrator, not DC itself

    db.flush()

    # ── Step 3: groups → identify DA SIDs ───────────────────────────────────
    groups_raw = _get_items(file_map.get("groups", {}))
    group_members: dict[str, list[str]] = {}  # group_sid → [member_sids]
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

    # Expand DA membership (including nested — one level)
    for da_gsid in list(da_group_sids):
        for member_sid in group_members.get(da_gsid, []):
            da_sids.add(member_sid)
            # One level of nesting: if member is a group, add its members too
            for nested_sid in group_members.get(member_sid, []):
                da_sids.add(nested_sid)

    # ── Step 4: users → creds ────────────────────────────────────────────────
    users_raw = _get_items(file_map.get("users", {}))
    for user in users_raw:
        props = user.get("Properties", {})
        full_name: str = props.get("name", "")  # S_DOTSON@EDU.STF or display name
        sid: str = props.get("objectid", "") or user.get("ObjectIdentifier", "")
        enabled: bool = props.get("enabled", True)
        domain = domain or props.get("domain", "") or (full_name.split("@")[1] if "@" in full_name else "")
        admincount: bool = props.get("admincount", False)
        spns: list = props.get("serviceprincipalnames", [])

        # Prefer samaccountname (always ASCII) over name (may be display name with Unicode)
        sam = props.get("samaccountname") or props.get("SamAccountName") or ""
        username_short = sam.lower() if sam else _user_short(full_name)
        sid_to_name[sid] = full_name

        # Mark DA if member of DA group or admincount=True with known DA patterns
        is_da_user = sid in da_sids or admincount

        cred = cred_by_username.get(username_short) or cred_by_username.get(full_name.lower())
        if cred:
            tags = list(cred.tags or [])
            if "bloodhound" not in tags:
                tags.append("bloodhound")
            if is_da_user and "da" not in tags:
                tags.append("da")
            if spns and "spn" not in tags:
                tags.append("spn")
            cred.tags = tags
            stats["creds_updated"] += 1
        else:
            cred = models.Cred(
                id=new_id("crd"), pid=pid,
                username=username_short,
                secret="", type="plain",
                service="AD",
                domain=domain.lower(),
                tags=(["bloodhound"] + (["da"] if is_da_user else []) + (["spn"] if spns else [])),
                host_ids=[],
                notes=full_name,
            )
            db.add(cred)
            db.flush()
            cred_by_username[username_short] = cred
            cred_by_username[full_name.lower()] = cred
            stats["creds_created"] += 1

        sid_to_cred_id[sid] = cred.id

        if is_da_user:
            stats["da_users"] += 1

    db.flush()

    # ── Step 5: identify DC hosts ────────────────────────────────────────────
    dc_host_ids: set[str] = set()
    for h in db.query(models.Host).filter(models.Host.pid == pid).all():
        if h.role == "domain_controller" or "dc" in {t.lower() for t in (h.tags or [])}:
            dc_host_ids.add(h.id)

    # Count DA-capable computers (for stats only — NOT adding to dc_host_ids:
    # a computer being a member of the DA group doesn't make it a DC)
    for sid in da_sids:
        if sid_to_host_id.get(sid):
            stats["da_computers"] += 1

    # ── Step 6: build access edges ───────────────────────────────────────────
    new_edges: list[dict] = []
    seen_pairs: set[tuple] = set()

    def add_edge(from_hid: str, to_hid: str, edge_type: str, label: str,
                 verified: bool = False, confidence: float = 0.7,
                 reason: str = "", source: str = "bloodhound") -> None:
        if not from_hid or not to_hid or from_hid == to_hid:
            return
        key = (from_hid, to_hid, edge_type)
        if key in seen_pairs:
            return
        seen_pairs.add(key)
        new_edges.append({
            "id": _edge_id(),
            "from_host_id": from_hid,  # attack_graph reads this directly
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

    # 6a. LocalAdmins from computers.json → smb_admin edges
    for comp in computers_raw:
        sid: str = comp.get("Properties", {}).get("objectid", "") or comp.get("ObjectIdentifier", "")
        to_hid = sid_to_host_id.get(sid)
        if not to_hid:
            continue
        for la in comp.get("LocalAdmins", {}).get("Results", []):
            la_sid = la.get("ObjectIdentifier", "")
            from_hid = sid_to_host_id.get(la_sid)
            if not from_hid:
                # User SID → link cred to host instead of edge
                cid = sid_to_cred_id.get(la_sid)
                if cid:
                    cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
                    if cred and to_hid not in (cred.host_ids or []):
                        cred.host_ids = list(cred.host_ids or []) + [to_hid]
                continue
            add_edge(from_hid, to_hid, "smb_admin", "LocalAdmin",
                     verified=True, confidence=0.9,
                     reason=f"BloodHound: AdminTo relationship")

    # 6b. Sessions from computers.json → has_session edges (attacker perspective)
    attacker_hosts = [h for h in existing_hosts if h.is_attacker]
    default_src = attacker_hosts[0].id if attacker_hosts else None

    for comp in computers_raw:
        sid: str = comp.get("Properties", {}).get("objectid", "") or comp.get("ObjectIdentifier", "")
        to_hid = sid_to_host_id.get(sid)
        if not to_hid:
            continue
        for sess in comp.get("Sessions", {}).get("Results", []):
            sess_sid = sess.get("ObjectIdentifier", "")
            # If a DA user has a session here → interesting lateral path target
            if sess_sid in da_sids:
                if default_src:
                    add_edge(default_src, to_hid, "lateral", "DA session",
                             verified=False, confidence=0.6,
                             reason=f"BloodHound: DA user {sid_to_name.get(sess_sid, sess_sid)} has session here")

    # 6c. DA users → credential edges to DCs
    for user in users_raw:
        sid: str = user.get("Properties", {}).get("objectid", "") or user.get("ObjectIdentifier", "")
        if sid not in da_sids:
            continue
        cid = sid_to_cred_id.get(sid)
        if not cid:
            continue
        cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
        if not cred:
            continue
        # Link DA cred to all DC hosts
        updated_host_ids = list(cred.host_ids or [])
        for dc_hid in dc_host_ids:
            if dc_hid not in updated_host_ids:
                updated_host_ids.append(dc_hid)
        cred.host_ids = updated_host_ids

    # 6d. ACL edges: GenericAll / WriteDACL on computers
    _ACL_EDGE_MAP = {
        "genericall":        ("generic_all",   "GenericAll",   0.95),
        "writedacl":         ("write_dacl",    "WriteDACL",    0.85),
        "genericwrite":      ("generic_write", "GenericWrite", 0.8),
        "writeowner":        ("write_owner",   "WriteOwner",   0.8),
        "allextendedright":  ("ext_rights",    "AllExtRights", 0.75),
        "dcsyncrights":      ("dcsync",        "DCSync",       1.0),
    }
    for comp in computers_raw:
        sid: str = comp.get("Properties", {}).get("objectid", "") or comp.get("ObjectIdentifier", "")
        to_hid = sid_to_host_id.get(sid)
        if not to_hid:
            continue
        for ace in comp.get("Aces", []):
            right = (ace.get("RightName") or "").lower()
            principal_sid = ace.get("PrincipalSID", "")
            if right not in _ACL_EDGE_MAP:
                continue
            from_hid = sid_to_host_id.get(principal_sid)
            if not from_hid:
                # User ACE → link cred
                cid = sid_to_cred_id.get(principal_sid)
                if cid:
                    cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
                    if cred and to_hid not in (cred.host_ids or []):
                        cred.host_ids = list(cred.host_ids or []) + [to_hid]
                continue
            edge_type, label, conf = _ACL_EDGE_MAP[right]
            add_edge(from_hid, to_hid, edge_type, label,
                     verified=True, confidence=conf,
                     reason=f"BloodHound ACL: {label}")
            stats["acl_edges"] += 1

    # 6e. Sessions file (older BloodHound format)
    sessions_raw = _get_items(file_map.get("sessions", {}))
    for sess in sessions_raw:
        comp_sid = sess.get("ComputerSID", "")
        user_sid = sess.get("UserSID", "")
        comp_hid = sid_to_host_id.get(comp_sid)
        if not comp_hid or user_sid not in da_sids:
            continue
        if default_src:
            add_edge(default_src, comp_hid, "lateral", "DA session",
                     verified=False, confidence=0.55,
                     reason=f"BloodHound: DA user session on this host")

    # ── Step 7: store edges in network ───────────────────────────────────────
    network = db.query(models.Network).filter(models.Network.pid == pid).order_by(models.Network.id).first()
    if not network:
        network = models.Network(
            id=new_id("net"), pid=pid, name="Network Map",
            background="#07080b", regions_json=[], nodes_json=[], edges_json=[], meta_json={},
        )
        db.add(network)
        db.flush()

    existing_edges = list(network.edges_json or [])
    # Dedup against existing BH edges
    existing_pairs = {(e.get("from_host_id"), e.get("to_host_id"), e.get("type")) for e in existing_edges if e.get("from_host_id")}
    for e in new_edges:
        key = (e["from_host_id"], e["to_host_id"], e["type"])
        if key not in existing_pairs:
            existing_edges.append(e)
            existing_pairs.add(key)
            stats["edges_added"] += 1

    network.edges_json = existing_edges
    flag_modified(network, "edges_json")
    db.commit()

    return stats


# ── FastAPI endpoint ─────────────────────────────────────────────────────────

@router.post("/api/projects/{pid}/import/bloodhound")
async def import_bloodhound_zip(
    pid: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
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
        db, pid, getattr(user, "username", None),
        "import", "bloodhound",
        f"BloodHound import: {result.get('hosts_created', 0)} hosts, "
        f"{result.get('creds_created', 0)} creds, {result.get('edges_added', 0)} edges",
        result,
    )
    db.commit()
    return result
