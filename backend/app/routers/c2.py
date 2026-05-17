"""
C2 framework integrations: Sliver, Adaptix, Mythic.

Each integration is stored as an encrypted config in global_settings.
Sync pulls sessions/agents/creds from the C2 and auto-populates
hosts, creds, and optionally findings.
"""
import asyncio
import json
import re
import secrets
from datetime import datetime
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.crypto import decrypt_str, encrypt_str
from ..core.deps import get_current_user, require_admin, is_admin
from ..core.events import bcast, log_event
from ..core.job_tracker import start_job, finish_job
from ..core.logging_setup import get_logger
from ..core.utils import new_id, ts_now, utcnow
from ..database import get_db, SessionLocal
from ..plugins.registry import registry

logger = get_logger(__name__)

_C2_STATUS_RANK = {"unknown": 0, "up": 1, "alive": 1, "access": 2, "pwned": 3, "owned": 4}


def _normalize_host_status(value: str) -> str:
    raw = (value or "").strip().lower()
    if raw in {"owned", "pwned", "access", "up", "alive", "unknown"}:
        return raw
    if raw in {"compromised", "compromise"}:
        return "pwned"
    return ""


def _has_live_session_signal(host_data: dict) -> bool:
    return bool(
        str(host_data.get("beacon_id") or "").strip()
        or str(host_data.get("agent_id") or "").strip()
        or str(host_data.get("process") or "").strip()
        or str(host_data.get("pid") or "").strip()
    )


def _status_from_c2_host(existing_status: str, host_data: dict) -> str:
    explicit = _normalize_host_status(host_data.get("status") or "")
    if explicit:
        return explicit if _C2_STATUS_RANK.get(explicit, 0) >= _C2_STATUS_RANK.get((existing_status or "").strip().lower(), 0) else existing_status

    current = (existing_status or "").strip().lower()
    if _has_live_session_signal(host_data) and host_data.get("alive", True):
        tier = _classify_privilege(host_data.get("username") or "")
        candidate = {"user": "access", "admin": "pwned", "system": "owned"}.get(tier, "access")
        return candidate if _C2_STATUS_RANK.get(candidate, 0) >= _C2_STATUS_RANK.get(current, 0) else existing_status

    if current:
        return existing_status
    return "up" if host_data.get("alive", True) else "unknown"


def _c2_owns_host_status(host: models.Host, source: str) -> bool:
    tags = {str(tag).strip().lower() for tag in (host.tags or []) if str(tag).strip()}
    return (host.import_source or "").strip().lower() == source.lower() or ({"c2", source.lower()} <= tags)


def _require_c2():
    m = registry.get("c2_integration")
    if not m or not m.enabled:
        raise HTTPException(404, "C2 Integration module is disabled")

router = APIRouter(prefix="/api/admin/c2", tags=["c2"])

_C2_SETTING_KEY = "c2_integrations"


def _visible_integrations_for_pid(integrations: list[dict], pid: str) -> list[dict]:
    return [
        i for i in integrations
        if i.get("enabled") and (not i.get("project_ids") or pid in i.get("project_ids", []))
    ]

# ── Config storage ────────────────────────────────────────────────────

def _load_integrations(db: Session) -> list[dict]:
    item = db.query(models.GlobalSetting).filter(
        models.GlobalSetting.key == _C2_SETTING_KEY
    ).first()
    if not item:
        return []
    raw = item.value if isinstance(item.value, list) else []
    return [_decrypt_integration(i) for i in raw]


def _save_integrations(db: Session, integrations: list[dict]):
    encrypted = [_encrypt_integration(i) for i in integrations]
    item = db.query(models.GlobalSetting).filter(
        models.GlobalSetting.key == _C2_SETTING_KEY
    ).first()
    if item:
        item.value = encrypted
    else:
        item = models.GlobalSetting(key=_C2_SETTING_KEY, value=encrypted)
        db.add(item)
    db.commit()


def _encrypt_integration(cfg: dict) -> dict:
    c = dict(cfg)
    if c.get("token"):
        c["token"] = encrypt_str(c["token"])
    if c.get("password"):
        c["password"] = encrypt_str(c["password"])
    return c


def _decrypt_integration(cfg: dict) -> dict:
    c = dict(cfg)
    if c.get("token"):
        c["token"] = decrypt_str(c["token"])
    if c.get("password"):
        c["password"] = decrypt_str(c["password"])
    return c


def _safe_integration(cfg: dict) -> dict:
    """Return config without sensitive fields for API responses."""
    c = dict(cfg)
    c["has_token"] = bool(c.get("token"))
    c["has_password"] = bool(c.get("password"))
    c["token"] = ""
    c["password"] = ""
    return c


# ── Pydantic models ───────────────────────────────────────────────────

class C2IntegrationCreate(BaseModel):
    name: str
    type: str                        # sliver | adaptix | mythic
    url: str = ""                    # Sliver carries lhost/lport inside operator config blob
    token: str = ""
    username: str = ""
    password: str = ""
    endpoint: str = "/endpoint"      # Adaptix: WS/API endpoint prefix
    verify_ssl: bool = False
    project_ids: list[str] = []
    enabled: bool = True
    sync_interval_minutes: int = 0   # 0 = manual only


class C2IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    endpoint: Optional[str] = None
    verify_ssl: Optional[bool] = None
    project_ids: Optional[list[str]] = None
    enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = None


class C2HostActionRequest(BaseModel):
    integration_id: str
    agent_id: str
    host_id: str
    mode: str = "command"   # command | bof
    commandline: str
    credential_source: str = ""   # rootnotes | c2
    credential_id: str = ""
    wait_for_output: bool = True
    timeout_seconds: int = 12
    title: str = ""


# ── CRUD ──────────────────────────────────────────────────────────────

def _is_owner_of(db: Session, pid: str, user: models.User) -> bool:
    from ..core.permissions import get_membership
    m = get_membership(db, pid, user.id)
    return bool(m and m.role == "owner")


def _can_manage_integration(db: Session, user: models.User, cfg: dict) -> bool:
    """
    Who can manage a C2 integration:
      - Global admin: always
      - Project owner: only if the integration is bound to projects they own
        (cfg["project_ids"] non-empty AND user owns at least one of them).
        Integrations with no project_ids (global) remain admin-only.
    """
    if is_admin(user):
        return True
    pids = cfg.get("project_ids") or []
    if not pids:
        return False
    return any(_is_owner_of(db, pid, user) for pid in pids)


def _visible_to_user(db: Session, user: models.User, cfg: dict) -> bool:
    """List/read visibility — broader than _can_manage: any project member
    sees integrations bound to projects they're members of."""
    if is_admin(user):
        return True
    pids = cfg.get("project_ids") or []
    if not pids:
        return False
    from ..core.permissions import get_membership
    return any(get_membership(db, pid, user.id) for pid in pids)


@router.get("")
def list_integrations(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_c2()
    integrations = _load_integrations(db)
    return [_safe_integration(i) for i in integrations if _visible_to_user(db, user, i)]


@router.post("", status_code=201)
def create_integration(
    body: C2IntegrationCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_c2()
    if body.type not in ("sliver", "adaptix", "mythic"):
        raise HTTPException(400, f"Unknown C2 type: {body.type}")
    # Non-admins must scope the integration to projects they own.
    if not is_admin(user):
        if not body.project_ids:
            raise HTTPException(403, "Only global admins can create unscoped C2 integrations")
        for pid in body.project_ids:
            if not _is_owner_of(db, pid, user):
                raise HTTPException(403, f"You are not an owner of project {pid}")
    integrations = _load_integrations(db)
    cfg = body.model_dump()
    cfg["id"] = new_id("c2")
    cfg["last_sync"] = None
    cfg["created_by"] = user.username
    integrations.append(cfg)
    _save_integrations(db, integrations)
    return _safe_integration(cfg)


@router.patch("/{iid}")
def update_integration(
    iid: str,
    body: C2IntegrationUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    integrations = _load_integrations(db)
    idx = next((i for i, c in enumerate(integrations) if c.get("id") == iid), None)
    if idx is None:
        raise HTTPException(404, "Integration not found")
    if not _can_manage_integration(db, user, integrations[idx]):
        raise HTTPException(403, "Insufficient permissions to manage this integration")
    updates = body.model_dump(exclude_none=True)
    # Non-admins cannot widen the scope to include projects they don't own,
    # and cannot remove project_ids entirely (would become a global integration).
    if not is_admin(user) and "project_ids" in updates:
        new_pids = updates["project_ids"] or []
        if not new_pids:
            raise HTTPException(403, "Only global admins can make an integration global")
        for pid in new_pids:
            if not _is_owner_of(db, pid, user):
                raise HTTPException(403, f"You are not an owner of project {pid}")
    integrations[idx].update(updates)
    _save_integrations(db, integrations)
    return _safe_integration(integrations[idx])


@router.delete("/{iid}", status_code=204)
def delete_integration(
    iid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    integrations = _load_integrations(db)
    target = next((c for c in integrations if c.get("id") == iid), None)
    if target is None:
        raise HTTPException(404, "Integration not found")
    if not _can_manage_integration(db, user, target):
        raise HTTPException(403, "Insufficient permissions to manage this integration")
    integrations = [c for c in integrations if c.get("id") != iid]
    _save_integrations(db, integrations)


# ── Connectors ────────────────────────────────────────────────────────

# ── Sliver ────────────────────────────────────────────────────────────
#
# Sliver multiplayer uses a native gRPC API over mTLS — there is no REST
# endpoint. Operator authentication is via a "config file" (JSON blob)
# generated by `sliver-server operator --name ... --lhost ... --save .`
# which bundles: operator name, ca_certificate, certificate, private_key,
# lhost, lport, token.
#
# We store this entire config JSON in cfg["token"] (single paste field
# in the UI). The connector parses it on each call and opens a gRPC
# channel via the official `sliver-py` client.

def _sliver_parse_config(cfg: dict):
    from sliver import SliverClientConfig  # local import — heavy gRPC stubs
    blob = (cfg.get("token") or "").strip()
    if not blob:
        raise HTTPException(400, "Sliver operator config (JSON) is empty")
    try:
        return SliverClientConfig.parse_config(blob)
    except Exception as e:
        raise HTTPException(400, f"Invalid Sliver operator config: {e}")


async def _sliver_connect(cfg: dict):
    from sliver import SliverClient
    config = _sliver_parse_config(cfg)
    client = SliverClient(config)
    await client.connect()
    return client


def _sliver_format_host(item, is_beacon: bool) -> dict:
    """Map a Session/Beacon proto to our hosts dict."""
    remote = getattr(item, "RemoteAddress", "") or ""
    ip = remote.split(":")[0] if remote else ""
    if not ip:
        ip = getattr(item, "ActiveC2", "") or ""
    os_str = getattr(item, "OS", "") or ""
    arch = getattr(item, "Arch", "") or ""
    return {
        "ip": ip,
        "hostname": getattr(item, "Hostname", "") or "",
        "os": (os_str + (" " + arch if arch else "")).strip(),
        "username": getattr(item, "Username", "") or "",
        "arch": arch,
        "process": getattr(item, "Filename", "") or "",
        "pid": getattr(item, "PID", None),
        "alive": not getattr(item, "IsDead", False),
        "beacon_id": getattr(item, "ID", "") or "",
        "note": ("Beacon: " if is_beacon else "Session: ") + (getattr(item, "Name", "") or ""),
        "source": "sliver",
        "domain": "",
    }


async def _sliver_sync(cfg: dict) -> dict:
    """Pull sessions + beacons via gRPC multiplayer API."""
    client = await _sliver_connect(cfg)
    try:
        sessions = await client.sessions()
        beacons = await client.beacons()
    finally:
        await client.close()
    hosts = (
        [_sliver_format_host(s, is_beacon=False) for s in (sessions or [])]
        + [_sliver_format_host(b, is_beacon=True) for b in (beacons or [])]
    )
    # Sliver has no built-in credential store — creds come from rootnotes only.
    return {"hosts": hosts, "creds": []}


async def _adaptix_sync(cfg: dict) -> dict:
    """
    Adaptix C2 REST API.
    All routes are under {endpoint} prefix (default /endpoint).
    Auth: POST {endpoint}/login -> JWT access_token
    Agents: GET {endpoint}/agent/list
    Creds: GET {endpoint}/creds/list
    Targets: GET {endpoint}/targets/list  (deduplicated hosts)
    """
    url = cfg["url"].rstrip("/")
    ep = cfg.get("endpoint", "/endpoint").rstrip("/") or "/endpoint"
    base = f"{url}{ep}"
    token = cfg.get("token", "")

    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        if not token:
            username = cfg.get("username") or "operator"
            password = cfg.get("password", "")
            login_r = await client.post(
                f"{base}/login",
                json={"username": username, "password": password, "version": ""},
            )
            login_r.raise_for_status()
            token = login_r.json().get("access_token") or login_r.json().get("token") or ""

        headers = {"Authorization": f"Bearer {token}"}

        # Targets — deduplicated host inventory
        targets_by_id: dict = {}
        try:
            t_r = await client.get(f"{base}/targets/list", headers=headers)
            if t_r.status_code == 200:
                tlist = t_r.json()
                if isinstance(tlist, list):
                    for t in tlist:
                        tid = t.get("t_target_id")
                        if tid:
                            targets_by_id[tid] = t
        except Exception:
            pass

        # Agents
        agents_r = await client.get(f"{base}/agent/list", headers=headers)
        agents_r.raise_for_status()
        agents = agents_r.json()
        if not isinstance(agents, list):
            agents = []

        # Index agents by id for quick lookup
        agents_by_id = {a["a_id"]: a for a in agents if a.get("a_id")}

        # Creds
        raw_creds = []
        try:
            c_r = await client.get(f"{base}/creds/list", headers=headers)
            if c_r.status_code == 200:
                cdata = c_r.json()
                if isinstance(cdata, list):
                    raw_creds = cdata
        except Exception:
            pass

    result_hosts = []
    seen_ips: set = set()

    # Primary: targets (one entry per compromised host)
    for t in targets_by_id.values():
        ip = (t.get("t_address") or "").strip()
        if not ip:
            continue

        # OS: use description or derive from int (0=unknown, 1=Windows, 2=Linux)
        os_desc = (t.get("t_os_desk") or "").strip()
        if not os_desc:
            os_int = t.get("t_os", 0)
            os_desc = {1: "Windows", 2: "Linux"}.get(os_int, "")

        # Grab first active agent for process/arch/user context
        agent_ids = t.get("t_agents") or []
        ctx_agent: dict = {}
        for aid in agent_ids:
            ag = agents_by_id.get(aid)
            if ag and ag.get("a_mark", "") != "Terminated":
                ctx_agent = ag
                break

        domain = (t.get("t_domain") or "").strip()
        note_parts = []
        if t.get("t_info"):
            note_parts.append(t["t_info"])
        if domain:
            note_parts.append(f"Domain: {domain}")
        if ctx_agent.get("a_process"):
            note_parts.append(f"Process: {ctx_agent['a_process']} (PID {ctx_agent.get('a_pid', '?')})")
        if ctx_agent.get("a_arch"):
            note_parts.append(f"Arch: {ctx_agent['a_arch']}")
        if ctx_agent.get("a_impersonated"):
            note_parts.append(f"Impersonated: {ctx_agent['a_impersonated']}")
        if agent_ids:
            note_parts.append(f"Agent IDs: {', '.join(agent_ids)}")

        result_hosts.append({
            "ip": ip,
            "hostname": (t.get("t_computer") or "").strip(),
            "os": os_desc,
            "domain": domain,
            "username": (ctx_agent.get("a_username") or "").strip(),
            "arch": (ctx_agent.get("a_arch") or "").strip(),
            "process": (ctx_agent.get("a_process") or "").strip(),
            "pid": ctx_agent.get("a_pid"),
            "alive": t.get("t_alive", True),
            # beacon_id set only when there is at least one non-terminated agent
            "beacon_id": ",".join(agent_ids) if ctx_agent else "",
            "note": "\n".join(note_parts),
            "source": "adaptix",
        })
        seen_ips.add(ip)

    # Secondary: agents without a target entry
    for a in agents:
        if not a:
            continue
        ip = (a.get("a_internal_ip") or a.get("a_external_ip") or "").strip()
        if not ip or ip in seen_ips:
            continue
        alive = a.get("a_mark", "") != "Terminated"
        domain = (a.get("a_domain") or "").strip()
        result_hosts.append({
            "ip": ip,
            "hostname": (a.get("a_computer") or "").strip(),
            "os": (a.get("a_os_desc") or "").strip(),
            "domain": domain,
            "username": (a.get("a_username") or "").strip(),
            "arch": (a.get("a_arch") or "").strip(),
            "process": (a.get("a_process") or "").strip(),
            "pid": a.get("a_pid"),
            "alive": alive,
            # beacon_id set only for non-terminated standalone agents
            "beacon_id": (a.get("a_id") or "") if alive else "",
            "note": f"Listener: {a.get('a_listener', '')}" + (f"\nDomain: {domain}" if domain else ""),
            "source": "adaptix",
        })
        seen_ips.add(ip)

    result_creds = []
    for c in raw_creds:
        if not c:
            continue
        uname = (c.get("c_username") or "").strip()
        if not uname:
            continue
        ctype_raw = (c.get("c_type") or "plain").lower()
        ctype = "hash" if ("hash" in ctype_raw or "ntlm" in ctype_raw) else "plain"
        result_creds.append({
            "username": uname,
            "secret": c.get("c_password") or "",
            "type": ctype,
            "realm": (c.get("c_realm") or "").strip(),
            "host": (c.get("c_host") or "").strip(),
            "source": "adaptix",
        })

    return {"hosts": result_hosts, "creds": result_creds}


# ── Mythic ────────────────────────────────────────────────────────────
#
# Mythic exposes a Hasura GraphQL endpoint at /graphql/v1/graphql.
# Auth: POST /auth → JWT, or static `apitoken` header (set in Mythic UI).
# Default port: 7443 (HTTPS). cfg["url"] should be https://host:7443.

async def _mythic_auth_headers(cfg: dict, client: httpx.AsyncClient) -> dict[str, str]:
    """Return headers carrying either an apitoken or a fresh JWT."""
    token = (cfg.get("token") or "").strip()
    if token:
        return {"apitoken": token}
    username = cfg.get("username") or "mythic_admin"
    password = cfg.get("password", "")
    url = cfg["url"].rstrip("/")
    r = await client.post(
        f"{url}/auth",
        json={"username": username, "password": password, "scripting_version": "0.1"},
    )
    r.raise_for_status()
    data = r.json()
    jwt = data.get("access_token") or data.get("token") or ""
    if not jwt:
        raise HTTPException(400, "Mythic login: no access_token in response")
    return {"Authorization": f"Bearer {jwt}"}


async def _mythic_graphql(cfg: dict, client: httpx.AsyncClient, query: str, headers: dict) -> dict:
    url = cfg["url"].rstrip("/")
    r = await client.post(
        f"{url}/graphql/",
        json={"query": query},
        headers=headers,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("errors"):
        raise HTTPException(400, f"Mythic GraphQL error: {data['errors']}")
    return data.get("data", {})


_MYTHIC_CALLBACK_FIELDS = """
id
agent_callback_id
host
user
domain
ip
external_ip
os
architecture
pid
process_name
active
integrity_level
description
last_checkin
init_callback
"""

_MYTHIC_CRED_FIELDS = """
id
account
realm
credential_text
type
comment
"""


async def _mythic_sync(cfg: dict) -> dict:
    """
    Mythic 3.x callbacks → hosts, credentials → creds.
    """
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _mythic_auth_headers(cfg, client)
        query = (
            "query RootNotesSync {"
            f"  callback {{ {_MYTHIC_CALLBACK_FIELDS} }}"
            f"  credential {{ {_MYTHIC_CRED_FIELDS} }}"
            "}"
        )
        data = await _mythic_graphql(cfg, client, query, headers)

    callbacks = data.get("callback") or []
    creds_raw = data.get("credential") or []

    result_hosts = []
    for cb in callbacks:
        if not cb:
            continue
        ip = (cb.get("ip") or "").strip()
        # Mythic sometimes stores ip as JSON-array string like "[\"10.0.0.5\"]"
        if ip.startswith("[") and ip.endswith("]"):
            try:
                arr = json.loads(ip)
                if isinstance(arr, list) and arr:
                    ip = str(arr[0]).strip()
            except Exception:
                pass
        if not ip:
            ip = (cb.get("external_ip") or "").strip()
        alive = bool(cb.get("active", True))
        note_parts = []
        if cb.get("description"):
            note_parts.append(cb["description"])
        if cb.get("integrity_level") is not None:
            note_parts.append(f"Integrity: {cb['integrity_level']}")
        if cb.get("process_name"):
            note_parts.append(f"Process: {cb['process_name']} (PID {cb.get('pid', '?')})")
        if cb.get("last_checkin"):
            note_parts.append(f"Last check-in: {cb['last_checkin']}")
        result_hosts.append({
            "ip": ip,
            "hostname": (cb.get("host") or "").strip(),
            "os": (cb.get("os") or "").strip(),
            "domain": (cb.get("domain") or "").strip(),
            "username": (cb.get("user") or "").strip(),
            "arch": (cb.get("architecture") or "").strip(),
            "process": (cb.get("process_name") or "").strip(),
            "pid": cb.get("pid"),
            "alive": alive,
            "beacon_id": str(cb.get("agent_callback_id") or cb.get("id") or "") if alive else "",
            "note": "\n".join(note_parts),
            "source": "mythic",
        })

    result_creds = []
    for c in creds_raw:
        if not c:
            continue
        account = (c.get("account") or "").strip()
        if not account:
            continue
        ctype_raw = (c.get("type") or "plaintext").lower()
        ctype = "hash" if ("hash" in ctype_raw or "ntlm" in ctype_raw or "kerberos" in ctype_raw) else "plain"
        result_creds.append({
            "username": account,
            "secret": c.get("credential_text") or "",
            "type": ctype,
            "realm": (c.get("realm") or "").strip(),
            "host": "",
            "source": "mythic",
        })

    return {"hosts": result_hosts, "creds": result_creds}


_CONNECTORS = {
    "sliver": _sliver_sync,
    "adaptix": _adaptix_sync,
    "mythic": _mythic_sync,
}


# ── Live-agents-only connectors (for sessions view) ───────────────────

async def _adaptix_live_agents(cfg: dict) -> list[dict]:
    """Return only currently active (non-terminated) Adaptix agents."""
    url = cfg["url"].rstrip("/")
    ep = cfg.get("endpoint", "/endpoint").rstrip("/") or "/endpoint"
    base = f"{url}{ep}"

    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        token = cfg.get("token", "")
        if not token:
            login_r = await client.post(
                f"{base}/login",
                json={"username": cfg.get("username") or "operator", "password": cfg.get("password", ""), "version": ""},
            )
            login_r.raise_for_status()
            token = login_r.json().get("access_token") or ""

        headers = {"Authorization": f"Bearer {token}"}
        agents_r = await client.get(f"{base}/agent/list", headers=headers)
        agents_r.raise_for_status()
        agents = agents_r.json()
        if not isinstance(agents, list):
            agents = []

    import time as _time
    now_ts = int(_time.time())
    # Per-integration override; otherwise treat agents idle > 10 min as dead.
    stale_threshold = int(cfg.get("stale_agent_seconds", 600))

    result = []
    for a in agents:
        mark = (a.get("a_mark") or "").strip()
        explicit_dead = mark.lower() in ("terminated", "dead", "killed", "lost", "inactive", "offline")

        # Adaptix exposes the last checkin as a_last_tick (unix seconds) on most
        # builds; older builds put it in a_last_seen as a parsable string. Treat
        # an agent as stale when we have a freshness signal AND it is older than
        # the configured threshold. If no signal is available we trust a_mark.
        last_tick_raw = a.get("a_last_tick") or a.get("a_last_seen") or 0
        try:
            last_tick = int(last_tick_raw)
        except Exception:
            last_tick = 0
        # a_last_tick is unix seconds when > 1e9
        stale = bool(last_tick > 1_000_000_000 and (now_ts - last_tick) > stale_threshold)

        alive = not (explicit_dead or stale)
        result.append({
            "ip": (a.get("a_internal_ip") or a.get("a_external_ip") or "").strip(),
            "hostname": (a.get("a_computer") or "").strip(),
            "username": (a.get("a_username") or "").strip(),
            "domain": (a.get("a_domain") or "").strip(),
            "os": (a.get("a_os_desc") or "").strip(),
            "arch": (a.get("a_arch") or "").strip(),
            "process": (a.get("a_process") or "").strip(),
            "agent_id": a.get("a_id") or "",
            "beacon_id": a.get("a_id") or "",
            "listener": a.get("a_listener") or "",
            "alive": alive,
            "mark": mark or ("stale" if stale else ""),
            "last_seen": a.get("a_last_seen") or "",
            "last_tick": last_tick if last_tick > 0 else None,
            "stale_seconds": (now_ts - last_tick) if (alive is False and stale) else None,
        })
    return result


async def _adaptix_auth_headers(cfg: dict, client: httpx.AsyncClient) -> dict[str, str]:
    token = cfg.get("token", "")
    if not token:
        login_r = await client.post(
            f"{cfg['_adaptix_base']}/login",
            json={"username": cfg.get("username") or "operator", "password": cfg.get("password", ""), "version": ""},
        )
        login_r.raise_for_status()
        token = login_r.json().get("access_token") or login_r.json().get("token") or ""
    return {"Authorization": f"Bearer {token}"}


def _adaptix_base(cfg: dict) -> str:
    url = cfg["url"].rstrip("/")
    ep = cfg.get("endpoint", "/endpoint").rstrip("/") or "/endpoint"
    return f"{url}{ep}"


async def _adaptix_fetch_creds(cfg: dict) -> list[dict]:
    base = _adaptix_base(cfg)
    local_cfg = {**cfg, "_adaptix_base": base}
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _adaptix_auth_headers(local_cfg, client)
        c_r = await client.get(f"{base}/creds/list", headers=headers)
        c_r.raise_for_status()
        data = c_r.json()
        if not isinstance(data, list):
            return []
        return data


async def _adaptix_fetch_bof_catalog(cfg: dict) -> list[dict]:
    base = _adaptix_base(cfg)
    local_cfg = {**cfg, "_adaptix_base": base}
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _adaptix_auth_headers(local_cfg, client)
        r = await client.post(f"{base}/axscript/commands", headers=headers, json={})
        if r.status_code in (404, 405):
            return []
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            return []
        return _normalize_axscript_catalog(data)


def _normalize_c2_cred(raw: dict, integration_id: str) -> dict:
    return {
        "id": raw.get("c_creds_id") or raw.get("id") or "",
        "source": "c2",
        "integration_id": integration_id,
        "username": (raw.get("c_username") or "").strip(),
        "secret": raw.get("c_password") or "",
        "domain": (raw.get("c_realm") or "").strip(),
        "host": (raw.get("c_host") or "").strip(),
        "type": (raw.get("c_type") or "plain").strip(),
        "label": (raw.get("c_username") or "").strip(),
    }


def _normalize_choice_list(raw) -> list[dict]:
    values = raw or []
    if isinstance(values, dict):
        values = values.get("choices") or values.get("options") or values.get("values") or []
    result = []
    for item in values:
        if isinstance(item, dict):
            value = item.get("value")
            if value is None:
                value = item.get("id") or item.get("name") or item.get("key")
            label = item.get("label") or item.get("title") or item.get("name") or str(value or "")
        else:
            value = item
            label = str(item)
        if value is None:
            continue
        result.append({"value": str(value), "label": str(label)})
    return result


def _normalize_param_type(raw_type: str, choices: list[dict]) -> str:
    t = (raw_type or "").strip().lower()
    if choices:
        return "choice"
    if t in ("bool", "boolean", "checkbox", "switch"):
        return "boolean"
    if t in ("int", "integer", "number", "float"):
        return "number"
    if t in ("select", "enum", "choice", "radio"):
        return "choice"
    if t in ("textarea", "multiline", "textblock"):
        return "textarea"
    return "text"


def _normalize_param(raw: dict, idx: int) -> dict:
    choices = _normalize_choice_list(raw.get("choices") or raw.get("options") or raw.get("enum") or raw.get("values"))
    key = raw.get("key") or raw.get("name") or raw.get("id") or raw.get("param") or raw.get("arg") or f"arg_{idx + 1}"
    label = raw.get("label") or raw.get("title") or raw.get("name") or key
    raw_type = raw.get("type") or raw.get("input_type") or raw.get("kind") or raw.get("widget") or ""
    return {
        "key": str(key),
        "label": str(label),
        "type": _normalize_param_type(str(raw_type), choices),
        "raw_type": str(raw_type),
        "required": bool(raw.get("required") or raw.get("mandatory")),
        "default": raw.get("default") if raw.get("default") is not None else raw.get("value"),
        "placeholder": raw.get("placeholder") or raw.get("example") or "",
        "description": raw.get("description") or raw.get("help") or raw.get("hint") or "",
        "choices": choices,
        "position": idx,
    }


def _extract_command_params(command: dict) -> list[dict]:
    raw_params = command.get("parameters") or command.get("params") or command.get("args") or command.get("fields") or command.get("options") or []
    if not isinstance(raw_params, list):
        return []
    return [_normalize_param(item if isinstance(item, dict) else {"name": str(item)}, idx) for idx, item in enumerate(raw_params)]


def _build_template_from_command(name: str, command: dict, params: list[dict]) -> str:
    template = command.get("template") or command.get("cmdline") or command.get("commandline") or command.get("usage") or ""
    template = str(template or "").strip()
    if template:
        return template
    if not params:
        return name
    return " ".join([name, *[f"{{{{{param['key'].upper()}}}}}" for param in params]])


def _parse_template_placeholders(template: str, params: list[dict]) -> list[dict]:
    known = {item["key"] for item in params}
    next_params = list(params)
    for match in re.findall(r"\{\{([A-Z0-9_]+)\}\}", template or ""):
        key = match.lower()
        if key in known:
            continue
        next_params.append({
            "key": key,
            "label": match,
            "type": "text",
            "raw_type": "placeholder",
            "required": False,
            "default": "",
            "placeholder": "",
            "description": "",
            "choices": [],
            "position": len(next_params),
        })
        known.add(key)
    return next_params


def _normalize_axscript_catalog(raw_catalog: list[dict]) -> list[dict]:
    result = []
    for source_idx, entry in enumerate(raw_catalog or []):
        source_name = entry.get("Agent") or entry.get("agent_name") or entry.get("Listener") or ""
        groups = entry.get("Groups") or entry.get("groups") or []
        for group_idx, group in enumerate(groups):
            if not isinstance(group, dict):
                continue
            group_name = group.get("group_name") or group.get("name") or "General"
            group_desc = group.get("group_description") or group.get("description") or ""
            script_name = group.get("script_name") or group.get("source") or source_name or ""
            for cmd_idx, command in enumerate(group.get("commands") or []):
                if not isinstance(command, dict):
                    continue
                name = str(command.get("name") or command.get("cmd") or command.get("title") or command.get("command") or "").strip()
                if not name:
                    continue
                params = _extract_command_params(command)
                template = _build_template_from_command(name, command, params)
                params = _parse_template_placeholders(template, params)
                result.append({
                    "id": f"{source_idx}:{group_idx}:{cmd_idx}:{name}",
                    "name": name,
                    "title": command.get("title") or name,
                    "group": group_name,
                    "group_description": group_desc,
                    "script_name": script_name,
                    "description": command.get("description") or command.get("help") or group_desc,
                    "template": template,
                    "parameters": params,
                    "raw": command,
                })
    return result


async def _adaptix_fetch_agent_tasks(cfg: dict, agent_id: str, limit: int = 30) -> list[dict]:
    base = _adaptix_base(cfg)
    local_cfg = {**cfg, "_adaptix_base": base}
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _adaptix_auth_headers(local_cfg, client)
        task_r = await client.get(f"{base}/agent/task/list", headers=headers, params={"agent_id": agent_id, "limit": limit, "offset": 0})
        task_r.raise_for_status()
        tasks = task_r.json()
        if not isinstance(tasks, list):
            return []
        return [{
            "task_id": item.get("a_task_id") or "",
            "cmdline": item.get("a_cmdline") or "",
            "completed": bool(item.get("a_completed")),
            "text": item.get("a_text") or "",
            "message": item.get("a_message") or "",
            "msg_type": item.get("a_msg_type") or "",
            "start_time": item.get("a_start_time") or "",
            "finish_time": item.get("a_finish_time") or "",
            "computer": item.get("a_computer") or "",
            "user": item.get("a_user") or "",
            "raw": item,
        } for item in tasks]


def _cred_matches_host(cred: dict, host: models.Host) -> bool:
    host_ips = set(host.ips or []) | ({host.ip} if host.ip else set())
    if cred.get("host") and cred.get("host") in host_ips:
        return True
    if host.hostname and cred.get("host") == host.hostname:
        return True
    host_domain = (host.domain or "").strip().lower()
    cred_domain = (cred.get("domain") or "").strip().lower()
    return bool(host_domain and cred_domain and host_domain == cred_domain)


def _render_command_with_cred(commandline: str, cred: dict | None, host: models.Host | None) -> str:
    if not cred:
        return commandline
    domain = (cred.get("domain") or "").strip()
    username = (cred.get("username") or "").strip()
    secret = cred.get("secret") or ""
    values = {
        "{{USER}}": username,
        "{{USERNAME}}": username,
        "{{PASS}}": secret,
        "{{PASSWORD}}": secret,
        "{{SECRET}}": secret,
        "{{HASH}}": secret,
        "{{DOMAIN}}": domain,
        "{{REALM}}": domain,
        "{{HOST}}": host.ip if host else "",
        "{{TARGET}}": host.ip if host else "",
    }
    rendered = commandline
    for key, value in values.items():
        rendered = rendered.replace(key, value or "")
    return rendered


async def _adaptix_execute(cfg: dict, agent_id: str, commandline: str, wait_for_output: bool = True, timeout_seconds: int = 12) -> dict:
    base = _adaptix_base(cfg)
    local_cfg = {**cfg, "_adaptix_base": base}
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=max(30, timeout_seconds + 5)) as client:
        headers = await _adaptix_auth_headers(local_cfg, client)
        exec_r = await client.post(f"{base}/agent/command/raw", headers=headers, json={"id": agent_id, "cmdline": commandline})
        exec_r.raise_for_status()
        exec_data = exec_r.json() if exec_r.content else {"ok": True}
        result = {"accepted": bool(exec_data.get("ok", True)), "message": exec_data.get("message") or "", "commandline": commandline, "agent_id": agent_id}
        if not wait_for_output:
            return result

        started = utcnow()
        latest = None
        while (utcnow() - started).total_seconds() < max(3, timeout_seconds):
            task_r = await client.get(f"{base}/agent/task/list", headers=headers, params={"agent_id": agent_id, "limit": 20, "offset": 0})
            if task_r.status_code == 200:
                tasks = task_r.json()
                if isinstance(tasks, list):
                    for task in tasks:
                        if (task.get("a_cmdline") or "").strip() == commandline.strip():
                            latest = task
                            if task.get("a_completed"):
                                result["task"] = task
                                result["output"] = task.get("a_text") or task.get("a_message") or ""
                                return result
            await asyncio.sleep(0.8)
        if latest:
            result["task"] = latest
            result["output"] = latest.get("a_text") or latest.get("a_message") or ""
        return result


def _sliver_format_live(item, is_beacon: bool) -> dict:
    alive = not getattr(item, "IsDead", False)
    remote = getattr(item, "RemoteAddress", "") or ""
    last_checkin = getattr(item, "LastCheckin", None)
    return {
        "ip": remote.split(":")[0] if remote else "",
        "hostname": getattr(item, "Hostname", "") or "",
        "username": getattr(item, "Username", "") or "",
        "domain": "",
        "os": (getattr(item, "OS", "") or "") + (" " + getattr(item, "Arch", "") if getattr(item, "Arch", "") else ""),
        "arch": getattr(item, "Arch", "") or "",
        "process": getattr(item, "Filename", "") or "",
        "beacon_id": getattr(item, "ID", "") or "",
        "listener": getattr(item, "ActiveC2", "") or "",
        "alive": alive,
        "mark": "alive" if alive else "dead",
        "last_seen": str(last_checkin) if last_checkin else "",
        "session_type": "beacon" if is_beacon else "session",
    }


async def _sliver_live_agents(cfg: dict) -> list[dict]:
    client = await _sliver_connect(cfg)
    try:
        sessions = await client.sessions()
        beacons = await client.beacons()
    finally:
        await client.close()
    return (
        [_sliver_format_live(s, is_beacon=False) for s in (sessions or [])]
        + [_sliver_format_live(b, is_beacon=True) for b in (beacons or [])]
    )


async def _sliver_execute(cfg: dict, agent_id: str, commandline: str,
                          wait_for_output: bool = True, timeout_seconds: int = 12) -> dict:
    """
    Run a shell command on a Sliver session or beacon. We try session
    first (interactive, output immediate); if the ID doesn't match a
    session we look it up among beacons (async, returns task id).

    Commandline is split into argv via shlex. By convention the first
    token is the program; subsequent tokens are args. Use shell-style
    quoting for spaces (`"foo bar"`).
    """
    import shlex
    try:
        parts = shlex.split(commandline)
    except ValueError as e:
        raise HTTPException(400, f"Sliver execute: malformed command line: {e}")
    if not parts:
        raise HTTPException(400, "Sliver execute: empty command")
    program, args = parts[0], parts[1:]

    client = await _sliver_connect(cfg)
    try:
        sessions = await client.sessions()
        target_session = next((s for s in (sessions or []) if getattr(s, "ID", "") == agent_id), None)
        if target_session:
            interact = client.interact_session(agent_id)
            exec_result = await asyncio.wait_for(
                interact.execute(program, args, output=wait_for_output),
                timeout=max(5, timeout_seconds),
            )
            output = ""
            if exec_result is not None:
                stdout = getattr(exec_result, "Stdout", b"") or b""
                stderr = getattr(exec_result, "Stderr", b"") or b""
                output = (stdout.decode(errors="replace") if isinstance(stdout, (bytes, bytearray)) else stdout)
                if stderr:
                    err = stderr.decode(errors="replace") if isinstance(stderr, (bytes, bytearray)) else stderr
                    output = f"{output}\n[stderr]\n{err}" if output else err
            return {
                "accepted": True,
                "agent_id": agent_id,
                "commandline": commandline,
                "kind": "session",
                "output": output,
                "status": getattr(exec_result, "Status", 0) if exec_result else 0,
            }

        beacons = await client.beacons()
        target_beacon = next((b for b in (beacons or []) if getattr(b, "ID", "") == agent_id), None)
        if not target_beacon:
            raise HTTPException(404, f"Sliver agent {agent_id!r} not found")
        interact = client.interact_beacon(agent_id)
        task = await interact.execute(program, args, output=wait_for_output)
        task_id = getattr(task, "ID", "") if task else ""
        return {
            "accepted": True,
            "agent_id": agent_id,
            "commandline": commandline,
            "kind": "beacon",
            "task_id": task_id,
            "output": "",  # Beacon outputs arrive async via events; surfaced through fetch_agent_tasks.
        }
    finally:
        await client.close()


async def _sliver_fetch_agent_tasks(cfg: dict, agent_id: str, limit: int = 30) -> list[dict]:
    """
    Sliver beacon tasks history. Sessions don't have task history (output
    is immediate, recorded only in our HostActivity log); for those we
    return an empty list.
    """
    client = await _sliver_connect(cfg)
    try:
        beacons = await client.beacons()
        target_beacon = next((b for b in (beacons or []) if getattr(b, "ID", "") == agent_id), None)
        if not target_beacon:
            return []
        interact = client.interact_beacon(agent_id)
        try:
            tasks = await interact.tasks()
        except Exception as e:
            logger.warning("Sliver beacon tasks fetch failed for %s: %s", agent_id, e)
            return []
    finally:
        await client.close()

    result = []
    for t in (tasks or [])[:limit]:
        description = getattr(t, "Description", "") or ""
        state = getattr(t, "State", "") or ""
        result.append({
            "task_id": getattr(t, "ID", "") or "",
            "cmdline": description,
            "completed": state.lower() == "completed",
            "text": "",  # full output streamed separately; not pulled here to keep request cheap
            "message": "",
            "msg_type": state,
            "start_time": str(getattr(t, "CreatedAt", "") or ""),
            "finish_time": str(getattr(t, "CompletedAt", "") or ""),
            "computer": "",
            "user": "",
            "raw": {"id": getattr(t, "ID", ""), "state": state, "description": description},
        })
    return result


async def _mythic_execute(cfg: dict, callback_id: str, commandline: str,
                          wait_for_output: bool = True, timeout_seconds: int = 12) -> dict:
    """
    Run a command on a Mythic callback. Uses the `createTask` mutation
    and polls task status + responses until completion (or timeout).

    `commandline` is passed as `params` to the `shell` command, which is
    the conventional arbitrary-shell entry point for most Mythic agents
    (Apollo, Poseidon, Athena, Atomic). To target a different command,
    prefix the line with `!<command> ` — e.g. `!run whoami`.
    """
    command = "shell"
    params = commandline
    stripped = commandline.lstrip()
    if stripped.startswith("!"):
        parts = stripped[1:].split(" ", 1)
        command = parts[0]
        params = parts[1] if len(parts) > 1 else ""

    cb_id = _mythic_resolve_callback_db_id(callback_id)

    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=max(30, timeout_seconds + 5)) as client:
        headers = await _mythic_auth_headers(cfg, client)
        # Mythic stores callback by integer id; agent_callback_id is a UUID
        # the operator usually sees. Resolve UUID → id if needed.
        if cb_id is None:
            lookup = await _mythic_graphql(
                cfg, client,
                f'query {{ callback(where: {{agent_callback_id: {{_eq: "{callback_id}"}} }}) {{ id }} }}',
                headers,
            )
            rows = lookup.get("callback") or []
            if not rows:
                raise HTTPException(404, f"Mythic callback {callback_id!r} not found")
            cb_id = rows[0]["id"]

        params_json = json.dumps(params)
        mutation = (
            "mutation RootNotesCreateTask {"
            f"  createTask(callback_id: {cb_id}, command: \"{command}\", params: {params_json}) {{"
            "    id display_id status error"
            "  }"
            "}"
        )
        data = await _mythic_graphql(cfg, client, mutation, headers)
        out = (data.get("createTask") or {})
        if out.get("error"):
            raise HTTPException(400, f"Mythic createTask error: {out['error']}")
        task_db_id = out.get("id")
        task_display_id = out.get("display_id")
        result = {
            "accepted": True,
            "task_id": task_db_id,
            "display_id": task_display_id,
            "commandline": commandline,
            "command": command,
            "agent_id": callback_id,
        }
        if not wait_for_output or not task_db_id:
            return result

        started = utcnow()
        latest = None
        while (utcnow() - started).total_seconds() < max(3, timeout_seconds):
            poll_q = (
                "query RootNotesPollTask {"
                f"  task(where: {{id: {{_eq: {task_db_id}}} }}) {{"
                "    id status completed stdout stderr"
                "    responses(order_by: {sequence_number: asc}) { response_text is_error }"
                "  }"
                "}"
            )
            poll_data = await _mythic_graphql(cfg, client, poll_q, headers)
            rows = poll_data.get("task") or []
            if rows:
                latest = rows[0]
                if latest.get("completed") or (latest.get("status") or "").lower() in ("completed", "error"):
                    break
            await asyncio.sleep(0.8)

        if latest:
            responses = latest.get("responses") or []
            output_parts = [r.get("response_text") or "" for r in responses]
            if latest.get("stdout"):
                output_parts.append(latest["stdout"])
            result["output"] = "\n".join(p for p in output_parts if p)
            result["task"] = latest
        return result


def _mythic_resolve_callback_db_id(callback_id: str) -> int | None:
    """If callback_id is already numeric, return it as int. Otherwise None
    (caller will resolve via GraphQL lookup using agent_callback_id UUID)."""
    try:
        return int(callback_id)
    except (TypeError, ValueError):
        return None


async def _mythic_fetch_agent_tasks(cfg: dict, callback_id: str, limit: int = 30) -> list[dict]:
    cb_id = _mythic_resolve_callback_db_id(callback_id)
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _mythic_auth_headers(cfg, client)
        if cb_id is None:
            lookup = await _mythic_graphql(
                cfg, client,
                f'query {{ callback(where: {{agent_callback_id: {{_eq: "{callback_id}"}} }}) {{ id }} }}',
                headers,
            )
            rows = lookup.get("callback") or []
            if not rows:
                return []
            cb_id = rows[0]["id"]

        query = (
            "query RootNotesAgentTasks {"
            f"  task(where: {{callback_id: {{_eq: {cb_id}}} }},"
            f"    order_by: {{timestamp: desc}}, limit: {max(1, min(limit, 100))}) {{"
            "    id display_id command_name params status completed timestamp stdout stderr"
            "    responses(order_by: {sequence_number: asc}, limit: 50) { response_text is_error }"
            "    operator { username }"
            "  }"
            "}"
        )
        data = await _mythic_graphql(cfg, client, query, headers)
    rows = data.get("task") or []
    result = []
    for t in rows:
        responses = t.get("responses") or []
        output_parts = [r.get("response_text") or "" for r in responses]
        if t.get("stdout"):
            output_parts.append(t["stdout"])
        result.append({
            "task_id": t.get("id"),
            "display_id": t.get("display_id"),
            "cmdline": f"{t.get('command_name') or ''} {t.get('params') or ''}".strip(),
            "completed": bool(t.get("completed")),
            "text": "\n".join(p for p in output_parts if p),
            "message": "",
            "msg_type": t.get("status") or "",
            "start_time": t.get("timestamp") or "",
            "finish_time": "",
            "computer": "",
            "user": (t.get("operator") or {}).get("username") or "",
            "raw": t,
        })
    return result


async def _mythic_live_agents(cfg: dict) -> list[dict]:
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        headers = await _mythic_auth_headers(cfg, client)
        query = (
            "query RootNotesLiveAgents {"
            f"  callback {{ {_MYTHIC_CALLBACK_FIELDS} }}"
            "}"
        )
        data = await _mythic_graphql(cfg, client, query, headers)
    callbacks = data.get("callback") or []
    result = []
    for cb in callbacks:
        if not cb:
            continue
        ip = (cb.get("ip") or "").strip()
        if ip.startswith("[") and ip.endswith("]"):
            try:
                arr = json.loads(ip)
                if isinstance(arr, list) and arr:
                    ip = str(arr[0]).strip()
            except Exception:
                pass
        alive = bool(cb.get("active", True))
        result.append({
            "ip": ip or (cb.get("external_ip") or "").strip(),
            "hostname": (cb.get("host") or "").strip(),
            "username": (cb.get("user") or "").strip(),
            "domain": (cb.get("domain") or "").strip(),
            "os": (cb.get("os") or "").strip(),
            "arch": (cb.get("architecture") or "").strip(),
            "process": (cb.get("process_name") or "").strip(),
            "beacon_id": str(cb.get("agent_callback_id") or cb.get("id") or ""),
            "listener": "",
            "alive": alive,
            "mark": "alive" if alive else "dead",
            "last_seen": cb.get("last_checkin") or "",
        })
    return result


_LIVE_CONNECTORS: dict[str, Any] = {
    "adaptix":       _adaptix_live_agents,
    "sliver":        _sliver_live_agents,
    "mythic":        _mythic_live_agents,
}


# ── Sync endpoint ─────────────────────────────────────────────────────

@router.post("/{iid}/test")
async def test_connection(
    iid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    integrations = _load_integrations(db)
    cfg = next((c for c in integrations if c.get("id") == iid), None)
    if not cfg:
        raise HTTPException(404, "Integration not found")
    if not _can_manage_integration(db, user, cfg):
        raise HTTPException(403, "Insufficient permissions to manage this integration")
    if not cfg.get("enabled"):
        raise HTTPException(400, "Integration is disabled")

    connector = _CONNECTORS.get(cfg["type"])
    if not connector:
        raise HTTPException(400, f"Unsupported C2 type: {cfg['type']}")

    try:
        data = await connector(cfg)
        if data.get("error"):
            raise HTTPException(400, f"C2 test failed: {data['error']}")
        return {
            "ok": True,
            "hosts_found": len(data.get("hosts") or []),
            "creds_found": len(data.get("creds") or []),
        }
    except HTTPException:
        raise
    except httpx.HTTPStatusError as e:
        raise HTTPException(400, f"C2 API error {e.response.status_code}: {e.response.text[:300]}")
    except httpx.ConnectError as e:
        raise HTTPException(400, f"Connection failed: {e}")
    except Exception as e:
        raise HTTPException(400, f"Error: {e}")


async def _do_project_sync(cfg: dict, pid: str, db: Session, iid: str | None = None, created_by: str = "auto") -> dict:
    """Core sync logic: fetch data from C2 and upsert into project. Used by both manual and auto-sync."""
    connector = _CONNECTORS.get(cfg["type"])
    if not connector:
        raise ValueError(f"Unsupported C2 type: {cfg['type']}")

    label = cfg.get("label") or cfg.get("type", "c2")
    job = start_job(
        db, pid, "c2_sync", f"C2 Sync: {label}",
        target=cfg.get("url", ""), created_by=created_by,
        connector_key="c2_integration", operation="sync",
        related_entity_type="project", related_entity_id=pid,
        request_json={"iid": iid, "type": cfg.get("type"), "url": cfg.get("url"), "project_id": pid},
    )

    try:
        result = await _do_project_sync_inner(cfg, pid, db, iid)
    except Exception as e:
        finish_job(db, job, status="failed", error_output=str(e))
        raise

    finish_job(db, job, status="done",
               output=f"hosts_found={result['hosts_found']} created={result['hosts_created']} updated={result['hosts_updated']} creds_created={result['creds_created']}",
               result=result)
    return result


async def _do_project_sync_inner(cfg: dict, pid: str, db: Session, iid: str | None = None) -> dict:
    connector = _CONNECTORS.get(cfg["type"])
    if connector is None:
        raise HTTPException(400, f"Unsupported C2 type: {cfg.get('type')}")
    data = await connector(cfg)
    # Connectors that hit a remote API may report failure in-band as
    # `{"error": "...", "hosts": [], "creds": []}` (especially MSF). Surface
    # the message instead of silently treating zero hosts as a successful sync.
    if data.get("error"):
        raise HTTPException(400, f"C2 sync failed: {data['error']}")
    ts = ts_now()
    created_hosts, updated_hosts, created_creds = 0, 0, 0
    source = cfg["type"]
    host_objects = []
    session_host_raw: list[tuple] = []  # (hobj, raw_h) for hosts with live sessions

    # ── Upsert hosts ─────────────────────────────────────────────────
    for h in data.get("hosts", []):
        ip = h.get("ip", "").strip()
        hostname = h.get("hostname", "").strip()
        if not ip and not hostname:
            continue
        if not ip:
            ip = hostname

        existing = db.query(models.Host).filter(
            models.Host.pid == pid, models.Host.ip == ip
        ).first()

        # OS: normalize
        os_raw = (h.get("os") or "").strip()
        os_clean = os_raw if os_raw else "Unknown"

        domain = (h.get("domain") or "").strip()

        # Notes: include C2 session metadata (already pre-formatted by connector)
        new_notes = (h.get("note") or "").strip()

        if existing:
            if hostname and not existing.hostname:
                existing.hostname = hostname
            if domain and not existing.domain:
                existing.domain = domain
            if os_clean and os_clean != "Unknown" and (not existing.os or existing.os in ("Linux", "Unknown", "")):
                existing.os = os_clean
            derived_status = _status_from_c2_host("", h)
            if _c2_owns_host_status(existing, source):
                if derived_status:
                    existing.status = derived_status
            else:
                next_status = _status_from_c2_host(existing.status or "", h)
                if next_status:
                    existing.status = next_status
            if new_notes and new_notes not in (existing.notes or ""):
                existing.notes = ((existing.notes or "") + "\n\n---\n" + new_notes).strip()
            if source not in (existing.tags or []):
                existing.tags = list(existing.tags or []) + [source]
            if not existing.import_source:
                existing.import_source = source
            updated_hosts += 1
            host_objects.append(existing)
        else:
            if not h.get("alive", True):
                continue
            initial_status = _status_from_c2_host("", h)
            hobj = models.Host(
                id=new_id("hst"),
                pid=pid,
                ip=ip,
                hostname=hostname,
                os=os_clean,
                domain=domain,
                status=initial_status or "up",
                tags=["c2", source],
                notes=new_notes,
                import_source=source,
            )
            db.add(hobj)
            created_hosts += 1
            host_objects.append(hobj)

        # Track hosts that have an actual live session signal
        if _has_live_session_signal(h):
            session_host_raw.append((host_objects[-1], h))

        # ── Auto-create cred for this session's user ─────────────────
        username = h.get("username", "").strip()
        if username:
            domain = ""
            uname = username
            if "\\" in username:
                parts = username.split("\\", 1)
                domain, uname = parts[0], parts[1]
            elif "@" in username:
                parts = username.split("@", 1)
                uname, domain = parts[0], parts[1]

            existing_cred = db.query(models.Cred).filter(
                models.Cred.pid == pid,
                models.Cred.username == uname,
                models.Cred.domain == domain,
            ).first()
            if not existing_cred:
                db.add(models.Cred(
                    id=new_id("crd"),
                    pid=pid,
                    username=uname,
                    domain=domain,
                    secret="",
                    type="plain",
                    service="os",
                    host=ip,
                    tags=["c2", source],
                ))
                created_creds += 1

    # ── Upsert harvested creds ────────────────────────────────────────
    for c in data.get("creds", []):
        uname = (c.get("username") or "").strip()
        if not uname:
            continue
        domain = (c.get("realm") or "").strip()
        existing = db.query(models.Cred).filter(
            models.Cred.pid == pid,
            models.Cred.username == uname,
            models.Cred.domain == domain,
        ).first()
        if not existing:
            db.add(models.Cred(
                id=new_id("crd"),
                pid=pid,
                username=uname,
                secret=c.get("secret", ""),
                type=c.get("type", "plain"),
                domain=domain,
                service=c.get("service", ""),
                host=c.get("host", ""),
                tags=["c2", source],
            ))
            created_creds += 1

    # ── Record C2 session as HostActivity so smart-build picks it up ─
    # Only hosts with an actual live session signal (beacon_id/agent_id/process/pid)
    session_host_ids = {hobj.id for hobj, _ in session_host_raw}

    for hobj, h in session_host_raw:
        try:
            existing_act = db.query(models.HostActivity).filter(
                models.HostActivity.pid == pid,
                models.HostActivity.host_id == hobj.id,
                models.HostActivity.activity_type == "c2",
            ).first()
            if existing_act:
                existing_act.ts = ts
                existing_act.summary = f"Active {source} session (synced {ts})"
            else:
                db.add(models.HostActivity(
                    id=new_id("ha"),
                    pid=pid,
                    host_id=hobj.id,
                    title=f"C2 session [{cfg['name']}]",
                    activity_type="c2",
                    summary=f"Active {source} session (synced {ts})",
                    status="done",
                    ts=ts,
                ))
        except Exception:
            pass

    # Remove stale C2 HostActivity for hosts synced from this connector but no longer
    # showing a live session signal (session ended / beacon gone)
    stale_host_ids = {hobj.id for hobj in host_objects} - session_host_ids
    if stale_host_ids:
        db.query(models.HostActivity).filter(
            models.HostActivity.pid == pid,
            models.HostActivity.host_id.in_(stale_host_ids),
            models.HostActivity.activity_type == "c2",
        ).delete(synchronize_session=False)

    log_event(
        db, pid, None, "c2", "sync",
        f"C2 sync [{cfg['name']}]: {created_hosts} new hosts, {updated_hosts} updated, {created_creds} creds",
        {"source": source, "integration": cfg["name"]},
    )
    db.commit()

    # ── Update last_sync ──────────────────────────────────────────────
    integrations_raw = db.query(models.GlobalSetting).filter(
        models.GlobalSetting.key == _C2_SETTING_KEY
    ).first()
    if integrations_raw and iid:
        raw_list = integrations_raw.value if isinstance(integrations_raw.value, list) else []
        for item in raw_list:
            if item.get("id") == iid:
                item["last_sync"] = ts
                break
        integrations_raw.value = raw_list
        db.commit()

    # ── Broadcast hosts ───────────────────────────────────────────────
    for hobj in host_objects:
        try:
            db.refresh(hobj)
            bcast(pid, "host", "upsert", schemas.Host.model_validate(hobj).model_dump())
        except Exception:
            pass

    # ── Auto-update topology ──────────────────────────────────────────
    if created_hosts > 0:
        try:
            from .topology import _run_auto_build
            _run_auto_build(pid, db)
        except Exception as e:
            logger.warning("C2 sync: topology auto-build failed for %s: %s", pid, e)

    return {
        "ok": True,
        "source": source,
        "hosts_found": len(data.get("hosts") or []),
        "hosts_created": created_hosts,
        "hosts_updated": updated_hosts,
        "creds_found": len(data.get("creds") or []),
        "creds_created": created_creds,
    }


@router.post("/{iid}/sync/{pid}")
async def sync_to_project(
    iid: str,
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_c2()
    integrations = _load_integrations(db)
    cfg = next((c for c in integrations if c.get("id") == iid), None)
    if not cfg:
        raise HTTPException(404, "Integration not found")
    if not cfg.get("enabled"):
        raise HTTPException(400, "Integration is disabled")
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    if not is_admin(user):
        from ..core.access import check_pid_access
        check_pid_access(db, pid, user, "hosts.create")
    try:
        return await _do_project_sync(cfg, pid, db, iid=iid, created_by=user.username)
    except httpx.HTTPStatusError as e:
        raise HTTPException(400, f"C2 API error {e.response.status_code}: {e.response.text[:300]}")
    except httpx.ConnectError as e:
        raise HTTPException(400, f"Connection failed: {e}")
    except Exception as e:
        raise HTTPException(400, f"Error: {e}")


# ── Project-scoped listing (for sync button in UI) ────────────────────

@router.get("/for-project/{pid}")
def list_for_project(
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    from ..core.access import check_pid_access
    check_pid_access(db, pid, user, "hosts.read")
    integrations = _load_integrations(db)
    visible = [_safe_integration(i) for i in _visible_integrations_for_pid(integrations, pid)]
    return visible


@router.get("/{iid}/bofs/{pid}")
async def list_bofs_for_project(
    iid: str,
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_c2()
    from ..core.access import check_pid_access
    check_pid_access(db, pid, user, "hosts.read")
    cfg = next((i for i in _visible_integrations_for_pid(_load_integrations(db), pid) if i.get("id") == iid), None)
    if not cfg:
        raise HTTPException(404, "Integration not found")
    if cfg.get("type") != "adaptix":
        return []
    try:
        return await _adaptix_fetch_bof_catalog(cfg)
    except Exception as e:
        logger.warning("Adaptix BOF catalog failed for %s: %s", iid, e)
        return []


@router.get("/agent-tasks/{pid}")
async def get_agent_tasks(
    pid: str,
    integration_id: str,
    agent_id: str,
    limit: int = 30,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_c2()
    from ..core.access import check_pid_access
    check_pid_access(db, pid, user, "hosts.read")
    if not integration_id.strip() or not agent_id.strip():
        raise HTTPException(400, "integration_id and agent_id are required")
    cfg = next((i for i in _visible_integrations_for_pid(_load_integrations(db), pid) if i.get("id") == integration_id), None)
    if not cfg:
        raise HTTPException(404, "Integration not found")
    c2_type = (cfg.get("type") or "").lower()
    try:
        if c2_type == "adaptix":
            return await _adaptix_fetch_agent_tasks(cfg, agent_id, max(1, min(limit, 100)))
        if c2_type == "mythic":
            return await _mythic_fetch_agent_tasks(cfg, agent_id, max(1, min(limit, 100)))
        if c2_type == "sliver":
            return await _sliver_fetch_agent_tasks(cfg, agent_id, max(1, min(limit, 100)))
        raise HTTPException(400, f"Agent task history not supported for C2 type {c2_type!r}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Failed to fetch agent tasks: {e}")


@router.get("/host-actions/{pid}/{host_id}")
async def get_host_actions(
    pid: str,
    host_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_c2()
    from ..core.access import check_pid_access
    from ..core.permissions import get_membership, get_permissions_for_role
    check_pid_access(db, pid, user, "hosts.read")
    if is_admin(user):
        can_read_secret = True
    else:
        m = get_membership(db, pid, user.id)
        can_read_secret = bool(m and "credentials.read_secret" in get_permissions_for_role(m.role))
    host = db.query(models.Host).filter(models.Host.id == host_id, models.Host.pid == pid).first()
    if not host:
        raise HTTPException(404, "Host not found")

    integrations = _visible_integrations_for_pid(_load_integrations(db), pid)
    sessions = []
    c2_creds = []
    bof_catalog = {}
    host_ips = set(host.ips or []) | ({host.ip} if host.ip else set())
    for cfg in integrations:
        c2_type = (cfg.get("type") or "").lower()
        if c2_type not in SUPPORTED_EXEC_C2_TYPES:
            continue
        live_fn = _LIVE_CONNECTORS.get(c2_type)
        if not live_fn:
            continue
        try:
            agents = await live_fn(cfg)
            matched = [a for a in agents if a.get("ip") in host_ips]
            for agent in matched:
                sessions.append({
                    "integration_id": cfg["id"],
                    "integration_name": cfg.get("name") or cfg["type"],
                    "integration_type": cfg["type"],
                    "agent_id": agent.get("agent_id") or agent.get("beacon_id") or "",
                    "beacon_id": agent.get("beacon_id") or "",
                    "ip": agent.get("ip") or "",
                    "hostname": agent.get("hostname") or "",
                    "username": agent.get("username") or "",
                    "domain": agent.get("domain") or "",
                    "os": agent.get("os") or "",
                    "arch": agent.get("arch") or "",
                    "process": agent.get("process") or "",
                    "listener": agent.get("listener") or "",
                    "session_type": agent.get("session_type") or "",
                    "alive": agent.get("alive", True),
                    "mark": agent.get("mark") or "",
                    "last_seen": agent.get("last_seen") or "",
                })
            # Cred fetch + BOF catalog are Adaptix-specific. Other C2 types
            # (if added later) should provide creds through their own sync.
            if c2_type == "adaptix":
                try:
                    creds = await _adaptix_fetch_creds(cfg)
                    c2_creds.extend([_normalize_c2_cred(item, cfg["id"]) for item in creds])
                except Exception as e:
                    logger.warning("Adaptix creds fetch failed for %s: %s", cfg.get("id"), e)
                try:
                    bof_catalog[cfg["id"]] = await _adaptix_fetch_bof_catalog(cfg)
                except Exception:
                    bof_catalog[cfg["id"]] = []
        except Exception as e:
            logger.warning("%s host actions failed for %s/%s: %s", c2_type, cfg.get("id"), host_id, e)

    project_creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    rootnotes_creds = []
    for cred in project_creds:
        host_ids = set(cred.host_ids or [])
        if host.id in host_ids or cred.host == host.ip or (host.hostname and cred.host == host.hostname) or (cred.is_domain and host.domain and (cred.domain or "").strip().lower() == (host.domain or "").strip().lower()):
            rootnotes_creds.append({
                "id": cred.id,
                "source": "rootnotes",
                "integration_id": "",
                "username": cred.username,
                "secret": decrypt_str(cred.secret) if can_read_secret else "",
                "domain": cred.domain,
                "host": cred.host,
                "type": cred.type,
                "label": cred.username,
            })

    if rootnotes_creds and can_read_secret:
        log_event(
            db, pid, getattr(user, "username", None), "audit", "read_credential_secrets",
            f"Credential secrets viewed via host actions ({len(rootnotes_creds)})",
            {"count": len(rootnotes_creds), "host_id": host.id},
        )
        db.commit()

    filtered_c2_creds = [item for item in c2_creds if _cred_matches_host(item, host)]
    return {
        "host_id": host.id,
        "sessions": sessions,
        "creds": rootnotes_creds + filtered_c2_creds,
        "bofs": bof_catalog,
    }


async def resolve_c2_cred(
    db: Session, pid: str, credential_id: str, credential_source: str, cfg: dict
) -> dict | None:
    """
    Lookup the cred selected for a C2 execution.

    `credential_source` ∈ {"rootnotes", "c2"}. For "c2" we ask the integration
    for its own cred list — currently only Adaptix exposes this. Other C2
    types fall through to the rootnotes Cred table.
    """
    if not credential_id:
        return None
    if credential_source == "c2" and (cfg.get("type") or "").lower() == "adaptix":
        creds = await _adaptix_fetch_creds(cfg)
        return next(
            (_normalize_c2_cred(item, cfg["id"]) for item in creds
             if str(item.get("c_creds_id") or item.get("id") or "") == credential_id),
            None,
        )
    # Fallback / MSF / rootnotes-sourced: regular project cred lookup
    cred = db.query(models.Cred).filter(models.Cred.id == credential_id, models.Cred.pid == pid).first()
    if not cred:
        return None
    return {
        "id": cred.id, "source": "rootnotes",
        "username": cred.username, "secret": decrypt_str(cred.secret),
        "domain": cred.domain, "host": cred.host, "type": cred.type,
    }


SUPPORTED_EXEC_C2_TYPES = ("adaptix", "mythic", "sliver")


async def perform_c2_command(
    db: Session,
    pid: str,
    host: models.Host,
    cfg: dict,
    agent_id: str,
    commandline: str,
    mode: str,
    cred: dict | None,
    wait_for_output: bool,
    timeout_seconds: int,
    title: str,
    actor_username: str = "",
) -> tuple[dict, models.HostActivity, str]:
    """
    Core C2 command execution — shared by the HTTP endpoint and the queued
    playbook step. Currently Adaptix-only; `SUPPORTED_EXEC_C2_TYPES` is the
    extension point — adding a new framework means adding to that tuple
    plus a branch below.

    Renders the command (cred substitution), calls the connector, records a
    HostActivity, broadcasts the event. Returns (raw_result_dict, activity_row,
    rendered_command). Raises on connector failure — caller decides how to
    surface the error (HTTP 400 vs. job finish_job(status='failed')).
    """
    c2_type = (cfg.get("type") or "").lower()
    if c2_type not in SUPPORTED_EXEC_C2_TYPES:
        raise ValueError(
            f"Execution is not supported for C2 type {c2_type!r}. "
            f"Supported: {', '.join(SUPPORTED_EXEC_C2_TYPES)}"
        )
    rendered_command = _render_command_with_cred(commandline, cred, host)
    if cred and cred.get("secret"):
        log_event(
            db, pid, actor_username or None, "audit", "secret_used_c2_exec",
            f"Credential secret used in C2 exec via {c2_type}: {cred.get('username') or ''}",
            {"cred_id": cred.get("id"), "username": cred.get("username"), "c2_type": c2_type, "agent_id": agent_id},
        )
        db.commit()
    if c2_type == "mythic":
        result = await _mythic_execute(cfg, agent_id, rendered_command, wait_for_output, timeout_seconds)
        summary = f"Executed via Mythic on callback {agent_id}"
    elif c2_type == "sliver":
        result = await _sliver_execute(cfg, agent_id, rendered_command, wait_for_output, timeout_seconds)
        summary = f"Executed via Sliver on {result.get('kind', 'agent')} {agent_id}"
    else:
        result = await _adaptix_execute(cfg, agent_id, rendered_command, wait_for_output, timeout_seconds)
        summary = f"Executed via Adaptix on agent {agent_id}"
    output = result.get("output") or result.get("message") or result.get("error") or ""
    # Strip the literal credential secret out of the stored command + output
    # before it lands in the DB and gets broadcast to every operator. The real
    # rendered_command was already handed to the connector above; it only
    # exists in memory from this point on.
    from ..core.secret_scrub import scrub_for_cred
    safe_command = scrub_for_cred(rendered_command, cred)
    safe_output = scrub_for_cred(output, cred)
    activity = models.HostActivity(
        id=new_id("ha"),
        pid=pid,
        host_id=host.id,
        title=title,
        activity_type="postex" if mode == "command" else "exploit",
        command=safe_command,
        summary=summary,
        output=safe_output,
        status="done",
        ts=ts_now(),
    )
    db.add(activity)
    db.commit()
    bcast(pid, "host_activity", "create", schemas.HostActivity.model_validate(activity).model_dump())
    log_event(
        db, pid, actor_username, "host_activity", "create",
        f"{title} on {host.ip or host.hostname}",
        {"host_id": host.id, "integration_id": cfg.get("id"), "c2_type": c2_type},
    )
    db.commit()
    return result, activity, rendered_command


@router.post("/execute/{pid}")
async def execute_host_action(
    pid: str,
    body: C2HostActionRequest,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_c2()
    from ..core.access import check_pid_access
    check_pid_access(db, pid, user, "command_outputs.create")
    host = db.query(models.Host).filter(models.Host.id == body.host_id, models.Host.pid == pid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    cfg = next((i for i in _visible_integrations_for_pid(_load_integrations(db), pid) if i.get("id") == body.integration_id), None)
    if not cfg:
        raise HTTPException(404, "Integration not found")
    if cfg.get("type") not in SUPPORTED_EXEC_C2_TYPES:
        raise HTTPException(400, f"Execution supported only for: {', '.join(SUPPORTED_EXEC_C2_TYPES)}")
    if not body.agent_id.strip():
        raise HTTPException(400, "agent_id is required")
    if not body.commandline.strip():
        raise HTTPException(400, "commandline is required")

    selected_cred = await resolve_c2_cred(
        db, pid, body.credential_id, body.credential_source, cfg,
    )

    title = (body.title or ("Adaptix BOF" if body.mode == "bof" else "Adaptix command")).strip()
    job = start_job(
        db, pid, "c2_exec", title,
        target=host.ip or host.hostname or host.id,
        command=body.commandline.strip(),
        created_by=user.username or "",
        connector_key="adaptix",
        operation="bof_execute" if body.mode == "bof" else "command_execute",
        related_entity_type="host",
        related_entity_id=host.id,
        request_json=body.model_dump(),
    )
    try:
        result, activity, rendered_command = await perform_c2_command(
            db, pid, host, cfg, body.agent_id.strip(), body.commandline.strip(),
            body.mode, selected_cred, body.wait_for_output, body.timeout_seconds,
            title, actor_username=user.username or "",
        )
        finish_job(db, job, status="done", output=result.get("output") or "", result=result)
        return {"ok": True, "job_id": job.id, "activity_id": activity.id, "result": result, "rendered_command": rendered_command}
    except Exception as e:
        finish_job(db, job, status="failed", error_output=str(e))
        raise HTTPException(400, f"Adaptix execution failed: {e}")


def _classify_privilege(username: str) -> str:
    """Classify agent privilege tier from username heuristics."""
    u = (username or "").strip()
    u_up = u.upper()
    # Machine accounts and NT AUTHORITY\SYSTEM
    if u.endswith("$") or u_up in ("SYSTEM", "ROOT") or "NT AUTHORITY" in u_up:
        return "system"
    # Well-known high-privilege local accounts
    if u_up in ("ADMINISTRATOR", "ADMIN"):
        return "admin"
    return "user"


_PRIV_RANK = {"system": 2, "admin": 1, "user": 0}
_PRIV_STATUS = {"system": "owned", "admin": "pwned", "user": "access"}
_PRIV_LABEL  = {"system": "SYSTEM", "admin": "admin", "user": "user"}


@router.get("/sessions/{pid}")
async def get_live_sessions(
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """Fetch live sessions from all enabled C2 integrations for a project and match to hosts."""
    _require_c2()
    from ..core.access import check_pid_access
    check_pid_access(db, pid, user, "hosts.read")

    integrations = _load_integrations(db)
    visible = _visible_integrations_for_pid(integrations, pid)

    project_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    ip_to_host = {h.ip: h for h in project_hosts if h.ip}

    result = []
    for cfg in visible:
        live_fn = _LIVE_CONNECTORS.get(cfg["type"])
        if not live_fn:
            continue
        try:
            agents = await live_fn(cfg)

            # Deduplicate: one entry per (ip, privilege_tier).
            # Within a tier keep the best agent: alive > dead, then most-recent last_seen.
            best: dict[tuple, dict] = {}
            for a in agents:
                ip = (a.get("ip") or "").strip()
                if not ip:
                    continue
                tier = _classify_privilege(a.get("username") or "")
                key = (ip, tier)
                prev = best.get(key)
                if prev is None:
                    best[key] = a
                else:
                    # Prefer alive over dead
                    if a.get("alive") and not prev.get("alive"):
                        best[key] = a
                    # If same alive-ness, prefer more recent last_seen
                    elif a.get("alive") == prev.get("alive"):
                        if (a.get("last_seen") or "") > (prev.get("last_seen") or ""):
                            best[key] = a

            for (ip, tier), a in sorted(best.items(), key=lambda x: (-_PRIV_RANK[x[0][1]], x[0][0])):
                matched = ip_to_host.get(ip)
                result.append({
                    "integration_id": cfg["id"],
                    "integration_name": cfg.get("name") or cfg["type"],
                    "integration_type": cfg["type"],
                    "ip": ip,
                    "hostname": a.get("hostname") or "",
                    "username": a.get("username") or "",
                    "domain": a.get("domain") or "",
                    "os": a.get("os") or "",
                    "arch": a.get("arch") or "",
                    "process": a.get("process") or "",
                    "beacon_id": a.get("beacon_id") or "",
                    "listener": a.get("listener") or "",
                    "alive": a.get("alive", True),
                    "mark": a.get("mark") or "",
                    "last_seen": a.get("last_seen") or "",
                    "privilege_tier": tier,
                    "privilege_label": _PRIV_LABEL[tier],
                    "suggested_status": _PRIV_STATUS[tier],
                    "matched_host_id": matched.id if matched else None,
                    "matched_host_status": matched.status if matched else None,
                })
        except Exception as e:
            result.append({
                "integration_id": cfg["id"],
                "integration_name": cfg.get("name") or cfg["type"],
                "integration_type": cfg["type"],
                "error": str(e),
            })

    return result
