"""
C2 framework integrations: Cobalt Strike, Sliver, Adaptix.

Each integration is stored as an encrypted config in global_settings.
Sync pulls sessions/agents/creds from the C2 and auto-populates
hosts, creds, and optionally findings.
"""
import secrets
from datetime import datetime
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.crypto import decrypt_str, encrypt_str
from ..core.deps import get_current_user, require_admin
from ..core.events import bcast, log_event
from ..core.job_tracker import start_job, finish_job
from ..core.logging_setup import get_logger
from ..core.utils import new_id
from ..database import get_db, SessionLocal
from ..plugins.registry import registry

logger = get_logger(__name__)


def _require_c2():
    m = registry.get("c2_integration")
    if not m or not m.enabled:
        raise HTTPException(404, "C2 Integration module is disabled")

router = APIRouter(prefix="/api/admin/c2", tags=["c2"])

_C2_SETTING_KEY = "c2_integrations"

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
    if c.get("token"):
        c["token"] = "***"
    if c.get("password"):
        c["password"] = "***"
    return c


# ── Pydantic models ───────────────────────────────────────────────────

class C2IntegrationCreate(BaseModel):
    name: str
    type: str                        # cobalt_strike | sliver | adaptix
    url: str
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


# ── CRUD ──────────────────────────────────────────────────────────────

@router.get("")
def list_integrations(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    _require_c2()
    return [_safe_integration(i) for i in _load_integrations(db)]


@router.post("", status_code=201)
def create_integration(
    body: C2IntegrationCreate,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    _require_c2()
    if body.type not in ("cobalt_strike", "sliver", "adaptix"):
        raise HTTPException(400, f"Unknown C2 type: {body.type}")
    integrations = _load_integrations(db)
    cfg = body.model_dump()
    cfg["id"] = new_id("c2")
    cfg["last_sync"] = None
    integrations.append(cfg)
    _save_integrations(db, integrations)
    return _safe_integration(cfg)


@router.patch("/{iid}")
def update_integration(
    iid: str,
    body: C2IntegrationUpdate,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    integrations = _load_integrations(db)
    idx = next((i for i, c in enumerate(integrations) if c.get("id") == iid), None)
    if idx is None:
        raise HTTPException(404, "Integration not found")
    updates = body.model_dump(exclude_none=True)
    integrations[idx].update(updates)
    _save_integrations(db, integrations)
    return _safe_integration(integrations[idx])


@router.delete("/{iid}", status_code=204)
def delete_integration(
    iid: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    integrations = _load_integrations(db)
    integrations = [c for c in integrations if c.get("id") != iid]
    _save_integrations(db, integrations)


# ── Connectors ────────────────────────────────────────────────────────

async def _cs_sync(cfg: dict) -> dict:
    """
    Cobalt Strike 4.7+ REST API.
    Requires: Team Server REST API enabled, Bearer token set.
    Docs: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_cobalt-strike-api.htm
    """
    url = cfg["url"].rstrip("/")
    headers = {"Authorization": f"Bearer {cfg['token']}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        beacons_r = await client.get(f"{url}/api/v1/beacons", headers=headers)
        beacons_r.raise_for_status()
        beacons = beacons_r.json() if isinstance(beacons_r.json(), list) else beacons_r.json().get("beacons", [])

        creds = []
        try:
            creds_r = await client.get(f"{url}/api/v1/credentials", headers=headers)
            if creds_r.status_code == 200:
                creds = creds_r.json() if isinstance(creds_r.json(), list) else creds_r.json().get("credentials", [])
        except Exception:
            pass

    result_hosts = []
    for b in beacons:
        if not b:
            continue
        result_hosts.append({
            "ip": b.get("internal") or b.get("host") or "",
            "hostname": b.get("computer") or "",
            "os": b.get("os") or "",
            "username": b.get("user") or "",
            "arch": b.get("arch") or "",
            "process": b.get("process") or "",
            "pid": b.get("pid"),
            "alive": bool(b.get("alive", True)),
            "beacon_id": str(b.get("id") or ""),
            "note": b.get("note") or "",
            "source": "cobalt_strike",
        })

    result_creds = []
    for c in creds:
        if not c:
            continue
        result_creds.append({
            "username": c.get("user") or c.get("username") or "",
            "secret": c.get("password") or c.get("hash") or "",
            "type": "hash" if c.get("hash") and not c.get("password") else "plain",
            "realm": c.get("realm") or c.get("domain") or "",
            "host": c.get("host") or "",
            "source": "cobalt_strike",
        })

    return {"hosts": result_hosts, "creds": result_creds}


async def _sliver_sync(cfg: dict) -> dict:
    """
    Sliver C2 REST API (enabled with `https` listener on multiplayer port).
    Token via: sliver-client generate-token
    Docs: https://github.com/BishopFox/sliver/wiki/HTTP(S)-C2
    """
    url = cfg["url"].rstrip("/")
    headers = {"Authorization": f"Bearer {cfg['token']}"}

    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        sessions_r = await client.get(f"{url}/v1/sessions", headers=headers)
        sessions_r.raise_for_status()
        data = sessions_r.json()
        sessions = data if isinstance(data, list) else data.get("Sessions", data.get("sessions", []))

        # Also try beacons (Sliver async beacons vs interactive sessions)
        beacons = []
        try:
            beacons_r = await client.get(f"{url}/v1/beacons", headers=headers)
            if beacons_r.status_code == 200:
                bdata = beacons_r.json()
                beacons = bdata if isinstance(bdata, list) else bdata.get("Beacons", bdata.get("beacons", []))
        except Exception:
            pass

    result_hosts = []
    for s in (sessions + beacons):
        if not s:
            continue
        remote = s.get("RemoteAddress") or s.get("remote_address") or ""
        ip = remote.split(":")[0] if remote else ""
        result_hosts.append({
            "ip": ip,
            "hostname": s.get("Hostname") or s.get("hostname") or "",
            "os": (s.get("OS") or s.get("os") or "") + " " + (s.get("Arch") or s.get("arch") or ""),
            "username": s.get("Username") or s.get("username") or "",
            "arch": s.get("Arch") or s.get("arch") or "",
            "process": s.get("ActiveC2") or "",
            "pid": None,
            "alive": not s.get("IsDead", s.get("is_dead", False)),
            "beacon_id": s.get("ID") or s.get("id") or "",
            "note": s.get("Name") or s.get("name") or "",
            "source": "sliver",
        })

    return {"hosts": result_hosts, "creds": []}


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
            "beacon_id": ",".join(agent_ids),
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
            "beacon_id": a.get("a_id") or "",
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


_CONNECTORS = {
    "cobalt_strike": _cs_sync,
    "sliver": _sliver_sync,
    "adaptix": _adaptix_sync,
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

    result = []
    for a in agents:
        mark = (a.get("a_mark") or "").strip()
        alive = mark.lower() not in ("terminated", "dead", "killed", "lost")
        result.append({
            "ip": (a.get("a_internal_ip") or a.get("a_external_ip") or "").strip(),
            "hostname": (a.get("a_computer") or "").strip(),
            "username": (a.get("a_username") or "").strip(),
            "domain": (a.get("a_domain") or "").strip(),
            "os": (a.get("a_os_desc") or "").strip(),
            "arch": (a.get("a_arch") or "").strip(),
            "process": (a.get("a_process") or "").strip(),
            "beacon_id": a.get("a_id") or "",
            "listener": a.get("a_listener") or "",
            "alive": alive,
            "mark": mark,
            "last_seen": a.get("a_last_seen") or "",
        })
    return result


async def _cs_live_agents(cfg: dict) -> list[dict]:
    url = cfg["url"].rstrip("/")
    headers = {"Authorization": f"Bearer {cfg.get('token', '')}"}
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        r = await client.get(f"{url}/api/v1/beacon", headers=headers)
        r.raise_for_status()
        raw = r.json()
        beacons = raw if isinstance(raw, list) else raw.get("beacons", [])
    result = []
    for b in (beacons or []):
        alive = bool(b.get("alive", True))
        result.append({
            "ip": b.get("internal") or b.get("host") or "",
            "hostname": b.get("computer") or "",
            "username": b.get("user") or "",
            "domain": "",
            "os": b.get("os") or "",
            "arch": b.get("arch") or "",
            "process": b.get("process") or "",
            "beacon_id": str(b.get("id") or ""),
            "listener": "",
            "alive": alive,
            "mark": "alive" if alive else "dead",
            "last_seen": b.get("last") or "",
        })
    return result


async def _sliver_live_agents(cfg: dict) -> list[dict]:
    url = cfg["url"].rstrip("/")
    headers = {"Authorization": f"Bearer {cfg.get('token', '')}"}
    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        r = await client.get(f"{url}/v1/sessions", headers=headers)
        r.raise_for_status()
        data = r.json()
        sessions = data if isinstance(data, list) else data.get("Sessions", [])
    result = []
    for s in (sessions or []):
        alive = not s.get("IsDead", s.get("is_dead", False))
        remote = s.get("RemoteAddress") or s.get("remote_address") or ""
        result.append({
            "ip": remote.split(":")[0] if remote else "",
            "hostname": s.get("Hostname") or s.get("hostname") or "",
            "username": s.get("Username") or s.get("username") or "",
            "domain": "",
            "os": (s.get("OS") or s.get("os") or "") + " " + (s.get("Arch") or s.get("arch") or ""),
            "arch": s.get("Arch") or s.get("arch") or "",
            "process": s.get("ActiveC2") or "",
            "beacon_id": s.get("ID") or s.get("id") or "",
            "listener": "",
            "alive": alive,
            "mark": "dead" if not alive else "alive",
            "last_seen": "",
        })
    return result


_LIVE_CONNECTORS: dict[str, Any] = {
    "adaptix":       _adaptix_live_agents,
    "cobalt_strike": _cs_live_agents,
    "sliver":        _sliver_live_agents,
}


# ── Sync endpoint ─────────────────────────────────────────────────────

@router.post("/{iid}/test")
async def test_connection(
    iid: str,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    integrations = _load_integrations(db)
    cfg = next((c for c in integrations if c.get("id") == iid), None)
    if not cfg:
        raise HTTPException(404, "Integration not found")
    if not cfg.get("enabled"):
        raise HTTPException(400, "Integration is disabled")

    connector = _CONNECTORS.get(cfg["type"])
    if not connector:
        raise HTTPException(400, f"Unsupported C2 type: {cfg['type']}")

    try:
        data = await connector(cfg)
        return {
            "ok": True,
            "hosts_found": len(data["hosts"]),
            "creds_found": len(data["creds"]),
        }
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
    data = await connector(cfg)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    created_hosts, updated_hosts, created_creds = 0, 0, 0
    source = cfg["type"]
    host_objects = []

    # ── Upsert hosts ─────────────────────────────────────────────────
    for h in data["hosts"]:
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
            if h.get("alive", True):
                existing.status = "pwned"
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
            hobj = models.Host(
                id=new_id("hst"),
                pid=pid,
                ip=ip,
                hostname=hostname,
                os=os_clean,
                domain=domain,
                status="pwned",
                tags=["c2", source],
                notes=new_notes,
                import_source=source,
            )
            db.add(hobj)
            created_hosts += 1
            host_objects.append(hobj)

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
    for c in data["creds"]:
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
        "hosts_found": len(data["hosts"]),
        "hosts_created": created_hosts,
        "hosts_updated": updated_hosts,
        "creds_found": len(data["creds"]),
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
    if user.role != "admin":
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
    integrations = _load_integrations(db)
    visible = [
        _safe_integration(i) for i in integrations
        if i.get("enabled")
        and (not i.get("project_ids") or pid in i.get("project_ids", []))
    ]
    return visible


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
_PRIV_STATUS = {"system": "pwned", "admin": "pwned", "user": "access"}
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
    visible = [
        i for i in integrations
        if i.get("enabled")
        and (not i.get("project_ids") or pid in i.get("project_ids", []))
    ]

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
