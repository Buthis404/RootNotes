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
from ..core.utils import new_id
from ..database import get_db, SessionLocal

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
    verify_ssl: bool = False
    project_ids: list[str] = []
    enabled: bool = True


class C2IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: Optional[bool] = None
    project_ids: Optional[list[str]] = None
    enabled: Optional[bool] = None


# ── CRUD ──────────────────────────────────────────────────────────────

@router.get("")
def list_integrations(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    return [_safe_integration(i) for i in _load_integrations(db)]


@router.post("", status_code=201)
def create_integration(
    body: C2IntegrationCreate,
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
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
    Docs: https://adaptix-framework.github.io/docs/
    Auth: Bearer token or username/password -> /api/auth/login -> JWT
    Agents: GET /api/agents
    """
    url = cfg["url"].rstrip("/")
    token = cfg.get("token", "")

    async with httpx.AsyncClient(verify=cfg.get("verify_ssl", False), timeout=30) as client:
        # Auth: if no token but username/password, get JWT first
        if not token and cfg.get("username") and cfg.get("password"):
            login_r = await client.post(
                f"{url}/api/auth/login",
                json={"username": cfg["username"], "password": cfg["password"]},
            )
            login_r.raise_for_status()
            token = login_r.json().get("token") or login_r.json().get("access_token") or ""

        headers = {"Authorization": f"Bearer {token}"} if token else {}

        agents_r = await client.get(f"{url}/api/agents", headers=headers)
        agents_r.raise_for_status()
        data = agents_r.json()
        agents = data if isinstance(data, list) else data.get("agents", data.get("data", []))

        # Try to get credentials/tasks
        creds = []
        try:
            creds_r = await client.get(f"{url}/api/credentials", headers=headers)
            if creds_r.status_code == 200:
                cdata = creds_r.json()
                creds = cdata if isinstance(cdata, list) else cdata.get("credentials", [])
        except Exception:
            pass

    result_hosts = []
    for a in agents:
        if not a:
            continue
        result_hosts.append({
            "ip": a.get("internal_ip") or a.get("ip") or a.get("ExternalIP") or "",
            "hostname": a.get("hostname") or a.get("computer_name") or a.get("ComputerName") or "",
            "os": a.get("os") or a.get("OS") or "",
            "username": a.get("username") or a.get("Username") or "",
            "arch": a.get("arch") or a.get("Arch") or "",
            "process": a.get("process") or a.get("Process") or "",
            "pid": a.get("pid") or a.get("PID"),
            "alive": a.get("alive", a.get("active", True)),
            "beacon_id": str(a.get("id") or a.get("ID") or ""),
            "note": a.get("name") or a.get("Name") or a.get("listener") or "",
            "source": "adaptix",
        })

    result_creds = []
    for c in creds:
        if not c:
            continue
        result_creds.append({
            "username": c.get("username") or c.get("user") or "",
            "secret": c.get("password") or c.get("hash") or c.get("secret") or "",
            "type": "hash" if c.get("hash") and not c.get("password") else "plain",
            "realm": c.get("domain") or c.get("realm") or "",
            "host": c.get("host") or "",
            "source": "adaptix",
        })

    return {"hosts": result_hosts, "creds": result_creds}


_CONNECTORS = {
    "cobalt_strike": _cs_sync,
    "sliver": _sliver_sync,
    "adaptix": _adaptix_sync,
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


@router.post("/{iid}/sync/{pid}")
async def sync_to_project(
    iid: str,
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    integrations = _load_integrations(db)
    cfg = next((c for c in integrations if c.get("id") == iid), None)
    if not cfg:
        raise HTTPException(404, "Integration not found")
    if not cfg.get("enabled"):
        raise HTTPException(400, "Integration is disabled")

    # Check project access
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    if user.role != "admin":
        from ..core.access import check_pid_access
        check_pid_access(db, pid, user, "hosts.create")

    connector = _CONNECTORS.get(cfg["type"])
    if not connector:
        raise HTTPException(400, f"Unsupported C2 type: {cfg['type']}")

    try:
        data = await connector(cfg)
    except httpx.HTTPStatusError as e:
        raise HTTPException(400, f"C2 API error {e.response.status_code}: {e.response.text[:300]}")
    except httpx.ConnectError as e:
        raise HTTPException(400, f"Connection failed: {e}")
    except Exception as e:
        raise HTTPException(400, f"Error: {e}")

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

        # Notes: include beacon metadata
        note_parts = []
        if h.get("process"):
            note_parts.append(f"Process: {h['process']}")
        if h.get("pid"):
            note_parts.append(f"PID: {h['pid']}")
        if h.get("arch"):
            note_parts.append(f"Arch: {h['arch']}")
        if h.get("beacon_id"):
            note_parts.append(f"Beacon/Session ID: {h['beacon_id']}")
        if h.get("note"):
            note_parts.append(f"Note: {h['note']}")
        new_notes = "\n".join(note_parts)

        if existing:
            if hostname and not existing.hostname:
                existing.hostname = hostname
            if os_clean and os_clean != "Unknown" and (not existing.os or existing.os in ("Linux", "Unknown", "")):
                existing.os = os_clean
            if h.get("alive", True):
                existing.status = "pwned"
            if new_notes and new_notes not in (existing.notes or ""):
                existing.notes = ((existing.notes or "") + "\n\n---\n" + new_notes).strip()
            if source not in (existing.tags or []):
                existing.tags = list(existing.tags or []) + [source]
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
                status="pwned",
                tags=["c2", source],
                notes=new_notes,
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
    if integrations_raw:
        raw_list = integrations_raw.value if isinstance(integrations_raw.value, list) else []
        for item in raw_list:
            if item.get("id") == iid:
                item["last_sync"] = ts
                break
        integrations_raw.value = raw_list
        db.commit()

    # ── Broadcast ────────────────────────────────────────────────────
    for hobj in host_objects:
        try:
            db.refresh(hobj)
            bcast(pid, "host", "upsert", schemas.Host.model_validate(hobj).model_dump())
        except Exception:
            pass

    return {
        "ok": True,
        "source": source,
        "hosts_found": len(data["hosts"]),
        "hosts_created": created_hosts,
        "hosts_updated": updated_hosts,
        "creds_found": len(data["creds"]),
        "creds_created": created_creds,
    }


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
