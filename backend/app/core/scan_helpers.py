"""
Shared scan helpers used by both synchronous scan endpoints (routers/scans.py)
and queued background jobs (core/job_runner.py).

Previously these were duplicated across the two modules.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .. import models
from ..core.utils import new_id


# ── Nmap host upsert ──────────────────────────────────────────────────


def nmap_upsert_host(db, pid: str, h: dict) -> tuple:
    existing = (
        db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == h["ip"]).first()
    )
    if existing:
        if h["ports"]:
            existing.ports = list(set((existing.ports or []) + h["ports"]))
        if h["services"]:
            existing.services = list(set((existing.services or []) + h["services"]))
        if h["hostname"] and not existing.hostname:
            existing.hostname = h["hostname"]
        if h["os"] and not existing.os:
            existing.os = h["os"]
        existing.status = "up"
        if not existing.import_source:
            existing.import_source = "nmap"
        return existing, False
    host_obj = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=h["ip"],
        hostname=h.get("hostname", ""),
        os=h.get("os", "Linux"),
        status="up",
        ports=h["ports"],
        services=h["services"],
        tags=["nmap"],
        import_source="nmap",
    )
    db.add(host_obj)
    return host_obj, True


# ── CME/NetExec host + cred upsert ────────────────────────────────────


def cme_upsert_host(db, pid: str, h: dict) -> tuple:
    existing = (
        db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == h["ip"]).first()
    )
    if existing:
        if h["hostname"] and not existing.hostname:
            existing.hostname = h["hostname"]
        existing.ports = list(set((existing.ports or []) + h["ports"]))
        existing.services = list(set((existing.services or []) + h["services"]))
        if not existing.import_source:
            existing.import_source = "netexec"
        return existing, False
    hobj = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=h["ip"],
        hostname=h.get("hostname", ""),
        os="Windows",
        status="up",
        ports=h["ports"],
        services=h["services"],
        tags=["cme"],
        import_source="netexec",
    )
    db.add(hobj)
    return hobj, True


def cme_upsert_cred(db, pid: str, c: dict, best_domain: str, existing_keys: set) -> tuple:
    key = (c["username"], c.get("service", "smb"))
    if key in existing_keys:
        return None, False
    cobj = models.Cred(
        id=new_id("crd"),
        pid=pid,
        username=c["username"],
        secret=c.get("secret", ""),
        type=c.get("type", "plain"),
        service=c.get("service", "smb"),
        domain=best_domain,
        tags=["cme"],
    )
    db.add(cobj)
    existing_keys.add(key)
    return cobj, True


def cme_build_auth(payload: dict) -> str:
    if payload.get("hash"):
        return f"-u '{payload.get('username') or ''}' -H '{payload.get('hash')}'"
    if payload.get("username") and payload.get("password"):
        return f"-u '{payload.get('username')}' -p '{payload.get('password')}'"
    if payload.get("username"):
        return f"-u '{payload.get('username')}'"
    return ""


def cme_process_hosts(db, pid: str, parsed_hosts: list) -> tuple:
    host_objects, discovered_domains = [], {}
    created = 0
    for h in parsed_hosts:
        if h.get("domain"):
            discovered_domains[h["ip"]] = h["domain"]
        hobj, was_created = cme_upsert_host(db, pid, h)
        if was_created:
            created += 1
        host_objects.append(hobj)
    return host_objects, discovered_domains, created


def cme_process_creds(db, pid: str, parsed_creds: list, best_domain: str, existing_keys: set) -> tuple:
    cred_objects = []
    created = 0
    for c in parsed_creds:
        cobj, was_created = cme_upsert_cred(db, pid, c, best_domain, existing_keys)
        if was_created:
            created += 1
            cred_objects.append(cobj)
    return cred_objects, created


# ── Httpx host upsert ─────────────────────────────────────────────────


def httpx_upsert_host(db, pid: str, r: dict) -> models.Host:
    h_ip = r["host"]
    existing = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == h_ip).first()
    if not existing:
        existing = (
            db.query(models.Host)
            .filter(models.Host.pid == pid, models.Host.hostname == h_ip)
            .first()
        )
    if existing:
        if r["port"] and r["port"] not in (existing.ports or []):
            existing.ports = list(set((existing.ports or []) + [r["port"]]))
        svc = "http" if r["port"] in (80, 8080) else "https"
        if svc not in (existing.services or []):
            existing.services = list(set((existing.services or []) + [svc]))
        return existing
    new_host = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=h_ip,
        hostname="",
        os="",
        status="up",
        ports=[r["port"]] if r["port"] else [],
        services=["http"] if r["port"] in (80, 8080) else ["https"],
        tags=["httpx"],
        import_source="httpx",
    )
    db.add(new_host)
    return new_host


# ── Ffuf severity + finding upsert ────────────────────────────────────


def ffuf_severity(status_code: int, path: str) -> str:
    severity = "info"
    if status_code in (200, 204):
        severity = "low"
    if path and any(
        kw in path.lower() for kw in ("admin", "config", "backup", "secret", ".env", "passwd")
    ):
        severity = "medium"
    return severity


def ffuf_upsert_finding(db, pid: str, r: dict, target_url: str, ts: str) -> bool:
    status_code = r.get("status") or 0
    path = r.get("input", {}).get("FUZZ") or r.get("url") or ""
    full_url = r.get("url") or f"{target_url}/{path}"
    length = r.get("length") or 0
    words = r.get("words") or 0
    existing = (
        db.query(models.Finding)
        .filter(models.Finding.pid == pid, models.Finding.title == f"ffuf: {full_url}")
        .first()
    )
    if existing:
        return False
    db.add(
        models.Finding(
            id=new_id("fnd"),
            pid=pid,
            title=f"ffuf: {full_url}",
            severity=ffuf_severity(status_code, path),
            description=f"HTTP {status_code} — size {length} bytes / {words} words",
            proof=f"URL: {full_url}\nStatus: {status_code}\nSize: {length}\nWords: {words}",
            status="open",
            ts=ts,
        )
    )
    return True


# ── DonPAPI cred upsert + loot fetch ──────────────────────────────────


def donpapi_upsert_cred(db, pid: str, cred: dict, target: str, encrypt_fn) -> bool:
    existing = (
        db.query(models.Cred)
        .filter(
            models.Cred.pid == pid,
            models.Cred.username == cred["username"],
            models.Cred.domain == (cred.get("domain") or ""),
            models.Cred.service == cred["service"],
        )
        .first()
    )
    if existing:
        return False
    db.add(
        models.Cred(
            id=new_id("c"),
            pid=pid,
            username=cred["username"],
            secret=encrypt_fn(cred["secret"]),
            type="plain",
            service=cred["service"],
            domain=cred.get("domain") or "",
            host=cred.get("host_hint") or target,
            tags=["donpapi", cred.get("kind") or ""],
        )
    )
    return True


def _donpapi_build_fetch_cmd(output_dir: str) -> str:
    return (
        f"tar -czf - -C \"$(dirname '{output_dir}')\" "
        f"\"$(basename '{output_dir}')\" 2>/dev/null | base64 -w 0"
    )


def _donpapi_create_loot_record(
    pid: str, target: str, target_host, tar_bytes: bytes,
    creds_created: int, job_or_id, job_id: str, db,
) -> str:
    from pathlib import Path as _Path
    from ..core.config import UPLOAD_ROOT
    from ..core.events import bcast as _bcast
    from ..core.utils import ts_now
    from .. import schemas

    loot_id = new_id("lt")
    loot_dir = UPLOAD_ROOT / pid / "loot"
    loot_dir.mkdir(parents=True, exist_ok=True)
    safe_target = target.replace("/", "_").replace(":", "_")
    filename = f"donpapi_{safe_target}.tar.gz"
    disk_path = _Path(loot_dir) / f"{loot_id}.tar.gz"
    disk_path.write_bytes(tar_bytes)
    _jid = job_id or (getattr(job_or_id, "id", "") if job_or_id else "")
    loot = models.Loot(
        id=loot_id,
        pid=pid,
        host_id=target_host.id if target_host else None,
        loot_type="file",
        value=filename,
        description=(
            f"DonPAPI dump artefacts from {target} "
            f"({len(tar_bytes)} bytes, {creds_created} cred(s))"
        ),
        source_path=f"/api/uploads/{pid}/loot/{loot_id}.tar.gz",
        filename=filename,
        content_type="application/gzip",
        file_size=len(tar_bytes),
        storage_path=str(disk_path),
        public_url=f"/api/uploads/{pid}/loot/{loot_id}.tar.gz",
        ts=ts_now(),
        job_id=_jid,
    )
    db.add(loot)
    db.flush()
    _bcast(pid, "loot", "create", schemas.Loot.model_validate(loot).model_dump())
    return loot_id


async def donpapi_fetch_loot(
    loop,
    ssh_config: dict,
    output_dir: str,
    pid: str,
    target: str,
    target_host,
    job_or_id,
    creds_created: int,
    db,
    *,
    cancel_token=None,
    job_actor: str = "",
    job_id: str = "",
) -> str:
    import base64 as _b64
    from pathlib import Path as _Path

    from ..core.config import UPLOAD_ROOT
    from ..core.events import bcast as _bcast, log_event
    from ..core.ssh_exec import run_ssh_command
    from ..core.ssh_exec_cancellable import run_ssh_command_cancellable
    from ..core.utils import ts_now
    from .. import schemas

    loot_id = ""
    try:
        fetch_cmd = _donpapi_build_fetch_cmd(output_dir)
        if cancel_token is not None:
            fetch_result = await loop.run_in_executor(
                None, lambda: run_ssh_command_cancellable(ssh_config, fetch_cmd, 120, cancel_token)
            )
        else:
            fetch_result = await loop.run_in_executor(
                None, lambda: run_ssh_command(ssh_config, fetch_cmd, 120)
            )
        b64_payload = (fetch_result.get("stdout") or "").strip()
        tar_bytes = b""
        if b64_payload:
            try:
                tar_bytes = _b64.b64decode(b64_payload)
            except Exception:
                tar_bytes = b""
        max_loot = 50 * 1024 * 1024
        if 0 < len(tar_bytes) <= max_loot:
            loot_id = _donpapi_create_loot_record(
                pid, target, target_host, tar_bytes, creds_created, job_or_id, job_id, db,
            )
    except Exception as exc:
        _actor = job_actor or (getattr(job_or_id, "created_by", "") if job_or_id else "")
        log_event(
            db,
            pid,
            _actor,
            "scan",
            "donpapi_loot_failed",
            f"DonPAPI loot fetch failed: {exc}",
            {"target": target, "error": str(exc)[:200]},
        )
    return loot_id
