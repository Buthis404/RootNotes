"""
Scan runner: Nmap, Nuclei, CrackMapExec/NetExec via attacker SSH.
Results are parsed and auto-populated into hosts/creds/findings.
"""

import asyncio
import json
import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Annotated
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast, log_event
from ..core.exec_context import build_remote_execution_command
from ..core.job_tracker import finish_job, start_job
from ..core.scan_helpers import (
    cme_build_auth,
    cme_process_creds,
    cme_process_hosts,
    donpapi_fetch_loot,
    donpapi_upsert_cred,
    ffuf_severity,
    ffuf_upsert_finding,
    httpx_upsert_host,
    nmap_upsert_host,
)
from ..core.ssh_exec import run_ssh_command
from ..core.utils import new_id, ts_now
from ..database import get_db
from ..plugins.registry import registry
from ..core.attacker_transport import resolve_scan_target
from .pivots import get_pivot_item, normalize_pivot_proxy_type

router = APIRouter(
    prefix="/api/projects/{pid}/scans", tags=["scans"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
    },
)

_MSG_TARGET_REQUIRED = "target is required"


def _require_attacker_ssh():
    module = registry.get("attacker_ssh")
    if not module or not module.enabled:
        raise HTTPException(404, "Attacker SSH module is disabled")


def _get_ssh_config(
    pid: str, target_id: str | None, db: Session | None = None, target_hint: str = ""
) -> dict:
    return resolve_scan_target(pid, target_id, db, target_hint)


def _build_scan_execution_command(
    pid: str,
    db: Session,
    ssh_config: dict,
    command: str,
    execution_source: str = "attacker",
    pivot_observation_id: str | None = None,
) -> str:
    source = (execution_source or "attacker").strip().lower()
    if source == "attacker":
        return command
    if source != "pivot_listener":
        raise HTTPException(400, "Invalid execution_source")
    if not pivot_observation_id:
        raise HTTPException(400, "pivot_observation_id is required for pivot_listener execution")

    obs = get_pivot_item(pid, pivot_observation_id, db)
    if not obs:
        raise HTTPException(404, "Pivot observation not found")
    pivot_proxy_type = normalize_pivot_proxy_type(obs.get("pivot_type") or "")
    if pivot_proxy_type not in {"socks4", "socks5"}:
        raise HTTPException(
            400,
            f"Selected pivot tunnel type is not supported for scans: {obs.get('pivot_type') or 'unknown'}",
        )
    bind = str(obs.get("bind_address") or "").strip()
    if not bind:
        raise HTTPException(400, "Selected pivot listener does not expose a bind address")
    if ":" in bind:
        proxy_host, proxy_port_raw = bind.rsplit(":", 1)
    else:
        proxy_host, proxy_port_raw = "127.0.0.1", bind
    try:
        proxy_port = int(proxy_port_raw)
    except ValueError:
        raise HTTPException(400, "Invalid pivot listener port")

    exec_cfg = {
        **ssh_config,
        "exec_proxy_type": pivot_proxy_type,
        "exec_proxy_host": proxy_host or "127.0.0.1",
        "exec_proxy_port": proxy_port,
        "exec_proxy_username": "",
        "exec_proxy_password": "",
    }
    return build_remote_execution_command(exec_cfg, command)


def _upsert_host(db: Session, pid: str, ip: str, **kwargs) -> models.Host:
    host = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
    if host:
        for k, v in kwargs.items():
            if v is not None and v != "" and v != []:
                setattr(host, k, v)
        return host
    # Race-safe: a parallel scan worker may insert the same (pid, ip) row
    # between the SELECT and the INSERT. The unique index on hosts(pid, ip)
    # turns that into an IntegrityError; we re-query and merge fields.
    from ..core.db_upsert import try_insert_or_get

    new_host = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=ip,
        status="up",
        **{k: v for k, v in kwargs.items() if v is not None},
    )
    host, created = try_insert_or_get(
        db,
        new_host,
        requery=lambda: db.query(models.Host)
        .filter(models.Host.pid == pid, models.Host.ip == ip)
        .first(),
    )
    if not created:
        for k, v in kwargs.items():
            if v is not None and v != "" and v != []:
                setattr(host, k, v)
    return host


# ── Nmap ──────────────────────────────────────────────────────────────


class NmapScanBody(BaseModel):
    target: str
    flags: str = "-sV -sC -T4 --open"
    target_id: str | None = None
    execution_source: str = "attacker"
    pivot_observation_id: str | None = None
    timeout_seconds: int = 180


def _nmap_xml_get_hostname(host_el) -> str:
    for hn in host_el.findall(".//hostname"):
        if hn.get("type") in ("user", "PTR", None):
            return hn.get("name", "")
    return ""


def _nmap_xml_get_os(host_el) -> str:
    os_el = host_el.find(".//osmatch")
    return os_el.get("name", "") if os_el is not None else ""


def _nmap_xml_get_ports(host_el) -> tuple[list, list]:
    ports, services = [], []
    for port_el in host_el.findall(".//port"):
        state = port_el.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = port_el.get("portid", "")
        proto = port_el.get("protocol", "tcp")
        svc_el = port_el.find("service")
        svc_name = svc_el.get("name", "") if svc_el is not None else ""
        svc_product = svc_el.get("product", "") if svc_el is not None else ""
        ports.append(f"{portid}/{proto}")
        if svc_name:
            label = f"{portid}/{svc_name}" + (f" ({svc_product})" if svc_product else "")
            services.append(label)
    return ports, services


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        if state_el is None or state_el.get("state") != "up":
            continue
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if not ip:
            continue
        ports, services = _nmap_xml_get_ports(host_el)
        hosts.append(
            {
                "ip": ip,
                "hostname": _nmap_xml_get_hostname(host_el),
                "os": _nmap_xml_get_os(host_el),
                "ports": ports,
                "services": services,
                "status": "up",
            }
        )
    return hosts


@router.post("/nmap", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def run_nmap_scan(
    pid: str,
    body: NmapScanBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_attacker_ssh()
    check_pid_access(db, pid, user, "hosts.create")

    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target)
    target = body.target.strip()
    if not target:
        raise HTTPException(400, _MSG_TARGET_REQUIRED)

    username = getattr(request.state, "username", None)
    cmd = _build_scan_execution_command(
        pid,
        db,
        ssh_config,
        f"nmap {body.flags} -oX - {target} 2>/dev/null",
        body.execution_source,
        body.pivot_observation_id,
    )
    job = start_job(
        db,
        pid,
        "nmap",
        f"Nmap: {target}",
        target=target,
        command=cmd,
        created_by=username or "",
        connector_key="nmap",
        operation="scan",
        related_entity=("project", pid),
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)
    )

    stdout = result.get("stdout", "")
    parsed = _parse_nmap_xml(stdout)

    created, updated = 0, 0
    ts_now()

    host_list = []
    for h in parsed:
        host_obj, was_new = nmap_upsert_host(db, pid, h)
        if was_new:
            created += 1
        else:
            updated += 1
        host_list.append(host_obj)

    log_event(
        db,
        pid,
        username,
        "scan",
        "nmap",
        f"Nmap scan: {target} → {created} new, {updated} updated",
        {"target": target, "created": created, "updated": updated},
    )
    db.commit()

    for host_obj in host_list:
        db.refresh(host_obj)
        payload = schemas.Host.model_validate(host_obj).model_dump()
        bcast(pid, "host", "upsert", payload)

    job_status = "done" if result.get("ok") else "failed"
    finish_job(
        db,
        job,
        status=job_status,
        output=stdout[:20000] if stdout else "",
        error_output=result.get("stderr", ""),
        result={"hosts_found": len(parsed), "hosts_created": created, "hosts_updated": updated},
    )

    return {
        "ok": result.get("ok", False),
        "job_id": job.id,
        "target": target,
        "hosts_found": len(parsed),
        "hosts_created": created,
        "hosts_updated": updated,
        "stderr": result.get("stderr", ""),
        "raw_xml": stdout if len(stdout) < 50000 else stdout[:50000] + "...",
    }


# ── Nuclei ────────────────────────────────────────────────────────────


class NucleiScanBody(BaseModel):
    target: str
    templates: str = ""
    severity: str = "critical,high,medium"
    target_id: str | None = None
    execution_source: str = "attacker"
    pivot_observation_id: str | None = None
    timeout_seconds: int = 300
    extra_flags: str = ""


_NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _nuclei_cve_from_info(info: dict) -> str:
    for tag in (info.get("tags") or "").split(","):
        tag = tag.strip()
        if tag.upper().startswith("CVE-"):
            return tag.upper()
    return ""


def _nuclei_parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    info = obj.get("info", {})
    severity = _NUCLEI_SEVERITY_MAP.get((info.get("severity") or "medium").lower(), "medium")
    reference = info.get("reference") or []
    if isinstance(reference, list):
        reference = "\n".join(reference)
    matched_at = obj.get("matched-at") or obj.get("host") or ""
    return {
        "title": info.get("name") or obj.get("template-id") or "Nuclei Finding",
        "severity": severity,
        "description": info.get("description") or "",
        "proof": f"URL: {matched_at}\nTemplate: {obj.get('template-id', '')}\nMatched: {obj.get('matched-at', '')}",
        "cve": _nuclei_cve_from_info(info),
        "host": matched_at,
        "template_id": obj.get("template-id", ""),
    }


def _parse_nuclei_jsonl(text: str) -> list[dict]:
    return [f for line in text.splitlines() if (f := _nuclei_parse_line(line))]


@router.post("/nuclei", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def run_nuclei_scan(
    pid: str,
    body: NucleiScanBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_attacker_ssh()
    check_pid_access(db, pid, user, "findings.create")

    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target)
    target = body.target.strip()
    if not target:
        raise HTTPException(400, _MSG_TARGET_REQUIRED)

    username = getattr(request.state, "username", None)
    tpl_flag = f"-t {body.templates}" if body.templates.strip() else ""
    cmd = _build_scan_execution_command(
        pid,
        db,
        ssh_config,
        f"nuclei -u {target} {tpl_flag} -severity {body.severity} -jsonl {body.extra_flags} 2>/dev/null",
        body.execution_source,
        body.pivot_observation_id,
    )
    job = start_job(
        db,
        pid,
        "nuclei",
        f"Nuclei: {target}",
        target=target,
        command=cmd,
        created_by=username or "",
        connector_key="nuclei",
        operation="scan",
        related_entity=("project", pid),
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)
    )

    parsed = _parse_nuclei_jsonl(result.get("stdout", ""))

    ts = ts_now()

    existing_titles = {
        f.title for f in db.query(models.Finding).filter(models.Finding.pid == pid).all()
    }
    created_findings = []

    for f in parsed:
        if f["title"] in existing_titles:
            continue
        finding = models.Finding(
            id=new_id("fnd"),
            pid=pid,
            title=f["title"],
            severity=f["severity"],
            description=f["description"],
            proof=f["proof"],
            cve=f["cve"],
            status="open",
            ts=ts,
        )
        db.add(finding)
        existing_titles.add(f["title"])
        created_findings.append(finding)

    log_event(
        db,
        pid,
        username,
        "scan",
        "nuclei",
        f"Nuclei scan: {target} → {len(created_findings)} findings",
        {"target": target, "found": len(parsed), "created": len(created_findings)},
    )
    db.commit()

    for finding in created_findings:
        db.refresh(finding)
        payload = schemas.Finding.model_validate(finding).model_dump()
        bcast(pid, "finding", "create", payload)

    job_status = "done" if result.get("ok") else "failed"
    finish_job(
        db,
        job,
        status=job_status,
        output=result.get("stdout", "")[:20000],
        error_output=result.get("stderr", ""),
        result={"findings_found": len(parsed), "findings_created": len(created_findings)},
    )

    return {
        "ok": result.get("ok", False),
        "job_id": job.id,
        "target": target,
        "findings_found": len(parsed),
        "findings_created": len(created_findings),
        "stderr": result.get("stderr", ""),
    }


# ── CrackMapExec / NetExec ────────────────────────────────────────────


class CmeScanBody(BaseModel):
    target: str
    username: str | None = None
    password: str | None = None
    domain: str | None = None
    hash: str | None = None
    protocol: str = "smb"
    extra_flags: str = "--users --groups"
    target_id: str | None = None
    execution_source: str = "attacker"
    pivot_observation_id: str | None = None
    timeout_seconds: int = 120


_CME_HOST_RE = re.compile(r"SMB\s+([\d.]+)\s+(\d+)\s+(\S+)\s+\[")
_CME_DOMAIN_RE = re.compile(r"\(domain:([\w.-]+)\)", re.IGNORECASE)


def _cme_parse_host_line(line: str, seen_ips: set) -> dict | None:
    m = _CME_HOST_RE.match(line)
    if not m:
        return None
    ip, port, hostname = m.group(1), m.group(2), m.group(3)
    domain = ""
    dm = _CME_DOMAIN_RE.search(line)
    if dm:
        parsed_domain = dm.group(1).strip()
        if parsed_domain.lower() != hostname.lower():
            domain = parsed_domain
    if ip in seen_ips:
        return None
    seen_ips.add(ip)
    return {"ip": ip, "hostname": hostname, "domain": domain, "ports": [f"{port}/tcp"], "services": [f"{port}/smb"]}


def _cme_parse_cred_lines(line: str, existing_usernames: set) -> list:
    results = []
    if "[+]" in line:
        tail = line.split("[+]", 1)[1].strip()
        left, sep, passwd = tail.partition(":")
        uname = left.strip().split()[-1] if left.strip() else ""
        passwd = passwd.strip().split()[0] if passwd.strip() else ""
        if sep and uname and passwd and passwd != "<empty>":
            results.append({"username": uname, "secret": passwd, "type": "plain", "service": "smb"})
            existing_usernames.add(uname)
    if "SMB" in line and "USERS" in line and "RID" in line:
        parts = line.split()
        uname = next((part for part in parts if "." in part and "(" not in part and ")" not in part), "").strip()
        if uname and uname not in existing_usernames:
            results.append({"username": uname, "secret": "", "type": "plain", "service": "smb"})
            existing_usernames.add(uname)
    return results


def _parse_cme_output(text: str) -> dict:
    hosts = []
    creds = []
    seen_ips: set = set()
    known_usernames: set = set()
    for line in text.splitlines():
        line = line.strip()
        host = _cme_parse_host_line(line, seen_ips)
        if host:
            hosts.append(host)
        creds.extend(_cme_parse_cred_lines(line, known_usernames))
    return {"hosts": hosts, "creds": creds}


def _build_cme_auth_flags(body: "CmeScanBody") -> str:
    if body.hash:
        return f"-u '{body.username or ''}' -H '{body.hash}'"
    if body.username and body.password:
        return f"-u '{body.username}' -p '{body.password}'"
    if body.username:
        return f"-u '{body.username}'"
    return ""


def _process_cme_hosts(db, pid: str, parsed_hosts: list) -> tuple[list, dict, int]:
    host_objects, discovered_domains, created = cme_process_hosts(db, pid, parsed_hosts)
    return host_objects, discovered_domains, created


def _process_cme_creds(db, pid: str, parsed_creds: list, best_domain: str, existing_keys: set) -> tuple[list, int]:
    return cme_process_creds(db, pid, parsed_creds, best_domain, existing_keys)


def _broadcast_cme_objects(pid: str, host_objects: list, cred_objects: list) -> None:
    for obj in host_objects:
        bcast(pid, "host", "upsert", schemas.Host.model_validate(obj).model_dump())
    for obj in cred_objects:
        bcast(pid, "cred", "create", schemas.Cred.model_validate(obj).model_dump())


@router.post("/cme", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def run_cme_scan(
    pid: str,
    body: CmeScanBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_attacker_ssh()
    check_pid_access(db, pid, user, "hosts.create")

    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target)
    target = body.target.strip()
    if not target:
        raise HTTPException(400, _MSG_TARGET_REQUIRED)

    username = getattr(request.state, "username", None)
    auth = _build_cme_auth_flags(body)
    domain = f"-d {body.domain}" if body.domain else ""
    cmd = _build_scan_execution_command(
        pid,
        db,
        ssh_config,
        f"nxc {body.protocol} {target} {auth} {domain} {body.extra_flags} 2>/dev/null",
        body.execution_source,
        body.pivot_observation_id,
    )
    job = start_job(
        db,
        pid,
        "cme",
        f"NetExec ({body.protocol}): {target}",
        target=target,
        command=cmd,
        created_by=username or "",
        connector_key="netexec",
        operation="scan",
        related_entity=("project", pid),
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    run_cmd = lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)  # noqa: E731
    result = await loop.run_in_executor(None, run_cmd)

    parsed = _parse_cme_output(result.get("stdout", "") + result.get("stderr", ""))

    host_objects, discovered_domains, created_hosts = _process_cme_hosts(db, pid, parsed["hosts"])
    best_domain = body.domain or next(iter(discovered_domains.values()), "")
    existing_cred_keys = {
        (c.username, c.service) for c in db.query(models.Cred).filter(models.Cred.pid == pid).all()
    }
    cred_objects, created_creds = _process_cme_creds(db, pid, parsed["creds"], best_domain, existing_cred_keys)

    log_event(
        db,
        pid,
        username,
        "scan",
        "cme",
        f"CME scan: {target} → {created_hosts} hosts, {created_creds} creds",
        {"target": target},
    )
    db.commit()

    for obj in host_objects:
        db.refresh(obj)
    for obj in cred_objects:
        db.refresh(obj)
    _broadcast_cme_objects(pid, host_objects, cred_objects)

    job_status = "done" if result.get("ok") else "failed"
    finish_job(
        db,
        job,
        status=job_status,
        output=result.get("stdout", "")[:20000],
        error_output=result.get("stderr", ""),
        result={
            "hosts_found": len(parsed["hosts"]),
            "hosts_created": created_hosts,
            "creds_found": len(parsed["creds"]),
            "creds_created": created_creds,
        },
    )

    return {
        "ok": result.get("ok", False),
        "job_id": job.id,
        "target": target,
        "hosts_found": len(parsed["hosts"]),
        "hosts_created": created_hosts,
        "creds_found": len(parsed["creds"]),
        "creds_created": created_creds,
        "stdout": result.get("stdout", "")[:5000],
        "stderr": result.get("stderr", ""),
    }


# ── httpx ─────────────────────────────────────────────────────────────


class HttpxScanBody(BaseModel):
    target: str
    flags: str = "-title -status-code -tech-detect -follow-redirects"
    timeout_seconds: int = 120
    target_id: str | None = None


def _httpx_parse_host_port(obj: dict) -> tuple[str, int]:
    host = obj.get("host") or obj.get("input") or ""
    parsed = urlsplit(host)
    if parsed.scheme:
        host = parsed.netloc or parsed.path
    host = host.split("/")[0].split(":")[0]
    try:
        port = int(obj.get("port") or 0)
    except (ValueError, TypeError):
        port = 80
    return host, port or 80


def _httpx_parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    tech = obj.get("tech") or obj.get("technologies") or []
    if isinstance(tech, str):
        tech = [t.strip() for t in tech.split(",") if t.strip()]
    host, port = _httpx_parse_host_port(obj)
    status = obj.get("status-code") or obj.get("status_code") or 0
    return {
        "url": obj.get("url") or obj.get("input") or "",
        "host": host,
        "port": port,
        "status": int(status) if status else 0,
        "title": obj.get("title") or "",
        "tech": tech,
        "webserver": obj.get("webserver") or obj.get("web-server") or "",
    }


def _parse_httpx_jsonl(text: str) -> list[dict]:
    return [r for line in text.splitlines() if (r := _httpx_parse_line(line))]


def _httpx_build_summary(r: dict) -> str:
    summary = f"[{r['status']}] {r['url']}"
    if r["title"]:
        summary += f" | {r['title']}"
    tech_str = ", ".join(r["tech"]) if r["tech"] else ""
    if tech_str:
        summary += f" | tech: {tech_str}"
    return summary


@router.post("/httpx", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def run_httpx(
    pid: str,
    body: HttpxScanBody,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[models.User, Depends(get_current_user)],
):
    _require_attacker_ssh()
    check_pid_access(db, pid, current_user, "scans.run")
    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target)
    username = current_user.username
    target = body.target.strip()

    flags = body.flags or "-title -status-code -tech-detect -follow-redirects"
    cmd = build_remote_execution_command(
        ssh_config,
        f"httpx -u '{target}' {flags} -json -silent 2>/dev/null || httpx -u '{target}' {flags} -json 2>&1",
    )

    job = start_job(
        db,
        pid,
        "httpx",
        f"httpx: {target}",
        target=target,
        command=cmd,
        created_by=username,
        connector_key="httpx",
        operation="scan",
        related_entity=("project", pid),
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)
    )

    stdout = result.get("stdout", "")
    parsed = _parse_httpx_jsonl(stdout)

    ts = ts_now()
    hosts_found = len({r["host"] for r in parsed if r["host"]})
    urls_found = len(parsed)
    activities_created = 0

    for r in parsed:
        if not r["host"]:
            continue
        host_obj = httpx_upsert_host(db, pid, r)
        db.add(models.HostActivity(
            id=new_id("hact"),
            pid=pid,
            host_id=host_obj.id,
            title=f"httpx: {r['url']}",
            activity_type="recon",
            command=cmd,
            summary=_httpx_build_summary(r),
            output=json.dumps(r),
            status="done",
            ts=ts,
        ))
        activities_created += 1

    log_event(
        db,
        pid,
        username,
        "scan",
        "httpx",
        f"httpx: {target} → {urls_found} URLs, {hosts_found} hosts",
        {"target": target},
    )
    db.commit()

    job_status = "done" if result.get("ok") else "failed"
    finish_job(
        db,
        job,
        status=job_status,
        output=stdout[:20000] if stdout else "",
        error_output=result.get("stderr", ""),
        result={
            "urls_found": urls_found,
            "hosts_found": hosts_found,
            "activities_created": activities_created,
        },
    )

    return {
        "ok": result.get("ok", False),
        "job_id": job.id,
        "target": target,
        "urls_found": urls_found,
        "hosts_found": hosts_found,
        "activities_created": activities_created,
    }


# ── ffuf ──────────────────────────────────────────────────────────────


class FfufScanBody(BaseModel):
    target_url: str
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    extensions: str = ""
    flags: str = "-mc 200,204,301,302,307,401,403,405"
    timeout_seconds: int = 300
    target_id: str | None = None


def _parse_ffuf_json(text: str) -> list[dict]:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{") and '"results"' in line:
            try:
                obj = json.loads(line)
                return obj.get("results") or []
            except json.JSONDecodeError:
                pass
    # Try full JSON (ffuf -o /dev/stdout -of json)
    try:
        obj = json.loads(text)
        return obj.get("results") or []
    except json.JSONDecodeError:
        pass
    return []


@router.post("/ffuf", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def run_ffuf(
    pid: str,
    body: FfufScanBody,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[models.User, Depends(get_current_user)],
):
    _require_attacker_ssh()
    check_pid_access(db, pid, current_user, "scans.run")
    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target_url)
    username = current_user.username
    target_url = body.target_url.strip().rstrip("/")

    ext_flag = f"-e {body.extensions}" if body.extensions.strip() else ""
    url = f"{target_url}/FUZZ"
    cmd = build_remote_execution_command(
        ssh_config,
        f"ffuf -u '{url}' -w '{body.wordlist}' {ext_flag} {body.flags} -o /tmp/ffuf_out.json -of json -s 2>/dev/null && cat /tmp/ffuf_out.json",
    )

    job = start_job(
        db,
        pid,
        "ffuf",
        f"ffuf: {target_url}",
        target=target_url,
        command=cmd,
        created_by=username,
        connector_key="ffuf",
        operation="scan",
        related_entity=("project", pid),
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)
    )

    stdout = result.get("stdout", "")
    parsed = _parse_ffuf_json(stdout)

    ts = ts_now()
    paths_found = len(parsed)
    findings_created = 0

    for r in parsed:
        if ffuf_upsert_finding(db, pid, r, target_url, ts):
            findings_created += 1

    log_event(
        db,
        pid,
        username,
        "scan",
        "ffuf",
        f"ffuf: {target_url} → {paths_found} paths, {findings_created} findings",
        {"target": target_url},
    )
    db.commit()

    job_status = "done" if result.get("ok") else "failed"
    finish_job(
        db,
        job,
        status=job_status,
        output=stdout[:20000] if stdout else "",
        error_output=result.get("stderr", ""),
        result={"paths_found": paths_found, "findings_created": findings_created},
    )

    return {
        "ok": result.get("ok", False),
        "job_id": job.id,
        "target_url": target_url,
        "paths_found": paths_found,
        "findings_created": findings_created,
    }


# ── DonPAPI ───────────────────────────────────────────────────────────
#
# DonPAPI dumps DPAPI-protected secrets (vaults / Wi-Fi profiles / browser
# saved logins / certs / masterkeys) from Windows hosts. Runs from the
# attacker box with domain credentials. Outputs a SQLite DB plus per-victim
# directories under -o <output_dir>.
#
# We invoke it with a per-job output directory, parse stdout for newly
# discovered cleartext credentials, fetch the output dir as a tarball Loot,
# and record a HostActivity entry on the target host.


class DonpapiScanBody(BaseModel):
    target: str  # IP or comma-list
    domain: str = ""
    username: str = ""
    password: str = ""
    nthash: str = ""
    extra_flags: str = ""
    target_id: str | None = None
    timeout_seconds: int = 600
    fetch_loot: bool = True


# Parses the human-readable stdout banner of donpapi >=2.x for cleartext
# entries. Format roughly looks like:
#   [+] Found credential on 10.0.0.5
#       URL: https://login.example.com
#       Login: alice@example.com
#       Password: P@ssw0rd!
#
# We pick out the trio of URL/Login/Password (and Wifi SSID/password)
# blocks. Non-cleartext blobs (cert, masterkey hashes) are skipped — they
# go into the Loot tarball instead.
def _parse_donpapi_stdout(text: str) -> list[dict]:
    """Best-effort parser for donpapi stdout — returns list of cred dicts."""
    creds = []
    # Split into "blocks" — each starts with a "Found credential ..." line
    parts = re.split(r"^(?=\s*\[\+\]\s*Found\s)", text or "", flags=re.IGNORECASE | re.MULTILINE)
    for part in parts:
        parsed = _parse_donpapi_block(part)
        if parsed:
            creds.append(parsed)
    return creds


_DONPAPI_KIND_MARKERS = ("found credential", "found wifi", "wifi profile", "found cookie", "cookie")
_DONPAPI_ALLOWED_KEYS = {"url", "login", "password", "username", "ssid", "wifi", "domain"}


def _parse_donpapi_header(header: str) -> tuple[str, str] | tuple[None, None]:
    lower_header = header.lower()
    if not any(marker in lower_header for marker in _DONPAPI_KIND_MARKERS):
        return None, None
    host_hint = header.rsplit(" on ", 1)[1].strip() if " on " in lower_header else ""
    kind = next((marker for marker in _DONPAPI_KIND_MARKERS if marker in lower_header), "donpapi")
    return kind, host_hint


def _get_donpapi_sep(line: str) -> str | None:
    if ":" in line:
        return ":"
    if "=" in line:
        return "="
    return None


def _is_allowed_donpapi_key(norm_key: str) -> bool:
    return norm_key in _DONPAPI_ALLOWED_KEYS


def _parse_donpapi_kv(lines: list[str]) -> dict[str, str]:
    kv: dict[str, str] = {}
    for line in lines:
        sep = _get_donpapi_sep(line)
        if not sep:
            continue
        key, _, value = line.partition(sep)
        norm_key = key.strip().lower()
        if _is_allowed_donpapi_key(norm_key):
            kv[norm_key] = value.strip()
    return kv


def _build_donpapi_cred(kind: str, host_hint: str, kv: dict[str, str]) -> dict | None:
    username = kv.get("login") or kv.get("username") or ""
    password = kv.get("password") or ""
    if not username or not password:
        return None
    return {
        "username": username,
        "secret": password,
        "domain": kv.get("domain") or "",
        "service": (kv.get("url") or kv.get("ssid") or kv.get("wifi") or "donpapi"),
        "kind": kind,
        "host_hint": host_hint,
    }


def _parse_donpapi_block(part: str) -> dict | None:
    lines = [line.strip() for line in part.splitlines() if line.strip()]
    if not lines:
        return None
    header = lines[0]
    kind, host_hint = _parse_donpapi_header(header)
    if not kind:
        return None
    kv = _parse_donpapi_kv(lines[1:])
    return _build_donpapi_cred(kind, host_hint, kv)


def _donpapi_build_command(
    target: str,
    domain: str,
    username: str,
    password: str,
    nthash: str,
    extra_flags: str,
    output_dir: str,
) -> str:
    """Compose the donpapi CLI invocation. Hash takes precedence over password."""
    auth = ""
    if nthash:
        auth = f"-H '{nthash}'"
    elif password:
        auth = f"-p '{password}'"
    user_arg = f"-u '{username}'" if username else ""
    dom_arg = f"-d '{domain}'" if domain else ""
    return (
        f"mkdir -p '{output_dir}' && donpapi collect "
        f"-t '{target}' {user_arg} {dom_arg} {auth} "
        f"--output-directory '{output_dir}' {extra_flags} 2>&1 ; "
        f"ls -la '{output_dir}' 2>/dev/null"
    )


def _donpapi_record_activity(
    db, pid: str, target_host, target: str, safe_cmd: str, safe_output: str, creds_created: int, result: dict
) -> str:
    if not target_host:
        return ""
    activity = models.HostActivity(
        id=new_id("ha"),
        pid=pid,
        host_id=target_host.id,
        title=f"DonPAPI: {target}",
        activity_type="credential_dump",
        command=safe_cmd,
        summary=f"DonPAPI dump → {creds_created} cred(s) harvested",
        output=safe_output[:20000],
        status="done" if result.get("ok") else "failed",
        ts=ts_now(),
    )
    db.add(activity)
    db.flush()
    return activity.id


async def _donpapi_try_fetch_loot(loop, ssh_config, output_dir, pid, target, target_host, job, creds_created, db, username, log_event_fn) -> str:
    try:
        return await donpapi_fetch_loot(loop, ssh_config, output_dir, pid, target, target_host, job, creds_created, db)
    except Exception as e:
        log_event_fn(
            db, pid, username, "scan", "donpapi_loot_failed",
            f"DonPAPI loot fetch failed: {e}", {"target": target, "error": str(e)[:200]},
        )
        return ""


@router.post("/donpapi", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def run_donpapi_scan(
    pid: str,
    body: DonpapiScanBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_attacker_ssh()
    check_pid_access(db, pid, user, "credentials.create")

    if not body.target.strip():
        raise HTTPException(400, _MSG_TARGET_REQUIRED)
    if not body.username:
        raise HTTPException(400, "username is required for DPAPI dump")
    if not (body.password or body.nthash):
        raise HTTPException(400, "password or nthash is required")

    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target.strip())

    output_dir = f"/data/uploads/donpapi_{int(datetime.now(UTC).timestamp())}"
    raw_cmd = _donpapi_build_command(
        body.target.strip(),
        body.domain,
        body.username,
        body.password,
        body.nthash,
        body.extra_flags,
        output_dir,
    )

    # Scrub the secret out of the stored command so downstream audit /
    # WS broadcast doesn't carry it (P12 hygiene rule from v0.4.6).
    from ..core.secret_scrub import scrub_secret

    safe_cmd = scrub_secret(scrub_secret(raw_cmd, body.password), body.nthash)

    username = getattr(request.state, "username", None)
    target = body.target.strip()
    job = start_job(
        db,
        pid,
        "donpapi",
        f"DonPAPI: {target}",
        target=target,
        command=safe_cmd,
        created_by=username or "",
        connector_key="donpapi",
        operation="scan",
        related_entity=("project", pid),
        request_json={
            "target": target,
            "domain": body.domain,
            "username": body.username,
            "target_id": body.target_id,
            "timeout_seconds": body.timeout_seconds,
            "fetch_loot": body.fetch_loot,
            "output_dir": output_dir,
            # password / nthash deliberately NOT echoed back in request_json
        },
    )

    loop = asyncio.get_running_loop()
    run_cmd = lambda: run_ssh_command(ssh_config, raw_cmd, body.timeout_seconds)  # noqa: E731
    result = await loop.run_in_executor(None, run_cmd)

    stdout = result.get("stdout", "") or ""
    stderr = result.get("stderr", "") or ""
    combined = stdout + ("\n" + stderr if stderr else "")
    safe_output = scrub_secret(scrub_secret(combined, body.password), body.nthash)

    parsed = _parse_donpapi_stdout(combined)

    from ..core.crypto import encrypt_str

    creds_created = sum(1 for cred in parsed if donpapi_upsert_cred(db, pid, cred, target, encrypt_str))

    target_host = (
        db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == target).first()
    )
    activity_id = _donpapi_record_activity(db, pid, target_host, target, safe_cmd, safe_output, creds_created, result)

    loot_id = ""
    if body.fetch_loot and result.get("ok"):
        loot_id = await _donpapi_try_fetch_loot(loop, ssh_config, output_dir, pid, target, target_host, job, creds_created, db, username, log_event)

    log_event(
        db,
        pid,
        username,
        "scan",
        "donpapi",
        f"DonPAPI on {target}: {creds_created} cred(s)",
        {
            "target": target,
            "creds_created": creds_created,
            "output_dir": output_dir,
            "loot_id": loot_id,
        },
    )
    db.commit()

    finish_job(
        db,
        job,
        status="done" if result.get("ok") else "failed",
        output=safe_output[:20000],
        error_output=scrub_secret(stderr, body.password),
        result={
            "creds_created": creds_created,
            "output_dir": output_dir,
            "activity_id": activity_id,
            "loot_id": loot_id,
        },
    )

    return {
        "ok": result.get("ok", False),
        "job_id": job.id,
        "target": target,
        "creds_created": creds_created,
        "output_dir": output_dir,
        "loot_id": loot_id,
    }
from urllib.parse import urlsplit
