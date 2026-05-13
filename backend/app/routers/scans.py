"""
Scan runner: Nmap, Nuclei, CrackMapExec/NetExec via attacker SSH.
Results are parsed and auto-populated into hosts/creds/findings.
"""
import asyncio
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast, log_event
from ..core.job_tracker import start_job, finish_job
from ..core.ssh_exec import run_ssh_command
from ..core.exec_context import build_remote_execution_command
from ..core.route_selection import choose_route_aware_target
from ..core.utils import new_id
from ..database import get_db
from ..plugins.registry import registry
from ..plugins.state import list_attacker_targets


router = APIRouter(prefix="/api/projects/{pid}/scans", tags=["scans"])


def _require_attacker_ssh():
    module = registry.get("attacker_ssh")
    if not module or not module.enabled:
        raise HTTPException(404, "Attacker SSH module is disabled")


def _get_ssh_config(pid: str, target_id: Optional[str], db: Session | None = None, target_hint: str = "") -> dict:
    targets = list_attacker_targets()
    if not targets:
        raise HTTPException(400, "No attacker SSH targets configured")
    if target_id:
        t = next((t for t in targets if t.get("id") == target_id), None)
        if not t:
            raise HTTPException(404, "Attacker target not found")
        return t
    project_targets = [t for t in targets if not t.get("project_ids") or pid in t.get("project_ids", [])]
    if not project_targets:
        raise HTTPException(400, "No attacker SSH target assigned to this project")
    if db is not None and target_hint:
        selected = choose_route_aware_target(pid, project_targets, db, target_hint)
        if selected:
            return selected
    return project_targets[0]


def _upsert_host(db: Session, pid: str, ip: str, **kwargs) -> models.Host:
    host = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
    if host:
        for k, v in kwargs.items():
            if v is not None and v != "" and v != []:
                setattr(host, k, v)
    else:
        host = models.Host(
            id=new_id("hst"),
            pid=pid,
            ip=ip,
            status="up",
            **{k: v for k, v in kwargs.items() if v is not None},
        )
        db.add(host)
    return host


# ── Nmap ──────────────────────────────────────────────────────────────

class NmapScanBody(BaseModel):
    target: str
    flags: str = "-sV -sC -T4 --open"
    target_id: Optional[str] = None
    timeout_seconds: int = 180


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

        hostname = ""
        for hn in host_el.findall(".//hostname"):
            if hn.get("type") in ("user", "PTR", None):
                hostname = hn.get("name", "")
                break

        os_guess = ""
        os_el = host_el.find(".//osmatch")
        if os_el is not None:
            os_guess = os_el.get("name", "")

        ports = []
        services = []
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

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "os": os_guess,
            "ports": ports,
            "services": services,
            "status": "up",
        })
    return hosts


@router.post("/nmap")
async def run_nmap_scan(
    pid: str,
    body: NmapScanBody,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_attacker_ssh()
    check_pid_access(db, pid, user, "hosts.create")

    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target)
    target = body.target.strip()
    if not target:
        raise HTTPException(400, "target is required")

    username = getattr(request.state, "username", None)
    cmd = build_remote_execution_command(ssh_config, f"nmap {body.flags} -oX - {target} 2>/dev/null")
    job = start_job(
        db, pid, "nmap", f"Nmap: {target}",
        target=target, command=cmd, created_by=username or "",
        connector_key="nmap", operation="scan",
        related_entity_type="project", related_entity_id=pid,
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)
    )

    stdout = result.get("stdout", "")
    parsed = _parse_nmap_xml(stdout)

    created, updated = 0, 0
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")

    host_list = []
    for h in parsed:
        existing = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == h["ip"]).first()
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
            updated += 1
            host_obj = existing
        else:
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
            created += 1
        host_list.append(host_obj)

    log_event(db, pid, username, "scan", "nmap", f"Nmap scan: {target} → {created} new, {updated} updated", {"target": target, "created": created, "updated": updated})
    db.commit()

    for host_obj in host_list:
        db.refresh(host_obj)
        payload = schemas.Host.model_validate(host_obj).model_dump()
        bcast(pid, "host", "upsert", payload)

    job_status = "done" if result.get("ok") else "failed"
    finish_job(db, job, status=job_status,
               output=stdout[:20000] if stdout else "",
               error_output=result.get("stderr", ""),
               result={"hosts_found": len(parsed), "hosts_created": created, "hosts_updated": updated})

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
    target_id: Optional[str] = None
    timeout_seconds: int = 300
    extra_flags: str = ""


def _parse_nuclei_jsonl(text: str) -> list[dict]:
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        severity = severity_map.get((info.get("severity") or "medium").lower(), "medium")
        title = info.get("name") or obj.get("template-id") or "Nuclei Finding"
        description = info.get("description") or ""
        reference = info.get("reference") or []
        if isinstance(reference, list):
            reference = "\n".join(reference)
        matched_at = obj.get("matched-at") or obj.get("host") or ""
        cve = ""
        for tag in (info.get("tags") or "").split(","):
            tag = tag.strip()
            if tag.upper().startswith("CVE-"):
                cve = tag.upper()
                break
        findings.append({
            "title": title,
            "severity": severity,
            "description": description,
            "proof": f"URL: {matched_at}\nTemplate: {obj.get('template-id', '')}\nMatched: {obj.get('matched-at', '')}",
            "cve": cve,
            "host": matched_at,
            "template_id": obj.get("template-id", ""),
        })
    return findings


@router.post("/nuclei")
async def run_nuclei_scan(
    pid: str,
    body: NucleiScanBody,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_attacker_ssh()
    check_pid_access(db, pid, user, "findings.create")

    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target)
    target = body.target.strip()
    if not target:
        raise HTTPException(400, "target is required")

    username = getattr(request.state, "username", None)
    tpl_flag = f"-t {body.templates}" if body.templates.strip() else ""
    cmd = build_remote_execution_command(ssh_config, f"nuclei -u {target} {tpl_flag} -severity {body.severity} -jsonl {body.extra_flags} 2>/dev/null")
    job = start_job(
        db, pid, "nuclei", f"Nuclei: {target}",
        target=target, command=cmd, created_by=username or "",
        connector_key="nuclei", operation="scan",
        related_entity_type="project", related_entity_id=pid,
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)
    )

    parsed = _parse_nuclei_jsonl(result.get("stdout", ""))

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")

    existing_titles = {f.title for f in db.query(models.Finding).filter(models.Finding.pid == pid).all()}
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

    log_event(db, pid, username, "scan", "nuclei", f"Nuclei scan: {target} → {len(created_findings)} findings", {"target": target, "found": len(parsed), "created": len(created_findings)})
    db.commit()

    for finding in created_findings:
        db.refresh(finding)
        payload = schemas.Finding.model_validate(finding).model_dump()
        bcast(pid, "finding", "create", payload)

    job_status = "done" if result.get("ok") else "failed"
    finish_job(db, job, status=job_status,
               output=result.get("stdout", "")[:20000],
               error_output=result.get("stderr", ""),
               result={"findings_found": len(parsed), "findings_created": len(created_findings)})

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
    username: Optional[str] = None
    password: Optional[str] = None
    domain: Optional[str] = None
    hash: Optional[str] = None
    protocol: str = "smb"
    extra_flags: str = "--users --groups"
    target_id: Optional[str] = None
    timeout_seconds: int = 120


def _parse_cme_output(text: str) -> dict:
    hosts = []
    creds = []

    host_pattern = re.compile(r"SMB\s+([\d.]+)\s+(\d+)\s+(\S+)\s+\[")
    domain_pattern = re.compile(r"\(domain:([\w.-]+)\)", re.IGNORECASE)
    cred_pattern = re.compile(r"\[\+\].*?(\S+\\?\S+):(.+?)\s")
    user_pattern = re.compile(r"SMB.*USERS.*?([\w.]+)\s+\(.*?RID.*?\)")

    seen_ips = set()
    for line in text.splitlines():
        line = line.strip()
        # Parse host line: SMB 10.0.0.1 445 DC01 [*] ... (domain:corp.local) ...
        m = host_pattern.match(line)
        if m:
            ip, port, hostname = m.group(1), m.group(2), m.group(3)
            domain = ""
            dm = domain_pattern.search(line)
            if dm:
                parsed_domain = dm.group(1).strip()
                # Only use domain if it differs from hostname (workgroup machines report hostname as domain)
                if parsed_domain.lower() != hostname.lower():
                    domain = parsed_domain
            if ip not in seen_ips:
                seen_ips.add(ip)
                hosts.append({
                    "ip": ip,
                    "hostname": hostname,
                    "domain": domain,
                    "ports": [f"{port}/tcp"],
                    "services": [f"{port}/smb"],
                })

        # Success auth line
        if "[+]" in line:
            m = cred_pattern.search(line)
            if m:
                uname = m.group(1).strip()
                passwd = m.group(2).strip()
                if uname and passwd and passwd != "<empty>":
                    creds.append({"username": uname, "secret": passwd, "type": "plain", "service": "smb"})

        # Enumerated users
        m = user_pattern.match(line)
        if m:
            uname = m.group(1).strip()
            if uname and uname not in {c["username"] for c in creds}:
                creds.append({"username": uname, "secret": "", "type": "plain", "service": "smb"})

    return {"hosts": hosts, "creds": creds}


@router.post("/cme")
async def run_cme_scan(
    pid: str,
    body: CmeScanBody,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_attacker_ssh()
    check_pid_access(db, pid, user, "hosts.create")

    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target)
    target = body.target.strip()
    if not target:
        raise HTTPException(400, "target is required")

    username = getattr(request.state, "username", None)
    auth = ""
    if body.hash:
        auth = f"-u '{body.username or ''}' -H '{body.hash}'"
    elif body.username and body.password:
        auth = f"-u '{body.username}' -p '{body.password}'"
    elif body.username:
        auth = f"-u '{body.username}'"

    domain = f"-d {body.domain}" if body.domain else ""
    cmd = build_remote_execution_command(ssh_config, f"nxc {body.protocol} {target} {auth} {domain} {body.extra_flags} 2>/dev/null")
    job = start_job(
        db, pid, "cme", f"NetExec ({body.protocol}): {target}",
        target=target, command=cmd, created_by=username or "",
        connector_key="netexec", operation="scan",
        related_entity_type="project", related_entity_id=pid,
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)
    )

    parsed = _parse_cme_output(result.get("stdout", "") + result.get("stderr", ""))

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")

    created_hosts, created_creds = 0, 0
    host_objects = []
    # Collect per-IP domain info discovered from scan output
    discovered_domains: dict[str, str] = {}

    for h in parsed["hosts"]:
        if h.get("domain"):
            discovered_domains[h["ip"]] = h["domain"]
        existing = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == h["ip"]).first()
        if existing:
            if h["hostname"] and not existing.hostname:
                existing.hostname = h["hostname"]
            existing.ports = list(set((existing.ports or []) + h["ports"]))
            existing.services = list(set((existing.services or []) + h["services"]))
            if not existing.import_source:
                existing.import_source = "netexec"
            host_objects.append(existing)
        else:
            hobj = models.Host(
                id=new_id("hst"), pid=pid,
                ip=h["ip"], hostname=h.get("hostname", ""),
                os="Windows", status="up",
                ports=h["ports"], services=h["services"],
                tags=["cme"],
                import_source="netexec",
            )
            db.add(hobj)
            created_hosts += 1
            host_objects.append(hobj)

    # Best domain: explicit from request > first discovered from scan
    best_domain = body.domain or (next(iter(discovered_domains.values()), "") if discovered_domains else "")

    existing_cred_keys = {(c.username, c.service) for c in db.query(models.Cred).filter(models.Cred.pid == pid).all()}
    cred_objects = []
    for c in parsed["creds"]:
        key = (c["username"], c.get("service", "smb"))
        if key not in existing_cred_keys:
            cobj = models.Cred(
                id=new_id("crd"), pid=pid,
                username=c["username"], secret=c.get("secret", ""),
                type=c.get("type", "plain"), service=c.get("service", "smb"),
                domain=best_domain,
                tags=["cme"],
            )
            db.add(cobj)
            existing_cred_keys.add(key)
            created_creds += 1
            cred_objects.append(cobj)

    log_event(db, pid, username, "scan", "cme", f"CME scan: {target} → {created_hosts} hosts, {created_creds} creds", {"target": target})
    db.commit()

    for obj in host_objects:
        db.refresh(obj)
        bcast(pid, "host", "upsert", schemas.Host.model_validate(obj).model_dump())
    for obj in cred_objects:
        db.refresh(obj)
        bcast(pid, "cred", "create", schemas.Cred.model_validate(obj).model_dump())

    job_status = "done" if result.get("ok") else "failed"
    finish_job(db, job, status=job_status,
               output=result.get("stdout", "")[:20000],
               error_output=result.get("stderr", ""),
               result={"hosts_found": len(parsed["hosts"]), "hosts_created": created_hosts,
                       "creds_found": len(parsed["creds"]), "creds_created": created_creds})

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
    target_id: Optional[str] = None


def _parse_httpx_jsonl(text: str) -> list[dict]:
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or obj.get("input") or ""
        status = obj.get("status-code") or obj.get("status_code") or 0
        title = obj.get("title") or ""
        tech = obj.get("tech") or obj.get("technologies") or []
        if isinstance(tech, str):
            tech = [t.strip() for t in tech.split(",") if t.strip()]
        webserver = obj.get("webserver") or obj.get("web-server") or ""
        host = obj.get("host") or obj.get("input") or ""
        # Normalise host: strip protocol
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split("/")[0].split(":")[0]
        port_str = obj.get("port") or ""
        try:
            port = int(port_str)
        except (ValueError, TypeError):
            port = 80
        results.append({
            "url": url,
            "host": host,
            "port": port,
            "status": int(status) if status else 0,
            "title": title,
            "tech": tech,
            "webserver": webserver,
        })
    return results


@router.post("/httpx")
async def run_httpx(
    pid: str,
    body: HttpxScanBody,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    _require_attacker_ssh()
    check_pid_access(db, pid, current_user)
    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target)
    username = current_user.username
    target = body.target.strip()

    flags = body.flags or "-title -status-code -tech-detect -follow-redirects"
    cmd = build_remote_execution_command(ssh_config, f"httpx -u '{target}' {flags} -json -silent 2>/dev/null || httpx -u '{target}' {flags} -json 2>&1")

    job = start_job(
        db, pid, "httpx", f"httpx: {target}",
        target=target, command=cmd, created_by=username,
        connector_key="httpx", operation="scan",
        related_entity_type="project", related_entity_id=pid,
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)
    )

    stdout = result.get("stdout", "")
    parsed = _parse_httpx_jsonl(stdout)

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    hosts_found = len({r["host"] for r in parsed if r["host"]})
    urls_found = len(parsed)
    activities_created = 0

    for r in parsed:
        h_ip = r["host"]
        if not h_ip:
            continue
        existing = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == h_ip).first()
        if not existing:
            existing = db.query(models.Host).filter(models.Host.pid == pid, models.Host.hostname == h_ip).first()
        if not existing:
            existing = models.Host(
                id=new_id("hst"), pid=pid,
                ip=h_ip, hostname="",
                os="", status="up",
                ports=[r["port"]] if r["port"] else [],
                services=["http"] if r["port"] in (80, 8080) else ["https"],
                tags=["httpx"],
                import_source="httpx",
            )
            db.add(existing)
        else:
            if r["port"] and r["port"] not in (existing.ports or []):
                existing.ports = list(set((existing.ports or []) + [r["port"]]))
            svc = "http" if r["port"] in (80, 8080) else "https"
            if svc not in (existing.services or []):
                existing.services = list(set((existing.services or []) + [svc]))

        tech_str = ", ".join(r["tech"]) if r["tech"] else ""
        summary = f"[{r['status']}] {r['url']}"
        if r["title"]:
            summary += f" | {r['title']}"
        if tech_str:
            summary += f" | tech: {tech_str}"

        activity = models.HostActivity(
            id=new_id("hact"), pid=pid,
            host_id=existing.id,
            title=f"httpx: {r['url']}",
            activity_type="recon",
            command=cmd,
            summary=summary,
            output=json.dumps(r),
            status="done",
            ts=ts,
        )
        db.add(activity)
        activities_created += 1

    log_event(db, pid, username, "scan", "httpx", f"httpx: {target} → {urls_found} URLs, {hosts_found} hosts", {"target": target})
    db.commit()

    job_status = "done" if result.get("ok") else "failed"
    finish_job(db, job, status=job_status,
               output=stdout[:20000] if stdout else "",
               error_output=result.get("stderr", ""),
               result={"urls_found": urls_found, "hosts_found": hosts_found, "activities_created": activities_created})

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
    target_id: Optional[str] = None


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


@router.post("/ffuf")
async def run_ffuf(
    pid: str,
    body: FfufScanBody,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    _require_attacker_ssh()
    check_pid_access(db, pid, current_user)
    ssh_config = _get_ssh_config(pid, body.target_id, db, body.target_url)
    username = current_user.username
    target_url = body.target_url.strip().rstrip("/")

    ext_flag = f"-e {body.extensions}" if body.extensions.strip() else ""
    url = f"{target_url}/FUZZ"
    cmd = build_remote_execution_command(ssh_config, f"ffuf -u '{url}' -w '{body.wordlist}' {ext_flag} {body.flags} -o /tmp/ffuf_out.json -of json -s 2>/dev/null && cat /tmp/ffuf_out.json")

    job = start_job(
        db, pid, "ffuf", f"ffuf: {target_url}",
        target=target_url, command=cmd, created_by=username,
        connector_key="ffuf", operation="scan",
        related_entity_type="project", related_entity_id=pid,
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command(ssh_config, cmd, body.timeout_seconds)
    )

    stdout = result.get("stdout", "")
    parsed = _parse_ffuf_json(stdout)

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    paths_found = len(parsed)
    findings_created = 0

    for r in parsed:
        status = r.get("status") or 0
        path = r.get("input", {}).get("FUZZ") or r.get("url") or ""
        full_url = r.get("url") or f"{target_url}/{path}"
        length = r.get("length") or 0
        words = r.get("words") or 0

        severity = "info"
        if status in (200, 204):
            severity = "low"
        if status in (401, 403):
            severity = "info"
        if path and any(kw in path.lower() for kw in ("admin", "config", "backup", "secret", ".env", "passwd")):
            severity = "medium"

        existing = db.query(models.Finding).filter(
            models.Finding.pid == pid,
            models.Finding.title == f"ffuf: {full_url}",
        ).first()
        if not existing:
            finding = models.Finding(
                id=new_id("fnd"),
                pid=pid,
                title=f"ffuf: {full_url}",
                severity=severity,
                description=f"HTTP {status} — size {length} bytes / {words} words",
                proof=f"URL: {full_url}\nStatus: {status}\nSize: {length}\nWords: {words}",
                status="open",
                ts=ts,
            )
            db.add(finding)
            findings_created += 1

    log_event(db, pid, username, "scan", "ffuf", f"ffuf: {target_url} → {paths_found} paths, {findings_created} findings", {"target": target_url})
    db.commit()

    job_status = "done" if result.get("ok") else "failed"
    finish_job(db, job, status=job_status,
               output=stdout[:20000] if stdout else "",
               error_output=result.get("stderr", ""),
               result={"paths_found": paths_found, "findings_created": findings_created})

    return {
        "ok": result.get("ok", False),
        "job_id": job.id,
        "target_url": target_url,
        "paths_found": paths_found,
        "findings_created": findings_created,
    }
