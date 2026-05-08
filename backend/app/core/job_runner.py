import asyncio

from .. import models, schemas
from ..database import SessionLocal
from ..core.events import bcast, log_event
from ..core.job_tracker import finish_job, mark_job_running
from ..core.ssh_exec import run_ssh_command
from ..core.utils import new_id
from ..core.writeback import apply_writeback

_ACTIVE_TASKS: set[asyncio.Task] = set()
_SUPPORTED_QUEUED_OPERATIONS = {
    ("nmap", "scan"),
    ("nuclei", "scan"),
    ("netexec", "scan"),
    ("attacker_ssh", "exec"),
    ("topology", "auto_build"),
    ("topology", "rebuild_layout"),
    ("httpx", "scan"),
    ("ffuf", "scan"),
}


def supports_queued_execution(connector_key: str, operation: str) -> bool:
    return (connector_key, operation) in _SUPPORTED_QUEUED_OPERATIONS


def schedule_job_run(job_id: str) -> None:
    task = asyncio.create_task(run_queued_job(job_id))
    _ACTIVE_TASKS.add(task)
    task.add_done_callback(_ACTIVE_TASKS.discard)


async def run_queued_job(job_id: str) -> None:
    db = SessionLocal()
    try:
        job = db.query(models.Job).filter(models.Job.id == job_id).first()
        if not job or job.status != "queued":
            return
        mark_job_running(db, job)
        await _dispatch_job(db, job)
        # Post-job enrichment: auto-update hosts/creds from results
        db.refresh(job)
        try:
            apply_writeback(db, job, job.result_json or {})
        except Exception:
            pass  # writeback errors must never fail the job
    except Exception as exc:
        job = db.query(models.Job).filter(models.Job.id == job_id).first()
        if job and job.status not in ("done", "failed", "cancelled"):
            finish_job(db, job, status="failed", error_output=str(exc))
    finally:
        db.close()


async def _dispatch_job(db, job: models.Job) -> None:
    if job.connector_key == "nmap" and job.operation == "scan":
        await _run_nmap_job(db, job)
        return
    if job.connector_key == "nuclei" and job.operation == "scan":
        await _run_nuclei_job(db, job)
        return
    if job.connector_key == "netexec" and job.operation == "scan":
        await _run_cme_job(db, job)
        return
    if job.connector_key == "attacker_ssh" and job.operation == "exec":
        await _run_exec_job(db, job)
        return
    if job.connector_key == "topology" and job.operation == "auto_build":
        await _run_topology_auto_build_job(db, job)
        return
    if job.connector_key == "topology" and job.operation == "rebuild_layout":
        await _run_topology_rebuild_job(db, job)
        return
    if job.connector_key == "httpx" and job.operation == "scan":
        await _run_httpx_job(db, job)
        return
    if job.connector_key == "ffuf" and job.operation == "scan":
        await _run_ffuf_job(db, job)
        return
    finish_job(db, job, status="failed", error_output="Queued execution is not supported for this connector/operation yet")


async def _run_nmap_job(db, job: models.Job) -> None:
    from ..routers.scans import _get_ssh_config, _parse_nmap_xml

    payload = job.request_json or {}
    target = (payload.get("target") or job.target or "").strip()
    flags = payload.get("flags") or "-sV -sC -T4 --open"
    timeout_seconds = int(payload.get("timeout_seconds") or 180)
    target_id = payload.get("target_id")
    if not target:
        finish_job(db, job, status="failed", error_output="Missing target")
        return

    ssh_config = _get_ssh_config(job.pid, target_id)
    cmd = f"nmap {flags} -oX - {target} 2>/dev/null"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: run_ssh_command(ssh_config, cmd, timeout_seconds))
    parsed = _parse_nmap_xml(result.get("stdout", ""))

    created, updated = 0, 0
    host_list = []
    for h in parsed:
        existing = db.query(models.Host).filter(models.Host.pid == job.pid, models.Host.ip == h["ip"]).first()
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
            updated += 1
            host_obj = existing
        else:
            host_obj = models.Host(
                id=new_id("hst"), pid=job.pid, ip=h["ip"], hostname=h.get("hostname", ""),
                os=h.get("os", "Linux"), status="up", ports=h["ports"], services=h["services"],
                tags=["nmap"], import_source="nmap",
            )
            db.add(host_obj)
            created += 1
        host_list.append(host_obj)
    log_event(db, job.pid, job.created_by, "scan", "nmap", f"Nmap scan: {target} → {created} new, {updated} updated", {"target": target, "created": created, "updated": updated})
    db.commit()
    for host_obj in host_list:
        db.refresh(host_obj)
        bcast(job.pid, "host", "upsert", schemas.Host.model_validate(host_obj).model_dump())
    finish_job(db, job, status="done" if result.get("ok") else "failed", output=result.get("stdout", "")[:20000], error_output=result.get("stderr", ""), result={"hosts_found": len(parsed), "hosts_created": created, "hosts_updated": updated})


async def _run_nuclei_job(db, job: models.Job) -> None:
    from ..routers.scans import _get_ssh_config, _parse_nuclei_jsonl

    payload = job.request_json or {}
    target = (payload.get("target") or job.target or "").strip()
    templates = payload.get("templates") or ""
    severity = payload.get("severity") or "critical,high,medium"
    extra_flags = payload.get("extra_flags") or ""
    timeout_seconds = int(payload.get("timeout_seconds") or 300)
    target_id = payload.get("target_id")
    if not target:
        finish_job(db, job, status="failed", error_output="Missing target")
        return
    ssh_config = _get_ssh_config(job.pid, target_id)
    tpl_flag = f"-t {templates}" if templates.strip() else ""
    cmd = f"nuclei -u {target} {tpl_flag} -severity {severity} -jsonl {extra_flags} 2>/dev/null"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: run_ssh_command(ssh_config, cmd, timeout_seconds))
    parsed = _parse_nuclei_jsonl(result.get("stdout", ""))
    existing_titles = {f.title for f in db.query(models.Finding).filter(models.Finding.pid == job.pid).all()}
    created_findings = []
    for f in parsed:
        if f["title"] in existing_titles:
            continue
        finding = models.Finding(id=new_id("fnd"), pid=job.pid, title=f["title"], severity=f["severity"], description=f["description"], proof=f["proof"], cve=f["cve"], status="open", ts=job.created_at[:16])
        db.add(finding)
        existing_titles.add(f["title"])
        created_findings.append(finding)
    log_event(db, job.pid, job.created_by, "scan", "nuclei", f"Nuclei scan: {target} → {len(created_findings)} findings", {"target": target, "found": len(parsed), "created": len(created_findings)})
    db.commit()
    for finding in created_findings:
        db.refresh(finding)
        bcast(job.pid, "finding", "create", schemas.Finding.model_validate(finding).model_dump())
    finish_job(db, job, status="done" if result.get("ok") else "failed", output=result.get("stdout", "")[:20000], error_output=result.get("stderr", ""), result={"findings_found": len(parsed), "findings_created": len(created_findings)})


async def _run_cme_job(db, job: models.Job) -> None:
    from ..routers.scans import _get_ssh_config, _parse_cme_output

    payload = job.request_json or {}
    target = (payload.get("target") or job.target or "").strip()
    timeout_seconds = int(payload.get("timeout_seconds") or 120)
    target_id = payload.get("target_id")
    protocol = payload.get("protocol") or "smb"
    if not target:
        finish_job(db, job, status="failed", error_output="Missing target")
        return
    ssh_config = _get_ssh_config(job.pid, target_id)
    auth = ""
    if payload.get("hash"):
        auth = f"-u '{payload.get('username') or ''}' -H '{payload.get('hash')}'"
    elif payload.get("username") and payload.get("password"):
        auth = f"-u '{payload.get('username')}' -p '{payload.get('password')}'"
    elif payload.get("username"):
        auth = f"-u '{payload.get('username')}'"
    domain = f"-d {payload.get('domain')}" if payload.get("domain") else ""
    cmd = f"nxc {protocol} {target} {auth} {domain} {payload.get('extra_flags') or '--users --groups'} 2>/dev/null"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: run_ssh_command(ssh_config, cmd, timeout_seconds))
    parsed = _parse_cme_output(result.get("stdout", "") + result.get("stderr", ""))
    created_hosts, created_creds = 0, 0
    host_objects = []
    discovered_domains = {}
    for h in parsed["hosts"]:
        if h.get("domain"):
            discovered_domains[h["ip"]] = h["domain"]
        existing = db.query(models.Host).filter(models.Host.pid == job.pid, models.Host.ip == h["ip"]).first()
        if existing:
            if h["hostname"] and not existing.hostname:
                existing.hostname = h["hostname"]
            existing.ports = list(set((existing.ports or []) + h["ports"]))
            existing.services = list(set((existing.services or []) + h["services"]))
            if not existing.import_source:
                existing.import_source = "netexec"
            host_objects.append(existing)
        else:
            hobj = models.Host(id=new_id("hst"), pid=job.pid, ip=h["ip"], hostname=h.get("hostname", ""), os="Windows", status="up", ports=h["ports"], services=h["services"], tags=["cme"], import_source="netexec")
            db.add(hobj)
            created_hosts += 1
            host_objects.append(hobj)
    best_domain = payload.get("domain") or (next(iter(discovered_domains.values()), "") if discovered_domains else "")
    existing_cred_keys = {(c.username, c.service) for c in db.query(models.Cred).filter(models.Cred.pid == job.pid).all()}
    cred_objects = []
    for c in parsed["creds"]:
        key = (c["username"], c.get("service", "smb"))
        if key not in existing_cred_keys:
            cobj = models.Cred(id=new_id("crd"), pid=job.pid, username=c["username"], secret=c.get("secret", ""), type=c.get("type", "plain"), service=c.get("service", "smb"), domain=best_domain, tags=["cme"])
            db.add(cobj)
            existing_cred_keys.add(key)
            created_creds += 1
            cred_objects.append(cobj)
    log_event(db, job.pid, job.created_by, "scan", "cme", f"CME scan: {target} → {created_hosts} hosts, {created_creds} creds", {"target": target})
    db.commit()
    for obj in host_objects:
        db.refresh(obj)
        bcast(job.pid, "host", "upsert", schemas.Host.model_validate(obj).model_dump())
    for obj in cred_objects:
        db.refresh(obj)
        bcast(job.pid, "cred", "create", schemas.Cred.model_validate(obj).model_dump())
    finish_job(db, job, status="done" if result.get("ok") else "failed", output=result.get("stdout", "")[:20000], error_output=result.get("stderr", ""), result={"hosts_found": len(parsed["hosts"]), "hosts_created": created_hosts, "creds_found": len(parsed["creds"]), "creds_created": created_creds})


async def _run_exec_job(db, job: models.Job) -> None:
    from ..routers.attacker_exec import _resolve_attacker_host, _resolve_project_cred, _build_ssh_config_from_project, _list_global_targets_for_project
    from ..plugins.state import list_attacker_targets

    payload = job.request_json or {}
    exec_mode = payload.get("execution_mode") or "auto"
    host_id = payload.get("host_id")
    cred_id = payload.get("cred_id")
    target_id = payload.get("target_id")
    timeout_seconds = int(payload.get("timeout_seconds") or 45)
    command = payload.get("command") or job.command
    title = payload.get("snippet_title") or job.title or "Remote command"

    attacker_host = None
    resolved_cred = None
    ssh_config = None
    used_global_target = None
    if exec_mode in {"auto", "project"}:
        attacker_host = _resolve_attacker_host(db, job.pid, host_id)
        resolved_cred = _resolve_project_cred(db, job.pid, attacker_host, cred_id)
        if resolved_cred:
            ssh_config = _build_ssh_config_from_project(attacker_host, resolved_cred, {"port": 22, "known_hosts_policy": "accept_new"})
        elif exec_mode == "project":
            finish_job(db, job, status="failed", error_output="No usable SSH credential found for attacker host")
            return
    if ssh_config is None:
        global_targets = _list_global_targets_for_project(job.pid)
        if target_id:
            used_global_target = next((target for target in global_targets if target.get("id") == target_id), None)
        else:
            used_global_target = global_targets[0] if global_targets else None
        if not used_global_target:
            finish_job(db, job, status="failed", error_output="No global attacker target is assigned to this project")
            return
        ssh_config = next((target for target in list_attacker_targets() if target.get("id") == used_global_target.get("id")), None)
        if not ssh_config:
            finish_job(db, job, status="failed", error_output="Stored global attacker target not found")
            return
    if attacker_host is None:
        attacker_host = _resolve_attacker_host(db, job.pid, host_id) if host_id else db.query(models.Host).filter(models.Host.pid == job.pid).order_by(models.Host.hostname, models.Host.ip).first()
        if not attacker_host:
            finish_job(db, job, status="failed", error_output="No host is available in the project to attach execution output")
            return
    activity = models.HostActivity(id=new_id("ha"), pid=job.pid, host_id=attacker_host.id, title=title, activity_type=payload.get("activity_type") or "postex", command=command, summary="Executing via queued attacker SSH job...", output="", status="running", ts=job.created_at[:16])
    db.add(activity)
    log_event(db, job.pid, job.created_by, "host_activity", "create", f"Attacker exec: {title}", {"host_id": attacker_host.id, "type": activity.activity_type})
    db.commit()
    db.refresh(activity)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: run_ssh_command(dict(ssh_config), command, timeout_seconds))
    activity.output = (result.get("stdout") or "") + (("\n" + result.get("stderr")) if result.get("stderr") else "")
    activity.status = "done" if result.get("ok") else "failed"
    activity.summary = f"Executed via attacker SSH ({'project cred' if resolved_cred else 'global config'})"
    db.commit()
    db.refresh(activity)
    bcast(job.pid, "host_activity", "update", schemas.HostActivity.model_validate(activity).model_dump())
    finish_job(db, job, status="done" if result.get("ok") else "failed", output=result.get("stdout", "")[:20000], error_output=result.get("stderr", ""), result={"exit_code": result.get("exit_code", -1), "host_id": attacker_host.id, "used_global_fallback": resolved_cred is None})


async def _run_httpx_job(db, job: models.Job) -> None:
    from ..routers.scans import _get_ssh_config, _parse_httpx_jsonl
    import json as _json
    from datetime import datetime as _dt

    payload = job.request_json or {}
    target = (payload.get("target") or job.target or "").strip()
    flags = payload.get("flags") or "-title -status-code -tech-detect -follow-redirects"
    timeout_seconds = int(payload.get("timeout_seconds") or 120)
    target_id = payload.get("target_id")
    if not target:
        finish_job(db, job, status="failed", error_output="Missing target")
        return
    ssh_config = _get_ssh_config(job.pid, target_id)
    cmd = f"httpx -u '{target}' {flags} -json -silent 2>/dev/null || httpx -u '{target}' {flags} -json 2>&1"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: run_ssh_command(ssh_config, cmd, timeout_seconds))
    parsed = _parse_httpx_jsonl(result.get("stdout", ""))
    ts = _dt.utcnow().strftime("%Y-%m-%d %H:%M")
    hosts_found = len({r["host"] for r in parsed if r["host"]})
    urls_found = len(parsed)
    activities_created = 0
    for r in parsed:
        h_ip = r["host"]
        if not h_ip:
            continue
        existing = db.query(models.Host).filter(models.Host.pid == job.pid, models.Host.ip == h_ip).first()
        if not existing:
            existing = db.query(models.Host).filter(models.Host.pid == job.pid, models.Host.hostname == h_ip).first()
        if not existing:
            existing = models.Host(id=new_id("hst"), pid=job.pid, ip=h_ip, hostname="", os="", status="up", ports=[r["port"]] if r["port"] else [], services=["http" if r["port"] in (80, 8080) else "https"], tags=["httpx"], import_source="httpx")
            db.add(existing)
        else:
            if r["port"] and r["port"] not in (existing.ports or []):
                existing.ports = list(set((existing.ports or []) + [r["port"]]))
        summary = f"[{r['status']}] {r['url']}"
        if r["title"]:
            summary += f" | {r['title']}"
        if r["tech"]:
            summary += f" | tech: {', '.join(r['tech'])}"
        activity = models.HostActivity(id=new_id("hact"), pid=job.pid, host_id=existing.id, title=f"httpx: {r['url']}", activity_type="recon", command=cmd, summary=summary, output=_json.dumps(r), status="done", ts=ts)
        db.add(activity)
        activities_created += 1
    log_event(db, job.pid, job.created_by, "scan", "httpx", f"httpx: {target} → {urls_found} URLs", {"target": target})
    db.commit()
    for h in db.query(models.Host).filter(models.Host.pid == job.pid, models.Host.import_source == "httpx").all():
        db.refresh(h)
        bcast(job.pid, "host", "upsert", schemas.Host.model_validate(h).model_dump())
    finish_job(db, job, status="done" if result.get("ok") else "failed", output=result.get("stdout", "")[:20000], error_output=result.get("stderr", ""), result={"urls_found": urls_found, "hosts_found": hosts_found, "activities_created": activities_created})


async def _run_ffuf_job(db, job: models.Job) -> None:
    from ..routers.scans import _get_ssh_config, _parse_ffuf_json
    import json as _json
    from datetime import datetime as _dt

    payload = job.request_json or {}
    target_url = (payload.get("target_url") or job.target or "").strip().rstrip("/")
    wordlist = payload.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/common.txt"
    extensions = payload.get("extensions") or ""
    flags = payload.get("flags") or "-mc 200,204,301,302,307,401,403,405"
    timeout_seconds = int(payload.get("timeout_seconds") or 300)
    target_id = payload.get("target_id")
    if not target_url:
        finish_job(db, job, status="failed", error_output="Missing target_url")
        return
    ssh_config = _get_ssh_config(job.pid, target_id)
    ext_flag = f"-e {extensions}" if extensions.strip() else ""
    url = f"{target_url}/FUZZ"
    cmd = f"ffuf -u '{url}' -w '{wordlist}' {ext_flag} {flags} -o /tmp/ffuf_out.json -of json -s 2>/dev/null && cat /tmp/ffuf_out.json"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: run_ssh_command(ssh_config, cmd, timeout_seconds))
    parsed = _parse_ffuf_json(result.get("stdout", ""))
    ts = _dt.utcnow().strftime("%Y-%m-%d %H:%M")
    findings_created = 0
    for r in parsed:
        status_code = r.get("status") or 0
        path = r.get("input", {}).get("FUZZ") or r.get("url") or ""
        full_url = r.get("url") or f"{target_url}/{path}"
        length = r.get("length") or 0
        words = r.get("words") or 0
        severity = "info"
        if status_code in (200, 204):
            severity = "low"
        if path and any(kw in path.lower() for kw in ("admin", "config", "backup", "secret", ".env", "passwd")):
            severity = "medium"
        existing = db.query(models.Finding).filter(models.Finding.pid == job.pid, models.Finding.title == f"ffuf: {full_url}").first()
        if not existing:
            db.add(models.Finding(id=new_id("fnd"), pid=job.pid, title=f"ffuf: {full_url}", severity=severity, description=f"HTTP {status_code} — size {length} bytes / {words} words", proof=f"URL: {full_url}\nStatus: {status_code}\nSize: {length}", status="open", ts=ts))
            findings_created += 1
    log_event(db, job.pid, job.created_by, "scan", "ffuf", f"ffuf: {target_url} → {len(parsed)} paths", {"target": target_url})
    db.commit()
    finish_job(db, job, status="done" if result.get("ok") else "failed", output=result.get("stdout", "")[:20000], error_output=result.get("stderr", ""), result={"paths_found": len(parsed), "findings_created": findings_created})


async def _run_topology_auto_build_job(db, job: models.Job) -> None:
    from ..routers.topology import _run_auto_build

    payload = job.request_json or {}
    result = _run_auto_build(job.pid, db, bool(payload.get("keep_manual_positions", True)), bool(payload.get("create_missing_networks", True)))
    if not result.get("ok"):
        finish_job(db, job, status="failed", error_output=result.get("error", "Topology auto-build failed"), result=result)
        return
    finish_job(db, job, status="done", result=result)


async def _run_topology_rebuild_job(db, job: models.Job) -> None:
    from ..routers.topology import compute_layout

    payload = job.request_json or {}
    keep_manual_positions = bool(payload.get("keep_manual_positions", True))
    network = db.query(models.Network).filter(models.Network.pid == job.pid).first()
    if not network:
        finish_job(db, job, status="failed", error_output="No network map found")
        return
    all_hosts = db.query(models.Host).filter(models.Host.pid == job.pid).all()
    hosts_for_layout = [{
        "id": h.id, "ip": h.ip, "hostname": h.hostname,
        "os": h.os, "status": h.status, "role": h.role,
        "is_attacker": h.is_attacker, "ports": h.ports or [], "services": h.services or [],
    } for h in all_hosts]
    existing_nodes = list(network.nodes_json or [])
    existing_edges = list(network.edges_json or [])
    positioned = compute_layout(hosts_for_layout, existing_nodes, keep_manual_positions, existing_edges)
    ip_to_new_pos = {n.get("ip"): (n.get("x", 0), n.get("y", 0)) for n in positioned}
    hid_to_new_pos = {n.get("id"): (n.get("x", 0), n.get("y", 0)) for n in positioned}
    for node in existing_nodes:
        if node.get("manually_positioned") and keep_manual_positions:
            continue
        new_pos = hid_to_new_pos.get(node.get("host_id")) or ip_to_new_pos.get(node.get("ip"))
        if new_pos:
            node["x"], node["y"] = new_pos
            node["auto_positioned"] = True
            node["manually_positioned"] = False
    network.nodes_json = existing_nodes
    network.edges_json = existing_edges
    db.commit()
    result = schemas.Network.from_orm_obj(network)
    bcast(job.pid, "network", "layout_applied", {"network": result.model_dump(), "updated_at": job.created_at})
    finish_job(db, job, status="done", result={"nodes_repositioned": len(positioned), "network_id": network.id})
