import asyncio

from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.job_tracker import finish_job, mark_job_running
from ..core.network_data import get_edges, get_nodes, replace_nodes
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
from ..core.ssh_exec import run_ssh_command_cancellable
from ..core.transport import CancellationToken
from ..core.utils import new_id
from ..core.writeback import apply_writeback
from ..database import SessionLocal

_MSG_MISSING_TARGET = "Missing target"
_MSG_CANCELLED = "Cancelled by user"

# Populated at module bottom after all handler functions are defined
_JOB_HANDLERS: dict = {}

_SUPPORTED_QUEUED_OPERATIONS = {
    ("nmap", "scan"),
    ("nuclei", "scan"),
    ("netexec", "scan"),
    ("attacker_ssh", "exec"),
    ("topology", "auto_build"),
    ("topology", "rebuild_layout"),
    ("httpx", "scan"),
    ("ffuf", "scan"),
    # P4: live C2 actions as a queued playbook step
    ("c2", "exec"),
    # P? donpapi DPAPI collection — queued so playbooks can include it
    ("donpapi", "scan"),
}


def supports_queued_execution(connector_key: str, operation: str) -> bool:
    return (connector_key, operation) in _SUPPORTED_QUEUED_OPERATIONS


def schedule_job_run(job_id: str, *, pid: str = "", priority: int = 0) -> None:
    from .worker_pool import get_pool

    get_pool().submit(job_id, pid=pid, priority=priority)


async def run_queued_job(job_id: str, cancel_token: CancellationToken | None = None) -> None:
    if cancel_token is None:
        cancel_token = CancellationToken()
    db = SessionLocal()
    try:
        job = db.query(models.Job).filter(models.Job.id == job_id).first()
        if not job or job.status != "queued":
            return
        mark_job_running(db, job)
        await _dispatch_job(db, job, cancel_token)
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


async def _dispatch_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    handler = _JOB_HANDLERS.get((job.connector_key, job.operation))
    if handler:
        result = handler(db, job, cancel_token)
        if asyncio.iscoroutine(result):
            await result
        return
    finish_job(
        db,
        job,
        status="failed",
        error_output="Queued execution is not supported for this connector/operation yet",
    )


async def _run_nmap_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    from ..routers.scans import _get_ssh_config, _parse_nmap_xml

    payload = job.request_json or {}
    target = (payload.get("target") or job.target or "").strip()
    flags = payload.get("flags") or "-sV -sC -T4 --open"
    timeout_seconds = int(payload.get("timeout_seconds") or 180)
    target_id = payload.get("target_id")
    if not target:
        finish_job(db, job, status="failed", error_output=_MSG_MISSING_TARGET)
        return

    ssh_config = _get_ssh_config(job.pid, target_id)
    cmd = f"nmap {flags} -oX - {target} 2>/dev/null"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command_cancellable(ssh_config, cmd, timeout_seconds, cancel_token)
    )
    if result.get("cancelled"):
        finish_job(db, job, status="cancelled", error_output=_MSG_CANCELLED)
        return
    parsed = _parse_nmap_xml(result.get("stdout", ""))

    created, updated = 0, 0
    host_list = []
    for h in parsed:
        host_obj, was_created = nmap_upsert_host(db, job.pid, h)
        if was_created:
            created += 1
        else:
            updated += 1
        host_list.append(host_obj)
    log_event(
        db,
        job.pid,
        job.created_by,
        "scan",
        "nmap",
        f"Nmap scan: {target} → {created} new, {updated} updated",
        {"target": target, "created": created, "updated": updated},
    )
    db.commit()
    for host_obj in host_list:
        db.refresh(host_obj)
        bcast(job.pid, "host", "upsert", schemas.Host.model_validate(host_obj).model_dump())
    finish_job(
        db,
        job,
        status="done" if result.get("ok") else "failed",
        output=result.get("stdout", "")[:20000],
        error_output=result.get("stderr", ""),
        result={"hosts_found": len(parsed), "hosts_created": created, "hosts_updated": updated},
    )


async def _run_nuclei_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    from ..routers.scans import _get_ssh_config, _parse_nuclei_jsonl

    payload = job.request_json or {}
    target = (payload.get("target") or job.target or "").strip()
    templates = payload.get("templates") or ""
    severity = payload.get("severity") or "critical,high,medium"
    extra_flags = payload.get("extra_flags") or ""
    timeout_seconds = int(payload.get("timeout_seconds") or 300)
    target_id = payload.get("target_id")
    if not target:
        finish_job(db, job, status="failed", error_output=_MSG_MISSING_TARGET)
        return
    ssh_config = _get_ssh_config(job.pid, target_id)
    tpl_flag = f"-t {templates}" if templates.strip() else ""
    cmd = f"nuclei -u {target} {tpl_flag} -severity {severity} -jsonl {extra_flags} 2>/dev/null"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command_cancellable(ssh_config, cmd, timeout_seconds, cancel_token)
    )
    if result.get("cancelled"):
        finish_job(db, job, status="cancelled", error_output=_MSG_CANCELLED)
        return
    parsed = _parse_nuclei_jsonl(result.get("stdout", ""))
    existing_titles = {
        f.title for f in db.query(models.Finding).filter(models.Finding.pid == job.pid).all()
    }
    created_findings = []
    for f in parsed:
        if f["title"] in existing_titles:
            continue
        finding = models.Finding(
            id=new_id("fnd"),
            pid=job.pid,
            title=f["title"],
            severity=f["severity"],
            description=f["description"],
            proof=f["proof"],
            cve=f["cve"],
            status="open",
            ts=job.created_at[:16],
        )
        db.add(finding)
        existing_titles.add(f["title"])
        created_findings.append(finding)
    log_event(
        db,
        job.pid,
        job.created_by,
        "scan",
        "nuclei",
        f"Nuclei scan: {target} → {len(created_findings)} findings",
        {"target": target, "found": len(parsed), "created": len(created_findings)},
    )
    db.commit()
    from .events import bcast_batch

    fevents: list[tuple[str, str, dict]] = []
    for finding in created_findings:
        db.refresh(finding)
        fevents.append(("finding", "create", schemas.Finding.model_validate(finding).model_dump()))
    bcast_batch(job.pid, fevents)
    finish_job(
        db,
        job,
        status="done" if result.get("ok") else "failed",
        output=result.get("stdout", "")[:20000],
        error_output=result.get("stderr", ""),
        result={"findings_found": len(parsed), "findings_created": len(created_findings)},
    )


async def _run_cme_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    from ..routers.scans import _get_ssh_config, _parse_cme_output

    payload = job.request_json or {}
    target = (payload.get("target") or job.target or "").strip()
    timeout_seconds = int(payload.get("timeout_seconds") or 120)
    target_id = payload.get("target_id")
    protocol = payload.get("protocol") or "smb"
    if not target:
        finish_job(db, job, status="failed", error_output=_MSG_MISSING_TARGET)
        return
    ssh_config = _get_ssh_config(job.pid, target_id)
    auth = cme_build_auth(payload)
    domain = f"-d {payload.get('domain')}" if payload.get("domain") else ""
    cmd = f"nxc {protocol} {target} {auth} {domain} {payload.get('extra_flags') or '--users --groups'} 2>/dev/null"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command_cancellable(ssh_config, cmd, timeout_seconds, cancel_token)
    )
    if result.get("cancelled"):
        finish_job(db, job, status="cancelled", error_output=_MSG_CANCELLED)
        return
    parsed = _parse_cme_output(result.get("stdout", "") + result.get("stderr", ""))
    host_objects, discovered_domains, created_hosts = cme_process_hosts(db, job.pid, parsed["hosts"])
    best_domain = payload.get("domain") or (
        next(iter(discovered_domains.values()), "") if discovered_domains else ""
    )
    existing_cred_keys = {
        (c.username, c.service)
        for c in db.query(models.Cred).filter(models.Cred.pid == job.pid).all()
    }
    cred_objects, created_creds = cme_process_creds(db, job.pid, parsed["creds"], best_domain, existing_cred_keys)
    log_event(
        db,
        job.pid,
        job.created_by,
        "scan",
        "cme",
        f"CME scan: {target} → {created_hosts} hosts, {created_creds} creds",
        {"target": target},
    )
    db.commit()
    # Coalesce: one envelope per project instead of N publishes on big
    # NetExec sweeps (one cred per pwned account adds up fast).
    from .events import bcast_batch

    events: list[tuple[str, str, dict]] = []
    for obj in host_objects:
        db.refresh(obj)
        events.append(("host", "upsert", schemas.Host.model_validate(obj).model_dump()))
    for obj in cred_objects:
        db.refresh(obj)
        events.append(("cred", "create", schemas.Cred.model_validate(obj).model_dump()))
    bcast_batch(job.pid, events)
    finish_job(
        db,
        job,
        status="done" if result.get("ok") else "failed",
        output=result.get("stdout", "")[:20000],
        error_output=result.get("stderr", ""),
        result={
            "hosts_found": len(parsed["hosts"]),
            "hosts_created": created_hosts,
            "creds_found": len(parsed["creds"]),
            "creds_created": created_creds,
        },
    )


def _resolve_exec_job_connection(db, job, payload):
    """Returns ((ssh_config, attacker_host, resolved_cred), None) or (None, error_msg)."""
    from .attacker_transport import resolve_exec_connection

    exec_mode = payload.get("execution_mode") or "auto"
    host_id = payload.get("host_id")
    cred_id = payload.get("cred_id")
    target_id = payload.get("target_id")
    command_hint = payload.get("command") or ""

    try:
        conn = resolve_exec_connection(
            db,
            job.pid,
            execution_mode=exec_mode,
            host_id=host_id,
            cred_id=cred_id,
            target_id=target_id,
            command_hint=command_hint,
        )
    except Exception as exc:
        return None, str(exc)

    return (conn.ssh_config, conn.attacker_host, conn.resolved_cred), None


async def _run_exec_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    payload = job.request_json or {}
    timeout_seconds = int(payload.get("timeout_seconds") or 45)
    command = payload.get("command") or job.command
    title = payload.get("snippet_title") or job.title or "Remote command"

    conn, err = _resolve_exec_job_connection(db, job, payload)
    if conn is None:
        finish_job(db, job, status="failed", error_output=err)
        return
    ssh_config, attacker_host, resolved_cred = conn

    activity = models.HostActivity(
        id=new_id("ha"),
        pid=job.pid,
        host_id=attacker_host.id,
        title=title,
        activity_type=payload.get("activity_type") or "postex",
        command=command,
        summary="Executing via queued attacker SSH job...",
        output="",
        status="running",
        ts=job.created_at[:16],
    )
    db.add(activity)
    log_event(
        db,
        job.pid,
        job.created_by,
        "host_activity",
        "create",
        f"Attacker exec: {title}",
        {"host_id": attacker_host.id, "type": activity.activity_type},
    )
    db.commit()
    db.refresh(activity)
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: run_ssh_command_cancellable(
            dict(ssh_config), command, timeout_seconds, cancel_token
        ),
    )
    if result.get("cancelled"):
        activity.output = _MSG_CANCELLED
        activity.status = "failed"
        db.commit()
        db.refresh(activity)
        bcast(
            job.pid,
            "host_activity",
            "update",
            schemas.HostActivity.model_validate(activity).model_dump(),
        )
        finish_job(db, job, status="cancelled", error_output=_MSG_CANCELLED)
        return
    activity.output = (result.get("stdout") or "") + (
        ("\n" + result.get("stderr")) if result.get("stderr") else ""
    )
    activity.status = "done" if result.get("ok") else "failed"
    activity.summary = (
        f"Executed via attacker SSH ({'project cred' if resolved_cred else 'global config'})"
    )
    db.commit()
    db.refresh(activity)
    bcast(
        job.pid,
        "host_activity",
        "update",
        schemas.HostActivity.model_validate(activity).model_dump(),
    )
    finish_job(
        db,
        job,
        status="done" if result.get("ok") else "failed",
        output=result.get("stdout", "")[:20000],
        error_output=result.get("stderr", ""),
        result={
            "exit_code": result.get("exit_code", -1),
            "host_id": attacker_host.id,
            "used_global_fallback": resolved_cred is None,
        },
    )


async def _run_httpx_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    import json as _json
    from datetime import UTC
    from datetime import datetime as _dt

    from ..routers.scans import _get_ssh_config, _parse_httpx_jsonl

    payload = job.request_json or {}
    target = (payload.get("target") or job.target or "").strip()
    flags = payload.get("flags") or "-title -status-code -tech-detect -follow-redirects"
    timeout_seconds = int(payload.get("timeout_seconds") or 120)
    target_id = payload.get("target_id")
    if not target:
        finish_job(db, job, status="failed", error_output=_MSG_MISSING_TARGET)
        return
    ssh_config = _get_ssh_config(job.pid, target_id)
    cmd = f"httpx -u '{target}' {flags} -json -silent 2>/dev/null || httpx -u '{target}' {flags} -json 2>&1"
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command_cancellable(ssh_config, cmd, timeout_seconds, cancel_token)
    )
    if result.get("cancelled"):
        finish_job(db, job, status="cancelled", error_output=_MSG_CANCELLED)
        return
    parsed = _parse_httpx_jsonl(result.get("stdout", ""))
    ts = _dt.now(UTC).strftime("%Y-%m-%d %H:%M")
    hosts_found = len({r["host"] for r in parsed if r["host"]})
    urls_found = len(parsed)
    activities_created = 0
    for r in parsed:
        if not r["host"]:
            continue
        host = httpx_upsert_host(db, job.pid, r)
        summary = f"[{r['status']}] {r['url']}"
        if r["title"]:
            summary += f" | {r['title']}"
        if r["tech"]:
            summary += f" | tech: {', '.join(r['tech'])}"
        activity = models.HostActivity(
            id=new_id("hact"),
            pid=job.pid,
            host_id=host.id,
            title=f"httpx: {r['url']}",
            activity_type="recon",
            command=cmd,
            summary=summary,
            output=_json.dumps(r),
            status="done",
            ts=ts,
        )
        db.add(activity)
        activities_created += 1
    log_event(
        db,
        job.pid,
        job.created_by,
        "scan",
        "httpx",
        f"httpx: {target} → {urls_found} URLs",
        {"target": target},
    )
    db.commit()
    for h in (
        db.query(models.Host)
        .filter(models.Host.pid == job.pid, models.Host.import_source == "httpx")
        .all()
    ):
        db.refresh(h)
        bcast(job.pid, "host", "upsert", schemas.Host.model_validate(h).model_dump())
    finish_job(
        db,
        job,
        status="done" if result.get("ok") else "failed",
        output=result.get("stdout", "")[:20000],
        error_output=result.get("stderr", ""),
        result={
            "urls_found": urls_found,
            "hosts_found": hosts_found,
            "activities_created": activities_created,
        },
    )


async def _run_ffuf_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    from datetime import UTC
    from datetime import datetime as _dt

    from ..routers.scans import _get_ssh_config, _parse_ffuf_json

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
    result = await loop.run_in_executor(
        None, lambda: run_ssh_command_cancellable(ssh_config, cmd, timeout_seconds, cancel_token)
    )
    if result.get("cancelled"):
        finish_job(db, job, status="cancelled", error_output=_MSG_CANCELLED)
        return
    parsed = _parse_ffuf_json(result.get("stdout", ""))
    ts = _dt.now(UTC).strftime("%Y-%m-%d %H:%M")
    findings_created = 0
    for r in parsed:
        if ffuf_upsert_finding(db, job.pid, r, target_url, ts):
            findings_created += 1
    log_event(
        db,
        job.pid,
        job.created_by,
        "scan",
        "ffuf",
        f"ffuf: {target_url} → {len(parsed)} paths",
        {"target": target_url},
    )
    db.commit()
    finish_job(
        db,
        job,
        status="done" if result.get("ok") else "failed",
        output=result.get("stdout", "")[:20000],
        error_output=result.get("stderr", ""),
        result={"paths_found": len(parsed), "findings_created": findings_created},
    )


def _run_topology_auto_build_job(
    db, job: models.Job, cancel_token: CancellationToken
) -> None:
    from ..routers.topology import _run_auto_build

    payload = job.request_json or {}
    result = _run_auto_build(
        job.pid,
        db,
        bool(payload.get("keep_manual_positions", True)),
        bool(payload.get("create_missing_networks", True)),
    )
    if not result.get("ok"):
        finish_job(
            db,
            job,
            status="failed",
            error_output=result.get("error", "Topology auto-build failed"),
            result=result,
        )
        return
    finish_job(db, job, status="done", result=result)


def _run_topology_rebuild_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    from ..routers.topology import compute_layout

    payload = job.request_json or {}
    keep_manual_positions = bool(payload.get("keep_manual_positions", True))
    network = db.query(models.Network).filter(models.Network.pid == job.pid).first()
    if not network:
        finish_job(db, job, status="failed", error_output="No network map found")
        return
    all_hosts = db.query(models.Host).filter(models.Host.pid == job.pid).all()
    hosts_for_layout = [
        {
            "id": h.id,
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os,
            "status": h.status,
            "role": h.role,
            "is_attacker": h.is_attacker,
            "ports": h.ports or [],
            "services": h.services or [],
        }
        for h in all_hosts
    ]
    existing_nodes = get_nodes(network.id, db)
    existing_edges = get_edges(network.id, db)
    positioned = compute_layout(
        hosts_for_layout, existing_nodes, keep_manual_positions, existing_edges
    )
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
    replace_nodes(network.id, network.pid, existing_nodes, db)
    db.commit()
    result = schemas.Network.from_orm_obj(network)
    bcast(
        job.pid,
        "network",
        "layout_applied",
        {"network": result.model_dump(), "updated_at": job.created_at},
    )
    finish_job(
        db,
        job,
        status="done",
        result={"nodes_repositioned": len(positioned), "network_id": network.id},
    )


def _parse_c2_exec_payload(job: "models.Job") -> dict:
    payload = job.request_json or {}
    mode = (payload.get("mode") or "command").strip()
    title_raw = (payload.get("title") or job.title or "").strip()
    title = title_raw or ("Adaptix BOF" if mode == "bof" else "Adaptix command")
    return {
        "integration_id": (payload.get("integration_id") or "").strip(),
        "agent_id": (payload.get("agent_id") or "").strip(),
        "host_id": (payload.get("host_id") or "").strip(),
        "commandline": (payload.get("commandline") or job.command or "").strip(),
        "mode": mode,
        "credential_source": (payload.get("credential_source") or "rootnotes").strip(),
        "credential_id": (payload.get("credential_id") or "").strip(),
        "wait_for_output": bool(payload.get("wait_for_output", True)),
        "timeout_seconds": int(payload.get("timeout_seconds") or 12),
        "title": title,
    }


def _c2_exec_resolve(db, pid: str, integration_id: str, agent_id: str, host_id: str, commandline: str):
    """Validates c2 exec prerequisites. Returns (host, cfg) or (None, None, error_msg)."""
    from ..routers.c2 import (
        SUPPORTED_EXEC_C2_TYPES,
        _load_integrations,
        _visible_integrations_for_pid,
    )

    if not integration_id or not agent_id or not host_id or not commandline:
        return None, None, "c2 step requires integration_id, agent_id, host_id, commandline"
    host = db.query(models.Host).filter(models.Host.id == host_id, models.Host.pid == pid).first()
    if not host:
        return None, None, f"Host {host_id} not in project"
    cfg = next(
        (i for i in _visible_integrations_for_pid(_load_integrations(db), pid) if i.get("id") == integration_id),
        None,
    )
    if not cfg:
        return None, None, f"C2 integration {integration_id} not visible in project"
    if cfg.get("type") not in SUPPORTED_EXEC_C2_TYPES:
        return None, None, (
            f"Execution supported only for: {', '.join(SUPPORTED_EXEC_C2_TYPES)} "
            f"(integration is {cfg.get('type')!r})"
        )
    return host, cfg, None


async def _run_c2_exec_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    """
    Run a queued C2 command via Adaptix (or another supported framework).

    Job payload (request_json) fields:
        integration_id       — id of the saved C2 integration to use
        agent_id             — target beacon/agent id on the C2
        host_id              — RootNotes host the activity will attach to
        commandline          — command to run (or BOF spec for bof mode)
        mode                 — "command" | "bof"
        credential_source    — "rootnotes" | "c2" (optional)
        credential_id        — cred to use for command-line %vars% (optional)
        wait_for_output      — bool, default True
        timeout_seconds      — int, default 12
    """
    from ..routers.c2 import perform_c2_command, resolve_c2_cred

    p = _parse_c2_exec_payload(job)
    host, cfg, err = _c2_exec_resolve(
        db, job.pid, p["integration_id"], p["agent_id"], p["host_id"], p["commandline"]
    )
    if err:
        finish_job(db, job, status="failed", error_output=err)
        return

    try:
        selected_cred = await resolve_c2_cred(
            db, job.pid, p["credential_id"], p["credential_source"], cfg
        )
        result, activity, rendered_command = await perform_c2_command(
            db,
            job.pid,
            host,
            cfg,
            p["agent_id"],
            p["commandline"],
            p["mode"],
            selected_cred,
            p["wait_for_output"],
            p["timeout_seconds"],
            p["title"],
            actor_username=job.created_by or "playbook",
        )
    except Exception as exc:
        finish_job(db, job, status="failed", error_output=f"C2 execution failed: {exc}")
        return

    finish_job(
        db,
        job,
        status="done",
        output=(result.get("output") or "")[:20000],
        result={
            "activity_id": activity.id,
            "host_id": host.id,
            "rendered_command": rendered_command,
            "c2_result": result,
        },
    )


def _parse_donpapi_payload(job: "models.Job") -> dict:
    from datetime import UTC
    from datetime import datetime as _dt

    payload = job.request_json or {}
    return {
        "target": (payload.get("target") or job.target or "").strip(),
        "username": (payload.get("username") or "").strip(),
        "domain": (payload.get("domain") or "").strip(),
        "cred_id": (payload.get("cred_id") or "").strip(),
        "password": payload.get("password") or "",
        "nthash": payload.get("nthash") or "",
        "extra_flags": payload.get("extra_flags") or "",
        "target_id": payload.get("target_id"),
        "timeout_seconds": int(payload.get("timeout_seconds") or 600),
        "fetch_loot": bool(payload.get("fetch_loot", True)),
        "output_dir": payload.get("output_dir") or f"/data/uploads/donpapi_{int(_dt.now(UTC).timestamp())}",
    }


def _resolve_cred_from_db(db, pid: str, cred_id: str, username: str, domain: str, password: str, nthash: str):
    """Enrich (username, domain, password, nthash) from a project Cred row. Returns tuple + error."""
    from ..core.crypto import decrypt_str

    cred = db.query(models.Cred).filter(models.Cred.id == cred_id, models.Cred.pid == pid).first()
    if not cred:
        return None, None, None, None, f"Cred {cred_id} not in project"
    if not username:
        username = cred.username or ""
    if not domain:
        domain = cred.domain or ""
    secret_plain = decrypt_str(cred.secret) if cred.secret else ""
    if (cred.type or "").lower() in {"ntlm", "hash"}:
        nthash = nthash or secret_plain
    else:
        password = password or secret_plain
    return username, domain, password, nthash, None


def _donpapi_resolve_cred(db, pid: str, cred_id: str, username: str, domain: str, password: str, nthash: str):
    """Returns (username, domain, password, nthash, error)."""
    if cred_id:
        username, domain, password, nthash, err = _resolve_cred_from_db(db, pid, cred_id, username, domain, password, nthash)
        if err:
            return None, None, None, None, err
    if not username:
        return None, None, None, None, "username is required"
    if not password and not nthash:
        return None, None, None, None, "password or nthash is required"
    return username, domain, password, nthash, None


async def _run_donpapi_job(db, job: models.Job, cancel_token: CancellationToken) -> None:
    """
    Queued DonPAPI collection.

    request_json fields:
        target          — IP / comma-list (required)
        username        — required
        domain          — optional
        cred_id         — optional, resolved from project Creds (preferred over inline secret)
        password        — optional, inline plaintext (avoid; prefer cred_id)
        nthash          — optional, NTLM hash
        extra_flags     — optional
        target_id       — attacker target id
        timeout_seconds — default 600
        fetch_loot      — default True
        output_dir      — optional override
    """
    from ..core.crypto import encrypt_str
    from ..core.secret_scrub import scrub_secret
    from ..core.utils import ts_now
    from ..routers.scans import _donpapi_build_command, _get_ssh_config, _parse_donpapi_stdout

    p = _parse_donpapi_payload(job)
    if not p["target"]:
        finish_job(db, job, status="failed", error_output=_MSG_MISSING_TARGET)
        return

    username, domain, password, nthash, err = _donpapi_resolve_cred(
        db, job.pid, p["cred_id"], p["username"], p["domain"], p["password"], p["nthash"]
    )
    if err:
        finish_job(db, job, status="failed", error_output=err)
        return

    target = p["target"]
    extra_flags = p["extra_flags"]
    output_dir = p["output_dir"]
    ssh_config = _get_ssh_config(job.pid, p["target_id"], db, target)
    raw_cmd = _donpapi_build_command(
        target, domain, username, password, nthash, extra_flags, output_dir
    )
    safe_cmd = scrub_secret(scrub_secret(raw_cmd, password), nthash)

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None,
        lambda: run_ssh_command_cancellable(ssh_config, raw_cmd, p["timeout_seconds"], cancel_token),
    )
    if result.get("cancelled"):
        finish_job(db, job, status="cancelled", error_output=_MSG_CANCELLED)
        return

    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    combined = stdout + ("\n" + stderr if stderr else "")
    safe_output = scrub_secret(scrub_secret(combined, password), nthash)

    parsed = _parse_donpapi_stdout(combined)
    creds_created = 0
    for cred in parsed:
        if donpapi_upsert_cred(db, job.pid, cred, target, encrypt_str):
            creds_created += 1

    target_host = (
        db.query(models.Host)
        .filter(
            models.Host.pid == job.pid,
            models.Host.ip == target,
        )
        .first()
    )
    activity_id = ""
    if target_host:
        activity = models.HostActivity(
            id=new_id("ha"),
            pid=job.pid,
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
        activity_id = activity.id

    loot_id = ""
    if p["fetch_loot"] and result.get("ok"):
        loot_id = await donpapi_fetch_loot(
            loop,
            ssh_config,
            output_dir,
            job.pid,
            target,
            target_host,
            job,
            creds_created,
            db,
            cancel_token=cancel_token,
            job_actor=job.created_by,
            job_id=job.id,
        )

    log_event(
        db,
        job.pid,
        job.created_by,
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
        error_output=scrub_secret(scrub_secret(stderr, password), nthash),
        result={
            "creds_created": creds_created,
            "output_dir": output_dir,
            "activity_id": activity_id,
            "loot_id": loot_id,
        },
    )


_JOB_HANDLERS.update(
    {
        ("nmap", "scan"): _run_nmap_job,
        ("nuclei", "scan"): _run_nuclei_job,
        ("netexec", "scan"): _run_cme_job,
        ("attacker_ssh", "exec"): _run_exec_job,
        ("topology", "auto_build"): _run_topology_auto_build_job,
        ("topology", "rebuild_layout"): _run_topology_rebuild_job,
        ("httpx", "scan"): _run_httpx_job,
        ("ffuf", "scan"): _run_ffuf_job,
        ("c2", "exec"): _run_c2_exec_job,
        ("donpapi", "scan"): _run_donpapi_job,
    }
)
