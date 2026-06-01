import asyncio
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ... import models
from ...core.events import bcast
from ...core.job_runner import schedule_job_run
from ...core.job_tracker import queue_job
from ...core.utils import ts_now
from ...database import SessionLocal

from ._data import BUILTIN_PLAYBOOKS
from ._models import PlaybookRunBody, BatchRunBody
from ._validation import (
    _normalize_branch_action,
    _step_deps_zero_idx,
    _evaluate_precondition,
    _resolve_result_condition_target,
)

_PLAYBOOK_RUN_NOT_FOUND = "Playbook run not found"
_STEP_REQUIRES_TARGET = "This playbook step requires target"
_STEP_REQUIRES_TARGET_URL = "This playbook step requires target_url"


def _now() -> str:
    return ts_now()


def _resolve_next_step_index(
    step: dict, *, success: bool, current_idx: int, total_steps: int
) -> int | None:
    action = _normalize_branch_action(
        step.get("on_success") if success else step.get("on_failure"), success=success
    )
    target = step.get("on_success_step") if success else step.get("on_failure_step")
    if action == "stop":
        return None
    if action == "jump":
        if isinstance(target, int) and 1 <= target <= total_steps:
            return target - 1
        return None
    next_idx = current_idx + 1
    return next_idx if next_idx < total_steps else None


def _playbook_run_dict(run: models.PlaybookRun) -> dict:
    return {
        "id": run.id,
        "pid": run.pid,
        "playbook_id": run.playbook_id,
        "title": run.title,
        "status": run.status,
        "created_by": run.created_by,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "target": run.target,
        "error_output": run.error_output,
        "jobs_json": run.jobs_json or [],
        "request_json": run.request_json or {},
        "result_json": run.result_json or {},
    }


_ROLLUP_KEYS = [
    "hosts_found",
    "hosts_created",
    "hosts_updated",
    "hosts_pwned",
    "hosts_valid",
    "hosts_failed",
    "hosts_success",
    "findings_created",
    "findings_found",
    "creds_created",
    "paths_found",
    "urls_found",
]


def _aggregate_run_results(db: Session, job_ids: list[str]) -> dict:
    totals: dict[str, int] = {}
    if not job_ids:
        return totals
    jobs = db.query(models.Job).filter(models.Job.id.in_(job_ids)).all()
    for job in jobs:
        rj = job.result_json or {}
        for key in _ROLLUP_KEYS:
            val = rj.get(key) or (rj.get("structured", {}) or {}).get("counts", {}).get(key)
            if isinstance(val, (int, float)) and val > 0:
                totals[key] = totals.get(key, 0) + int(val)
    return totals


def _status_icon(status: str) -> str:
    if status == "done":
        return "✅"
    if status == "failed":
        return "❌"
    return "⏹"


def _job_result_terminal(result: dict) -> str:
    status = result.get("status")
    if status == "done":
        return "done"
    if status == "cancelled":
        return "cancelled"
    return "failed"


def _dag_terminal_status(cancelled_any: bool, any_failed: bool) -> str:
    if cancelled_any and not any_failed:
        return "cancelled"
    if any_failed:
        return "failed"
    return "done"


def _dispatch_run_notification(db: Session, run: models.PlaybookRun, new_status: str) -> None:
    from ...core.notifications import dispatch_sync

    batch_id = (run.request_json or {}).get("batch_id")
    event = "playbook_done" if not batch_id else "batch_done"
    icon = _status_icon(new_status)
    title = f"{icon} {'Batch' if batch_id else 'Playbook'} run {new_status}: {run.title}"
    result = run.result_json or {}
    parts = [
        f"Target: {run.target}" if run.target else None,
        f"Steps: {result.get('job_count', len(run.jobs_json or []))}",
        f"Batch: {batch_id}" if batch_id else None,
    ]
    body = "\n".join(p for p in parts if p)
    dispatch_sync(db, event, title, body, {"run_id": run.id, "pid": run.pid})


def _update_run(db: Session, run: models.PlaybookRun, **updates) -> models.PlaybookRun:
    for key, value in updates.items():
        setattr(run, key, value)
    db.commit()
    db.refresh(run)
    bcast(run.pid, "playbook_run", "update", _playbook_run_dict(run))
    new_status = updates.get("status")
    if new_status in ("done", "failed", "cancelled"):
        _dispatch_run_notification(db, run, new_status)
    return run


def _serialize_builtin(playbook: dict) -> dict:
    return {
        "id": playbook["id"],
        "title": playbook["title"],
        "description": playbook.get("description", ""),
        "editable": False,
        "source": "builtin",
        "steps": playbook.get("steps", []),
    }


def _serialize_custom(playbook: models.CustomPlaybook) -> dict:
    return {
        "id": playbook.id,
        "title": playbook.title,
        "description": playbook.description,
        "editable": True,
        "source": "custom",
        "created_by": playbook.created_by,
        "created_at": playbook.created_at,
        "updated_at": playbook.updated_at,
        "steps": playbook.steps_json or [],
    }


def _resolve_playbook(db: Session, playbook_id: str) -> dict | None:
    builtin = BUILTIN_PLAYBOOKS.get(playbook_id)
    if builtin:
        return _serialize_builtin(builtin)
    custom = db.query(models.CustomPlaybook).filter(models.CustomPlaybook.id == playbook_id).first()
    if custom:
        return _serialize_custom(custom)
    return None


def _substitute_run_vars(command: str, body: PlaybookRunBody) -> str:
    """Replace {target}/{domain}/{username}/{password}/{hash} placeholders in commands."""
    subs = {
        "{target}": body.target or "",
        "{domain}": body.domain or "",
        "{username}": body.username or "",
        "{password}": body.password or "",
        "{hash}": body.hash or "",
    }
    for k, v in subs.items():
        command = command.replace(k, v)
    return command


def _spec_topology(pid: str, params: dict, body: PlaybookRunBody, created_by: str, title: str, operation: str) -> dict:
    if operation not in {"auto_build", "rebuild_layout"}:
        raise HTTPException(400, f"Unsupported topology operation: {operation}")
    return {
        "job_type": "topology",
        "title": title,
        "connector_key": "topology",
        "operation": operation,
        "related_entity_type": "network",
        "related_entity_id": pid,
        "request_json": {
            "keep_manual_positions": params.get(
                "keep_manual_positions", body.keep_manual_positions
            ),
            "create_missing_networks": params.get(
                "create_missing_networks", body.create_missing_networks
            ),
        },
        "created_by": created_by,
    }


def _spec_nmap_scan(pid: str, params: dict, body: PlaybookRunBody, created_by: str, title: str, **_kw) -> dict:
    target = (params.get("target") or body.target or "").strip()
    if not target:
        raise HTTPException(400, _STEP_REQUIRES_TARGET)
    flags = params.get("flags") or body.flags
    target_id = params.get("target_id") or body.target_id
    timeout_seconds = int(params.get("timeout_seconds") or 180)
    return {
        "job_type": "nmap",
        "title": f"{title}: {target}",
        "target": target,
        "command": f"nmap {flags} -oX - {target} 2>/dev/null",
        "connector_key": "nmap",
        "operation": "scan",
        "related_entity_type": "project",
        "related_entity_id": pid,
        "request_json": {
            "target": target,
            "flags": flags,
            "target_id": target_id,
            "timeout_seconds": timeout_seconds,
        },
        "created_by": created_by,
    }


def _spec_nuclei_scan(pid: str, params: dict, body: PlaybookRunBody, created_by: str, title: str, **_kw) -> dict:
    target_url = (params.get("target_url") or body.target_url or "").strip()
    if not target_url:
        raise HTTPException(400, _STEP_REQUIRES_TARGET_URL)
    severity = params.get("severity") or body.severity
    target_id = params.get("target_id") or body.target_id
    timeout_seconds = int(params.get("timeout_seconds") or 300)
    templates = params.get("templates") or ""
    extra_flags = params.get("extra_flags") or ""
    return {
        "job_type": "nuclei",
        "title": f"{title}: {target_url}",
        "target": target_url,
        "command": f"nuclei -u {target_url} -severity {severity} -jsonl {extra_flags} 2>/dev/null",
        "connector_key": "nuclei",
        "operation": "scan",
        "related_entity_type": "project",
        "related_entity_id": pid,
        "request_json": {
            "target": target_url,
            "severity": severity,
            "target_id": target_id,
            "timeout_seconds": timeout_seconds,
            "templates": templates,
            "extra_flags": extra_flags,
        },
        "created_by": created_by,
    }


def _spec_netexec_scan(pid: str, params: dict, body: PlaybookRunBody, created_by: str, title: str, **_kw) -> dict:
    target = (params.get("target") or body.target or "").strip()
    if not target:
        raise HTTPException(400, _STEP_REQUIRES_TARGET)
    protocol = params.get("protocol") or "smb"
    extra_flags = params.get("extra_flags") or "--users --groups"
    timeout_seconds = int(params.get("timeout_seconds") or 120)
    username = params.get("username") or body.username or ""
    password = params.get("password") or body.password or ""
    domain = params.get("domain") or body.domain or ""
    hash_ = params.get("hash") or body.hash or ""
    return {
        "job_type": "cme",
        "title": f"{title}: {target}",
        "target": target,
        "command": f"nxc {protocol} {target} {extra_flags} 2>/dev/null",
        "connector_key": "netexec",
        "operation": "scan",
        "related_entity_type": "project",
        "related_entity_id": pid,
        "request_json": {
            "target": target,
            "protocol": protocol,
            "extra_flags": extra_flags,
            "target_id": params.get("target_id") or body.target_id,
            "timeout_seconds": timeout_seconds,
            "username": username,
            "password": password,
            "domain": domain,
            "hash": hash_,
        },
        "created_by": created_by,
    }


def _spec_attacker_ssh_exec(pid: str, params: dict, body: PlaybookRunBody, created_by: str, title: str, **_kw) -> dict:
    raw_command = (params.get("command") or "").strip()
    if not raw_command:
        raise HTTPException(400, "This playbook step requires command")
    command = _substitute_run_vars(raw_command, body)
    return {
        "job_type": "exec",
        "title": title,
        "target": params.get("target") or body.target or "",
        "command": command,
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "related_entity_type": params.get("related_entity_type") or "project",
        "related_entity_id": params.get("related_entity_id") or pid,
        "request_json": {
            "command": command,
            "snippet_title": title,
            "host_id": params.get("host_id"),
            "cred_id": params.get("cred_id"),
            "target_id": params.get("target_id") or body.target_id,
            "execution_mode": params.get("execution_mode") or "auto",
            "timeout_seconds": int(params.get("timeout_seconds") or 45),
            "activity_type": params.get("activity_type") or "postex",
        },
        "created_by": created_by,
    }


def _spec_donpapi_scan(pid: str, params: dict, body: PlaybookRunBody, created_by: str, title: str, **_kw) -> dict:
    target = (params.get("target") or body.target or "").strip()
    if not target:
        raise HTTPException(400, _STEP_REQUIRES_TARGET)
    username = params.get("username") or body.username or ""
    password = params.get("password") or body.password or ""
    nthash = params.get("nthash") or params.get("hash") or body.hash or ""
    domain = params.get("domain") or body.domain or ""
    cred_id = params.get("cred_id") or ""
    if not cred_id and not username:
        raise HTTPException(400, "donpapi step requires cred_id or username")
    if not cred_id and not (password or nthash):
        raise HTTPException(400, "donpapi step requires password or nthash (or cred_id)")
    timeout_seconds = int(params.get("timeout_seconds") or 600)
    return {
        "job_type": "donpapi",
        "title": f"{title}: {target}",
        "target": target,
        "command": f"donpapi collect -t {target} ...",
        "connector_key": "donpapi",
        "operation": "scan",
        "related_entity_type": "project",
        "related_entity_id": pid,
        "request_json": {
            "target": target,
            "username": username,
            "domain": domain,
            "cred_id": cred_id,
            "password": password,
            "nthash": nthash,
            "extra_flags": params.get("extra_flags") or "",
            "fetch_loot": bool(params.get("fetch_loot", True)),
            "timeout_seconds": timeout_seconds,
            "target_id": params.get("target_id") or body.target_id,
        },
        "created_by": created_by,
    }


def _spec_httpx_scan(pid: str, params: dict, body: PlaybookRunBody, created_by: str, title: str, **_kw) -> dict:
    target = (params.get("target") or body.target or "").strip()
    if not target:
        raise HTTPException(400, _STEP_REQUIRES_TARGET)
    flags = params.get("flags") or "-title -status-code -tech-detect -follow-redirects"
    timeout_seconds = int(params.get("timeout_seconds") or 120)
    return {
        "job_type": "httpx",
        "title": f"{title}: {target}",
        "target": target,
        "command": f"httpx -u '{target}' {flags} -json -silent 2>/dev/null",
        "connector_key": "httpx",
        "operation": "scan",
        "related_entity_type": "project",
        "related_entity_id": pid,
        "request_json": {
            "target": target,
            "flags": flags,
            "target_id": params.get("target_id") or body.target_id,
            "timeout_seconds": timeout_seconds,
        },
        "created_by": created_by,
    }


def _validate_c2_required_params(integration_id: str, agent_id: str, host_id: str, commandline: str) -> None:
    if not integration_id:
        raise HTTPException(400, "c2:exec step requires integration_id")
    if not agent_id:
        raise HTTPException(400, "c2:exec step requires agent_id")
    if not host_id:
        raise HTTPException(400, "c2:exec step requires host_id")
    if not commandline:
        raise HTTPException(400, "c2:exec step requires commandline")


def _spec_c2_exec(pid: str, params: dict, body: PlaybookRunBody, created_by: str, title: str, **_kw) -> dict:
    integration_id = (params.get("integration_id") or "").strip()
    agent_id = (params.get("agent_id") or "").strip()
    host_id = (params.get("host_id") or "").strip()
    commandline = (params.get("commandline") or "").strip()
    _validate_c2_required_params(integration_id, agent_id, host_id, commandline)
    commandline = _substitute_run_vars(commandline, body)
    mode = params.get("mode") or "command"
    if mode not in ("command", "bof"):
        raise HTTPException(400, f"c2:exec mode must be command|bof, got: {mode}")
    return {
        "job_type": "c2_exec",
        "title": params.get("title") or title,
        "target": params.get("target") or host_id,
        "command": commandline,
        "connector_key": "c2",
        "operation": "exec",
        "related_entity_type": "host",
        "related_entity_id": host_id,
        "request_json": {
            "integration_id": integration_id,
            "agent_id": agent_id,
            "host_id": host_id,
            "commandline": commandline,
            "mode": mode,
            "credential_source": params.get("credential_source") or "rootnotes",
            "credential_id": params.get("credential_id") or "",
            "wait_for_output": bool(params.get("wait_for_output", True)),
            "timeout_seconds": int(params.get("timeout_seconds") or 12),
            "title": params.get("title") or title,
        },
        "created_by": created_by,
    }


def _spec_ffuf_scan(pid: str, params: dict, body: PlaybookRunBody, created_by: str, title: str, **_kw) -> dict:
    target_url = (params.get("target_url") or body.target_url or "").strip()
    if not target_url:
        raise HTTPException(400, _STEP_REQUIRES_TARGET_URL)
    wordlist = params.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/common.txt"
    extensions = params.get("extensions") or ""
    flags = params.get("flags") or "-mc 200,204,301,302,307,401,403,405"
    timeout_seconds = int(params.get("timeout_seconds") or 300)
    ext_flag = f"-e {extensions}" if extensions.strip() else ""
    url = f"{target_url}/FUZZ"
    cmd = f"ffuf -u '{url}' -w '{wordlist}' {ext_flag} {flags} -o /tmp/ffuf_out.json -of json -s 2>/dev/null && cat /tmp/ffuf_out.json"
    return {
        "job_type": "ffuf",
        "title": f"{title}: {target_url}",
        "target": target_url,
        "command": cmd,
        "connector_key": "ffuf",
        "operation": "scan",
        "related_entity_type": "project",
        "related_entity_id": pid,
        "request_json": {
            "target_url": target_url,
            "wordlist": wordlist,
            "extensions": extensions,
            "flags": flags,
            "target_id": params.get("target_id") or body.target_id,
            "timeout_seconds": timeout_seconds,
        },
        "created_by": created_by,
    }


_SPEC_DISPATCH = {
    ("topology", "auto_build"): _spec_topology,
    ("topology", "rebuild_layout"): _spec_topology,
    ("nmap", "scan"): _spec_nmap_scan,
    ("nuclei", "scan"): _spec_nuclei_scan,
    ("netexec", "scan"): _spec_netexec_scan,
    ("attacker_ssh", "exec"): _spec_attacker_ssh_exec,
    ("donpapi", "scan"): _spec_donpapi_scan,
    ("httpx", "scan"): _spec_httpx_scan,
    ("c2", "exec"): _spec_c2_exec,
    ("ffuf", "scan"): _spec_ffuf_scan,
}


def _job_spec_for_step(pid: str, step: dict, body: PlaybookRunBody, created_by: str) -> dict:
    connector_key = step.get("connector_key")
    operation = step.get("operation")
    params = dict(step.get("params") or {})
    title = step.get("title") or f"{connector_key}:{operation}"
    handler = _SPEC_DISPATCH.get((connector_key, operation))
    if not handler:
        raise HTTPException(400, f"Unsupported playbook step: {connector_key}:{operation}")
    return handler(pid, params, body, created_by, title, operation=operation)


def _upsert_run_job_state(db: Session, run_id: str, job_id: str, status: str) -> None:
    run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
    if not run:
        return
    jobs_json = list(run.jobs_json or [])
    changed = False
    for item in jobs_json:
        if item.get("id") == job_id:
            item["status"] = status
            changed = True
            break
    if changed:
        _update_run(db, run, jobs_json=jobs_json)


async def _wait_for_job(job_id: str, run_id: str | None = None) -> dict:
    while True:
        await asyncio.sleep(1)
        db = SessionLocal()
        try:
            job = db.query(models.Job).filter(models.Job.id == job_id).first()
            if not job:
                return {"status": "missing"}
            if run_id:
                _upsert_run_job_state(db, run_id, job_id, job.status)
            if job.status in ("done", "failed", "cancelled"):
                return {
                    "status": job.status,
                    "id": job.id,
                    "result_json": job.result_json or {},
                    "error_output": job.error_output or "",
                }
        finally:
            db.close()


def _seq_build_result(completed: list, failed: list, **extra) -> dict:
    return {
        "completed_jobs": [item.get("id") for item in completed],
        "failed_jobs": [item.get("id") for item in failed],
        "rollup": extra.pop("rollup", None) or {},
        **extra,
    }


def _seq_rollup(db: Session, completed: list) -> dict:
    return _aggregate_run_results(db, [i.get("id") for i in completed if i.get("id")])


def _seq_apply_terminal(run_id: str, status: str, error_output: str = "", result_json: dict | None = None) -> None:
    db = SessionLocal()
    try:
        run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
        if run and run.status != "cancelled":
            _update_run(db, run, status=status, finished_at=_now(), error_output=error_output, result_json=result_json or {})
    finally:
        db.close()


def _seq_process_step_result(
    run_id: str, job_id: str, step: dict, result: dict,
    completed: list, failed: list, idx: int, total_steps: int, db,
) -> tuple[int | None, bool]:
    completed.append(result)
    condition_idx, condition_stop = _resolve_result_condition_target(
        step, result or {}, status=result.get("status"), total_steps=total_steps
    )
    if condition_stop:
        terminal = _job_result_terminal(result)
        rollup = _seq_rollup(db, completed) if db else {}
        _seq_apply_terminal(run_id, terminal, result_json=_seq_build_result(
            completed, failed, job_count=len(completed), condition_stop=True, rollup=rollup,
        ))
        return None, True
    if condition_idx is not None:
        return condition_idx, False
    if result.get("status") != "done":
        failed.append(result)
        next_idx = _resolve_next_step_index(
            step, success=False, current_idx=idx, total_steps=total_steps
        )
        if next_idx is not None:
            return next_idx, False
        terminal = "cancelled" if result.get("status") == "cancelled" else "failed"
        rollup = _seq_rollup(db, completed) if db else {}
        _seq_apply_terminal(
            run_id, terminal,
            error_output=f"Step job {job_id} ended with status {result.get('status')}",
            result_json=_seq_build_result(completed, failed, failed_job_id=job_id, rollup=rollup),
        )
        return None, True
    next_idx = _resolve_next_step_index(
        step, success=True, current_idx=idx, total_steps=total_steps
    )
    if next_idx is None:
        rollup = _seq_rollup(db, completed) if db else {}
        _seq_apply_terminal(run_id, "done", result_json=_seq_build_result(
            completed, failed, job_count=len(completed), rollup=rollup,
        ))
        return None, True
    return next_idx, False


async def _run_sequence(run_id: str, job_ids: list[str], steps: list[dict]) -> None:
    db = SessionLocal()
    try:
        run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
        if not run:
            return
        _update_run(db, run, status="running", started_at=run.started_at or _now())
    finally:
        db.close()

    completed = []
    failed = []
    total_steps = len(job_ids)
    idx = 0
    while idx < total_steps:
        job_id = job_ids[idx]
        step = steps[idx] if idx < len(steps) else {}
        db = SessionLocal()
        run_pid = ""
        try:
            run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
            if not run or run.status == "cancelled":
                return
            run_pid = run.pid
        finally:
            db.close()

        schedule_job_run(job_id, pid=run_pid)
        result = await _wait_for_job(job_id, run_id)
        next_idx, should_exit = _seq_process_step_result(
            run_id, job_id, step, result, completed, failed, idx, total_steps, db
        )
        if should_exit:
            return
        if next_idx is not None:
            idx = next_idx
            continue
        break


def _queue_single_step(
    db: Session,
    pid: str,
    playbook_id: str,
    step: dict,
    body: PlaybookRunBody,
    created_by: str,
    run_id: str,
    *,
    step_idx: int,
    attempt: int,
) -> models.Job:
    spec = _job_spec_for_step(pid, step, body, created_by)
    request_json = {
        **spec.get("request_json", {}),
        "playbook_id": playbook_id,
        "playbook_run_id": run_id,
        "step_idx": step_idx,
        "attempt": attempt,
    }
    return queue_job(
        db,
        pid,
        spec["job_type"],
        spec["title"],
        target=spec.get("target", ""),
        command=spec.get("command", ""),
        created_by=spec.get("created_by", ""),
        connector_key=spec["connector_key"],
        operation=spec["operation"],
        related_entity=(spec.get("related_entity_type", "project"), spec.get("related_entity_id", pid)),
        request_json=request_json,
    )


def _append_run_job(run_id: str, job: models.Job, step_idx: int, attempt: int) -> None:
    db = SessionLocal()
    try:
        run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
        if not run:
            return
        jobs_json = list(run.jobs_json or [])
        jobs_json.append(
            {
                "id": job.id,
                "title": job.title,
                "status": job.status,
                "step_idx": step_idx,
                "attempt": attempt,
            }
        )
        _update_run(db, run, jobs_json=jobs_json)
    finally:
        db.close()


def _dag_finalize(run_id: str, state: dict[int, dict]) -> None:
    completed = [s["job_id"] for s in state.values() if s["final_status"] == "done" and s["job_id"]]
    failed_jobs = [
        s["job_id"] for s in state.values() if s["final_status"] == "failed" and s["job_id"]
    ]
    cancelled_any = any(s["final_status"] == "cancelled" for s in state.values())
    any_failed = bool(failed_jobs)
    db = SessionLocal()
    try:
        run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
        if not run or run.status == "cancelled":
            return
        terminal = _dag_terminal_status(cancelled_any, any_failed)
        _update_run(
            db,
            run,
            status=terminal,
            finished_at=_now(),
            error_output="" if terminal == "done" else f"{len(failed_jobs)} step(s) failed",
            result_json={
                "completed_jobs": completed,
                "failed_jobs": failed_jobs,
                "step_states": {
                    str(i): {
                        "status": s["final_status"],
                        "attempts": s["attempts"],
                        "job_id": s["job_id"],
                    }
                    for i, s in state.items()
                },
                "dag_mode": True,
                "rollup": _aggregate_run_results(db, completed),
            },
        )
    finally:
        db.close()


def _dag_try_launch(steps: list[dict], state: dict[int, dict], n: int, _run_one_step) -> dict[asyncio.Task, int]:
    def _dep_status_ok(i: int) -> bool:
        deps = _step_deps_zero_idx(steps[i])
        return all(state[d]["status"] in ("done", "skipped", "failed") for d in deps)

    def _should_skip_from_dep_failure(i: int) -> bool:
        deps = _step_deps_zero_idx(steps[i])
        any_failed = any(state[d]["final_status"] == "failed" for d in deps)
        if not any_failed:
            return False
        return _normalize_branch_action(steps[i].get("on_failure"), success=False) != "next"

    launched: dict[asyncio.Task, int] = {}
    for i in range(n):
        if state[i]["status"] != "pending":
            continue
        if not _dep_status_ok(i):
            continue
        if _should_skip_from_dep_failure(i):
            state[i]["status"] = "skipped"
            state[i]["final_status"] = "skipped"
            continue
        deps = _step_deps_zero_idx(steps[i])
        pre = steps[i].get("precondition")
        if pre and not _evaluate_precondition(pre, state, deps):
            state[i]["status"] = "skipped"
            state[i]["final_status"] = "skipped"
            continue
        state[i]["status"] = "running"
        task = asyncio.create_task(_run_one_step(i))
        launched[task] = i
    return launched



def _queue_and_wait_step(
    idx: int, step: dict, state: dict, run_id: str, pid: str,
    playbook: dict, body: PlaybookRunBody, created_by: str, attempt: int,
) -> str:
    db = SessionLocal()
    try:
        job = _queue_single_step(
            db, pid, playbook["id"], step, body, created_by, run_id,
            step_idx=idx, attempt=attempt,
        )
    finally:
        db.close()
    _append_run_job(run_id, job, idx, attempt)
    state[idx]["job_id"] = job.id

    db = SessionLocal()
    try:
        run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
        if not run or run.status == "cancelled":
            state[idx]["status"] = "cancelled"
            state[idx]["final_status"] = "cancelled"
            return "cancelled"
    finally:
        db.close()

    schedule_job_run(job.id, pid=pid)
    return job.id

def _parse_step_retry_config(step: dict) -> tuple[int, int, set[str]]:
    return (
        int(step.get("retry_count") or 0),
        int(step.get("retry_delay_seconds") or 0),
        set(step.get("retry_on") or ["failed"]),
    )


def _set_step_terminal(state: dict, idx: int, status: str) -> None:
    state[idx]["status"] = status
    state[idx]["final_status"] = status


async def _dag_run_one_step(
    idx: int, steps: list, state: dict, run_id: str, pid: str,
    playbook: dict, body: PlaybookRunBody, created_by: str,
) -> None:
    step = steps[idx]
    retry_count, retry_delay, retry_on = _parse_step_retry_config(step)
    attempts_max = retry_count + 1
    last_status = "failed"
    for attempt in range(1, attempts_max + 1):
        state[idx]["attempts"] = attempt
        job_id = _queue_and_wait_step(idx, step, state, run_id, pid, playbook, body, created_by, attempt)
        if state[idx]["status"] == "cancelled":
            return

        job = type("JobRef", (), {"id": job_id})()
        result = await _wait_for_job(job.id, run_id)
        last_status = result.get("status") or "failed"
        state[idx]["result_json"] = result.get("result_json") or {}

        if last_status == "done":
            _set_step_terminal(state, idx, "done")
            return
        if last_status in retry_on and attempt < attempts_max:
            if retry_delay > 0:
                await asyncio.sleep(retry_delay)
            continue
        break

    _set_step_terminal(state, idx, "cancelled" if last_status == "cancelled" else "failed")


async def _run_dag(
    run_id: str,
    pid: str,
    playbook: dict,
    body: PlaybookRunBody,
    created_by: str,
) -> None:
    """DAG-aware playbook runner with retry + precondition support.

    States per step: pending → running → done|failed|skipped|cancelled.
    A step becomes ready when every dependency is in {done, skipped, failed}.
    If any dep failed and the step does not opt into running anyway (on_failure='next'),
    the step is marked skipped (failure propagation).
    """
    steps = playbook.get("steps", [])
    n = len(steps)

    db = SessionLocal()
    try:
        run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
        if not run:
            return
        _update_run(db, run, status="running", started_at=run.started_at or _now())
    finally:
        db.close()

    state: dict[int, dict] = {
        i: {
            "status": "pending",
            "result_json": None,
            "job_id": None,
            "attempts": 0,
            "final_status": None,
        }
        for i in range(n)
    }

    async def _step(i: int) -> None:
        await _dag_run_one_step(i, steps, state, run_id, pid, playbook, body, created_by)

    running_tasks: dict[asyncio.Task, int] = {}
    while True:
        db = SessionLocal()
        try:
            run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
            if not run:
                return
            if run.status == "cancelled":
                for t in running_tasks:
                    t.cancel()
                return
        finally:
            db.close()

        newly_launched = _dag_try_launch(steps, state, n, _step)
        running_tasks.update(newly_launched)

        if not running_tasks:
            break

        done_tasks, _pending = await asyncio.wait(
            list(running_tasks.keys()), return_when=asyncio.FIRST_COMPLETED
        )
        for t in done_tasks:
            running_tasks.pop(t, None)

    _dag_finalize(run_id, state)


def _create_run_record(
    db: Session,
    pid: str,
    playbook: dict,
    body: PlaybookRunBody,
    created_by: str,
    jobs: list[models.Job],
) -> models.PlaybookRun:
    run = models.PlaybookRun(
        id=f"pbr_{uuid4().hex[:10]}",
        pid=pid,
        playbook_id=playbook["id"],
        title=playbook["title"],
        status="queued",
        created_by=created_by,
        created_at=_now(),
        started_at="",
        finished_at="",
        target=body.target.strip() or body.target_url.strip(),
        error_output="",
        jobs_json=[{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
        request_json=body.model_dump(),
        result_json={},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
    return run


def _queue_playbook_jobs(
    db: Session,
    pid: str,
    playbook: dict,
    body: PlaybookRunBody,
    created_by: str,
    run_id: str | None = None,
) -> list[models.Job]:
    jobs = []
    for step in playbook.get("steps", []):
        spec = _job_spec_for_step(pid, step, body, created_by)
        jobs.append(
            queue_job(
                db,
                pid,
                spec["job_type"],
                spec["title"],
                target=spec.get("target", ""),
                command=spec.get("command", ""),
                created_by=spec.get("created_by", ""),
                connector_key=spec["connector_key"],
                operation=spec["operation"],
                related_entity=(spec.get("related_entity_type", "project"), spec.get("related_entity_id", pid)),
                request_json={
                    **spec.get("request_json", {}),
                    "playbook_id": playbook["id"],
                    **({"playbook_run_id": run_id} if run_id else {}),
                },
            )
        )
    return jobs


def _resolve_batch_hosts(db: Session, pid: str, body: BatchRunBody) -> list:
    q = db.query(models.Host).filter(models.Host.pid == pid, ~models.Host.is_attacker)
    if body.host_ids:
        q = q.filter(models.Host.id.in_(body.host_ids))
    else:
        if body.host_tags:
            q = q.filter(models.Host.tags.overlap(body.host_tags))
        if body.host_status:
            q = q.filter(models.Host.status == body.host_status)
    return q.all()


def _launch_playbook_run(
    pid: str, playbook_id: str, body_dict: dict, created_by: str = "scheduler"
) -> str | None:
    """
    Launch a playbook run without an HTTP request context.
    Used by the cron scheduler. Returns the run ID or None on failure.
    """
    from ...database import SessionLocal

    db = SessionLocal()
    try:
        playbook = _resolve_playbook(db, playbook_id)
        if not playbook:
            return None
        body = PlaybookRunBody(
            **{k: v for k, v in body_dict.items() if k in PlaybookRunBody.model_fields}
        )
        provisional_run_id = f"pbr_{uuid4().hex[:10]}"
        jobs = _queue_playbook_jobs(db, pid, playbook, body, created_by, provisional_run_id)
        run = models.PlaybookRun(
            id=provisional_run_id,
            pid=pid,
            playbook_id=playbook["id"],
            title=playbook["title"],
            status="queued",
            created_by=created_by,
            created_at=_now(),
            started_at="",
            finished_at="",
            target=body.target.strip() or body.target_url.strip(),
            error_output="",
            jobs_json=[{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
            request_json=body_dict,
            result_json={},
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
        _task = asyncio.create_task(
            _run_sequence(run.id, [job.id for job in jobs], playbook.get("steps", []))
        )
        return run.id
    except Exception as e:
        import logging

        logging.getLogger(__name__).warning("[scheduler] _launch_playbook_run failed: %s", e)
        return None
    finally:
        db.close()
