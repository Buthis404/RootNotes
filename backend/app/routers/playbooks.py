import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast
from ..core.job_runner import schedule_job_run
from ..core.job_tracker import queue_job
from ..core.utils import new_id
from ..database import SessionLocal, get_db
from ..plugins.registry import registry

router = APIRouter(tags=["playbooks"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class PlaybookStepBody(BaseModel):
    title: str
    connector_key: str
    operation: str
    params: dict = Field(default_factory=dict)
    on_failure: str = "stop"  # stop | continue


class PlaybookBody(BaseModel):
    title: str
    description: str = ""
    steps: list[PlaybookStepBody] = Field(default_factory=list)


class PlaybookRunBody(BaseModel):
    target: str = ""
    target_url: str = ""
    target_id: str | None = None
    flags: str = "-sV -sC -T4 --open"
    severity: str = "critical,high,medium"
    keep_manual_positions: bool = True
    create_missing_networks: bool = True


STEP_TEMPLATES = {
    "topology:auto_build": {
        "id": "topology:auto_build",
        "title": "Topology Auto-Build",
        "connector_key": "topology",
        "operation": "auto_build",
        "description": "Build or refresh the network graph from known hosts.",
        "fields": [
            {"key": "keep_manual_positions", "label": "Keep manual positions", "type": "boolean", "default": True},
            {"key": "create_missing_networks", "label": "Create missing networks", "type": "boolean", "default": True},
        ],
    },
    "topology:rebuild_layout": {
        "id": "topology:rebuild_layout",
        "title": "Topology Rebuild Layout",
        "connector_key": "topology",
        "operation": "rebuild_layout",
        "description": "Recompute node positions for the current map.",
        "fields": [
            {"key": "keep_manual_positions", "label": "Keep manual positions", "type": "boolean", "default": True},
        ],
    },
    "nmap:scan": {
        "id": "nmap:scan",
        "title": "Nmap Scan",
        "connector_key": "nmap",
        "operation": "scan",
        "description": "Network discovery and service fingerprinting.",
        "fields": [
            {"key": "target", "label": "Target", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "flags", "label": "Flags", "type": "text", "default": "-sV -sC -T4 --open"},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 180},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "nuclei:scan": {
        "id": "nuclei:scan",
        "title": "Nuclei Scan",
        "connector_key": "nuclei",
        "operation": "scan",
        "description": "Template-based vulnerability scan for a URL.",
        "fields": [
            {"key": "target_url", "label": "Target URL", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "severity", "label": "Severity", "type": "text", "default": "critical,high,medium"},
            {"key": "templates", "label": "Templates path", "type": "text", "default": ""},
            {"key": "extra_flags", "label": "Extra flags", "type": "text", "default": ""},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 300},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "netexec:scan": {
        "id": "netexec:scan",
        "title": "NetExec Scan",
        "connector_key": "netexec",
        "operation": "scan",
        "description": "Credential-aware internal enumeration.",
        "fields": [
            {"key": "target", "label": "Target", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "protocol", "label": "Protocol", "type": "select", "options": ["smb", "winrm", "rdp", "ldap", "mssql"], "default": "smb"},
            {"key": "extra_flags", "label": "Extra flags", "type": "text", "default": "--users --groups"},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 120},
            {"key": "username", "label": "Username", "type": "text", "default": ""},
            {"key": "password", "label": "Password", "type": "text", "default": ""},
            {"key": "domain", "label": "Domain", "type": "text", "default": ""},
            {"key": "hash", "label": "Hash", "type": "text", "default": ""},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "attacker_ssh:exec": {
        "id": "attacker_ssh:exec",
        "title": "Attacker SSH Exec",
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "description": "Execute a command from the attacker box.",
        "fields": [
            {"key": "command", "label": "Command", "type": "textarea", "default": "", "required": True},
            {"key": "execution_mode", "label": "Execution mode", "type": "select", "options": ["auto", "project", "global"], "default": "auto"},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 45},
            {"key": "activity_type", "label": "Activity type", "type": "text", "default": "postex"},
            {"key": "host_id", "label": "Host id", "type": "text", "default": ""},
            {"key": "cred_id", "label": "Cred id", "type": "text", "default": ""},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
}


def _template_for(connector_key: str, operation: str) -> dict | None:
    return STEP_TEMPLATES.get(f"{connector_key}:{operation}")


def _normalize_field_value(field: dict, value):
    if field.get("type") == "number":
        try:
            return int(value)
        except Exception:
            return field.get("default", 0)
    if field.get("type") == "boolean":
        return bool(value)
    return "" if value is None else value


def _validate_playbook_payload(body: PlaybookBody, available_connectors: list[dict]) -> dict:
    errors = []
    warnings = []
    connector_map = {item["key"]: item for item in available_connectors}

    if not body.title.strip():
        errors.append("Title is required")
    if not body.steps:
        errors.append("At least one step is required")

    normalized_steps = []
    for idx, step in enumerate(body.steps):
        prefix = f"Step {idx + 1}"
        if not step.title.strip():
            errors.append(f"{prefix}: title is required")
        connector = connector_map.get(step.connector_key)
        if not connector:
            errors.append(f"{prefix}: unsupported connector {step.connector_key!r}")
            continue
        if step.operation not in (connector.get("supported_operations") or []):
            errors.append(f"{prefix}: unsupported operation {step.operation!r} for connector {step.connector_key!r}")
            continue
        if step.on_failure not in {"stop", "continue"}:
            errors.append(f"{prefix}: on_failure must be 'stop' or 'continue'")

        template = _template_for(step.connector_key, step.operation)
        params = dict(step.params or {})
        if template:
          allowed = {field["key"]: field for field in template.get("fields", [])}
          unknown = [key for key in params.keys() if key not in allowed]
          if unknown:
              warnings.append(f"{prefix}: unknown params will be ignored: {', '.join(sorted(unknown))}")
          normalized_params = {}
          for key, field in allowed.items():
              value = params.get(key, field.get("default"))
              if field.get("required") and str(value).strip() == "":
                  errors.append(f"{prefix}: field {key!r} is required")
              if (not field.get("runtime_fallback")) and field.get("type") == "text" and field.get("required", False) is False and key in params and value == "":
                  pass
              normalized_params[key] = _normalize_field_value(field, value)
          params = normalized_params
        normalized_steps.append({
            "title": step.title.strip(),
            "connector_key": step.connector_key,
            "operation": step.operation,
            "params": params,
            "on_failure": step.on_failure,
        })

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "normalized": {
            "title": body.title.strip(),
            "description": body.description.strip(),
            "steps": normalized_steps,
        },
    }


BUILTIN_PLAYBOOKS = {
    "topology-refresh": {
        "id": "topology-refresh",
        "title": "Topology Refresh",
        "description": "Rebuild the operational graph from all known hosts.",
        "editable": False,
        "steps": [
            {"title": "Topology auto-build", "connector_key": "topology", "operation": "auto_build", "params": {}, "on_failure": "stop"},
        ],
    },
    "internal-recon": {
        "id": "internal-recon",
        "title": "Internal Recon",
        "description": "Run an Nmap scan and then refresh topology from discovered hosts.",
        "editable": False,
        "steps": [
            {"title": "Nmap scan", "connector_key": "nmap", "operation": "scan", "params": {}, "on_failure": "stop"},
            {"title": "Topology auto-build", "connector_key": "topology", "operation": "auto_build", "params": {}, "on_failure": "continue"},
        ],
    },
    "web-triage": {
        "id": "web-triage",
        "title": "Web Triage",
        "description": "Run a Nuclei scan against a supplied target URL.",
        "editable": False,
        "steps": [
            {"title": "Nuclei scan", "connector_key": "nuclei", "operation": "scan", "params": {}, "on_failure": "stop"},
        ],
    },
}


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


def _update_run(db: Session, run: models.PlaybookRun, **updates) -> models.PlaybookRun:
    for key, value in updates.items():
        setattr(run, key, value)
    db.commit()
    db.refresh(run)
    bcast(run.pid, "playbook_run", "update", _playbook_run_dict(run))
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


def _job_spec_for_step(pid: str, step: dict, body: PlaybookRunBody, created_by: str) -> dict:
    connector_key = step.get("connector_key")
    operation = step.get("operation")
    params = dict(step.get("params") or {})
    title = step.get("title") or f"{connector_key}:{operation}"

    if connector_key == "topology":
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
                "keep_manual_positions": params.get("keep_manual_positions", body.keep_manual_positions),
                "create_missing_networks": params.get("create_missing_networks", body.create_missing_networks),
            },
            "created_by": created_by,
        }

    if connector_key == "nmap" and operation == "scan":
        target = (params.get("target") or body.target or "").strip()
        if not target:
            raise HTTPException(400, "This playbook step requires target")
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
            "request_json": {"target": target, "flags": flags, "target_id": target_id, "timeout_seconds": timeout_seconds},
            "created_by": created_by,
        }

    if connector_key == "nuclei" and operation == "scan":
        target_url = (params.get("target_url") or body.target_url or "").strip()
        if not target_url:
            raise HTTPException(400, "This playbook step requires target_url")
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
            "request_json": {"target": target_url, "severity": severity, "target_id": target_id, "timeout_seconds": timeout_seconds, "templates": templates, "extra_flags": extra_flags},
            "created_by": created_by,
        }

    if connector_key == "netexec" and operation == "scan":
        target = (params.get("target") or body.target or "").strip()
        if not target:
            raise HTTPException(400, "This playbook step requires target")
        protocol = params.get("protocol") or "smb"
        extra_flags = params.get("extra_flags") or "--users --groups"
        timeout_seconds = int(params.get("timeout_seconds") or 120)
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
                "username": params.get("username") or "",
                "password": params.get("password") or "",
                "domain": params.get("domain") or "",
                "hash": params.get("hash") or "",
            },
            "created_by": created_by,
        }

    if connector_key == "attacker_ssh" and operation == "exec":
        command = (params.get("command") or "").strip()
        if not command:
            raise HTTPException(400, "This playbook step requires command")
        return {
            "job_type": "exec",
            "title": title,
            "target": params.get("target") or "",
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

    raise HTTPException(400, f"Unsupported playbook step: {connector_key}:{operation}")


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
                return {"status": job.status, "id": job.id}
        finally:
            db.close()


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
    for idx, job_id in enumerate(job_ids):
        db = SessionLocal()
        try:
            run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
            if not run or run.status == "cancelled":
                return
        finally:
            db.close()

        schedule_job_run(job_id)
        result = await _wait_for_job(job_id, run_id)
        completed.append(result)
        if result.get("status") != "done":
            on_failure = (steps[idx] or {}).get("on_failure", "stop")
            if on_failure == "continue":
                continue
            db = SessionLocal()
            try:
                run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
                if run and run.status != "cancelled":
                    terminal = "cancelled" if result.get("status") == "cancelled" else "failed"
                    _update_run(
                        db,
                        run,
                        status=terminal,
                        finished_at=_now(),
                        error_output=f"Step job {job_id} ended with status {result.get('status')}",
                        result_json={"completed_jobs": [item.get("id") for item in completed], "failed_job_id": job_id},
                    )
            finally:
                db.close()
            break
    else:
        db = SessionLocal()
        try:
            run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
            if run and run.status != "cancelled":
                _update_run(
                    db,
                    run,
                    status="done",
                    finished_at=_now(),
                    result_json={"completed_jobs": [item.get("id") for item in completed], "job_count": len(completed)},
                )
        finally:
            db.close()


def _create_run_record(db: Session, pid: str, playbook: dict, body: PlaybookRunBody, created_by: str, jobs: list[models.Job]) -> models.PlaybookRun:
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


def _queue_playbook_jobs(db: Session, pid: str, playbook: dict, body: PlaybookRunBody, created_by: str, run_id: str | None = None) -> list[models.Job]:
    jobs = []
    for step in playbook.get("steps", []):
        spec = _job_spec_for_step(pid, step, body, created_by)
        jobs.append(queue_job(
            db,
            pid,
            spec["job_type"],
            spec["title"],
            target=spec.get("target", ""),
            command=spec.get("command", ""),
            created_by=spec.get("created_by", ""),
            connector_key=spec["connector_key"],
            operation=spec["operation"],
            related_entity_type=spec.get("related_entity_type", "project"),
            related_entity_id=spec.get("related_entity_id", pid),
            request_json={**spec.get("request_json", {}), "playbook_id": playbook["id"], **({"playbook_run_id": run_id} if run_id else {})},
        ))
    return jobs


@router.get("/api/playbooks")
def list_playbooks(db: Session = Depends(get_db)):
    builtin = [_serialize_builtin(item) for item in BUILTIN_PLAYBOOKS.values()]
    custom = [_serialize_custom(item) for item in db.query(models.CustomPlaybook).order_by(models.CustomPlaybook.updated_at.desc()).all()]
    return {"playbooks": builtin + custom}


@router.get("/api/playbooks/step-templates")
def list_step_templates():
    return {"templates": list(STEP_TEMPLATES.values())}


@router.post("/api/playbooks/validate")
def validate_playbook(body: PlaybookBody):
    return _validate_playbook_payload(body, registry.list_connectors())


@router.post("/api/playbooks/custom", status_code=201)
def create_custom_playbook(body: PlaybookBody, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    validation = _validate_playbook_payload(body, registry.list_connectors())
    if not validation["ok"]:
        raise HTTPException(400, {"errors": validation["errors"], "warnings": validation["warnings"]})
    ts = _now()
    normalized = validation["normalized"]
    playbook = models.CustomPlaybook(
        id=new_id("pb"),
        title=normalized["title"],
        description=normalized["description"],
        steps_json=normalized["steps"],
        created_by=getattr(user, "username", "") or "",
        created_at=ts,
        updated_at=ts,
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return _serialize_custom(playbook)


@router.patch("/api/playbooks/custom/{playbook_id}")
def update_custom_playbook(playbook_id: str, body: PlaybookBody, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    playbook = db.query(models.CustomPlaybook).filter(models.CustomPlaybook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(404, "Custom playbook not found")
    validation = _validate_playbook_payload(body, registry.list_connectors())
    if not validation["ok"]:
        raise HTTPException(400, {"errors": validation["errors"], "warnings": validation["warnings"]})
    normalized = validation["normalized"]
    playbook.title = normalized["title"]
    playbook.description = normalized["description"]
    playbook.steps_json = normalized["steps"]
    playbook.updated_at = _now()
    db.commit()
    db.refresh(playbook)
    return _serialize_custom(playbook)


@router.delete("/api/playbooks/custom/{playbook_id}", status_code=204)
def delete_custom_playbook(playbook_id: str, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    playbook = db.query(models.CustomPlaybook).filter(models.CustomPlaybook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(404, "Custom playbook not found")
    db.delete(playbook)
    db.commit()


@router.get("/api/projects/{pid}/playbook-runs")
def list_playbook_runs(
    pid: str,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.read")
    runs = db.query(models.PlaybookRun).filter(models.PlaybookRun.pid == pid).order_by(models.PlaybookRun.created_at.desc()).limit(limit).all()
    return {"runs": [_playbook_run_dict(run) for run in runs]}


@router.get("/api/projects/{pid}/playbook-runs/{run_id}")
def get_playbook_run(
    pid: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.read")
    run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id, models.PlaybookRun.pid == pid).first()
    if not run:
        raise HTTPException(404, "Playbook run not found")
    return _playbook_run_dict(run)


@router.post("/api/projects/{pid}/playbooks/{playbook_id}/run", status_code=201)
async def run_playbook(
    pid: str,
    playbook_id: str,
    body: PlaybookRunBody,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    playbook = _resolve_playbook(db, playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    created_by = getattr(user, "username", "") or ""
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
        request_json=body.model_dump(),
        result_json={},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
    asyncio.create_task(_run_sequence(run.id, [job.id for job in jobs], playbook.get("steps", [])))
    return {
        "ok": True,
        "playbook_run": _playbook_run_dict(run),
        "playbook": {"id": playbook["id"], "title": playbook["title"]},
        "jobs": [{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
    }


@router.post("/api/projects/{pid}/playbook-runs/{run_id}/cancel")
def cancel_playbook_run(
    pid: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id, models.PlaybookRun.pid == pid).first()
    if not run:
        raise HTTPException(404, "Playbook run not found")
    if run.status in ("done", "failed", "cancelled"):
        raise HTTPException(400, "Playbook run is already in a terminal state")
    jobs_json = list(run.jobs_json or [])
    active_ids = [item.get("id") for item in jobs_json if item.get("status") in ("queued", "running")]
    for job_id in active_ids:
        job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
        if job and job.status in ("queued", "running"):
            job.status = "cancelled"
    for item in jobs_json:
        if item.get("status") in ("queued", "running"):
            item["status"] = "cancelled"
    _update_run(db, run, status="cancelled", finished_at=_now(), error_output="Cancelled by user", jobs_json=jobs_json, result_json={"cancelled_jobs": active_ids})
    return _playbook_run_dict(run)


@router.post("/api/projects/{pid}/playbook-runs/{run_id}/rerun", status_code=201)
async def rerun_playbook_run(
    pid: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id, models.PlaybookRun.pid == pid).first()
    if not run:
        raise HTTPException(404, "Playbook run not found")
    playbook = _resolve_playbook(db, run.playbook_id)
    if not playbook:
        raise HTTPException(404, "Source playbook not found")
    body = PlaybookRunBody(**(run.request_json or {}))
    created_by = getattr(user, "username", "") or ""
    new_run_id = f"pbr_{uuid4().hex[:10]}"
    jobs = _queue_playbook_jobs(db, pid, playbook, body, created_by, new_run_id)
    rerun = models.PlaybookRun(
        id=new_run_id,
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
        result_json={"rerun_of": run.id},
    )
    db.add(rerun)
    db.commit()
    db.refresh(rerun)
    bcast(pid, "playbook_run", "create", _playbook_run_dict(rerun))
    asyncio.create_task(_run_sequence(rerun.id, [job.id for job in jobs], playbook.get("steps", [])))
    return {"ok": True, "playbook_run": _playbook_run_dict(rerun)}
