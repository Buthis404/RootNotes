import asyncio
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast, log_event
from ..core.job_tracker import start_job, finish_job
from ..core.ssh_exec import run_ssh_command
from ..core.utils import new_id
from ..database import get_db
from ..plugins.registry import registry
from ..plugins.state import list_attacker_targets


router = APIRouter(prefix="/api/projects/{pid}/attacker-exec", tags=["attacker-exec"])


class AttackerExecBody(BaseModel):
    command: str
    snippet_title: str = ""
    host_id: str | None = None
    cred_id: str | None = None
    target_id: str | None = None
    execution_mode: str = "auto"  # auto | project | global
    timeout_seconds: int = 45
    activity_type: str = "postex"


def _require_enabled():
    module = registry.get("attacker_ssh")
    if not module or not module.enabled:
        raise HTTPException(404, "Attacker SSH module is disabled")


def _resolve_attacker_host(db: Session, pid: str, host_id: str | None) -> models.Host:
    q = db.query(models.Host).filter(models.Host.pid == pid)
    if host_id:
        host = q.filter(models.Host.id == host_id).first()
        if not host:
            raise HTTPException(404, "Attacker host not found")
    else:
        host = q.filter((models.Host.is_attacker == True) | (models.Host.role == "attacker")).order_by(models.Host.hostname, models.Host.ip).first()
        if not host:
            raise HTTPException(400, "No attacker host is configured in this project")
    if not (host.is_attacker or (host.role or "").lower() == "attacker"):
        raise HTTPException(400, "Selected host is not marked as attacker")
    return host


def _cred_matches_host(cred: models.Cred, host: models.Host) -> bool:
    if host.id in (cred.host_ids or []):
        return True
    return cred.host in {host.ip, host.hostname}


def _resolve_project_cred(db: Session, pid: str, host: models.Host, cred_id: str | None) -> models.Cred | None:
    q = db.query(models.Cred).filter(models.Cred.pid == pid)
    if cred_id:
        cred = q.filter(models.Cred.id == cred_id).first()
        if not cred:
            raise HTTPException(404, "Credential not found")
        if not _cred_matches_host(cred, host):
            raise HTTPException(400, "Credential is not linked to the selected attacker host")
        return cred

    candidates = [
        cred for cred in q.all()
        if _cred_matches_host(cred, host)
        and cred.secret
        and cred.type in {"plain", "key"}
        and ((cred.service or "").lower() in {"", "ssh"} or cred.type == "key")
    ]
    candidates.sort(key=lambda cred: ((cred.type != "key"), (cred.service or "") != "ssh", cred.username or ""))
    return candidates[0] if candidates else None


def _build_ssh_config_from_project(host: models.Host, cred: models.Cred, fallback: dict) -> dict:
    return {
        "host": host.ip,
        "port": fallback.get("port") or 22,
        "username": cred.username,
        "password": cred.secret if cred.type != "key" else "",
        "private_key": cred.secret if cred.type == "key" else "",
        "known_hosts_policy": fallback.get("known_hosts_policy") or "accept_new",
    }


def _list_global_targets_for_project(pid: str) -> list[dict]:
    return [
        {
            "id": target.get("id"),
            "name": target.get("name") or target.get("host") or target.get("id"),
            "host": target.get("host", ""),
            "port": target.get("port", 22),
            "username": target.get("username", ""),
            "enabled": target.get("enabled", True),
            "project_ids": target.get("project_ids", []),
            "source": "global",
        }
        for target in list_attacker_targets()
        if target.get("enabled", True) and (not target.get("project_ids") or pid in target.get("project_ids", []))
    ]


@router.get("/targets")
def list_execution_targets(
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_enabled()
    check_pid_access(db, pid, user, "command_outputs.read")

    project_hosts = db.query(models.Host).filter(
        models.Host.pid == pid,
        (models.Host.is_attacker == True) | (models.Host.role == "attacker"),
    ).order_by(models.Host.hostname, models.Host.ip).all()

    host_targets = []
    for host in project_hosts:
        linked_creds = [
            cred for cred in db.query(models.Cred).filter(models.Cred.pid == pid).all()
            if _cred_matches_host(cred, host) and cred.secret and cred.type in {"plain", "key"}
        ]
        host_targets.append({
            "id": host.id,
            "name": host.hostname or host.ip or host.id,
            "host": host.ip,
            "source": "project",
            "cred_count": len(linked_creds),
        })

    return {
        "project_hosts": host_targets,
        "global_targets": _list_global_targets_for_project(pid),
    }


@router.post("")
async def execute_attacker_command(
    pid: str,
    body: AttackerExecBody,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_enabled()
    check_pid_access(db, pid, user, "command_outputs.create")

    attacker_host = None
    resolved_cred = None

    if body.execution_mode not in {"auto", "project", "global"}:
        raise HTTPException(400, "Invalid execution_mode")

    ssh_config = None
    used_global_target = None
    if body.execution_mode in {"auto", "project"}:
        attacker_host = _resolve_attacker_host(db, pid, body.host_id)
        resolved_cred = _resolve_project_cred(db, pid, attacker_host, body.cred_id)
        if resolved_cred:
            ssh_config = _build_ssh_config_from_project(attacker_host, resolved_cred, {"port": 22, "known_hosts_policy": "accept_new"})
        elif body.execution_mode == "project":
            raise HTTPException(400, "No usable SSH credential found for attacker host")

    if ssh_config is None:
        global_targets = _list_global_targets_for_project(pid)
        if body.target_id:
            used_global_target = next((target for target in global_targets if target.get("id") == body.target_id), None)
            if not used_global_target:
                raise HTTPException(404, "Global attacker target not found for this project")
        else:
            used_global_target = global_targets[0] if global_targets else None
        if not used_global_target:
            raise HTTPException(400, "No global attacker target is assigned to this project")
        ssh_config = next((target for target in list_attacker_targets() if target.get("id") == used_global_target.get("id")), None)
        if not ssh_config:
            raise HTTPException(404, "Stored global attacker target not found")

    if attacker_host is None:
        attacker_host = _resolve_attacker_host(db, pid, body.host_id) if body.host_id else db.query(models.Host).filter(models.Host.pid == pid).order_by(models.Host.hostname, models.Host.ip).first()
        if not attacker_host:
            raise HTTPException(400, "No host is available in the project to attach execution output")

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    title = body.snippet_title.strip() or (body.command.strip().splitlines()[0][:80] if body.command.strip() else "Remote command")

    exec_username = getattr(request.state, "username", None)

    # Create activity record with status "running" before the SSH call
    activity = models.HostActivity(
        id=new_id("ha"),
        pid=pid,
        host_id=attacker_host.id,
        title=title,
        activity_type=body.activity_type or "postex",
        command=body.command,
        summary=f"Executing via attacker SSH ({'project cred' if resolved_cred else 'global config'})...",
        output="",
        status="running",
        ts=ts,
    )
    db.add(activity)
    log_event(db, pid, exec_username, "host_activity", "create", f"Attacker exec: {title}", {"host_id": attacker_host.id, "type": activity.activity_type})
    db.commit()
    db.refresh(activity)

    job = start_job(db, pid, "exec", title,
                    target=attacker_host.ip or attacker_host.hostname or "",
                    command=body.command, created_by=exec_username or "",
                    connector_key="attacker_ssh", operation="exec",
                    related_entity_type="host", related_entity_id=attacker_host.id,
                    request_json=body.model_dump())

    # Run SSH in thread pool to avoid blocking the event loop
    loop = asyncio.get_event_loop()
    try:
        _config = dict(ssh_config)
        _cmd = body.command
        _timeout = body.timeout_seconds
        result = await loop.run_in_executor(None, lambda: run_ssh_command(_config, _cmd, _timeout))
    except ValueError as e:
        activity.status = "failed"
        activity.output = str(e)
        db.commit()
        finish_job(db, job, status="failed", error_output=str(e))
        raise HTTPException(400, str(e))

    combined_output = (result.get("stdout") or "") + (("\n" + result.get("stderr")) if result.get("stderr") else "")

    # Update activity with result
    activity.output = combined_output
    activity.status = "done" if result.get("ok") else "failed"
    activity.summary = f"Executed via attacker SSH ({'project cred' if resolved_cred else 'global config'})"
    db.commit()
    db.refresh(activity)

    finish_job(db, job,
               status="done" if result.get("ok") else "failed",
               output=result.get("stdout", "")[:20000],
               error_output=result.get("stderr", ""),
               result={"exit_code": result.get("exit_code", -1)})

    payload = schemas.HostActivity.model_validate(activity).model_dump()
    bcast(pid, "host_activity", "update", payload)

    return {
        "ok": result.get("ok", False),
        "job_id": job.id,
        "exit_code": result.get("exit_code", -1),
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "host": schemas.Host.model_validate(attacker_host).model_dump(),
        "cred": schemas.Cred.model_validate(resolved_cred).model_dump() if resolved_cred else None,
        "used_global_fallback": resolved_cred is None,
        "global_target": used_global_target,
        "activity": payload,
    }
