import asyncio

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
from ..core.route_selection import annotate_targets_with_route_context, choose_route_aware_target
from ..core.ssh_exec import is_transport_failure as _is_transport_failure
from ..core.ssh_exec import run_ssh_command
from ..core.utils import new_id, ts_now
from ..database import get_db
from ..core.attacker_transport import (
    ResolvedConnection,
    build_ssh_config_from_cred,
    list_global_targets_for_project,
    require_attacker_ssh,
    resolve_exec_connection,
    resolve_project_attacker_host,
    resolve_project_ssh_cred,
)

router = APIRouter(
    prefix="/api/projects/{pid}/attacker-exec", tags=["attacker-exec"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
        502: {"description": "Bad gateway"},
    },
)


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
    require_attacker_ssh()


def _resolve_attacker_host(db: Session, pid: str, host_id: str | None) -> models.Host:
    return resolve_project_attacker_host(db, pid, host_id)


def _cred_matches_host(cred: models.Cred, host: models.Host) -> bool:
    from ..core.attacker_transport import _cred_matches_host as _match
    return _match(cred, host)


def _resolve_project_cred(
    db: Session, pid: str, host: models.Host, cred_id: str | None
) -> models.Cred | None:
    return resolve_project_ssh_cred(db, pid, host, cred_id)


def _build_ssh_config_from_project(host: models.Host, cred: models.Cred, fallback: dict) -> dict:
    return build_ssh_config_from_cred(host, cred, fallback)


def _list_global_targets_for_project(pid: str) -> list[dict]:
    return list_global_targets_for_project(pid)


def _extract_command_target_hint(command: str) -> str:
    return command or ""


@router.get("/targets", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
def list_execution_targets(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_enabled()
    check_pid_access(db, pid, user, "command_outputs.read")

    project_hosts = (
        db.query(models.Host)
        .filter(
            models.Host.pid == pid,
            (models.Host.is_attacker) | (models.Host.role == "attacker"),
        )
        .order_by(models.Host.hostname, models.Host.ip)
        .all()
    )

    host_targets = []
    for host in project_hosts:
        linked_creds = [
            cred
            for cred in db.query(models.Cred).filter(models.Cred.pid == pid).all()
            if _cred_matches_host(cred, host) and cred.secret and cred.type in {"plain", "key"}
        ]
        host_targets.append(
            {
                "id": host.id,
                "name": host.hostname or host.ip or host.id,
                "host": host.ip,
                "source": "project",
                "cred_count": len(linked_creds),
            }
        )

    global_targets = annotate_targets_with_route_context(
        pid, _list_global_targets_for_project(pid), db
    )

    return {
        "project_hosts": host_targets,
        "global_targets": global_targets,
    }


def _resolve_global_exec_candidates(
    pid: str, body: "AttackerExecBody", db: "Session", global_targets: list
) -> tuple[dict, list, dict | None]:
    """Resolve SSH config + candidate list from global targets via transport service."""
    from ..core.attacker_transport import _find_global_target_by_id
    from ..plugins.state import list_attacker_targets as _list_all

    if body.target_id:
        used_global_target = next((t for t in global_targets if t.get("id") == body.target_id), None)
        if not used_global_target:
            raise HTTPException(404, "Global attacker target not found for this project")
        ssh_config = _find_global_target_by_id(used_global_target.get("id"))
        if not ssh_config:
            raise HTTPException(404, "Stored global attacker target not found")
        return ssh_config, [ssh_config], used_global_target

    if not global_targets:
        raise HTTPException(400, "No global attacker target is assigned to this project")
    hinted = choose_route_aware_target(pid, global_targets, db, _extract_command_target_hint(body.command))
    all_stored = _list_all()
    ranked = ([hinted] if hinted else []) + (
        [gt for gt in global_targets if gt.get("id") != hinted.get("id")] if hinted else global_targets
    )
    candidates = [t for gt in ranked for t in all_stored if t.get("id") == gt.get("id") and t.get("enabled", True)]
    if not candidates:
        raise HTTPException(400, "No enabled global attacker targets found")
    return candidates[0], candidates, None


async def _run_ssh_with_fallback(loop, candidates: list, cmd: str, timeout_seconds: int) -> dict:
    result = None
    for idx, cfg in enumerate(candidates):
        config = dict(cfg)
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda c=config: run_ssh_command(c, cmd, timeout_seconds)),
                timeout=timeout_seconds,
            )
        except asyncio.TimeoutError:
            result = None
            if idx + 1 < len(candidates):
                continue
            break
        if _is_transport_failure(result) and idx + 1 < len(candidates):
            continue
        break
    return result


def _resolve_execution_context(
    db: Session, pid: str, body: "AttackerExecBody"
) -> tuple[dict, list, dict | None, "models.Host", "models.Cred | None"]:
    """Resolve SSH config, candidates, global target, attacker host, and credential."""
    conn = resolve_exec_connection(
        db, pid,
        execution_mode=body.execution_mode,
        host_id=body.host_id,
        cred_id=body.cred_id,
        target_id=body.target_id,
        command_hint=body.command or "",
    )
    return conn.ssh_config, conn.candidates, conn.global_target, conn.attacker_host, conn.resolved_cred


@router.post("", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
async def execute_attacker_command(
    pid: str,
    body: AttackerExecBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_enabled()
    check_pid_access(db, pid, user, "command_outputs.create")

    if body.execution_mode not in {"auto", "project", "global"}:
        raise HTTPException(400, "Invalid execution_mode")

    ssh_config, _exec_ssh_candidates, used_global_target, attacker_host, resolved_cred = (
        _resolve_execution_context(db, pid, body)
    )

    ts = ts_now()
    title = body.snippet_title.strip() or (
        body.command.strip().splitlines()[0][:80] if body.command.strip() else "Remote command"
    )
    exec_username = getattr(request.state, "username", None)
    cred_label = "project cred" if resolved_cred else "global config"

    activity = models.HostActivity(
        id=new_id("ha"), pid=pid, host_id=attacker_host.id, title=title,
        activity_type=body.activity_type or "postex", command=body.command,
        summary=f"Executing via attacker SSH ({cred_label})...",
        output="", status="running", ts=ts,
    )
    db.add(activity)
    log_event(db, pid, exec_username, "host_activity", "create", f"Attacker exec: {title}",
              {"host_id": attacker_host.id, "type": activity.activity_type})
    db.commit()
    db.refresh(activity)

    job = start_job(
        db, pid, "exec", title, target=attacker_host.ip or attacker_host.hostname or "",
        command=body.command, created_by=exec_username or "", connector_key="attacker_ssh",
        operation="exec", related_entity=("host", attacker_host.id),
        request_json=body.model_dump(),
    )

    loop = asyncio.get_running_loop()
    _cmd = build_remote_execution_command(ssh_config, body.command)
    try:
        result = await _run_ssh_with_fallback(loop, _exec_ssh_candidates, _cmd, body.timeout_seconds)
    except ValueError as e:
        activity.status = "failed"
        activity.output = str(e)
        db.commit()
        finish_job(db, job, status="failed", error_output=str(e))
        raise HTTPException(400, str(e))

    if _is_transport_failure(result):
        err = f"All {len(_exec_ssh_candidates)} attacker target(s) unreachable: {result.get('stderr', '')[:200]}"
        activity.status = "failed"
        activity.output = err
        db.commit()
        finish_job(db, job, status="failed", error_output=err)
        raise HTTPException(502, err)

    combined_output = (result.get("stdout") or "") + (
        ("\n" + result.get("stderr")) if result.get("stderr") else ""
    )
    ok_status = "done" if result.get("ok") else "failed"
    activity.output = combined_output
    activity.status = ok_status
    activity.summary = f"Executed via attacker SSH ({cred_label})"
    db.commit()
    db.refresh(activity)

    finish_job(
        db, job, status=ok_status,
        output=result.get("stdout", "")[:20000], error_output=result.get("stderr", ""),
        result={"exit_code": result.get("exit_code", -1)},
    )

    payload = schemas.HostActivity.model_validate(activity).model_dump()
    bcast(pid, "host_activity", "update", payload)

    return {
        "ok": result.get("ok", False), "job_id": job.id,
        "exit_code": result.get("exit_code", -1),
        "stdout": result.get("stdout", ""), "stderr": result.get("stderr", ""),
        "host": schemas.Host.model_validate(attacker_host).model_dump(),
        "cred": schemas.Cred.model_validate(resolved_cred).model_dump() if resolved_cred else None,
        "used_global_fallback": resolved_cred is None,
        "global_target": used_global_target, "activity": payload,
    }
