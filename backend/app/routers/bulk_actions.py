"""
Bulk actions: run commands across multiple hosts, validate credentials.
All operations require the attacker_ssh module to be enabled.
"""
import asyncio
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast, log_event
from ..core.job_tracker import start_job, finish_job
from ..core.ssh_exec import run_ssh_command
from ..core.utils import new_id
from ..database import get_db
from ..plugins.registry import registry
from ..plugins.state import list_attacker_targets
from ..schemas import HostActivity as HASchema

router = APIRouter(prefix="/api/projects/{pid}", tags=["bulk-actions"])


def _require_attacker_ssh():
    module = registry.get("attacker_ssh")
    if not module or not module.enabled:
        raise HTTPException(404, "Attacker SSH module is disabled")


def _resolve_exec_ssh_config(
    db: Session,
    pid: str,
    attacker_host_id: str | None = None,
    attacker_target_id: str | None = None,
) -> dict | None:
    """Resolve SSH config for the executor host.

    Priority:
    1. Explicit attacker_host_id (project host)
    2. Explicit attacker_target_id (global target)
    3. Auto: first project attacker host with a usable cred
    4. Auto: first global target assigned to this project
    """
    # --- Explicit project host ---
    if attacker_host_id:
        host = db.query(models.Host).filter(
            models.Host.id == attacker_host_id, models.Host.pid == pid,
        ).first()
        if host:
            all_creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
            candidates = [
                c for c in all_creds
                if (host.id in (c.host_ids or []) or c.host in {host.ip, host.hostname})
                and c.secret and c.type in {"plain", "key"}
            ]
            candidates.sort(key=lambda c: ((c.type != "key"), c.username or ""))
            cred = candidates[0] if candidates else None
            if cred:
                return {
                    "host": host.ip,
                    "port": 22,
                    "username": cred.username,
                    "password": cred.secret if cred.type != "key" else "",
                    "private_key": cred.secret if cred.type == "key" else "",
                    "known_hosts_policy": "accept_new",
                }
        return None

    # --- Explicit global target ---
    if attacker_target_id:
        for t in list_attacker_targets():
            if t.get("id") == attacker_target_id and t.get("enabled", True):
                return t
        return None

    # --- Auto: project attacker host ---
    attacker_host = db.query(models.Host).filter(
        models.Host.pid == pid,
        (models.Host.is_attacker == True) | (models.Host.role == "attacker"),
    ).order_by(models.Host.hostname, models.Host.ip).first()

    if attacker_host:
        all_creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
        candidates = [
            c for c in all_creds
            if (attacker_host.id in (c.host_ids or []) or c.host in {attacker_host.ip, attacker_host.hostname})
            and c.secret and c.type in {"plain", "key"}
        ]
        candidates.sort(key=lambda c: ((c.type != "key"), c.username or ""))
        cred = candidates[0] if candidates else None
        if cred:
            return {
                "host": attacker_host.ip,
                "port": 22,
                "username": cred.username,
                "password": cred.secret if cred.type != "key" else "",
                "private_key": cred.secret if cred.type == "key" else "",
                "known_hosts_policy": "accept_new",
            }

    # --- Auto: global target for this project ---
    for target in list_attacker_targets():
        if not target.get("enabled", True):
            continue
        project_ids = target.get("project_ids", [])
        if not project_ids or pid in project_ids:
            return target

    return None


# ── Bulk exec ─────────────────────────────────────────────────────────

class BulkExecBody(BaseModel):
    host_ids: List[str]
    command_template: str        # use {target} as placeholder for target host IP
    scan_type: str = "exec"      # exec | nmap | cme | nuclei
    snippet_title: str = ""
    activity_type: str = "scan"
    timeout_seconds: int = 60
    attacker_host_id: str | None = None    # project attacker host to run FROM
    attacker_target_id: str | None = None  # global target to run FROM


@router.post("/bulk-exec")
async def bulk_exec(
    pid: str,
    body: BulkExecBody,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_attacker_ssh()
    check_pid_access(db, pid, user, "command_outputs.create")

    if not body.host_ids:
        raise HTTPException(400, "No hosts selected")
    if not body.command_template.strip():
        raise HTTPException(400, "Command template is required")

    ssh_config = _resolve_exec_ssh_config(
        db, pid,
        attacker_host_id=body.attacker_host_id,
        attacker_target_id=body.attacker_target_id,
    )
    if not ssh_config:
        raise HTTPException(400, "No attacker SSH configuration available for this project")

    target_hosts = db.query(models.Host).filter(
        models.Host.pid == pid,
        models.Host.id.in_(body.host_ids),
    ).all()
    if not target_hosts:
        raise HTTPException(404, "No valid hosts found")

    exec_username = getattr(request.state, "username", None)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    loop = asyncio.get_event_loop()
    results = []

    for host in target_hosts:
        target_ip = host.ip or host.hostname or "unknown"
        command = (
            body.command_template
            .replace("{target}", target_ip)
            .replace("{TARGET}", target_ip)
            .replace("{{TARGET}}", target_ip)
            .replace("{{target}}", target_ip)
        )
        title = body.snippet_title.strip() or f"{body.scan_type}: {target_ip}"

        activity = models.HostActivity(
            id=new_id("ha"),
            pid=pid,
            host_id=host.id,
            title=title,
            activity_type=body.activity_type or "scan",
            command=command,
            summary="Running via attacker SSH (bulk run)...",
            output="",
            status="running",
            ts=ts,
        )
        db.add(activity)
        db.commit()
        db.refresh(activity)
        log_event(db, pid, exec_username, "host_activity", "create",
                  f"Bulk exec: {title}", {"host_id": host.id})
        db.commit()

        bcast(pid, "host_activity", "create", HASchema.model_validate(activity).model_dump())

        job = start_job(db, pid, body.scan_type or "exec", title,
                        target=target_ip, command=command, created_by=exec_username or "")

        try:
            cfg = dict(ssh_config)
            cmd = command
            timeout = body.timeout_seconds
            result = await loop.run_in_executor(
                None, lambda c=cfg, m=cmd, t=timeout: run_ssh_command(c, m, t)
            )
        except ValueError as e:
            activity.status = "failed"
            activity.output = str(e)
            db.commit()
            finish_job(db, job, status="failed", error_output=str(e))
            bcast(pid, "host_activity", "update", HASchema.model_validate(activity).model_dump())
            results.append({"host_id": host.id, "ip": target_ip, "ok": False,
                            "error": str(e), "job_id": job.id, "activity_id": activity.id})
            continue

        combined = (result.get("stdout") or "") + (("\n" + result.get("stderr")) if result.get("stderr") else "")
        ok = result.get("ok", False)
        activity.output = combined
        activity.status = "done" if ok else "failed"
        activity.summary = "Completed via attacker SSH (bulk run)"
        db.commit()
        db.refresh(activity)

        finish_job(db, job,
                   status="done" if ok else "failed",
                   output=result.get("stdout", "")[:20000],
                   error_output=result.get("stderr", ""),
                   result={"exit_code": result.get("exit_code", -1)})

        bcast(pid, "host_activity", "update", HASchema.model_validate(activity).model_dump())

        results.append({
            "host_id": host.id,
            "ip": target_ip,
            "ok": ok,
            "exit_code": result.get("exit_code", -1),
            "stdout": result.get("stdout", "")[:5000],
            "stderr": result.get("stderr", ""),
            "job_id": job.id,
            "activity_id": activity.id,
        })

    return {"ok": True, "results": results}


# ── Credential validation ─────────────────────────────────────────────

class ValidateCredBody(BaseModel):
    host_ids: List[str]
    service: str = "auto"        # ssh | smb | auto
    timeout_seconds: int = 15
    attacker_host_id: str | None = None
    attacker_target_id: str | None = None


def _build_validate_command(cred: models.Cred, target_ip: str, service: str) -> str:
    username = cred.username.replace("'", "'\\''")
    secret = cred.secret.replace("'", "'\\''")

    if service == "ssh":
        if cred.type == "key":
            # Write key to temp file, use it, clean up
            return (
                f"keyfile=$(mktemp); "
                f"printf '%s' '{secret}' > \"$keyfile\"; "
                f"chmod 600 \"$keyfile\"; "
                f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes "
                f"-i \"$keyfile\" '{username}'@'{target_ip}' id 2>&1; "
                f"rc=$?; rm -f \"$keyfile\"; exit $rc"
            )
        else:
            return (
                f"sshpass -p '{secret}' "
                f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
                f"'{username}'@'{target_ip}' id 2>&1"
            )
    else:  # smb
        if cred.type in ("ntlm", "hash"):
            return f"netexec smb '{target_ip}' -u '{username}' -H '{secret}' 2>&1 | head -10"
        else:
            return f"netexec smb '{target_ip}' -u '{username}' -p '{secret}' 2>&1 | head -10"


def _parse_validation_result(ok: bool, exit_code: int, output: str, service: str) -> bool:
    if service == "smb":
        lower = output.lower()
        if "pwn3d!" in lower:
            return True
        if "[+]" in lower and "status_logon_failure" not in lower and "status_access_denied" not in lower:
            return True
        return False
    # SSH: exit code 0 = success
    return ok and exit_code == 0


@router.post("/creds/{cred_id}/validate")
async def validate_cred(
    pid: str,
    cred_id: str,
    body: ValidateCredBody,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    _require_attacker_ssh()
    check_pid_access(db, pid, user, "command_outputs.create")

    cred = db.query(models.Cred).filter(
        models.Cred.id == cred_id, models.Cred.pid == pid
    ).first()
    if not cred:
        raise HTTPException(404, "Credential not found")
    if not cred.secret:
        raise HTTPException(400, "Credential has no secret to validate")
    if not body.host_ids:
        raise HTTPException(400, "No hosts selected")

    ssh_config = _resolve_exec_ssh_config(
        db, pid,
        attacker_host_id=body.attacker_host_id,
        attacker_target_id=body.attacker_target_id,
    )
    if not ssh_config:
        raise HTTPException(400, "No attacker SSH configuration available for this project")

    target_hosts = db.query(models.Host).filter(
        models.Host.pid == pid,
        models.Host.id.in_(body.host_ids),
    ).all()
    if not target_hosts:
        raise HTTPException(404, "No valid hosts found")

    exec_username = getattr(request.state, "username", None)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    loop = asyncio.get_event_loop()
    results = []

    for host in target_hosts:
        target_ip = host.ip or host.hostname
        if not target_ip:
            results.append({"host_id": host.id, "ok": False, "error": "Host has no IP"})
            continue

        # Determine service
        service = body.service
        if service == "auto":
            if cred.type == "key":
                service = "ssh"
            elif cred.service and cred.service.lower() in {"ssh"}:
                service = "ssh"
            elif host.os == "Windows" or cred.is_domain or cred.type in ("ntlm", "hash"):
                service = "smb"
            else:
                service = "ssh"

        command = _build_validate_command(cred, target_ip, service)

        try:
            cfg = dict(ssh_config)
            cmd = command
            timeout = body.timeout_seconds
            result = await loop.run_in_executor(
                None, lambda c=cfg, m=cmd, t=timeout: run_ssh_command(c, m, t)
            )
        except ValueError as e:
            results.append({
                "host_id": host.id, "ip": target_ip, "ok": False,
                "service": service, "error": str(e),
            })
            continue

        combined = (result.get("stdout") or "") + (("\n" + result.get("stderr")) if result.get("stderr") else "")
        success = _parse_validation_result(
            result.get("ok", False), result.get("exit_code", 1), combined, service
        )

        # Upsert CredHostNote with result
        chn = db.query(models.CredHostNote).filter(
            models.CredHostNote.cred_id == cred_id,
            models.CredHostNote.host_id == host.id,
        ).first()

        access_role = "ssh" if service == "ssh" else "local_admin"
        note_text = f"Validated {service} on {ts}: {'SUCCESS' if success else 'FAILED'}"

        if chn:
            chn.notes = note_text
            if success and access_role not in (chn.access or []):
                chn.access = list(chn.access or []) + [access_role]
        else:
            db.add(models.CredHostNote(
                id=new_id("chn"),
                cred_id=cred_id,
                host_id=host.id,
                pid=pid,
                notes=note_text,
                access=[access_role] if success else [],
            ))

        # Record activity
        activity = models.HostActivity(
            id=new_id("ha"),
            pid=pid,
            host_id=host.id,
            title=f"Cred validate: {cred.username} ({service})",
            activity_type="scan",
            command=f"validate {service} {cred.username}@{target_ip}",
            summary=f"{'✓ valid' if success else '✗ failed'} — {cred.username} on {target_ip} ({service})",
            output=combined[:5000],
            status="done" if success else "failed",
            ts=ts,
        )
        db.add(activity)
        log_event(db, pid, exec_username, "host_activity", "create",
                  f"Cred validate: {cred.username}", {"host_id": host.id, "success": success})
        db.commit()
        db.refresh(activity)

        bcast(pid, "host_activity", "update", HASchema.model_validate(activity).model_dump())

        results.append({
            "host_id": host.id,
            "ip": target_ip,
            "ok": success,
            "service": service,
            "output": combined[:2000],
            "activity_id": activity.id,
        })

    return {"ok": True, "results": results, "cred_id": cred_id}
