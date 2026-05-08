"""
Bulk actions: run commands across multiple hosts, validate credentials.
All operations require the attacker_ssh module to be enabled.
"""
import asyncio
from copy import deepcopy
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
from ..core.permissions import get_membership, get_permissions_for_role
from ..core.utils import domains_match
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
    credential_id: str | None = None


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

    selected_cred = None
    if body.credential_id:
        membership = get_membership(db, pid, user.id) if user.role != "admin" else None
        can_read_secret = user.role == "admin" or bool(membership and "credentials.read_secret" in get_permissions_for_role(membership.role))
        if not can_read_secret:
            raise HTTPException(403, "Insufficient permissions to use credential secrets")
        selected_cred = db.query(models.Cred).filter(models.Cred.id == body.credential_id, models.Cred.pid == pid).first()
        if not selected_cred:
            raise HTTPException(404, "Credential not found")
        if not selected_cred.secret:
            raise HTTPException(400, "Credential has no secret")

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
    loop = asyncio.get_running_loop()
    results = []
    access_role = _infer_bulk_access_role(body.command_template)
    graph_updates = 0

    for host in target_hosts:
        target_ip = host.ip or host.hostname or "unknown"
        cred_domain = (selected_cred.domain or "").strip() if selected_cred else ""
        cred_user = selected_cred.username if selected_cred else ""
        cred_secret = selected_cred.secret if selected_cred else ""
        command = (
            body.command_template
            .replace("{target}", target_ip)
            .replace("{TARGET}", target_ip)
            .replace("{{TARGET}}", target_ip)
            .replace("{{target}}", target_ip)
            .replace("{{USER}}", cred_user)
            .replace("{{USERNAME}}", cred_user)
            .replace("{{PASS}}", cred_secret)
            .replace("{{PASSWORD}}", cred_secret)
            .replace("{{SECRET}}", cred_secret)
            .replace("{{HASH}}", cred_secret)
            .replace("{{DOMAIN}}", cred_domain)
            .replace("{{REALM}}", cred_domain)
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
                        target=target_ip, command=command, created_by=exec_username or "",
                        connector_key="attacker_ssh", operation="bulk_exec",
                        related_entity_type="host", related_entity_id=host.id,
                        request_json={**body.model_dump(), "resolved_host_id": host.id, "resolved_target": target_ip})

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
        success = _is_bulk_auth_success(command, ok, result.get("exit_code", -1), combined)
        activity.output = combined
        activity.status = "done" if ok else "failed"
        activity.summary = "Credential-driven bulk run success" if success and selected_cred else "Completed via attacker SSH (bulk run)"
        if selected_cred:
            note_text = f"Bulk run on {ts}: {'SUCCESS' if success else 'FAILED'}"
            _upsert_cred_host_note(db, pid, selected_cred.id, host, note_text, access_role, success)
            _maybe_promote_host_status(host, success)
            if _enrich_access_graph(db, pid, body.attacker_host_id, host, access_role, success, ts):
                graph_updates += 1
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
            "success": success,
            "exit_code": result.get("exit_code", -1),
            "stdout": result.get("stdout", "")[:5000],
            "stderr": result.get("stderr", ""),
            "job_id": job.id,
            "activity_id": activity.id,
        })

    summary = {
        "total": len(results),
        "ok": sum(1 for item in results if item.get("ok")),
        "failed": sum(1 for item in results if not item.get("ok")),
        "successful_auth": sum(1 for item in results if item.get("success")),
        "state_updates": sum(1 for item in results if item.get("success") and selected_cred),
        "graph_updates": graph_updates,
        "credential_id": selected_cred.id if selected_cred else "",
        "access_role": access_role or "",
    }

    return {"ok": True, "results": results, "summary": summary}


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


def _infer_bulk_access_role(command: str) -> str | None:
    lower = (command or "").lower()
    if "evil-winrm" in lower or "netexec winrm" in lower:
        return "winrm"
    if "ssh " in lower or "sshpass" in lower:
        return "ssh"
    if "wmiexec" in lower or "psexec" in lower:
        return "local_admin"
    return None


def _is_bulk_auth_success(command: str, ok: bool, exit_code: int, output: str) -> bool:
    lower = (output or "").lower()
    cmd = (command or "").lower()
    if "netexec smb" in cmd or "crackmapexec smb" in cmd:
        if "pwn3d!" in lower:
            return True
        if "[+]" in lower and "status_logon_failure" not in lower and "status_access_denied" not in lower:
            return True
        return False
    if "netexec winrm" in cmd or "evil-winrm" in cmd:
        if "pwn3d!" in lower or "established" in lower or "evil-winrm shell" in lower:
            return True
        if "[+]" in lower and "logon_failure" not in lower and "access_denied" not in lower:
            return True
        return ok and exit_code == 0
    if "ldapsearch" in cmd:
        return ("dn:" in lower or "result: 0 success" in lower) and "invalid credentials" not in lower
    return ok and exit_code == 0


def _maybe_promote_host_status(host: models.Host, success: bool):
    if not success:
        return
    current = (host.status or "").lower()
    if current in {"", "unknown", "alive"}:
        host.status = "access"


def _upsert_cred_host_note(db: Session, pid: str, cred_id: str, host: models.Host, note_text: str, access_role: str | None, success: bool):
    chn = db.query(models.CredHostNote).filter(
        models.CredHostNote.cred_id == cred_id,
        models.CredHostNote.host_id == host.id,
    ).first()
    if chn:
        chn.notes = note_text
        if success and access_role and access_role not in (chn.access or []):
            chn.access = list(chn.access or []) + [access_role]
        return chn
    chn = models.CredHostNote(
        id=new_id("chn"),
        cred_id=cred_id,
        host_id=host.id,
        pid=pid,
        notes=note_text,
        access=[access_role] if success and access_role else [],
    )
    db.add(chn)
    return chn


def _edge_version(edge: dict) -> int:
    return int(edge.get("version") or 0) + 1


def _enrich_access_graph(db: Session, pid: str, attacker_host_id: str | None, target_host: models.Host, access_role: str | None, success: bool, ts: str):
    if not success or not attacker_host_id or not access_role:
        return None
    network = db.query(models.Network).filter(models.Network.pid == pid).order_by(models.Network.id).first()
    if not network:
        return None
    nodes = deepcopy(network.nodes_json or [])
    edges = deepcopy(network.edges_json or [])
    attacker_node = next((node for node in nodes if node.get("host_id") == attacker_host_id), None)
    target_node = next((node for node in nodes if node.get("host_id") == target_host.id), None)
    if not attacker_node or not target_node:
        return None

    existing = next((edge for edge in edges if {edge.get("from"), edge.get("to")} == {attacker_node.get("id"), target_node.get("id")}), None)
    reason = f"Credential-driven bulk run succeeded via {access_role} on {ts}"
    label = access_role.replace("_", " ")
    if existing:
        existing["type"] = access_role
        existing["label"] = label
        existing["reason"] = reason
        existing["state"] = "observed"
        existing["verified"] = True
        existing["confidence"] = max(float(existing.get("confidence") or 0), 1.0)
        existing["source"] = "manual"
        existing["is_manual"] = True
        existing["manual_override"] = True
        existing["updated_at"] = datetime.utcnow().isoformat()
        existing["version"] = _edge_version(existing)
        network.edges_json = edges
        db.commit()
        payload = {"network_id": network.id, "link": existing, "updated_at": existing["updated_at"]}
        bcast(pid, "network", "link_updated", payload)
        return payload

    edge = {
        "id": new_id("edg"),
        "from": attacker_node.get("id"),
        "to": target_node.get("id"),
        "style": "lateral",
        "type": access_role,
        "label": label,
        "confidence": 1.0,
        "source": "manual",
        "reason": reason,
        "state": "observed",
        "verified": True,
        "is_manual": True,
        "manual_override": True,
        "updated_at": datetime.utcnow().isoformat(),
        "version": 1,
    }
    edges.append(edge)
    network.edges_json = edges
    db.commit()
    payload = {"network_id": network.id, "link": edge, "updated_at": edge["updated_at"]}
    bcast(pid, "network", "link_created", payload)
    return payload


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
    loop = asyncio.get_running_loop()
    results = []

    job = start_job(
        db, pid, "cred_validate", f"Cred validate: {cred.username}",
        target=cred.username,
        command=f"validate {body.service} against {len(body.host_ids)} host(s)",
        created_by=exec_username or "",
        connector_key="attacker_ssh",
        operation="cred_validate",
        related_entity_type="cred",
        related_entity_id=cred.id,
        request_json={"cred_id": cred.id, **body.model_dump()},
    )

    for host in target_hosts:
        target_ip = host.ip or host.hostname
        if not target_ip:
            results.append({"host_id": host.id, "ok": False, "error": "Host has no IP"})
            continue

        if cred.is_domain and cred.domain and not domains_match(cred.domain, host.domain or ''):
            results.append({
                "host_id": host.id,
                "ip": target_ip,
                "ok": False,
                "service": body.service,
                "error": f"Domain mismatch: cred={cred.domain} host={host.domain or '-'}",
            })
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

    success_count = sum(1 for item in results if item.get("ok"))
    finish_job(
        db,
        job,
        status="done",
        output="\n".join(
            f"{item.get('ip', item.get('host_id', '?'))}: {'OK' if item.get('ok') else 'FAIL'} ({item.get('service', body.service)})"
            for item in results
        )[:20000],
        result={
            "cred_id": cred.id,
            "hosts_total": len(results),
            "hosts_valid": success_count,
            "hosts_failed": len(results) - success_count,
        },
    )

    return {"ok": True, "results": results, "cred_id": cred_id, "job_id": job.id}
