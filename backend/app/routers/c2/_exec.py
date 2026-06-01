from typing import Annotated

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from ... import models, schemas
from ...core.crypto import decrypt_str
from ...core.deps import get_current_user, is_admin
from ...core.events import bcast, log_event
from ...core.job_tracker import finish_job, start_job
from ...core.logging_setup import get_logger
from ...core.permissions import PERM_HOSTS_READ
from ...core.utils import new_id, ts_now
from ...database import get_db

from ._integrations import (
    router,
    _require_c2,
    _load_integrations,
    _visible_integrations_for_pid,
    _MSG_INTEGRATION_NOT_FOUND,
    C2HostActionRequest,
)
from ._adaptix import _adaptix_fetch_creds, _adaptix_fetch_bof_catalog, _adaptix_execute, _normalize_c2_cred
from ._mythic import _mythic_execute
from ._sliver import _sliver_execute
from ._sessions import _LIVE_CONNECTORS

logger = get_logger(__name__)

SUPPORTED_EXEC_C2_TYPES = ("adaptix", "mythic", "sliver")


def _cred_matches_host(cred: dict, host: models.Host) -> bool:
    host_ips = set(host.ips or []) | ({host.ip} if host.ip else set())
    if cred.get("host") and cred.get("host") in host_ips:
        return True
    if host.hostname and cred.get("host") == host.hostname:
        return True
    host_domain = (host.domain or "").strip().lower()
    cred_domain = (cred.get("domain") or "").strip().lower()
    return bool(host_domain and cred_domain and host_domain == cred_domain)


def _render_command_with_cred(commandline: str, cred: dict | None, host: models.Host | None) -> str:
    if not cred:
        return commandline
    domain = (cred.get("domain") or "").strip()
    username = (cred.get("username") or "").strip()
    secret = cred.get("secret") or ""
    values = {
        "{{USER}}": username,
        "{{USERNAME}}": username,
        "{{PASS}}": secret,
        "{{PASSWORD}}": secret,
        "{{SECRET}}": secret,
        "{{HASH}}": secret,
        "{{DOMAIN}}": domain,
        "{{REALM}}": domain,
        "{{HOST}}": host.ip if host else "",
        "{{TARGET}}": host.ip if host else "",
    }
    rendered = commandline
    for key, value in values.items():
        rendered = rendered.replace(key, value or "")
    return rendered


def _build_host_action_session(cfg: dict, agent: dict) -> dict:
    return {
        "integration_id": cfg["id"],
        "integration_name": cfg.get("name") or cfg["type"],
        "integration_type": cfg["type"],
        "agent_id": agent.get("agent_id") or agent.get("beacon_id") or "",
        "beacon_id": agent.get("beacon_id") or "",
        "ip": agent.get("ip") or "",
        "hostname": agent.get("hostname") or "",
        "username": agent.get("username") or "",
        "domain": agent.get("domain") or "",
        "os": agent.get("os") or "",
        "arch": agent.get("arch") or "",
        "process": agent.get("process") or "",
        "listener": agent.get("listener") or "",
        "session_type": agent.get("session_type") or "",
        "alive": agent.get("alive", True),
        "mark": agent.get("mark") or "",
        "last_seen": agent.get("last_seen") or "",
    }


async def _process_integration_for_host(
    cfg: dict, host_ips: set, sessions: list, c2_creds: list, bof_catalog: dict, host_id: str
) -> None:
    c2_type = (cfg.get("type") or "").lower()
    if c2_type not in SUPPORTED_EXEC_C2_TYPES:
        return
    live_fn = _LIVE_CONNECTORS.get(c2_type)
    if not live_fn:
        return
    try:
        agents = await live_fn(cfg)
        for agent in [a for a in agents if a.get("ip") in host_ips]:
            sessions.append(_build_host_action_session(cfg, agent))
        if c2_type == "adaptix":
            try:
                creds = await _adaptix_fetch_creds(cfg)
                c2_creds.extend([_normalize_c2_cred(item, cfg["id"]) for item in creds])
            except Exception as e:
                logger.warning("Adaptix creds fetch failed for %s: %s", cfg.get("id"), e)
            try:
                bof_catalog[cfg["id"]] = await _adaptix_fetch_bof_catalog(cfg)
            except Exception:
                bof_catalog[cfg["id"]] = []
    except Exception as e:
        logger.warning("%s host actions failed for %s/%s: %s", c2_type, cfg.get("id"), host_id, e)


def _cred_matches_project_host(cred: "models.Cred", host: "models.Host") -> bool:
    host_ids = set(cred.host_ids or [])
    if host.id in host_ids:
        return True
    if cred.host in {host.ip, host.hostname} and cred.host:
        return True
    if not cred.is_domain or not host.domain:
        return False
    return (cred.domain or "").strip().lower() == (host.domain or "").strip().lower()


def _build_rootnotes_cred_dict(cred: "models.Cred", can_read_secret: bool) -> dict:
    return {
        "id": cred.id,
        "source": "rootnotes",
        "integration_id": "",
        "username": cred.username,
        "secret": decrypt_str(cred.secret) if can_read_secret else "",
        "domain": cred.domain,
        "host": cred.host,
        "type": cred.type,
        "label": cred.username,
    }


@router.get("/host-actions/{pid}/{host_id}", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
async def get_host_actions(
    pid: str,
    host_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_c2()
    from ...core.access import check_pid_access
    from ...core.permissions import get_membership, get_permissions_for_role

    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    if is_admin(user):
        can_read_secret = True
    else:
        m = get_membership(db, pid, user.id)
        can_read_secret = bool(m and "credentials.read_secret" in get_permissions_for_role(m.role))
    host = db.query(models.Host).filter(models.Host.id == host_id, models.Host.pid == pid).first()
    if not host:
        raise HTTPException(404, "Host not found")

    integrations = _visible_integrations_for_pid(_load_integrations(db), pid)
    sessions: list = []
    c2_creds: list = []
    bof_catalog: dict = {}
    host_ips = set(host.ips or []) | ({host.ip} if host.ip else set())
    for cfg in integrations:
        await _process_integration_for_host(cfg, host_ips, sessions, c2_creds, bof_catalog, host_id)

    project_creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    rootnotes_creds = [
        _build_rootnotes_cred_dict(cred, can_read_secret)
        for cred in project_creds
        if _cred_matches_project_host(cred, host)
    ]

    if rootnotes_creds and can_read_secret:
        log_event(
            db,
            pid,
            getattr(user, "username", None),
            "audit",
            "read_credential_secrets",
            f"Credential secrets viewed via host actions ({len(rootnotes_creds)})",
            {"count": len(rootnotes_creds), "host_id": host.id},
        )
        db.commit()

    filtered_c2_creds = [item for item in c2_creds if _cred_matches_host(item, host)]
    return {
        "host_id": host.id,
        "sessions": sessions,
        "creds": rootnotes_creds + filtered_c2_creds,
        "bofs": bof_catalog,
    }


async def resolve_c2_cred(
    db: Session, pid: str, credential_id: str, credential_source: str, cfg: dict
) -> dict | None:
    if not credential_id:
        return None
    if credential_source == "c2" and (cfg.get("type") or "").lower() == "adaptix":
        creds = await _adaptix_fetch_creds(cfg)
        return next(
            (
                _normalize_c2_cred(item, cfg["id"])
                for item in creds
                if str(item.get("c_creds_id") or item.get("id") or "") == credential_id
            ),
            None,
        )
    cred = (
        db.query(models.Cred)
        .filter(models.Cred.id == credential_id, models.Cred.pid == pid)
        .first()
    )
    if not cred:
        return None
    return {
        "id": cred.id,
        "source": "rootnotes",
        "username": cred.username,
        "secret": decrypt_str(cred.secret),
        "domain": cred.domain,
        "host": cred.host,
        "type": cred.type,
    }


async def perform_c2_command(
    db: Session,
    pid: str,
    host: models.Host,
    cfg: dict,
    agent_id: str,
    commandline: str,
    mode: str,
    cred: dict | None,
    wait_for_output: bool,
    timeout_seconds: int,
    title: str,
    actor_username: str = "",
) -> tuple[dict, models.HostActivity, str]:
    c2_type = (cfg.get("type") or "").lower()
    if c2_type not in SUPPORTED_EXEC_C2_TYPES:
        raise ValueError(
            f"Execution is not supported for C2 type {c2_type!r}. "
            f"Supported: {', '.join(SUPPORTED_EXEC_C2_TYPES)}"
        )
    rendered_command = _render_command_with_cred(commandline, cred, host)
    if cred and cred.get("secret"):
        log_event(
            db,
            pid,
            actor_username or None,
            "audit",
            "secret_used_c2_exec",
            f"Credential secret used in C2 exec via {c2_type}: {cred.get('username') or ''}",
            {
                "cred_id": cred.get("id"),
                "username": cred.get("username"),
                "c2_type": c2_type,
                "agent_id": agent_id,
            },
        )
        db.commit()
    if c2_type == "mythic":
        result = await _mythic_execute(
            cfg, agent_id, rendered_command, wait_for_output, timeout_seconds
        )
        summary = f"Executed via Mythic on callback {agent_id}"
    elif c2_type == "sliver":
        result = await _sliver_execute(
            cfg, agent_id, rendered_command, wait_for_output, timeout_seconds
        )
        summary = f"Executed via Sliver on {result.get('kind', 'agent')} {agent_id}"
    else:
        result = await _adaptix_execute(
            cfg, agent_id, rendered_command, wait_for_output, timeout_seconds
        )
        summary = f"Executed via Adaptix on agent {agent_id}"
    output = result.get("output") or result.get("message") or result.get("error") or ""
    from ...core.secret_scrub import scrub_for_cred

    safe_command = scrub_for_cred(rendered_command, cred)
    safe_output = scrub_for_cred(output, cred)
    activity = models.HostActivity(
        id=new_id("ha"),
        pid=pid,
        host_id=host.id,
        title=title,
        activity_type="postex" if mode == "command" else "exploit",
        command=safe_command,
        summary=summary,
        output=safe_output,
        status="done",
        ts=ts_now(),
    )
    db.add(activity)
    db.commit()
    bcast(
        pid, "host_activity", "create", schemas.HostActivity.model_validate(activity).model_dump()
    )
    log_event(
        db,
        pid,
        actor_username,
        "host_activity",
        "create",
        f"{title} on {host.ip or host.hostname}",
        {"host_id": host.id, "integration_id": cfg.get("id"), "c2_type": c2_type},
    )
    db.commit()
    return result, activity, rendered_command


@router.post("/execute/{pid}", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
async def execute_host_action(
    pid: str,
    body: C2HostActionRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_c2()
    from ...core.access import check_pid_access

    check_pid_access(db, pid, user, "command_outputs.create")
    host = (
        db.query(models.Host).filter(models.Host.id == body.host_id, models.Host.pid == pid).first()
    )
    if not host:
        raise HTTPException(404, "Host not found")
    cfg = next(
        (
            i
            for i in _visible_integrations_for_pid(_load_integrations(db), pid)
            if i.get("id") == body.integration_id
        ),
        None,
    )
    if not cfg:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    if cfg.get("type") not in SUPPORTED_EXEC_C2_TYPES:
        raise HTTPException(
            400, f"Execution supported only for: {', '.join(SUPPORTED_EXEC_C2_TYPES)}"
        )
    if not body.agent_id.strip():
        raise HTTPException(400, "agent_id is required")
    if not body.commandline.strip():
        raise HTTPException(400, "commandline is required")

    selected_cred = await resolve_c2_cred(
        db,
        pid,
        body.credential_id,
        body.credential_source,
        cfg,
    )

    title = (body.title or ("Adaptix BOF" if body.mode == "bof" else "Adaptix command")).strip()
    job = start_job(
        db,
        pid,
        "c2_exec",
        title,
        target=host.ip or host.hostname or host.id,
        command=body.commandline.strip(),
        created_by=user.username or "",
        connector_key="adaptix",
        operation="bof_execute" if body.mode == "bof" else "command_execute",
        related_entity=("host", host.id),
        request_json=body.model_dump(),
    )
    try:
        result, activity, rendered_command = await perform_c2_command(
            db,
            pid,
            host,
            cfg,
            body.agent_id.strip(),
            body.commandline.strip(),
            body.mode,
            selected_cred,
            body.wait_for_output,
            body.timeout_seconds,
            title,
            actor_username=user.username or "",
        )
        finish_job(db, job, status="done", output=result.get("output") or "", result=result)
        return {
            "ok": True,
            "job_id": job.id,
            "activity_id": activity.id,
            "result": result,
            "rendered_command": rendered_command,
        }
    except Exception as e:
        finish_job(db, job, status="failed", error_output=str(e))
        raise HTTPException(400, f"Adaptix execution failed: {e}")
