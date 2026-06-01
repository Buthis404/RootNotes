from typing import Annotated

import httpx
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from ... import models, schemas
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
    _can_manage_integration,
    _safe_integration,
    _visible_integrations_for_pid,
    _MSG_INTEGRATION_NOT_FOUND,
    _MSG_INSUFFICIENT_PERMS,
    _has_live_session_signal,
    _status_from_c2_host,
    _c2_owns_host_status,
    _C2_SETTING_KEY,
)
from ._sliver import _sliver_sync, _sliver_fetch_agent_tasks
from ._adaptix import _adaptix_sync, _adaptix_fetch_agent_tasks, _adaptix_fetch_bof_catalog
from ._mythic import _mythic_sync, _mythic_fetch_agent_tasks

logger = get_logger(__name__)

_CONNECTORS = {
    "sliver": _sliver_sync,
    "adaptix": _adaptix_sync,
    "mythic": _mythic_sync,
}


@router.post("/{iid}/test", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
async def test_connection(
    iid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    integrations = _load_integrations(db)
    cfg = next((c for c in integrations if c.get("id") == iid), None)
    if not cfg:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    if not _can_manage_integration(db, user, cfg):
        raise HTTPException(403, _MSG_INSUFFICIENT_PERMS)
    if not cfg.get("enabled"):
        raise HTTPException(400, "Integration is disabled")

    connector = _CONNECTORS.get(cfg["type"])
    if not connector:
        raise HTTPException(400, f"Unsupported C2 type: {cfg['type']}")

    try:
        data = await connector(cfg)
        if data.get("error"):
            raise HTTPException(400, f"C2 test failed: {data['error']}")
        return {
            "ok": True,
            "hosts_found": len(data.get("hosts") or []),
            "creds_found": len(data.get("creds") or []),
        }
    except HTTPException:
        raise
    except httpx.HTTPStatusError as e:
        raise HTTPException(400, f"C2 API error {e.response.status_code}: {e.response.text[:300]}")
    except httpx.ConnectError as e:
        raise HTTPException(400, f"Connection failed: {e}")
    except Exception as e:
        raise HTTPException(400, f"Error: {e}")


async def _do_project_sync(
    cfg: dict, pid: str, db: Session, iid: str | None = None, created_by: str = "auto"
) -> dict:
    connector = _CONNECTORS.get(cfg["type"])
    if not connector:
        raise ValueError(f"Unsupported C2 type: {cfg['type']}")

    label = cfg.get("label") or cfg.get("type", "c2")
    job = start_job(
        db,
        pid,
        "c2_sync",
        f"C2 Sync: {label}",
        target=cfg.get("url", ""),
        created_by=created_by,
        connector_key="c2_integration",
        operation="sync",
        related_entity=("project", pid),
        request_json={
            "iid": iid,
            "type": cfg.get("type"),
            "url": cfg.get("url"),
            "project_id": pid,
        },
    )

    try:
        result = await _do_project_sync_inner(cfg, pid, db, iid)
    except Exception as e:
        finish_job(db, job, status="failed", error_output=str(e))
        raise

    finish_job(
        db,
        job,
        status="done",
        output=f"hosts_found={result['hosts_found']} created={result['hosts_created']} updated={result['hosts_updated']} creds_created={result['creds_created']}",
        result=result,
    )
    return result


def _c2_update_host_status(host, source: str, h: dict) -> None:
    derived_status = _status_from_c2_host("", h)
    if _c2_owns_host_status(host, source):
        if derived_status:
            host.status = derived_status
    else:
        next_status = _status_from_c2_host(host.status or "", h)
        if next_status:
            host.status = next_status


def _c2_enrich_host(host, hostname: str, domain: str, os_clean: str, new_notes: str, source: str, h: dict) -> None:
    if hostname and not host.hostname:
        host.hostname = hostname
    if domain and not host.domain:
        host.domain = domain
    if os_clean and os_clean != "Unknown" and (not host.os or host.os in ("Linux", "Unknown", "")):
        host.os = os_clean
    _c2_update_host_status(host, source, h)
    cur_notes = host.notes or ""
    cur_tags = host.tags or []
    if new_notes and new_notes not in cur_notes:
        host.notes = (cur_notes + "\n\n---\n" + new_notes).strip()
    if source not in cur_tags:
        host.tags = list(cur_tags) + [source]
    if not host.import_source:
        host.import_source = source


def _c2_upsert_session_cred(db, pid: str, ip: str, username: str, source: str) -> int:
    username = (username or "").strip()
    if not username:
        return 0
    cred_domain = ""
    uname = username
    if "\\" in username:
        parts = username.split("\\", 1)
        cred_domain, uname = parts[0], parts[1]
    elif "@" in username:
        parts = username.split("@", 1)
        uname, cred_domain = parts[0], parts[1]
    existing_cred = (
        db.query(models.Cred)
        .filter(
            models.Cred.pid == pid,
            models.Cred.username == uname,
            models.Cred.domain == cred_domain,
            models.Cred.host == ip,
        )
        .first()
    )
    if existing_cred:
        return 0
    from ...core.db_upsert import try_insert_or_get

    new_cred = models.Cred(
        id=new_id("crd"),
        pid=pid,
        username=uname,
        domain=cred_domain,
        secret="",
        type="plain",
        service="os",
        host=ip,
        tags=["c2", source],
    )
    _, was_created = try_insert_or_get(
        db,
        new_cred,
        requery=lambda: db.query(models.Cred)
        .filter(
            models.Cred.pid == pid,
            models.Cred.username == uname,
            models.Cred.domain == cred_domain,
            models.Cred.host == ip,
        )
        .first(),
    )
    return 1 if was_created else 0


def _c2_sync_one_host(db, pid: str, h: dict, source: str):
    ip = h.get("ip", "").strip()
    hostname = h.get("hostname", "").strip()
    if not ip and not hostname:
        return None, 0, 0, 0
    if not ip:
        ip = hostname
    os_clean = (h.get("os") or "").strip() or "Unknown"
    domain = (h.get("domain") or "").strip()
    new_notes = (h.get("note") or "").strip()
    existing = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
    if existing:
        _c2_enrich_host(existing, hostname, domain, os_clean, new_notes, source, h)
        cred_delta = _c2_upsert_session_cred(db, pid, ip, h.get("username", ""), source)
        return existing, 0, 1, cred_delta
    if not h.get("alive", True):
        return None, 0, 0, 0
    from ...core.db_upsert import try_insert_or_get

    new_host = models.Host(
        id=new_id("hst"),
        pid=pid,
        ip=ip,
        hostname=hostname,
        os=os_clean,
        domain=domain,
        status=_status_from_c2_host("", h) or "up",
        tags=["c2", source],
        notes=new_notes,
        import_source=source,
    )
    row, was_created = try_insert_or_get(
        db,
        new_host,
        requery=lambda: db.query(models.Host)
        .filter(models.Host.pid == pid, models.Host.ip == ip)
        .first(),
    )
    if not was_created:
        _c2_enrich_host(row, hostname, domain, os_clean, new_notes, source, h)
    cred_delta = _c2_upsert_session_cred(db, pid, ip, h.get("username", ""), source)
    created = 1 if was_created else 0
    updated = 0 if was_created else 1
    return row, created, updated, cred_delta


def _c2_upsert_harvested_cred(db, pid: str, c: dict, source: str) -> bool:
    uname = (c.get("username") or "").strip()
    if not uname:
        return False
    domain = (c.get("realm") or "").strip()
    existing = (
        db.query(models.Cred)
        .filter(
            models.Cred.pid == pid,
            models.Cred.username == uname,
            models.Cred.domain == domain,
        )
        .first()
    )
    if existing:
        return False
    db.add(
        models.Cred(
            id=new_id("crd"),
            pid=pid,
            username=uname,
            secret=c.get("secret", ""),
            type=c.get("type", "plain"),
            domain=domain,
            service=c.get("service", ""),
            host=c.get("host", ""),
            tags=["c2", source],
        )
    )
    return True


def _c2_record_c2_activities(db, pid: str, cfg: dict, source: str, ts: str, session_host_raw: list, host_objects: list) -> None:
    session_host_ids = {hobj.id for hobj, _ in session_host_raw}
    for hobj, _h in session_host_raw:
        try:
            existing_act = (
                db.query(models.HostActivity)
                .filter(
                    models.HostActivity.pid == pid,
                    models.HostActivity.host_id == hobj.id,
                    models.HostActivity.activity_type == "c2",
                )
                .first()
            )
            if existing_act:
                existing_act.ts = ts
                existing_act.summary = f"Active {source} session (synced {ts})"
            else:
                db.add(
                    models.HostActivity(
                        id=new_id("ha"),
                        pid=pid,
                        host_id=hobj.id,
                        title=f"C2 session [{cfg['name']}]",
                        activity_type="c2",
                        summary=f"Active {source} session (synced {ts})",
                        status="done",
                        ts=ts,
                    )
                )
        except Exception as e:
            logger.debug("failed to record C2 session activity (pid=%s): %s", pid, e)
    stale_host_ids = {hobj.id for hobj in host_objects} - session_host_ids
    if stale_host_ids:
        db.query(models.HostActivity).filter(
            models.HostActivity.pid == pid,
            models.HostActivity.host_id.in_(stale_host_ids),
            models.HostActivity.activity_type == "c2",
        ).delete(synchronize_session=False)


def _c2_update_last_sync(db, iid: str | None, ts: str) -> None:
    if not iid:
        return
    integrations_raw = (
        db.query(models.GlobalSetting).filter(models.GlobalSetting.key == _C2_SETTING_KEY).first()
    )
    if not integrations_raw:
        return
    raw_list = integrations_raw.value if isinstance(integrations_raw.value, list) else []
    for item in raw_list:
        if item.get("id") == iid:
            item["last_sync"] = ts
            break
    integrations_raw.value = raw_list
    db.commit()


def _broadcast_synced_hosts(db: "Session", pid: str, host_objects: list) -> None:
    for hobj in host_objects:
        try:
            db.refresh(hobj)
            bcast(pid, "host", "upsert", schemas.Host.model_validate(hobj).model_dump())
        except Exception as e:
            logger.debug("failed to broadcast synced host (pid=%s): %s", pid, e)


def _trigger_topology_rebuild_if_needed(pid: str, db: "Session", created_hosts: int) -> None:
    if created_hosts <= 0:
        return
    try:
        from ..topology import _run_auto_build
        _run_auto_build(pid, db)
    except Exception as e:
        logger.warning("C2 sync: topology auto-build failed for %s: %s", pid, e)


async def _do_project_sync_inner(cfg: dict, pid: str, db: Session, iid: str | None = None) -> dict:
    connector = _CONNECTORS.get(cfg["type"])
    if connector is None:
        raise HTTPException(400, f"Unsupported C2 type: {cfg.get('type')}")
    data = await connector(cfg)
    if data.get("error"):
        raise HTTPException(400, f"C2 sync failed: {data['error']}")
    ts = ts_now()
    created_hosts, updated_hosts, created_creds = 0, 0, 0
    source = cfg["type"]
    host_objects = []
    session_host_raw: list[tuple] = []

    for h in data.get("hosts", []):
        host_obj, c, u, cred_delta = _c2_sync_one_host(db, pid, h, source)
        if host_obj is None:
            continue
        created_hosts += c
        updated_hosts += u
        created_creds += cred_delta
        host_objects.append(host_obj)
        if _has_live_session_signal(h):
            session_host_raw.append((host_obj, h))

    for c in data.get("creds", []):
        if _c2_upsert_harvested_cred(db, pid, c, source):
            created_creds += 1

    _c2_record_c2_activities(db, pid, cfg, source, ts, session_host_raw, host_objects)

    log_event(
        db,
        pid,
        None,
        "c2",
        "sync",
        f"C2 sync [{cfg['name']}]: {created_hosts} new hosts, {updated_hosts} updated, {created_creds} creds",
        {"source": source, "integration": cfg["name"]},
    )
    db.commit()

    _c2_update_last_sync(db, iid, ts)

    _broadcast_synced_hosts(db, pid, host_objects)
    _trigger_topology_rebuild_if_needed(pid, db, created_hosts)

    return {
        "ok": True,
        "source": source,
        "hosts_found": len(data.get("hosts") or []),
        "hosts_created": created_hosts,
        "hosts_updated": updated_hosts,
        "creds_found": len(data.get("creds") or []),
        "creds_created": created_creds,
    }


@router.post("/{iid}/sync/{pid}", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
async def sync_to_project(
    iid: str,
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_c2()
    integrations = _load_integrations(db)
    cfg = next((c for c in integrations if c.get("id") == iid), None)
    if not cfg:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    if not cfg.get("enabled"):
        raise HTTPException(400, "Integration is disabled")
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    if not is_admin(user):
        from ...core.access import check_pid_access

        check_pid_access(db, pid, user, "hosts.create")
    try:
        return await _do_project_sync(cfg, pid, db, iid=iid, created_by=user.username)
    except httpx.HTTPStatusError as e:
        raise HTTPException(400, f"C2 API error {e.response.status_code}: {e.response.text[:300]}")
    except httpx.ConnectError as e:
        raise HTTPException(400, f"Connection failed: {e}")
    except Exception as e:
        raise HTTPException(400, f"Error: {e}")


@router.get("/for-project/{pid}", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
def list_for_project(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    from ...core.access import check_pid_access

    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    integrations = _load_integrations(db)
    visible = [_safe_integration(i) for i in _visible_integrations_for_pid(integrations, pid)]
    return visible


@router.get("/{iid}/bofs/{pid}", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
async def list_bofs_for_project(
    iid: str,
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_c2()
    from ...core.access import check_pid_access

    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    cfg = next(
        (
            i
            for i in _visible_integrations_for_pid(_load_integrations(db), pid)
            if i.get("id") == iid
        ),
        None,
    )
    if not cfg:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    if cfg.get("type") != "adaptix":
        return []
    try:
        return await _adaptix_fetch_bof_catalog(cfg)
    except Exception as e:
        logger.warning("Adaptix BOF catalog failed for %s: %s", iid, e)
        return []


@router.get("/agent-tasks/{pid}", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
async def get_agent_tasks(
    pid: str,
    integration_id: str,
    agent_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    limit: int = 30,
):
    _require_c2()
    from ...core.access import check_pid_access

    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    if not integration_id.strip() or not agent_id.strip():
        raise HTTPException(400, "integration_id and agent_id are required")
    cfg = next(
        (
            i
            for i in _visible_integrations_for_pid(_load_integrations(db), pid)
            if i.get("id") == integration_id
        ),
        None,
    )
    if not cfg:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    c2_type = (cfg.get("type") or "").lower()
    try:
        if c2_type == "adaptix":
            return await _adaptix_fetch_agent_tasks(cfg, agent_id, max(1, min(limit, 100)))
        if c2_type == "mythic":
            return await _mythic_fetch_agent_tasks(cfg, agent_id, max(1, min(limit, 100)))
        if c2_type == "sliver":
            return await _sliver_fetch_agent_tasks(cfg, agent_id, max(1, min(limit, 100)))
        raise HTTPException(400, f"Agent task history not supported for C2 type {c2_type!r}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Failed to fetch agent tasks: {e}")
