import asyncio
import io
import json
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from typing import Annotated
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ... import models
from ...core.access import check_pid_access
from ...core.deps import get_current_user
from ...core.events import bcast
from ...core.utils import new_id, ts_now
from ...database import get_db
from ...plugins.registry import registry

from ._data import BUILTIN_PLAYBOOKS, STEP_TEMPLATES, _PLAYBOOK_RUN_NOT_FOUND, _CMD_OUTPUTS_CREATE
from ._engine import (
    _launch_playbook_run,
    _now,
    _playbook_run_dict,
    _queue_playbook_jobs,
    _resolve_batch_hosts,
    _resolve_playbook,
    _run_dag,
    _run_sequence,
    _serialize_builtin,
    _serialize_custom,
    _update_run,
)
from ._models import BatchRunBody, OperationPackCreate, PlaybookBody, PlaybookRunBody
from ._data import _BUILTIN_PACKS
from ._validation import _is_dag_mode, _validate_playbook_payload

router = APIRouter(tags=["playbooks"])


@router.get("/api/playbooks")
def list_playbooks(db: Annotated[Session, Depends(get_db)]):
    builtin = [_serialize_builtin(item) for item in BUILTIN_PLAYBOOKS.values()]
    custom = [
        _serialize_custom(item)
        for item in db.query(models.CustomPlaybook)
        .order_by(models.CustomPlaybook.updated_at.desc())
        .all()
    ]
    return {"playbooks": builtin + custom}


@router.get("/api/playbooks/step-templates")
def list_step_templates():
    return {"templates": list(STEP_TEMPLATES.values())}


@router.post("/api/playbooks/validate")
def validate_playbook(body: PlaybookBody):
    return _validate_playbook_payload(body, registry.list_connectors())


@router.post("/api/playbooks/custom", status_code=201, responses={400: {"description": "Bad request"}})
def create_custom_playbook(
    body: PlaybookBody, user: Annotated[models.User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]
):
    validation = _validate_playbook_payload(body, registry.list_connectors())
    if not validation["ok"]:
        raise HTTPException(
            400, {"errors": validation["errors"], "warnings": validation["warnings"]}
        )
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


@router.patch("/api/playbooks/custom/{playbook_id}", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
def update_custom_playbook(
    playbook_id: str,
    body: PlaybookBody,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    playbook = (
        db.query(models.CustomPlaybook).filter(models.CustomPlaybook.id == playbook_id).first()
    )
    if not playbook:
        raise HTTPException(404, "Custom playbook not found")
    validation = _validate_playbook_payload(body, registry.list_connectors())
    if not validation["ok"]:
        raise HTTPException(
            400, {"errors": validation["errors"], "warnings": validation["warnings"]}
        )
    normalized = validation["normalized"]
    playbook.title = normalized["title"]
    playbook.description = normalized["description"]
    playbook.steps_json = normalized["steps"]
    playbook.updated_at = _now()
    db.commit()
    db.refresh(playbook)
    return _serialize_custom(playbook)


@router.delete("/api/playbooks/custom/{playbook_id}", status_code=204, responses={404: {"description": "Not found"}})
def delete_custom_playbook(
    playbook_id: str, user: Annotated[models.User, Depends(get_current_user)], db: Annotated[Session, Depends(get_db)]
):
    playbook = (
        db.query(models.CustomPlaybook).filter(models.CustomPlaybook.id == playbook_id).first()
    )
    if not playbook:
        raise HTTPException(404, "Custom playbook not found")
    db.delete(playbook)
    db.commit()


@router.get("/api/projects/{pid}/playbook-runs")
def list_playbook_runs(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    limit: int = 100,
):
    check_pid_access(db, pid, user, "command_outputs.read")
    runs = (
        db.query(models.PlaybookRun)
        .filter(models.PlaybookRun.pid == pid)
        .order_by(models.PlaybookRun.created_at.desc())
        .limit(limit)
        .all()
    )
    return {"runs": [_playbook_run_dict(run) for run in runs]}


@router.get("/api/projects/{pid}/playbook-runs/{run_id}", responses={404: {"description": "Not found"}})
def get_playbook_run(
    pid: str,
    run_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "command_outputs.read")
    run = (
        db.query(models.PlaybookRun)
        .filter(models.PlaybookRun.id == run_id, models.PlaybookRun.pid == pid)
        .first()
    )
    if not run:
        raise HTTPException(404, _PLAYBOOK_RUN_NOT_FOUND)
    return _playbook_run_dict(run)


@router.post("/api/projects/{pid}/playbooks/{playbook_id}/run", status_code=201, responses={404: {"description": "Not found"}})
async def run_playbook(
    pid: str,
    playbook_id: str,
    body: PlaybookRunBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, _CMD_OUTPUTS_CREATE)
    playbook = _resolve_playbook(db, playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    created_by = getattr(user, "username", "") or ""
    provisional_run_id = f"pbr_{uuid4().hex[:10]}"
    steps_list = playbook.get("steps", [])
    dag_mode = _is_dag_mode(steps_list)

    if dag_mode:
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
            jobs_json=[],
            request_json=body.model_dump(),
            result_json={"dag_mode": True},
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
        _task = asyncio.create_task(_run_dag(run.id, pid, playbook, body, created_by))
        return {
            "ok": True,
            "playbook_run": _playbook_run_dict(run),
            "playbook": {"id": playbook["id"], "title": playbook["title"]},
            "jobs": [],
            "dag_mode": True,
        }

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
    _task = asyncio.create_task(_run_sequence(run.id, [job.id for job in jobs], playbook.get("steps", [])))
    return {
        "ok": True,
        "playbook_run": _playbook_run_dict(run),
        "playbook": {"id": playbook["id"], "title": playbook["title"]},
        "jobs": [{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
    }


@router.post("/api/projects/{pid}/playbooks/{playbook_id}/batch-run", status_code=201, responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
async def batch_run_playbook(
    pid: str,
    playbook_id: str,
    body: BatchRunBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, _CMD_OUTPUTS_CREATE)
    playbook = _resolve_playbook(db, playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    hosts = _resolve_batch_hosts(db, pid, body)
    if not hosts:
        raise HTTPException(400, "No matching hosts found for the given filter")

    batch_id = f"batch_{uuid4().hex[:10]}"
    created_by = getattr(user, "username", "") or ""
    parallelism = max(1, min(body.parallelism, 10))

    runs_and_jobs: list[tuple[models.PlaybookRun, list[models.Job]]] = []
    for host in hosts:
        run_body = PlaybookRunBody(
            target=host.ip or "",
            target_url=body.target_url,
            flags=body.flags,
            severity=body.severity,
            keep_manual_positions=body.keep_manual_positions,
            create_missing_networks=body.create_missing_networks,
            username=body.username,
            password=body.password,
            domain=body.domain,
            hash=body.hash,
        )
        new_run_id = f"pbr_{uuid4().hex[:10]}"
        jobs = _queue_playbook_jobs(db, pid, playbook, run_body, created_by, new_run_id)
        run = models.PlaybookRun(
            id=new_run_id,
            pid=pid,
            playbook_id=playbook["id"],
            title=f"{playbook['title']} — {host.ip}",
            status="queued",
            created_by=created_by,
            created_at=_now(),
            started_at="",
            finished_at="",
            target=host.ip or "",
            error_output="",
            jobs_json=[{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
            request_json={**run_body.model_dump(), "batch_id": batch_id, "host_id": host.id},
            result_json={},
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
        runs_and_jobs.append((run, jobs))

    sem = asyncio.Semaphore(parallelism)

    async def _run_with_sem(run: models.PlaybookRun, job_ids: list[str], steps: list[dict]) -> None:
        async with sem:
            await _run_sequence(run.id, job_ids, steps)

    _batch_tasks: list[asyncio.Task] = []
    for run, jobs in runs_and_jobs:
        _batch_tasks.append(asyncio.create_task(_run_with_sem(run, [j.id for j in jobs], playbook.get("steps", []))))

    return {
        "ok": True,
        "batch_id": batch_id,
        "total": len(runs_and_jobs),
        "runs": [_playbook_run_dict(r) for r, _ in runs_and_jobs],
    }


@router.post("/api/projects/{pid}/playbook-runs/{run_id}/cancel", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}})
def cancel_playbook_run(
    pid: str,
    run_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, _CMD_OUTPUTS_CREATE)
    run = (
        db.query(models.PlaybookRun)
        .filter(models.PlaybookRun.id == run_id, models.PlaybookRun.pid == pid)
        .first()
    )
    if not run:
        raise HTTPException(404, _PLAYBOOK_RUN_NOT_FOUND)
    if run.status in ("done", "failed", "cancelled"):
        raise HTTPException(400, "Playbook run is already in a terminal state")
    jobs_json = list(run.jobs_json or [])
    active_ids = [
        item.get("id") for item in jobs_json if item.get("status") in ("queued", "running")
    ]
    for job_id in active_ids:
        job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
        if job and job.status in ("queued", "running"):
            job.status = "cancelled"
    for item in jobs_json:
        if item.get("status") in ("queued", "running"):
            item["status"] = "cancelled"
    _update_run(
        db,
        run,
        status="cancelled",
        finished_at=_now(),
        error_output="Cancelled by user",
        jobs_json=jobs_json,
        result_json={"cancelled_jobs": active_ids},
    )
    return _playbook_run_dict(run)


@router.post("/api/projects/{pid}/playbook-runs/{run_id}/rerun", status_code=201, responses={404: {"description": "Not found"}})
async def rerun_playbook_run(
    pid: str,
    run_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, _CMD_OUTPUTS_CREATE)
    run = (
        db.query(models.PlaybookRun)
        .filter(models.PlaybookRun.id == run_id, models.PlaybookRun.pid == pid)
        .first()
    )
    if not run:
        raise HTTPException(404, _PLAYBOOK_RUN_NOT_FOUND)
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
    _task = asyncio.create_task(
        _run_sequence(rerun.id, [job.id for job in jobs], playbook.get("steps", []))
    )
    return {"ok": True, "playbook_run": _playbook_run_dict(rerun)}


@router.get("/api/playbooks/custom/export")
def export_custom_playbooks(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    items = db.query(models.CustomPlaybook).order_by(models.CustomPlaybook.title).all()
    data = [
        {"title": p.title, "description": p.description, "steps": p.steps_json or []} for p in items
    ]
    payload = json.dumps(
        {"format": "rootnotes-playbooks", "version": "1", "playbooks": data},
        ensure_ascii=False,
        indent=2,
    ).encode()
    return StreamingResponse(
        io.BytesIO(payload),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="custom_playbooks.json"'},
    )


@router.post("/api/playbooks/custom/import", status_code=201)
async def import_custom_playbooks(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile, File(...)],
):
    raw = json.loads((await file.read()).decode())
    items = raw if isinstance(raw, list) else raw.get("playbooks", [])
    now = ts_now()
    created = skipped = 0
    existing_titles = {p.title.strip().lower() for p in db.query(models.CustomPlaybook).all()}
    for item in items:
        title = (item.get("title") or "").strip()
        if not title or title.lower() in existing_titles:
            skipped += 1
            continue
        db.add(
            models.CustomPlaybook(
                id=f"pbk_{uuid4().hex[:10]}",
                title=title,
                description=item.get("description", ""),
                steps_json=item.get("steps", []),
                created_by=user.username,
                created_at=now,
                updated_at=now,
            )
        )
        existing_titles.add(title.lower())
        created += 1
    db.commit()
    return {"created": created, "skipped": skipped}


@router.get("/api/playbooks/packs")
def list_operation_packs(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    custom = db.query(models.OperationPack).order_by(models.OperationPack.name).all()
    custom_out = [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "steps": p.steps or [],
            "tags": p.tags or [],
            "is_builtin": False,
            "created_by": p.created_by,
            "created_at": p.created_at,
        }
        for p in custom
    ]
    return {"packs": _BUILTIN_PACKS + custom_out}


@router.post("/api/playbooks/packs", status_code=201)
def create_operation_pack(
    body: OperationPackCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    now = ts_now()
    pack = models.OperationPack(
        id=f"pack_{uuid4().hex[:10]}",
        name=body.name,
        description=body.description,
        steps=body.steps,
        tags=body.tags,
        is_builtin=False,
        created_by=user.username,
        created_at=now,
    )
    db.add(pack)
    db.commit()
    db.refresh(pack)
    return {
        "id": pack.id,
        "name": pack.name,
        "description": pack.description,
        "steps": pack.steps or [],
        "tags": pack.tags or [],
        "is_builtin": False,
        "created_by": pack.created_by,
        "created_at": pack.created_at,
    }


@router.delete("/api/playbooks/packs/{pack_id}", status_code=204, responses={404: {"description": "Not found"}})
def delete_operation_pack(
    pack_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    pack = db.query(models.OperationPack).filter(models.OperationPack.id == pack_id).first()
    if not pack:
        raise HTTPException(404, "Pack not found")
    db.delete(pack)
    db.commit()
