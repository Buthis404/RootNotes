import asyncio
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast
from ..core.job_runner import schedule_job_run
from ..core.job_tracker import queue_job
from ..database import SessionLocal, get_db

router = APIRouter(tags=["playbooks"])


class PlaybookRunBody(BaseModel):
    target: str = ""
    target_url: str = ""
    target_id: str | None = None
    flags: str = "-sV -sC -T4 --open"
    severity: str = "critical,high,medium"
    keep_manual_positions: bool = True
    create_missing_networks: bool = True


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


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


PLAYBOOKS = {
    "topology-refresh": {
        "id": "topology-refresh",
        "title": "Topology Refresh",
        "description": "Rebuild the operational graph from all known hosts.",
        "steps": [
            {"type": "topology", "operation": "auto_build", "title": "Topology auto-build"},
        ],
    },
    "internal-recon": {
        "id": "internal-recon",
        "title": "Internal Recon",
        "description": "Run an Nmap scan and then refresh topology from discovered hosts.",
        "steps": [
            {"type": "nmap", "operation": "scan", "title": "Nmap scan"},
            {"type": "topology", "operation": "auto_build", "title": "Topology auto-build"},
        ],
    },
    "web-triage": {
        "id": "web-triage",
        "title": "Web Triage",
        "description": "Run a Nuclei scan against a supplied target URL.",
        "steps": [
            {"type": "nuclei", "operation": "scan", "title": "Nuclei scan"},
        ],
    },
}


def _job_spec_for_step(pid: str, step: dict, body: PlaybookRunBody, created_by: str) -> dict:
    if step["type"] == "topology":
        return {
            "job_type": "topology",
            "title": step["title"],
            "connector_key": "topology",
            "operation": step["operation"],
            "related_entity_type": "network",
            "related_entity_id": pid,
            "request_json": {
                "keep_manual_positions": body.keep_manual_positions,
                "create_missing_networks": body.create_missing_networks,
            },
            "created_by": created_by,
        }
    if step["type"] == "nmap":
        if not body.target.strip():
            raise HTTPException(400, "This playbook requires target")
        return {
            "job_type": "nmap",
            "title": f"{step['title']}: {body.target.strip()}",
            "target": body.target.strip(),
            "command": f"nmap {body.flags} -oX - {body.target.strip()} 2>/dev/null",
            "connector_key": "nmap",
            "operation": "scan",
            "related_entity_type": "project",
            "related_entity_id": pid,
            "request_json": {
                "target": body.target.strip(),
                "flags": body.flags,
                "target_id": body.target_id,
                "timeout_seconds": 180,
            },
            "created_by": created_by,
        }
    if step["type"] == "nuclei":
        if not body.target_url.strip():
            raise HTTPException(400, "This playbook requires target_url")
        return {
            "job_type": "nuclei",
            "title": f"{step['title']}: {body.target_url.strip()}",
            "target": body.target_url.strip(),
            "command": f"nuclei -u {body.target_url.strip()} -severity {body.severity} -jsonl 2>/dev/null",
            "connector_key": "nuclei",
            "operation": "scan",
            "related_entity_type": "project",
            "related_entity_id": pid,
            "request_json": {
                "target": body.target_url.strip(),
                "severity": body.severity,
                "target_id": body.target_id,
                "timeout_seconds": 300,
                "templates": "",
                "extra_flags": "",
            },
            "created_by": created_by,
        }
    raise HTTPException(400, f"Unsupported playbook step type: {step['type']}")


async def _wait_for_job(job_id: str) -> dict:
    while True:
        await asyncio.sleep(1)
        db = SessionLocal()
        try:
            job = db.query(models.Job).filter(models.Job.id == job_id).first()
            if not job:
                return {"status": "missing"}
            if job.status in ("done", "failed", "cancelled"):
                return {"status": job.status, "id": job.id}
        finally:
            db.close()


async def _run_sequence(run_id: str, job_ids: list[str]) -> None:
    db = SessionLocal()
    try:
        run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
        if not run:
            return
        _update_run(db, run, status="running", started_at=run.started_at or _now())
    finally:
        db.close()

    completed = []
    for job_id in job_ids:
        schedule_job_run(job_id)
        result = await _wait_for_job(job_id)
        completed.append(result)
        if result.get("status") != "done":
            db = SessionLocal()
            try:
                run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
                if run:
                    terminal = "cancelled" if result.get("status") == "cancelled" else "failed"
                    _update_run(
                        db,
                        run,
                        status=terminal,
                        finished_at=_now(),
                        error_output=f"Step job {job_id} ended with status {result.get('status')}",
                        result_json={"completed_jobs": [item.get('id') for item in completed], "failed_job_id": job_id},
                    )
            finally:
                db.close()
            break
    else:
        db = SessionLocal()
        try:
            run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
            if run:
                _update_run(
                    db,
                    run,
                    status="done",
                    finished_at=_now(),
                    result_json={"completed_jobs": [item.get('id') for item in completed], "job_count": len(completed)},
                )
        finally:
            db.close()


@router.get("/api/playbooks")
def list_playbooks():
    return {"playbooks": list(PLAYBOOKS.values())}


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
    playbook = PLAYBOOKS.get(playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    run_id = f"pbr_{uuid4().hex[:10]}"
    queued_jobs = []
    for step in playbook["steps"]:
        spec = _job_spec_for_step(pid, step, body, getattr(user, "username", "") or "")
        queued_jobs.append(queue_job(
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
            request_json={**spec.get("request_json", {}), "playbook_id": playbook_id, "playbook_run_id": run_id},
        ))
    run = models.PlaybookRun(
        id=run_id,
        pid=pid,
        playbook_id=playbook_id,
        title=playbook["title"],
        status="queued",
        created_by=getattr(user, "username", "") or "",
        created_at=_now(),
        started_at="",
        finished_at="",
        target=body.target.strip() or body.target_url.strip(),
        error_output="",
        jobs_json=[{"id": job.id, "title": job.title, "status": job.status} for job in queued_jobs],
        request_json=body.model_dump(),
        result_json={},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
    asyncio.create_task(_run_sequence(run_id, [job.id for job in queued_jobs]))
    return {
        "ok": True,
        "playbook_run": _playbook_run_dict(run),
        "playbook": {"id": playbook["id"], "title": playbook["title"]},
        "jobs": [{"id": job.id, "title": job.title, "status": job.status} for job in queued_jobs],
    }
