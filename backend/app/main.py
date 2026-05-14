"""
RootNotes — FastAPI application entry point.

This file assembles the application from domain modules.
Business logic lives in routers/, core/, and plugins/.
"""
import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy.orm import Session

from .core.logging_setup import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

from . import models
from .database import get_db, engine, SessionLocal
from .ws import manager
from .core.config import JWT_SECRET, JWT_ALGO, UPLOAD_ROOT, CORS_ORIGINS, COOKIE_NAME
from .core.limiter import limiter
from .core.security import decode_token, gen_password, hash_password
from .core.deps import decode_ws_token
from .core.utils import new_id
from .core.crypto import encrypt_str, loot_value_is_sensitive, note_content_is_confidential
from .plugins.registry import registry
from .plugins.loader import initialize as init_plugins
from .plugins.state import list_modules as list_module_state

# ── Schema migrations via Alembic ─────────────────────────────────────
def _run_migrations() -> None:
    from alembic.config import Config
    from alembic import command
    from pathlib import Path as _Path
    cfg = Config(str(_Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False))
    cfg.set_main_option("script_location", str(_Path(__file__).resolve().parent.parent / "alembic"))
    command.upgrade(cfg, "head")
    logger.info("Alembic migrations applied")

_run_migrations()


# ── Scheduled playbooks background task ──────────────────────────────
async def _scheduled_playbooks_loop():
    """Check and fire scheduled playbooks every minute."""
    await asyncio.sleep(60)  # let app fully start
    while True:
        try:
            from .core.cron_utils import cron_matches, next_run
            from .routers.playbooks import _launch_playbook_run
            db = SessionLocal()
            try:
                now = datetime.utcnow().replace(second=0, microsecond=0)
                scheds = db.query(models.ScheduledPlaybook).filter(
                    models.ScheduledPlaybook.enabled == True
                ).all()
                for sched in scheds:
                    if not sched.next_run_at:
                        continue
                    try:
                        nr = datetime.strptime(sched.next_run_at, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        continue
                    if now >= nr:
                        # Launch
                        run_id = await _launch_playbook_run(
                            pid=sched.pid,
                            playbook_id=sched.playbook_id,
                            body_dict=sched.body_json or {},
                            created_by="scheduler",
                        )
                        sched.last_run_at = now.strftime("%Y-%m-%d %H:%M:%S")
                        try:
                            sched.next_run_at = next_run(sched.cron_expr, after=now).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            sched.next_run_at = ""
                        db.commit()
                        logger.info("[scheduler] Fired schedule %s → run %s", sched.id, run_id)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[scheduler] loop error: %s", e)
        await asyncio.sleep(60)


# ── C2 auto-sync background task ─────────────────────────────────────
async def _c2_auto_sync_loop():
    """Periodically sync C2 integrations that have sync_interval_minutes > 0."""
    await asyncio.sleep(30)  # initial delay to let app fully start
    while True:
        try:
            from .routers.c2 import _load_integrations, _CONNECTORS, _C2_SETTING_KEY, _do_project_sync
            db = SessionLocal()
            try:
                integrations = _load_integrations(db)
                now = datetime.utcnow()
                for cfg in integrations:
                    if not cfg.get("enabled"):
                        continue
                    interval = int(cfg.get("sync_interval_minutes") or 0)
                    if interval <= 0:
                        continue
                    last_sync = cfg.get("last_sync")
                    if last_sync:
                        try:
                            last_dt = datetime.strptime(last_sync, "%Y-%m-%d %H:%M")
                            if (now - last_dt).total_seconds() / 60 < interval:
                                continue
                        except Exception:
                            pass
                    project_ids = cfg.get("project_ids") or []
                    if not project_ids:
                        project_ids = [p.id for p in db.query(models.Project).all()]
                    for pid in project_ids:
                        try:
                            await _do_project_sync(cfg, pid, db, iid=cfg.get("id"), created_by="auto-sync")
                            logger.info("[c2-auto-sync] %s → %s OK", cfg.get("name"), pid)
                        except Exception as e:
                            logger.warning("[c2-auto-sync] %s → %s failed: %s", cfg.get("name"), pid, e)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[c2-auto-sync] loop error: %s", e)
        await asyncio.sleep(60)


# ── Lifespan: auto-create admin on first run ──────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        if db.query(models.User).count() == 0:
            env_username = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
            env_password = os.environ.get("ADMIN_PASSWORD", "").strip()
            password = env_password if env_password else gen_password()
            admin = models.User(
                id=new_id("u"),
                username=env_username,
                display_name=env_username,
                password_hash=hash_password(password),
                role="admin",
                created_at=datetime.utcnow().isoformat()[:16],
                active=True,
            )
            db.add(admin)
            db.commit()
            border = "=" * 54
            logger.info(border)
            logger.info("  RootNotes — first run")
            logger.info("  Admin account created:")
            logger.info("  Username: %s", env_username)
            if not env_password:
                logger.info("  Password: %s  (set ADMIN_PASSWORD env var to choose)", password)
            else:
                logger.info("  Password: (from ADMIN_PASSWORD env var)")
            logger.info(border)

        # Migrate: encrypt any plaintext sensitive values left from before current security model.
        plaintext_creds = [c for c in db.query(models.Cred).all() if c.secret and not c.secret.startswith("__enc__:")]
        if plaintext_creds:
            for c in plaintext_creds:
                c.secret = encrypt_str(c.secret)
            db.commit()
            logger.info("Migrated %d plaintext credential secrets to encrypted storage", len(plaintext_creds))

        plaintext_confidential_notes = [n for n in db.query(models.Note).all() if n.content and note_content_is_confidential(n.tags or []) and not n.content.startswith("__enc__:")]
        if plaintext_confidential_notes:
            for note in plaintext_confidential_notes:
                note.content = encrypt_str(note.content)
            db.commit()
            logger.info("Migrated %d confidential notes to encrypted storage", len(plaintext_confidential_notes))

        plaintext_loot_values = [
            loot for loot in db.query(models.Loot).all()
            if loot.value and loot_value_is_sensitive(loot.loot_type, loot.artifact_type, loot.filename, loot.storage_path, loot.public_url) and not loot.value.startswith("__enc__:")
        ]
        if plaintext_loot_values:
            for loot in plaintext_loot_values:
                loot.value = encrypt_str(loot.value)
            db.commit()
            logger.info("Migrated %d sensitive loot values to encrypted storage", len(plaintext_loot_values))

        # Backfill: make admin user owner of all projects without owners
        admin_users = db.query(models.User).filter(models.User.role == "admin", models.User.active == True).all()
        if admin_users:
            first_admin = admin_users[0]
            projects_without_owner = db.query(models.Project).filter(
                ~models.Project.id.in_(
                    db.query(models.ProjectMember.project_id).filter(
                        models.ProjectMember.role == "owner",
                        models.ProjectMember.is_active == True,
                    )
                )
            ).all()
            from datetime import datetime as dt
            for project in projects_without_owner:
                existing = db.query(models.ProjectMember).filter(
                    models.ProjectMember.project_id == project.id,
                    models.ProjectMember.user_id == first_admin.id,
                ).first()
                if existing:
                    existing.role = "owner"
                    existing.is_active = True
                else:
                    db.add(models.ProjectMember(
                        id=new_id("pm"),
                        project_id=project.id,
                        user_id=first_admin.id,
                        role="owner",
                        created_at=dt.utcnow().isoformat(),
                        created_by=first_admin.id,
                        is_active=True,
                    ))
            db.commit()
    finally:
        db.close()

    init_plugins(app)

    # Start worker pool + recovery
    from .core.worker_pool import get_pool, startup_recovery
    pool = get_pool()
    await pool.start()
    recovery_db = SessionLocal()
    try:
        recovered = await startup_recovery(recovery_db)
        if recovered:
            import logging
            logging.getLogger(__name__).info("Recovered %d queued jobs on startup", recovered)
    finally:
        recovery_db.close()

    # Start Redis pub/sub for WebSocket broadcast
    await manager.startup()

    # Start background tasks
    task_c2 = asyncio.create_task(_c2_auto_sync_loop())
    task_scheduler = asyncio.create_task(_scheduled_playbooks_loop())
    yield
    task_c2.cancel()
    task_scheduler.cancel()
    await pool.stop()
    await manager.shutdown()
    for t in (task_c2, task_scheduler):
        try:
            await t
        except asyncio.CancelledError:
            pass


# ── FastAPI app ───────────────────────────────────────────────────────
app = FastAPI(title="RootNotes API", lifespan=lifespan)
# Authenticated file downloads — replaces the unauthenticated StaticFiles mount.
# Token can be passed as ?token= query param for <a href> download links.

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )

# ── Auth middleware ───────────────────────────────────────────────────
_PUBLIC_PATHS = ("/api/auth/login", "/api/auth/setup", "/api/auth/status", "/api/auth/logout", "/api/webhooks/")

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or path.startswith(_PUBLIC_PATHS):
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    # Cookie auth (httpOnly, set by /api/auth/login)
    if not auth.startswith("Bearer "):
        cookie_token = request.cookies.get(COOKIE_NAME, "")
        if cookie_token:
            auth = f"Bearer {cookie_token}"
    # SSE/EventSource can't set headers — allow token via query param for stream endpoints
    if not auth.startswith("Bearer "):
        qs_token = request.query_params.get("token", "")
        if qs_token:
            auth = f"Bearer {qs_token}"
    if not auth.startswith("Bearer "):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    payload = decode_token(auth[7:])
    if not payload:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)
    request.state.uid      = payload["sub"]
    request.state.username = payload.get("username", "")
    request.state.role     = payload.get("role", "user")
    if request.state.role == "viewer" and request.method not in ("GET", "HEAD", "OPTIONS"):
        return JSONResponse({"detail": "Read-only account"}, status_code=403)
    return await call_next(request)


# ── Authenticated file downloads ─────────────────────────────────────
@app.get("/api/uploads/{pid}/{path:path}")
async def download_upload(
    pid: str,
    path: str,
    request: Request,
    db: Session = Depends(get_db),
):
    from fastapi.responses import FileResponse
    from .core.access import check_pid_access
    from .core.deps import get_current_user_from_token

    token = request.headers.get("Authorization", "")
    if not token.startswith("Bearer "):
        qs = request.query_params.get("token", "")
        if qs:
            token = f"Bearer {qs}"
    if not token.startswith("Bearer "):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    user_payload = decode_token(token[7:])
    if not user_payload:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    user = db.query(models.User).filter(models.User.id == user_payload["sub"]).first()
    if not user or not user.active:
        return JSONResponse({"detail": "User not found"}, status_code=401)

    from .core.access import check_pid_access as _check
    from .core.events import log_event as _log_event
    try:
        entity = "loot" if path.startswith("loot/") else "note_attachment"
        permission = "loot.read" if entity == "loot" else "notes.read"
        _check(db, pid, user, permission)
    except Exception:
        return JSONResponse({"detail": "Access denied"}, status_code=403)

    # Resolve safe file path
    from .core.utils import ensure_under_upload_root
    from pathlib import Path as _Path
    target = UPLOAD_ROOT / pid / path
    try:
        safe = ensure_under_upload_root(target)
    except Exception:
        return JSONResponse({"detail": "Invalid path"}, status_code=400)

    if not safe.exists() or not safe.is_file():
        return JSONResponse({"detail": "File not found"}, status_code=404)

    _log_event(db, pid, getattr(user, "username", None), "audit", "download_sensitive_file", f"Downloaded {entity}: {safe.name}", {"path": path, "entity": entity})
    db.commit()

    # Look up original content_type and filename from DB
    from fastapi.responses import Response, StreamingResponse as _SR
    import mimetypes
    disk_name = safe.name
    content_type = None
    orig_filename = disk_name
    if entity == "loot":
        loot_rec = db.query(models.Loot).filter(
            models.Loot.pid == pid,
            models.Loot.storage_path.like(f"%{disk_name}")
        ).first()
        if loot_rec:
            content_type = loot_rec.content_type or None
            orig_filename = loot_rec.filename or disk_name
    if not content_type:
        content_type = mimetypes.guess_type(orig_filename)[0] or "application/octet-stream"

    file_size = safe.stat().st_size
    range_header = request.headers.get("Range")

    def _iter_file(start: int, end: int, chunk: int = 1024 * 1024):
        with open(safe, "rb") as f:
            f.seek(start)
            remaining = end - start + 1
            while remaining > 0:
                data = f.read(min(chunk, remaining))
                if not data:
                    break
                remaining -= len(data)
                yield data

    disposition = f'attachment; filename="{orig_filename}"'

    if range_header:
        # Parse Range: bytes=start-end
        try:
            byte_range = range_header.replace("bytes=", "").strip()
            start_str, end_str = byte_range.split("-")
            start = int(start_str) if start_str else 0
            end = int(end_str) if end_str else file_size - 1
            end = min(end, file_size - 1)
        except Exception:
            return Response(status_code=416, headers={"Content-Range": f"bytes */{file_size}"})
        if start > end or start >= file_size:
            return Response(status_code=416, headers={"Content-Range": f"bytes */{file_size}"})
        length = end - start + 1
        return _SR(
            _iter_file(start, end),
            status_code=206,
            media_type=content_type,
            headers={
                "Content-Disposition": disposition,
                "Content-Range": f"bytes {start}-{end}/{file_size}",
                "Content-Length": str(length),
                "Accept-Ranges": "bytes",
            },
        )

    return _SR(
        _iter_file(0, file_size - 1),
        status_code=200,
        media_type=content_type,
        headers={
            "Content-Disposition": disposition,
            "Content-Length": str(file_size),
            "Accept-Ranges": "bytes",
        },
    )


# ── WebSocket ─────────────────────────────────────────────────────────
@app.websocket("/ws/{pid}")
async def websocket_endpoint(ws: WebSocket, pid: str, token: str = "", db: Session = Depends(get_db)):
    # Accept token from query param or cookie
    effective_token = token or ws.cookies.get(COOKIE_NAME, "")
    user = decode_ws_token(effective_token, db)
    if not user:
        await ws.close(code=4001)
        return
    if user.role != "admin":
        from .core.permissions import get_membership
        membership = get_membership(db, pid, user.id)
        if not membership:
            await ws.close(code=4003)
            return
    await manager.connect(ws, pid, user.username)
    await manager.broadcast_presence(pid)
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
                if msg.get("type") == "ping":
                    await ws.send_text('{"type":"pong"}')
                    continue
                if msg.get("type") == "focus":
                    await manager.set_focus(ws, msg.get("note_id"))
                elif msg.get("type") == "blur":
                    await manager.set_focus(ws, None)
                await manager.broadcast_presence(pid)
            except Exception as e:
                logger.warning("WebSocket message parse error for pid=%s: %s", pid, e)
    except WebSocketDisconnect:
        await manager.disconnect(ws, pid)
        await manager.broadcast_presence(pid)


# ── Health & presence ─────────────────────────────────────────────────
@app.get("/health")
async def health():
    import shutil
    from .database import engine
    checks = {}

    # DB check
    try:
        with engine.connect() as conn:
            conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        checks["db"] = "ok"
    except Exception as e:
        checks["db"] = f"error: {e}"

    # Disk check (upload volume)
    try:
        usage = shutil.disk_usage("/data/uploads")
        free_pct = usage.free / usage.total * 100
        checks["disk_free_pct"] = round(free_pct, 1)
        checks["disk"] = "ok" if free_pct > 5 else "low"
    except Exception as e:
        checks["disk"] = f"error: {e}"

    ok = all(v == "ok" or (isinstance(v, (int, float)) and v > 5) for v in checks.values())
    return {"status": "ok" if ok else "degraded", **checks}


@app.get("/api/presence")
async def get_global_presence():
    return {"online": manager.get_all_online()}


# ── Modules endpoint ──────────────────────────────────────────────────
@app.get("/api/modules")
def list_modules():
    return {"modules": list_module_state()}


@app.get("/api/connectors")
def list_connectors():
    return {"connectors": registry.list_connectors()}


# ── Include all domain routers ────────────────────────────────────────
from .routers import (
    auth, admin, projects, hosts, creds, notes,
    networks, network_map, findings, checklist, timeline, objectives,
    activities, attack_paths, loots, scopes,
    cred_host_notes, search, templates, import_export, topology, members,
    system_modules, attacker_exec, export, project_templates,
    scans, webhooks, c2, jobs, bulk_actions, playbooks, notifications,
    scheduled_playbooks, domains,
    ai, import_scanners, attack_graph, kb, collections, pivots,
    import_bloodhound, mitre, report,
)

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(system_modules.router)
app.include_router(projects.router)
app.include_router(members.router)
app.include_router(hosts.router)
app.include_router(creds.router)
app.include_router(notes.router)
app.include_router(networks.router)
app.include_router(network_map.router)
app.include_router(findings.router)
app.include_router(checklist.router)
app.include_router(timeline.router)
app.include_router(objectives.router)
app.include_router(activities.router)
app.include_router(attack_paths.router)
app.include_router(loots.router)
app.include_router(scopes.router)
app.include_router(cred_host_notes.router)
app.include_router(search.router)
app.include_router(templates.router)
app.include_router(import_export.router)
app.include_router(topology.router)
app.include_router(attacker_exec.router)
app.include_router(export.router)
app.include_router(project_templates.router)
app.include_router(scans.router)
app.include_router(webhooks.router)
app.include_router(c2.router)
app.include_router(jobs.router)
app.include_router(bulk_actions.router)
app.include_router(playbooks.router)
app.include_router(notifications.router)
app.include_router(scheduled_playbooks.router)
app.include_router(domains.router)
app.include_router(ai.router)
app.include_router(import_scanners.router)
app.include_router(attack_graph.router)
app.include_router(kb.router)
app.include_router(collections.router)
app.include_router(pivots.router)
app.include_router(import_bloodhound.router)
app.include_router(mitre.router)
app.include_router(report.router)


@app.get("/api/worker/status", tags=["worker"])
async def worker_status(db: Session = Depends(get_db)):
    from .core.worker_pool import get_pool
    from . import models as _models
    pool = get_pool()
    queued_db = db.query(_models.Job).filter(_models.Job.status == "queued").count()
    running_db = db.query(_models.Job).filter(_models.Job.status == "running").count()
    return {
        "max_workers": pool._max_workers,
        "max_per_project": pool._max_per_project,
        "active": pool.active_count,
        "active_jobs": pool.active_jobs,
        "per_project": pool.per_project_counts,
        "queue_size": pool.queue_size,
        "queued_in_db": queued_db,
        "running_in_db": running_db,
    }
