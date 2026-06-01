"""
RootNotes — FastAPI application entry point.

This file assembles the application from domain modules.
Business logic lives in routers/, core/, and plugins/.
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from typing import Annotated
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy.orm import Session

from .core.logging_setup import configure_logging, get_logger
from .core.utils import ts_now, utcnow

configure_logging()
logger = get_logger(__name__)

from . import models
from .core.config import COOKIE_NAME, CORS_ORIGINS, UPLOAD_ROOT
from .core.crypto import (
    encrypt_str,
    loot_value_is_sensitive,
    note_content_is_confidential,
    validate_encryption_config,
)
from .core.deps import decode_ws_token, is_admin
from .core.enums import MemberRole, UserRole
from .core.limiter import limiter
from .core.security import decode_token, gen_password, hash_password
from .core.token_blacklist import is_blacklisted
from .core.utils import new_id
from .database import SessionLocal, engine, get_db
from .plugins.loader import initialize as init_plugins
from .plugins.registry import registry
from .plugins.state import list_modules as list_module_state
from .ws import manager


# ── Schema migrations via Alembic ─────────────────────────────────────
def _run_migrations() -> None:
    from pathlib import Path as _Path

    from alembic.config import Config

    from alembic import command

    cfg = Config(str(_Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", engine.url.render_as_string(hide_password=False))
    cfg.set_main_option("script_location", str(_Path(__file__).resolve().parent.parent / "alembic"))
    command.upgrade(cfg, "head")
    logger.info("Alembic migrations applied")


if os.environ.get("APP_ENV", "dev").lower() not in ("test", "testing"):
    _run_migrations()


def _fire_scheduled_playbook(sched, db, now) -> None:
    from .core.cron_utils import next_run
    from .routers.playbooks import _launch_playbook_run

    run_id = _launch_playbook_run(
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


# ── Scheduled playbooks background task ──────────────────────────────
def _maybe_fire_sched(sched, db, now) -> None:
    if not sched.next_run_at:
        return
    try:
        nr = datetime.strptime(sched.next_run_at, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return
    if now >= nr:
        _fire_scheduled_playbook(sched, db, now)


async def _scheduled_playbooks_loop():
    """Check and fire scheduled playbooks every minute."""
    await asyncio.sleep(60)  # let app fully start
    while True:
        try:
            db = SessionLocal()
            try:
                now = utcnow().replace(second=0, microsecond=0)
                scheds = (
                    db.query(models.ScheduledPlaybook)
                    .filter(models.ScheduledPlaybook.enabled)
                    .all()
                )
                for sched in scheds:
                    _maybe_fire_sched(sched, db, now)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[scheduler] loop error: %s", e)
        await asyncio.sleep(60)


def _c2_sync_is_due(cfg: dict, now) -> bool:
    interval = int(cfg.get("sync_interval_minutes") or 0)
    if interval <= 0:
        return False
    last_sync = cfg.get("last_sync")
    if not last_sync:
        return True
    try:
        last_dt = datetime.strptime(last_sync, "%Y-%m-%d %H:%M")
        return (now - last_dt).total_seconds() / 60 >= interval
    except Exception:
        return True


async def _c2_sync_one_integration(cfg: dict, db, _now) -> None:
    from .routers.c2 import _do_project_sync

    project_ids = cfg.get("project_ids") or []
    if not project_ids:
        project_ids = [p.id for p in db.query(models.Project).all()]
    for pid in project_ids:
        try:
            await _do_project_sync(cfg, pid, db, iid=cfg.get("id"), created_by="auto-sync")
            logger.info("[c2-auto-sync] %s → %s OK", cfg.get("name"), pid)
        except Exception as e:
            logger.warning("[c2-auto-sync] %s → %s failed: %s", cfg.get("name"), pid, e)


# ── C2 auto-sync background task ─────────────────────────────────────
async def _c2_auto_sync_loop():
    """Periodically sync C2 integrations that have sync_interval_minutes > 0."""
    await asyncio.sleep(30)  # initial delay to let app fully start
    while True:
        try:
            from .routers.c2 import _load_integrations

            db = SessionLocal()
            try:
                integrations = _load_integrations(db)
                now = utcnow()
                for cfg in integrations:
                    if not cfg.get("enabled") or not _c2_sync_is_due(cfg, now):
                        continue
                    await _c2_sync_one_integration(cfg, db, now)
            finally:
                db.close()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("[c2-auto-sync] loop error: %s", e)
        await asyncio.sleep(60)


def _ensure_admin_user(db) -> None:
    if db.query(models.User).count() != 0:
        return
    env_username = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
    env_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    password = env_password if env_password else gen_password()
    admin = models.User(
        id=new_id("u"),
        username=env_username,
        display_name=env_username,
        password_hash=hash_password(password),
        role=UserRole.ADMIN,
        created_at=ts_now(),
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


def _migrate_plaintext_secrets(db) -> None:
    plaintext_creds = [
        c for c in db.query(models.Cred).all()
        if c.secret and not c.secret.startswith(_ENC_PREFIX)
    ]
    if plaintext_creds:
        for c in plaintext_creds:
            c.secret = encrypt_str(c.secret)
        db.commit()
        logger.info("Migrated %d plaintext credential secrets to encrypted storage", len(plaintext_creds))

    plaintext_notes = [
        n for n in db.query(models.Note).all()
        if n.content and note_content_is_confidential(n.tags or [])
        and not n.content.startswith(_ENC_PREFIX)
    ]
    if plaintext_notes:
        for note in plaintext_notes:
            note.content = encrypt_str(note.content)
        db.commit()
        logger.info("Migrated %d confidential notes to encrypted storage", len(plaintext_notes))

    plaintext_loot = [
        loot for loot in db.query(models.Loot).all()
        if loot.value
        and loot_value_is_sensitive(loot.loot_type, loot.artifact_type, loot.filename, loot.storage_path, loot.public_url)
        and not loot.value.startswith(_ENC_PREFIX)
    ]
    if plaintext_loot:
        for loot in plaintext_loot:
            loot.value = encrypt_str(loot.value)
        db.commit()
        logger.info("Migrated %d sensitive loot values to encrypted storage", len(plaintext_loot))


def _backfill_project_owners(db) -> None:
    admin_users = (
        db.query(models.User)
        .filter(models.User.role == UserRole.ADMIN.value, models.User.active)
        .all()
    )
    if not admin_users:
        return
    first_admin = admin_users[0]
    projects_without_owner = (
        db.query(models.Project)
        .filter(
            ~models.Project.id.in_(
                db.query(models.ProjectMember.project_id).filter(
                    models.ProjectMember.role == MemberRole.OWNER,
                    models.ProjectMember.is_active,
                )
            )
        )
        .all()
    )
    for project in projects_without_owner:
        existing = (
            db.query(models.ProjectMember)
            .filter(
                models.ProjectMember.project_id == project.id,
                models.ProjectMember.user_id == first_admin.id,
            )
            .first()
        )
        if existing:
            existing.role = MemberRole.OWNER
            existing.is_active = True
        else:
            db.add(
                models.ProjectMember(
                    id=new_id("pm"),
                    project_id=project.id,
                    user_id=first_admin.id,
                    role=MemberRole.OWNER,
                    created_at=datetime.now(UTC).isoformat(),
                    created_by=first_admin.id,
                    is_active=True,
                )
            )
    db.commit()


# ── Lifespan: auto-create admin on first run ──────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    _test_mode = os.environ.get("APP_ENV", "dev").lower() in ("test", "testing")

    if _test_mode:
        # Skip all DB/pool/Redis startup in test mode — tests supply their own session.
        yield
        return

    validate_encryption_config()

    db = SessionLocal()
    try:
        _ensure_admin_user(db)
        _migrate_plaintext_secrets(db)
        _backfill_project_owners(db)
    finally:
        db.close()

    init_plugins(app)

    # ── arq pool (when WORKER_BACKEND=arq) ──────────────────────────────
    _arq_pool = None
    if os.environ.get("WORKER_BACKEND", "internal").lower() == "arq":
        try:
            from arq import create_pool as _arq_create_pool

            from .core.arq_pool import set_arq_pool
            from .core.arq_worker import _redis_settings_from_url

            _arq_pool = await _arq_create_pool(_redis_settings_from_url())
            set_arq_pool(_arq_pool)
            logger.info("arq Redis pool initialised (WORKER_BACKEND=arq)")
        except Exception as _arq_exc:
            logger.error(
                "Failed to initialise arq pool: %s — falling back to internal worker", _arq_exc
            )

    # Start worker pool + recovery
    from .core.worker_pool import get_pool, startup_recovery

    pool = get_pool()
    pool.start()
    recovery_db = SessionLocal()
    try:
        recovered = startup_recovery(recovery_db)
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
    if _arq_pool is not None:
        await _arq_pool.close()
        logger.info("arq Redis pool closed")
    await manager.shutdown()
    await asyncio.gather(task_c2, task_scheduler, return_exceptions=True)


# ── FastAPI app ───────────────────────────────────────────────────────
_ENC_PREFIX = "__enc__:"
_BEARER_PREFIX = "Bearer "


def _iter_file(safe, start: int, end: int, chunk: int = 1024 * 1024):
    with open(safe, "rb") as f:
        f.seek(start)
        remaining = end - start + 1
        while remaining > 0:
            data = f.read(min(chunk, remaining))
            if not data:
                break
            remaining -= len(data)
            yield data


def _parse_range_header(header: str, file_size: int) -> tuple[int, int] | None:
    """Return (start, end) for a valid Range header, or None for 416."""
    try:
        byte_range = header.replace("bytes=", "").strip()
        start_str, end_str = byte_range.split("-")
        start = int(start_str) if start_str else 0
        end = int(end_str) if end_str else file_size - 1
        end = min(end, file_size - 1)
    except Exception:
        return None
    if start > end or start >= file_size:
        return None
    return start, end


def _resolve_loot_meta(db, pid: str, disk_name: str, entity: str) -> tuple:
    """Return (loot_rec, content_type, orig_filename) for a download."""
    import mimetypes

    loot_rec = None
    orig_filename = disk_name
    content_type = None
    if entity == "loot":
        loot_rec = (
            db.query(models.Loot)
            .filter(models.Loot.pid == pid, models.Loot.storage_path.like(f"%{disk_name}"))
            .first()
        )
        if loot_rec:
            content_type = loot_rec.content_type or None
            orig_filename = loot_rec.filename or disk_name
    if not content_type:
        content_type = mimetypes.guess_type(orig_filename)[0] or "application/octet-stream"
    return loot_rec, content_type, orig_filename


async def _handle_ws_message(ws: WebSocket, pid: str, msg: dict) -> None:
    if msg.get("type") == "ping":
        await manager.touch_presence(ws)
        await ws.send_text('{"type":"pong"}')
        return
    if msg.get("type") == "focus":
        await manager.set_focus(ws, msg.get("note_id"))
    elif msg.get("type") == "blur":
        await manager.set_focus(ws, None)
    await manager.broadcast_presence(pid)

app = FastAPI(title="RootNotes API", lifespan=lifespan)
# Authenticated file downloads — replaces the unauthenticated StaticFiles mount.
# Token can be passed as ?token= query param for <a href> download links.

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Gzip JSON responses ≥1KB. Hosts/jobs/timeline list endpoints often
# return tens of KB of repetitive JSON keys — typical compression
# ratio is 5-10x. minimum_size avoids overhead on tiny payloads.
app.add_middleware(GZipMiddleware, minimum_size=1024)

# Unified error contract: every error response is {code, message, details?, detail}
from .core.errors import install_error_handlers  # noqa: E402

install_error_handlers(app)

# ── Auth middleware ───────────────────────────────────────────────────
_PUBLIC_PATHS = ("/api/auth/login", "/api/auth/setup", "/api/auth/status", "/api/webhooks/")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or path.startswith(_PUBLIC_PATHS):
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    # Cookie auth (httpOnly, set by /api/auth/login)
    if not auth.startswith(_BEARER_PREFIX):
        cookie_token = request.cookies.get(COOKIE_NAME, "")
        if cookie_token:
            auth = f"Bearer {cookie_token}"
    # SSE/EventSource can't set headers — allow token via query param for stream endpoints
    if not auth.startswith(_BEARER_PREFIX):
        qs_token = request.query_params.get("token", "")
        if qs_token:
            auth = f"Bearer {qs_token}"
    if not auth.startswith(_BEARER_PREFIX):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    payload = decode_token(auth[7:])
    if not payload:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)
    if await is_blacklisted(payload.get("jti", "")):
        return JSONResponse({"detail": "Token has been revoked"}, status_code=401)
    request.state.uid = payload["sub"]
    request.state.username = payload.get("username", "")
    request.state.role = payload.get("role", "user")
    if request.state.role == UserRole.VIEWER and request.method not in ("GET", "HEAD", "OPTIONS"):
        return JSONResponse({"detail": "Read-only account"}, status_code=403)
    return await call_next(request)


# CORSMiddleware must be added last so it becomes the outermost layer,
# handling OPTIONS preflight before auth_middleware can reject it.
_cors_origins = CORS_ORIGINS if CORS_ORIGINS else ["*"]
_cors_credentials = bool(CORS_ORIGINS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=_cors_credentials,
)


# ── Authenticated file downloads ─────────────────────────────────────

async def _authenticate_download_request(
    request: Request, db: Session
) -> tuple["models.User | None", "JSONResponse | None"]:
    token = request.headers.get("Authorization", "")
    if not token.startswith(_BEARER_PREFIX):
        qs = request.query_params.get("token", "")
        if qs:
            token = f"Bearer {qs}"
    if not token.startswith(_BEARER_PREFIX):
        return None, JSONResponse({"detail": "Not authenticated"}, status_code=401)
    user_payload = decode_token(token[7:])
    if not user_payload:
        return None, JSONResponse({"detail": "Invalid or expired token"}, status_code=401)
    if await is_blacklisted(user_payload.get("jti", "")):
        return None, JSONResponse({"detail": "Token has been revoked"}, status_code=401)
    user = db.query(models.User).filter(models.User.id == user_payload["sub"]).first()
    if not user or not user.active:
        return None, JSONResponse({"detail": "User not found"}, status_code=401)
    return user, None


def _serve_encrypted_loot_file(loot_rec, safe, content_type: str, disposition: str):
    if not (loot_rec and getattr(loot_rec, "file_encrypted", False)):
        return None
    from cryptography.fernet import InvalidToken

    from .core.crypto import decrypt_bytes as _decrypt_bytes
    from fastapi.responses import Response

    try:
        decrypted = _decrypt_bytes(safe.read_bytes())
    except (InvalidToken, Exception) as _exc:
        logger.error("Failed to decrypt loot file %s: %s", safe, _exc)
        return JSONResponse({"detail": "File decryption failed"}, status_code=500)
    return Response(
        content=decrypted,
        status_code=200,
        media_type=content_type,
        headers={"Content-Disposition": disposition, "Content-Length": str(len(decrypted))},
    )


def _serve_upload_range_response(safe, range_header: str, file_size: int, content_type: str, disposition: str):
    from fastapi.responses import Response
    from fastapi.responses import StreamingResponse as _SR

    parsed = _parse_range_header(range_header, file_size)
    if parsed is None:
        return Response(status_code=416, headers={"Content-Range": f"bytes */{file_size}"})
    start, end = parsed
    return _SR(
        _iter_file(safe, start, end),
        status_code=206,
        media_type=content_type,
        headers={
            "Content-Disposition": disposition,
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Content-Length": str(end - start + 1),
            "Accept-Ranges": "bytes",
        },
    )


@app.get("/api/uploads/{pid}/{path:path}")
async def download_upload(
    pid: str,
    path: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    user, err = await _authenticate_download_request(request, db)
    if err:
        return err

    from .core.access import check_pid_access as _check
    from .core.events import log_event as _log_event

    try:
        entity = "loot" if path.startswith("loot/") else "note_attachment"
        permission = "loot.read" if entity == "loot" else "notes.read"
        _check(db, pid, user, permission)
    except Exception:
        return JSONResponse({"detail": "Access denied"}, status_code=403)

    from .core.utils import ensure_under_upload_root

    target = UPLOAD_ROOT / pid / path
    try:
        safe = ensure_under_upload_root(target)
    except Exception:
        return JSONResponse({"detail": "Invalid path"}, status_code=400)

    if not safe.exists() or not safe.is_file():
        return JSONResponse({"detail": "File not found"}, status_code=404)

    _log_event(
        db,
        pid,
        getattr(user, "username", None),
        "audit",
        "download_sensitive_file",
        f"Downloaded {entity}: {safe.name}",
        {"path": path, "entity": entity},
    )
    db.commit()

    loot_rec, content_type, orig_filename = _resolve_loot_meta(db, pid, safe.name, entity)
    disposition = f'attachment; filename="{orig_filename}"'

    encrypted_resp = _serve_encrypted_loot_file(loot_rec, safe, content_type, disposition)
    if encrypted_resp is not None:
        return encrypted_resp

    from fastapi.responses import StreamingResponse as _SR

    file_size = safe.stat().st_size
    range_header = request.headers.get("Range")
    if range_header:
        return _serve_upload_range_response(safe, range_header, file_size, content_type, disposition)

    return _SR(
        _iter_file(safe, 0, file_size - 1),
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
async def websocket_endpoint(
    ws: WebSocket,
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    token: str = "",
):
    # Accept token from query param or cookie
    effective_token = token or ws.cookies.get(COOKIE_NAME, "")
    user = decode_ws_token(effective_token, db)
    if not user:
        await ws.close(code=4001)
        return
    from .core.permissions import get_membership, get_permissions_for_role

    is_global_admin = is_admin(user)
    if is_global_admin:
        # Global admins effectively have every project-level permission
        permissions: frozenset[str] = frozenset()
    else:
        membership = get_membership(db, pid, user.id)
        if not membership:
            await ws.close(code=4003)
            return
        permissions = frozenset(get_permissions_for_role(membership.role))
    await manager.connect(
        ws, pid, user.username, permissions=permissions, is_global_admin=is_global_admin
    )
    await manager.broadcast_presence(pid)
    try:
        while True:
            raw = await ws.receive_text()
            try:
                await _handle_ws_message(ws, pid, json.loads(raw))
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

    try:
        with engine.connect() as conn:
            conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        checks["db"] = "ok"
    except Exception as e:
        checks["db"] = f"error: {e}"

    try:
        import redis.asyncio as aioredis

        _redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = aioredis.from_url(_redis_url)
        await r.ping()
        await r.aclose()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {e}"

    try:
        usage = shutil.disk_usage("/data/uploads")
        free_pct = usage.free / usage.total * 100
        checks["disk_free_pct"] = round(free_pct, 1)
        checks["disk"] = "ok" if free_pct > 5 else "low"
    except Exception as e:
        checks["disk"] = f"error: {e}"

    try:
        from alembic.config import Config as AlembicConfig
        from alembic.script import ScriptDirectory

        _root = _Path(__file__).resolve().parent.parent
        cfg = AlembicConfig(str(_root / "alembic.ini"))
        cfg.set_main_option("script_location", str(_root / "alembic"))
        script = ScriptDirectory.from_config(cfg)
        head = script.get_current_head()
        from alembic.runtime.migration import MigrationContext

        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            current = context.get_current_revision()
        checks["migration"] = "ok" if current == head else f"pending ({current} → {head})"
    except Exception:
        checks["migration"] = "unknown"

    ok = all(
        v == "ok" or (isinstance(v, (int, float)) and v > 5)
        for v in checks.values()
    )
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
    activities,
    admin,
    ai,
    attack_graph,
    attack_paths,
    attacker_exec,
    auth,
    bulk_actions,
    c2,
    checklist,
    collections,
    cred_host_notes,
    creds,
    domains,
    export,
    findings,
    hosts,
    import_bloodhound,
    import_export,
    import_scanners,
    jobs,
    kb,
    loots,
    members,
    mitre,
    network_map,
    networks,
    notes,
    notifications,
    objectives,
    pivots,
    playbooks,
    project_templates,
    projects,
    report,
    scans,
    scheduled_playbooks,
    scopes,
    search,
    system_modules,
    templates,
    timeline,
    topology,
    webhooks,
)
from .routers import audit as audit_router

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(system_modules.router)
app.include_router(audit_router.router)
app.include_router(projects.router)
app.include_router(members.router)
app.include_router(hosts.router)
app.include_router(creds.router)
app.include_router(domains.router)
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
async def worker_status(db: Annotated[Session, Depends(get_db)]):
    from . import models as _models
    from .core.worker_pool import get_pool

    pool = get_pool()
    queued_db = db.query(_models.Job).filter(_models.Job.status == "queued").count()
    running_db = db.query(_models.Job).filter(_models.Job.status == "running").count()

    backend = os.environ.get("WORKER_BACKEND", "internal").lower()
    if backend == "arq":
        from .core.arq_pool import get_arq_pool
        from .core.arq_worker import ARQ_QUEUE_NAME

        arq_pool = get_arq_pool()
        arq_queue_size = 0
        if arq_pool is not None:
            try:
                arq_queue_size = await arq_pool.zcard(ARQ_QUEUE_NAME)
            except Exception:
                arq_queue_size = -1
        return {
            "backend": "arq",
            "arq_queue_size": arq_queue_size,
            "relay_queue_size": pool.queue_size,
            "queued_in_db": queued_db,
            "running_in_db": running_db,
        }

    return {
        "backend": "internal",
        "max_workers": pool._max_workers,
        "max_per_project": pool._max_per_project,
        "active": pool.active_count,
        "active_jobs": pool.active_jobs,
        "per_project": pool.per_project_counts,
        "queue_size": pool.queue_size,
        "queued_in_db": queued_db,
        "running_in_db": running_db,
    }
