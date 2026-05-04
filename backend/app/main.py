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
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from .core.logging_setup import configure_logging, get_logger

configure_logging()
logger = get_logger(__name__)

from . import models
from .database import get_db, engine, SessionLocal
from .ws import manager
from .core.config import JWT_SECRET, JWT_ALGO, UPLOAD_ROOT
from .core.limiter import limiter
from .core.security import decode_token, gen_password, hash_password
from .core.deps import decode_ws_token
from .core.utils import new_id
from .plugins.registry import registry
from .plugins.loader import initialize as init_plugins
from .plugins.state import list_modules as list_module_state

# ── Schema migrations (lightweight, idempotent) ───────────────────────
models.Base.metadata.create_all(bind=engine)

with engine.begin() as conn:
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS global_settings (key TEXT PRIMARY KEY, value JSONB NOT NULL DEFAULT '{}')"))
    conn.execute(text("ALTER TABLE networks ADD COLUMN IF NOT EXISTS background TEXT NOT NULL DEFAULT '#07080b'"))
    conn.execute(text("ALTER TABLE networks ADD COLUMN IF NOT EXISTS regions_json JSONB NOT NULL DEFAULT '[]'"))
    conn.execute(text("ALTER TABLE networks ALTER COLUMN name SET DEFAULT 'Network'"))
    conn.execute(text("UPDATE networks SET name = 'Network' WHERE name = 'Сеть'"))
    conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS ips TEXT[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS note_attachments (id TEXT PRIMARY KEY, note_id TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, filename TEXT NOT NULL, content_type TEXT NOT NULL DEFAULT 'application/octet-stream', file_size INTEGER NOT NULL DEFAULT 0, storage_path TEXT NOT NULL, public_url TEXT NOT NULL, ts TEXT NOT NULL)"))
    conn.execute(text("ALTER TABLE notes ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 0"))
    conn.execute(text("ALTER TABLE creds ADD COLUMN IF NOT EXISTS host_ids TEXT[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("ALTER TABLE creds ADD COLUMN IF NOT EXISTS is_domain BOOLEAN NOT NULL DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE creds ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("ALTER TABLE creds ADD COLUMN IF NOT EXISTS domain TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS domain TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'unknown'"))
    conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS is_attacker BOOLEAN NOT NULL DEFAULT FALSE"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, host_id TEXT, title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium', cvss TEXT NOT NULL DEFAULT '', cve TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', proof TEXT NOT NULL DEFAULT '', recommendation TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS checklist_items (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, phase TEXT NOT NULL, text TEXT NOT NULL, done BOOLEAN NOT NULL DEFAULT FALSE, order_idx INTEGER NOT NULL DEFAULT 0)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS timeline_events (id TEXT PRIMARY KEY, pid TEXT NOT NULL, username TEXT, entity TEXT NOT NULL, action TEXT NOT NULL, label TEXT NOT NULL, meta JSONB NOT NULL DEFAULT '{}', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS objectives (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, host_id TEXT, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'flag', points INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'not_started', flag_value TEXT NOT NULL DEFAULT '', captured_by TEXT NOT NULL DEFAULT '', captured_at TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS host_activities (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, title TEXT NOT NULL DEFAULT '', activity_type TEXT NOT NULL DEFAULT 'recon', command TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '', output TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'done', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS attack_paths (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, name TEXT NOT NULL DEFAULT 'Attack Path', description TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS attack_steps (id TEXT PRIMARY KEY, path_id TEXT NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE, pid TEXT NOT NULL, step_order INTEGER NOT NULL DEFAULT 0, node_type TEXT NOT NULL DEFAULT 'host', label TEXT NOT NULL DEFAULT '', sublabel TEXT NOT NULL DEFAULT '', technique TEXT NOT NULL DEFAULT '', mitre_id TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS loots (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, host_id TEXT, loot_type TEXT NOT NULL DEFAULT 'file', value TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', source_path TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS filename TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS content_type TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS file_size INTEGER NOT NULL DEFAULT 0"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS storage_path TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS public_url TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS scopes (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, value TEXT NOT NULL, scope_type TEXT NOT NULL DEFAULT 'cidr', in_scope BOOLEAN NOT NULL DEFAULT TRUE, description TEXT NOT NULL DEFAULT '')"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS cred_host_notes (id TEXT PRIMARY KEY, cred_id TEXT NOT NULL REFERENCES creds(id) ON DELETE CASCADE, host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, notes TEXT NOT NULL DEFAULT '', access TEXT[] NOT NULL DEFAULT '{}')"))
    conn.execute(text("ALTER TABLE cred_host_notes ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE cred_host_notes ADD COLUMN IF NOT EXISTS access TEXT[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS finding_templates_custom (id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium', cvss TEXT NOT NULL DEFAULT '', cve TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', proof TEXT NOT NULL DEFAULT '', recommendation TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS custom_snippets (id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'Misc', command TEXT NOT NULL DEFAULT '', tags TEXT[] NOT NULL DEFAULT '{}', opsec TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)"))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS project_members (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT NOT NULL,
            created_by TEXT,
            is_active BOOLEAN NOT NULL DEFAULT TRUE
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pm_project_id ON project_members(project_id)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_pm_user_id ON project_members(user_id)"))
    conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_pm_project_user ON project_members(project_id, user_id)"))
    conn.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS webhook_token TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_projects_webhook_token ON projects(webhook_token) WHERE webhook_token <> ''"))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            title TEXT NOT NULL DEFAULT '',
            target TEXT NOT NULL DEFAULT '',
            command TEXT NOT NULL DEFAULT '',
            output TEXT NOT NULL DEFAULT '',
            error_output TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '',
            result_json JSONB NOT NULL DEFAULT '{}'
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_jobs_pid ON jobs(pid)"))
    conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS import_source TEXT NOT NULL DEFAULT ''"))


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

    # Start C2 auto-sync background task
    task = asyncio.create_task(_c2_auto_sync_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ── FastAPI app ───────────────────────────────────────────────────────
app = FastAPI(title="RootNotes API", lifespan=lifespan)
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_ROOT)), name="uploads")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth middleware ───────────────────────────────────────────────────
_PUBLIC_PATHS = ("/api/auth/login", "/api/auth/setup", "/api/auth/status", "/api/webhooks/")

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or path.startswith(_PUBLIC_PATHS):
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
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


# ── WebSocket ─────────────────────────────────────────────────────────
@app.websocket("/ws/{pid}")
async def websocket_endpoint(ws: WebSocket, pid: str, token: str = "", db: Session = Depends(get_db)):
    user = decode_ws_token(token, db)
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
                if msg.get("type") == "focus":
                    manager.set_focus(ws, msg.get("note_id"))
                elif msg.get("type") == "blur":
                    manager.set_focus(ws, None)
                await manager.broadcast_presence(pid)
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(ws, pid)
        await manager.broadcast_presence(pid)


# ── Health & presence ─────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/presence")
def get_global_presence():
    return {"online": manager.get_all_online()}


# ── Modules endpoint ──────────────────────────────────────────────────
@app.get("/api/modules")
def list_modules():
    return {"modules": list_module_state()}


# ── Include all domain routers ────────────────────────────────────────
from .routers import (
    auth, admin, projects, hosts, creds, notes,
    networks, network_map, findings, checklist, timeline, objectives,
    activities, attack_paths, loots, scopes,
    cred_host_notes, search, templates, import_export, topology, members,
    system_modules, attacker_exec, export, project_templates,
    scans, webhooks, c2, jobs, bulk_actions,
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
