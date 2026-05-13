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
from .core.crypto import encrypt_str, loot_value_is_sensitive, note_content_is_confidential
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
    conn.execute(text("ALTER TABLE networks ADD COLUMN IF NOT EXISTS meta_json JSONB NOT NULL DEFAULT '{}'"))
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
    conn.execute(text("CREATE TABLE IF NOT EXISTS pivot_observations (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, source_host_id TEXT NOT NULL DEFAULT '', pivot_host_id TEXT NOT NULL DEFAULT '', target_host_id TEXT NOT NULL DEFAULT '', tool TEXT NOT NULL DEFAULT '', pivot_type TEXT NOT NULL DEFAULT 'route', label TEXT NOT NULL DEFAULT '', route_cidr TEXT NOT NULL DEFAULT '', bind_address TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active', notes TEXT NOT NULL DEFAULT '', collector_target_id TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL, last_seen TEXT NOT NULL DEFAULT '')"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS attack_paths (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, name TEXT NOT NULL DEFAULT 'Attack Path', description TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS attack_steps (id TEXT PRIMARY KEY, path_id TEXT NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE, pid TEXT NOT NULL, step_order INTEGER NOT NULL DEFAULT 0, node_type TEXT NOT NULL DEFAULT 'host', label TEXT NOT NULL DEFAULT '', sublabel TEXT NOT NULL DEFAULT '', technique TEXT NOT NULL DEFAULT '', mitre_id TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS loots (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, host_id TEXT, loot_type TEXT NOT NULL DEFAULT 'file', value TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', source_path TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS filename TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS content_type TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS file_size INTEGER NOT NULL DEFAULT 0"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS storage_path TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS public_url TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS scopes (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, value TEXT NOT NULL, scope_type TEXT NOT NULL DEFAULT 'cidr', in_scope BOOLEAN NOT NULL DEFAULT TRUE, description TEXT NOT NULL DEFAULT '')"))
    conn.execute(text("ALTER TABLE scopes ADD COLUMN IF NOT EXISTS gateway_ip TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE scopes ADD COLUMN IF NOT EXISTS is_entry BOOLEAN NOT NULL DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE scopes ADD COLUMN IF NOT EXISTS via_host_id TEXT NOT NULL DEFAULT ''"))
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
            connector_key TEXT NOT NULL DEFAULT '',
            operation TEXT NOT NULL DEFAULT '',
            scope_type TEXT NOT NULL DEFAULT 'project',
            scope_id TEXT NOT NULL DEFAULT '',
            related_entity_type TEXT NOT NULL DEFAULT '',
            related_entity_id TEXT NOT NULL DEFAULT '',
            retry_of_job_id TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '',
            request_json JSONB NOT NULL DEFAULT '{}',
            result_json JSONB NOT NULL DEFAULT '{}'
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_jobs_pid ON jobs(pid)"))
    conn.execute(text("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS connector_key TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS operation TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scope_type TEXT NOT NULL DEFAULT 'project'"))
    conn.execute(text("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scope_id TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS related_entity_type TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS related_entity_id TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS retry_of_job_id TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS request_json JSONB NOT NULL DEFAULT '{}'"))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS playbook_runs (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            playbook_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'queued',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '',
            target TEXT NOT NULL DEFAULT '',
            error_output TEXT NOT NULL DEFAULT '',
            jobs_json JSONB NOT NULL DEFAULT '[]',
            request_json JSONB NOT NULL DEFAULT '{}',
            result_json JSONB NOT NULL DEFAULT '{}'
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_playbook_runs_pid ON playbook_runs(pid)"))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS custom_playbooks (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            steps_json JSONB NOT NULL DEFAULT '[]',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """))
    conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS import_source TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS scheduled_playbooks (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            playbook_id TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            cron_expr TEXT NOT NULL DEFAULT '0 * * * *',
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            body_json JSONB NOT NULL DEFAULT '{}',
            last_run_at TEXT NOT NULL DEFAULT '',
            next_run_at TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_scheduled_playbooks_pid ON scheduled_playbooks(pid)"))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS project_domains (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            aliases TEXT[] NOT NULL DEFAULT '{}',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_project_domains_pid ON project_domains(pid)"))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS kb_articles (
            id TEXT PRIMARY KEY,
            pid TEXT REFERENCES projects(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            content TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'General',
            tags TEXT[] NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_kb_articles_pid ON kb_articles(pid)"))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS host_collections (
            id TEXT PRIMARY KEY,
            pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            color TEXT NOT NULL DEFAULT '#4f8ef7',
            filters_json JSONB NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_host_collections_pid ON host_collections(pid)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_hosts_pid ON hosts(pid)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_creds_pid ON creds(pid)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_notes_pid ON notes(pid)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_notes_ts ON notes(ts DESC)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_pid ON findings(pid)"))
    conn.execute(text("ALTER TABLE findings ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual'"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(pid, source) WHERE source <> 'manual'"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_loots_pid ON loots(pid)"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS job_id TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS cred_id TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS finding_id TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS playbook_run_id TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS sha256 TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS artifact_type TEXT NOT NULL DEFAULT 'file'"))
    conn.execute(text("ALTER TABLE loots ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_loots_job_id ON loots(job_id) WHERE job_id <> ''"))
    conn.execute(text("ALTER TABLE host_activities ADD COLUMN IF NOT EXISTS job_id TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_host_activities_pid ON host_activities(pid)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_host_activities_host_id ON host_activities(host_id)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_cred_host_notes_cred_id ON cred_host_notes(cred_id)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_cred_host_notes_host_id ON cred_host_notes(host_id)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_attack_steps_path_id ON attack_steps(path_id)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_timeline_events_pid ON timeline_events(pid)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_timeline_events_ts ON timeline_events(ts DESC)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_checklist_items_pid ON checklist_items(pid)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_scopes_pid ON scopes(pid)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_objectives_pid ON objectives(pid)"))


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

    # Start background tasks
    task_c2 = asyncio.create_task(_c2_auto_sync_loop())
    task_scheduler = asyncio.create_task(_scheduled_playbooks_loop())
    yield
    task_c2.cancel()
    task_scheduler.cancel()
    await pool.stop()
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
            except Exception as e:
                logger.warning("WebSocket message parse error for pid=%s: %s", pid, e)
    except WebSocketDisconnect:
        manager.disconnect(ws, pid)
        await manager.broadcast_presence(pid)


# ── Health & presence ─────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok"}


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


@app.get("/api/worker/status", tags=["worker"])
async def worker_status(db: Session = Depends(get_db)):
    from .core.worker_pool import get_pool
    from . import models as _models
    pool = get_pool()
    queued_db = db.query(_models.Job).filter(_models.Job.status == "queued").count()
    running_db = db.query(_models.Job).filter(_models.Job.status == "running").count()
    return {
        "max_workers": pool._max_workers,
        "active": pool.active_count,
        "active_jobs": pool.active_jobs,
        "queue_size": pool.queue_size,
        "queued_in_db": queued_db,
        "running_in_db": running_db,
    }
