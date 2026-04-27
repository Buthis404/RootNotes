import uuid
import asyncio
import json
import os
import re
import io
import zipfile
import tempfile
import secrets
import string
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime, timedelta
from typing import List
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext

from . import models, schemas
from .database import get_db, engine
from .ws import manager

models.Base.metadata.create_all(bind=engine)

UPLOAD_ROOT = Path(os.environ.get("UPLOAD_ROOT", "/data/uploads"))
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
SAFE_UPLOAD_RE = re.compile(r"[^A-Za-z0-9._-]+")

JWT_SECRET = os.environ.get("JWT_SECRET", "redteam-notes-change-me-in-production")
JWT_ALGO   = "HS256"
JWT_EXPIRE_HOURS = 24 * 7   # 1 week

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer  = HTTPBearer(auto_error=False)

_ALPHABET = string.ascii_letters + string.digits


def _gen_password(length: int = 12) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-create admin on first run (or when no users exist)
    from .database import SessionLocal
    db = SessionLocal()
    try:
        if db.query(models.User).count() == 0:
            env_username = os.environ.get("ADMIN_USERNAME", "admin").strip() or "admin"
            env_password = os.environ.get("ADMIN_PASSWORD", "").strip()
            password = env_password if env_password else _gen_password()
            admin = models.User(
                id=new_id("u"),
                username=env_username,
                password_hash=pwd_ctx.hash(password),
                role="admin",
                created_at=datetime.utcnow().isoformat()[:16],
                active=True,
            )
            db.add(admin)
            db.commit()
            border = "=" * 54
            print(f"\n{border}", flush=True)
            print("  RootNotes — first run", flush=True)
            print("  Admin account created:", flush=True)
            print(f"  Username: {env_username}", flush=True)
            if not env_password:
                print(f"  Password: {password}  (set ADMIN_PASSWORD env var to choose)", flush=True)
            else:
                print(f"  Password: (from ADMIN_PASSWORD env var)", flush=True)
            print(f"{border}\n", flush=True)
    finally:
        db.close()
    yield

# Lightweight schema migration for existing databases.
with engine.begin() as conn:
    conn.execute(text("ALTER TABLE networks ADD COLUMN IF NOT EXISTS background TEXT NOT NULL DEFAULT '#07080b'"))
    conn.execute(text("ALTER TABLE networks ADD COLUMN IF NOT EXISTS regions_json JSONB NOT NULL DEFAULT '[]'"))
    conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS ips TEXT[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS note_attachments (id TEXT PRIMARY KEY, note_id TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, filename TEXT NOT NULL, content_type TEXT NOT NULL DEFAULT 'application/octet-stream', file_size INTEGER NOT NULL DEFAULT 0, storage_path TEXT NOT NULL, public_url TEXT NOT NULL, ts TEXT NOT NULL)"))
    conn.execute(text("ALTER TABLE notes ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 0"))
    conn.execute(text("ALTER TABLE creds ADD COLUMN IF NOT EXISTS host_ids TEXT[] NOT NULL DEFAULT '{}'"))
    conn.execute(text("ALTER TABLE creds ADD COLUMN IF NOT EXISTS is_domain BOOLEAN NOT NULL DEFAULT FALSE"))
    conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS domain TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, host_id TEXT, title TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium', cvss TEXT NOT NULL DEFAULT '', cve TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', proof TEXT NOT NULL DEFAULT '', recommendation TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'open', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS checklist_items (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, phase TEXT NOT NULL, text TEXT NOT NULL, done BOOLEAN NOT NULL DEFAULT FALSE, order_idx INTEGER NOT NULL DEFAULT 0)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS timeline_events (id TEXT PRIMARY KEY, pid TEXT NOT NULL, username TEXT, entity TEXT NOT NULL, action TEXT NOT NULL, label TEXT NOT NULL, meta JSONB NOT NULL DEFAULT '{}', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS objectives (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, host_id TEXT, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'flag', points INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'not_started', flag_value TEXT NOT NULL DEFAULT '', captured_by TEXT NOT NULL DEFAULT '', captured_at TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS attack_paths (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, name TEXT NOT NULL DEFAULT 'Attack Path', description TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS attack_steps (id TEXT PRIMARY KEY, path_id TEXT NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE, pid TEXT NOT NULL, step_order INTEGER NOT NULL DEFAULT 0, node_type TEXT NOT NULL DEFAULT 'host', label TEXT NOT NULL DEFAULT '', sublabel TEXT NOT NULL DEFAULT '', technique TEXT NOT NULL DEFAULT '', mitre_id TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS loots (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, host_id TEXT, loot_type TEXT NOT NULL DEFAULT 'file', value TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', source_path TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS scopes (id TEXT PRIMARY KEY, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, value TEXT NOT NULL, scope_type TEXT NOT NULL DEFAULT 'cidr', in_scope BOOLEAN NOT NULL DEFAULT TRUE, description TEXT NOT NULL DEFAULT '')"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS cred_host_notes (id TEXT PRIMARY KEY, cred_id TEXT NOT NULL REFERENCES creds(id) ON DELETE CASCADE, host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, pid TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, notes TEXT NOT NULL DEFAULT '', access TEXT[] NOT NULL DEFAULT '{}')"))
    conn.execute(text("ALTER TABLE cred_host_notes ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT ''"))
    conn.execute(text("ALTER TABLE cred_host_notes ADD COLUMN IF NOT EXISTS access TEXT[] NOT NULL DEFAULT '{}'"))

app = FastAPI(title="RootNotes API", lifespan=lifespan)
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_ROOT)), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Auth helpers ──────────────────────────────────────────────────────
_PUBLIC_PATHS = ("/api/auth/login", "/api/auth/setup", "/api/auth/status")

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Allow public paths and non-API routes (static, WS handled separately)
    if not path.startswith("/api/") or path.startswith(_PUBLIC_PATHS):
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)
    try:
        payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALGO])
        request.state.uid      = payload["sub"]
        request.state.username = payload.get("username", "")
        request.state.role     = payload.get("role", "user")
    except JWTError:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)
    return await call_next(request)


def _make_token(user: models.User) -> str:
    exp = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode({"sub": user.id, "username": user.username, "role": user.role, "exp": exp}, JWT_SECRET, algorithm=JWT_ALGO)


def _token_response(user: models.User) -> dict:
    return {"access_token": _make_token(user), "token_type": "bearer",
            "user": schemas.UserOut.model_validate(user).model_dump()}


def get_current_user(request: Request, db: Session = Depends(get_db)) -> models.User:
    uid = getattr(request.state, "uid", None)
    if not uid:
        raise HTTPException(401, "Not authenticated")
    user = db.query(models.User).filter(models.User.id == uid, models.User.active == True).first()
    if not user:
        raise HTTPException(401, "User not found or inactive")
    return user


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user


def _decode_ws_token(token: str, db: Session) -> str:
    """Verify WS token, return display name or raise."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        uid = payload["sub"]
    except JWTError:
        return None
    user = db.query(models.User).filter(models.User.id == uid, models.User.active == True).first()
    return user.username if user else None


def new_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def safe_upload_name(name: str) -> str:
    base = Path(name or "attachment.bin").name
    cleaned = SAFE_UPLOAD_RE.sub("_", base).strip("._")
    return cleaned or "attachment.bin"


def ensure_under_upload_root(path: Path) -> Path:
    root = UPLOAD_ROOT.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise HTTPException(400, "Invalid upload path")
    return resolved


def log_event(db: Session, pid: str, username: str, entity: str, action: str, label: str, meta: dict = None):
    db.add(models.TimelineEvent(
        id=new_id("evt"), pid=pid, username=username,
        entity=entity, action=action, label=label,
        meta=meta or {}, ts=datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
    ))


def bcast(pid: str, entity: str, action: str, data: dict, ws=None):
    """Fire-and-forget broadcast helper callable from sync endpoints."""
    msg = {"pid": pid, "entity": entity, "action": action, "data": data}
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(manager.broadcast(pid, msg, exclude=ws))
    except RuntimeError:
        pass


# ── Auth endpoints ────────────────────────────────────────────────────
@app.get("/api/auth/status")
def auth_status(db: Session = Depends(get_db)):
    return {"initialized": db.query(models.User).count() > 0}


@app.post("/api/auth/setup", status_code=201)
def auth_setup(body: schemas.SetupRequest, db: Session = Depends(get_db)):
    if db.query(models.User).count() > 0:
        raise HTTPException(403, "Already initialized — use login")
    user = models.User(id=new_id("u"), username=body.username.strip(),
                       password_hash=pwd_ctx.hash(body.password),
                       role="admin", created_at=datetime.utcnow().isoformat()[:16], active=True)
    db.add(user); db.commit(); db.refresh(user)
    return _token_response(user)


@app.post("/api/auth/login")
def auth_login(body: schemas.LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == body.username.strip(), models.User.active == True).first()
    if not user or not pwd_ctx.verify(body.password, user.password_hash):
        raise HTTPException(401, "Неверный логин или пароль")
    return _token_response(user)


@app.get("/api/auth/me")
def auth_me(user: models.User = Depends(get_current_user)):
    return schemas.UserOut.model_validate(user)


# ── Admin endpoints ───────────────────────────────────────────────────
@app.get("/api/admin/users")
def admin_list_users(admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    return [schemas.UserOut.model_validate(u) for u in db.query(models.User).order_by(models.User.created_at).all()]


@app.post("/api/admin/users", status_code=201)
def admin_create_user(body: schemas.CreateUserRequest, admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == body.username.strip()).first():
        raise HTTPException(409, "Пользователь с таким логином уже существует")
    user = models.User(id=new_id("u"), username=body.username.strip(),
                       password_hash=pwd_ctx.hash(body.password),
                       role=body.role, created_at=datetime.utcnow().isoformat()[:16], active=True)
    db.add(user); db.commit(); db.refresh(user)
    return schemas.UserOut.model_validate(user)


@app.patch("/api/admin/users/{uid}")
def admin_update_user(uid: str, body: schemas.UpdateUserRequest, admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == uid).first()
    if not user:
        raise HTTPException(404, "User not found")
    if body.role is not None:
        if uid == admin.id and body.role != "admin":
            raise HTTPException(400, "Нельзя снять с себя роль администратора")
        user.role = body.role
    if body.active is not None:
        if uid == admin.id and not body.active:
            raise HTTPException(400, "Нельзя деактивировать себя")
        user.active = body.active
    if body.password:
        user.password_hash = pwd_ctx.hash(body.password)
    db.commit(); db.refresh(user)
    return schemas.UserOut.model_validate(user)


@app.delete("/api/admin/users/{uid}", status_code=204)
def admin_delete_user(uid: str, admin: models.User = Depends(require_admin), db: Session = Depends(get_db)):
    if uid == admin.id:
        raise HTTPException(400, "Нельзя удалить себя")
    user = db.query(models.User).filter(models.User.id == uid).first()
    if not user:
        raise HTTPException(404, "User not found")
    db.delete(user); db.commit()


# ── WebSocket endpoint ────────────────────────────────────────────────
@app.websocket("/ws/{pid}")
async def websocket_endpoint(ws: WebSocket, pid: str, token: str = "", db: Session = Depends(get_db)):
    username = _decode_ws_token(token, db)
    if not username:
        await ws.close(code=4001)
        return
    await manager.connect(ws, pid, username)
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


# ── Projects ─────────────────────────────────────────────────────────
@app.get("/api/projects", response_model=list[schemas.Project])
def list_projects(db: Session = Depends(get_db)):
    return db.query(models.Project).all()


@app.post("/api/projects", response_model=schemas.Project, status_code=201)
def create_project(body: schemas.ProjectCreate, db: Session = Depends(get_db)):
    project = models.Project(id=new_id("p"), **body.model_dump())
    db.add(project)
    db.commit()
    db.refresh(project)
    # Broadcast to all (no pid room yet, skip)
    return project


@app.patch("/api/projects/{pid}", response_model=schemas.Project)
def update_project(pid: str, body: schemas.ProjectUpdate, db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(project, k, v)
    db.commit()
    db.refresh(project)
    p = schemas.Project.model_validate(project)
    bcast(pid, "project", "update", p.model_dump())
    return project


@app.delete("/api/projects/{pid}", status_code=204)
def delete_project(pid: str, db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    db.delete(project)
    db.commit()
    bcast(pid, "project", "delete", {"id": pid})


# ── Notes ────────────────────────────────────────────────────────────
@app.get("/api/notes", response_model=list[schemas.Note])
def list_notes(pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Note)
    if pid:
        q = q.filter(models.Note.pid == pid)
    return q.all()


@app.post("/api/notes", response_model=schemas.Note, status_code=201)
def create_note(body: schemas.NoteCreate, request: Request, db: Session = Depends(get_db)):
    note = models.Note(id=new_id("n"), **body.model_dump())
    db.add(note)
    log_event(db, note.pid, getattr(request.state, 'username', None), 'note', 'create', f"Note created: «{note.title}»", {"id": note.id})
    db.commit()
    db.refresh(note)
    n = schemas.Note.model_validate(note)
    bcast(note.pid, "note", "create", n.model_dump())
    return note


@app.patch("/api/notes/{nid}", response_model=schemas.Note)
def update_note(nid: str, body: schemas.NoteUpdate, request: Request, db: Session = Depends(get_db)):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, "Note not found")
    if body.client_version is not None and body.client_version != note.version:
        raise HTTPException(status_code=409, detail=schemas.Note.model_validate(note).model_dump())
    old_title = note.title
    patch = body.model_dump(exclude_none=True, exclude={"client_version"})
    for k, v in patch.items():
        setattr(note, k, v)
    note.version += 1
    if body.title is not None and body.title != old_title:
        log_event(db, note.pid, getattr(request.state, 'username', None), 'note', 'update', f"Note renamed: «{old_title}» → «{note.title}»", {"id": note.id})
    db.commit()
    db.refresh(note)
    n = schemas.Note.model_validate(note)
    bcast(note.pid, "note", "update", n.model_dump())
    return note


@app.get("/api/notes/{nid}/attachments", response_model=list[schemas.NoteAttachment])
def list_note_attachments(nid: str, db: Session = Depends(get_db)):
    return db.query(models.NoteAttachment).filter(models.NoteAttachment.note_id == nid).all()


@app.post("/api/notes/{nid}/attachments", response_model=schemas.NoteAttachment, status_code=201)
async def upload_note_attachment(nid: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, "Note not found")
    safe_name = safe_upload_name(file.filename or "attachment.bin")
    att_id = new_id("att")
    ext = Path(safe_name).suffix
    note_dir = UPLOAD_ROOT / note.pid / nid
    note_dir.mkdir(parents=True, exist_ok=True)
    disk_name = f"{att_id}{ext}"
    disk_path = ensure_under_upload_root(note_dir / disk_name)
    content = await file.read()
    disk_path.write_bytes(content)
    attachment = models.NoteAttachment(
        id=att_id,
        note_id=nid,
        pid=note.pid,
        filename=safe_name,
        content_type=file.content_type or "application/octet-stream",
        file_size=len(content),
        storage_path=str(disk_path),
        public_url=f"/uploads/{note.pid}/{nid}/{disk_name}",
        ts=datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
    )
    db.add(attachment)
    db.commit()
    db.refresh(attachment)
    bcast(note.pid, "note_attachment", "create", schemas.NoteAttachment.model_validate(attachment).model_dump())
    return attachment


@app.delete("/api/attachments/{aid}", status_code=204)
def delete_attachment(aid: str, db: Session = Depends(get_db)):
    attachment = db.query(models.NoteAttachment).filter(models.NoteAttachment.id == aid).first()
    if not attachment:
        raise HTTPException(404, "Attachment not found")
    pid = attachment.pid
    note_id = attachment.note_id
    try:
        ensure_under_upload_root(Path(attachment.storage_path)).unlink(missing_ok=True)
    except Exception:
        pass
    db.delete(attachment)
    db.commit()
    bcast(pid, "note_attachment", "delete", {"id": aid, "note_id": note_id})


@app.delete("/api/notes/{nid}", status_code=204)
def delete_note(nid: str, request: Request, db: Session = Depends(get_db)):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, "Note not found")
    pid = note.pid
    log_event(db, pid, getattr(request.state, 'username', None), 'note', 'delete', f"Note deleted: «{note.title}»")
    db.delete(note)
    db.commit()
    bcast(pid, "note", "delete", {"id": nid})


# ── Hosts ────────────────────────────────────────────────────────────
@app.get("/api/hosts", response_model=list[schemas.Host])
def list_hosts(pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Host)
    if pid:
        q = q.filter(models.Host.pid == pid)
    return [schemas.Host.model_validate(h) for h in q.all()]


@app.post("/api/hosts", response_model=schemas.Host, status_code=201)
def create_host(body: schemas.HostCreate, request: Request, db: Session = Depends(get_db)):
    payload = body.model_dump()
    host = models.Host(id=new_id("hst"), **payload)
    db.add(host)
    label = f"Host added: {host.ip}" + (f" ({host.hostname})" if host.hostname else "")
    log_event(db, host.pid, getattr(request.state, 'username', None), 'host', 'create', label, {"ip": host.ip})
    db.commit()
    db.refresh(host)
    h = schemas.Host.model_validate(host)
    bcast(host.pid, "host", "create", h.model_dump())
    return host


@app.patch("/api/hosts/{hid}", response_model=schemas.Host)
def update_host(hid: str, body: schemas.HostUpdate, request: Request, db: Session = Depends(get_db)):
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    old_status = host.status
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(host, k, v)
    if body.status is not None and body.status != old_status:
        log_event(db, host.pid, getattr(request.state, 'username', None), 'host', 'status',
                  f"Host {host.ip} status → {host.status}", {"ip": host.ip, "old": old_status, "new": host.status})
    db.commit()
    db.refresh(host)
    h = schemas.Host.model_validate(host)
    bcast(host.pid, "host", "update", h.model_dump())
    return host


@app.delete("/api/hosts/{hid}", status_code=204)
def delete_host(hid: str, request: Request, db: Session = Depends(get_db)):
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    pid = host.pid
    log_event(db, pid, getattr(request.state, 'username', None), 'host', 'delete', f"Host deleted: {host.ip}", {"ip": host.ip})
    db.delete(host)
    db.commit()
    bcast(pid, "host", "delete", {"id": hid})


# ── Creds ────────────────────────────────────────────────────────────
@app.get("/api/creds", response_model=list[schemas.Cred])
def list_creds(pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Cred)
    if pid:
        q = q.filter(models.Cred.pid == pid)
    return q.all()


@app.post("/api/creds", response_model=schemas.Cred, status_code=201)
def create_cred(body: schemas.CredCreate, request: Request, db: Session = Depends(get_db)):
    cred = models.Cred(id=new_id("c"), **body.model_dump())
    db.add(cred)
    label = f"Cred added: {cred.username}" + (f"@{cred.host}" if cred.host else "")
    log_event(db, cred.pid, getattr(request.state, 'username', None), 'cred', 'create', label, {"username": cred.username})
    db.commit()
    db.refresh(cred)
    c = schemas.Cred.model_validate(cred)
    bcast(cred.pid, "cred", "create", c.model_dump())
    return cred


@app.patch("/api/creds/{cid}", response_model=schemas.Cred)
def update_cred(cid: str, body: schemas.CredUpdate, request: Request, db: Session = Depends(get_db)):
    cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
    if not cred:
        raise HTTPException(404, "Cred not found")
    old_cracked = cred.cracked
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(cred, k, v)
    if body.cracked is not None and body.cracked and not old_cracked:
        log_event(db, cred.pid, getattr(request.state, 'username', None), 'cred', 'cracked',
                  f"Cred cracked: {cred.username}", {"username": cred.username})
    db.commit()
    db.refresh(cred)
    c = schemas.Cred.model_validate(cred)
    bcast(cred.pid, "cred", "update", c.model_dump())
    return cred


@app.delete("/api/creds/{cid}", status_code=204)
def delete_cred(cid: str, request: Request, db: Session = Depends(get_db)):
    cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
    if not cred:
        raise HTTPException(404, "Cred not found")
    pid = cred.pid
    log_event(db, pid, getattr(request.state, 'username', None), 'cred', 'delete', f"Cred deleted: {cred.username}", {"username": cred.username})
    db.delete(cred)
    db.commit()
    bcast(pid, "cred", "delete", {"id": cid})


# ── Networks (multiple per project) ──────────────────────────────────
@app.get("/api/networks", response_model=list[schemas.Network])
def list_networks(pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Network)
    if pid:
        q = q.filter(models.Network.pid == pid)
    return [schemas.Network.from_orm_obj(n) for n in q.all()]


@app.post("/api/networks", response_model=schemas.Network, status_code=201)
def create_network(body: schemas.NetworkCreate, db: Session = Depends(get_db)):
    net = models.Network(id=new_id("net"), pid=body.pid, name=body.name, background=body.background, regions_json=[], nodes_json=[], edges_json=[])
    db.add(net)
    db.commit()
    db.refresh(net)
    result = schemas.Network.from_orm_obj(net)
    bcast(body.pid, "network", "create", result.model_dump())
    return result


@app.patch("/api/networks/{nid}", response_model=schemas.Network)
def update_network(nid: str, body: schemas.NetworkUpdate, db: Session = Depends(get_db)):
    net = db.query(models.Network).filter(models.Network.id == nid).first()
    if not net:
        raise HTTPException(404, "Network not found")
    if body.name is not None:
        net.name = body.name
    if body.background is not None:
        net.background = body.background
    if body.regions is not None:
        net.regions_json = body.regions
    if body.nodes is not None:
        net.nodes_json = body.nodes
    if body.edges is not None:
        net.edges_json = body.edges
    db.commit()
    db.refresh(net)
    result = schemas.Network.from_orm_obj(net)
    bcast(net.pid, "network", "update", result.model_dump())
    return result


@app.delete("/api/networks/{nid}", status_code=204)
def delete_network(nid: str, db: Session = Depends(get_db)):
    net = db.query(models.Network).filter(models.Network.id == nid).first()
    if not net:
        raise HTTPException(404, "Network not found")
    pid = net.pid
    db.delete(net)
    db.commit()
    bcast(pid, "network", "delete", {"id": nid})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/presence")
def get_global_presence():
    return {"online": manager.get_all_online()}


# ── Findings ──────────────────────────────────────────────────────────
@app.get("/api/findings", response_model=list[schemas.Finding])
def list_findings(pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Finding)
    if pid:
        q = q.filter(models.Finding.pid == pid)
    return q.all()


@app.post("/api/findings", response_model=schemas.Finding, status_code=201)
def create_finding(body: schemas.FindingCreate, request: Request, db: Session = Depends(get_db)):
    finding = models.Finding(id=new_id("f"), **body.model_dump())
    db.add(finding)
    log_event(db, finding.pid, getattr(request.state, 'username', None), 'finding', 'create',
              f"Finding [{finding.severity.upper()}]: {finding.title}", {"severity": finding.severity})
    db.commit()
    db.refresh(finding)
    f = schemas.Finding.model_validate(finding)
    bcast(finding.pid, "finding", "create", f.model_dump())
    return finding


@app.patch("/api/findings/{fid}", response_model=schemas.Finding)
def update_finding(fid: str, body: schemas.FindingUpdate, request: Request, db: Session = Depends(get_db)):
    finding = db.query(models.Finding).filter(models.Finding.id == fid).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    old_status = finding.status
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(finding, k, v)
    if body.status is not None and body.status != old_status:
        log_event(db, finding.pid, getattr(request.state, 'username', None), 'finding', 'status',
                  f"Finding «{finding.title}» status → {finding.status}", {"old": old_status, "new": finding.status})
    db.commit()
    db.refresh(finding)
    f = schemas.Finding.model_validate(finding)
    bcast(finding.pid, "finding", "update", f.model_dump())
    return finding


@app.delete("/api/findings/{fid}", status_code=204)
def delete_finding(fid: str, request: Request, db: Session = Depends(get_db)):
    finding = db.query(models.Finding).filter(models.Finding.id == fid).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    pid = finding.pid
    log_event(db, pid, getattr(request.state, 'username', None), 'finding', 'delete', f"Finding deleted: «{finding.title}»")
    db.delete(finding)
    db.commit()
    bcast(pid, "finding", "delete", {"id": fid})


# ── Checklist ─────────────────────────────────────────────────────────
@app.get("/api/checklist", response_model=list[schemas.ChecklistItem])
def list_checklist(pid: str, phase: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.ChecklistItem).filter(models.ChecklistItem.pid == pid)
    if phase:
        q = q.filter(models.ChecklistItem.phase == phase)
    return q.order_by(models.ChecklistItem.order_idx).all()


@app.post("/api/checklist", response_model=list[schemas.ChecklistItem], status_code=201)
def bulk_create_checklist(body: list[schemas.ChecklistItemCreate], db: Session = Depends(get_db)):
    items = [models.ChecklistItem(id=new_id("cl"), **item.model_dump()) for item in body]
    db.add_all(items)
    db.commit()
    for item in items:
        db.refresh(item)
    return items


@app.patch("/api/checklist/{cid}", response_model=schemas.ChecklistItem)
def update_checklist_item(cid: str, body: schemas.ChecklistItemUpdate, request: Request, db: Session = Depends(get_db)):
    item = db.query(models.ChecklistItem).filter(models.ChecklistItem.id == cid).first()
    if not item:
        raise HTTPException(404, "Checklist item not found")
    old_done = item.done
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(item, k, v)
    if body.done is not None and body.done != old_done:
        action = 'checked' if item.done else 'unchecked'
        log_event(db, item.pid, getattr(request.state, 'username', None), 'checklist', action,
                  f"Checklist [{item.phase}]: {item.text}", {"phase": item.phase})
    db.commit()
    db.refresh(item)
    return item


@app.delete("/api/checklist/{cid}", status_code=204)
def delete_checklist_item(cid: str, db: Session = Depends(get_db)):
    item = db.query(models.ChecklistItem).filter(models.ChecklistItem.id == cid).first()
    if not item:
        raise HTTPException(404, "Checklist item not found")
    db.delete(item)
    db.commit()


# ── Timeline ──────────────────────────────────────────────────────────
@app.get("/api/timeline", response_model=list[schemas.TimelineEvent])
def get_timeline(pid: str, entity: str | None = None, limit: int = 200, db: Session = Depends(get_db)):
    q = db.query(models.TimelineEvent).filter(models.TimelineEvent.pid == pid)
    if entity:
        q = q.filter(models.TimelineEvent.entity == entity)
    return q.order_by(models.TimelineEvent.ts.desc()).limit(limit).all()


# ── Objectives ────────────────────────────────────────────────────────
@app.get("/api/objectives", response_model=list[schemas.Objective])
def list_objectives(pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Objective)
    if pid:
        q = q.filter(models.Objective.pid == pid)
    return q.order_by(models.Objective.ts.desc()).all()

@app.post("/api/objectives", response_model=schemas.Objective)
def create_objective(body: schemas.ObjectiveCreate, request: Request, db: Session = Depends(get_db)):
    obj = models.Objective(**body.model_dump(), id=new_id("obj"), ts=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"))
    db.add(obj)
    log_event(db, obj.pid, getattr(request.state, 'username', None), 'objective', 'create',
              f"Objective added: {obj.title}", {"category": obj.category})
    db.commit()
    db.refresh(obj)
    bcast(obj.pid, "objective", "create", schemas.Objective.model_validate(obj).model_dump())
    return obj

@app.patch("/api/objectives/{oid}", response_model=schemas.Objective)
def update_objective(oid: str, body: schemas.ObjectiveUpdate, request: Request, db: Session = Depends(get_db)):
    obj = db.query(models.Objective).filter(models.Objective.id == oid).first()
    if not obj:
        raise HTTPException(404)
    old_status = obj.status
    updates = body.model_dump(exclude_none=True)
    for k, v in updates.items():
        setattr(obj, k, v)
    if body.status == "captured" and not obj.captured_at:
        obj.captured_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    if body.status is not None and body.status != old_status:
        log_event(db, obj.pid, getattr(request.state, 'username', None), 'objective', 'status',
                  f"Objective «{obj.title}» → {obj.status}", {"old": old_status, "new": obj.status})
    db.commit()
    db.refresh(obj)
    bcast(obj.pid, "objective", "update", schemas.Objective.model_validate(obj).model_dump())
    return obj

@app.delete("/api/objectives/{oid}")
def delete_objective(oid: str, request: Request, db: Session = Depends(get_db)):
    obj = db.query(models.Objective).filter(models.Objective.id == oid).first()
    if not obj:
        raise HTTPException(404)
    pid = obj.pid
    log_event(db, pid, getattr(request.state, 'username', None), 'objective', 'delete',
              f"Objective deleted: {obj.title}")
    db.delete(obj)
    db.commit()
    bcast(pid, "objective", "delete", {"id": oid})
    return {"ok": True}


# ── Attack Paths ─────────────────────────────────────────────────────
@app.get("/api/attack-paths", response_model=list[schemas.AttackPath])
def list_attack_paths(pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.AttackPath)
    if pid:
        q = q.filter(models.AttackPath.pid == pid)
    return q.order_by(models.AttackPath.ts).all()

@app.post("/api/attack-paths", response_model=schemas.AttackPath)
def create_attack_path(body: schemas.AttackPathCreate, request: Request, db: Session = Depends(get_db)):
    ap = models.AttackPath(**body.model_dump(), id=new_id("ap"), ts=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"))
    db.add(ap)
    log_event(db, ap.pid, getattr(request.state, 'username', None), 'attack_path', 'create',
              f"Attack path created: {ap.name}")
    db.commit()
    db.refresh(ap)
    bcast(ap.pid, "attack_path", "create", schemas.AttackPath.model_validate(ap).model_dump())
    return ap

@app.patch("/api/attack-paths/{ap_id}", response_model=schemas.AttackPath)
def update_attack_path(ap_id: str, body: schemas.AttackPathUpdate, db: Session = Depends(get_db)):
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == ap_id).first()
    if not ap:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(ap, k, v)
    db.commit()
    db.refresh(ap)
    bcast(ap.pid, "attack_path", "update", schemas.AttackPath.model_validate(ap).model_dump())
    return ap

@app.delete("/api/attack-paths/{ap_id}")
def delete_attack_path(ap_id: str, request: Request, db: Session = Depends(get_db)):
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == ap_id).first()
    if not ap:
        raise HTTPException(404)
    pid = ap.pid
    log_event(db, pid, getattr(request.state, 'username', None), 'attack_path', 'delete',
              f"Attack path deleted: {ap.name}")
    db.delete(ap)
    db.commit()
    bcast(pid, "attack_path", "delete", {"id": ap_id})
    return {"ok": True}

@app.get("/api/attack-steps", response_model=list[schemas.AttackStep])
def list_attack_steps(path_id: str | None = None, pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.AttackStep)
    if path_id:
        q = q.filter(models.AttackStep.path_id == path_id)
    elif pid:
        q = q.filter(models.AttackStep.pid == pid)
    return q.order_by(models.AttackStep.step_order).all()

@app.post("/api/attack-steps", response_model=schemas.AttackStep)
def create_attack_step(body: schemas.AttackStepCreate, db: Session = Depends(get_db)):
    step = models.AttackStep(**body.model_dump(), id=new_id("as"), ts=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"))
    db.add(step)
    db.commit()
    db.refresh(step)
    bcast(step.pid, "attack_step", "create", schemas.AttackStep.model_validate(step).model_dump())
    return step

@app.patch("/api/attack-steps/{step_id}", response_model=schemas.AttackStep)
def update_attack_step(step_id: str, body: schemas.AttackStepUpdate, db: Session = Depends(get_db)):
    step = db.query(models.AttackStep).filter(models.AttackStep.id == step_id).first()
    if not step:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(step, k, v)
    db.commit()
    db.refresh(step)
    bcast(step.pid, "attack_step", "update", schemas.AttackStep.model_validate(step).model_dump())
    return step

@app.delete("/api/attack-steps/{step_id}")
def delete_attack_step(step_id: str, db: Session = Depends(get_db)):
    step = db.query(models.AttackStep).filter(models.AttackStep.id == step_id).first()
    if not step:
        raise HTTPException(404)
    pid = step.pid
    db.delete(step)
    db.commit()
    bcast(pid, "attack_step", "delete", {"id": step_id})
    return {"ok": True}


# ── Loot ─────────────────────────────────────────────────────────────
@app.get("/api/loots", response_model=list[schemas.Loot])
def list_loots(pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Loot)
    if pid:
        q = q.filter(models.Loot.pid == pid)
    return q.order_by(models.Loot.ts.desc()).all()

@app.post("/api/loots", response_model=schemas.Loot, status_code=201)
def create_loot(body: schemas.LootCreate, request: Request, db: Session = Depends(get_db)):
    loot = models.Loot(**body.model_dump(), id=new_id("lt"), ts=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"))
    db.add(loot)
    log_event(db, loot.pid, getattr(request.state, 'username', None), 'loot', 'create',
              f"Loot [{loot.loot_type}]: {(loot.value or loot.description or '')[:40]}")
    db.commit()
    db.refresh(loot)
    bcast(loot.pid, "loot", "create", schemas.Loot.model_validate(loot).model_dump())
    return loot

@app.patch("/api/loots/{lid}", response_model=schemas.Loot)
def update_loot(lid: str, body: schemas.LootUpdate, db: Session = Depends(get_db)):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(loot, k, v)
    db.commit()
    db.refresh(loot)
    bcast(loot.pid, "loot", "update", schemas.Loot.model_validate(loot).model_dump())
    return loot

@app.delete("/api/loots/{lid}", status_code=204)
def delete_loot(lid: str, request: Request, db: Session = Depends(get_db)):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404)
    pid = loot.pid
    log_event(db, pid, getattr(request.state, 'username', None), 'loot', 'delete',
              f"Loot deleted: {(loot.value or loot.description or '')[:40]}")
    db.delete(loot)
    db.commit()
    bcast(pid, "loot", "delete", {"id": lid})


# ── Scope ─────────────────────────────────────────────────────────────
@app.get("/api/scopes", response_model=list[schemas.Scope])
def list_scopes(pid: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.Scope)
    if pid:
        q = q.filter(models.Scope.pid == pid)
    return q.all()

@app.post("/api/scopes", response_model=schemas.Scope, status_code=201)
def create_scope(body: schemas.ScopeCreate, request: Request, db: Session = Depends(get_db)):
    scope = models.Scope(**body.model_dump(), id=new_id("sc"))
    db.add(scope)
    log_event(db, scope.pid, getattr(request.state, 'username', None), 'scope', 'create',
              f"Scope {'added' if scope.in_scope else 'excluded'}: {scope.value}", {"type": scope.scope_type})
    db.commit()
    db.refresh(scope)
    bcast(scope.pid, "scope", "create", schemas.Scope.model_validate(scope).model_dump())
    return scope

@app.patch("/api/scopes/{sid}", response_model=schemas.Scope)
def update_scope(sid: str, body: schemas.ScopeUpdate, db: Session = Depends(get_db)):
    scope = db.query(models.Scope).filter(models.Scope.id == sid).first()
    if not scope:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(scope, k, v)
    db.commit()
    db.refresh(scope)
    bcast(scope.pid, "scope", "update", schemas.Scope.model_validate(scope).model_dump())
    return scope

@app.delete("/api/scopes/{sid}", status_code=204)
def delete_scope(sid: str, request: Request, db: Session = Depends(get_db)):
    scope = db.query(models.Scope).filter(models.Scope.id == sid).first()
    if not scope:
        raise HTTPException(404)
    pid = scope.pid
    log_event(db, pid, getattr(request.state, 'username', None), 'scope', 'delete',
              f"Scope removed: {scope.value}")
    db.delete(scope)
    db.commit()
    bcast(pid, "scope", "delete", {"id": sid})


# ── CredHostNotes ─────────────────────────────────────────────────────
@app.get("/api/cred-host-notes", response_model=list[schemas.CredHostNote])
def list_cred_host_notes(pid: str | None = None, cred_id: str | None = None, host_id: str | None = None, db: Session = Depends(get_db)):
    q = db.query(models.CredHostNote)
    if pid:
        q = q.filter(models.CredHostNote.pid == pid)
    if cred_id:
        q = q.filter(models.CredHostNote.cred_id == cred_id)
    if host_id:
        q = q.filter(models.CredHostNote.host_id == host_id)
    return q.all()

@app.post("/api/cred-host-notes", response_model=schemas.CredHostNote, status_code=201)
def create_cred_host_note(body: schemas.CredHostNoteCreate, db: Session = Depends(get_db)):
    existing = db.query(models.CredHostNote).filter(
        models.CredHostNote.cred_id == body.cred_id,
        models.CredHostNote.host_id == body.host_id
    ).first()
    if existing:
        for k, v in body.model_dump(exclude={"cred_id", "host_id", "pid"}).items():
            setattr(existing, k, v)
        db.commit()
        db.refresh(existing)
        return existing
    note = models.CredHostNote(id=new_id("chn"), **body.model_dump())
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

@app.patch("/api/cred-host-notes/{nid}", response_model=schemas.CredHostNote)
def update_cred_host_note(nid: str, body: schemas.CredHostNoteUpdate, db: Session = Depends(get_db)):
    note = db.query(models.CredHostNote).filter(models.CredHostNote.id == nid).first()
    if not note:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(note, k, v)
    db.commit()
    db.refresh(note)
    return note

@app.delete("/api/cred-host-notes/{nid}", status_code=204)
def delete_cred_host_note(nid: str, db: Session = Depends(get_db)):
    note = db.query(models.CredHostNote).filter(models.CredHostNote.id == nid).first()
    if not note:
        raise HTTPException(404)
    db.delete(note)
    db.commit()


# ── Search ────────────────────────────────────────────────────────────
@app.get("/api/search")
def search(q: str = "", pid: str = "", limit: int = 30, db: Session = Depends(get_db)):
    if not q or len(q) < 2:
        return {"hosts": [], "creds": [], "notes": [], "findings": [], "loots": []}
    ql = q.lower()

    def match_host(h):
        return ql in (f"{h.ip} {h.hostname} {h.notes} {' '.join(h.tags or [])}").lower()

    def match_cred(c):
        return ql in (f"{c.username} {c.service} {c.host} {c.notes}").lower()

    def match_note(n):
        return ql in (f"{n.title} {n.content[:500]} {' '.join(n.tags or [])}").lower()

    def match_finding(f):
        return ql in (f"{f.title} {f.description[:300]} {f.cve}").lower()

    def match_loot(l):
        return ql in (f"{l.value} {l.description} {l.source_path}").lower()

    hq = db.query(models.Host)
    cq = db.query(models.Cred)
    nq = db.query(models.Note)
    fq = db.query(models.Finding)
    lq = db.query(models.Loot)
    if pid:
        hq = hq.filter(models.Host.pid == pid)
        cq = cq.filter(models.Cred.pid == pid)
        nq = nq.filter(models.Note.pid == pid)
        fq = fq.filter(models.Finding.pid == pid)
        lq = lq.filter(models.Loot.pid == pid)

    hosts    = [schemas.Host.model_validate(h).model_dump() for h in hq.all() if match_host(h)][:limit]
    creds    = [schemas.Cred.model_validate(c).model_dump() for c in cq.all() if match_cred(c)][:limit]
    notes    = [schemas.Note.model_validate(n).model_dump() for n in nq.all() if match_note(n)][:limit]
    findings = [schemas.Finding.model_validate(f).model_dump() for f in fq.all() if match_finding(f)][:limit]
    loots    = [schemas.Loot.model_validate(l).model_dump() for l in lq.all() if match_loot(l)][:limit]
    return {"hosts": hosts, "creds": creds, "notes": notes, "findings": findings, "loots": loots}


# ── Export / Import ───────────────────────────────────────────────────

@app.get("/api/export/{pid}")
def export_project(pid: str, db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")

    notes        = db.query(models.Note).filter(models.Note.pid == pid).all()
    hosts        = db.query(models.Host).filter(models.Host.pid == pid).all()
    creds        = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    networks     = db.query(models.Network).filter(models.Network.pid == pid).all()
    attachments  = db.query(models.NoteAttachment).filter(models.NoteAttachment.pid == pid).all()
    findings     = db.query(models.Finding).filter(models.Finding.pid == pid).all()
    objectives   = db.query(models.Objective).filter(models.Objective.pid == pid).all()
    attack_paths = db.query(models.AttackPath).filter(models.AttackPath.pid == pid).all()
    attack_steps = db.query(models.AttackStep).filter(models.AttackStep.pid == pid).all()
    loots        = db.query(models.Loot).filter(models.Loot.pid == pid).all()
    scopes       = db.query(models.Scope).filter(models.Scope.pid == pid).all()
    checklist    = db.query(models.ChecklistItem).filter(models.ChecklistItem.pid == pid).all()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("project.json", json.dumps({
            "id": project.id, "name": project.name, "ip": project.ip,
            "os": project.os, "status": project.status,
            "added": project.added, "description": project.description,
        }, ensure_ascii=False))

        zf.writestr("notes.json", json.dumps([{
            "id": n.id, "title": n.title, "content": n.content,
            "phase": n.phase, "tags": n.tags, "ts": n.ts, "starred": n.starred,
        } for n in notes], ensure_ascii=False))

        zf.writestr("hosts.json", json.dumps([{
            "id": h.id, "ip": h.ip, "ips": h.ips, "hostname": h.hostname,
            "os": h.os, "status": h.status, "ports": h.ports,
            "services": h.services, "tags": h.tags, "notes": h.notes,
        } for h in hosts], ensure_ascii=False))

        zf.writestr("creds.json", json.dumps([{
            "id": c.id, "host": c.host, "username": c.username,
            "secret": c.secret, "type": c.type, "service": c.service,
            "notes": c.notes, "cracked": c.cracked,
            "host_ids": c.host_ids or [], "is_domain": c.is_domain,
        } for c in creds], ensure_ascii=False))

        nets_out = [schemas.Network.from_orm_obj(n).model_dump() for n in networks]
        zf.writestr("networks.json", json.dumps(nets_out, ensure_ascii=False))

        zf.writestr("findings.json", json.dumps([{
            "id": f.id, "host_id": f.host_id, "title": f.title,
            "severity": f.severity, "cvss": f.cvss, "cve": f.cve,
            "description": f.description, "proof": f.proof,
            "recommendation": f.recommendation, "status": f.status, "ts": f.ts,
        } for f in findings], ensure_ascii=False))

        zf.writestr("objectives.json", json.dumps([{
            "id": o.id, "host_id": o.host_id, "title": o.title,
            "description": o.description, "category": o.category,
            "points": o.points, "status": o.status, "flag_value": o.flag_value,
            "captured_by": o.captured_by, "captured_at": o.captured_at, "ts": o.ts,
        } for o in objectives], ensure_ascii=False))

        zf.writestr("attack_paths.json", json.dumps([{
            "id": ap.id, "name": ap.name, "description": ap.description, "ts": ap.ts,
        } for ap in attack_paths], ensure_ascii=False))

        zf.writestr("attack_steps.json", json.dumps([{
            "id": s.id, "path_id": s.path_id, "step_order": s.step_order,
            "node_type": s.node_type, "label": s.label, "sublabel": s.sublabel,
            "technique": s.technique, "mitre_id": s.mitre_id, "notes": s.notes, "ts": s.ts,
        } for s in attack_steps], ensure_ascii=False))

        zf.writestr("loots.json", json.dumps([{
            "id": l.id, "host_id": l.host_id, "loot_type": l.loot_type,
            "value": l.value, "description": l.description,
            "source_path": l.source_path, "ts": l.ts,
        } for l in loots], ensure_ascii=False))

        zf.writestr("scopes.json", json.dumps([{
            "id": s.id, "value": s.value, "scope_type": s.scope_type,
            "in_scope": s.in_scope, "description": s.description,
        } for s in scopes], ensure_ascii=False))

        zf.writestr("checklist.json", json.dumps([{
            "id": c.id, "phase": c.phase, "text": c.text,
            "done": c.done, "order_idx": c.order_idx,
        } for c in checklist], ensure_ascii=False))

        atts_meta = []
        for att in attachments:
            ext = Path(att.filename).suffix
            zip_entry = f"attachments/{att.id}{ext}"
            atts_meta.append({
                "id": att.id, "note_id": att.note_id, "filename": att.filename,
                "content_type": att.content_type, "file_size": att.file_size,
                "public_url": att.public_url, "ts": att.ts,
                "zip_entry": zip_entry,
            })
            disk = Path(att.storage_path)
            if disk.exists():
                zf.write(disk, zip_entry)

        zf.writestr("attachments.json", json.dumps(atts_meta, ensure_ascii=False))

    buf.seek(0)
    safe_name = re.sub(r"[^\w\-.]", "_", project.name)
    filename = f"{safe_name}_export.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/import_project", status_code=201)
async def import_project(file: UploadFile = File(...), db: Session = Depends(get_db)):
    raw = await file.read()
    try:
        buf = io.BytesIO(raw)
        zf = zipfile.ZipFile(buf, "r")
    except zipfile.BadZipFile:
        raise HTTPException(400, "Файл не является корректным ZIP-архивом")

    names = set(zf.namelist())

    def read_json(entry):
        return json.loads(zf.read(entry)) if entry in names else []

    try:
        project_data   = json.loads(zf.read("project.json"))
        notes_data     = read_json("notes.json")
        hosts_data     = read_json("hosts.json")
        creds_data     = read_json("creds.json")
        nets_data      = read_json("networks.json")
        atts_data      = read_json("attachments.json")
        findings_data  = read_json("findings.json")
        obj_data       = read_json("objectives.json")
        ap_data        = read_json("attack_paths.json")
        as_data        = read_json("attack_steps.json")
        loots_data     = read_json("loots.json")
        scopes_data    = read_json("scopes.json")
        checklist_data = read_json("checklist.json")
    except Exception as e:
        raise HTTPException(400, f"Ошибка чтения архива: {e}")

    try:
        # ── Create project ──────────────────────────────────────
        new_pid = new_id("p")
        project = models.Project(
            id=new_pid,
            name=project_data.get("name", "Imported") + " (импорт)",
            ip=project_data.get("ip", ""),
            os=project_data.get("os", "Unknown"),
            status=project_data.get("status", "active"),
            added=datetime.utcnow().strftime("%Y-%m-%d"),
            description=project_data.get("description", ""),
        )
        db.add(project)
        db.flush()

        # ── Notes ───────────────────────────────────────────────
        note_id_map: dict[str, str] = {}
        note_objs: list[models.Note] = []
        for n in notes_data:
            new_nid = new_id("n")
            note_id_map[n["id"]] = new_nid
            obj = models.Note(
                id=new_nid, pid=new_pid,
                title=n.get("title", ""),
                content=n.get("content", ""),
                phase=n.get("phase", "recon"),
                tags=n.get("tags", []),
                ts=n.get("ts", ""),
                starred=n.get("starred", False),
            )
            db.add(obj)
            note_objs.append(obj)
        db.flush()

        # ── Attachments ─────────────────────────────────────────
        url_map: dict[str, str] = {}
        for att in atts_data:
            old_nid = att.get("note_id", "")
            new_nid = note_id_map.get(old_nid)
            if not new_nid:
                continue
            zip_entry = att.get("zip_entry") or f"attachments/{att['id']}{Path(att['filename']).suffix}"
            if zip_entry not in names:
                continue
            new_att_id = new_id("att")
            ext = Path(att["filename"]).suffix
            note_dir = UPLOAD_ROOT / new_pid / new_nid
            note_dir.mkdir(parents=True, exist_ok=True)
            disk_name = f"{new_att_id}{ext}"
            disk_path = ensure_under_upload_root(note_dir / disk_name)
            disk_path.write_bytes(zf.read(zip_entry))
            new_url = f"/uploads/{new_pid}/{new_nid}/{disk_name}"
            url_map[att["public_url"]] = new_url
            db.add(models.NoteAttachment(
                id=new_att_id, note_id=new_nid, pid=new_pid,
                filename=att.get("filename", disk_name),
                content_type=att.get("content_type", "application/octet-stream"),
                file_size=att.get("file_size", 0),
                storage_path=str(disk_path),
                public_url=new_url,
                ts=att.get("ts", datetime.utcnow().strftime("%Y-%m-%d %H:%M")),
            ))

        for obj in note_objs:
            content = obj.content or ""
            for old_url, new_url in url_map.items():
                content = content.replace(old_url, new_url)
            obj.content = content

        # ── Hosts (build id map for relations) ──────────────────
        host_id_map: dict[str, str] = {}
        for h in hosts_data:
            new_hid = new_id("hst")
            host_id_map[h["id"]] = new_hid
            db.add(models.Host(
                id=new_hid, pid=new_pid,
                ip=h.get("ip", ""), ips=h.get("ips", []),
                hostname=h.get("hostname", ""),
                os=h.get("os", "Unknown"),
                status=h.get("status", "unknown"),
                ports=h.get("ports", []), services=h.get("services", []),
                tags=h.get("tags", []), notes=h.get("notes", ""),
            ))

        # ── Creds (remap host_ids) ──────────────────────────────
        for c in creds_data:
            old_hids = c.get("host_ids") or []
            new_hids = [host_id_map[hid] for hid in old_hids if hid in host_id_map]
            db.add(models.Cred(
                id=new_id("c"), pid=new_pid,
                host=c.get("host", ""), username=c.get("username", ""),
                secret=c.get("secret", ""), type=c.get("type", "plain"),
                service=c.get("service", ""), notes=c.get("notes", ""),
                cracked=c.get("cracked", False),
                host_ids=new_hids, is_domain=c.get("is_domain", False),
            ))

        # ── Networks ─────────────────────────────────────────────
        for net in nets_data:
            db.add(models.Network(
                id=new_id("net"), pid=new_pid,
                name=net.get("name", "Network"),
                background=net.get("background", "#07080b"),
                regions_json=net.get("regions", []),
                nodes_json=net.get("nodes", []),
                edges_json=net.get("edges", []),
            ))

        # ── Findings (remap host_id) ─────────────────────────────
        for f in findings_data:
            old_hid = f.get("host_id")
            db.add(models.Finding(
                id=new_id("f"), pid=new_pid,
                host_id=host_id_map.get(old_hid) if old_hid else None,
                title=f.get("title", ""), severity=f.get("severity", "medium"),
                cvss=f.get("cvss", ""), cve=f.get("cve", ""),
                description=f.get("description", ""), proof=f.get("proof", ""),
                recommendation=f.get("recommendation", ""),
                status=f.get("status", "open"), ts=f.get("ts", ""),
            ))

        # ── Objectives (remap host_id) ───────────────────────────
        for o in obj_data:
            old_hid = o.get("host_id")
            db.add(models.Objective(
                id=new_id("obj"), pid=new_pid,
                host_id=host_id_map.get(old_hid) if old_hid else None,
                title=o.get("title", ""), description=o.get("description", ""),
                category=o.get("category", "flag"), points=o.get("points", 0),
                status=o.get("status", "not_started"),
                flag_value=o.get("flag_value", ""),
                captured_by=o.get("captured_by", ""),
                captured_at=o.get("captured_at", ""),
                ts=o.get("ts", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")),
            ))

        # ── Attack Paths + Steps (build path id map) ─────────────
        path_id_map: dict[str, str] = {}
        for ap in ap_data:
            new_apid = new_id("ap")
            path_id_map[ap["id"]] = new_apid
            db.add(models.AttackPath(
                id=new_apid, pid=new_pid,
                name=ap.get("name", "Attack Path"),
                description=ap.get("description", ""),
                ts=ap.get("ts", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")),
            ))
        db.flush()

        for s in as_data:
            old_pid_ref = s.get("path_id", "")
            new_path_id = path_id_map.get(old_pid_ref)
            if not new_path_id:
                continue
            db.add(models.AttackStep(
                id=new_id("as"), path_id=new_path_id, pid=new_pid,
                step_order=s.get("step_order", 0),
                node_type=s.get("node_type", "host"),
                label=s.get("label", ""), sublabel=s.get("sublabel", ""),
                technique=s.get("technique", ""), mitre_id=s.get("mitre_id", ""),
                notes=s.get("notes", ""),
                ts=s.get("ts", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")),
            ))

        # ── Loot (remap host_id) ─────────────────────────────────
        for l in loots_data:
            old_hid = l.get("host_id")
            db.add(models.Loot(
                id=new_id("lt"), pid=new_pid,
                host_id=host_id_map.get(old_hid) if old_hid else None,
                loot_type=l.get("loot_type", "file"),
                value=l.get("value", ""),
                description=l.get("description", ""),
                source_path=l.get("source_path", ""),
                ts=l.get("ts", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")),
            ))

        # ── Scope ─────────────────────────────────────────────────
        for s in scopes_data:
            db.add(models.Scope(
                id=new_id("sc"), pid=new_pid,
                value=s.get("value", ""),
                scope_type=s.get("scope_type", "cidr"),
                in_scope=s.get("in_scope", True),
                description=s.get("description", ""),
            ))

        # ── Checklist ─────────────────────────────────────────────
        for c in checklist_data:
            db.add(models.ChecklistItem(
                id=new_id("cl"), pid=new_pid,
                phase=c.get("phase", "recon"),
                text=c.get("text", ""),
                done=c.get("done", False),
                order_idx=c.get("order_idx", 0),
            ))

        db.commit()
        zf.close()
        return {"project_id": new_pid, "name": project.name}

    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Ошибка импорта: {e}")


# ── Batch import ──────────────────────────────────────────────────────
class BatchImportBody(BaseModel):
    hosts: List[schemas.HostCreate] = []
    creds: List[schemas.CredCreate] = []


class BatchImportResult(BaseModel):
    hosts_added: int
    creds_added: int


@app.post("/api/import/{pid}", response_model=BatchImportResult, status_code=201)
def batch_import(pid: str, body: BatchImportBody, db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")

    all_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    existing_by_ip       = {h.ip: h       for h in all_hosts if h.ip}
    existing_by_hostname = {(h.hostname or '').upper(): h for h in all_hosts if h.hostname}

    status_rank = {'unknown': 0, 'alive': 1, 'scanned': 2, 'access': 3, 'pwned': 4, 'owned': 5}

    hosts_added = 0
    new_hosts = []
    for h in body.hosts:
        h_data = h.model_dump()
        h_data['pid'] = pid

        ip       = h_data.get('ip', '')
        hn_upper = (h_data.get('hostname') or '').upper()

        # Match existing host: by IP first, then by hostname
        existing = existing_by_ip.get(ip) or (existing_by_hostname.get(hn_upper) if hn_upper else None)

        if existing:
            # Merge ports / services / tags
            existing.ports    = list(set((existing.ports    or []) + h_data.get('ports',    [])))
            existing.services = list(set((existing.services or []) + h_data.get('services', [])))
            existing.tags     = list(set((existing.tags     or []) + h_data.get('tags',     [])))

            # Fill missing fields
            if h_data.get('hostname') and not existing.hostname:
                existing.hostname = h_data['hostname']
            if h_data.get('domain') and not existing.domain:
                existing.domain = h_data['domain']

            # Update IP if we now have a real one and existing is missing / was a hostname placeholder
            if h_data.get('ip') and (not existing.ip or existing.ip == existing.hostname):
                existing.ip = h_data['ip']
                existing_by_ip[existing.ip] = existing

            # Update OS: prefer more specific (longer) string
            incoming_os = h_data.get('os', '')
            if incoming_os and incoming_os not in ('Unknown', '') and (
                existing.os in ('Unknown', '', None) or
                len(incoming_os) > len(existing.os or '')
            ):
                existing.os = incoming_os

            # Merge notes (append BH info if not already present)
            if h_data.get('notes'):
                if not existing.notes:
                    existing.notes = h_data['notes']
                elif h_data['notes'] not in existing.notes:
                    existing.notes = existing.notes.rstrip() + '\n' + h_data['notes']

            # Raise status if new data indicates higher compromise level
            if status_rank.get(h_data.get('status', 'unknown'), 0) > status_rank.get(existing.status, 0):
                existing.status = h_data['status']

            new_hosts.append(existing)
        else:
            host = models.Host(id=new_id("hst"), **h_data)
            db.add(host)
            existing_by_ip[ip] = host
            if hn_upper:
                existing_by_hostname[hn_upper] = host
            hosts_added += 1
            new_hosts.append(host)

    new_creds = []
    creds_added = 0
    for c in body.creds:
        c_data = c.model_dump()
        c_data['pid'] = pid
        cred = models.Cred(id=new_id("c"), **c_data)
        db.add(cred)
        creds_added += 1
        new_creds.append(cred)

    db.commit()

    # Broadcast all new/updated hosts and creds
    for h in new_hosts:
        db.refresh(h)
        bcast(pid, "host", "upsert", schemas.Host.model_validate(h).model_dump())
    for c in new_creds:
        db.refresh(c)
        bcast(pid, "cred", "create", schemas.Cred.model_validate(c).model_dump())

    return BatchImportResult(hosts_added=hosts_added, creds_added=creds_added)
