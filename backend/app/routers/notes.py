import logging
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.config import UPLOAD_ROOT
from ..core.events import bcast, log_event
from ..core.utils import new_id, safe_upload_name, ensure_under_upload_root
from ..core.deps import get_current_user
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

logger = logging.getLogger(__name__)

router = APIRouter(tags=["notes"])


@router.get("/api/notes", response_model=list[schemas.Note])
def list_notes(
    pid: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        check_pid_access(db, pid, user, "notes.read")
        return db.query(models.Note).filter(models.Note.pid == pid).all()
    if user.role == "admin":
        return db.query(models.Note).all()
    member_pids = get_user_member_pids(db, user)
    return db.query(models.Note).filter(models.Note.pid.in_(member_pids)).all()


@router.post("/api/notes", response_model=schemas.Note, status_code=201)
def create_note(body: schemas.NoteCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "notes.create")
    note = models.Note(id=new_id("n"), **body.model_dump())
    db.add(note)
    log_event(db, note.pid, getattr(request.state, "username", None), "note", "create", f"Note created: «{note.title}»", {"id": note.id})
    db.commit()
    db.refresh(note)
    n = schemas.Note.model_validate(note)
    bcast(note.pid, "note", "create", n.model_dump())
    return note


@router.patch("/api/notes/{nid}", response_model=schemas.Note)
def update_note(nid: str, body: schemas.NoteUpdate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, "Note not found")
    check_object_access(db, note.pid, user, "notes.update")
    if body.client_version is not None and body.client_version != note.version:
        raise HTTPException(status_code=409, detail=schemas.Note.model_validate(note).model_dump())
    old_title = note.title
    patch = body.model_dump(exclude_none=True, exclude={"client_version"})
    for k, v in patch.items():
        setattr(note, k, v)
    note.version += 1
    if body.title is not None and body.title != old_title:
        log_event(db, note.pid, getattr(request.state, "username", None), "note", "update", f"Note renamed: «{old_title}» → «{note.title}»", {"id": note.id})
    db.commit()
    db.refresh(note)
    n = schemas.Note.model_validate(note)
    bcast(note.pid, "note", "update", n.model_dump())
    return note


@router.delete("/api/notes/{nid}", status_code=204)
def delete_note(nid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, "Note not found")
    check_object_access(db, note.pid, user, "notes.delete")
    pid = note.pid
    log_event(db, pid, getattr(request.state, "username", None), "note", "delete", f"Note deleted: «{note.title}»")
    db.delete(note)
    db.commit()
    bcast(pid, "note", "delete", {"id": nid})


@router.get("/api/notes/{nid}/attachments", response_model=list[schemas.NoteAttachment])
def list_note_attachments(nid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, "Note not found")
    check_object_access(db, note.pid, user, "notes.read")
    return db.query(models.NoteAttachment).filter(models.NoteAttachment.note_id == nid).all()


@router.post("/api/notes/{nid}/attachments", response_model=schemas.NoteAttachment, status_code=201)
async def upload_note_attachment(nid: str, file: UploadFile = File(...), db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, "Note not found")
    check_object_access(db, note.pid, user, "notes.update")
    safe_name = safe_upload_name(file.filename or "attachment.bin")
    att_id = new_id("att")
    ext = Path(safe_name).suffix
    note_dir = UPLOAD_ROOT / note.pid / nid
    note_dir.mkdir(parents=True, exist_ok=True)
    disk_name = f"{att_id}{ext}"
    disk_path = ensure_under_upload_root(note_dir / disk_name)
    MAX_UPLOAD = 50 * 1024 * 1024  # 50 MB
    content = await file.read()
    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, "File exceeds 50 MB limit")
    disk_path.write_bytes(content)
    attachment = models.NoteAttachment(
        id=att_id,
        note_id=nid,
        pid=note.pid,
        filename=safe_name,
        content_type=file.content_type or "application/octet-stream",
        file_size=len(content),
        storage_path=str(disk_path),
        public_url=f"/api/uploads/{note.pid}/{nid}/{disk_name}",
        ts=datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
    )
    db.add(attachment)
    db.commit()
    db.refresh(attachment)
    bcast(note.pid, "note_attachment", "create", schemas.NoteAttachment.model_validate(attachment).model_dump())
    return attachment


@router.delete("/attachments/{aid}", status_code=204)
def delete_attachment(aid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    attachment = db.query(models.NoteAttachment).filter(models.NoteAttachment.id == aid).first()
    if not attachment:
        raise HTTPException(404, "Attachment not found")
    check_object_access(db, attachment.pid, user, "notes.update")
    pid = attachment.pid
    note_id = attachment.note_id
    try:
        ensure_under_upload_root(Path(attachment.storage_path)).unlink(missing_ok=True)
    except Exception as e:
        logger.warning("Failed to delete attachment file %s: %s", attachment.storage_path, e)
    db.delete(attachment)
    db.commit()
    bcast(pid, "note_attachment", "delete", {"id": aid, "note_id": note_id})
