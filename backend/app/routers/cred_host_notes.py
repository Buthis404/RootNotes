from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.utils import new_id
from ..core.deps import get_current_user, is_admin
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(prefix="/api/cred-host-notes", tags=["cred-host-notes"])


@router.get("", response_model=list[schemas.CredHostNote])
def list_cred_host_notes(
    pid: str | None = None,
    cred_id: str | None = None,
    host_id: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        check_pid_access(db, pid, user, "credentials.read")
        q = db.query(models.CredHostNote).filter(models.CredHostNote.pid == pid)
    elif is_admin(user):
        q = db.query(models.CredHostNote)
    else:
        member_pids = get_user_member_pids(db, user)
        q = db.query(models.CredHostNote).filter(models.CredHostNote.pid.in_(member_pids))
    if cred_id:
        q = q.filter(models.CredHostNote.cred_id == cred_id)
    if host_id:
        q = q.filter(models.CredHostNote.host_id == host_id)
    return q.all()


@router.post("", response_model=schemas.CredHostNote, status_code=201)
def create_cred_host_note(body: schemas.CredHostNoteCreate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "credentials.update")
    existing = db.query(models.CredHostNote).filter(
        models.CredHostNote.cred_id == body.cred_id,
        models.CredHostNote.host_id == body.host_id,
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


@router.patch("/{nid}", response_model=schemas.CredHostNote)
def update_cred_host_note(nid: str, body: schemas.CredHostNoteUpdate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    note = db.query(models.CredHostNote).filter(models.CredHostNote.id == nid).first()
    if not note:
        raise HTTPException(404)
    check_object_access(db, note.pid, user, "credentials.update")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(note, k, v)
    db.commit()
    db.refresh(note)
    return note


@router.delete("/{nid}", status_code=204)
def delete_cred_host_note(nid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    note = db.query(models.CredHostNote).filter(models.CredHostNote.id == nid).first()
    if not note:
        raise HTTPException(404)
    check_object_access(db, note.pid, user, "credentials.update")
    db.delete(note)
    db.commit()
