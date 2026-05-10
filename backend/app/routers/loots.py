from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi import File, UploadFile
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.config import UPLOAD_ROOT
from ..core.events import bcast, log_event
from ..core.utils import new_id, safe_upload_name, ensure_under_upload_root
from ..core.artifact_extractor import sha256_bytes as _sha256
from ..core.deps import get_current_user
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(prefix="/api/loots", tags=["loots"])


@router.get("", response_model=list[schemas.Loot])
def list_loots(
    pid: str | None = None,
    job_id: str | None = None,
    artifact_type: str | None = None,
    host_id: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    if pid:
        check_pid_access(db, pid, user, "loot.read")
        q = db.query(models.Loot).filter(models.Loot.pid == pid)
        if job_id:
            q = q.filter(models.Loot.job_id == job_id)
        if artifact_type:
            q = q.filter(models.Loot.artifact_type == artifact_type)
        if host_id:
            q = q.filter(models.Loot.host_id == host_id)
        return q.order_by(models.Loot.ts.desc()).all()
    if user.role == "admin":
        q = db.query(models.Loot)
        if job_id:
            q = q.filter(models.Loot.job_id == job_id)
        return q.order_by(models.Loot.ts.desc()).all()
    member_pids = get_user_member_pids(db, user)
    return db.query(models.Loot).filter(models.Loot.pid.in_(member_pids)).order_by(models.Loot.ts.desc()).all()


@router.post("", response_model=schemas.Loot, status_code=201)
def create_loot(body: schemas.LootCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "loot.create")
    loot = models.Loot(**body.model_dump(), id=new_id("lt"), ts=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"))
    db.add(loot)
    log_event(db, loot.pid, getattr(request.state, "username", None), "loot", "create",
              f"Loot [{loot.loot_type}]: {(loot.value or loot.description or '')[:40]}")
    db.commit()
    db.refresh(loot)
    bcast(loot.pid, "loot", "create", schemas.Loot.model_validate(loot).model_dump())
    return loot


@router.patch("/{lid}", response_model=schemas.Loot)
def update_loot(lid: str, body: schemas.LootUpdate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404)
    check_object_access(db, loot.pid, user, "loot.update")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(loot, k, v)
    db.commit()
    db.refresh(loot)
    bcast(loot.pid, "loot", "update", schemas.Loot.model_validate(loot).model_dump())
    return loot


@router.delete("/{lid}", status_code=204)
def delete_loot(lid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404)
    check_object_access(db, loot.pid, user, "loot.delete")
    pid = loot.pid
    log_event(db, pid, getattr(request.state, "username", None), "loot", "delete",
              f"Loot deleted: {(loot.value or loot.description or '')[:40]}")
    try:
        if loot.storage_path:
            ensure_under_upload_root(Path(loot.storage_path)).unlink(missing_ok=True)
    except Exception:
        pass
    db.delete(loot)
    db.commit()
    bcast(pid, "loot", "delete", {"id": lid})


@router.post("/{lid}/file", response_model=schemas.Loot, status_code=201)
async def upload_loot_file(lid: str, request: Request, file: UploadFile = File(...), db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404, "Loot not found")
    check_object_access(db, loot.pid, user, "loot.update")
    safe_name = safe_upload_name(file.filename or "loot.bin")
    ext = Path(safe_name).suffix
    loot_dir = UPLOAD_ROOT / loot.pid / "loot"
    loot_dir.mkdir(parents=True, exist_ok=True)
    disk_name = f"{loot.id}{ext}"
    disk_path = ensure_under_upload_root(loot_dir / disk_name)
    MAX_UPLOAD = 50 * 1024 * 1024  # 50 MB
    content = await file.read()
    if len(content) > MAX_UPLOAD:
        raise HTTPException(413, "File exceeds 50 MB limit")
    disk_path.write_bytes(content)
    loot.filename = safe_name
    loot.content_type = file.content_type or "application/octet-stream"
    loot.file_size = len(content)
    loot.storage_path = str(disk_path)
    loot.public_url = f"/api/uploads/{loot.pid}/loot/{disk_name}"
    loot.sha256 = _sha256(content)
    loot.artifact_type = "file"
    if not loot.value:
        loot.value = safe_name
    if not loot.source_path:
        loot.source_path = f"/api/uploads/{loot.pid}/loot/{disk_name}"
    loot.loot_type = "file"
    db.commit()
    db.refresh(loot)
    payload = schemas.Loot.model_validate(loot).model_dump()
    log_event(db, loot.pid, getattr(request.state, "username", None), "loot", "upload", f"Loot file uploaded: {safe_name}")
    db.commit()
    bcast(loot.pid, "loot", "update", payload)
    return loot
