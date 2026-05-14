from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi import File, UploadFile
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.config import UPLOAD_ROOT
from ..core.events import bcast, log_event
from ..core.utils import new_id, safe_upload_name, ensure_under_upload_root, ts_now
from ..core.artifact_extractor import sha256_bytes as _sha256
from ..core.crypto import decrypt_str, encrypt_str, loot_value_is_sensitive
from ..core.deps import get_current_user
from ..core.access import check_pid_access, check_object_access, get_user_member_pids

router = APIRouter(prefix="/api/loots", tags=["loots"])


def _loot_out(loot: models.Loot) -> dict:
    data = schemas.Loot.model_validate(loot).model_dump()
    if loot_value_is_sensitive(
        data.get("loot_type", ""),
        data.get("artifact_type", ""),
        data.get("filename", ""),
        getattr(loot, "storage_path", ""),
        data.get("public_url", ""),
    ):
        data["value"] = decrypt_str(data.get("value") or "")
    return data


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
        loots = q.order_by(models.Loot.ts.desc()).all()
        sensitive_count = sum(1 for loot in loots if loot_value_is_sensitive(loot.loot_type, loot.artifact_type, loot.filename, loot.storage_path, loot.public_url))
        if sensitive_count:
            log_event(db, pid, getattr(user, "username", None), "audit", "read_sensitive_loot", f"Sensitive loot viewed ({sensitive_count})", {"count": sensitive_count})
            db.commit()
        return [_loot_out(loot) for loot in loots]
    if user.role == "admin":
        q = db.query(models.Loot)
        if job_id:
            q = q.filter(models.Loot.job_id == job_id)
        return [_loot_out(loot) for loot in q.order_by(models.Loot.ts.desc()).all()]
    member_pids = get_user_member_pids(db, user)
    return [_loot_out(loot) for loot in db.query(models.Loot).filter(models.Loot.pid.in_(member_pids)).order_by(models.Loot.ts.desc()).all()]


@router.post("", response_model=schemas.Loot, status_code=201)
def create_loot(body: schemas.LootCreate, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    check_pid_access(db, body.pid, user, "loot.create")
    payload = body.model_dump()
    if loot_value_is_sensitive(payload.get("loot_type", ""), payload.get("artifact_type", ""), payload.get("filename", ""), "", payload.get("public_url", "")) and payload.get("value"):
        payload["value"] = encrypt_str(payload["value"])
    loot = models.Loot(**payload, id=new_id("lt"), ts=ts_now())
    db.add(loot)
    log_event(db, loot.pid, getattr(request.state, "username", None), "loot", "create",
              f"Loot [{loot.loot_type}]: {(decrypt_str(loot.value) or loot.description or '')[:40]}")
    db.commit()
    db.refresh(loot)
    payload = _loot_out(loot)
    bcast(loot.pid, "loot", "create", payload)
    return payload


@router.patch("/{lid}", response_model=schemas.Loot)
def update_loot(lid: str, body: schemas.LootUpdate, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404)
    check_object_access(db, loot.pid, user, "loot.update")
    updates = body.model_dump(exclude_none=True)
    next_is_sensitive = loot_value_is_sensitive(
        updates.get("loot_type", loot.loot_type),
        updates.get("artifact_type", loot.artifact_type),
        updates.get("filename", loot.filename),
        updates.get("storage_path", loot.storage_path),
        updates.get("public_url", loot.public_url),
    )
    if "value" in updates or any(key in updates for key in ("loot_type", "artifact_type", "filename", "public_url")):
        next_value = updates.get("value", loot.value or "")
        if next_is_sensitive and next_value:
            updates["value"] = encrypt_str(decrypt_str(next_value))
        else:
            updates["value"] = decrypt_str(next_value)
    for k, v in updates.items():
        setattr(loot, k, v)
    db.commit()
    db.refresh(loot)
    payload = _loot_out(loot)
    bcast(loot.pid, "loot", "update", payload)
    return payload


@router.delete("/{lid}", status_code=204)
def delete_loot(lid: str, request: Request, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404)
    check_object_access(db, loot.pid, user, "loot.delete")
    pid = loot.pid
    log_event(db, pid, getattr(request.state, "username", None), "loot", "delete",
              f"Loot deleted: {(decrypt_str(loot.value) or loot.description or '')[:40]}")
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
    payload = _loot_out(loot)
    log_event(db, loot.pid, getattr(request.state, "username", None), "loot", "upload", f"Loot file uploaded: {safe_name}")
    db.commit()
    bcast(loot.pid, "loot", "update", payload)
    return loot
