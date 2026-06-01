import io
import json
import re
import secrets
import zipfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from typing import Annotated
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access
from ..core.config import UPLOAD_ROOT
from ..core.crypto import (
    decrypt_bytes,
    decrypt_str,
    encrypt_str,
    loot_value_is_sensitive,
    note_content_is_confidential,
)
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast_batch, log_event
from ..core.network_data import (
    get_edges,
    get_nodes,
    get_regions,
    replace_edges,
    replace_nodes,
    replace_regions,
)
from ..core.permissions import add_project_owner, get_membership, get_permissions_for_role
from ..core.utils import (
    ensure_under_upload_root,
    new_id,
    normalize_domain,
    sync_project_ip_from_scopes,
    sync_scopes_from_project_ip,
    ts_now,
)
from ..database import get_db

router = APIRouter(tags=["import-export"])

_F_PROJECT = "project.json"
_F_NOTES = "notes.json"
_F_HOSTS = "hosts.json"
_F_CREDS = "creds.json"
_F_NETWORKS = "networks.json"
_F_FINDINGS = "findings.json"
_F_OBJECTIVES = "objectives.json"
_F_HOST_ACTIVITIES = "host_activities.json"
_F_ATTACK_PATHS = "attack_paths.json"
_F_ATTACK_STEPS = "attack_steps.json"
_F_LOOTS = "loots.json"
_F_SCOPES = "scopes.json"
_F_CHECKLIST = "checklist.json"
_F_CRED_HOST_NOTES = "cred_host_notes.json"
_F_ATTACHMENTS = "attachments.json"


def _write_loot_zip_entry(zf, loot, loots_meta: list) -> None:
    loot_entry = {
        "id": loot.id,
        "host_id": loot.host_id,
        "loot_type": loot.loot_type,
        "value": (
            decrypt_str(loot.value)
            if loot_value_is_sensitive(loot.loot_type, loot.artifact_type, loot.filename, loot.storage_path, loot.public_url)
            else loot.value
        ),
        "description": loot.description,
        "source_path": loot.source_path,
        "filename": loot.filename,
        "content_type": loot.content_type,
        "file_size": loot.file_size,
        "public_url": loot.public_url,
        "ts": loot.ts,
    }
    disk = Path(loot.storage_path) if loot.storage_path else None
    if disk and disk.exists():
        zip_entry = f"loot/{loot.id}{Path(loot.filename or loot.value or 'loot.bin').suffix}"
        if getattr(loot, "file_encrypted", False):
            try:
                zf.writestr(zip_entry, decrypt_bytes(disk.read_bytes()))
            except Exception:
                zf.write(disk, zip_entry)
        else:
            zf.write(disk, zip_entry)
        loot_entry["zip_entry"] = zip_entry
    loots_meta.append(loot_entry)


def _write_export_zip(
    zf, project, db, can_read_secret: bool, data: dict,
) -> None:
    notes = data["notes"]
    hosts = data["hosts"]
    creds = data["creds"]
    networks = data["networks"]
    attachments = data["attachments"]
    findings = data["findings"]
    objectives = data["objectives"]
    host_activities = data["host_activities"]
    attack_paths = data["attack_paths"]
    attack_steps = data["attack_steps"]
    loots = data["loots"]
    scopes = data["scopes"]
    checklist = data["checklist"]
    cred_host_notes = data["cred_host_notes"]
    zf.writestr(_F_PROJECT, json.dumps(
        {"id": project.id, "name": project.name, "ip": project.ip, "os": project.os,
         "status": project.status, "added": project.added, "description": project.description},
        ensure_ascii=False,
    ))
    zf.writestr(_F_NOTES, json.dumps(
        [{"id": n.id, "title": n.title, "content": (decrypt_str(n.content) if note_content_is_confidential(n.tags or []) else n.content),
          "phase": n.phase, "tags": n.tags, "ts": n.ts, "starred": n.starred}
         for n in notes],
        ensure_ascii=False,
    ))
    zf.writestr(_F_HOSTS, json.dumps(
        [{"id": h.id, "ip": h.ip, "ips": h.ips, "hostname": h.hostname, "os": h.os,
          "status": h.status, "ports": h.ports, "services": h.services, "tags": h.tags,
          "notes": h.notes, "domain": h.domain, "role": h.role, "is_attacker": h.is_attacker}
         for h in hosts],
        ensure_ascii=False,
    ))
    zf.writestr(_F_CREDS, json.dumps(
        [{"id": c.id, "host": c.host, "username": c.username,
          "secret": decrypt_str(c.secret) if can_read_secret else "",
          "type": c.type, "service": c.service, "notes": c.notes, "tags": c.tags,
          "cracked": c.cracked, "domain": c.domain, "host_ids": c.host_ids or [], "is_domain": c.is_domain}
         for c in creds],
        ensure_ascii=False,
    ))
    nets_out = []
    for n in networks:
        nd = schemas.Network.from_orm_obj(n).model_dump()
        nd["nodes"] = get_nodes(n.id, db)
        nd["edges"] = get_edges(n.id, db)
        nd["regions"] = get_regions(n.id, db)
        nets_out.append(nd)
    zf.writestr(_F_NETWORKS, json.dumps(nets_out, ensure_ascii=False))
    zf.writestr(_F_FINDINGS, json.dumps(
        [{"id": f.id, "host_id": f.host_id, "title": f.title, "severity": f.severity,
          "cvss": f.cvss, "cve": f.cve, "description": f.description, "proof": f.proof,
          "recommendation": f.recommendation, "status": f.status, "ts": f.ts}
         for f in findings],
        ensure_ascii=False,
    ))
    zf.writestr(_F_OBJECTIVES, json.dumps(
        [{"id": o.id, "host_id": o.host_id, "title": o.title, "description": o.description,
          "category": o.category, "points": o.points, "status": o.status, "flag_value": o.flag_value,
          "captured_by": o.captured_by, "captured_at": o.captured_at, "ts": o.ts}
         for o in objectives],
        ensure_ascii=False,
    ))
    zf.writestr(_F_HOST_ACTIVITIES, json.dumps(
        [{"id": a.id, "host_id": a.host_id, "title": a.title, "activity_type": a.activity_type,
          "command": a.command, "summary": a.summary, "output": a.output, "status": a.status, "ts": a.ts}
         for a in host_activities],
        ensure_ascii=False,
    ))
    zf.writestr(_F_ATTACK_PATHS, json.dumps(
        [{"id": ap.id, "name": ap.name, "description": ap.description, "ts": ap.ts}
         for ap in attack_paths],
        ensure_ascii=False,
    ))
    zf.writestr(_F_ATTACK_STEPS, json.dumps(
        [{"id": s.id, "path_id": s.path_id, "step_order": s.step_order, "node_type": s.node_type,
          "label": s.label, "sublabel": s.sublabel, "technique": s.technique,
          "mitre_id": s.mitre_id, "notes": s.notes, "ts": s.ts}
         for s in attack_steps],
        ensure_ascii=False,
    ))
    loots_meta: list = []
    for loot in loots:
        _write_loot_zip_entry(zf, loot, loots_meta)
    zf.writestr(_F_LOOTS, json.dumps(loots_meta, ensure_ascii=False))
    zf.writestr(_F_SCOPES, json.dumps(
        [{"id": s.id, "value": s.value, "scope_type": s.scope_type, "in_scope": s.in_scope, "description": s.description}
         for s in scopes],
        ensure_ascii=False,
    ))
    zf.writestr(_F_CHECKLIST, json.dumps(
        [{"id": c.id, "phase": c.phase, "text": c.text, "done": c.done, "order_idx": c.order_idx}
         for c in checklist],
        ensure_ascii=False,
    ))
    zf.writestr(_F_CRED_HOST_NOTES, json.dumps(
        [{"id": n.id, "cred_id": n.cred_id, "host_id": n.host_id, "notes": n.notes, "access": n.access}
         for n in cred_host_notes],
        ensure_ascii=False,
    ))
    atts_meta = []
    for att in attachments:
        ext = Path(att.filename).suffix
        zip_entry = f"attachments/{att.id}{ext}"
        atts_meta.append({
            "id": att.id, "note_id": att.note_id, "filename": att.filename,
            "content_type": att.content_type, "file_size": att.file_size,
            "public_url": att.public_url, "ts": att.ts, "zip_entry": zip_entry,
        })
        disk = Path(att.storage_path)
        if disk.exists():
            zf.write(disk, zip_entry)
    zf.writestr(_F_ATTACHMENTS, json.dumps(atts_meta, ensure_ascii=False))


@router.get("/api/export/{pid}", responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 500: {"description": "Internal server error"}})
def export_project(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    password: Annotated[str | None, Query(
        description="ZIP password. If omitted and project has secrets, one is auto-generated.",
    )] = None,
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    check_pid_access(db, pid, user, "project.export")

    can_read_secret = True
    if not is_admin(user):
        m = get_membership(db, pid, user.id)
        can_read_secret = bool(m and "credentials.read_secret" in get_permissions_for_role(m.role))

    notes = db.query(models.Note).filter(models.Note.pid == pid).all()
    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    networks = db.query(models.Network).filter(models.Network.pid == pid).all()
    attachments = db.query(models.NoteAttachment).filter(models.NoteAttachment.pid == pid).all()
    findings = db.query(models.Finding).filter(models.Finding.pid == pid).all()
    objectives = db.query(models.Objective).filter(models.Objective.pid == pid).all()
    host_activities = db.query(models.HostActivity).filter(models.HostActivity.pid == pid).all()
    attack_paths = db.query(models.AttackPath).filter(models.AttackPath.pid == pid).all()
    attack_steps = db.query(models.AttackStep).filter(models.AttackStep.pid == pid).all()
    loots = db.query(models.Loot).filter(models.Loot.pid == pid).all()
    scopes = db.query(models.Scope).filter(models.Scope.pid == pid).all()
    checklist = db.query(models.ChecklistItem).filter(models.ChecklistItem.pid == pid).all()
    cred_host_notes = db.query(models.CredHostNote).filter(models.CredHostNote.pid == pid).all()

    has_secrets = can_read_secret and any(bool(decrypt_str(c.secret)) for c in creds if c.secret)

    if can_read_secret and any(c.secret for c in creds):
        log_event(
            db, pid, getattr(user, "username", None), "audit", "export_with_secrets",
            f"Project exported with credential secrets ({sum(1 for c in creds if c.secret)})",
            {"cred_count": sum(1 for c in creds if c.secret)},
        )
        db.commit()

    zip_password: str | None = None
    if has_secrets:
        zip_password = password if password else secrets.token_urlsafe(16)

    zip_kwargs = {"notes": notes, "hosts": hosts, "creds": creds, "networks": networks,
                  "attachments": attachments, "findings": findings, "objectives": objectives,
                  "host_activities": host_activities, "attack_paths": attack_paths,
                  "attack_steps": attack_steps, "loots": loots, "scopes": scopes,
                  "checklist": checklist, "cred_host_notes": cred_host_notes}

    buf = io.BytesIO()
    if zip_password:
        try:
            import pyzipper
            with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(zip_password.encode())
                _write_export_zip(zf, project, db, can_read_secret, zip_kwargs)
        except ImportError:
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                _write_export_zip(zf, project, db, can_read_secret, zip_kwargs)
            zip_password = None
    else:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            _write_export_zip(zf, project, db, can_read_secret, zip_kwargs)

    buf.seek(0)
    safe_name = re.sub(r"[^\w\-.]", "_", project.name)
    filename = f"{safe_name}_export.zip"
    from urllib.parse import quote
    encoded_name = quote(filename, safe="")
    headers = {"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}"}
    if zip_password:
        headers["X-Zip-Password"] = zip_password
    return StreamingResponse(buf, media_type="application/zip", headers=headers)


def _import_notes_and_attachments(db, new_pid: str, notes_data: list, atts_data: list, zf, names: set) -> tuple[dict, dict]:
    note_id_map: dict = {}
    note_objs: list = []
    for n in notes_data:
        new_nid = new_id("n")
        note_id_map[n["id"]] = new_nid
        obj = models.Note(
            id=new_nid, pid=new_pid,
            title=n.get("title", ""),
            content=(
                encrypt_str(n.get("content", ""))
                if note_content_is_confidential(n.get("tags", [])) and n.get("content", "")
                else n.get("content", "")
            ),
            phase=n.get("phase", "recon"), tags=n.get("tags", []),
            ts=n.get("ts", ""), starred=n.get("starred", False),
        )
        db.add(obj)
        note_objs.append(obj)
    db.flush()

    url_map: dict = {}
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
            file_size=att.get("file_size", 0), storage_path=str(disk_path),
            public_url=new_url, ts=att.get("ts", ts_now()),
        ))

    for obj in note_objs:
        content = obj.content or ""
        for old_url, new_url in url_map.items():
            content = content.replace(old_url, new_url)
        obj.content = content

    return note_id_map, url_map


def _import_hosts_and_creds(db, new_pid: str, hosts_data: list, creds_data: list) -> tuple[dict, dict]:
    host_id_map: dict = {}
    for h in hosts_data:
        new_hid = new_id("hst")
        host_id_map[h["id"]] = new_hid
        db.add(models.Host(
            id=new_hid, pid=new_pid, ip=h.get("ip", ""), ips=h.get("ips", []),
            hostname=h.get("hostname", ""), os=h.get("os", "Unknown"),
            status=h.get("status", "unknown"), ports=h.get("ports", []),
            services=h.get("services", []), tags=h.get("tags", []),
            notes=h.get("notes", ""), domain=normalize_domain(h.get("domain", "")),
            role=h.get("role", "unknown"), is_attacker=h.get("is_attacker", False),
        ))
    cred_id_map: dict = {}
    for c in creds_data:
        old_hids = c.get("host_ids") or []
        new_hids = [host_id_map[hid] for hid in old_hids if hid in host_id_map]
        new_cid = new_id("c")
        if c.get("id"):
            cred_id_map[c["id"]] = new_cid
        db.add(models.Cred(
            id=new_cid, pid=new_pid, host=c.get("host", ""), username=c.get("username", ""),
            secret=encrypt_str(c.get("secret", "")), type=c.get("type", "plain"),
            service=c.get("service", ""), notes=c.get("notes", ""), tags=c.get("tags", []),
            domain=normalize_domain(c.get("domain", "")), cracked=c.get("cracked", False),
            host_ids=new_hids, is_domain=c.get("is_domain", False),
        ))
    return host_id_map, cred_id_map


def _import_networks(db, new_pid: str, nets_data: list) -> None:
    for net in nets_data:
        net_id = new_id("net")
        db.add(models.Network(
            id=net_id, pid=new_pid, name=net.get("name", "Network"),
            background=net.get("background", "#07080b"), meta_json=net.get("meta", {}),
        ))
        db.flush()
        if net.get("nodes"):
            replace_nodes(net_id, new_pid, net["nodes"], db)
        if net.get("edges"):
            replace_edges(net_id, new_pid, net["edges"], db)
        if net.get("regions"):
            replace_regions(net_id, new_pid, net["regions"], db)


def _import_activities_and_paths(
    db, new_pid: str, findings_data: list, obj_data: list,
    host_activity_data: list, ap_data: list, as_data: list, host_id_map: dict,
) -> None:
    for f in findings_data:
        old_hid = f.get("host_id")
        db.add(models.Finding(
            id=new_id("f"), pid=new_pid,
            host_id=host_id_map.get(old_hid) if old_hid else None,
            title=f.get("title", ""), severity=f.get("severity", "medium"),
            cvss=f.get("cvss", ""), cve=f.get("cve", ""),
            description=f.get("description", ""), proof=f.get("proof", ""),
            recommendation=f.get("recommendation", ""), status=f.get("status", "open"),
            ts=f.get("ts", ""),
        ))
    for o in obj_data:
        old_hid = o.get("host_id")
        db.add(models.Objective(
            id=new_id("obj"), pid=new_pid,
            host_id=host_id_map.get(old_hid) if old_hid else None,
            title=o.get("title", ""), description=o.get("description", ""),
            category=o.get("category", "flag"), points=o.get("points", 0),
            status=o.get("status", "not_started"), flag_value=o.get("flag_value", ""),
            captured_by=o.get("captured_by", ""), captured_at=o.get("captured_at", ""),
            ts=o.get("ts", ts_now()),
        ))
    for a in host_activity_data:
        new_hid = host_id_map.get(a.get("host_id"))
        if not new_hid:
            continue
        db.add(models.HostActivity(
            id=new_id("ha"), pid=new_pid, host_id=new_hid,
            title=a.get("title", ""), activity_type=a.get("activity_type", "recon"),
            command=a.get("command", ""), summary=a.get("summary", ""),
            output=a.get("output", ""), status=a.get("status", "done"), ts=a.get("ts", ts_now()),
        ))
    path_id_map: dict = {}
    for ap in ap_data:
        new_apid = new_id("ap")
        path_id_map[ap["id"]] = new_apid
        db.add(models.AttackPath(
            id=new_apid, pid=new_pid, name=ap.get("name", "Attack Path"),
            description=ap.get("description", ""), ts=ap.get("ts", ts_now()),
        ))
    db.flush()
    for s in as_data:
        new_path_id = path_id_map.get(s.get("path_id", ""))
        if not new_path_id:
            continue
        db.add(models.AttackStep(
            id=new_id("as"), path_id=new_path_id, pid=new_pid,
            step_order=s.get("step_order", 0), node_type=s.get("node_type", "host"),
            label=s.get("label", ""), sublabel=s.get("sublabel", ""),
            technique=s.get("technique", ""), mitre_id=s.get("mitre_id", ""),
            notes=s.get("notes", ""), ts=s.get("ts", ts_now()),
        ))


def _import_one_loot(db, new_pid: str, loot: dict, host_id_map: dict, zf, names: set) -> None:
    old_hid = loot.get("host_id")
    new_lid = new_id("lt")
    filename = loot.get("filename", "")
    content_type = loot.get("content_type", "")
    file_size = loot.get("file_size", 0)
    public_url = ""
    storage_path = ""
    source_path = loot.get("source_path", "")
    zip_entry = loot.get("zip_entry")
    if zip_entry and zip_entry in names:
        safe_name = filename or Path(zip_entry).name
        ext = Path(safe_name).suffix
        loot_dir = UPLOAD_ROOT / new_pid / "loot"
        loot_dir.mkdir(parents=True, exist_ok=True)
        disk_name = f"{new_lid}{ext}"
        disk_path = ensure_under_upload_root(loot_dir / disk_name)
        disk_path.write_bytes(zf.read(zip_entry))
        storage_path = str(disk_path)
        public_url = f"/uploads/{new_pid}/loot/{disk_name}"
        if not source_path:
            source_path = public_url
    raw_value = loot.get("value", "")
    is_sensitive = loot_value_is_sensitive(loot.get("loot_type", "file"), loot.get("artifact_type", "file"), filename, storage_path, public_url)
    loot_value = encrypt_str(raw_value) if (is_sensitive and raw_value) else raw_value
    db.add(models.Loot(
        id=new_lid, pid=new_pid,
        host_id=host_id_map.get(old_hid) if old_hid else None,
        loot_type=loot.get("loot_type", "file"), value=loot_value,
        description=loot.get("description", ""), source_path=source_path,
        filename=filename, content_type=content_type, file_size=file_size,
        storage_path=storage_path, public_url=public_url, ts=loot.get("ts", ts_now()),
        artifact_type=loot.get("artifact_type", "file"), tags=loot.get("tags", []),
        job_id=loot.get("job_id", ""), cred_id=loot.get("cred_id", ""),
        finding_id=loot.get("finding_id", ""), playbook_run_id=loot.get("playbook_run_id", ""),
        sha256=loot.get("sha256", ""),
    ))


def _import_loots_and_scope(
    db, new_pid: str, loots_data: list, scopes_data: list, checklist_data: list,
    chn_data: list, host_id_map: dict, cred_id_map: dict, zf, names: set,
) -> None:
    for loot in loots_data:
        _import_one_loot(db, new_pid, loot, host_id_map, zf, names)
    for s in scopes_data:
        db.add(models.Scope(
            id=new_id("sc"), pid=new_pid, value=s.get("value", ""),
            scope_type=s.get("scope_type", "cidr"), in_scope=s.get("in_scope", True),
            description=s.get("description", ""),
        ))
    if scopes_data:
        sync_project_ip_from_scopes(db, new_pid)
    else:
        sync_scopes_from_project_ip(db, new_pid)
    for c in checklist_data:
        db.add(models.ChecklistItem(
            id=new_id("cl"), pid=new_pid, phase=c.get("phase", "recon"),
            text=c.get("text", ""), done=c.get("done", False), order_idx=c.get("order_idx", 0),
        ))
    for n in chn_data:
        new_cred = cred_id_map.get(n.get("cred_id"))
        new_host = host_id_map.get(n.get("host_id"))
        if not new_cred or not new_host:
            continue
        db.add(models.CredHostNote(
            id=new_id("chn"), cred_id=new_cred, host_id=new_host, pid=new_pid,
            notes=n.get("notes", ""), access=n.get("access", []),
        ))


@router.post("/api/import_project", status_code=201, responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 500: {"description": "Internal server error"}})
async def import_project(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
):
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
        project_data = json.loads(zf.read(_F_PROJECT))
        notes_data = read_json(_F_NOTES)
        hosts_data = read_json(_F_HOSTS)
        creds_data = read_json(_F_CREDS)
        nets_data = read_json(_F_NETWORKS)
        atts_data = read_json(_F_ATTACHMENTS)
        findings_data = read_json(_F_FINDINGS)
        obj_data = read_json(_F_OBJECTIVES)
        host_activity_data = read_json(_F_HOST_ACTIVITIES)
        ap_data = read_json(_F_ATTACK_PATHS)
        as_data = read_json(_F_ATTACK_STEPS)
        loots_data = read_json(_F_LOOTS)
        scopes_data = read_json(_F_SCOPES)
        checklist_data = read_json(_F_CHECKLIST)
        chn_data = read_json(_F_CRED_HOST_NOTES)
    except Exception as e:
        raise HTTPException(400, f"Ошибка чтения архива: {e}")

    try:
        new_pid = new_id("p")
        project = models.Project(
            id=new_pid,
            name=project_data.get("name", "Imported") + " (импорт)",
            ip=project_data.get("ip", ""),
            os=project_data.get("os", "Unknown"),
            status=project_data.get("status", "active"),
            added=ts_now(),
            description=project_data.get("description", ""),
        )
        db.add(project)
        db.flush()
        add_project_owner(db, new_pid, user.id, created_by=user.id)

        _, _url_map = _import_notes_and_attachments(db, new_pid, notes_data, atts_data, zf, names)
        host_id_map, cred_id_map = _import_hosts_and_creds(db, new_pid, hosts_data, creds_data)
        _import_networks(db, new_pid, nets_data)
        _import_activities_and_paths(db, new_pid, findings_data, obj_data, host_activity_data, ap_data, as_data, host_id_map)
        _import_loots_and_scope(db, new_pid, loots_data, scopes_data, checklist_data, chn_data, host_id_map, cred_id_map, zf, names)

        db.commit()
        zf.close()
        return {"project_id": new_pid, "name": project.name}

    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Ошибка импорта: {e}")


# ── Batch import ──────────────────────────────────────────────────────


class BatchImportBody(BaseModel):
    hosts: list[schemas.HostCreate] = []
    creds: list[schemas.CredCreate] = []
    source: str = ""  # import_source applied to all new hosts if they don't have one


class BatchImportResult(BaseModel):
    hosts_added: int
    creds_added: int


def _merge_host_os(existing, incoming_os: str) -> None:
    if (
        incoming_os
        and incoming_os not in ("Unknown", "")
        and (existing.os in ("Unknown", "", None) or len(incoming_os) > len(existing.os or ""))
    ):
        existing.os = incoming_os


def _merge_host_notes(existing, new_notes: str) -> None:
    if new_notes:
        if not existing.notes:
            existing.notes = new_notes
        elif new_notes not in existing.notes:
            existing.notes = existing.notes.rstrip() + "\n" + new_notes


def _merge_host_identity(existing, h_data: dict) -> None:
    if h_data.get("hostname") and not existing.hostname:
        existing.hostname = h_data["hostname"]
    if h_data.get("domain") and not existing.domain:
        existing.domain = h_data["domain"]
    if h_data.get("role") and (existing.role in ("", "unknown") or existing.role != "attacker"):
        existing.role = h_data["role"]
    if h_data.get("is_attacker"):
        existing.is_attacker = True
        existing.role = "attacker"
        existing.status = "attacker"
    if h_data.get("ip") and (not existing.ip or existing.ip == existing.hostname):
        existing.ip = h_data["ip"]


def _merge_existing_host(existing, h_data: dict, status_rank: dict) -> None:
    existing.ips = list(dict.fromkeys((existing.ips or []) + h_data.get("ips", [])))
    existing.ports = list(set((existing.ports or []) + h_data.get("ports", [])))
    existing.services = list(set((existing.services or []) + h_data.get("services", [])))
    existing.tags = list(set((existing.tags or []) + h_data.get("tags", [])))
    _merge_host_identity(existing, h_data)
    _merge_host_os(existing, h_data.get("os", ""))
    _merge_host_notes(existing, h_data.get("notes", ""))
    if status_rank.get(h_data.get("status", "unknown"), 0) > status_rank.get(existing.status, 0):
        existing.status = h_data["status"]


def _prepare_host_data(h, pid: str) -> tuple[dict, str, str]:
    h_data = h.model_dump()
    h_data["pid"] = pid
    h_data["domain"] = normalize_domain(h_data.get("domain", ""))
    h_data["role"] = h_data.get("role") or "unknown"
    h_data["is_attacker"] = bool(h_data.get("is_attacker")) or h_data["role"] == "attacker"
    if h_data["is_attacker"]:
        h_data["status"] = "attacker"
    ip = h_data.get("ip", "")
    hn_upper = (h_data.get("hostname") or "").upper()
    return h_data, ip, hn_upper


def _merge_into_existing(existing, h_data: dict, status_rank: dict, existing_by_ip: dict, new_hosts: list) -> None:
    _merge_existing_host(existing, h_data, status_rank)
    if h_data.get("ip") and (not existing.ip or existing.ip == existing.hostname):
        existing_by_ip[existing.ip] = existing
    new_hosts.append(existing)


def _create_new_host(db, _pid: str, body, h_data: dict, ip: str, hn_upper: str,
                     existing_by_ip: dict, existing_by_hostname: dict,
                     new_hosts: list, truly_new_host_ids: list) -> None:
    if body.source and not h_data.get("import_source"):
        h_data["import_source"] = body.source
    host = models.Host(id=new_id("hst"), **h_data)
    db.add(host)
    existing_by_ip[ip] = host
    if hn_upper:
        existing_by_hostname[hn_upper] = host
    new_hosts.append(host)
    truly_new_host_ids.append(host.id)


def _batch_import_hosts(
    db, pid: str, body, existing_by_ip: dict, existing_by_hostname: dict, status_rank: dict
) -> tuple[int, list, list]:
    hosts_added = 0
    new_hosts: list = []
    truly_new_host_ids: list[str] = []
    for h in body.hosts:
        h_data, ip, hn_upper = _prepare_host_data(h, pid)
        existing = existing_by_ip.get(ip) or (existing_by_hostname.get(hn_upper) if hn_upper else None)
        if existing:
            _merge_into_existing(existing, h_data, status_rank, existing_by_ip, new_hosts)
        else:
            _create_new_host(db, pid, body, h_data, ip, hn_upper, existing_by_ip, existing_by_hostname, new_hosts, truly_new_host_ids)
            hosts_added += 1
    return hosts_added, new_hosts, truly_new_host_ids


@router.post("/api/import/{pid}", response_model=BatchImportResult, status_code=201, responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}, 500: {"description": "Internal server error"}})
def batch_import(
    pid: str,
    body: BatchImportBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    check_pid_access(db, pid, user, "project.import")

    all_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    existing_by_ip = {h.ip: h for h in all_hosts if h.ip}
    existing_by_hostname = {(h.hostname or "").upper(): h for h in all_hosts if h.hostname}

    status_rank = {"unknown": 0, "alive": 1, "scanned": 2, "access": 3, "pwned": 4, "owned": 5}

    hosts_added, new_hosts, truly_new_host_ids = _batch_import_hosts(
        db, pid, body, existing_by_ip, existing_by_hostname, status_rank
    )

    new_creds = []
    creds_added = 0
    for c in body.creds:
        c_data = c.model_dump()
        c_data["pid"] = pid
        c_data["domain"] = normalize_domain(c_data.get("domain", ""))
        cred = models.Cred(id=new_id("c"), **c_data)
        db.add(cred)
        creds_added += 1
        new_creds.append(cred)

    db.commit()

    # Coalesce into one envelope per project — N row imports used to
    # produce N Redis publishes + N per-connection iterations.
    events: list[tuple[str, str, dict]] = []
    for h in new_hosts:
        db.refresh(h)
        events.append(("host", "upsert", schemas.Host.model_validate(h).model_dump()))
    for c in new_creds:
        db.refresh(c)
        events.append(("cred", "create", schemas.Cred.model_validate(c).model_dump()))
    bcast_batch(pid, events)

    # Reversible Timeline event — operators can rollback the freshly-imported
    # rows in one click. We only undo NEWLY CREATED entities (delete); we
    # deliberately do NOT roll back enrichment applied to existing hosts —
    # the merge semantics are non-trivial and a wrong rollback could lose
    # legitimate operator edits made before the import.
    new_cred_ids = [c.id for c in new_creds]
    undo_ops = [{"entity": "host", "id": hid, "type": "delete"} for hid in truly_new_host_ids] + [
        {"entity": "cred", "id": cid, "type": "delete"} for cid in new_cred_ids
    ]
    if undo_ops:
        username = getattr(user, "username", None)
        log_event(
            db,
            pid,
            username,
            "audit",
            "bulk_import_completed",
            f"Bulk import: {hosts_added} hosts + {creds_added} creds (source: {body.source or 'unspecified'})",
            {
                "hosts_added": hosts_added,
                "creds_added": creds_added,
                "source": body.source or "",
                "reversible": True,
                "undo": {"type": "batch", "operations": undo_ops[:1000]},
            },
        )
        db.commit()

    return BatchImportResult(hosts_added=hosts_added, creds_added=creds_added)
