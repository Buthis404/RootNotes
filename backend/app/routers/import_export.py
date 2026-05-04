import io
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.config import UPLOAD_ROOT
from ..core.events import bcast
from ..core.utils import new_id, normalize_domain, ensure_under_upload_root, sync_project_ip_from_scopes, sync_scopes_from_project_ip
from ..core.deps import get_current_user
from ..core.access import check_pid_access
from ..core.permissions import add_project_owner, get_membership, get_permissions_for_role

router = APIRouter(tags=["import-export"])


@router.get("/api/export/{pid}")
def export_project(pid: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    check_pid_access(db, pid, user, "project.export")

    # Determine if user can read secrets
    can_read_secret = True
    if user.role != "admin":
        m = get_membership(db, pid, user.id)
        can_read_secret = bool(m and "credentials.read_secret" in get_permissions_for_role(m.role))

    notes           = db.query(models.Note).filter(models.Note.pid == pid).all()
    hosts           = db.query(models.Host).filter(models.Host.pid == pid).all()
    creds           = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    networks        = db.query(models.Network).filter(models.Network.pid == pid).all()
    attachments     = db.query(models.NoteAttachment).filter(models.NoteAttachment.pid == pid).all()
    findings        = db.query(models.Finding).filter(models.Finding.pid == pid).all()
    objectives      = db.query(models.Objective).filter(models.Objective.pid == pid).all()
    host_activities = db.query(models.HostActivity).filter(models.HostActivity.pid == pid).all()
    attack_paths    = db.query(models.AttackPath).filter(models.AttackPath.pid == pid).all()
    attack_steps    = db.query(models.AttackStep).filter(models.AttackStep.pid == pid).all()
    loots           = db.query(models.Loot).filter(models.Loot.pid == pid).all()
    scopes          = db.query(models.Scope).filter(models.Scope.pid == pid).all()
    checklist       = db.query(models.ChecklistItem).filter(models.ChecklistItem.pid == pid).all()
    cred_host_notes = db.query(models.CredHostNote).filter(models.CredHostNote.pid == pid).all()

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
            "domain": h.domain, "role": h.role, "is_attacker": h.is_attacker,
        } for h in hosts], ensure_ascii=False))

        zf.writestr("creds.json", json.dumps([{
            "id": c.id, "host": c.host, "username": c.username,
            "secret": c.secret if can_read_secret else "", "type": c.type, "service": c.service,
            "notes": c.notes, "tags": c.tags, "cracked": c.cracked, "domain": c.domain,
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

        zf.writestr("host_activities.json", json.dumps([{
            "id": a.id, "host_id": a.host_id, "title": a.title,
            "activity_type": a.activity_type, "command": a.command,
            "summary": a.summary, "output": a.output, "status": a.status, "ts": a.ts,
        } for a in host_activities], ensure_ascii=False))

        zf.writestr("attack_paths.json", json.dumps([{
            "id": ap.id, "name": ap.name, "description": ap.description, "ts": ap.ts,
        } for ap in attack_paths], ensure_ascii=False))

        zf.writestr("attack_steps.json", json.dumps([{
            "id": s.id, "path_id": s.path_id, "step_order": s.step_order,
            "node_type": s.node_type, "label": s.label, "sublabel": s.sublabel,
            "technique": s.technique, "mitre_id": s.mitre_id, "notes": s.notes, "ts": s.ts,
        } for s in attack_steps], ensure_ascii=False))

        loots_meta = []
        for loot in loots:
            loot_entry = {
                "id": loot.id, "host_id": loot.host_id, "loot_type": loot.loot_type,
                "value": loot.value, "description": loot.description,
                "source_path": loot.source_path, "filename": loot.filename,
                "content_type": loot.content_type, "file_size": loot.file_size,
                "public_url": loot.public_url, "ts": loot.ts,
            }
            disk = Path(loot.storage_path) if loot.storage_path else None
            if disk and disk.exists():
                zip_entry = f"loot/{loot.id}{Path(loot.filename or loot.value or 'loot.bin').suffix}"
                zf.write(disk, zip_entry)
                loot_entry["zip_entry"] = zip_entry
            loots_meta.append(loot_entry)
        zf.writestr("loots.json", json.dumps(loots_meta, ensure_ascii=False))

        zf.writestr("scopes.json", json.dumps([{
            "id": s.id, "value": s.value, "scope_type": s.scope_type,
            "in_scope": s.in_scope, "description": s.description,
        } for s in scopes], ensure_ascii=False))

        zf.writestr("checklist.json", json.dumps([{
            "id": c.id, "phase": c.phase, "text": c.text,
            "done": c.done, "order_idx": c.order_idx,
        } for c in checklist], ensure_ascii=False))

        zf.writestr("cred_host_notes.json", json.dumps([{
            "id": n.id, "cred_id": n.cred_id, "host_id": n.host_id,
            "notes": n.notes, "access": n.access,
        } for n in cred_host_notes], ensure_ascii=False))

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

        zf.writestr("attachments.json", json.dumps(atts_meta, ensure_ascii=False))

    buf.seek(0)
    safe_name = re.sub(r"[^\w\-.]", "_", project.name)
    filename = f"{safe_name}_export.zip"
    return StreamingResponse(buf, media_type="application/zip",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.post("/api/import_project", status_code=201)
async def import_project(file: UploadFile = File(...), db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
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
        project_data       = json.loads(zf.read("project.json"))
        notes_data         = read_json("notes.json")
        hosts_data         = read_json("hosts.json")
        creds_data         = read_json("creds.json")
        nets_data          = read_json("networks.json")
        atts_data          = read_json("attachments.json")
        findings_data      = read_json("findings.json")
        obj_data           = read_json("objectives.json")
        host_activity_data = read_json("host_activities.json")
        ap_data            = read_json("attack_paths.json")
        as_data            = read_json("attack_steps.json")
        loots_data         = read_json("loots.json")
        scopes_data        = read_json("scopes.json")
        checklist_data     = read_json("checklist.json")
        chn_data           = read_json("cred_host_notes.json")
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
            added=datetime.utcnow().strftime("%Y-%m-%d"),
            description=project_data.get("description", ""),
        )
        db.add(project)
        db.flush()
        # Make importer the owner of the new project
        add_project_owner(db, new_pid, user.id, created_by=user.id)

        note_id_map: dict[str, str] = {}
        note_objs: list[models.Note] = []
        for n in notes_data:
            new_nid = new_id("n")
            note_id_map[n["id"]] = new_nid
            obj = models.Note(
                id=new_nid, pid=new_pid,
                title=n.get("title", ""), content=n.get("content", ""),
                phase=n.get("phase", "recon"), tags=n.get("tags", []),
                ts=n.get("ts", ""), starred=n.get("starred", False),
            )
            db.add(obj)
            note_objs.append(obj)
        db.flush()

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
                storage_path=str(disk_path), public_url=new_url,
                ts=att.get("ts", datetime.utcnow().strftime("%Y-%m-%d %H:%M")),
            ))

        for obj in note_objs:
            content = obj.content or ""
            for old_url, new_url in url_map.items():
                content = content.replace(old_url, new_url)
            obj.content = content

        host_id_map: dict[str, str] = {}
        for h in hosts_data:
            new_hid = new_id("hst")
            host_id_map[h["id"]] = new_hid
            db.add(models.Host(
                id=new_hid, pid=new_pid,
                ip=h.get("ip", ""), ips=h.get("ips", []),
                hostname=h.get("hostname", ""), os=h.get("os", "Unknown"),
                status=h.get("status", "unknown"),
                ports=h.get("ports", []), services=h.get("services", []),
                tags=h.get("tags", []), notes=h.get("notes", ""),
                domain=normalize_domain(h.get("domain", "")),
                role=h.get("role", "unknown"), is_attacker=h.get("is_attacker", False),
            ))

        cred_id_map: dict[str, str] = {}
        for c in creds_data:
            old_hids = c.get("host_ids") or []
            new_hids = [host_id_map[hid] for hid in old_hids if hid in host_id_map]
            new_cid = new_id("c")
            if c.get("id"):
                cred_id_map[c["id"]] = new_cid
            db.add(models.Cred(
                id=new_cid, pid=new_pid,
                host=c.get("host", ""), username=c.get("username", ""),
                secret=c.get("secret", ""), type=c.get("type", "plain"),
                service=c.get("service", ""), notes=c.get("notes", ""),
                tags=c.get("tags", []), domain=normalize_domain(c.get("domain", "")),
                cracked=c.get("cracked", False),
                host_ids=new_hids, is_domain=c.get("is_domain", False),
            ))

        for net in nets_data:
            db.add(models.Network(
                id=new_id("net"), pid=new_pid,
                name=net.get("name", "Network"),
                background=net.get("background", "#07080b"),
                regions_json=net.get("regions", []),
                nodes_json=net.get("nodes", []),
                edges_json=net.get("edges", []),
            ))

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

        for o in obj_data:
            old_hid = o.get("host_id")
            db.add(models.Objective(
                id=new_id("obj"), pid=new_pid,
                host_id=host_id_map.get(old_hid) if old_hid else None,
                title=o.get("title", ""), description=o.get("description", ""),
                category=o.get("category", "flag"), points=o.get("points", 0),
                status=o.get("status", "not_started"),
                flag_value=o.get("flag_value", ""), captured_by=o.get("captured_by", ""),
                captured_at=o.get("captured_at", ""),
                ts=o.get("ts", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")),
            ))

        for a in host_activity_data:
            old_hid = a.get("host_id")
            new_hid = host_id_map.get(old_hid)
            if not new_hid:
                continue
            db.add(models.HostActivity(
                id=new_id("ha"), pid=new_pid, host_id=new_hid,
                title=a.get("title", ""), activity_type=a.get("activity_type", "recon"),
                command=a.get("command", ""), summary=a.get("summary", ""), output=a.get("output", ""),
                status=a.get("status", "done"), ts=a.get("ts", datetime.utcnow().strftime("%Y-%m-%d %H:%M")),
            ))

        path_id_map: dict[str, str] = {}
        for ap in ap_data:
            new_apid = new_id("ap")
            path_id_map[ap["id"]] = new_apid
            db.add(models.AttackPath(
                id=new_apid, pid=new_pid,
                name=ap.get("name", "Attack Path"), description=ap.get("description", ""),
                ts=ap.get("ts", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")),
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
                notes=s.get("notes", ""), ts=s.get("ts", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")),
            ))

        for l in loots_data:
            old_hid = l.get("host_id")
            new_lid = new_id("lt")
            filename = l.get("filename", "")
            content_type = l.get("content_type", "")
            file_size = l.get("file_size", 0)
            public_url = ""
            storage_path = ""
            source_path = l.get("source_path", "")

            zip_entry = l.get("zip_entry")
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

            db.add(models.Loot(
                id=new_lid, pid=new_pid,
                host_id=host_id_map.get(old_hid) if old_hid else None,
                loot_type=l.get("loot_type", "file"), value=l.get("value", ""),
                description=l.get("description", ""), source_path=source_path,
                filename=filename, content_type=content_type, file_size=file_size,
                storage_path=storage_path, public_url=public_url,
                ts=l.get("ts", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")),
            ))

        for s in scopes_data:
            db.add(models.Scope(
                id=new_id("sc"), pid=new_pid,
                value=s.get("value", ""), scope_type=s.get("scope_type", "cidr"),
                in_scope=s.get("in_scope", True), description=s.get("description", ""),
            ))

        if scopes_data:
            sync_project_ip_from_scopes(db, new_pid)
        else:
            sync_scopes_from_project_ip(db, new_pid)

        for c in checklist_data:
            db.add(models.ChecklistItem(
                id=new_id("cl"), pid=new_pid,
                phase=c.get("phase", "recon"), text=c.get("text", ""),
                done=c.get("done", False), order_idx=c.get("order_idx", 0),
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
    source: str = ""  # import_source applied to all new hosts if they don't have one


class BatchImportResult(BaseModel):
    hosts_added: int
    creds_added: int


@router.post("/api/import/{pid}", response_model=BatchImportResult, status_code=201)
def batch_import(pid: str, body: BatchImportBody, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, "Project not found")
    check_pid_access(db, pid, user, "project.import")

    all_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    existing_by_ip       = {h.ip: h for h in all_hosts if h.ip}
    existing_by_hostname = {(h.hostname or "").upper(): h for h in all_hosts if h.hostname}

    status_rank = {"unknown": 0, "alive": 1, "scanned": 2, "access": 3, "pwned": 4, "owned": 5}

    hosts_added = 0
    new_hosts = []
    for h in body.hosts:
        h_data = h.model_dump()
        h_data["pid"] = pid
        h_data["domain"] = normalize_domain(h_data.get("domain", ""))
        h_data["role"] = h_data.get("role") or "unknown"
        h_data["is_attacker"] = bool(h_data.get("is_attacker")) or h_data["role"] == "attacker"
        if h_data["is_attacker"]:
            h_data["status"] = "attacker"

        ip       = h_data.get("ip", "")
        hn_upper = (h_data.get("hostname") or "").upper()
        existing = existing_by_ip.get(ip) or (existing_by_hostname.get(hn_upper) if hn_upper else None)

        if existing:
            existing.ips      = list(dict.fromkeys((existing.ips or []) + h_data.get("ips", [])))
            existing.ports    = list(set((existing.ports    or []) + h_data.get("ports",    [])))
            existing.services = list(set((existing.services or []) + h_data.get("services", [])))
            existing.tags     = list(set((existing.tags     or []) + h_data.get("tags",     [])))
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
                existing_by_ip[existing.ip] = existing
            incoming_os = h_data.get("os", "")
            if incoming_os and incoming_os not in ("Unknown", "") and (
                existing.os in ("Unknown", "", None) or len(incoming_os) > len(existing.os or "")
            ):
                existing.os = incoming_os
            if h_data.get("notes"):
                if not existing.notes:
                    existing.notes = h_data["notes"]
                elif h_data["notes"] not in existing.notes:
                    existing.notes = existing.notes.rstrip() + "\n" + h_data["notes"]
            if status_rank.get(h_data.get("status", "unknown"), 0) > status_rank.get(existing.status, 0):
                existing.status = h_data["status"]
            new_hosts.append(existing)
        else:
            if body.source and not h_data.get("import_source"):
                h_data["import_source"] = body.source
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
        c_data["pid"] = pid
        c_data["domain"] = normalize_domain(c_data.get("domain", ""))
        cred = models.Cred(id=new_id("c"), **c_data)
        db.add(cred)
        creds_added += 1
        new_creds.append(cred)

    db.commit()

    for h in new_hosts:
        db.refresh(h)
        bcast(pid, "host", "upsert", schemas.Host.model_validate(h).model_dump())
    for c in new_creds:
        db.refresh(c)
        bcast(pid, "cred", "create", schemas.Cred.model_validate(c).model_dump())

    return BatchImportResult(hosts_added=hosts_added, creds_added=creds_added)
