from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_, func

from ..database import get_db
from .. import models, schemas
from ..core.deps import get_current_user
from ..core.access import check_pid_access, get_user_member_pids

router = APIRouter(tags=["search"])

_FILTER_KEYS = {"type", "severity", "status", "service", "role", "source", "connector", "tag"}


def _parse_query(raw: str):
    """Split 'key:value' filter tokens from free-text query."""
    filters = {}
    words = []
    for token in raw.strip().split():
        if ":" in token:
            k, v = token.split(":", 1)
            if k in _FILTER_KEYS and v:
                filters[k] = v.lower()
                continue
        words.append(token)
    return " ".join(words), filters


def _allowed_pids(db, user, pid: str):
    if pid:
        check_pid_access(db, pid, user, "search.read")
        return [pid]
    if user.role == "admin":
        return None
    return get_user_member_pids(db, user)


def _scope(query, model, pid_list, pid_exact: str):
    if pid_exact:
        return query.filter(model.pid == pid_exact)
    if pid_list is not None:
        return query.filter(model.pid.in_(pid_list))
    return query


def _fts(text_expr, q: str):
    """Return (match_condition, rank_expr) using websearch_to_tsquery."""
    vec = func.to_tsvector("english", text_expr)
    tsq = func.websearch_to_tsquery("english", q)
    return vec.op("@@")(tsq), func.ts_rank(vec, tsq)


def _ilike(q: str):
    return f"%{q}%"


@router.get("/api/search")
def search(
    q: str = "",
    pid: str = "",
    limit: int = 60,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    q = q.strip()
    if not q or len(q) < 2:
        return {"items": [], "total": 0, "facets": {}}

    clean_q, filters = _parse_query(q)
    pids = _allowed_pids(db, user, pid)
    type_f = filters.get("type")
    sev_f = filters.get("severity")
    status_f = filters.get("status")
    source_f = filters.get("source")

    # decide search mode
    use_fts = bool(clean_q and len(clean_q) >= 2)
    like = _ilike(clean_q or q)

    items: list[dict] = []

    # ── Hosts ────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("host", "hosts"):
        hq = _scope(db.query(models.Host), models.Host, pids, pid)
        if filters.get("role"):
            hq = hq.filter(models.Host.role == filters["role"])
        if status_f:
            hq = hq.filter(models.Host.status == status_f)
        if filters.get("tag"):
            hq = hq.filter(func.array_to_string(models.Host.tags, ",").ilike(f"%{filters['tag']}%"))
        if use_fts:
            vec_expr = (
                func.coalesce(models.Host.ip, "") + " "
                + func.coalesce(models.Host.hostname, "") + " "
                + func.coalesce(models.Host.os, "") + " "
                + func.coalesce(models.Host.notes, "")
            )
            match, rank = _fts(vec_expr, clean_q)
            hq = hq.filter(match).order_by(rank.desc())
        else:
            hq = hq.filter(or_(
                models.Host.ip.ilike(like),
                models.Host.hostname.ilike(like),
                models.Host.os.ilike(like),
                models.Host.notes.ilike(like),
            ))
        for h in hq.limit(limit).all():
            # related: creds and findings linked to this host
            related = []
            linked_creds = db.query(models.Cred).filter(
                models.Cred.pid == h.pid, models.Cred.host == h.ip
            ).limit(5).all()
            for c in linked_creds:
                related.append({"type": "cred", "id": c.id, "title": c.username, "snippet": c.service or ""})
            linked_findings = db.query(models.Finding).filter(
                models.Finding.pid == h.pid,
                models.Finding.host_id == h.id,
            ).limit(3).all()
            for f in linked_findings:
                related.append({"type": "finding", "id": f.id, "title": f.title, "snippet": f.severity or ""})
            items.append({
                "type": "host", "id": h.id, "pid": h.pid,
                "title": h.ip,
                "subtitle": h.hostname or "",
                "snippet": (h.os or "") + (" • " + h.role if h.role else ""),
                "meta": {"status": h.status, "role": h.role, "os": h.os},
                "related": related,
            })

    # ── Creds ─────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("cred", "creds"):
        cq = _scope(db.query(models.Cred), models.Cred, pids, pid)
        if filters.get("service"):
            cq = cq.filter(models.Cred.service == filters["service"])
        if filters.get("tag"):
            cq = cq.filter(func.array_to_string(models.Cred.tags, ",").ilike(f"%{filters['tag']}%"))
        if use_fts:
            vec_expr = (
                func.coalesce(models.Cred.username, "") + " "
                + func.coalesce(models.Cred.service, "") + " "
                + func.coalesce(models.Cred.host, "") + " "
                + func.coalesce(models.Cred.notes, "")
            )
            match, rank = _fts(vec_expr, clean_q)
            cq = cq.filter(match).order_by(rank.desc())
        else:
            cq = cq.filter(or_(
                models.Cred.username.ilike(like),
                models.Cred.service.ilike(like),
                models.Cred.host.ilike(like),
                models.Cred.notes.ilike(like),
            ))
        from ..core.permissions import get_membership, get_permissions_for_role
        for c in cq.limit(limit).all():
            d = schemas.Cred.model_validate(c).model_dump()
            if user.role != "admin":
                m = get_membership(db, c.pid, user.id)
                if not m or "credentials.read_secret" not in get_permissions_for_role(m.role):
                    d["secret"] = ""
            items.append({
                "type": "cred", "id": c.id, "pid": c.pid,
                "title": c.username,
                "subtitle": c.host or "",
                "snippet": (c.service or "unknown") + (" • cracked" if c.cracked else ""),
                "meta": {"service": c.service, "cred_type": c.type, "cracked": c.cracked},
                "_raw": d,
            })

    # ── Notes ─────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("note", "notes"):
        nq = _scope(db.query(models.Note), models.Note, pids, pid)
        if use_fts:
            vec_expr = (
                func.coalesce(models.Note.title, "") + " "
                + func.coalesce(models.Note.content, "")
            )
            match, rank = _fts(vec_expr, clean_q)
            nq = nq.filter(match).order_by(rank.desc())
        else:
            nq = nq.filter(or_(
                models.Note.title.ilike(like),
                models.Note.content.ilike(like),
            ))
        for n in nq.limit(limit).all():
            items.append({
                "type": "note", "id": n.id, "pid": n.pid,
                "title": n.title or "(untitled)",
                "subtitle": "",
                "snippet": (n.content or "")[:100],
                "meta": {"phase": n.phase, "starred": n.starred},
            })

    # ── Findings ──────────────────────────────────────────────────────────────
    if not type_f or type_f in ("finding", "findings"):
        fq = _scope(db.query(models.Finding), models.Finding, pids, pid)
        if sev_f:
            fq = fq.filter(models.Finding.severity == sev_f)
        if status_f:
            fq = fq.filter(models.Finding.status == status_f)
        if source_f:
            fq = fq.filter(models.Finding.source == source_f)
        if use_fts:
            vec_expr = (
                func.coalesce(models.Finding.title, "") + " "
                + func.coalesce(models.Finding.description, "") + " "
                + func.coalesce(models.Finding.cve, "")
            )
            match, rank = _fts(vec_expr, clean_q)
            fq = fq.filter(match).order_by(rank.desc())
        elif clean_q or not (sev_f or status_f or source_f):
            fq = fq.filter(or_(
                models.Finding.title.ilike(like),
                models.Finding.description.ilike(like),
                models.Finding.cve.ilike(like),
            ))
        for f in fq.limit(limit).all():
            items.append({
                "type": "finding", "id": f.id, "pid": f.pid,
                "title": f.title,
                "subtitle": f.cve or "",
                "snippet": (f.description or "")[:100],
                "meta": {"severity": f.severity, "status": f.status, "source": f.source},
            })

    # ── Loot ──────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("loot",):
        lq = _scope(db.query(models.Loot), models.Loot, pids, pid)
        if use_fts:
            vec_expr = (
                func.coalesce(models.Loot.description, "") + " "
                + func.coalesce(models.Loot.source_path, "") + " "
                + func.coalesce(models.Loot.loot_type, "")
            )
            match, rank = _fts(vec_expr, clean_q)
            lq = lq.filter(match).order_by(rank.desc())
        else:
            lq = lq.filter(or_(
                models.Loot.value.ilike(like),
                models.Loot.description.ilike(like),
                models.Loot.source_path.ilike(like),
            ))
        for l in lq.limit(limit).all():
            items.append({
                "type": "loot", "id": l.id, "pid": l.pid,
                "title": l.description or l.loot_type or "loot",
                "subtitle": l.source_path or "",
                "snippet": l.loot_type + (f" • {l.artifact_type}" if getattr(l, "artifact_type", None) else ""),
                "meta": {"loot_type": l.loot_type, "artifact_type": getattr(l, "artifact_type", None)},
            })

    # ── Jobs ──────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("job", "jobs"):
        jq = _scope(db.query(models.Job), models.Job, pids, pid)
        if status_f:
            jq = jq.filter(models.Job.status == status_f)
        if filters.get("connector"):
            jq = jq.filter(models.Job.connector_key == filters["connector"])
        if use_fts:
            vec_expr = (
                func.coalesce(models.Job.title, "") + " "
                + func.coalesce(models.Job.connector_key, "")
            )
            match, rank = _fts(vec_expr, clean_q)
            jq = jq.filter(match).order_by(rank.desc())
        else:
            jq = jq.filter(or_(
                models.Job.title.ilike(like),
                models.Job.connector_key.ilike(like),
            ))
        for j in jq.order_by(models.Job.created_at.desc()).limit(limit).all():
            items.append({
                "type": "job", "id": j.id, "pid": j.pid,
                "title": j.title or j.id,
                "subtitle": j.connector_key or "",
                "snippet": j.status or "",
                "meta": {"status": j.status, "connector": j.connector_key},
            })

    # Facets (type counts)
    type_counts: dict[str, int] = {}
    for it in items:
        type_counts[it["type"]] = type_counts.get(it["type"], 0) + 1

    return {
        "items": items[:limit],
        "total": len(items),
        "facets": {"type": type_counts},
        # backward-compat fields
        "hosts":    [i for i in items if i["type"] == "host"],
        "creds":    [i.get("_raw", i) for i in items if i["type"] == "cred"],
        "notes":    [i for i in items if i["type"] == "note"],
        "findings": [i for i in items if i["type"] == "finding"],
        "loots":    [i for i in items if i["type"] == "loot"],
    }
