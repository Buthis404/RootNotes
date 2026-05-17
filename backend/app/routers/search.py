import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_, func

from ..database import get_db
from .. import models, schemas
from ..core.deps import get_current_user, is_admin
from ..core.access import check_pid_access, get_user_member_pids
from ..core.limiter import limiter
from ..core.utils import ts_now

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
    if is_admin(user):
        return None
    return get_user_member_pids(db, user)


def _scope(query, model, pid_list, pid_exact: str):
    if pid_exact:
        return query.filter(model.pid == pid_exact)
    if pid_list is not None:
        return query.filter(model.pid.in_(pid_list))
    return query


_HL_OPTIONS = "MaxWords=15,MinWords=8,ShortWord=3,HighlightAll=FALSE,StartSel=<b>,StopSel=</b>"


def _fts(text_expr, q: str):
    """Return (match_condition, rank_expr, headline_fn) using websearch_to_tsquery."""
    vec = func.to_tsvector("english", text_expr)
    tsq = func.websearch_to_tsquery("english", q)
    rank = func.ts_rank_cd(vec, tsq)
    headline = lambda snippet_expr: func.ts_headline("english", snippet_expr, tsq, _HL_OPTIONS)  # noqa: E731
    return vec.op("@@")(tsq), rank, headline


def _ilike(q: str):
    return f"%{q}%"


def _host_related(h, db) -> list:
    related = []
    for c in db.query(models.Cred).filter(models.Cred.pid == h.pid, models.Cred.host == h.ip).limit(5).all():
        related.append({"type": "cred", "id": c.id, "title": c.username, "snippet": c.service or ""})
    for f in db.query(models.Finding).filter(models.Finding.pid == h.pid, models.Finding.host_id == h.id).limit(3).all():
        related.append({"type": "finding", "id": f.id, "title": f.title, "snippet": f.severity or ""})
    return related


@router.get("/api/search")
@limiter.limit("60/minute")
def search(
    request: Request,
    q: str = "",
    pid: str = "",
    limit: int = 40,
    offset: int = 0,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    q = q.strip()
    if not q or len(q) < 2:
        return {"items": [], "total": 0, "facets": {}, "has_more": False}

    clean_q, filters = _parse_query(q)
    pids = _allowed_pids(db, user, pid)
    type_f = filters.get("type")
    sev_f = filters.get("severity")
    status_f = filters.get("status")
    source_f = filters.get("source")

    use_fts = bool(clean_q and len(clean_q) >= 2)
    like = _ilike(clean_q or q)
    # per-type fetch limit before global sort — larger to allow proper ranking
    fetch = limit + offset + 40

    # Each item gets a _rank float for global ordering (higher = better match)
    items: list[dict] = []

    def _add(item: dict, rank_val: float = 0.0):
        item["_rank"] = float(rank_val)
        items.append(item)

    # ── Hosts ─────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("host", "hosts"):
        hq = _scope(db.query(models.Host), models.Host, pids, pid)
        if filters.get("role"):
            hq = hq.filter(models.Host.role == filters["role"])
        if status_f:
            hq = hq.filter(models.Host.status == status_f)
        if filters.get("tag"):
            hq = hq.filter(func.array_to_string(models.Host.tags, ",").ilike(f"%{filters['tag']}%"))
        vec_expr = (
            func.coalesce(models.Host.ip, "") + " "
            + func.coalesce(models.Host.hostname, "") + " "
            + func.coalesce(models.Host.os, "") + " "
            + func.coalesce(models.Host.notes, "")
        )
        if use_fts:
            match, rank, hl = _fts(vec_expr, clean_q)
            rows = hq.filter(match).add_columns(rank, hl(func.coalesce(models.Host.notes, func.coalesce(models.Host.os, "")))).order_by(rank.desc()).limit(fetch).all()
            for h, rv, snippet_hl in rows:
                related = _host_related(h, db)
                _add({"type": "host", "id": h.id, "pid": h.pid, "title": h.ip,
                      "subtitle": h.hostname or "",
                      "snippet": snippet_hl or ((h.os or "") + (" • " + h.role if h.role else "")),
                      "snippet_html": bool(snippet_hl and "<b>" in snippet_hl),
                      "meta": {"status": h.status, "role": h.role, "os": h.os},
                      "related": related}, rv)
        else:
            for h in hq.filter(or_(models.Host.ip.ilike(like), models.Host.hostname.ilike(like),
                                   models.Host.os.ilike(like), models.Host.notes.ilike(like))).limit(fetch).all():
                _add({"type": "host", "id": h.id, "pid": h.pid, "title": h.ip,
                      "subtitle": h.hostname or "",
                      "snippet": (h.os or "") + (" • " + h.role if h.role else ""),
                      "meta": {"status": h.status, "role": h.role, "os": h.os},
                      "related": _host_related(h, db)}, 0.5)

    # ── Creds ─────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("cred", "creds"):
        from ..core.permissions import get_membership, get_permissions_for_role
        cq = _scope(db.query(models.Cred), models.Cred, pids, pid)
        if filters.get("service"):
            cq = cq.filter(models.Cred.service == filters["service"])
        if filters.get("tag"):
            cq = cq.filter(func.array_to_string(models.Cred.tags, ",").ilike(f"%{filters['tag']}%"))
        vec_expr = (func.coalesce(models.Cred.username, "") + " " + func.coalesce(models.Cred.service, "")
                    + " " + func.coalesce(models.Cred.host, "") + " " + func.coalesce(models.Cred.notes, ""))
        if use_fts:
            match, rank, hl = _fts(vec_expr, clean_q)
            rows = cq.filter(match).add_columns(rank).order_by(rank.desc()).limit(fetch).all()
            for c, rv in rows:
                d = schemas.Cred.model_validate(c).model_dump()
                if not is_admin(user):
                    m = get_membership(db, c.pid, user.id)
                    if not m or "credentials.read_secret" not in get_permissions_for_role(m.role):
                        d["secret"] = ""
                _add({"type": "cred", "id": c.id, "pid": c.pid, "title": c.username,
                      "subtitle": c.host or "",
                      "snippet": (c.service or "unknown") + (" • cracked" if c.cracked else ""),
                      "meta": {"service": c.service, "cred_type": c.type, "cracked": c.cracked},
                      "_raw": d}, rv)
        else:
            for c in cq.filter(or_(models.Cred.username.ilike(like), models.Cred.service.ilike(like),
                                   models.Cred.host.ilike(like), models.Cred.notes.ilike(like))).limit(fetch).all():
                d = schemas.Cred.model_validate(c).model_dump()
                if not is_admin(user):
                    m = get_membership(db, c.pid, user.id)
                    if not m or "credentials.read_secret" not in get_permissions_for_role(m.role):
                        d["secret"] = ""
                _add({"type": "cred", "id": c.id, "pid": c.pid, "title": c.username,
                      "subtitle": c.host or "",
                      "snippet": (c.service or "unknown") + (" • cracked" if c.cracked else ""),
                      "meta": {"service": c.service, "cred_type": c.type, "cracked": c.cracked},
                      "_raw": d}, 0.5)

    # ── Notes ─────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("note", "notes"):
        nq = _scope(db.query(models.Note), models.Note, pids, pid)
        vec_expr = func.coalesce(models.Note.title, "") + " " + func.coalesce(models.Note.content, "")
        if use_fts:
            match, rank, hl = _fts(vec_expr, clean_q)
            rows = nq.filter(match).add_columns(rank, hl(func.coalesce(models.Note.content, ""))).order_by(rank.desc()).limit(fetch).all()
            for n, rv, snip in rows:
                _add({"type": "note", "id": n.id, "pid": n.pid, "title": n.title or "(untitled)",
                      "subtitle": "", "snippet": snip or (n.content or "")[:120],
                      "snippet_html": bool(snip and "<b>" in snip),
                      "meta": {"phase": n.phase, "starred": n.starred}}, rv)
        else:
            for n in nq.filter(or_(models.Note.title.ilike(like), models.Note.content.ilike(like))).limit(fetch).all():
                _add({"type": "note", "id": n.id, "pid": n.pid, "title": n.title or "(untitled)",
                      "subtitle": "", "snippet": (n.content or "")[:120],
                      "meta": {"phase": n.phase, "starred": n.starred}}, 0.5)

    # ── Findings ──────────────────────────────────────────────────────────────
    if not type_f or type_f in ("finding", "findings"):
        fq = _scope(db.query(models.Finding), models.Finding, pids, pid)
        if sev_f:
            fq = fq.filter(models.Finding.severity == sev_f)
        if status_f:
            fq = fq.filter(models.Finding.status == status_f)
        if source_f:
            fq = fq.filter(models.Finding.source == source_f)
        vec_expr = (func.coalesce(models.Finding.title, "") + " " + func.coalesce(models.Finding.description, "")
                    + " " + func.coalesce(models.Finding.cve, ""))
        if use_fts:
            match, rank, hl = _fts(vec_expr, clean_q)
            rows = fq.filter(match).add_columns(rank, hl(func.coalesce(models.Finding.description, ""))).order_by(rank.desc()).limit(fetch).all()
            for f, rv, snip in rows:
                _add({"type": "finding", "id": f.id, "pid": f.pid, "title": f.title,
                      "subtitle": f.cve or "", "snippet": snip or (f.description or "")[:120],
                      "snippet_html": bool(snip and "<b>" in snip),
                      "meta": {"severity": f.severity, "status": f.status, "source": f.source}}, rv)
        elif clean_q or (sev_f or status_f or source_f):
            filt = fq if (sev_f or status_f or source_f) and not clean_q else fq.filter(or_(
                models.Finding.title.ilike(like), models.Finding.description.ilike(like), models.Finding.cve.ilike(like)))
            for f in filt.limit(fetch).all():
                _add({"type": "finding", "id": f.id, "pid": f.pid, "title": f.title,
                      "subtitle": f.cve or "", "snippet": (f.description or "")[:120],
                      "meta": {"severity": f.severity, "status": f.status, "source": f.source}}, 0.5)

    # ── Loot ──────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("loot",):
        lq = _scope(db.query(models.Loot), models.Loot, pids, pid)
        vec_expr = (func.coalesce(models.Loot.description, "") + " " + func.coalesce(models.Loot.source_path, "")
                    + " " + func.coalesce(models.Loot.loot_type, ""))
        if use_fts:
            match, rank, hl = _fts(vec_expr, clean_q)
            rows = lq.filter(match).add_columns(rank).order_by(rank.desc()).limit(fetch).all()
            for l, rv in rows:
                _add({"type": "loot", "id": l.id, "pid": l.pid,
                      "title": l.description or l.loot_type or "loot",
                      "subtitle": l.source_path or "",
                      "snippet": l.loot_type + (f" • {l.artifact_type}" if getattr(l, "artifact_type", None) else ""),
                      "meta": {"loot_type": l.loot_type, "artifact_type": getattr(l, "artifact_type", None)}}, rv)
        else:
            for l in lq.filter(or_(models.Loot.value.ilike(like), models.Loot.description.ilike(like),
                                   models.Loot.source_path.ilike(like))).limit(fetch).all():
                _add({"type": "loot", "id": l.id, "pid": l.pid,
                      "title": l.description or l.loot_type or "loot",
                      "subtitle": l.source_path or "",
                      "snippet": l.loot_type + (f" • {l.artifact_type}" if getattr(l, "artifact_type", None) else ""),
                      "meta": {"loot_type": l.loot_type}}, 0.5)

    # ── Jobs ──────────────────────────────────────────────────────────────────
    if not type_f or type_f in ("job", "jobs"):
        jq = _scope(db.query(models.Job), models.Job, pids, pid)
        if status_f:
            jq = jq.filter(models.Job.status == status_f)
        if filters.get("connector"):
            jq = jq.filter(models.Job.connector_key == filters["connector"])
        vec_expr = func.coalesce(models.Job.title, "") + " " + func.coalesce(models.Job.connector_key, "")
        if use_fts:
            match, rank, _ = _fts(vec_expr, clean_q)
            rows = jq.filter(match).add_columns(rank).order_by(rank.desc()).limit(fetch).all()
            for j, rv in rows:
                _add({"type": "job", "id": j.id, "pid": j.pid, "title": j.title or j.id,
                      "subtitle": j.connector_key or "", "snippet": j.status or "",
                      "meta": {"status": j.status, "connector": j.connector_key}}, rv)
        else:
            for j in jq.filter(or_(models.Job.title.ilike(like), models.Job.connector_key.ilike(like))
                                ).order_by(models.Job.created_at.desc()).limit(fetch).all():
                _add({"type": "job", "id": j.id, "pid": j.pid, "title": j.title or j.id,
                      "subtitle": j.connector_key or "", "snippet": j.status or "",
                      "meta": {"status": j.status, "connector": j.connector_key}}, 0.5)

    # ── KB Articles ───────────────────────────────────────────────────────────
    if not type_f or type_f in ("kb", "knowledge"):
        kbq = db.query(models.KBArticle)
        if pid:
            kbq = kbq.filter(or_(models.KBArticle.pid == pid, models.KBArticle.pid == None))
        vec_expr = func.coalesce(models.KBArticle.title, "") + " " + func.coalesce(models.KBArticle.content, "")
        if use_fts:
            match, rank, hl = _fts(vec_expr, clean_q)
            rows = kbq.filter(match).add_columns(rank, hl(func.coalesce(models.KBArticle.content, ""))).order_by(rank.desc()).limit(fetch).all()
            for a, rv, snip in rows:
                _add({"type": "kb", "id": a.id, "pid": a.pid or "",
                      "title": a.title, "subtitle": a.category or "",
                      "snippet": snip or (a.content or "")[:120],
                      "snippet_html": bool(snip and "<b>" in snip),
                      "meta": {"category": a.category, "tags": a.tags or []}}, rv)
        else:
            for a in kbq.filter(or_(models.KBArticle.title.ilike(like), models.KBArticle.content.ilike(like))).limit(fetch).all():
                _add({"type": "kb", "id": a.id, "pid": a.pid or "",
                      "title": a.title, "subtitle": a.category or "",
                      "snippet": (a.content or "")[:120],
                      "meta": {"category": a.category, "tags": a.tags or []}}, 0.5)

    # ── Snippets ──────────────────────────────────────────────────────────────
    if not type_f or type_f in ("snippet", "snippets"):
        sq = db.query(models.CustomSnippet)
        vec_expr = (func.coalesce(models.CustomSnippet.title, "") + " "
                    + func.coalesce(models.CustomSnippet.command, "") + " "
                    + func.coalesce(models.CustomSnippet.opsec, ""))
        if use_fts:
            match, rank, hl = _fts(vec_expr, clean_q)
            rows = sq.filter(match).add_columns(rank, hl(func.coalesce(models.CustomSnippet.command, ""))).order_by(rank.desc()).limit(fetch).all()
            for s, rv, snip in rows:
                _add({"type": "snippet", "id": s.id, "pid": "",
                      "title": s.title, "subtitle": s.category or "",
                      "snippet": snip or (s.command or "")[:120],
                      "snippet_html": bool(snip and "<b>" in snip),
                      "meta": {"category": s.category, "tags": s.tags or []}}, rv)
        else:
            for s in sq.filter(or_(models.CustomSnippet.title.ilike(like), models.CustomSnippet.command.ilike(like),
                                   models.CustomSnippet.opsec.ilike(like))).limit(fetch).all():
                _add({"type": "snippet", "id": s.id, "pid": "",
                      "title": s.title, "subtitle": s.category or "",
                      "snippet": (s.command or "")[:120],
                      "meta": {"category": s.category, "tags": s.tags or []}}, 0.5)

    # ── Global ranking + pagination ───────────────────────────────────────────
    items.sort(key=lambda x: x["_rank"], reverse=True)
    # remove internal rank field
    for it in items:
        it.pop("_rank", None)

    total = len(items)
    page = items[offset: offset + limit]

    type_counts: dict[str, int] = {}
    for it in items:
        type_counts[it["type"]] = type_counts.get(it["type"], 0) + 1

    return {
        "items": page,
        "total": total,
        "has_more": (offset + limit) < total,
        "facets": {"type": type_counts},
        # backward-compat
        "hosts":    [i for i in page if i["type"] == "host"],
        "creds":    [i.get("_raw", i) for i in page if i["type"] == "cred"],
        "notes":    [i for i in page if i["type"] == "note"],
        "findings": [i for i in page if i["type"] == "finding"],
        "loots":    [i for i in page if i["type"] == "loot"],
    }


# ── Saved searches ────────────────────────────────────────────────────────────

class SavedSearchCreate(BaseModel):
    name: str
    query: str
    pid: str | None = None


@router.get("/api/saved-searches")
def list_saved_searches(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    rows = db.query(models.SavedSearch).filter(
        models.SavedSearch.user_id == user.id
    ).order_by(models.SavedSearch.created_at.desc()).all()
    return [{"id": r.id, "name": r.name, "query": r.query, "pid": r.pid, "created_at": r.created_at} for r in rows]


@router.post("/api/saved-searches", status_code=201)
def create_saved_search(
    body: SavedSearchCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    row = models.SavedSearch(
        id=str(uuid.uuid4()),
        user_id=user.id,
        name=body.name.strip() or body.query[:40],
        query=body.query,
        pid=body.pid or None,
        created_at=ts_now(),
    )
    db.add(row)
    db.commit()
    return {"id": row.id, "name": row.name, "query": row.query, "pid": row.pid, "created_at": row.created_at}


@router.delete("/api/saved-searches/{sid}", status_code=204)
def delete_saved_search(
    sid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    row = db.query(models.SavedSearch).filter(
        models.SavedSearch.id == sid,
        models.SavedSearch.user_id == user.id,
    ).first()
    if not row:
        raise HTTPException(404)
    db.delete(row)
    db.commit()
