import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Annotated
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access, get_user_member_pids
from ..core.deps import get_current_user, is_admin
from ..core.limiter import limiter
from ..core.utils import ts_now
from ..database import get_db

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

    def headline(snippet_expr):
        return func.ts_headline("english", snippet_expr, tsq, _HL_OPTIONS)

    return vec.op("@@")(tsq), rank, headline


def _ilike(q: str):
    return f"%{q}%"


def _host_related(h, db) -> list:
    related = []
    for c in (
        db.query(models.Cred)
        .filter(models.Cred.pid == h.pid, models.Cred.host == h.ip)
        .limit(5)
        .all()
    ):
        related.append(
            {"type": "cred", "id": c.id, "title": c.username, "snippet": c.service or ""}
        )
    for f in (
        db.query(models.Finding)
        .filter(models.Finding.pid == h.pid, models.Finding.host_id == h.id)
        .limit(3)
        .all()
    ):
        related.append(
            {"type": "finding", "id": f.id, "title": f.title, "snippet": f.severity or ""}
        )
    return related


def _host_snippet(h) -> str:
    return (h.os or "") + (" • " + h.role if h.role else "")


def _search_hosts(db, pids, pid, filters, use_fts, clean_q, like, fetch) -> list[dict]:
    items: list[dict] = []
    hq = _scope(db.query(models.Host), models.Host, pids, pid)
    if filters.get("role"):
        hq = hq.filter(models.Host.role == filters["role"])
    if filters.get("status"):
        hq = hq.filter(models.Host.status == filters["status"])
    if filters.get("tag"):
        hq = hq.filter(func.array_to_string(models.Host.tags, ",").ilike(f"%{filters['tag']}%"))
    vec_expr = (
        func.coalesce(models.Host.ip, "")
        + " " + func.coalesce(models.Host.hostname, "")
        + " " + func.coalesce(models.Host.os, "")
        + " " + func.coalesce(models.Host.notes, "")
    )
    meta_fn = lambda h: {"status": h.status, "role": h.role, "os": h.os}  # noqa: E731
    if use_fts:
        match, rank, hl = _fts(vec_expr, clean_q)
        rows = (
            hq.filter(match)
            .add_columns(rank, hl(func.coalesce(models.Host.notes, func.coalesce(models.Host.os, ""))))
            .order_by(rank.desc()).limit(fetch).all()
        )
        for h, rv, snippet_hl in rows:
            items.append({
                "_rank": float(rv), "type": "host", "id": h.id, "pid": h.pid,
                "title": h.ip, "subtitle": h.hostname or "",
                "snippet": snippet_hl or _host_snippet(h),
                "snippet_html": bool(snippet_hl and "<b>" in snippet_hl),
                "meta": meta_fn(h), "related": _host_related(h, db),
            })
    else:
        for h in hq.filter(or_(
            models.Host.ip.ilike(like), models.Host.hostname.ilike(like),
            models.Host.os.ilike(like), models.Host.notes.ilike(like),
        )).limit(fetch).all():
            items.append({
                "_rank": 0.5, "type": "host", "id": h.id, "pid": h.pid,
                "title": h.ip, "subtitle": h.hostname or "",
                "snippet": _host_snippet(h), "meta": meta_fn(h),
                "related": _host_related(h, db),
            })
    return items


def _mask_cred_secret(c, d: dict, user, db) -> None:
    from ..core.permissions import get_membership, get_permissions_for_role
    if is_admin(user):
        return
    m = get_membership(db, c.pid, user.id)
    if not m or "credentials.read_secret" not in get_permissions_for_role(m.role):
        d["secret"] = ""


def _cred_snippet(c) -> str:
    return (c.service or "unknown") + (" • cracked" if c.cracked else "")


def _search_creds(db, user, pids, pid, filters, use_fts, clean_q, like, fetch) -> list[dict]:
    items: list[dict] = []
    cq = _scope(db.query(models.Cred), models.Cred, pids, pid)
    if filters.get("service"):
        cq = cq.filter(models.Cred.service == filters["service"])
    if filters.get("tag"):
        cq = cq.filter(func.array_to_string(models.Cred.tags, ",").ilike(f"%{filters['tag']}%"))
    vec_expr = (
        func.coalesce(models.Cred.username, "")
        + " " + func.coalesce(models.Cred.service, "")
        + " " + func.coalesce(models.Cred.host, "")
        + " " + func.coalesce(models.Cred.notes, "")
    )
    meta_fn = lambda c: {"service": c.service, "cred_type": c.type, "cracked": c.cracked}  # noqa: E731
    if use_fts:
        match, rank, _ = _fts(vec_expr, clean_q)
        rows = cq.filter(match).add_columns(rank).order_by(rank.desc()).limit(fetch).all()
        for c, rv in rows:
            d = schemas.Cred.model_validate(c).model_dump()
            _mask_cred_secret(c, d, user, db)
            items.append({
                "_rank": float(rv), "type": "cred", "id": c.id, "pid": c.pid,
                "title": c.username, "subtitle": c.host or "",
                "snippet": _cred_snippet(c), "meta": meta_fn(c), "_raw": d,
            })
    else:
        for c in cq.filter(or_(
            models.Cred.username.ilike(like), models.Cred.service.ilike(like),
            models.Cred.host.ilike(like), models.Cred.notes.ilike(like),
        )).limit(fetch).all():
            d = schemas.Cred.model_validate(c).model_dump()
            _mask_cred_secret(c, d, user, db)
            items.append({
                "_rank": 0.5, "type": "cred", "id": c.id, "pid": c.pid,
                "title": c.username, "subtitle": c.host or "",
                "snippet": _cred_snippet(c), "meta": meta_fn(c), "_raw": d,
            })
    return items


def _search_notes(db, pids, pid, use_fts, clean_q, like, fetch) -> list[dict]:
    items: list[dict] = []
    nq = _scope(db.query(models.Note), models.Note, pids, pid)
    vec_expr = func.coalesce(models.Note.title, "") + " " + func.coalesce(models.Note.content, "")
    if use_fts:
        match, rank, hl = _fts(vec_expr, clean_q)
        rows = (
            nq.filter(match)
            .add_columns(rank, hl(func.coalesce(models.Note.content, "")))
            .order_by(rank.desc()).limit(fetch).all()
        )
        for n, rv, snip in rows:
            items.append({
                "_rank": float(rv), "type": "note", "id": n.id, "pid": n.pid,
                "title": n.title or "(untitled)", "subtitle": "",
                "snippet": snip or (n.content or "")[:120],
                "snippet_html": bool(snip and "<b>" in snip),
                "meta": {"phase": n.phase, "starred": n.starred},
            })
    else:
        for n in nq.filter(
            or_(models.Note.title.ilike(like), models.Note.content.ilike(like))
        ).limit(fetch).all():
            items.append({
                "_rank": 0.5, "type": "note", "id": n.id, "pid": n.pid,
                "title": n.title or "(untitled)", "subtitle": "",
                "snippet": (n.content or "")[:120],
                "meta": {"phase": n.phase, "starred": n.starred},
            })
    return items


def _findings_like_query(fq, sev_f, status_f, source_f, clean_q, like):
    if (sev_f or status_f or source_f) and not clean_q:
        return fq
    return fq.filter(or_(
        models.Finding.title.ilike(like),
        models.Finding.description.ilike(like),
        models.Finding.cve.ilike(like),
    ))


def _rank_key(x: dict) -> float:
    return x["_rank"]


def _findings_fts_item(f, rv, snip) -> dict:
    return {
        "_rank": float(rv), "type": "finding", "id": f.id, "pid": f.pid,
        "title": f.title, "subtitle": f.cve or "",
        "snippet": snip or (f.description or "")[:120],
        "snippet_html": bool(snip and "<b>" in snip),
        "meta": _findings_meta(f),
    }


def _findings_meta(f) -> dict:
    return {"severity": f.severity, "status": f.status, "source": f.source}


def _type_match(type_f: str, names: tuple) -> bool:
    return not type_f or type_f in names


def _search_findings(db, pids, pid, filters, use_fts, clean_q, like, fetch) -> list[dict]:
    items: list[dict] = []
    sev_f = filters.get("severity")
    status_f = filters.get("status")
    source_f = filters.get("source")
    fq = _scope(db.query(models.Finding), models.Finding, pids, pid)
    if sev_f:
        fq = fq.filter(models.Finding.severity == sev_f)
    if status_f:
        fq = fq.filter(models.Finding.status == status_f)
    if source_f:
        fq = fq.filter(models.Finding.source == source_f)
    vec_expr = (
        func.coalesce(models.Finding.title, "")
        + " " + func.coalesce(models.Finding.description, "")
        + " " + func.coalesce(models.Finding.cve, "")
    )
    if use_fts:
        match, rank, hl = _fts(vec_expr, clean_q)
        rows = (
            fq.filter(match)
            .add_columns(rank, hl(func.coalesce(models.Finding.description, "")))
            .order_by(rank.desc()).limit(fetch).all()
        )
        for f, rv, snip in rows:
            items.append(_findings_fts_item(f, rv, snip))
    elif clean_q or sev_f or status_f or source_f:
        for f in _findings_like_query(fq, sev_f, status_f, source_f, clean_q, like).limit(fetch).all():
            items.append({
                "_rank": 0.5, "type": "finding", "id": f.id, "pid": f.pid,
                "title": f.title, "subtitle": f.cve or "",
                "snippet": (f.description or "")[:120], "meta": _findings_meta(f),
            })
    return items


def _loot_snippet(loot) -> str:
    art = getattr(loot, "artifact_type", None)
    return loot.loot_type + (f" • {art}" if art else "")


def _search_loots(db, pids, pid, use_fts, clean_q, like, fetch) -> list[dict]:
    items: list[dict] = []
    lq = _scope(db.query(models.Loot), models.Loot, pids, pid)
    vec_expr = (
        func.coalesce(models.Loot.description, "")
        + " " + func.coalesce(models.Loot.source_path, "")
        + " " + func.coalesce(models.Loot.loot_type, "")
    )
    if use_fts:
        match, rank, _ = _fts(vec_expr, clean_q)
        rows = lq.filter(match).add_columns(rank).order_by(rank.desc()).limit(fetch).all()
        for loot, rv in rows:
            items.append({
                "_rank": float(rv), "type": "loot", "id": loot.id, "pid": loot.pid,
                "title": loot.description or loot.loot_type or "loot",
                "subtitle": loot.source_path or "", "snippet": _loot_snippet(loot),
                "meta": {"loot_type": loot.loot_type, "artifact_type": getattr(loot, "artifact_type", None)},
            })
    else:
        for loot in lq.filter(or_(
            models.Loot.value.ilike(like),
            models.Loot.description.ilike(like),
            models.Loot.source_path.ilike(like),
        )).limit(fetch).all():
            items.append({
                "_rank": 0.5, "type": "loot", "id": loot.id, "pid": loot.pid,
                "title": loot.description or loot.loot_type or "loot",
                "subtitle": loot.source_path or "", "snippet": _loot_snippet(loot),
                "meta": {"loot_type": loot.loot_type},
            })
    return items


def _search_jobs(db, pids, pid, filters, use_fts, clean_q, like, fetch) -> list[dict]:
    items: list[dict] = []
    jq = _scope(db.query(models.Job), models.Job, pids, pid)
    if filters.get("status"):
        jq = jq.filter(models.Job.status == filters["status"])
    if filters.get("connector"):
        jq = jq.filter(models.Job.connector_key == filters["connector"])
    vec_expr = func.coalesce(models.Job.title, "") + " " + func.coalesce(models.Job.connector_key, "")
    mk_item = lambda j, rank: {  # noqa: E731
        "_rank": rank, "type": "job", "id": j.id, "pid": j.pid,
        "title": j.title or j.id, "subtitle": j.connector_key or "",
        "snippet": j.status or "", "meta": {"status": j.status, "connector": j.connector_key},
    }
    if use_fts:
        match, rank_expr, _ = _fts(vec_expr, clean_q)
        for j, rv in jq.filter(match).add_columns(rank_expr).order_by(rank_expr.desc()).limit(fetch).all():
            items.append(mk_item(j, float(rv)))
    else:
        for j in jq.filter(
            or_(models.Job.title.ilike(like), models.Job.connector_key.ilike(like))
        ).order_by(models.Job.created_at.desc()).limit(fetch).all():
            items.append(mk_item(j, 0.5))
    return items


def _search_kb(db, pid, use_fts, clean_q, like, fetch) -> list[dict]:
    items: list[dict] = []
    kbq = db.query(models.KBArticle)
    if pid:
        kbq = kbq.filter(or_(models.KBArticle.pid == pid, models.KBArticle.pid == None))  # noqa: E711
    vec_expr = func.coalesce(models.KBArticle.title, "") + " " + func.coalesce(models.KBArticle.content, "")
    mk_item = lambda a, rank, snip="": {  # noqa: E731
        "_rank": rank, "type": "kb", "id": a.id, "pid": a.pid or "",
        "title": a.title, "subtitle": a.category or "",
        "snippet": snip or (a.content or "")[:120],
        "snippet_html": bool(snip and "<b>" in snip),
        "meta": {"category": a.category, "tags": a.tags or []},
    }
    if use_fts:
        match, rank, hl = _fts(vec_expr, clean_q)
        rows = (
            kbq.filter(match)
            .add_columns(rank, hl(func.coalesce(models.KBArticle.content, "")))
            .order_by(rank.desc()).limit(fetch).all()
        )
        for a, rv, snip in rows:
            items.append(mk_item(a, float(rv), snip))
    else:
        for a in kbq.filter(
            or_(models.KBArticle.title.ilike(like), models.KBArticle.content.ilike(like))
        ).limit(fetch).all():
            items.append(mk_item(a, 0.5))
    return items


def _search_snippets(db, use_fts, clean_q, like, fetch) -> list[dict]:
    items: list[dict] = []
    sq = db.query(models.CustomSnippet)
    vec_expr = (
        func.coalesce(models.CustomSnippet.title, "")
        + " " + func.coalesce(models.CustomSnippet.command, "")
        + " " + func.coalesce(models.CustomSnippet.opsec, "")
    )
    mk_item = lambda s, rank, snip="": {  # noqa: E731
        "_rank": rank, "type": "snippet", "id": s.id, "pid": "",
        "title": s.title, "subtitle": s.category or "",
        "snippet": snip or (s.command or "")[:120],
        "snippet_html": bool(snip and "<b>" in snip),
        "meta": {"category": s.category, "tags": s.tags or []},
    }
    if use_fts:
        match, rank, hl = _fts(vec_expr, clean_q)
        rows = (
            sq.filter(match)
            .add_columns(rank, hl(func.coalesce(models.CustomSnippet.command, "")))
            .order_by(rank.desc()).limit(fetch).all()
        )
        for s, rv, snip in rows:
            items.append(mk_item(s, float(rv), snip))
    else:
        for s in sq.filter(or_(
            models.CustomSnippet.title.ilike(like),
            models.CustomSnippet.command.ilike(like),
            models.CustomSnippet.opsec.ilike(like),
        )).limit(fetch).all():
            items.append(mk_item(s, 0.5))
    return items


@router.get("/api/search", responses={404: {"description": "Not found"}})
@limiter.limit("60/minute")
def search(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    q: str = "",
    pid: str = "",
    limit: int = 40,
    offset: int = 0,
):
    q = q.strip()
    if not q or len(q) < 2:
        return {"items": [], "total": 0, "facets": {}, "has_more": False}

    clean_q, filters = _parse_query(q)
    pids = _allowed_pids(db, user, pid)
    type_f = filters.get("type")
    use_fts = bool(clean_q and len(clean_q) >= 2)
    like = _ilike(clean_q or q)
    fetch = limit + offset + 40  # per-type fetch limit before global sort

    items: list[dict] = []
    if _type_match(type_f, ("host", "hosts")):
        items.extend(_search_hosts(db, pids, pid, filters, use_fts, clean_q, like, fetch))
    if _type_match(type_f, ("cred", "creds")):
        items.extend(_search_creds(db, user, pids, pid, filters, use_fts, clean_q, like, fetch))
    if _type_match(type_f, ("note", "notes")):
        items.extend(_search_notes(db, pids, pid, use_fts, clean_q, like, fetch))
    if _type_match(type_f, ("finding", "findings")):
        items.extend(_search_findings(db, pids, pid, filters, use_fts, clean_q, like, fetch))
    if _type_match(type_f, ("loot",)):
        items.extend(_search_loots(db, pids, pid, use_fts, clean_q, like, fetch))
    if _type_match(type_f, ("job", "jobs")):
        items.extend(_search_jobs(db, pids, pid, filters, use_fts, clean_q, like, fetch))
    if _type_match(type_f, ("kb", "knowledge")):
        items.extend(_search_kb(db, pid, use_fts, clean_q, like, fetch))
    if _type_match(type_f, ("snippet", "snippets")):
        items.extend(_search_snippets(db, use_fts, clean_q, like, fetch))

    items.sort(key=_rank_key, reverse=True)
    for it in items:
        it.pop("_rank", None)

    total = len(items)
    page = items[offset : offset + limit]

    type_counts: dict[str, int] = {}
    for it in items:
        type_counts[it["type"]] = type_counts.get(it["type"], 0) + 1

    return {
        "items": page,
        "total": total,
        "has_more": (offset + limit) < total,
        "facets": {"type": type_counts},
        # backward-compat
        "hosts": [i for i in page if i["type"] == "host"],
        "creds": [i.get("_raw", i) for i in page if i["type"] == "cred"],
        "notes": [i for i in page if i["type"] == "note"],
        "findings": [i for i in page if i["type"] == "finding"],
        "loots": [i for i in page if i["type"] == "loot"],
    }


# ── Saved searches ────────────────────────────────────────────────────────────


class SavedSearchCreate(BaseModel):
    name: str
    query: str
    pid: str | None = None


@router.get("/api/saved-searches", responses={404: {"description": "Not found"}})
def list_saved_searches(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    rows = (
        db.query(models.SavedSearch)
        .filter(models.SavedSearch.user_id == user.id)
        .order_by(models.SavedSearch.created_at.desc())
        .all()
    )
    return [
        {"id": r.id, "name": r.name, "query": r.query, "pid": r.pid, "created_at": r.created_at}
        for r in rows
    ]


@router.post("/api/saved-searches", status_code=201, responses={404: {"description": "Not found"}})
def create_saved_search(
    body: SavedSearchCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
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
    return {
        "id": row.id,
        "name": row.name,
        "query": row.query,
        "pid": row.pid,
        "created_at": row.created_at,
    }


@router.delete("/api/saved-searches/{sid}", status_code=204, responses={404: {"description": "Not found"}})
def delete_saved_search(
    sid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    row = (
        db.query(models.SavedSearch)
        .filter(
            models.SavedSearch.id == sid,
            models.SavedSearch.user_id == user.id,
        )
        .first()
    )
    if not row:
        raise HTTPException(404)
    db.delete(row)
    db.commit()
