from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_

from ..database import get_db
from .. import models, schemas
from ..core.deps import get_current_user
from ..core.access import check_pid_access, get_user_member_pids

router = APIRouter(tags=["search"])


@router.get("/api/search")
def search(q: str = "", pid: str = "", limit: int = 30, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if not q or len(q) < 2:
        return {"hosts": [], "creds": [], "notes": [], "findings": [], "loots": []}

    like = f"%{q}%"

    hq = db.query(models.Host)
    cq = db.query(models.Cred)
    nq = db.query(models.Note)
    fq = db.query(models.Finding)
    lq = db.query(models.Loot)

    if pid:
        check_pid_access(db, pid, user, "search.read")
        hq = hq.filter(models.Host.pid == pid)
        cq = cq.filter(models.Cred.pid == pid)
        nq = nq.filter(models.Note.pid == pid)
        fq = fq.filter(models.Finding.pid == pid)
        lq = lq.filter(models.Loot.pid == pid)
    elif user.role != "admin":
        member_pids = get_user_member_pids(db, user)
        hq = hq.filter(models.Host.pid.in_(member_pids))
        cq = cq.filter(models.Cred.pid.in_(member_pids))
        nq = nq.filter(models.Note.pid.in_(member_pids))
        fq = fq.filter(models.Finding.pid.in_(member_pids))
        lq = lq.filter(models.Loot.pid.in_(member_pids))

    hq = hq.filter(or_(
        models.Host.ip.ilike(like),
        models.Host.hostname.ilike(like),
        models.Host.os.ilike(like),
        models.Host.notes.ilike(like),
    ))

    cq = cq.filter(or_(
        models.Cred.username.ilike(like),
        models.Cred.service.ilike(like),
        models.Cred.host.ilike(like),
        models.Cred.notes.ilike(like),
    ))

    nq = nq.filter(or_(
        models.Note.title.ilike(like),
        models.Note.content.ilike(like),
    ))

    fq = fq.filter(or_(
        models.Finding.title.ilike(like),
        models.Finding.description.ilike(like),
        models.Finding.cve.ilike(like),
    ))

    lq = lq.filter(or_(
        models.Loot.value.ilike(like),
        models.Loot.description.ilike(like),
        models.Loot.source_path.ilike(like),
    ))

    # Mask cred secrets if no permission per project
    from ..core.permissions import get_membership, get_permissions_for_role
    def cred_dump(c):
        d = schemas.Cred.model_validate(c).model_dump()
        if user.role != "admin":
            m = get_membership(db, c.pid, user.id)
            if not m or "credentials.read_secret" not in get_permissions_for_role(m.role):
                d["secret"] = ""
        return d

    hosts    = [schemas.Host.model_validate(h).model_dump() for h in hq.limit(limit).all()]
    creds    = [cred_dump(c) for c in cq.limit(limit).all()]
    notes    = [schemas.Note.model_validate(n).model_dump() for n in nq.limit(limit).all()]
    findings = [schemas.Finding.model_validate(f).model_dump() for f in fq.limit(limit).all()]
    loots    = [schemas.Loot.model_validate(l).model_dump() for l in lq.limit(limit).all()]
    return {"hosts": hosts, "creds": creds, "notes": notes, "findings": findings, "loots": loots}
