from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models, schemas
from ..core.deps import get_current_user
from ..core.access import check_pid_access, get_user_member_pids

router = APIRouter(tags=["search"])


@router.get("/api/search")
def search(q: str = "", pid: str = "", limit: int = 30, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    if not q or len(q) < 2:
        return {"hosts": [], "creds": [], "notes": [], "findings": [], "loots": []}
    ql = q.lower()

    def match_host(h):
        return ql in (f"{h.ip} {h.hostname} {h.notes} {' '.join(h.tags or [])}").lower()

    def match_cred(c):
        return ql in (f"{c.username} {c.service} {c.host} {c.notes} {' '.join(c.tags or [])}").lower()

    def match_note(n):
        return ql in (f"{n.title} {n.content[:500]} {' '.join(n.tags or [])}").lower()

    def match_finding(f):
        return ql in (f"{f.title} {f.description[:300]} {f.cve}").lower()

    def match_loot(loot):
        return ql in (f"{loot.value} {loot.description} {loot.source_path}").lower()

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
        # Restrict to user's member projects
        member_pids = get_user_member_pids(db, user)
        hq = hq.filter(models.Host.pid.in_(member_pids))
        cq = cq.filter(models.Cred.pid.in_(member_pids))
        nq = nq.filter(models.Note.pid.in_(member_pids))
        fq = fq.filter(models.Finding.pid.in_(member_pids))
        lq = lq.filter(models.Loot.pid.in_(member_pids))

    # Mask cred secrets if no permission per project
    from ..core.permissions import get_membership, get_permissions_for_role
    def cred_dump(c):
        d = schemas.Cred.model_validate(c).model_dump()
        if user.role != "admin":
            m = get_membership(db, c.pid, user.id)
            if not m or "credentials.read_secret" not in get_permissions_for_role(m.role):
                d["secret"] = ""
        return d

    hosts    = [schemas.Host.model_validate(h).model_dump() for h in hq.all() if match_host(h)][:limit]
    creds    = [cred_dump(c) for c in cq.all() if match_cred(c)][:limit]
    notes    = [schemas.Note.model_validate(n).model_dump() for n in nq.all() if match_note(n)][:limit]
    findings = [schemas.Finding.model_validate(f).model_dump() for f in fq.all() if match_finding(f)][:limit]
    loots    = [schemas.Loot.model_validate(l).model_dump() for l in lq.all() if match_loot(l)][:limit]
    return {"hosts": hosts, "creds": creds, "notes": notes, "findings": findings, "loots": loots}
