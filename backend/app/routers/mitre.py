from fastapi import APIRouter, Depends
from typing import Annotated
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..database import get_db
from .kb import MITRE_CATEGORY

router = APIRouter(tags=["mitre"])

TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def _kb_to_technique(article: models.KBArticle) -> dict:
    mid = article.tags[0] if article.tags else ""
    # title format: "T1234 — Name"  or just the title
    name = article.title
    if " — " in name:
        name = name.split(" — ", 1)[1]
    tactic = ""
    for tag in article.tags or []:
        # tactic stored as snake_case tag, e.g. "lateral_movement"
        candidate = tag.replace("_", " ").title()
        if candidate in TACTIC_ORDER:
            tactic = candidate
            break
    return {"id": mid, "tactic": tactic, "name": name, "kb_id": article.id}


def _index_attack_steps(steps) -> tuple[set, dict]:
    used_ids: set[str] = set()
    used_names: dict[str, list[dict]] = {}
    for s in steps:
        mid = (s.mitre_id or "").strip().upper()
        if mid:
            used_ids.add(mid)
        tech = (s.technique or "").strip()
        if tech:
            key = tech.lower()
            if key not in used_names:
                used_names[key] = []
            used_names[key].append({"step_id": s.id, "label": s.label, "technique": tech})
    return used_ids, used_names


@router.get("/api/projects/{pid}/mitre/coverage")
def get_mitre_coverage(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")

    kb_articles = (
        db.query(models.KBArticle)
        .filter(
            models.KBArticle.pid is None,
            models.KBArticle.category == MITRE_CATEGORY,
        )
        .all()
    )

    techniques = [_kb_to_technique(a) for a in kb_articles]
    kb_seeded = len(techniques) > 0
    steps = db.query(models.AttackStep).filter(models.AttackStep.pid == pid).all()
    used_ids, used_names = _index_attack_steps(steps)

    enriched = []
    for t in techniques:
        tid = t["id"].upper()
        name_key = t["name"].lower()
        used = tid in used_ids or any(name_key in k or k in name_key for k in used_names)
        enriched.append({**t, "used": used})

    unmapped = []
    known_ids = {t["id"].upper() for t in techniques}
    for s in steps:
        mid = (s.mitre_id or "").strip().upper()
        if mid and mid not in known_ids:
            unmapped.append({"id": mid, "name": s.technique or "", "label": s.label})

    return {
        "techniques": enriched,
        "tactic_order": TACTIC_ORDER,
        "kb_seeded": kb_seeded,
        "stats": {
            "total_techniques": len(techniques),
            "covered": sum(1 for t in enriched if t["used"]),
            "steps_with_mitre": sum(1 for s in steps if s.mitre_id),
            "steps_total": len(steps),
        },
        "unmapped": unmapped,
    }
