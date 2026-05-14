import re
import uuid
import json
from datetime import datetime, timezone
from pathlib import Path
from fastapi import HTTPException
from sqlalchemy.orm import Session

from .config import UPLOAD_ROOT, DEFAULT_CATALOG_PATH, SAFE_UPLOAD_RE
from .. import models


def new_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def ts_now() -> str:
    """Return current UTC time as ISO-8601 string with Z suffix: 2026-01-15T14:32:07Z"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_domain(value: str) -> str:
    cleaned = (value or "").strip().lower()
    if cleaned and cleaned.replace('.', '') == '':
        return ''
    cleaned = re.sub(r"\.{2,}", ".", cleaned)
    return cleaned


def domain_short_label(value: str) -> str:
    normalized = normalize_domain(value).strip('.')
    if not normalized:
        return ""
    return normalized.split(".", 1)[0]


def domains_match(left: str, right: str) -> bool:
    a = normalize_domain(left).strip('.')
    b = normalize_domain(right).strip('.')
    if not a or not b:
        return False
    if a == b:
        return True
    a_has_dot = "." in a
    b_has_dot = "." in b
    if not a_has_dot and b_has_dot:
        return a == domain_short_label(b)
    if not b_has_dot and a_has_dot:
        return b == domain_short_label(a)
    return False


def norm_text(value: str) -> str:
    return " ".join((value or "").strip().lower().split())


def safe_upload_name(name: str) -> str:
    base = Path(name or "attachment.bin").name
    cleaned = SAFE_UPLOAD_RE.sub("_", base).strip("._")
    return cleaned or "attachment.bin"


def ensure_under_upload_root(path: Path) -> Path:
    root = UPLOAD_ROOT.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise HTTPException(400, "Invalid upload path")
    return resolved


def split_scope_values(raw: str) -> list[str]:
    parts = re.split(r"[\n,;]+", raw or "")
    out = []
    seen = set()
    for part in parts:
        value = part.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def infer_scope_type(value: str) -> str:
    val = (value or "").strip().lower()
    if val.startswith("http://") or val.startswith("https://"):
        return "url"
    if "/" in val and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", val):
        return "cidr"
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val):
        return "cidr"
    if "." in val and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val):
        return (
            "domain"
            if val.count(".") == 1 or val.endswith(".local") or val.endswith(".corp") or val.endswith(".lan")
            else "hostname"
        )
    return "hostname"


def is_project_network_value(value: str) -> bool:
    val = (value or "").strip()
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$", val))


def sync_project_ip_from_scopes(db: Session, pid: str):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        return
    scopes = (
        db.query(models.Scope)
        .filter(models.Scope.pid == pid, models.Scope.in_scope == True)
        .all()
    )
    values = [
        s.value.strip()
        for s in scopes
        if (s.value or "").strip() and s.scope_type == "cidr" and is_project_network_value(s.value)
    ]
    next_ip = ", ".join(values)
    if project.ip != next_ip:
        project.ip = next_ip


def sync_scopes_from_project_ip(db: Session, pid: str):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        return
    target_values = [v for v in split_scope_values(project.ip) if is_project_network_value(v)]
    scopes = (
        db.query(models.Scope)
        .filter(models.Scope.pid == pid, models.Scope.in_scope == True, models.Scope.scope_type == "cidr")
        .all()
    )
    by_value = {s.value.strip(): s for s in scopes if (s.value or "").strip()}

    for value in target_values:
        existing = by_value.get(value)
        inferred_type = infer_scope_type(value)
        if existing:
            if existing.scope_type != inferred_type:
                existing.scope_type = inferred_type
        else:
            db.add(models.Scope(
                id=new_id("sc"),
                pid=pid,
                value=value,
                scope_type=inferred_type,
                in_scope=True,
                description="",
            ))

    for scope in scopes:
        if (scope.value or "").strip() not in target_values:
            db.delete(scope)


def load_default_catalog() -> dict:
    try:
        return json.loads(DEFAULT_CATALOG_PATH.read_text())
    except Exception:
        return {"finding_templates": [], "snippets": []}


def list_default_finding_templates() -> list[dict]:
    return [
        {**item, "created_at": "", "is_custom": False}
        for item in load_default_catalog().get("finding_templates", [])
    ]


def list_default_snippets() -> list[dict]:
    return [
        {**item, "created_at": "", "is_custom": False}
        for item in load_default_catalog().get("snippets", [])
    ]
