from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ... import models
from ...core.crypto import decrypt_str, encrypt_str
from ...core.deps import get_current_user, is_admin
from ...core.enums import MemberRole
from ...core.utils import new_id
from ...database import get_db
from ...plugins.registry import registry

_C2_STATUS_RANK = {"unknown": 0, "up": 1, "alive": 1, "access": 2, "pwned": 3, "owned": 4}


def _normalize_host_status(value: str) -> str:
    raw = (value or "").strip().lower()
    if raw in {"owned", "pwned", "access", "up", "alive", "unknown"}:
        return raw
    if raw in {"compromised", "compromise"}:
        return "pwned"
    return ""


def _has_live_session_signal(host_data: dict) -> bool:
    return bool(
        str(host_data.get("beacon_id") or "").strip()
        or str(host_data.get("agent_id") or "").strip()
        or str(host_data.get("process") or "").strip()
        or str(host_data.get("pid") or "").strip()
    )


def _classify_privilege(username: str) -> str:
    u = (username or "").strip()
    u_up = u.upper()
    if u.endswith("$") or u_up in ("SYSTEM", "ROOT") or "NT AUTHORITY" in u_up:
        return "system"
    if u_up in ("ADMINISTRATOR", "ADMIN"):
        return "admin"
    return "user"


def _status_from_c2_host(existing_status: str, host_data: dict) -> str:
    explicit = _normalize_host_status(host_data.get("status") or "")
    if explicit:
        return (
            explicit
            if _C2_STATUS_RANK.get(explicit, 0)
            >= _C2_STATUS_RANK.get((existing_status or "").strip().lower(), 0)
            else existing_status
        )

    current = (existing_status or "").strip().lower()
    if _has_live_session_signal(host_data) and host_data.get("alive", True):
        tier = _classify_privilege(host_data.get("username") or "")
        candidate = {"user": "access", "admin": "pwned", "system": "owned"}.get(tier, "access")
        return (
            candidate
            if _C2_STATUS_RANK.get(candidate, 0) >= _C2_STATUS_RANK.get(current, 0)
            else existing_status
        )

    if current:
        return existing_status
    return "up" if host_data.get("alive", True) else "unknown"


def _c2_owns_host_status(host: models.Host, source: str) -> bool:
    tags = {str(tag).strip().lower() for tag in (host.tags or []) if str(tag).strip()}
    return (host.import_source or "").strip().lower() == source.lower() or (
        {"c2", source.lower()} <= tags
    )


def _require_c2():
    m = registry.get("c2_integration")
    if not m or not m.enabled:
        raise HTTPException(404, "C2 Integration module is disabled")


router = APIRouter(
    prefix="/api/admin/c2", tags=["c2"],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        502: {"description": "Bad gateway"},
    },
)

_C2_ENDPOINT_PATH = "/endpoint"
_MSG_INTEGRATION_NOT_FOUND = "Integration not found"
_MSG_INSUFFICIENT_PERMS = "Insufficient permissions to manage this integration"

_C2_SETTING_KEY = "c2_integrations"


def _visible_integrations_for_pid(integrations: list[dict], pid: str) -> list[dict]:
    return [
        i
        for i in integrations
        if i.get("enabled") and (not i.get("project_ids") or pid in i.get("project_ids", []))
    ]


def _load_integrations(db: Session) -> list[dict]:
    item = (
        db.query(models.GlobalSetting).filter(models.GlobalSetting.key == _C2_SETTING_KEY).first()
    )
    if not item:
        return []
    raw = item.value if isinstance(item.value, list) else []
    return [_decrypt_integration(i) for i in raw]


def _save_integrations(db: Session, integrations: list[dict]):
    encrypted = [_encrypt_integration(i) for i in integrations]
    item = (
        db.query(models.GlobalSetting).filter(models.GlobalSetting.key == _C2_SETTING_KEY).first()
    )
    if item:
        item.value = encrypted
    else:
        item = models.GlobalSetting(key=_C2_SETTING_KEY, value=encrypted)
        db.add(item)
    db.commit()


def _encrypt_integration(cfg: dict) -> dict:
    c = dict(cfg)
    if c.get("token"):
        c["token"] = encrypt_str(c["token"])
    if c.get("password"):
        c["password"] = encrypt_str(c["password"])
    return c


def _decrypt_integration(cfg: dict) -> dict:
    c = dict(cfg)
    if c.get("token"):
        c["token"] = decrypt_str(c["token"])
    if c.get("password"):
        c["password"] = decrypt_str(c["password"])
    return c


def _safe_integration(cfg: dict) -> dict:
    c = dict(cfg)
    c["has_token"] = bool(c.get("token"))
    c["has_password"] = bool(c.get("password"))
    c["token"] = ""
    c["password"] = ""
    return c


class C2IntegrationCreate(BaseModel):
    name: str
    type: str
    url: str = ""
    token: str = ""
    username: str = ""
    password: str = ""
    endpoint: str = _C2_ENDPOINT_PATH
    verify_ssl: bool = False
    project_ids: list[str] = []
    enabled: bool = True
    sync_interval_minutes: int = 0


class C2IntegrationUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    token: str | None = None
    username: str | None = None
    password: str | None = None
    endpoint: str | None = None
    verify_ssl: bool | None = None
    project_ids: list[str] | None = None
    enabled: bool | None = None
    sync_interval_minutes: int | None = None


class C2HostActionRequest(BaseModel):
    integration_id: str
    agent_id: str
    host_id: str
    mode: str = "command"
    commandline: str
    credential_source: str = ""
    credential_id: str = ""
    wait_for_output: bool = True
    timeout_seconds: int = 12
    title: str = ""


def _is_owner_of(db: Session, pid: str, user: models.User) -> bool:
    from ...core.permissions import get_membership

    m = get_membership(db, pid, user.id)
    return bool(m and m.role == MemberRole.OWNER)


def _can_manage_integration(db: Session, user: models.User, cfg: dict) -> bool:
    if is_admin(user):
        return True
    pids = cfg.get("project_ids") or []
    if not pids:
        return False
    return any(_is_owner_of(db, pid, user) for pid in pids)


def _visible_to_user(db: Session, user: models.User, cfg: dict) -> bool:
    if is_admin(user):
        return True
    pids = cfg.get("project_ids") or []
    if not pids:
        return False
    from ...core.permissions import get_membership

    return any(get_membership(db, pid, user.id) for pid in pids)


@router.get("", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
def list_integrations(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_c2()
    integrations = _load_integrations(db)
    return [_safe_integration(i) for i in integrations if _visible_to_user(db, user, i)]


@router.post("", status_code=201, responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
def create_integration(
    body: C2IntegrationCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_c2()
    if body.type not in ("sliver", "adaptix", "mythic"):
        raise HTTPException(400, f"Unknown C2 type: {body.type}")
    if not is_admin(user):
        if not body.project_ids:
            raise HTTPException(403, "Only global admins can create unscoped C2 integrations")
        for pid in body.project_ids:
            if not _is_owner_of(db, pid, user):
                raise HTTPException(403, f"You are not an owner of project {pid}")
    integrations = _load_integrations(db)
    cfg = body.model_dump()
    cfg["id"] = new_id("c2")
    cfg["last_sync"] = None
    cfg["created_by"] = user.username
    integrations.append(cfg)
    _save_integrations(db, integrations)
    return _safe_integration(cfg)


@router.patch("/{iid}", responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
def update_integration(
    iid: str,
    body: C2IntegrationUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    integrations = _load_integrations(db)
    idx = next((i for i, c in enumerate(integrations) if c.get("id") == iid), None)
    if idx is None:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    if not _can_manage_integration(db, user, integrations[idx]):
        raise HTTPException(403, _MSG_INSUFFICIENT_PERMS)
    updates = body.model_dump(exclude_none=True)
    if not is_admin(user) and "project_ids" in updates:
        new_pids = updates["project_ids"] or []
        if not new_pids:
            raise HTTPException(403, "Only global admins can make an integration global")
        for pid in new_pids:
            if not _is_owner_of(db, pid, user):
                raise HTTPException(403, f"You are not an owner of project {pid}")
    integrations[idx].update(updates)
    _save_integrations(db, integrations)
    return _safe_integration(integrations[idx])


@router.delete("/{iid}", status_code=204, responses={400: {"description": "Bad request"}, 403: {"description": "Forbidden"}, 404: {"description": "Not found"}, 502: {"description": "Bad gateway"}})
def delete_integration(
    iid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    integrations = _load_integrations(db)
    target = next((c for c in integrations if c.get("id") == iid), None)
    if target is None:
        raise HTTPException(404, _MSG_INTEGRATION_NOT_FOUND)
    if not _can_manage_integration(db, user, target):
        raise HTTPException(403, _MSG_INSUFFICIENT_PERMS)
    integrations = [c for c in integrations if c.get("id") != iid]
    _save_integrations(db, integrations)
