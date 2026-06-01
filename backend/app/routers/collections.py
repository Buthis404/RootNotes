"""
Host Collections — saved filter sets that resolve to a list of hosts at runtime.

Filter fields:
  tags         list[str]  — host has ANY (or ALL) of these tags
  tags_mode    "any"|"all"
  status       list[str]  — host status is one of these
  role         list[str]  — host role is one of these
  os_contains  str        — case-insensitive substring in host.os
  domain_contains str     — case-insensitive substring in host.domain
  subnet       str        — CIDR, e.g. "192.168.1.0/24"
  ports_open   list[str]  — host.ports has any of these port strings
  exclude_attacker bool   — skip is_attacker hosts (default True)
  has_c2       bool|None  — host has a 'c2' tag (set by C2 sync)
"""

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from typing import Annotated
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast
from ..core.permissions import PERM_HOSTS_READ
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/projects/{pid}/collections", tags=["collections"])


# ── Schema ────────────────────────────────────────────────────────────


class CollectionFilter(BaseModel):
    tags: list[str] = []
    tags_mode: str = "any"  # "any" | "all"
    status: list[str] = []
    role: list[str] = []
    os_contains: str = ""
    domain_contains: str = ""
    subnet: str = ""
    ports_open: list[str] = []
    exclude_attacker: bool = True
    has_c2: bool | None = None  # True = must have c2 tag, False = must NOT have it


class CollectionIn(BaseModel):
    name: str
    description: str = ""
    color: str = ""
    filters: CollectionFilter = CollectionFilter()


class CollectionUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    color: str | None = None
    filters: CollectionFilter | None = None


# ── Resolver (reusable by bulk_actions + playbooks) ───────────────────


def _apply_tags_query_filter(q, tags: list, tags_mode: str):
    if tags_mode == "all":
        for tag in tags:
            q = q.filter(models.Host.tags.contains([tag]))
    else:
        q = q.filter(models.Host.tags.overlap(tags))
    return q


def _apply_collection_sql_filters(q, filters: dict):
    exclude_attacker = filters.get("exclude_attacker", True)
    if exclude_attacker:
        q = q.filter(not models.Host.is_attacker)
    tags = filters.get("tags") or []
    if tags:
        q = _apply_tags_query_filter(q, tags, filters.get("tags_mode", "any"))
    statuses = filters.get("status") or []
    if statuses:
        q = q.filter(models.Host.status.in_(statuses))
    roles = filters.get("role") or []
    if roles:
        q = q.filter(models.Host.role.in_(roles))
    os_str = filters.get("os_contains", "")
    if os_str:
        q = q.filter(models.Host.os.ilike(f"%{os_str}%"))
    domain_str = filters.get("domain_contains", "")
    if domain_str:
        q = q.filter(models.Host.domain.ilike(f"%{domain_str}%"))
    has_c2 = filters.get("has_c2")
    if has_c2 is True:
        q = q.filter(models.Host.tags.contains(["c2"]))
    elif has_c2 is False:
        q = q.filter(~models.Host.tags.contains(["c2"]))
    return q


def resolve_collection_hosts(
    db: Session,
    pid: str,
    filters: dict,
) -> list[models.Host]:
    """Return hosts in `pid` matching the filter dict. Pure SQL + Python fallback."""
    q = db.query(models.Host).filter(models.Host.pid == pid)
    q = _apply_collection_sql_filters(q, filters)
    hosts = q.all()

    subnet = filters.get("subnet", "")
    if subnet:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            hosts = [h for h in hosts if _ip_in_network(h.ip, net)]
        except ValueError:
            pass

    ports_open = filters.get("ports_open") or []
    if ports_open:
        port_set = {str(p) for p in ports_open}
        hosts = [h for h in hosts if port_set.intersection(set(h.ports or []))]

    return hosts


def _ip_in_network(ip_str: str, net: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in net
    except ValueError:
        return False


def _collection_dict(c: models.HostCollection) -> dict:
    return {
        "id": c.id,
        "pid": c.pid,
        "name": c.name,
        "description": c.description,
        "color": c.color,
        "filters": c.filters_json or {},
        "created_by": c.created_by,
        "created_at": c.created_at,
        "updated_at": c.updated_at,
    }


# ── Routes ────────────────────────────────────────────────────────────


@router.get("", responses={404: {"description": "Not found"}})
def list_collections(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    rows = (
        db.query(models.HostCollection)
        .filter(models.HostCollection.pid == pid)
        .order_by(models.HostCollection.name)
        .all()
    )
    return [_collection_dict(r) for r in rows]


@router.post("", status_code=201, responses={404: {"description": "Not found"}})
def create_collection(
    pid: str,
    body: CollectionIn,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    now = ts_now()
    coll = models.HostCollection(
        id=new_id("coll"),
        pid=pid,
        name=body.name.strip(),
        description=body.description,
        color=body.color or "#4f8ef7",
        filters_json=body.filters.model_dump(),
        created_by=user.username,
        created_at=now,
        updated_at=now,
    )
    db.add(coll)
    db.commit()
    db.refresh(coll)
    result = _collection_dict(coll)
    bcast(pid, "collection", "create", result)
    return result


@router.get("/{coll_id}", responses={404: {"description": "Not found"}})
def get_collection(
    pid: str,
    coll_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    coll = _get_or_404(db, pid, coll_id)
    return _collection_dict(coll)


@router.patch("/{coll_id}", responses={404: {"description": "Not found"}})
def update_collection(
    pid: str,
    coll_id: str,
    body: CollectionUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    coll = _get_or_404(db, pid, coll_id)
    now = ts_now()
    if body.name is not None:
        coll.name = body.name.strip()
    if body.description is not None:
        coll.description = body.description
    if body.color is not None:
        coll.color = body.color
    if body.filters is not None:
        coll.filters_json = body.filters.model_dump()
    coll.updated_at = now
    db.commit()
    db.refresh(coll)
    result = _collection_dict(coll)
    bcast(pid, "collection", "update", result)
    return result


@router.delete("/{coll_id}", status_code=204, responses={404: {"description": "Not found"}})
def delete_collection(
    pid: str,
    coll_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    coll = _get_or_404(db, pid, coll_id)
    db.delete(coll)
    db.commit()
    bcast(pid, "collection", "delete", {"id": coll_id})


@router.get("/{coll_id}/resolve", responses={404: {"description": "Not found"}})
def resolve_collection(
    pid: str,
    coll_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Resolve the collection to its current matching host list."""
    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    coll = _get_or_404(db, pid, coll_id)
    hosts = resolve_collection_hosts(db, pid, coll.filters_json or {})
    return {
        "collection_id": coll_id,
        "collection_name": coll.name,
        "count": len(hosts),
        "host_ids": [h.id for h in hosts],
        "hosts": [
            {"id": h.id, "ip": h.ip, "hostname": h.hostname, "os": h.os, "status": h.status}
            for h in hosts
        ],
    }


@router.post("/preview", responses={404: {"description": "Not found"}})
def preview_filter(
    pid: str,
    body: CollectionFilter,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Preview how many hosts a filter would match before saving."""
    check_pid_access(db, pid, user, PERM_HOSTS_READ)
    hosts = resolve_collection_hosts(db, pid, body.model_dump())
    return {
        "count": len(hosts),
        "hosts": [
            {
                "id": h.id,
                "ip": h.ip,
                "hostname": h.hostname,
                "os": h.os,
                "status": h.status,
                "tags": h.tags,
            }
            for h in hosts
        ],
    }


def _get_or_404(db: Session, pid: str, coll_id: str) -> models.HostCollection:
    coll = (
        db.query(models.HostCollection)
        .filter(
            models.HostCollection.id == coll_id,
            models.HostCollection.pid == pid,
        )
        .first()
    )
    if not coll:
        raise HTTPException(404, "Collection not found")
    return coll
