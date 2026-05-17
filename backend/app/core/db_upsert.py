"""
Race-safe upserts for high-concurrency surfaces (webhook beacons,
C2 sync, parallel imports).

Each helper uses PostgreSQL `INSERT ... ON CONFLICT (...) DO UPDATE`
which collapses the read-decide-write window into a single atomic
statement. The relevant partial unique indexes are created by migration
006 — if those indexes are missing the helpers fall back to the slower
"query, then add" path and a warning is logged once per process.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import inspect
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models
from .utils import new_id

logger = logging.getLogger(__name__)

_warned_missing_index: set[str] = set()


def _warn_once(index_name: str) -> None:
    if index_name in _warned_missing_index:
        return
    _warned_missing_index.add(index_name)
    logger.warning(
        "Index %s missing — falling back to non-atomic upsert. Run migration 006.",
        index_name,
    )


def _has_index(db: Session, table: str, index: str) -> bool:
    insp = inspect(db.get_bind())
    try:
        return any(idx.get("name") == index for idx in insp.get_indexes(table))
    except Exception:
        return False


def upsert_host_by_ip(
    db: Session,
    *,
    pid: str,
    ip: str,
    defaults: dict[str, Any],
    update_on_conflict: dict[str, Any] | None = None,
) -> tuple[models.Host, bool]:
    """Atomic upsert: returns (host, created_bool).

    `defaults` populates the row on INSERT (must include any non-nullable
    columns not covered by SQLAlchemy defaults).
    `update_on_conflict` is the partial dict applied on the UPDATE side
    when the row already exists (typically a subset of mutable fields).
    """
    ip = (ip or "").strip()
    if not ip:
        raise ValueError("upsert_host_by_ip requires a non-empty ip")

    if not _has_index(db, "hosts", "uq_hosts_pid_ip"):
        _warn_once("uq_hosts_pid_ip")
        existing = db.query(models.Host).filter(
            models.Host.pid == pid, models.Host.ip == ip
        ).first()
        if existing:
            if update_on_conflict:
                for k, v in update_on_conflict.items():
                    setattr(existing, k, v)
            return existing, False
        host = models.Host(id=defaults.get("id") or new_id("hst"), pid=pid, ip=ip, **{k: v for k, v in defaults.items() if k not in ("id", "pid", "ip")})
        db.add(host)
        db.flush()
        return host, True

    # PostgreSQL path — atomic insert with ON CONFLICT
    insert_values = {"id": defaults.get("id") or new_id("hst"), "pid": pid, "ip": ip}
    for k, v in defaults.items():
        if k not in insert_values:
            insert_values[k] = v
    stmt = pg_insert(models.Host).values(**insert_values)
    if update_on_conflict:
        stmt = stmt.on_conflict_do_update(
            index_elements=["pid", "ip"],
            index_where=(models.Host.ip != ""),
            set_=update_on_conflict,
        )
    else:
        stmt = stmt.on_conflict_do_nothing(
            index_elements=["pid", "ip"],
            index_where=(models.Host.ip != ""),
        )
    result = db.execute(stmt)
    # rowcount is 1 if INSERT actually happened, 0 (or 1 on DO UPDATE) otherwise
    db.flush()
    host = db.query(models.Host).filter(
        models.Host.pid == pid, models.Host.ip == ip
    ).first()
    # We can't tell ON CONFLICT DO UPDATE from INSERT via rowcount alone, so
    # report `created=True` only when the row id equals the one we proposed
    created = bool(host and host.id == insert_values["id"])
    return host, created


def try_insert_or_get(
    db: Session,
    new_row: Any,
    requery,
) -> tuple[Any, bool]:
    """Race-safe insert with re-query fallback when a unique index trips.

    `new_row` is an already-constructed SQLAlchemy model instance ready to
    `db.add()`. `requery` is a 0-arg callable that returns the row that
    would have been the conflict target (typically a `db.query(...).first()`).

    Returns `(row, created)` — when the savepoint commit fails with
    IntegrityError we rollback, call `requery()` to fetch the row that
    the parallel writer created, and hand it back. The caller can then
    apply the same enrichment it would have applied on the
    "row already exists" branch.

    Use this for high-traffic surfaces (c2 sync, bulk import) where a
    parallel writer could land between our existence check and our
    INSERT. Cheaper than ON CONFLICT for cases where the insert payload
    is computed lazily.
    """
    try:
        with db.begin_nested():
            db.add(new_row)
            db.flush()
        return new_row, True
    except IntegrityError:
        # The `with db.begin_nested():` context already rolled back the
        # savepoint on the exception; the outer transaction is intact.
        existing = requery()
        if existing is None:
            # Index reported a conflict but the row vanished (race+delete
            # in the same window?). Surface the error so caller can decide.
            raise
        return existing, False
