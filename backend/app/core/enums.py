"""
Centralised string-enum vocabularies.

These are plain `str` Enums so the underlying database columns can stay
as `String` for back-compat — Python-side comparisons against `Enum`
members are type-safe and `.value` matches what is stored in the DB.

Two helpers per enum:
- `cls.values()`        — set of all valid string values (for validation /
                          Pydantic Literal generation / docs)
- `cls.coerce(raw)`     — best-effort normalisation; returns the Enum if
                          the input maps to a known value, else None.
                          Use this at API edges where we still accept
                          arbitrary strings from older clients.
"""

from __future__ import annotations

from enum import Enum


class _StrEnumBase(str, Enum):
    """`str` Enum with values()/coerce() conveniences."""

    @classmethod
    def values(cls) -> set[str]:
        return {member.value for member in cls}

    @classmethod
    def coerce(cls, raw):
        if raw is None:
            return None
        if isinstance(raw, cls):
            return raw
        s = str(raw).strip().lower()
        for member in cls:
            if member.value == s:
                return member
        return None


# ── Global user role (User.role) ──────────────────────────────────────
class UserRole(_StrEnumBase):
    ADMIN = "admin"  # super-admin: bypasses every project-level check
    USER = "user"  # normal: sees only projects where they are a member
    # NOTE: UserRole.VIEWER ("viewer") is a *global* account-level role that
    # blocks all non-GET requests in middleware (main.py). It shares the string
    # "viewer" with MemberRole.VIEWER, which is a *per-project* role granting
    # read-only access within that project. Do not confuse the two.
    # This global role is considered legacy — prefer creating normal USER
    # accounts and assigning MemberRole.VIEWER at the project level instead.
    VIEWER = "viewer"


# ── Per-project membership role (ProjectMember.role) ─────────────────
class MemberRole(_StrEnumBase):
    OWNER = "owner"
    ADMIN = "admin"
    EDITOR = "editor"
    OPERATOR = "operator"
    VIEWER = "viewer"
    AUDITOR = "auditor"


# ── Finding severity (Finding.severity, Vuln.severity) ───────────────
class Severity(_StrEnumBase):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Generic per-host status (Host.status) ─────────────────────────────
class HostStatus(_StrEnumBase):
    UNKNOWN = "unknown"
    UP = "up"
    DOWN = "down"
    ALIVE = "alive"
    ACCESS = "access"
    PWNED = "pwned"
    OWNED = "owned"


# ── Finding lifecycle (Finding.status) ────────────────────────────────
class FindingStatus(_StrEnumBase):
    OPEN = "open"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ── Background job state machine (Job.status, PlaybookRun.status) ────
class JobStatus(_StrEnumBase):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"  # DAG runner — step skipped by precondition / dep failure

    @classmethod
    def terminal(cls) -> set[str]:
        """Statuses that mean the job/run will not progress further."""
        return {cls.DONE.value, cls.FAILED.value, cls.CANCELLED.value, cls.SKIPPED.value}
