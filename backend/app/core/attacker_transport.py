"""
Unified attacker SSH transport service.

Consolidates the attacker-target resolution and SSH config building logic
that was previously duplicated across attacker_exec.py, scans.py,
bulk_actions.py, and job_runner.py.

Public API:
    resolve_project_attacker_host()  — find attacker host in project
    resolve_project_ssh_cred()       — find SSH credential for a project host
    build_ssh_config_from_cred()     — build SSH dict from host+cred
    list_global_targets_for_project()— filter global targets by project
    resolve_scan_target()            — pick SSH config for scan-style operations
    resolve_exec_connection()        — full resolution for exec-style operations
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from fastapi import HTTPException

from ..core.crypto import decrypt_str
from ..core.route_selection import choose_route_aware_target
from ..plugins.registry import registry
from ..plugins.state import list_attacker_targets, list_attacker_targets_for_exec

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from .. import models


# ── Result types ──────────────────────────────────────────────────────


@dataclass
class AttackerHost:
    """A resolved attacker host from the project."""
    host: "models.Host"
    cred: "models.Cred | None" = None


@dataclass
class ResolvedConnection:
    """Complete resolved SSH connection context."""
    ssh_config: dict
    attacker_host: "models.Host | None" = None
    resolved_cred: "models.Cred | None" = None
    candidates: list[dict] = field(default_factory=list)
    global_target: dict | None = None


# ── Module check ──────────────────────────────────────────────────────


def require_attacker_ssh() -> None:
    """Raise HTTP 404 if the attacker_ssh module is disabled."""
    module = registry.get("attacker_ssh")
    if not module or not module.enabled:
        raise HTTPException(404, "Attacker SSH module is disabled")


# ── Project-level resolution ──────────────────────────────────────────


def resolve_project_attacker_host(
    db: "Session", pid: str, host_id: str | None = None
) -> "models.Host":
    """Find an attacker host in the project.

    Args:
        db: Database session.
        pid: Project ID.
        host_id: Optional explicit host ID.

    Returns:
        The resolved attacker Host model.

    Raises:
        HTTPException: 404 if host not found, 400 if not an attacker host.
    """
    from .. import models

    q = db.query(models.Host).filter(models.Host.pid == pid)
    if host_id:
        host = q.filter(models.Host.id == host_id).first()
        if not host:
            raise HTTPException(404, "Attacker host not found")
    else:
        host = (
            q.filter((models.Host.is_attacker) | (models.Host.role == "attacker"))
            .order_by(models.Host.hostname, models.Host.ip)
            .first()
        )
        if not host:
            raise HTTPException(400, "No attacker host is configured in this project")
    if not (host.is_attacker or (host.role or "").lower() == "attacker"):
        raise HTTPException(400, "Selected host is not marked as attacker")
    return host


def _cred_matches_host(cred: "models.Cred", host: "models.Host") -> bool:
    """Check if a credential is linked to a host."""
    if host.id in (cred.host_ids or []):
        return True
    return cred.host in {host.ip, host.hostname}


def resolve_project_ssh_cred(
    db: "Session", pid: str, host: "models.Host", cred_id: str | None = None
) -> "models.Cred | None":
    """Find an SSH-capable credential for a project attacker host.

    Priority: explicit cred_id > best auto-matched (key preferred, ssh service preferred).

    Args:
        db: Database session.
        pid: Project ID.
        host: The attacker host to find a credential for.
        cred_id: Optional explicit credential ID.

    Returns:
        The matching Cred model, or None if no credential is available.

    Raises:
        HTTPException: 404 if cred_id is given but not found, 400 if not linked.
    """
    from .. import models

    q = db.query(models.Cred).filter(models.Cred.pid == pid)
    if cred_id:
        cred = q.filter(models.Cred.id == cred_id).first()
        if not cred:
            raise HTTPException(404, "Credential not found")
        if not _cred_matches_host(cred, host):
            raise HTTPException(400, "Credential is not linked to the selected attacker host")
        return cred

    candidates = [
        cred
        for cred in q.all()
        if _cred_matches_host(cred, host)
        and cred.secret
        and cred.type in {"plain", "key"}
        and ((cred.service or "").lower() in {"", "ssh"} or cred.type == "key")
    ]
    candidates.sort(
        key=lambda c: ((c.type != "key"), (c.service or "") != "ssh", c.username or "")
    )
    return candidates[0] if candidates else None


def build_ssh_config_from_cred(
    host: "models.Host", cred: "models.Cred", fallback: dict | None = None
) -> dict:
    """Build an SSH config dict from a host and credential.

    Args:
        host: The attacker host (provides IP).
        cred: The credential (provides username + secret).
        fallback: Optional dict with port/known_hosts_policy overrides.

    Returns:
        SSH config dict suitable for ssh_exec functions.
    """
    fallback = fallback or {}
    secret = decrypt_str(cred.secret)
    return {
        "host": host.ip,
        "port": fallback.get("port") or 22,
        "username": cred.username,
        "password": secret if cred.type != "key" else "",
        "private_key": secret if cred.type == "key" else "",
        "known_hosts_policy": fallback.get("known_hosts_policy") or "accept_new",
    }


# ── Global target resolution ──────────────────────────────────────────


def list_global_targets_for_project(pid: str) -> list[dict]:
    """Return enabled global attacker targets visible to a project.

    Filters by project_ids: if a target has a non-empty project_ids list,
    the pid must be in it. Targets with empty project_ids are visible to all.
    """
    return [
        {
            "id": target.get("id"),
            "name": target.get("name") or target.get("host") or target.get("id"),
            "host": target.get("host", ""),
            "port": target.get("port", 22),
            "username": target.get("username", ""),
            "enabled": target.get("enabled", True),
            "project_ids": target.get("project_ids", []),
            "source": "global",
        }
        for target in list_attacker_targets()
        if target.get("enabled", True)
        and (not target.get("project_ids") or pid in target.get("project_ids", []))
    ]


def _find_global_target_by_id(target_id: str) -> dict | None:
    """Find an enabled global attacker target by ID."""
    for t in list_attacker_targets():
        if t.get("id") == target_id and t.get("enabled", True):
            return t
    return None


def _find_exec_target_by_id(target_id: str) -> dict | None:
    """Find an enabled exec-capable global target. Raises if pivot-only."""
    for t in list_attacker_targets():
        if t.get("id") == target_id and t.get("enabled", True):
            if not t.get("is_operator", True):
                raise HTTPException(
                    400, "Selected target is configured for pivots only — it cannot run operations"
                )
            return t
    return None


# ── Scan-style resolution ─────────────────────────────────────────────


def resolve_scan_target(
    pid: str,
    target_id: str | None = None,
    db: "Session | None" = None,
    target_hint: str = "",
) -> dict:
    """Resolve SSH config for scan-style operations (nmap, nuclei, etc.).

    These operations only use global attacker targets marked as operator-capable.

    Args:
        pid: Project ID.
        target_id: Optional explicit target ID.
        db: Optional database session (for route-aware selection).
        target_hint: Optional scan target IP/hostname for route matching.

    Returns:
        SSH config dict for the selected target.

    Raises:
        HTTPException: 400/404 if no suitable target is found.
    """
    targets = list_attacker_targets_for_exec()
    if not targets:
        raise HTTPException(400, "No operator-capable attacker SSH targets configured")

    if target_id:
        all_targets = list_attacker_targets()
        t = next((t for t in all_targets if t.get("id") == target_id), None)
        if not t:
            raise HTTPException(404, "Attacker target not found")
        if not t.get("is_operator", True):
            raise HTTPException(
                400, "Selected target is configured for pivots only — it cannot run scans"
            )
        return t

    project_targets = [
        t
        for t in targets
        if not t.get("project_ids") or pid in t.get("project_ids", [])
    ]
    if not project_targets:
        raise HTTPException(
            400, "No operator-capable attacker SSH target assigned to this project"
        )

    if db is not None and target_hint:
        selected = choose_route_aware_target(pid, project_targets, db, target_hint)
        if selected:
            return selected

    return project_targets[0]


# ── Exec-style resolution ─────────────────────────────────────────────


def _try_project_ssh(
    db: "Session",
    pid: str,
    execution_mode: str,
    host_id: str | None,
    cred_id: str | None,
) -> tuple[dict, "models.Host", "models.Cred"] | None:
    attacker_host = resolve_project_attacker_host(db, pid, host_id)
    resolved_cred = resolve_project_ssh_cred(db, pid, attacker_host, cred_id)
    if resolved_cred:
        ssh_config = build_ssh_config_from_cred(
            attacker_host, resolved_cred,
            {"port": 22, "known_hosts_policy": "accept_new"},
        )
        return ssh_config, attacker_host, resolved_cred
    if execution_mode == "project":
        raise HTTPException(400, "No usable SSH credential found for attacker host")
    return None


def _resolve_global_ssh_explicit(
    global_targets: list[dict], target_id: str
) -> tuple[dict, list[dict], dict]:
    gt = next((t for t in global_targets if t.get("id") == target_id), None)
    if not gt:
        raise HTTPException(404, "Global attacker target not found for this project")
    stored = _find_global_target_by_id(gt.get("id"))
    if not stored:
        raise HTTPException(404, "Stored global attacker target not found")
    return stored, [stored], gt


def _resolve_global_ssh_auto(
    db: "Session", pid: str, global_targets: list[dict], command_hint: str
) -> tuple[dict, list[dict]]:
    all_stored = list_attacker_targets()
    hinted = choose_route_aware_target(pid, global_targets, db, command_hint) if db else None
    if hinted:
        ranked = [hinted] + [
            gt for gt in global_targets if gt.get("id") != hinted.get("id")
        ]
    else:
        ranked = global_targets
    candidates = [
        t for gt in ranked
        for t in all_stored
        if t.get("id") == gt.get("id") and t.get("enabled", True)
    ]
    if not candidates:
        raise HTTPException(400, "No enabled global attacker targets found")
    return candidates[0], candidates


def _ensure_attacker_host(
    db: "Session", pid: str, host_id: str | None
) -> "models.Host":
    from .. import models

    if host_id:
        return resolve_project_attacker_host(db, pid, host_id)
    host = (
        db.query(models.Host)
        .filter(models.Host.pid == pid)
        .order_by(models.Host.hostname, models.Host.ip)
        .first()
    )
    if not host:
        raise HTTPException(400, "No host is available in the project to attach execution output")
    return host


def resolve_exec_connection(
    db: "Session",
    pid: str,
    *,
    execution_mode: str = "auto",
    host_id: str | None = None,
    cred_id: str | None = None,
    target_id: str | None = None,
    command_hint: str = "",
) -> ResolvedConnection:
    """Resolve SSH connection for exec-style operations.

    Supports project hosts with credentials, global targets, and fallback chains.

    Resolution order:
        1. If mode is 'auto' or 'project': try project attacker host + credential.
        2. If no project SSH config found (or mode is 'global'): use global targets.
        3. If no explicit attacker host, attach output to first available project host.

    Args:
        db: Database session.
        pid: Project ID.
        execution_mode: 'auto', 'project', or 'global'.
        host_id: Optional explicit attacker host ID.
        cred_id: Optional explicit credential ID.
        target_id: Optional explicit global target ID.
        command_hint: Optional command text for route-aware target selection.

    Returns:
        ResolvedConnection with ssh_config, attacker_host, cred, candidates.

    Raises:
        HTTPException: 400/404 on resolution failure.
    """
    from .. import models

    ssh_config: dict | None = None
    attacker_host: "models.Host | None" = None
    resolved_cred: "models.Cred | None" = None
    candidates: list[dict] = []
    global_target: dict | None = None

    if execution_mode in {"auto", "project"}:
        result = _try_project_ssh(db, pid, execution_mode, host_id, cred_id)
        if result:
            ssh_config, attacker_host, resolved_cred = result

    if ssh_config is None:
        global_targets = list_global_targets_for_project(pid)
        if not global_targets:
            raise HTTPException(400, "No global attacker target is assigned to this project")
        if target_id:
            ssh_config, candidates, global_target = _resolve_global_ssh_explicit(
                global_targets, target_id
            )
        else:
            ssh_config, candidates = _resolve_global_ssh_auto(
                db, pid, global_targets, command_hint
            )
    else:
        candidates = [ssh_config]

    if attacker_host is None:
        attacker_host = _ensure_attacker_host(db, pid, host_id)

    return ResolvedConnection(
        ssh_config=ssh_config,
        attacker_host=attacker_host,
        resolved_cred=resolved_cred,
        candidates=candidates,
        global_target=global_target,
    )


# ── Bulk-exec resolution ──────────────────────────────────────────────


def _resolve_exec_project_ssh(db: "Session", pid: str, attacker_host_id: str) -> list[dict]:
    from .. import models
    host = (
        db.query(models.Host)
        .filter(models.Host.id == attacker_host_id, models.Host.pid == pid)
        .first()
    )
    if host:
        cred = resolve_project_ssh_cred(db, pid, host)
        if cred:
            return [build_ssh_config_from_cred(host, cred)]
    return []


def _resolve_exec_global_ssh(attacker_target_id: str) -> list[dict]:
    t = _find_exec_target_by_id(attacker_target_id)
    return [t] if t else []


def _resolve_exec_auto_ssh(db: "Session", pid: str) -> list[dict]:
    from .. import models
    attacker_hosts = (
        db.query(models.Host)
        .filter(
            models.Host.pid == pid,
            (models.Host.is_attacker) | (models.Host.role == "attacker"),
        )
        .order_by(models.Host.hostname, models.Host.ip)
        .all()
    )
    configs: list[dict] = []
    for ah in attacker_hosts:
        cred = resolve_project_ssh_cred(db, pid, ah)
        if cred:
            cfg = build_ssh_config_from_cred(ah, cred)
            configs.append(cfg)

    for target in list_attacker_targets_for_exec():
        project_ids = target.get("project_ids", [])
        if not project_ids or pid in project_ids:
            t = dict(target)
            t.setdefault("_label", f"{target.get('host', '?')} (global target)")
            configs.append(t)

    return configs


def resolve_exec_ssh_configs(
    db: "Session",
    pid: str,
    *,
    attacker_host_id: str | None = None,
    attacker_target_id: str | None = None,
) -> list[dict]:
    """Return ALL candidate SSH configs in priority order for transport fallback.

    This is used by bulk-exec which needs to try multiple targets when one
    is unreachable.

    Args:
        db: Database session.
        pid: Project ID.
        attacker_host_id: Optional explicit project attacker host.
        attacker_target_id: Optional explicit global target ID.

    Returns:
        List of SSH config dicts in priority order.
    """
    if attacker_host_id:
        return _resolve_exec_project_ssh(db, pid, attacker_host_id)
    if attacker_target_id:
        return _resolve_exec_global_ssh(attacker_target_id)
    return _resolve_exec_auto_ssh(db, pid)
