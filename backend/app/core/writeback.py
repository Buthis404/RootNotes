"""
Result writeback — automatically enriches host/cred state from completed job output.

Called after every queued job finishes. Each rule is narrow and safe:
never overwrites data that looks more authoritative than what the job found.
"""

import logging
import re

from .. import models, schemas
from ..core.artifact_extractor import extract as _extract_artifacts
from ..core.artifact_extractor import sha256_bytes as _sha256
from ..core.events import bcast
from ..core.notifications import dispatch_sync
from ..core.result_normalizer import normalize as _normalize_result
from ..core.utils import new_id

logger = logging.getLogger(__name__)

# Ports → auto-tags
_PORT_TAGS: list[tuple[set[int], str]] = [
    ({88}, "dc"),
    ({389, 636, 3268, 3269}, "ldap"),
    ({445}, "smb"),
    ({80, 8080, 8000, 8008}, "web"),
    ({443, 8443, 4443}, "web"),
    ({22}, "ssh"),
    ({3389}, "rdp"),
    ({1433}, "mssql"),
    ({5985, 5986}, "winrm"),
    ({21}, "ftp"),
    ({25, 587, 465}, "smtp"),
    ({3306}, "mysql"),
    ({5432}, "postgres"),
    ({27017}, "mongodb"),
    ({6379}, "redis"),
]

_PWNED_RE = re.compile(r"\(Pwn3d!\)", re.IGNORECASE)
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def _parse_port_num(port_str: str | None) -> int | None:
    try:
        return int(str(port_str).split("/")[0])
    except (ValueError, TypeError):
        return None


def _tags_for_ports(ports: list) -> set[str]:
    nums = {_parse_port_num(p) for p in (ports or [])} - {None}
    tags = set()
    for port_set, tag in _PORT_TAGS:
        if nums & port_set:
            tags.add(tag)
    return tags


def _add_tags(host: models.Host, new_tags: set[str]) -> bool:
    current = set(host.tags or [])
    added = new_tags - current
    if added:
        host.tags = list(current | added)
        return True
    return False


def apply_writeback(db, job: models.Job, result: dict) -> None:
    """
    Post-job enrichment. Called synchronously after finish_job() in job_runner.
    Modifies hosts/creds in-place; caller must have an open db session and commit.
    """
    connector = job.connector_key
    operation = job.operation
    pid = job.pid
    output = (job.output or "") + (job.error_output or "")
    req = job.request_json or {}
    status = job.status

    # ── nmap: auto-tag hosts by discovered ports ─────────────────────
    if connector == "nmap" and operation == "scan" and status == "done":
        _writeback_nmap_tags(db, pid, req, result, output)

    # ── netexec: detect Pwn3d / successful auth → status + tags ──────
    elif connector == "netexec" and operation == "scan" and status == "done":
        _writeback_netexec(db, pid, req, result, output)

    # ── httpx: add "web" tag to probed hosts ──────────────────────────
    elif connector == "httpx" and operation == "scan" and status == "done":
        _writeback_httpx_tags(db, pid, req, result)

    # ── attacker_ssh exec: link cred to host on success ───────────────
    elif connector == "attacker_ssh" and operation == "exec" and status == "done":
        _writeback_exec_cred_link(db, pid, req, result)

    # ── structured result: always populate after all writeback rules ──
    _apply_structured_result(db, job, result)

    # ── artifact extraction: auto-create Loot records from output ─────
    if status == "done" and job.output:
        _save_extracted_artifacts(db, job)


# ── Rule implementations ──────────────────────────────────────────────


def _writeback_nmap_tags(db, pid: str, req: dict, _result: dict, _output: str) -> None:
    req.get("target") or ""
    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    changed = []
    for host in hosts:
        port_tags = _tags_for_ports(host.ports or [])
        if port_tags and _add_tags(host, port_tags):
            changed.append(host)
    if changed:
        db.commit()
        for host in changed:
            db.refresh(host)
            bcast(pid, "host", "upsert", schemas.Host.model_validate(host).model_dump())


def _collect_pwned_ips(output: str) -> set[str]:
    pwned_ips: set[str] = set()
    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    for line in output.splitlines():
        if _PWNED_RE.search(line):
            m = ip_re.search(line)
            if m:
                pwned_ips.add(m.group(1))
    return pwned_ips


def _mark_hosts_compromised(db, pid: str, pwned_ips: set[str]) -> list:
    pwned_hosts = (
        db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip.in_(pwned_ips)).all()
    )
    changed = []
    for host in pwned_hosts:
        updated = False
        if host.status != "compromised":
            host.status = "compromised"
            updated = True
        if _add_tags(host, {"pwned"}):
            updated = True
        if updated:
            changed.append(host)
    return changed


def _find_cred_by_username(db, pid: str, username: str, domain: str):
    cred = (
        db.query(models.Cred)
        .filter(models.Cred.pid == pid, models.Cred.username == username)
        .first()
    )
    if not cred and domain:
        qualified = f"{domain}\\{username}"
        cred = (
            db.query(models.Cred)
            .filter(models.Cred.pid == pid, models.Cred.username == qualified)
            .first()
        )
    return cred


def _link_cred_to_hosts(db, pid: str, req: dict, changed: list) -> None:
    username = req.get("username") or ""
    password = req.get("password") or ""
    domain = req.get("domain") or ""
    if not (username and (password or req.get("hash"))):
        return
    cred = _find_cred_by_username(db, pid, username, domain)
    if cred:
        for host in changed:
            current_ids = list(cred.host_ids or [])
            if host.id not in current_ids:
                cred.host_ids = current_ids + [host.id]


def _notify_compromised_hosts(db, pid: str, changed: list) -> None:
    db.commit()
    for host in changed:
        db.refresh(host)
        bcast(pid, "host", "upsert", schemas.Host.model_validate(host).model_dump())
        label = host.hostname or host.ip
        dispatch_sync(
            db,
            "host_compromised",
            f"🔴 Host Compromised: {label}",
            f"IP: {host.ip}\nHostname: {host.hostname or '—'}\nNetExec found (Pwn3d!) — admin access confirmed.",
            {"host_id": host.id, "ip": host.ip},
        )


def _writeback_netexec(db, pid: str, req: dict, _result: dict, output: str) -> None:
    pwned_ips = _collect_pwned_ips(output)
    if not pwned_ips:
        return
    changed = _mark_hosts_compromised(db, pid, pwned_ips)
    _link_cred_to_hosts(db, pid, req, changed)
    if changed:
        _notify_compromised_hosts(db, pid, changed)


def _writeback_httpx_tags(db, pid: str, req: dict, _result: dict) -> None:
    target = (req.get("target") or "").strip()
    if not target:
        return
    # Tag the specific target host with "web" if it exists
    host = (
        db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == target).first()
        or db.query(models.Host)
        .filter(models.Host.pid == pid, models.Host.hostname == target)
        .first()
    )
    if host and _add_tags(host, {"web"}):
        db.commit()
        db.refresh(host)
        bcast(pid, "host", "upsert", schemas.Host.model_validate(host).model_dump())


def _writeback_exec_cred_link(db, pid: str, req: dict, result: dict) -> None:
    host_id = result.get("host_id") or req.get("host_id")
    cred_id = req.get("cred_id")
    if not host_id or not cred_id:
        return
    cred = db.query(models.Cred).filter(models.Cred.id == cred_id, models.Cred.pid == pid).first()
    if not cred:
        return
    current_ids = list(cred.host_ids or [])
    if host_id not in current_ids:
        cred.host_ids = current_ids + [host_id]


def _apply_structured_result(db, job: models.Job, result: dict) -> None:
    try:
        sr = _normalize_result(job)
        merged = dict(result)
        merged["structured"] = sr.to_dict()
        job.result_json = merged
        db.add(job)
        db.commit()
    except Exception:
        db.commit()


def _save_extracted_artifacts(db, job: models.Job) -> None:
    try:
        artifacts = _extract_artifacts(job.output, job)
        if not artifacts:
            return
        ts = job.finished_at or job.created_at
        playbook_run_id = (job.request_json or {}).get("playbook_run_id", "")
        for art in artifacts:
            sha = _sha256(art.value.encode())
            # Deduplicate within project by sha256 + artifact_type
            exists = (
                db.query(models.Loot)
                .filter(
                    models.Loot.pid == job.pid,
                    models.Loot.sha256 == sha,
                    models.Loot.artifact_type == art.artifact_type,
                )
                .first()
            )
            if exists:
                continue
            loot = models.Loot(
                id=new_id("lt"),
                pid=job.pid,
                host_id=art.host_id,
                cred_id=art.cred_id or "",
                job_id=job.id,
                playbook_run_id=playbook_run_id,
                loot_type=art.loot_type,
                artifact_type=art.artifact_type,
                value=art.value,
                description=art.description,
                sha256=sha,
                tags=art.tags,
                ts=ts,
            )
            db.add(loot)
        db.commit()
    except Exception as e:
        logger.debug("artifact writeback failed for job %s: %s", job.id, e)
