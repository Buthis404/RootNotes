"""
Result writeback — automatically enriches host/cred state from completed job output.

Called after every queued job finishes. Each rule is narrow and safe:
never overwrites data that looks more authoritative than what the job found.
"""
import re
from typing import Optional

from .. import models, schemas
from ..core.events import bcast, log_event
from ..core.utils import new_id
from ..core.notifications import dispatch_sync
from ..core.result_normalizer import normalize as _normalize_result
from ..core.artifact_extractor import extract as _extract_artifacts, sha256_bytes as _sha256

# Ports → auto-tags
_PORT_TAGS: list[tuple[set[int], str]] = [
    ({88},                      "dc"),
    ({389, 636, 3268, 3269},    "ldap"),
    ({445},                     "smb"),
    ({80, 8080, 8000, 8008},    "web"),
    ({443, 8443, 4443},         "web"),
    ({22},                      "ssh"),
    ({3389},                    "rdp"),
    ({1433},                    "mssql"),
    ({5985, 5986},              "winrm"),
    ({21},                      "ftp"),
    ({25, 587, 465},            "smtp"),
    ({3306},                    "mysql"),
    ({5432},                    "postgres"),
    ({27017},                   "mongodb"),
    ({6379},                    "redis"),
]

_PWNED_RE = re.compile(r"\(Pwn3d!\)", re.IGNORECASE)
_ADMIN_RE  = re.compile(r"\[\+\].*?([\d.]+).*?(?:\(Pwn3d!\)|ADMIN)", re.IGNORECASE)


def _parse_port_num(port_str: str) -> Optional[int]:
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
    pid       = job.pid
    output    = (job.output or "") + (job.error_output or "")
    req       = job.request_json or {}
    status    = job.status

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

def _writeback_nmap_tags(db, pid: str, req: dict, result: dict, output: str) -> None:
    target = req.get("target") or ""
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


def _writeback_netexec(db, pid: str, req: dict, result: dict, output: str) -> None:
    pwned_ips: set[str] = set()

    # Detect (Pwn3d!) lines — extract IP from same line
    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    for line in output.splitlines():
        if _PWNED_RE.search(line):
            m = ip_re.search(line)
            if m:
                pwned_ips.add(m.group(1))

    if not pwned_ips:
        return

    changed = []
    for ip in pwned_ips:
        host = db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == ip).first()
        if not host:
            continue
        updated = False
        if host.status not in ("compromised",):
            host.status = "compromised"
            updated = True
        if _add_tags(host, {"pwned"}):
            updated = True
        if updated:
            changed.append(host)

    # Also link the credential used to the pwned hosts
    username = req.get("username") or ""
    password = req.get("password") or ""
    domain   = req.get("domain") or ""
    if username and (password or req.get("hash")):
        cred = db.query(models.Cred).filter(
            models.Cred.pid == pid,
            models.Cred.username == username,
        ).first()
        if not cred:
            cred = db.query(models.Cred).filter(
                models.Cred.pid == pid,
                models.Cred.username == (f"{domain}\\{username}" if domain else username),
            ).first()
        if cred:
            for host in changed:
                current_ids = list(cred.host_ids or [])
                if host.id not in current_ids:
                    cred.host_ids = current_ids + [host.id]

    if changed:
        db.commit()
        for host in changed:
            db.refresh(host)
            bcast(pid, "host", "upsert", schemas.Host.model_validate(host).model_dump())
            label = host.hostname or host.ip
            dispatch_sync(db, "host_compromised",
                          f"🔴 Host Compromised: {label}",
                          f"IP: {host.ip}\nHostname: {host.hostname or '—'}\nNetExec found (Pwn3d!) — admin access confirmed.",
                          {"host_id": host.id, "ip": host.ip})


def _writeback_httpx_tags(db, pid: str, req: dict, result: dict) -> None:
    target = (req.get("target") or "").strip()
    if not target:
        return
    # Tag the specific target host with "web" if it exists
    host = (
        db.query(models.Host).filter(models.Host.pid == pid, models.Host.ip == target).first()
        or db.query(models.Host).filter(models.Host.pid == pid, models.Host.hostname == target).first()
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
        pass
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
            exists = db.query(models.Loot).filter(
                models.Loot.pid == job.pid,
                models.Loot.sha256 == sha,
                models.Loot.artifact_type == art.artifact_type,
            ).first()
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
    except Exception:
        pass
