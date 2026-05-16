"""
AI tool implementations — callable by the LLM agent.
Each async function takes (db, pid, **kwargs).
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from .. import models
from .utils import new_id, ts_now

logger = logging.getLogger(__name__)


# ── Tool implementations ──────────────────────────────────────────────

async def tool_list_hosts(db: Session, pid: str, query: str = "", tags=None, status: str = None):
    q = db.query(models.Host).filter(models.Host.pid == pid)
    if query:
        q = q.filter(
            (models.Host.ip.ilike(f"%{query}%")) | (models.Host.hostname.ilike(f"%{query}%"))
        )
    if status:
        q = q.filter(models.Host.status == status)
    hosts = q.all()
    if tags:
        if isinstance(tags, str):
            tags = [tags]
        hosts = [h for h in hosts if any(t in (h.tags or []) for t in tags)]
    result = []
    for h in hosts:
        result.append({
            "id": h.id,
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os,
            "status": h.status,
            "ports": (h.ports or [])[:5],
            "tags": h.tags or [],
            "is_attacker": h.is_attacker,
        })
    return result


async def tool_get_host(db: Session, pid: str, host_id: str):
    h = db.query(models.Host).filter(models.Host.id == host_id, models.Host.pid == pid).first()
    if not h:
        return {"error": "Host not found"}
    return {
        "id": h.id,
        "ip": h.ip,
        "ips": h.ips or [],
        "hostname": h.hostname,
        "os": h.os,
        "status": h.status,
        "ports": h.ports or [],
        "services": h.services or [],
        "tags": h.tags or [],
        "notes": h.notes,
        "domain": h.domain,
        "role": h.role,
        "is_attacker": h.is_attacker,
        "import_source": h.import_source,
    }


async def tool_list_creds(db: Session, pid: str, query: str = "", cred_type: str = None):
    q = db.query(models.Cred).filter(models.Cred.pid == pid)
    if cred_type:
        q = q.filter(models.Cred.type == cred_type)
    creds = q.all()
    if query:
        creds = [c for c in creds if query.lower() in c.username.lower() or query.lower() in (c.domain or "").lower()]
    result = []
    for c in creds:
        result.append({
            "id": c.id,
            "username": c.username,
            "domain": c.domain,
            "type": c.type,
            "service": c.service,
            "host": c.host,
            "tags": c.tags or [],
            "host_ids": c.host_ids or [],
        })
    return result


async def tool_list_findings(db: Session, pid: str, severity: str = None, status: str = None):
    q = db.query(models.Finding).filter(models.Finding.pid == pid)
    if severity:
        q = q.filter(models.Finding.severity == severity)
    if status:
        q = q.filter(models.Finding.status == status)
    findings = q.all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "host_id": f.host_id,
            "cve": f.cve,
            "cvss": f.cvss,
            "description": f.description[:200] if f.description else "",
        }
        for f in findings
    ]


async def tool_create_finding(db: Session, pid: str, title: str, severity: str,
                               description: str = "", recommendation: str = "", host_id: str = None):
    now = ts_now()
    finding = models.Finding(
        id=new_id("f"),
        pid=pid,
        title=title,
        severity=severity,
        description=description,
        recommendation=recommendation,
        host_id=host_id,
        status="open",
        ts=now,
        cvss="",
        cve="",
        proof="",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "host_id": finding.host_id,
    }


async def tool_add_host_tag(db: Session, pid: str, host_id: str, tag: str):
    host = db.query(models.Host).filter(models.Host.id == host_id, models.Host.pid == pid).first()
    if not host:
        return {"error": "Host not found"}
    tags = list(host.tags or [])
    if tag not in tags:
        tags.append(tag)
        host.tags = tags
        db.commit()
        db.refresh(host)
    return {
        "id": host.id,
        "ip": host.ip,
        "hostname": host.hostname,
        "tags": host.tags or [],
    }


async def tool_list_jobs(db: Session, pid: str, limit: int = 10, status: str = None):
    q = db.query(models.Job).filter(models.Job.pid == pid)
    if status:
        q = q.filter(models.Job.status == status)
    jobs = q.order_by(models.Job.created_at.desc()).limit(limit).all()
    return [
        {
            "id": j.id,
            "title": j.title,
            "status": j.status,
            "connector_key": j.connector_key,
            "operation": j.operation,
            "created_at": j.created_at,
            "finished_at": j.finished_at,
        }
        for j in jobs
    ]


async def tool_get_job_output(db: Session, pid: str, job_id: str):
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        return {"error": "Job not found"}
    output = (job.output or "")[:3000]
    return {
        "id": job.id,
        "title": job.title,
        "status": job.status,
        "output": output,
        "output_truncated": len(job.output or "") > 3000,
        "result_json": job.result_json or {},
    }


async def tool_get_scope(db: Session, pid: str):
    scopes = db.query(models.Scope).filter(models.Scope.pid == pid).all()
    return [
        {
            "id": s.id,
            "value": s.value,
            "scope_type": s.scope_type,
            "in_scope": s.in_scope,
            "description": s.description,
        }
        for s in scopes
    ]


async def tool_list_activities(db: Session, pid: str, host_id: str = None, limit: int = 20):
    q = db.query(models.HostActivity).filter(models.HostActivity.pid == pid)
    if host_id:
        q = q.filter(models.HostActivity.host_id == host_id)
    activities = q.order_by(models.HostActivity.ts.desc()).limit(limit).all()
    return [
        {
            "id": a.id,
            "host_id": a.host_id,
            "title": a.title,
            "activity_type": a.activity_type,
            "summary": a.summary,
            "status": a.status,
            "ts": a.ts,
        }
        for a in activities
    ]


async def tool_run_playbook(db: Session, pid: str, playbook_id: str, target: str = "",
                             username: str = "", password: str = "", domain: str = "", hash: str = ""):
    from ..routers.playbooks import _launch_playbook_run
    body_dict = {
        "target": target,
        "username": username,
        "password": password,
        "domain": domain,
        "hash": hash,
    }
    run_id = await _launch_playbook_run(pid=pid, playbook_id=playbook_id, body_dict=body_dict, created_by="ai-agent")
    return {"run_id": run_id, "status": "launched"}


async def tool_create_note(db: Session, pid: str, title: str, content: str,
                            phase: str = "recon", tags=None):
    now = ts_now()
    note = models.Note(
        id=new_id("n"),
        pid=pid,
        title=title,
        content=content,
        phase=phase,
        tags=tags or [],
        ts=now,
        starred=False,
        version=0,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return {
        "id": note.id,
        "pid": note.pid,
        "title": note.title,
        "phase": note.phase,
        "tags": note.tags or [],
        "ts": note.ts,
    }


# ── Tool definitions ──────────────────────────────────────────────────

TOOL_DEFS = [
    {
        "name": "list_hosts",
        "description": "List hosts in the project. Filter by IP/hostname query, tags, or status.",
        "params": {
            "query": {"type": "string", "description": "Filter by IP or hostname (partial match)"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "Filter hosts that have any of these tags"},
            "status": {"type": "string", "description": "Filter by host status (e.g. compromised, unknown, alive)"},
        },
        "required": [],
    },
    {
        "name": "get_host",
        "description": "Get full details of a host including ports, services, notes, tags.",
        "params": {
            "host_id": {"type": "string", "description": "Host ID"},
        },
        "required": ["host_id"],
    },
    {
        "name": "list_creds",
        "description": "List credentials in the project (secrets are not included).",
        "params": {
            "query": {"type": "string", "description": "Filter by username or domain"},
            "cred_type": {"type": "string", "description": "Filter by type: plain, hash, ntlm, kerberos"},
        },
        "required": [],
    },
    {
        "name": "list_findings",
        "description": "List security findings/vulnerabilities in the project.",
        "params": {
            "severity": {"type": "string", "description": "Filter by severity: critical, high, medium, low, info"},
            "status": {"type": "string", "description": "Filter by status: open, resolved, accepted"},
        },
        "required": [],
    },
    {
        "name": "create_finding",
        "description": "Create a new security finding/vulnerability.",
        "params": {
            "title": {"type": "string", "description": "Finding title"},
            "severity": {"type": "string", "description": "Severity: critical, high, medium, low, info"},
            "description": {"type": "string", "description": "Finding description"},
            "recommendation": {"type": "string", "description": "Remediation recommendation"},
            "host_id": {"type": "string", "description": "Associated host ID (optional)"},
        },
        "required": ["title", "severity"],
    },
    {
        "name": "add_host_tag",
        "description": "Add a tag to a host.",
        "params": {
            "host_id": {"type": "string", "description": "Host ID"},
            "tag": {"type": "string", "description": "Tag to add"},
        },
        "required": ["host_id", "tag"],
    },
    {
        "name": "list_jobs",
        "description": "List recent jobs/scans in the project.",
        "params": {
            "limit": {"type": "integer", "description": "Max results (default 10)"},
            "status": {"type": "string", "description": "Filter by status: queued, running, done, failed"},
        },
        "required": [],
    },
    {
        "name": "get_job_output",
        "description": "Get the output of a job/scan (truncated to 3000 chars).",
        "params": {
            "job_id": {"type": "string", "description": "Job ID"},
        },
        "required": ["job_id"],
    },
    {
        "name": "get_scope",
        "description": "Get the scope/target list for the project.",
        "params": {},
        "required": [],
    },
    {
        "name": "list_activities",
        "description": "List host activities/events in the project.",
        "params": {
            "host_id": {"type": "string", "description": "Filter by host ID"},
            "limit": {"type": "integer", "description": "Max results (default 20)"},
        },
        "required": [],
    },
    {
        "name": "run_playbook",
        "description": "Launch a playbook run asynchronously.",
        "params": {
            "playbook_id": {"type": "string", "description": "Playbook ID to run"},
            "target": {"type": "string", "description": "Target IP/host"},
            "username": {"type": "string", "description": "Username for auth"},
            "password": {"type": "string", "description": "Password for auth"},
            "domain": {"type": "string", "description": "Domain for auth"},
            "hash": {"type": "string", "description": "NTLM hash for auth"},
        },
        "required": ["playbook_id"],
    },
    {
        "name": "create_note",
        "description": "Create a note in the project.",
        "params": {
            "title": {"type": "string", "description": "Note title"},
            "content": {"type": "string", "description": "Note content (markdown)"},
            "phase": {"type": "string", "description": "Phase: recon, exploitation, post-exploitation, reporting"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "Tags for the note"},
        },
        "required": ["title", "content"],
    },
]


def _tool_def_to_openai(td: dict) -> dict:
    """Convert internal tool def to OpenAI function tool format."""
    return {
        "type": "function",
        "function": {
            "name": td["name"],
            "description": td["description"],
            "parameters": {
                "type": "object",
                "properties": td.get("params", {}),
                "required": td.get("required", []),
            },
        },
    }


def _tool_def_to_anthropic(td: dict) -> dict:
    """Convert internal tool def to Anthropic tool format."""
    return {
        "name": td["name"],
        "description": td["description"],
        "input_schema": {
            "type": "object",
            "properties": td.get("params", {}),
            "required": td.get("required", []),
        },
    }


TOOLS_OPENAI = [_tool_def_to_openai(t) for t in TOOL_DEFS]
TOOLS_ANTHROPIC = [_tool_def_to_anthropic(t) for t in TOOL_DEFS]


_TOOL_MAP = {
    "list_hosts": tool_list_hosts,
    "get_host": tool_get_host,
    "list_creds": tool_list_creds,
    "list_findings": tool_list_findings,
    "create_finding": tool_create_finding,
    "add_host_tag": tool_add_host_tag,
    "list_jobs": tool_list_jobs,
    "get_job_output": tool_get_job_output,
    "get_scope": tool_get_scope,
    "list_activities": tool_list_activities,
    "run_playbook": tool_run_playbook,
    "create_note": tool_create_note,
}


async def execute_tool(db: Session, pid: str, name: str, args: dict) -> dict:
    """Dispatch a tool call by name."""
    fn = _TOOL_MAP.get(name)
    if fn is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        result = await fn(db=db, pid=pid, **args)
        return result
    except Exception as e:
        logger.warning("[ai_tools] tool %s error: %s", name, e)
        return {"error": str(e)}
