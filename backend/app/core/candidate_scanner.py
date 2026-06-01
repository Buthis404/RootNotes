"""
Project-wide finding candidate scanner (P8).

Analyses the full project state — creds, hosts, CredHostNotes, network edges,
host activities, recent job structured results — and surfaces analyst hints as
Finding records with status='candidate' and source='auto'.

Rules:
  R1  reused_admin_cred        — admin cred valid on 3+ hosts
  R2  valid_on_many_hosts      — any cred valid on 5+ hosts
  R3  privileged_on_sensitive  — admin access on DC/server/db
  R4  da_context               — domain_admin access anywhere
  R5  lateral_path_confirmed   — verified access-graph edge
  R6  live_session_sensitive   — C2 session on DC/server
  R7  kerberoastable_spns      — SPN accounts found (from job candidates)
  R8  adcs_vulnerable          — vulnerable ADCS template (from job candidates)
  R9  unconstrained_delegation — unconstrained delegation found
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import models
from ..core.utils import new_id, ts_now
from .network_data import get_edges, get_nodes

_SENSITIVE_ROLES = {"domain_controller", "server", "file_server", "database"}
_ADMIN_ACCESS = {"local_admin", "domain_admin", "shell"}
_ACCESS_EDGE_TYPES = {
    "ssh",
    "winrm",
    "smb_admin",
    "local_admin",
    "shell",
    "c2_session",
    "lateral",
    "pivot",
    "auth_path",
    "domain_admin",
}


@dataclass
class CandidateResult:
    created: int = 0
    updated: int = 0
    skipped: int = 0
    candidates: list = field(default_factory=list)


def run_scan(db, pid: str) -> CandidateResult:
    ts = ts_now()

    hosts = {h.id: h for h in db.query(models.Host).filter(models.Host.pid == pid).all()}
    creds = {c.id: c for c in db.query(models.Cred).filter(models.Cred.pid == pid).all()}
    chns = db.query(models.CredHostNote).filter(models.CredHostNote.pid == pid).all()
    activities = db.query(models.HostActivity).filter(models.HostActivity.pid == pid).all()
    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    recent_jobs = (
        db.query(models.Job)
        .filter(models.Job.pid == pid, models.Job.status == "done")
        .order_by(models.Job.finished_at.desc())
        .limit(200)
        .all()
    )

    existing = (
        db.query(models.Finding)
        .filter(models.Finding.pid == pid, models.Finding.source == "auto")
        .all()
    )
    existing_proofs: set[str] = {f.proof for f in existing if f.proof}

    candidates: list[dict] = []
    candidates += _scan_r1_r2(chns, creds)
    candidates += _scan_r3(chns, hosts, creds)
    candidates += _scan_r4(chns, hosts, creds)
    candidates += _scan_r5(network, db)
    candidates += _scan_r6(activities, hosts)
    candidates += _scan_r7_r8_r9(recent_jobs)

    return _persist(db, pid, ts, candidates, existing_proofs)


def _cred_label(creds: dict, cred_id: str) -> str:
    cred = creds.get(cred_id)
    return cred.username if cred else cred_id


def _scan_r1_r2(chns, creds) -> list[dict]:
    results: list[dict] = []
    cred_access: dict[str, list[str]] = {}
    cred_admin: dict[str, list[str]] = {}

    for chn in chns:
        roles = chn.access or []
        if roles:
            cred_access.setdefault(chn.cred_id, []).append(chn.host_id)
        if any(r in _ADMIN_ACCESS for r in roles):
            cred_admin.setdefault(chn.cred_id, []).append(chn.host_id)

    for cred_id, host_ids in cred_admin.items():
        unique = list(set(host_ids))
        if len(unique) >= 3:
            label = _cred_label(creds, cred_id)
            results.append(
                {
                    "rule": "reused_admin_cred",
                    "title": f"Admin credential reuse: {label} has admin access on {len(unique)} hosts",
                    "severity": "high",
                    "description": (
                        f"Credential **{label}** has confirmed admin-level access (local_admin / domain_admin / shell) "
                        f"on {len(unique)} hosts. This indicates lateral movement potential and/or a reused password."
                    ),
                    "recommendation": "Rotate this credential immediately. Review why admin access is uniform across hosts.",
                    "proof": f"R1:{cred_id}",
                    "host_id": None,
                }
            )

    for cred_id, host_ids in cred_access.items():
        unique = list(set(host_ids))
        if len(unique) >= 5:
            label = _cred_label(creds, cred_id)
            results.append(
                {
                    "rule": "valid_on_many_hosts",
                    "title": f"Credential valid on {len(unique)} hosts: {label}",
                    "severity": "medium",
                    "description": (
                        f"Credential **{label}** was validated successfully on {len(unique)} hosts. "
                        f"This suggests password reuse across the environment."
                    ),
                    "recommendation": "Enforce unique local admin passwords (LAPS). Audit password reuse policy.",
                    "proof": f"R2:{cred_id}",
                    "host_id": None,
                }
            )

    return results


def _scan_r3(chns, hosts, creds) -> list[dict]:
    results: list[dict] = []
    for chn in chns:
        host = hosts.get(chn.host_id)
        if not host or host.role not in _SENSITIVE_ROLES:
            continue
        admin_roles = [r for r in (chn.access or []) if r in _ADMIN_ACCESS]
        if not admin_roles:
            continue
        cred = creds.get(chn.cred_id)
        label = cred.username if cred else chn.cred_id
        host_label = host.hostname or host.ip or host.id
        results.append(
            {
                "rule": "privileged_on_sensitive",
                "title": f"Admin access on {host.role.replace('_', ' ')}: {host_label}",
                "severity": "critical" if host.role == "domain_controller" else "high",
                "description": (
                    f"Credential **{label}** has **{', '.join(admin_roles)}** access on **{host_label}** "
                    f"(role: {host.role.replace('_', ' ')}). This is a high-impact access point."
                ),
                "recommendation": f"Verify this access is authorized. Document the attack path to {host_label}.",
                "proof": f"R3:{chn.cred_id}:{chn.host_id}",
                "host_id": chn.host_id,
            }
        )
    return results


def _scan_r4(chns, hosts, creds) -> list[dict]:
    results: list[dict] = []
    for chn in chns:
        if "domain_admin" not in (chn.access or []):
            continue
        host = hosts.get(chn.host_id)
        cred = creds.get(chn.cred_id)
        label = cred.username if cred else chn.cred_id
        host_label = (host.hostname or host.ip or chn.host_id) if host else chn.host_id
        results.append(
            {
                "rule": "da_context",
                "title": f"Domain Admin access confirmed: {label}",
                "severity": "critical",
                "description": (
                    f"Credential **{label}** has confirmed **Domain Admin** access (verified on {host_label}). "
                    f"This represents full domain compromise."
                ),
                "recommendation": "Document full attack chain. Notify client. Prepare domain compromise report.",
                "proof": f"R4:{chn.cred_id}",
                "host_id": chn.host_id,
            }
        )
    return results


def _scan_r5(network, db) -> list[dict]:
    if not network:
        return []
    results: list[dict] = []
    edges = get_edges(network.id, db)
    nodes = {n["id"]: n for n in get_nodes(network.id, db)}
    for edge in edges:
        if not edge.get("verified"):
            continue
        etype = edge.get("type", "")
        if etype not in _ACCESS_EDGE_TYPES:
            continue
        fn = nodes.get(edge.get("from", ""), {})
        tn = nodes.get(edge.get("to", ""), {})
        from_label = fn.get("label") or fn.get("ip") or edge.get("from", "?")
        to_label = tn.get("label") or tn.get("ip") or edge.get("to", "?")
        results.append(
            {
                "rule": "lateral_path_confirmed",
                "title": f"Lateral path confirmed: {from_label} → {to_label} ({etype})",
                "severity": "high",
                "description": (
                    f"A verified **{etype}** access edge exists between **{from_label}** and **{to_label}**. "
                    f"This represents a confirmed lateral movement path."
                ),
                "recommendation": "Document this lateral path. Include in the attack narrative.",
                "proof": f"R5:{edge.get('id', edge.get('from',''))}:{edge.get('to','')}",
                "host_id": tn.get("host_id"),
            }
        )
    return results


def _scan_r6(activities, hosts) -> list[dict]:
    results: list[dict] = []
    for act in activities:
        if act.activity_type != "c2":
            continue
        host = hosts.get(act.host_id)
        if not host or host.role not in _SENSITIVE_ROLES:
            continue
        host_label = host.hostname or host.ip or host.id
        results.append(
            {
                "rule": "live_session_sensitive",
                "title": f"Live C2 session on {host.role.replace('_', ' ')}: {host_label}",
                "severity": "critical" if host.role == "domain_controller" else "high",
                "description": (
                    f"An active C2 session is recorded on **{host_label}** (role: {host.role.replace('_', ' ')}). "
                    f"Last activity: {act.ts}."
                ),
                "recommendation": "This is a critical finding. Document implant details and operator context.",
                "proof": f"R6:{act.host_id}",
                "host_id": act.host_id,
            }
        )
    return results


_JOB_RULE_MAP = {
    "kerberoastable_accounts": ("R7", "medium"),
    "adcs_vulnerable_template": ("R8", "critical"),
    "adcs_detected": ("R8b", "medium"),
    "unconstrained_delegation": ("R9", "high"),
    "domain_admin_access": ("R4b", "critical"),
    "mssql_sysadmin": ("R3b", "high"),
}


def _scan_r7_r8_r9(recent_jobs) -> list[dict]:
    results: list[dict] = []
    seen: set[str] = set()
    for job in recent_jobs:
        rj = job.result_json or {}
        for fc in rj.get("structured", {}).get("finding_candidates", []):
            fc_type = fc.get("type", "")
            if fc_type not in _JOB_RULE_MAP:
                continue
            rule_prefix, sev = _JOB_RULE_MAP[fc_type]
            proof = f"{rule_prefix}:{job.id}:{fc_type}"
            if proof in seen:
                continue
            seen.add(proof)
            results.append(
                {
                    "rule": fc_type,
                    "title": fc.get("title", fc_type),
                    "severity": fc.get("severity") or sev,
                    "description": fc.get("details", "")
                    or f"Detected during job {job.id} ({job.title}).",
                    "recommendation": _recommendation_for(fc_type),
                    "proof": proof,
                    "host_id": fc.get("host_id"),
                }
            )
    return results


def _persist(
    db, pid: str, ts: str, candidates: list[dict], existing_proofs: set[str]
) -> CandidateResult:
    result = CandidateResult()
    for c in candidates:
        proof = c["proof"]
        if proof in existing_proofs:
            result.skipped += 1
            continue
        existing_proofs.add(proof)
        finding = models.Finding(
            id=new_id("fin"),
            pid=pid,
            host_id=c.get("host_id"),
            title=c["title"],
            severity=c["severity"],
            description=c["description"],
            recommendation=c["recommendation"],
            proof=proof,
            status="candidate",
            source="auto",
            ts=ts,
        )
        db.add(finding)
        result.created += 1
        result.candidates.append(
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "rule": c["rule"],
            }
        )
    db.commit()
    return result


def _recommendation_for(fc_type: str) -> str:
    return {
        "kerberoastable_accounts": "Request TGS tickets and attempt offline cracking with hashcat/john.",
        "adcs_vulnerable_template": "Use certipy-ad exploit to obtain a domain cert. Escalate to DA if ESC1/ESC3.",
        "adcs_detected": "Enumerate templates for misconfigurations using certipy-ad find -vulnerable.",
        "unconstrained_delegation": "If you can compromise this account/host, use it to capture TGT tickets from any connecting service.",
        "domain_admin_access": "Document full attack chain. Prepare domain compromise report.",
        "mssql_sysadmin": "Attempt xp_cmdshell or SQL agent job for code execution.",
    }.get(fc_type, "Review and escalate as appropriate.")
