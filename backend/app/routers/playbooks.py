import asyncio
import io
import json
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast
from ..core.job_runner import schedule_job_run
from ..core.job_tracker import queue_job
from ..core.utils import new_id, ts_now
from ..database import SessionLocal, get_db
from ..plugins.registry import registry

router = APIRouter(tags=["playbooks"])


def _now() -> str:
    return ts_now()


class PlaybookStepBody(BaseModel):
    title: str
    connector_key: str
    operation: str
    params: dict = Field(default_factory=dict)
    on_success: str = "next"  # next | stop | jump
    on_success_step: int | None = None
    on_failure: str = "stop"  # stop | continue | jump
    on_failure_step: int | None = None
    result_conditions: list[dict] = Field(default_factory=list)


class PlaybookBody(BaseModel):
    title: str
    description: str = ""
    steps: list[PlaybookStepBody] = Field(default_factory=list)


class PlaybookRunBody(BaseModel):
    target: str = ""
    target_url: str = ""
    target_id: str | None = None
    flags: str = "-sV -sC -T4 --open"
    severity: str = "critical,high,medium"
    keep_manual_positions: bool = True
    create_missing_networks: bool = True
    # AD / auth fields — used for credential substitution in steps
    username: str = ""
    password: str = ""
    domain: str = ""
    hash: str = ""


class BatchRunBody(BaseModel):
    host_ids: list[str] = []       # explicit host selection (from UI checkboxes)
    host_tags: list[str] = []      # filter: hosts with any of these tags
    host_status: str = ""          # filter: hosts by status
    parallelism: int = 3           # max concurrent runs (1-10)
    # Playbook run params (same as PlaybookRunBody)
    target_url: str = ""
    flags: str = "-sV -sC -T4 --open"
    severity: str = "critical,high,medium"
    keep_manual_positions: bool = True
    create_missing_networks: bool = True
    username: str = ""
    password: str = ""
    domain: str = ""
    hash: str = ""


STEP_TEMPLATES = {
    "topology:auto_build": {
        "id": "topology:auto_build",
        "title": "Topology Auto-Build",
        "connector_key": "topology",
        "operation": "auto_build",
        "description": "Build or refresh the network graph from known hosts.",
        "fields": [
            {"key": "keep_manual_positions", "label": "Keep manual positions", "type": "boolean", "default": True},
            {"key": "create_missing_networks", "label": "Create missing networks", "type": "boolean", "default": True},
        ],
    },
    "topology:rebuild_layout": {
        "id": "topology:rebuild_layout",
        "title": "Topology Rebuild Layout",
        "connector_key": "topology",
        "operation": "rebuild_layout",
        "description": "Recompute node positions for the current map.",
        "fields": [
            {"key": "keep_manual_positions", "label": "Keep manual positions", "type": "boolean", "default": True},
        ],
    },
    "nmap:scan": {
        "id": "nmap:scan",
        "title": "Nmap Scan",
        "connector_key": "nmap",
        "operation": "scan",
        "description": "Network discovery and service fingerprinting.",
        "fields": [
            {"key": "target", "label": "Target", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "flags", "label": "Flags", "type": "text", "default": "-sV -sC -T4 --open"},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 180},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "nuclei:scan": {
        "id": "nuclei:scan",
        "title": "Nuclei Scan",
        "connector_key": "nuclei",
        "operation": "scan",
        "description": "Template-based vulnerability scan for a URL.",
        "fields": [
            {"key": "target_url", "label": "Target URL", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "severity", "label": "Severity", "type": "text", "default": "critical,high,medium"},
            {"key": "templates", "label": "Templates path", "type": "text", "default": ""},
            {"key": "extra_flags", "label": "Extra flags", "type": "text", "default": ""},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 300},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "netexec:scan": {
        "id": "netexec:scan",
        "title": "NetExec Scan",
        "connector_key": "netexec",
        "operation": "scan",
        "description": "Credential-aware internal enumeration.",
        "fields": [
            {"key": "target", "label": "Target", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "protocol", "label": "Protocol", "type": "select", "options": ["smb", "winrm", "rdp", "ldap", "mssql"], "default": "smb"},
            {"key": "extra_flags", "label": "Extra flags", "type": "text", "default": "--users --groups"},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 120},
            {"key": "username", "label": "Username", "type": "text", "default": ""},
            {"key": "password", "label": "Password", "type": "text", "default": ""},
            {"key": "domain", "label": "Domain", "type": "text", "default": ""},
            {"key": "hash", "label": "Hash", "type": "text", "default": ""},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "attacker_ssh:exec": {
        "id": "attacker_ssh:exec",
        "title": "Attacker SSH Exec",
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "description": "Execute a command from the attacker box.",
        "fields": [
            {"key": "command", "label": "Command", "type": "textarea", "default": "", "required": True},
            {"key": "execution_mode", "label": "Execution mode", "type": "select", "options": ["auto", "project", "global"], "default": "auto"},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 45},
            {"key": "activity_type", "label": "Activity type", "type": "text", "default": "postex"},
            {"key": "host_id", "label": "Host id", "type": "text", "default": ""},
            {"key": "cred_id", "label": "Cred id", "type": "text", "default": ""},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    # ── AD / Kerberos templates ───────────────────────────────────────────
    "attacker_ssh:kerberoast": {
        "id": "attacker_ssh:kerberoast",
        "title": "Kerberoast (impacket)",
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "description": "Request Kerberos TGS tickets for SPN accounts and save for offline cracking.",
        "fields": [
            {"key": "command", "label": "Command", "type": "textarea",
             "default": "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {target} -request -outputfile /tmp/kerberoast_{target}.txt 2>&1 && echo 'DONE'", "required": True},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 120},
            {"key": "activity_type", "label": "Activity type", "type": "text", "default": "kerberoast"},
            {"key": "execution_mode", "label": "Execution mode", "type": "select", "options": ["auto", "project", "global"], "default": "auto"},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
            {"key": "host_id", "label": "Host id", "type": "text", "default": ""},
            {"key": "cred_id", "label": "Cred id", "type": "text", "default": ""},
        ],
    },
    "attacker_ssh:asreproast": {
        "id": "attacker_ssh:asreproast",
        "title": "AS-REP Roast (impacket)",
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "description": "Find accounts without Kerberos pre-authentication and request AS-REP hashes.",
        "fields": [
            {"key": "command", "label": "Command", "type": "textarea",
             "default": "impacket-GetNPUsers '{domain}/' -dc-ip {target} -no-pass -usersfile /tmp/users.txt -outputfile /tmp/asrep_{target}.txt 2>&1 && echo 'DONE'", "required": True},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 90},
            {"key": "activity_type", "label": "Activity type", "type": "text", "default": "asreproast"},
            {"key": "execution_mode", "label": "Execution mode", "type": "select", "options": ["auto", "project", "global"], "default": "auto"},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
            {"key": "host_id", "label": "Host id", "type": "text", "default": ""},
            {"key": "cred_id", "label": "Cred id", "type": "text", "default": ""},
        ],
    },
    "attacker_ssh:ldap_dump": {
        "id": "attacker_ssh:ldap_dump",
        "title": "LDAP Dump (ldapdomaindump)",
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "description": "Dump all AD objects via LDAP and save to /tmp. Requires valid domain credentials.",
        "fields": [
            {"key": "command", "label": "Command", "type": "textarea",
             "default": "ldapdomaindump -u '{domain}\\{username}' -p '{password}' {target} -o /tmp/ldap_{target} 2>&1 && echo 'DONE'", "required": True},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 180},
            {"key": "activity_type", "label": "Activity type", "type": "text", "default": "ldap_enum"},
            {"key": "execution_mode", "label": "Execution mode", "type": "select", "options": ["auto", "project", "global"], "default": "auto"},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
            {"key": "host_id", "label": "Host id", "type": "text", "default": ""},
            {"key": "cred_id", "label": "Cred id", "type": "text", "default": ""},
        ],
    },
    "netexec:ldap_enum": {
        "id": "netexec:ldap_enum",
        "title": "NetExec LDAP Enum",
        "connector_key": "netexec",
        "operation": "scan",
        "description": "Enumerate AD users, groups, computers and password policy via LDAP.",
        "fields": [
            {"key": "target", "label": "Target DC IP", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "protocol", "label": "Protocol", "type": "select", "options": ["ldap", "ldaps"], "default": "ldap"},
            {"key": "extra_flags", "label": "Extra flags", "type": "text", "default": "--users --groups --computers --password-not-required --admin-count --trusted-for-delegation"},
            {"key": "username", "label": "Username", "type": "text", "default": ""},
            {"key": "password", "label": "Password", "type": "text", "default": ""},
            {"key": "domain", "label": "Domain", "type": "text", "default": ""},
            {"key": "hash", "label": "Hash", "type": "text", "default": ""},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 120},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "netexec:spray_smb": {
        "id": "netexec:spray_smb",
        "title": "NetExec SMB Spray",
        "connector_key": "netexec",
        "operation": "scan",
        "description": "Password spray a single username:password pair across SMB targets. Uses --continue-on-success.",
        "fields": [
            {"key": "target", "label": "Target", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "protocol", "label": "Protocol", "type": "select", "options": ["smb", "winrm", "rdp", "mssql", "ssh"], "default": "smb"},
            {"key": "extra_flags", "label": "Extra flags", "type": "text", "default": "--continue-on-success --no-bruteforce"},
            {"key": "username", "label": "Username", "type": "text", "default": ""},
            {"key": "password", "label": "Password", "type": "text", "default": ""},
            {"key": "domain", "label": "Domain", "type": "text", "default": ""},
            {"key": "hash", "label": "Hash (NTLM)", "type": "text", "default": ""},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 120},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "httpx:scan": {
        "id": "httpx:scan",
        "title": "httpx Web Probe",
        "connector_key": "httpx",
        "operation": "scan",
        "description": "Probe HTTP/HTTPS services on a host or URL list. Discovers live web services, titles, and technologies.",
        "fields": [
            {"key": "target", "label": "Target (host, IP, CIDR or URL)", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "flags", "label": "Flags", "type": "text", "default": "-title -status-code -tech-detect -follow-redirects"},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 120},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "ffuf:scan": {
        "id": "ffuf:scan",
        "title": "ffuf Content Discovery",
        "connector_key": "ffuf",
        "operation": "scan",
        "description": "Fuzz web directories and files. Creates findings for discovered paths.",
        "fields": [
            {"key": "target_url", "label": "Target URL", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "wordlist", "label": "Wordlist path", "type": "text", "default": "/usr/share/seclists/Discovery/Web-Content/common.txt"},
            {"key": "extensions", "label": "Extensions (e.g. php,html)", "type": "text", "default": ""},
            {"key": "flags", "label": "Flags", "type": "text", "default": "-mc 200,204,301,302,307,401,403,405"},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 300},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    # ── AD — new step templates ───────────────────────────────────────────────
    "attacker_ssh:spn_enum": {
        "id": "attacker_ssh:spn_enum",
        "title": "SPN Enumeration (impacket)",
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "description": "List all SPN accounts (Kerberoastable) without requesting tickets.",
        "fields": [
            {"key": "command", "label": "Command", "type": "textarea",
             "default": "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {target} 2>&1", "required": True},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 60},
            {"key": "activity_type", "label": "Activity type", "type": "text", "default": "recon"},
            {"key": "execution_mode", "label": "Execution mode", "type": "select", "options": ["auto", "project", "global"], "default": "auto"},
        ],
    },
    "attacker_ssh:adcs_enum": {
        "id": "attacker_ssh:adcs_enum",
        "title": "ADCS Enum (certipy)",
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "description": "Find vulnerable AD CS templates (ESC1–ESC8) via certipy-ad.",
        "fields": [
            {"key": "command", "label": "Command", "type": "textarea",
             "default": "certipy-ad find -u '{username}@{domain}' -p '{password}' -dc-ip {target} -stdout 2>&1", "required": True},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 120},
            {"key": "activity_type", "label": "Activity type", "type": "text", "default": "recon"},
            {"key": "execution_mode", "label": "Execution mode", "type": "select", "options": ["auto", "project", "global"], "default": "auto"},
        ],
    },
    "attacker_ssh:delegation_enum": {
        "id": "attacker_ssh:delegation_enum",
        "title": "Delegation Enum (impacket)",
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "description": "Find accounts with unconstrained or constrained Kerberos delegation.",
        "fields": [
            {"key": "command", "label": "Command", "type": "textarea",
             "default": "impacket-findDelegation '{domain}/{username}:{password}' -dc-ip {target} 2>&1", "required": True},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 60},
            {"key": "activity_type", "label": "Activity type", "type": "text", "default": "recon"},
            {"key": "execution_mode", "label": "Execution mode", "type": "select", "options": ["auto", "project", "global"], "default": "auto"},
        ],
    },
    "attacker_ssh:bloodhound_collect": {
        "id": "attacker_ssh:bloodhound_collect",
        "title": "BloodHound Collection (bloodhound-python)",
        "connector_key": "attacker_ssh",
        "operation": "exec",
        "description": "Collect BloodHound data via bloodhound-python. Saves JSON files to /tmp/bh_{target}/.",
        "fields": [
            {"key": "command", "label": "Command", "type": "textarea",
             "default": "mkdir -p /tmp/bh_{target} && bloodhound-python -u '{username}' -p '{password}' -d '{domain}' -ns {target} -c All --zip -o /tmp/bh_{target}/ 2>&1 && echo 'DONE'", "required": True},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 300},
            {"key": "activity_type", "label": "Activity type", "type": "text", "default": "recon"},
            {"key": "execution_mode", "label": "Execution mode", "type": "select", "options": ["auto", "project", "global"], "default": "auto"},
        ],
    },
    "netexec:spray_winrm": {
        "id": "netexec:spray_winrm",
        "title": "NetExec WinRM Spray",
        "connector_key": "netexec",
        "operation": "scan",
        "description": "Password spray via WinRM. Identifies hosts where the credential grants remote shell access.",
        "fields": [
            {"key": "target", "label": "Target", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "protocol", "label": "Protocol", "type": "select", "options": ["winrm", "smb", "mssql", "rdp"], "default": "winrm"},
            {"key": "extra_flags", "label": "Extra flags", "type": "text", "default": "--continue-on-success --no-bruteforce"},
            {"key": "username", "label": "Username", "type": "text", "default": ""},
            {"key": "password", "label": "Password", "type": "text", "default": ""},
            {"key": "domain", "label": "Domain", "type": "text", "default": ""},
            {"key": "hash", "label": "Hash (NTLM)", "type": "text", "default": ""},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 120},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
    "netexec:adcs_check": {
        "id": "netexec:adcs_check",
        "title": "NetExec ADCS Check",
        "connector_key": "netexec",
        "operation": "scan",
        "description": "Check for ADCS (Certificate Services) via NetExec ldap --adcs module.",
        "fields": [
            {"key": "target", "label": "Target DC IP", "type": "text", "default": "", "runtime_fallback": True},
            {"key": "protocol", "label": "Protocol", "type": "select", "options": ["ldap", "ldaps"], "default": "ldap"},
            {"key": "extra_flags", "label": "Extra flags", "type": "text", "default": "--adcs"},
            {"key": "username", "label": "Username", "type": "text", "default": ""},
            {"key": "password", "label": "Password", "type": "text", "default": ""},
            {"key": "domain", "label": "Domain", "type": "text", "default": ""},
            {"key": "hash", "label": "Hash (NTLM)", "type": "text", "default": ""},
            {"key": "timeout_seconds", "label": "Timeout", "type": "number", "default": 60},
            {"key": "target_id", "label": "Attacker target id", "type": "text", "default": ""},
        ],
    },
}

CONDITION_OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "contains"}


def _template_for(connector_key: str, operation: str) -> dict | None:
    return STEP_TEMPLATES.get(f"{connector_key}:{operation}")


def _normalize_field_value(field: dict, value):
    if field.get("type") == "number":
        try:
            return int(value)
        except Exception:
            return field.get("default", 0)
    if field.get("type") == "boolean":
        return bool(value)
    return "" if value is None else value


def _normalize_branch_action(value: str | None, *, success: bool) -> str:
    if not value:
        return "next" if success else "stop"
    value = value.strip().lower()
    if value == "continue":
        return "next"
    return value


def _normalize_condition(rule: dict) -> dict:
    return {
        "when": (rule.get("when") or "success").strip().lower(),
        "result_key": str(rule.get("result_key") or "").strip(),
        "operator": str(rule.get("operator") or "eq").strip().lower(),
        "value": rule.get("value"),
        "action": _normalize_branch_action(rule.get("action"), success=True),
        "target_step": rule.get("target_step"),
    }


def _extract_result_value(result: dict, result_key: str):
    current = result
    for part in result_key.split('.'):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _condition_matches(actual, operator: str, expected) -> bool:
    if operator == "eq":
        return actual == expected
    if operator == "ne":
        return actual != expected
    if operator == "contains":
        return expected in actual if isinstance(actual, (str, list, tuple, set)) else False
    try:
        a = float(actual)
        b = float(expected)
    except Exception:
        return False
    if operator == "gt":
        return a > b
    if operator == "gte":
        return a >= b
    if operator == "lt":
        return a < b
    if operator == "lte":
        return a <= b
    return False


def _resolve_result_condition_target(step: dict, job_result: dict, *, status: str, total_steps: int):
    rules = step.get("result_conditions") or []
    for raw_rule in rules:
        rule = _normalize_condition(raw_rule)
        if rule["when"] not in {"success", "failure", "always"}:
            continue
        if rule["when"] == "success" and status != "done":
            continue
        if rule["when"] == "failure" and status == "done":
            continue
        actual = _extract_result_value(job_result or {}, rule["result_key"])
        if _condition_matches(actual, rule["operator"], rule["value"]):
            if rule["action"] == "stop":
                return None, True
            if rule["action"] == "jump":
                target = rule.get("target_step")
                if isinstance(target, int) and 1 <= target <= total_steps:
                    return target - 1, False
                return None, True
            return None, False
    return None, False


def _validate_playbook_payload(body: PlaybookBody, available_connectors: list[dict]) -> dict:
    errors = []
    warnings = []
    connector_map = {item["key"]: item for item in available_connectors}

    if not body.title.strip():
        errors.append("Title is required")
    if not body.steps:
        errors.append("At least one step is required")

    normalized_steps = []
    total_steps = len(body.steps)
    for idx, step in enumerate(body.steps):
        prefix = f"Step {idx + 1}"
        if not step.title.strip():
            errors.append(f"{prefix}: title is required")
        connector = connector_map.get(step.connector_key)
        if not connector:
            errors.append(f"{prefix}: unsupported connector {step.connector_key!r}")
            continue
        if step.operation not in (connector.get("supported_operations") or []):
            errors.append(f"{prefix}: unsupported operation {step.operation!r} for connector {step.connector_key!r}")
            continue
        on_success = _normalize_branch_action(step.on_success, success=True)
        on_failure = _normalize_branch_action(step.on_failure, success=False)
        if on_success not in {"next", "stop", "jump"}:
            errors.append(f"{prefix}: on_success must be 'next', 'stop', or 'jump'")
        if on_failure not in {"next", "stop", "jump"}:
            errors.append(f"{prefix}: on_failure must be 'stop', 'next', or 'jump'")
        if on_success == "jump":
            if step.on_success_step is None:
                errors.append(f"{prefix}: on_success_step is required when on_success='jump'")
            elif step.on_success_step < 1 or step.on_success_step > total_steps:
                errors.append(f"{prefix}: on_success_step must be between 1 and {total_steps}")
        if on_failure == "jump":
            if step.on_failure_step is None:
                errors.append(f"{prefix}: on_failure_step is required when on_failure='jump'")
            elif step.on_failure_step < 1 or step.on_failure_step > total_steps:
                errors.append(f"{prefix}: on_failure_step must be between 1 and {total_steps}")

        template = _template_for(step.connector_key, step.operation)
        params = dict(step.params or {})
        normalized_conditions = []
        for ridx, raw_rule in enumerate(step.result_conditions or []):
            cond = _normalize_condition(raw_rule)
            if cond["when"] not in {"success", "failure", "always"}:
                errors.append(f"{prefix}: condition {ridx + 1} has invalid when value")
            if not cond["result_key"]:
                errors.append(f"{prefix}: condition {ridx + 1} requires result_key")
            if cond["operator"] not in CONDITION_OPERATORS:
                errors.append(f"{prefix}: condition {ridx + 1} has invalid operator")
            if cond["action"] not in {"next", "stop", "jump"}:
                errors.append(f"{prefix}: condition {ridx + 1} has invalid action")
            if cond["action"] == "jump":
                if cond["target_step"] is None:
                    errors.append(f"{prefix}: condition {ridx + 1} requires target_step when action='jump'")
                elif cond["target_step"] < 1 or cond["target_step"] > total_steps:
                    errors.append(f"{prefix}: condition {ridx + 1} target_step must be between 1 and {total_steps}")
            normalized_conditions.append(cond)
        if template:
          allowed = {field["key"]: field for field in template.get("fields", [])}
          unknown = [key for key in params.keys() if key not in allowed]
          if unknown:
              warnings.append(f"{prefix}: unknown params will be ignored: {', '.join(sorted(unknown))}")
          normalized_params = {}
          for key, field in allowed.items():
              value = params.get(key, field.get("default"))
              if field.get("required") and str(value).strip() == "":
                  errors.append(f"{prefix}: field {key!r} is required")
              if (not field.get("runtime_fallback")) and field.get("type") == "text" and field.get("required", False) is False and key in params and value == "":
                  pass
              normalized_params[key] = _normalize_field_value(field, value)
          params = normalized_params
        normalized_steps.append({
            "title": step.title.strip(),
            "connector_key": step.connector_key,
            "operation": step.operation,
            "params": params,
            "on_success": on_success,
            "on_success_step": step.on_success_step,
            "on_failure": on_failure,
            "on_failure_step": step.on_failure_step,
            "result_conditions": normalized_conditions,
        })

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "normalized": {
            "title": body.title.strip(),
            "description": body.description.strip(),
            "steps": normalized_steps,
        },
    }


BUILTIN_PLAYBOOKS = {
    "topology-refresh": {
        "id": "topology-refresh",
        "title": "Topology Refresh",
        "description": "Rebuild the operational graph from all known hosts.",
        "editable": False,
        "steps": [
            {"title": "Topology auto-build", "connector_key": "topology", "operation": "auto_build", "params": {}, "on_failure": "stop"},
        ],
    },
    "internal-recon": {
        "id": "internal-recon",
        "title": "Internal Recon",
        "description": "Run an Nmap scan and then refresh topology from discovered hosts.",
        "editable": False,
        "steps": [
            {"title": "Nmap scan", "connector_key": "nmap", "operation": "scan", "params": {}, "on_success": "next", "on_failure": "stop", "result_conditions": [{"when": "success", "result_key": "hosts_found", "operator": "eq", "value": 0, "action": "stop"}]},
            {"title": "Topology auto-build", "connector_key": "topology", "operation": "auto_build", "params": {}, "on_success": "next", "on_failure": "stop"},
        ],
    },
    "web-triage": {
        "id": "web-triage",
        "title": "Web Triage",
        "description": "Run a Nuclei scan against a supplied target URL.",
        "editable": False,
        "steps": [
            {"title": "Nuclei scan", "connector_key": "nuclei", "operation": "scan", "params": {}, "on_success": "next", "on_failure": "stop", "result_conditions": [{"when": "success", "result_key": "findings_created", "operator": "gt", "value": 0, "action": "stop"}]},
        ],
    },
    # ── AD Playbooks ──────────────────────────────────────────────────────
    "ad-ldap-enum": {
        "id": "ad-ldap-enum",
        "title": "AD — LDAP Enumeration",
        "description": "Enumerate AD users, groups, computers and password policy via NetExec LDAP. Requires domain credentials in the run form.",
        "editable": False,
        "steps": [
            {
                "title": "NetExec LDAP — users/groups/computers",
                "connector_key": "netexec", "operation": "scan",
                "params": {"protocol": "ldap", "extra_flags": "--users --groups --computers --password-not-required --admin-count --trusted-for-delegation"},
                "on_success": "next", "on_failure": "stop",
            },
        ],
    },
    "ad-spray-smb": {
        "id": "ad-spray-smb",
        "title": "AD — SMB Password Spray",
        "description": "Spray a single username:password pair across SMB hosts. Set credentials in the run form. Uses --continue-on-success so the scan keeps going after first hit.",
        "editable": False,
        "steps": [
            {
                "title": "NetExec SMB spray",
                "connector_key": "netexec", "operation": "scan",
                "params": {"protocol": "smb", "extra_flags": "--continue-on-success --no-bruteforce"},
                "on_success": "next", "on_failure": "stop",
            },
        ],
    },
    "ad-kerberoast": {
        "id": "ad-kerberoast",
        "title": "AD — Kerberoast",
        "description": "Request TGS tickets for all SPN accounts via impacket-GetUserSPNs. Tickets saved to /tmp on the attacker box for offline cracking. Set domain/username/password in the run form.",
        "editable": False,
        "steps": [
            {
                "title": "Kerberoast — GetUserSPNs",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {target} -request -outputfile /tmp/kerberoast_{target}.txt 2>&1 && echo 'DONE'",
                    "timeout_seconds": 120, "activity_type": "kerberoast", "execution_mode": "auto",
                },
                "on_success": "stop", "on_failure": "stop",
            },
        ],
    },
    "ad-asreproast": {
        "id": "ad-asreproast",
        "title": "AD — AS-REP Roast",
        "description": "Find accounts without Kerberos pre-auth and capture AS-REP hashes. Requires a users list at /tmp/users.txt on the attacker box. Set domain in the run form.",
        "editable": False,
        "steps": [
            {
                "title": "AS-REP Roast — GetNPUsers",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "impacket-GetNPUsers '{domain}/' -dc-ip {target} -no-pass -usersfile /tmp/users.txt -outputfile /tmp/asrep_{target}.txt 2>&1 && echo 'DONE'",
                    "timeout_seconds": 90, "activity_type": "asreproast", "execution_mode": "auto",
                },
                "on_success": "stop", "on_failure": "stop",
            },
        ],
    },
    "ad-full-recon": {
        "id": "ad-full-recon",
        "title": "AD — Full DC Recon",
        "description": "Full Domain Controller reconnaissance: port scan → LDAP enum (users/groups/computers/policy) → Kerberoast → topology refresh. Set target (DC IP) and credentials in the run form.",
        "editable": False,
        "steps": [
            {
                "title": "Nmap — DC port scan",
                "connector_key": "nmap", "operation": "scan",
                "params": {"flags": "-p 88,135,139,389,445,464,636,3268,3269 -sV --open"},
                "on_success": "next", "on_failure": "next",
            },
            {
                "title": "NetExec LDAP — users/groups/computers",
                "connector_key": "netexec", "operation": "scan",
                "params": {"protocol": "ldap", "extra_flags": "--users --groups --computers --password-not-required --admin-count"},
                "on_success": "next", "on_failure": "next",
            },
            {
                "title": "Kerberoast — GetUserSPNs",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {target} -request -outputfile /tmp/kerberoast_{target}.txt 2>&1 && echo 'DONE'",
                    "timeout_seconds": 120, "activity_type": "kerberoast", "execution_mode": "auto",
                },
                "on_success": "next", "on_failure": "next",
            },
            {
                "title": "Topology auto-build",
                "connector_key": "topology", "operation": "auto_build",
                "params": {},
                "on_success": "stop", "on_failure": "stop",
            },
        ],
    },
    # ── New AD playbooks (P6) ─────────────────────────────────────────────────
    "ad-spn-enum": {
        "id": "ad-spn-enum",
        "title": "AD — SPN Discovery",
        "description": "List all Kerberoastable SPN accounts without requesting tickets. Quick recon step before deciding to Kerberoast.",
        "editable": False,
        "steps": [
            {
                "title": "GetUserSPNs — list only",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {target} 2>&1",
                    "timeout_seconds": 60, "activity_type": "recon", "execution_mode": "auto",
                },
                "on_success": "stop", "on_failure": "stop",
            },
        ],
    },
    "ad-delegation-enum": {
        "id": "ad-delegation-enum",
        "title": "AD — Delegation Enumeration",
        "description": "Find accounts and computers with unconstrained or constrained Kerberos delegation configured.",
        "editable": False,
        "steps": [
            {
                "title": "findDelegation — unconstrained/constrained",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "impacket-findDelegation '{domain}/{username}:{password}' -dc-ip {target} 2>&1",
                    "timeout_seconds": 60, "activity_type": "recon", "execution_mode": "auto",
                },
                "on_success": "stop", "on_failure": "stop",
            },
        ],
    },
    "ad-adcs-enum": {
        "id": "ad-adcs-enum",
        "title": "AD — ADCS Vulnerability Check",
        "description": "Enumerate Certificate Services templates for misconfigurations (ESC1–ESC8). Runs certipy-ad find against the DC.",
        "editable": False,
        "steps": [
            {
                "title": "certipy-ad find — ESC1-ESC8",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "certipy-ad find -u '{username}@{domain}' -p '{password}' -dc-ip {target} -stdout -vulnerable 2>&1",
                    "timeout_seconds": 120, "activity_type": "recon", "execution_mode": "auto",
                },
                "on_success": "stop", "on_failure": "stop",
            },
        ],
    },
    "ad-spray-winrm": {
        "id": "ad-spray-winrm",
        "title": "AD — WinRM Spray",
        "description": "Spray credentials via WinRM across all targets. Identifies hosts where the credential grants remote shell access (Pwn3d! = local admin).",
        "editable": False,
        "steps": [
            {
                "title": "NetExec WinRM spray",
                "connector_key": "netexec", "operation": "scan",
                "params": {"protocol": "winrm", "extra_flags": "--continue-on-success --no-bruteforce"},
                "on_success": "stop", "on_failure": "stop",
            },
        ],
    },
    "ad-bloodhound": {
        "id": "ad-bloodhound",
        "title": "AD — BloodHound Collection",
        "description": "Collect full BloodHound data via bloodhound-python (All collectors). Saves a ZIP to /tmp/bh_{target}/ on the attacker box.",
        "editable": False,
        "steps": [
            {
                "title": "bloodhound-python — All collectors",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "mkdir -p /tmp/bh_{target} && bloodhound-python -u '{username}' -p '{password}' -d '{domain}' -ns {target} -c All --zip -o /tmp/bh_{target}/ 2>&1 && echo 'DONE'",
                    "timeout_seconds": 300, "activity_type": "recon", "execution_mode": "auto",
                },
                "on_success": "stop", "on_failure": "stop",
            },
        ],
    },
    "ad-full-enum": {
        "id": "ad-full-enum",
        "title": "AD — Full Enumeration Chain",
        "description": "Comprehensive AD enumeration: port scan → LDAP users/groups → SPN list → Kerberoast → delegation check → ADCS → topology refresh.",
        "editable": False,
        "steps": [
            {
                "title": "Nmap — DC port scan",
                "connector_key": "nmap", "operation": "scan",
                "params": {"flags": "-p 53,88,135,139,389,443,445,464,636,3268,3269,5985 -sV --open"},
                "on_success": "next", "on_failure": "next",
            },
            {
                "title": "NetExec LDAP — users/groups/computers/policy",
                "connector_key": "netexec", "operation": "scan",
                "params": {"protocol": "ldap", "extra_flags": "--users --groups --computers --password-not-required --admin-count --trusted-for-delegation --pass-pol"},
                "on_success": "next", "on_failure": "next",
            },
            {
                "title": "NetExec LDAP — ADCS check",
                "connector_key": "netexec", "operation": "scan",
                "params": {"protocol": "ldap", "extra_flags": "--adcs"},
                "on_success": "next", "on_failure": "next",
            },
            {
                "title": "SPN discovery — Kerberoastable accounts",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {target} 2>&1",
                    "timeout_seconds": 60, "activity_type": "recon", "execution_mode": "auto",
                },
                "on_success": "next", "on_failure": "next",
            },
            {
                "title": "Kerberoast — request TGS tickets",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {target} -request -outputfile /tmp/kerberoast_{target}.txt 2>&1 && echo 'DONE'",
                    "timeout_seconds": 120, "activity_type": "kerberoast", "execution_mode": "auto",
                },
                "on_success": "next", "on_failure": "next",
            },
            {
                "title": "Delegation enumeration",
                "connector_key": "attacker_ssh", "operation": "exec",
                "params": {
                    "command": "impacket-findDelegation '{domain}/{username}:{password}' -dc-ip {target} 2>&1",
                    "timeout_seconds": 60, "activity_type": "recon", "execution_mode": "auto",
                },
                "on_success": "next", "on_failure": "next",
            },
            {
                "title": "Topology refresh",
                "connector_key": "topology", "operation": "auto_build",
                "params": {},
                "on_success": "stop", "on_failure": "stop",
            },
        ],
    },
}


def _resolve_next_step_index(step: dict, *, success: bool, current_idx: int, total_steps: int) -> int | None:
    action = _normalize_branch_action(step.get("on_success") if success else step.get("on_failure"), success=success)
    target = step.get("on_success_step") if success else step.get("on_failure_step")
    if action == "stop":
        return None
    if action == "jump":
        if isinstance(target, int) and 1 <= target <= total_steps:
            return target - 1
        return None
    next_idx = current_idx + 1
    return next_idx if next_idx < total_steps else None


def _playbook_run_dict(run: models.PlaybookRun) -> dict:
    return {
        "id": run.id,
        "pid": run.pid,
        "playbook_id": run.playbook_id,
        "title": run.title,
        "status": run.status,
        "created_by": run.created_by,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "target": run.target,
        "error_output": run.error_output,
        "jobs_json": run.jobs_json or [],
        "request_json": run.request_json or {},
        "result_json": run.result_json or {},
    }


_ROLLUP_KEYS = [
    "hosts_found", "hosts_created", "hosts_updated", "hosts_pwned", "hosts_valid",
    "hosts_failed", "hosts_success", "findings_created", "findings_found",
    "creds_created", "paths_found", "urls_found",
]


def _aggregate_run_results(db: Session, job_ids: list[str]) -> dict:
    totals: dict[str, int] = {}
    for jid in job_ids:
        job = db.query(models.Job).filter(models.Job.id == jid).first()
        if not job or not job.result_json:
            continue
        rj = job.result_json or {}
        for key in _ROLLUP_KEYS:
            val = rj.get(key) or (rj.get("structured", {}) or {}).get("counts", {}).get(key)
            if isinstance(val, (int, float)) and val > 0:
                totals[key] = totals.get(key, 0) + int(val)
    return totals


def _update_run(db: Session, run: models.PlaybookRun, **updates) -> models.PlaybookRun:
    for key, value in updates.items():
        setattr(run, key, value)
    db.commit()
    db.refresh(run)
    bcast(run.pid, "playbook_run", "update", _playbook_run_dict(run))
    # Notify on terminal status
    new_status = updates.get("status")
    if new_status in ("done", "failed", "cancelled"):
        from ..core.notifications import dispatch_sync
        batch_id = (run.request_json or {}).get("batch_id")
        event = "playbook_done" if not batch_id else "batch_done"
        icon = "✅" if new_status == "done" else ("❌" if new_status == "failed" else "⏹")
        title = f"{icon} {'Batch' if batch_id else 'Playbook'} run {new_status}: {run.title}"
        result = run.result_json or {}
        parts = [f"Target: {run.target}" if run.target else None,
                 f"Steps: {result.get('job_count', len(run.jobs_json or []))}" ,
                 f"Batch: {batch_id}" if batch_id else None]
        body = "\n".join(p for p in parts if p)
        dispatch_sync(db, event, title, body, {"run_id": run.id, "pid": run.pid})
    return run


def _serialize_builtin(playbook: dict) -> dict:
    return {
        "id": playbook["id"],
        "title": playbook["title"],
        "description": playbook.get("description", ""),
        "editable": False,
        "source": "builtin",
        "steps": playbook.get("steps", []),
    }


def _serialize_custom(playbook: models.CustomPlaybook) -> dict:
    return {
        "id": playbook.id,
        "title": playbook.title,
        "description": playbook.description,
        "editable": True,
        "source": "custom",
        "created_by": playbook.created_by,
        "created_at": playbook.created_at,
        "updated_at": playbook.updated_at,
        "steps": playbook.steps_json or [],
    }


def _resolve_playbook(db: Session, playbook_id: str) -> dict | None:
    builtin = BUILTIN_PLAYBOOKS.get(playbook_id)
    if builtin:
        return _serialize_builtin(builtin)
    custom = db.query(models.CustomPlaybook).filter(models.CustomPlaybook.id == playbook_id).first()
    if custom:
        return _serialize_custom(custom)
    return None


def _substitute_run_vars(command: str, body: PlaybookRunBody) -> str:
    """Replace {target}/{domain}/{username}/{password}/{hash} placeholders in commands."""
    subs = {
        "{target}": body.target or "",
        "{domain}": body.domain or "",
        "{username}": body.username or "",
        "{password}": body.password or "",
        "{hash}": body.hash or "",
    }
    for k, v in subs.items():
        command = command.replace(k, v)
    return command


def _job_spec_for_step(pid: str, step: dict, body: PlaybookRunBody, created_by: str) -> dict:
    connector_key = step.get("connector_key")
    operation = step.get("operation")
    params = dict(step.get("params") or {})
    title = step.get("title") or f"{connector_key}:{operation}"

    if connector_key == "topology":
        if operation not in {"auto_build", "rebuild_layout"}:
            raise HTTPException(400, f"Unsupported topology operation: {operation}")
        return {
            "job_type": "topology",
            "title": title,
            "connector_key": "topology",
            "operation": operation,
            "related_entity_type": "network",
            "related_entity_id": pid,
            "request_json": {
                "keep_manual_positions": params.get("keep_manual_positions", body.keep_manual_positions),
                "create_missing_networks": params.get("create_missing_networks", body.create_missing_networks),
            },
            "created_by": created_by,
        }

    if connector_key == "nmap" and operation == "scan":
        target = (params.get("target") or body.target or "").strip()
        if not target:
            raise HTTPException(400, "This playbook step requires target")
        flags = params.get("flags") or body.flags
        target_id = params.get("target_id") or body.target_id
        timeout_seconds = int(params.get("timeout_seconds") or 180)
        return {
            "job_type": "nmap",
            "title": f"{title}: {target}",
            "target": target,
            "command": f"nmap {flags} -oX - {target} 2>/dev/null",
            "connector_key": "nmap",
            "operation": "scan",
            "related_entity_type": "project",
            "related_entity_id": pid,
            "request_json": {"target": target, "flags": flags, "target_id": target_id, "timeout_seconds": timeout_seconds},
            "created_by": created_by,
        }

    if connector_key == "nuclei" and operation == "scan":
        target_url = (params.get("target_url") or body.target_url or "").strip()
        if not target_url:
            raise HTTPException(400, "This playbook step requires target_url")
        severity = params.get("severity") or body.severity
        target_id = params.get("target_id") or body.target_id
        timeout_seconds = int(params.get("timeout_seconds") or 300)
        templates = params.get("templates") or ""
        extra_flags = params.get("extra_flags") or ""
        return {
            "job_type": "nuclei",
            "title": f"{title}: {target_url}",
            "target": target_url,
            "command": f"nuclei -u {target_url} -severity {severity} -jsonl {extra_flags} 2>/dev/null",
            "connector_key": "nuclei",
            "operation": "scan",
            "related_entity_type": "project",
            "related_entity_id": pid,
            "request_json": {"target": target_url, "severity": severity, "target_id": target_id, "timeout_seconds": timeout_seconds, "templates": templates, "extra_flags": extra_flags},
            "created_by": created_by,
        }

    if connector_key == "netexec" and operation == "scan":
        target = (params.get("target") or body.target or "").strip()
        if not target:
            raise HTTPException(400, "This playbook step requires target")
        protocol = params.get("protocol") or "smb"
        extra_flags = params.get("extra_flags") or "--users --groups"
        timeout_seconds = int(params.get("timeout_seconds") or 120)
        # Step params take priority; fall back to run-form auth fields
        username = params.get("username") or body.username or ""
        password = params.get("password") or body.password or ""
        domain = params.get("domain") or body.domain or ""
        hash_ = params.get("hash") or body.hash or ""
        return {
            "job_type": "cme",
            "title": f"{title}: {target}",
            "target": target,
            "command": f"nxc {protocol} {target} {extra_flags} 2>/dev/null",
            "connector_key": "netexec",
            "operation": "scan",
            "related_entity_type": "project",
            "related_entity_id": pid,
            "request_json": {
                "target": target,
                "protocol": protocol,
                "extra_flags": extra_flags,
                "target_id": params.get("target_id") or body.target_id,
                "timeout_seconds": timeout_seconds,
                "username": username,
                "password": password,
                "domain": domain,
                "hash": hash_,
            },
            "created_by": created_by,
        }

    if connector_key == "attacker_ssh" and operation == "exec":
        raw_command = (params.get("command") or "").strip()
        if not raw_command:
            raise HTTPException(400, "This playbook step requires command")
        command = _substitute_run_vars(raw_command, body)
        return {
            "job_type": "exec",
            "title": title,
            "target": params.get("target") or body.target or "",
            "command": command,
            "connector_key": "attacker_ssh",
            "operation": "exec",
            "related_entity_type": params.get("related_entity_type") or "project",
            "related_entity_id": params.get("related_entity_id") or pid,
            "request_json": {
                "command": command,
                "snippet_title": title,
                "host_id": params.get("host_id"),
                "cred_id": params.get("cred_id"),
                "target_id": params.get("target_id") or body.target_id,
                "execution_mode": params.get("execution_mode") or "auto",
                "timeout_seconds": int(params.get("timeout_seconds") or 45),
                "activity_type": params.get("activity_type") or "postex",
            },
            "created_by": created_by,
        }

    if connector_key == "httpx" and operation == "scan":
        target = (params.get("target") or body.target or "").strip()
        if not target:
            raise HTTPException(400, "This playbook step requires target")
        flags = params.get("flags") or "-title -status-code -tech-detect -follow-redirects"
        timeout_seconds = int(params.get("timeout_seconds") or 120)
        return {
            "job_type": "httpx",
            "title": f"{title}: {target}",
            "target": target,
            "command": f"httpx -u '{target}' {flags} -json -silent 2>/dev/null",
            "connector_key": "httpx",
            "operation": "scan",
            "related_entity_type": "project",
            "related_entity_id": pid,
            "request_json": {"target": target, "flags": flags, "target_id": params.get("target_id") or body.target_id, "timeout_seconds": timeout_seconds},
            "created_by": created_by,
        }

    if connector_key == "ffuf" and operation == "scan":
        target_url = (params.get("target_url") or body.target_url or "").strip()
        if not target_url:
            raise HTTPException(400, "This playbook step requires target_url")
        wordlist = params.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        extensions = params.get("extensions") or ""
        flags = params.get("flags") or "-mc 200,204,301,302,307,401,403,405"
        timeout_seconds = int(params.get("timeout_seconds") or 300)
        ext_flag = f"-e {extensions}" if extensions.strip() else ""
        url = f"{target_url}/FUZZ"
        cmd = f"ffuf -u '{url}' -w '{wordlist}' {ext_flag} {flags} -o /tmp/ffuf_out.json -of json -s 2>/dev/null && cat /tmp/ffuf_out.json"
        return {
            "job_type": "ffuf",
            "title": f"{title}: {target_url}",
            "target": target_url,
            "command": cmd,
            "connector_key": "ffuf",
            "operation": "scan",
            "related_entity_type": "project",
            "related_entity_id": pid,
            "request_json": {"target_url": target_url, "wordlist": wordlist, "extensions": extensions, "flags": flags, "target_id": params.get("target_id") or body.target_id, "timeout_seconds": timeout_seconds},
            "created_by": created_by,
        }

    raise HTTPException(400, f"Unsupported playbook step: {connector_key}:{operation}")


def _upsert_run_job_state(db: Session, run_id: str, job_id: str, status: str) -> None:
    run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
    if not run:
        return
    jobs_json = list(run.jobs_json or [])
    changed = False
    for item in jobs_json:
        if item.get("id") == job_id:
            item["status"] = status
            changed = True
            break
    if changed:
        _update_run(db, run, jobs_json=jobs_json)


async def _wait_for_job(job_id: str, run_id: str | None = None) -> dict:
    while True:
        await asyncio.sleep(1)
        db = SessionLocal()
        try:
            job = db.query(models.Job).filter(models.Job.id == job_id).first()
            if not job:
                return {"status": "missing"}
            if run_id:
                _upsert_run_job_state(db, run_id, job_id, job.status)
            if job.status in ("done", "failed", "cancelled"):
                return {"status": job.status, "id": job.id}
        finally:
            db.close()


async def _run_sequence(run_id: str, job_ids: list[str], steps: list[dict]) -> None:
    db = SessionLocal()
    try:
        run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
        if not run:
            return
        _update_run(db, run, status="running", started_at=run.started_at or _now())
    finally:
        db.close()

    completed = []
    failed = []
    total_steps = len(job_ids)
    idx = 0
    while idx < total_steps:
        job_id = job_ids[idx]
        step = steps[idx] if idx < len(steps) else {}
        db = SessionLocal()
        run_pid = ""
        try:
            run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
            if not run or run.status == "cancelled":
                return
            run_pid = run.pid
        finally:
            db.close()

        schedule_job_run(job_id, pid=run_pid)
        result = await _wait_for_job(job_id, run_id)
        completed.append(result)
        condition_idx, condition_stop = _resolve_result_condition_target(step, result or {}, status=result.get("status"), total_steps=total_steps)
        if condition_stop:
            db = SessionLocal()
            try:
                run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
                if run and run.status != "cancelled":
                    terminal = "done" if result.get("status") == "done" else ("cancelled" if result.get("status") == "cancelled" else "failed")
                    _update_run(
                        db,
                        run,
                        status=terminal,
                        finished_at=_now(),
                        result_json={"completed_jobs": [item.get("id") for item in completed], "failed_jobs": [item.get("id") for item in failed], "job_count": len(completed), "condition_stop": True, "rollup": _aggregate_run_results(db, [i.get("id") for i in completed if i.get("id")])},
                    )
            finally:
                db.close()
            return
        if condition_idx is not None:
            idx = condition_idx
            continue
        if result.get("status") != "done":
            failed.append(result)
            next_idx = _resolve_next_step_index(step, success=False, current_idx=idx, total_steps=total_steps)
            if next_idx is not None:
                idx = next_idx
                continue
            db = SessionLocal()
            try:
                run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
                if run and run.status != "cancelled":
                    terminal = "cancelled" if result.get("status") == "cancelled" else "failed"
                    _update_run(
                        db,
                        run,
                        status=terminal,
                        finished_at=_now(),
                        error_output=f"Step job {job_id} ended with status {result.get('status')}",
                        result_json={"completed_jobs": [item.get("id") for item in completed], "failed_jobs": [item.get("id") for item in failed], "failed_job_id": job_id, "rollup": _aggregate_run_results(db, [i.get("id") for i in completed if i.get("id")])},
                    )
            finally:
                db.close()
            break
        next_idx = _resolve_next_step_index(step, success=True, current_idx=idx, total_steps=total_steps)
        if next_idx is None:
            db = SessionLocal()
            try:
                run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
                if run and run.status != "cancelled":
                    _update_run(
                        db,
                        run,
                        status="done",
                        finished_at=_now(),
                        result_json={"completed_jobs": [item.get("id") for item in completed], "failed_jobs": [item.get("id") for item in failed], "job_count": len(completed), "rollup": _aggregate_run_results(db, [i.get("id") for i in completed if i.get("id")])},
                    )
            finally:
                db.close()
            return
        idx = next_idx


def _create_run_record(db: Session, pid: str, playbook: dict, body: PlaybookRunBody, created_by: str, jobs: list[models.Job]) -> models.PlaybookRun:
    run = models.PlaybookRun(
        id=f"pbr_{uuid4().hex[:10]}",
        pid=pid,
        playbook_id=playbook["id"],
        title=playbook["title"],
        status="queued",
        created_by=created_by,
        created_at=_now(),
        started_at="",
        finished_at="",
        target=body.target.strip() or body.target_url.strip(),
        error_output="",
        jobs_json=[{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
        request_json=body.model_dump(),
        result_json={},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
    return run


def _queue_playbook_jobs(db: Session, pid: str, playbook: dict, body: PlaybookRunBody, created_by: str, run_id: str | None = None) -> list[models.Job]:
    jobs = []
    for step in playbook.get("steps", []):
        spec = _job_spec_for_step(pid, step, body, created_by)
        jobs.append(queue_job(
            db,
            pid,
            spec["job_type"],
            spec["title"],
            target=spec.get("target", ""),
            command=spec.get("command", ""),
            created_by=spec.get("created_by", ""),
            connector_key=spec["connector_key"],
            operation=spec["operation"],
            related_entity_type=spec.get("related_entity_type", "project"),
            related_entity_id=spec.get("related_entity_id", pid),
            request_json={**spec.get("request_json", {}), "playbook_id": playbook["id"], **({"playbook_run_id": run_id} if run_id else {})},
        ))
    return jobs


@router.get("/api/playbooks")
def list_playbooks(db: Session = Depends(get_db)):
    builtin = [_serialize_builtin(item) for item in BUILTIN_PLAYBOOKS.values()]
    custom = [_serialize_custom(item) for item in db.query(models.CustomPlaybook).order_by(models.CustomPlaybook.updated_at.desc()).all()]
    return {"playbooks": builtin + custom}


@router.get("/api/playbooks/step-templates")
def list_step_templates():
    return {"templates": list(STEP_TEMPLATES.values())}


@router.post("/api/playbooks/validate")
def validate_playbook(body: PlaybookBody):
    return _validate_playbook_payload(body, registry.list_connectors())


@router.post("/api/playbooks/custom", status_code=201)
def create_custom_playbook(body: PlaybookBody, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    validation = _validate_playbook_payload(body, registry.list_connectors())
    if not validation["ok"]:
        raise HTTPException(400, {"errors": validation["errors"], "warnings": validation["warnings"]})
    ts = _now()
    normalized = validation["normalized"]
    playbook = models.CustomPlaybook(
        id=new_id("pb"),
        title=normalized["title"],
        description=normalized["description"],
        steps_json=normalized["steps"],
        created_by=getattr(user, "username", "") or "",
        created_at=ts,
        updated_at=ts,
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return _serialize_custom(playbook)


@router.patch("/api/playbooks/custom/{playbook_id}")
def update_custom_playbook(playbook_id: str, body: PlaybookBody, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    playbook = db.query(models.CustomPlaybook).filter(models.CustomPlaybook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(404, "Custom playbook not found")
    validation = _validate_playbook_payload(body, registry.list_connectors())
    if not validation["ok"]:
        raise HTTPException(400, {"errors": validation["errors"], "warnings": validation["warnings"]})
    normalized = validation["normalized"]
    playbook.title = normalized["title"]
    playbook.description = normalized["description"]
    playbook.steps_json = normalized["steps"]
    playbook.updated_at = _now()
    db.commit()
    db.refresh(playbook)
    return _serialize_custom(playbook)


@router.delete("/api/playbooks/custom/{playbook_id}", status_code=204)
def delete_custom_playbook(playbook_id: str, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    playbook = db.query(models.CustomPlaybook).filter(models.CustomPlaybook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(404, "Custom playbook not found")
    db.delete(playbook)
    db.commit()


@router.get("/api/projects/{pid}/playbook-runs")
def list_playbook_runs(
    pid: str,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.read")
    runs = db.query(models.PlaybookRun).filter(models.PlaybookRun.pid == pid).order_by(models.PlaybookRun.created_at.desc()).limit(limit).all()
    return {"runs": [_playbook_run_dict(run) for run in runs]}


@router.get("/api/projects/{pid}/playbook-runs/{run_id}")
def get_playbook_run(
    pid: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.read")
    run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id, models.PlaybookRun.pid == pid).first()
    if not run:
        raise HTTPException(404, "Playbook run not found")
    return _playbook_run_dict(run)


@router.post("/api/projects/{pid}/playbooks/{playbook_id}/run", status_code=201)
async def run_playbook(
    pid: str,
    playbook_id: str,
    body: PlaybookRunBody,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    playbook = _resolve_playbook(db, playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")
    created_by = getattr(user, "username", "") or ""
    provisional_run_id = f"pbr_{uuid4().hex[:10]}"
    jobs = _queue_playbook_jobs(db, pid, playbook, body, created_by, provisional_run_id)
    run = models.PlaybookRun(
        id=provisional_run_id,
        pid=pid,
        playbook_id=playbook["id"],
        title=playbook["title"],
        status="queued",
        created_by=created_by,
        created_at=_now(),
        started_at="",
        finished_at="",
        target=body.target.strip() or body.target_url.strip(),
        error_output="",
        jobs_json=[{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
        request_json=body.model_dump(),
        result_json={},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
    asyncio.create_task(_run_sequence(run.id, [job.id for job in jobs], playbook.get("steps", [])))
    return {
        "ok": True,
        "playbook_run": _playbook_run_dict(run),
        "playbook": {"id": playbook["id"], "title": playbook["title"]},
        "jobs": [{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
    }


def _resolve_batch_hosts(db: Session, pid: str, body: BatchRunBody) -> list:
    q = db.query(models.Host).filter(models.Host.pid == pid, models.Host.is_attacker == False)
    if body.host_ids:
        q = q.filter(models.Host.id.in_(body.host_ids))
    else:
        if body.host_tags:
            # PostgreSQL ARRAY overlap: host must have at least one matching tag
            q = q.filter(models.Host.tags.overlap(body.host_tags))
        if body.host_status:
            q = q.filter(models.Host.status == body.host_status)
    return q.all()


@router.post("/api/projects/{pid}/playbooks/{playbook_id}/batch-run", status_code=201)
async def batch_run_playbook(
    pid: str,
    playbook_id: str,
    body: BatchRunBody,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """Fan-out: run one playbook against a filtered set of hosts. Each host gets its own PlaybookRun.

    The host's IP is injected as `target` for every run, so any step that uses
    `body.target` (nmap, netexec, attacker_ssh command {target} placeholder) will
    automatically get the right target per host.
    """
    check_pid_access(db, pid, user, "command_outputs.create")
    playbook = _resolve_playbook(db, playbook_id)
    if not playbook:
        raise HTTPException(404, "Playbook not found")

    hosts = _resolve_batch_hosts(db, pid, body)
    if not hosts:
        raise HTTPException(400, "No matching hosts found for the given filter")

    batch_id = f"batch_{uuid4().hex[:10]}"
    created_by = getattr(user, "username", "") or ""
    parallelism = max(1, min(body.parallelism, 10))

    runs_and_jobs: list[tuple[models.PlaybookRun, list[models.Job]]] = []
    for host in hosts:
        run_body = PlaybookRunBody(
            target=host.ip or "",
            target_url=body.target_url,
            flags=body.flags,
            severity=body.severity,
            keep_manual_positions=body.keep_manual_positions,
            create_missing_networks=body.create_missing_networks,
            username=body.username,
            password=body.password,
            domain=body.domain,
            hash=body.hash,
        )
        new_run_id = f"pbr_{uuid4().hex[:10]}"
        jobs = _queue_playbook_jobs(db, pid, playbook, run_body, created_by, new_run_id)
        run = models.PlaybookRun(
            id=new_run_id,
            pid=pid,
            playbook_id=playbook["id"],
            title=f"{playbook['title']} — {host.ip}",
            status="queued",
            created_by=created_by,
            created_at=_now(),
            started_at="",
            finished_at="",
            target=host.ip or "",
            error_output="",
            jobs_json=[{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
            request_json={**run_body.model_dump(), "batch_id": batch_id, "host_id": host.id},
            result_json={},
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
        runs_and_jobs.append((run, jobs))

    sem = asyncio.Semaphore(parallelism)

    async def _run_with_sem(run: models.PlaybookRun, job_ids: list[str], steps: list[dict]) -> None:
        async with sem:
            await _run_sequence(run.id, job_ids, steps)

    for run, jobs in runs_and_jobs:
        asyncio.create_task(_run_with_sem(run, [j.id for j in jobs], playbook.get("steps", [])))

    return {
        "ok": True,
        "batch_id": batch_id,
        "total": len(runs_and_jobs),
        "runs": [_playbook_run_dict(r) for r, _ in runs_and_jobs],
    }


@router.post("/api/projects/{pid}/playbook-runs/{run_id}/cancel")
def cancel_playbook_run(
    pid: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id, models.PlaybookRun.pid == pid).first()
    if not run:
        raise HTTPException(404, "Playbook run not found")
    if run.status in ("done", "failed", "cancelled"):
        raise HTTPException(400, "Playbook run is already in a terminal state")
    jobs_json = list(run.jobs_json or [])
    active_ids = [item.get("id") for item in jobs_json if item.get("status") in ("queued", "running")]
    for job_id in active_ids:
        job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
        if job and job.status in ("queued", "running"):
            job.status = "cancelled"
    for item in jobs_json:
        if item.get("status") in ("queued", "running"):
            item["status"] = "cancelled"
    _update_run(db, run, status="cancelled", finished_at=_now(), error_output="Cancelled by user", jobs_json=jobs_json, result_json={"cancelled_jobs": active_ids})
    return _playbook_run_dict(run)


@router.post("/api/projects/{pid}/playbook-runs/{run_id}/rerun", status_code=201)
async def rerun_playbook_run(
    pid: str,
    run_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "command_outputs.create")
    run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id, models.PlaybookRun.pid == pid).first()
    if not run:
        raise HTTPException(404, "Playbook run not found")
    playbook = _resolve_playbook(db, run.playbook_id)
    if not playbook:
        raise HTTPException(404, "Source playbook not found")
    body = PlaybookRunBody(**(run.request_json or {}))
    created_by = getattr(user, "username", "") or ""
    new_run_id = f"pbr_{uuid4().hex[:10]}"
    jobs = _queue_playbook_jobs(db, pid, playbook, body, created_by, new_run_id)
    rerun = models.PlaybookRun(
        id=new_run_id,
        pid=pid,
        playbook_id=playbook["id"],
        title=playbook["title"],
        status="queued",
        created_by=created_by,
        created_at=_now(),
        started_at="",
        finished_at="",
        target=body.target.strip() or body.target_url.strip(),
        error_output="",
        jobs_json=[{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
        request_json=body.model_dump(),
        result_json={"rerun_of": run.id},
    )
    db.add(rerun)
    db.commit()
    db.refresh(rerun)
    bcast(pid, "playbook_run", "create", _playbook_run_dict(rerun))
    asyncio.create_task(_run_sequence(rerun.id, [job.id for job in jobs], playbook.get("steps", [])))
    return {"ok": True, "playbook_run": _playbook_run_dict(rerun)}


async def _launch_playbook_run(pid: str, playbook_id: str, body_dict: dict, created_by: str = "scheduler") -> str | None:
    """
    Launch a playbook run without an HTTP request context.
    Used by the cron scheduler. Returns the run ID or None on failure.
    """
    from ..database import SessionLocal
    db = SessionLocal()
    try:
        playbook = _resolve_playbook(db, playbook_id)
        if not playbook:
            return None
        body = PlaybookRunBody(**{k: v for k, v in body_dict.items() if k in PlaybookRunBody.model_fields})
        provisional_run_id = f"pbr_{uuid4().hex[:10]}"
        jobs = _queue_playbook_jobs(db, pid, playbook, body, created_by, provisional_run_id)
        run = models.PlaybookRun(
            id=provisional_run_id,
            pid=pid,
            playbook_id=playbook["id"],
            title=playbook["title"],
            status="queued",
            created_by=created_by,
            created_at=_now(),
            started_at="",
            finished_at="",
            target=body.target.strip() or body.target_url.strip(),
            error_output="",
            jobs_json=[{"id": job.id, "title": job.title, "status": job.status} for job in jobs],
            request_json=body_dict,
            result_json={},
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        bcast(pid, "playbook_run", "create", _playbook_run_dict(run))
        asyncio.create_task(_run_sequence(run.id, [job.id for job in jobs], playbook.get("steps", [])))
        return run.id
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("[scheduler] _launch_playbook_run failed: %s", e)
        return None
    finally:
        db.close()


# ── Custom playbook export / import ──────────────────────────────────────────

@router.get("/api/playbooks/custom/export")
def export_custom_playbooks(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    items = db.query(models.CustomPlaybook).order_by(models.CustomPlaybook.title).all()
    data = [
        {"title": p.title, "description": p.description, "steps": p.steps_json or []}
        for p in items
    ]
    payload = json.dumps({"format": "rootnotes-playbooks", "version": "1", "playbooks": data}, ensure_ascii=False, indent=2).encode()
    return StreamingResponse(io.BytesIO(payload), media_type="application/json",
                             headers={"Content-Disposition": 'attachment; filename="custom_playbooks.json"'})


@router.post("/api/playbooks/custom/import", status_code=201)
async def import_custom_playbooks(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    raw = json.loads((await file.read()).decode())
    items = raw if isinstance(raw, list) else raw.get("playbooks", [])
    now = ts_now()
    created = skipped = 0
    existing_titles = {p.title.strip().lower() for p in db.query(models.CustomPlaybook).all()}
    for item in items:
        title = (item.get("title") or "").strip()
        if not title or title.lower() in existing_titles:
            skipped += 1
            continue
        db.add(models.CustomPlaybook(
            id=f"pbk_{uuid4().hex[:10]}",
            title=title,
            description=item.get("description", ""),
            steps_json=item.get("steps", []),
            created_by=user.username,
            created_at=now,
            updated_at=now,
        ))
        existing_titles.add(title.lower())
        created += 1
    db.commit()
    return {"created": created, "skipped": skipped}


# ── Operation Packs ───────────────────────────────────────────────────────────

_BUILTIN_PACKS = [
    {
        "id": "pack_builtin_initial_recon",
        "name": "Initial Recon",
        "description": "Fast host discovery + port scan + service version detection",
        "tags": ["recon", "nmap"],
        "steps": [
            {"title": "Ping sweep", "connector_key": "nmap", "operation": "ping_sweep",
             "params": {"target": "{target}"}, "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "Port scan (top 1000)", "connector_key": "nmap", "operation": "scan",
             "params": {"target": "{target}", "flags": "-sV -sC -T4 --open --top-ports 1000"},
             "on_success": "next", "on_failure": "stop",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "UDP top ports", "connector_key": "nmap", "operation": "scan",
             "params": {"target": "{target}", "flags": "-sU --top-ports 20 -T4"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
        ],
    },
    {
        "id": "pack_builtin_web_enum",
        "name": "Web Enumeration",
        "description": "HTTP/HTTPS service detection, directory busting, tech fingerprinting",
        "tags": ["web", "enum"],
        "steps": [
            {"title": "Web port scan", "connector_key": "nmap", "operation": "scan",
             "params": {"target": "{target}", "flags": "-sV -p 80,443,8080,8443,8000,8888 -T4"},
             "on_success": "next", "on_failure": "stop",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "Nikto scan", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "nikto -h {target} 2>&1 | head -100"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "Gobuster dir", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "gobuster dir -u http://{target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 30 2>&1"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
        ],
    },
    {
        "id": "pack_builtin_ad_enum",
        "name": "AD Enumeration",
        "description": "Active Directory recon: domain info, users, SPNs, delegation",
        "tags": ["ad", "enum", "impacket"],
        "steps": [
            {"title": "Domain info (crackmapexec)", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "crackmapexec smb {target} 2>&1"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "Enumerate users (impacket)", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "impacket-GetADUsers '{domain}/{username}:{password}' -dc-ip {target} -all 2>&1"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "Kerberoasting", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "impacket-GetUserSPNs '{domain}/{username}:{password}' -dc-ip {target} -request -outputfile /tmp/kerberoast.txt 2>&1 && echo DONE"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "AS-REP Roasting", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "impacket-GetNPUsers '{domain}/' -dc-ip {target} -no-pass -usersfile /tmp/users.txt 2>&1"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
        ],
    },
    {
        "id": "pack_builtin_cred_dump",
        "name": "Credential Dump",
        "description": "Local credential harvesting: SAM, LSA, LSASS dump",
        "tags": ["creds", "post-exploitation", "impacket"],
        "steps": [
            {"title": "SAM dump (impacket)", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "impacket-secretsdump '{domain}/{username}:{password}@{target}' -just-dc-user Administrator 2>&1"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "LSA secrets", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "impacket-secretsdump '{domain}/{username}:{password}@{target}' -just-dc-ntlm 2>&1"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "DPAPI secrets", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "impacket-dpapi.py masterkey -file /path/to/masterkey -sid S-1-5-21-... 2>&1"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
        ],
    },
    {
        "id": "pack_builtin_lateral_smb",
        "name": "Lateral Movement (SMB)",
        "description": "Lateral movement via SMB: share enum, exec, pivot setup",
        "tags": ["lateral", "smb", "impacket"],
        "steps": [
            {"title": "SMB share enum", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "crackmapexec smb {target} -u '{username}' -p '{password}' --shares 2>&1"},
             "on_success": "next", "on_failure": "stop",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "Execute command (psexec)", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "impacket-psexec '{domain}/{username}:{password}@{target}' 'whoami /all' 2>&1"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
            {"title": "WMI exec", "connector_key": "ssh_exec", "operation": "exec",
             "params": {"command": "impacket-wmiexec '{domain}/{username}:{password}@{target}' 'whoami /all' 2>&1"},
             "on_success": "next", "on_failure": "continue",
             "on_success_step": None, "on_failure_step": None, "result_conditions": []},
        ],
    },
]


class OperationPackCreate(BaseModel):
    name: str
    description: str = ""
    steps: list = []
    tags: list[str] = []


@router.get("/api/playbooks/packs")
def list_operation_packs(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    custom = db.query(models.OperationPack).order_by(models.OperationPack.name).all()
    custom_out = [
        {"id": p.id, "name": p.name, "description": p.description,
         "steps": p.steps or [], "tags": p.tags or [],
         "is_builtin": False, "created_by": p.created_by, "created_at": p.created_at}
        for p in custom
    ]
    return {"packs": _BUILTIN_PACKS + custom_out}


@router.post("/api/playbooks/packs", status_code=201)
def create_operation_pack(
    body: OperationPackCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    now = ts_now()
    pack = models.OperationPack(
        id=f"pack_{uuid4().hex[:10]}",
        name=body.name,
        description=body.description,
        steps=body.steps,
        tags=body.tags,
        is_builtin=False,
        created_by=user.username,
        created_at=now,
    )
    db.add(pack)
    db.commit()
    db.refresh(pack)
    return {"id": pack.id, "name": pack.name, "description": pack.description,
            "steps": pack.steps or [], "tags": pack.tags or [],
            "is_builtin": False, "created_by": pack.created_by, "created_at": pack.created_at}


@router.delete("/api/playbooks/packs/{pack_id}", status_code=204)
def delete_operation_pack(
    pack_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    pack = db.query(models.OperationPack).filter(models.OperationPack.id == pack_id).first()
    if not pack:
        raise HTTPException(404, "Pack not found")
    db.delete(pack)
    db.commit()
