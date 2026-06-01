"""
Builds a StructuredResult from a finished job.

Called from writeback.apply_writeback() after all DB mutations are done.
Does not touch the DB — reads only from job fields.
"""

from __future__ import annotations

import re

from .result_schema import StructuredResult, finding_candidate

# ── Output pattern matchers ───────────────────────────────────────────────────

_AUTH_FAIL_RE = re.compile(
    r"permission denied|authentication failed|login failed|invalid credentials"
    r"|access denied|FAILED LOGIN|bad password|no route to host|connection refused"
    r"|connection timed out|Host key verification failed",
    re.IGNORECASE,
)
_PWNED_RE = re.compile(r"\(Pwn3d!\)", re.IGNORECASE)
_PLUS_LINE_RE = re.compile(r"^\s*\[?\+\]", re.MULTILINE)
_MINUS_LINE_RE = re.compile(r"^\s*\[?-\]", re.MULTILINE)
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
_ROOT_RE = re.compile(r"\broot\b|# $|\(root\)|SYSTEM|NT AUTHORITY.SYSTEM", re.IGNORECASE)
_SUDO_RE = re.compile(r"\bsudo\b|\bsudoers\b", re.IGNORECASE)
_SYSADMIN_RE = re.compile(r"\bsysadmin\b|\(admin\)", re.IGNORECASE)
_DA_RE = re.compile(r"domain admins|domain admin", re.IGNORECASE)
_WINRM_PROTO_RE = re.compile(r"netexec winrm|evil-winrm", re.IGNORECASE)
_MSSQL_PROTO_RE = re.compile(r"netexec mssql", re.IGNORECASE)
_LDAP_PROTO_RE = re.compile(r"netexec ldap", re.IGNORECASE)
_RDP_PROTO_RE = re.compile(r"netexec rdp", re.IGNORECASE)
_ADCS_VULN_RE = re.compile(r"ESC\d|vulnerable|Certificate Templates", re.IGNORECASE)
_DELEG_UNCONSTRAINED_RE = re.compile(r"unconstrained", re.IGNORECASE)
_DELEG_CONSTRAINED_RE = re.compile(r"constrained|msDS-AllowedToDelegateTo", re.IGNORECASE)
_SPN_RE = re.compile(r"ServicePrincipalName|SPN\s*:", re.IGNORECASE)
_BH_DONE_RE = re.compile(r"Compressing output into|Enumeration completed|DONE", re.IGNORECASE)


def _extract_adcs_templates(output: str) -> list[str]:
    templates: list[str] = []
    for line in output.splitlines():
        if "Template Name" not in line:
            continue
        _, sep, rest = line.partition(":")
        if not sep:
            continue
        value = rest.strip().split()[0] if rest.strip() else ""
        if value:
            templates.append(value)
    return templates


def normalize(job) -> StructuredResult:
    """
    Returns a StructuredResult for a finished job model object.
    job must have: connector_key, operation, status, output, error_output,
                   request_json, result_json attributes.
    """
    ck = job.connector_key or ""
    op = job.operation or ""
    status = job.status or ""
    output = (job.output or "") + "\n" + (job.error_output or "")
    req = job.request_json or {}
    res = job.result_json or {}

    r = StructuredResult(ok=(status == "done"))

    if ck == "attacker_ssh" and op in (
        "exec",
        "bulk_exec",
        "kerberoast",
        "asreproast",
        "ldap_dump",
        "spn_enum",
        "adcs_enum",
        "delegation_enum",
        "bloodhound_collect",
    ):
        r = _normalize_ssh_exec(r, req, res, output, op)
    elif ck == "netexec":
        r = _normalize_netexec(r, req, res, output, op)
    elif op == "cred_validate":
        r = _normalize_cred_validate(r, req, res)
    else:
        _normalize_scan_connectors(r, ck, op, res)

    if not r.summary and not r.ok:
        r.summary = "job failed"

    return r


# ── Scan connector normalizers ────────────────────────────────────────────────


def _normalize_scan_connectors(r: StructuredResult, ck: str, op: str, res: dict) -> None:
    if ck == "nmap" and op == "scan":
        _normalize_scan_counts(
            r,
            res,
            {
                "hosts_found": res.get("hosts_found", 0),
                "hosts_created": res.get("hosts_created", 0),
                "hosts_updated": res.get("hosts_updated", 0),
            },
        )
        r.summary = (
            f"nmap: {res.get('hosts_found', 0)} hosts found, "
            f"{res.get('hosts_created', 0)} created"
        )
    elif ck == "nuclei" and op == "scan":
        _normalize_scan_counts(
            r,
            res,
            {
                "findings_found": res.get("findings_found", 0),
                "findings_created": res.get("findings_created", 0),
            },
        )
        created = res.get("findings_created", 0)
        r.summary = f"nuclei: {created} finding{'s' if created != 1 else ''} created"
    elif ck == "httpx" and op == "scan":
        _normalize_scan_counts(
            r,
            res,
            {
                "urls_found": res.get("urls_found", 0),
                "hosts_found": res.get("hosts_found", 0),
                "activities_created": res.get("activities_created", 0),
            },
        )
        r.summary = f"httpx: {res.get('urls_found', 0)} URLs, {res.get('hosts_found', 0)} hosts"
    elif ck == "ffuf" and op == "scan":
        _normalize_scan_counts(
            r,
            res,
            {
                "paths_found": res.get("paths_found", 0),
                "findings_created": res.get("findings_created", 0),
            },
        )
        r.summary = (
            f"ffuf: {res.get('paths_found', 0)} paths, "
            f"{res.get('findings_created', 0)} findings"
        )
    elif ck.startswith("c2") and op == "sync":
        _normalize_scan_counts(
            r,
            res,
            {
                "hosts_created": res.get("hosts_created", 0),
                "creds_created": res.get("creds_created", 0),
            },
        )
        r.summary = (
            f"c2 sync: {res.get('hosts_created', 0)} hosts, {res.get('creds_created', 0)} creds"
        )
    elif ck == "topology":
        r.counts = {k: v for k, v in res.items() if isinstance(v, int)}
        r.summary = "topology built"


# ── Specialised normalizers ───────────────────────────────────────────────────


def _ssh_exec_infer_role(r: StructuredResult, req: dict, res: dict, output: str) -> None:
    if _PWNED_RE.search(output):
        r.access_role = "local_admin"
    elif _ROOT_RE.search(output):
        r.access_role = "shell"
    else:
        r.access_role = req.get("access_role") or None
    if res.get("access_role") and not r.access_role:
        r.access_role = res["access_role"]


def _ssh_exec_op_adcs(r: StructuredResult, output: str, host_id) -> None:
    templates = _extract_adcs_templates(output)
    vuln_count = len(re.findall(r"ESC\d", output, re.IGNORECASE))
    if vuln_count > 0:
        r.finding_candidates.append(
            finding_candidate(
                type="adcs_vulnerable_template",
                title=f"ADCS: {vuln_count} vulnerable template(s) found",
                severity="critical",
                host_id=host_id,
                details=f"Templates: {', '.join(templates[:5])}",
            )
        )
    r.summary = (
        f"adcs: {vuln_count} vuln templates" if vuln_count else "adcs: no vulnerable templates"
    )
    r.counts = {"vulnerable_templates": vuln_count, "templates_found": len(templates)}


def _ssh_exec_op_delegation(r: StructuredResult, output: str, host_id) -> None:
    unconstrained = len(_DELEG_UNCONSTRAINED_RE.findall(output))
    constrained = len(_DELEG_CONSTRAINED_RE.findall(output))
    if unconstrained > 0:
        r.finding_candidates.append(
            finding_candidate(
                type="unconstrained_delegation",
                title=f"Unconstrained delegation configured ({unconstrained} object(s))",
                severity="high",
                host_id=host_id,
                details="Accounts/computers with unconstrained Kerberos delegation are high-value targets",
            )
        )
    if unconstrained or constrained:
        r.summary = f"delegation: {unconstrained} unconstrained, {constrained} constrained"
    r.counts = {"unconstrained": unconstrained, "constrained": constrained}


def _ssh_exec_op_spn(r: StructuredResult, output: str, host_id) -> None:
    spn_lines = [ln for ln in output.splitlines() if _SPN_RE.search(ln) or "/" in ln and "@" in ln]
    spn_count = len(spn_lines)
    if spn_count > 0:
        r.finding_candidates.append(
            finding_candidate(
                type="kerberoastable_accounts",
                title=f"{spn_count} Kerberoastable SPN account(s) found",
                severity="medium",
                host_id=host_id,
                details="Consider running Kerberoast to request TGS tickets for offline cracking",
            )
        )
    r.summary = f"spn: {spn_count} kerberoastable accounts"
    r.counts = {"spn_accounts": spn_count}


def _ssh_exec_op_bloodhound(r: StructuredResult, output: str, host_id) -> None:
    done = bool(_BH_DONE_RE.search(output))
    r.summary = (
        "bloodhound: collection complete" if done else "bloodhound: collection may have errors"
    )
    if done:
        r.finding_candidates.append(
            finding_candidate(
                type="bloodhound_data_collected",
                title="BloodHound data collected — ready for analysis",
                severity="info",
                host_id=host_id,
            )
        )


def _ssh_exec_process_op(r: StructuredResult, output: str, op: str, host_id, cred_id) -> None:
    is_adcs = op == "adcs_enum" or (op == "exec" and _ADCS_VULN_RE.search(output))
    is_deleg = op == "delegation_enum" or (
        op == "exec"
        and (_DELEG_UNCONSTRAINED_RE.search(output) or _DELEG_CONSTRAINED_RE.search(output))
    )
    is_spn = op == "spn_enum" or (op == "exec" and _SPN_RE.search(output))

    if is_adcs:
        _ssh_exec_op_adcs(r, output, host_id)
    elif is_deleg:
        _ssh_exec_op_delegation(r, output, host_id)
    elif is_spn:
        _ssh_exec_op_spn(r, output, host_id)
    elif op == "bloodhound_collect":
        _ssh_exec_op_bloodhound(r, output, host_id)
    elif r.access_role in ("local_admin", "domain_admin") and host_id:
        r.finding_candidates.append(
            finding_candidate(
                type="privileged_access",
                title=f"Privileged access confirmed ({r.access_role})",
                severity="high",
                host_id=host_id,
                cred_id=cred_id,
            )
        )


def _ssh_exec_ok(
    r: StructuredResult, req: dict, res: dict, output: str, op: str
) -> StructuredResult:
    r.auth_success = True
    r.ok = True
    _ssh_exec_infer_role(r, req, res, output)

    host_id = res.get("host_id") or req.get("host_id")
    if host_id:
        r.hosts_affected = [host_id]

    cred_id = req.get("cred_id")
    if cred_id:
        r.creds_affected = [cred_id]

    role_label = f" [{r.access_role}]" if r.access_role else ""
    r.summary = f"exec ok{role_label}"

    _ssh_exec_process_op(r, output, op, host_id, cred_id)
    return r


def _normalize_ssh_exec(
    r: StructuredResult, req: dict, res: dict, output: str, op: str
) -> StructuredResult:
    exit_code = res.get("exit_code")

    if exit_code == 0:
        r = _ssh_exec_ok(r, req, res, output, op)
    elif exit_code == 255:
        r.auth_success = None
        r.ok = False
        r.summary = "transport unreachable"
    else:
        if _AUTH_FAIL_RE.search(output):
            r.auth_success = False
            r.summary = "auth failed"
        else:
            r.auth_success = None
            r.ok = False
            r.summary = f"exec failed (exit {exit_code})"

    r.counts = {"exit_code": exit_code} if exit_code is not None else {}
    return r


def _nxc_detect_proto(cmd: str, output: str) -> str:
    if _WINRM_PROTO_RE.search(cmd) or _WINRM_PROTO_RE.search(output):
        return "winrm"
    if _MSSQL_PROTO_RE.search(cmd) or _MSSQL_PROTO_RE.search(output):
        return "mssql"
    if _LDAP_PROTO_RE.search(cmd) or _LDAP_PROTO_RE.search(output):
        return "ldap"
    if _RDP_PROTO_RE.search(cmd) or _RDP_PROTO_RE.search(output):
        return "rdp"
    return "smb"


def _nxc_classify_line(
    line: str,
    pwned_ips: list,
    success_ips: list,
    failed_ips: list,
    sysadmin_ips: list,
    da_ips: list,
) -> None:
    ip_match = _IP_RE.search(line)
    ip = ip_match.group(1) if ip_match else None
    if not ip:
        return
    if _PWNED_RE.search(line):
        pwned_ips.append(ip)
    elif _PLUS_LINE_RE.search(line):
        success_ips.append(ip)
        if _SYSADMIN_RE.search(line):
            sysadmin_ips.append(ip)
        if _DA_RE.search(line):
            da_ips.append(ip)
    elif _MINUS_LINE_RE.search(line):
        failed_ips.append(ip)


def _nxc_scan_output_lines(
    output: str,
) -> tuple[list, list, list, list, list]:
    pwned_ips: list[str] = []
    success_ips: list[str] = []
    failed_ips: list[str] = []
    sysadmin_ips: list[str] = []
    da_ips: list[str] = []
    for line in output.splitlines():
        _nxc_classify_line(line, pwned_ips, success_ips, failed_ips, sysadmin_ips, da_ips)
    return pwned_ips, success_ips, failed_ips, sysadmin_ips, da_ips


def _nxc_apply_access_findings(
    r: StructuredResult,
    proto: str,
    pwned_ips: list,
    da_ips: list,
    sysadmin_ips: list,
    success_ips: list,
    failed_ips: list,
) -> None:
    total_success = len(pwned_ips) + len(success_ips)
    if pwned_ips:
        r.auth_success = True
        r.access_role = "local_admin"
        for ip in pwned_ips:
            r.finding_candidates.append(
                finding_candidate(
                    type="pwned_host",
                    title=f"(Pwn3d!) admin access via {proto} — {ip}",
                    severity="critical",
                    details=f"NetExec confirmed admin access on {ip} ({proto})",
                )
            )
    elif da_ips:
        r.auth_success = True
        r.access_role = "domain_admin"
        for ip in da_ips:
            r.finding_candidates.append(
                finding_candidate(
                    type="domain_admin_access",
                    title=f"Domain Admin access confirmed — {ip}",
                    severity="critical",
                    details=f"NetExec LDAP confirmed Domain Admin membership on {ip}",
                )
            )
    elif sysadmin_ips:
        r.auth_success = True
        r.access_role = "database"
        for ip in sysadmin_ips:
            r.finding_candidates.append(
                finding_candidate(
                    type="mssql_sysadmin",
                    title=f"MSSQL sysadmin access — {ip}",
                    severity="high",
                    details=f"NetExec confirmed sysadmin on MSSQL {ip}",
                )
            )
    elif success_ips:
        r.auth_success = True
        role_map = {
            "winrm": "winrm",
            "mssql": "database",
            "ldap": "domain_user",
            "rdp": "rdp",
            "smb": "smb",
        }
        r.access_role = role_map.get(proto, proto)
        if proto == "ldap" and len(success_ips) >= 1:
            r.finding_candidates.append(
                finding_candidate(
                    type="ldap_auth_success",
                    title="LDAP bind succeeded — valid domain cred",
                    severity="medium",
                    details=f"Credential authenticated against LDAP on {', '.join(success_ips[:3])}",
                )
            )
    elif failed_ips and total_success == 0:
        r.auth_success = False


def _normalize_netexec(
    r: StructuredResult, req: dict, res: dict, output: str, _op: str
) -> StructuredResult:
    cmd = (req.get("command") or "").lower()
    proto = _nxc_detect_proto(cmd, output)
    pwned_ips, success_ips, failed_ips, sysadmin_ips, da_ips = _nxc_scan_output_lines(output)

    _nxc_apply_access_findings(r, proto, pwned_ips, da_ips, sysadmin_ips, success_ips, failed_ips)

    total_success = len(pwned_ips) + len(success_ips)
    total_fail = len(failed_ips)
    r.counts = {
        "hosts_success": total_success,
        "hosts_pwned": len(pwned_ips),
        "hosts_failed": total_fail,
        **{k: v for k, v in res.items() if isinstance(v, int)},
    }

    if proto == "ldap" and _ADCS_VULN_RE.search(output):
        adcs_templates = _extract_adcs_templates(output)
        if adcs_templates:
            r.finding_candidates.append(
                finding_candidate(
                    type="adcs_detected",
                    title=f"AD Certificate Services detected ({len(adcs_templates)} template(s))",
                    severity="medium",
                    details=f"Templates: {', '.join(adcs_templates[:5])}",
                )
            )

    proto_label = proto.upper()
    if pwned_ips:
        r.summary = f"{proto_label}: {len(pwned_ips)} pwned, {total_success} auth ok"
    elif total_success:
        r.summary = f"{proto_label}: {total_success} auth ok, {total_fail} failed"
    else:
        r.summary = f"{proto_label}: {total_fail} failed"

    return r


def _normalize_cred_validate(r: StructuredResult, req: dict, res: dict) -> StructuredResult:
    valid = res.get("hosts_valid", 0)
    failed = res.get("hosts_failed", 0)
    total = res.get("hosts_total", 0)
    cred_id = res.get("cred_id") or req.get("cred_id")

    if valid > 0:
        r.auth_success = True
        if cred_id:
            r.creds_affected = [cred_id]
        # Finding candidate: valid on many hosts
        if valid >= 3:
            r.finding_candidates.append(
                finding_candidate(
                    type="valid_on_many_hosts",
                    title=f"Credential valid on {valid} hosts",
                    severity="high",
                    cred_id=cred_id,
                    details=f"{valid}/{total} hosts accepted this credential",
                )
            )
    elif failed > 0:
        r.auth_success = False

    r.counts = {"hosts_total": total, "hosts_valid": valid, "hosts_failed": failed}
    r.summary = f"cred validate: {valid}/{total} hosts valid"
    return r


def _normalize_scan_counts(r: StructuredResult, _res: dict, counts: dict) -> StructuredResult:
    r.counts = {**counts}
    return r
