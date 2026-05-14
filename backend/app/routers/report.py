"""PDF report generation endpoint."""
import io
import html as html_lib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..database import get_db
from .. import models
from ..core.deps import get_current_user
from ..core.access import check_pid_access

router = APIRouter(tags=["report"])

SEV_COLOR = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f39c12",
    "low":      "#2980b9",
    "info":     "#7f8c8d",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _e(s) -> str:
    return html_lib.escape(str(s or ""))


def _sev_badge(sev: str) -> str:
    c = SEV_COLOR.get(sev, "#7f8c8d")
    return (
        f'<span style="display:inline-block;padding:1px 7px;border-radius:3px;'
        f'font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;'
        f'background:{c}22;color:{c};border:1px solid {c}66">{_e(sev)}</span>'
    )


def _build_html(
    project: models.Project,
    hosts: list,
    creds: list,
    findings: list,
    scopes: list,
    attack_paths: list,
    attack_steps: list,
    notes: list,
) -> str:
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # ── Risk score ───────────────────────────────────────────────────────
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    raw_score = sum(weights.get(f.severity, 0) for f in findings)
    if raw_score == 0:    risk_label, risk_color = "None",     "#7f8c8d"
    elif raw_score >= 30: risk_label, risk_color = "Critical", "#c0392b"
    elif raw_score >= 15: risk_label, risk_color = "High",     "#e67e22"
    elif raw_score >= 6:  risk_label, risk_color = "Medium",   "#f39c12"
    else:                 risk_label, risk_color = "Low",      "#2980b9"

    non_attacker = [h for h in hosts if not getattr(h, "is_attacker", False)]
    pwned = [h for h in non_attacker if h.status in ("pwned", "owned", "access")]
    cracked = [c for c in creds if c.cracked]
    findings_sorted = sorted(findings, key=lambda f: SEV_ORDER.index(f.severity) if f.severity in SEV_ORDER else 99)

    sev_counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}

    # ── Findings rows ────────────────────────────────────────────────────
    finding_rows = ""
    finding_details = ""
    for i, f in enumerate(findings_sorted, 1):
        host = next((h for h in non_attacker if h.id == f.host_id), None)
        host_str = f"{host.ip}{' (' + host.hostname + ')' if host and host.hostname else ''}" if host else ""
        finding_rows += f"""
        <tr>
          <td>{_sev_badge(f.severity)}</td>
          <td><strong>{_e(f.title)}</strong></td>
          <td style="font-family:monospace;font-size:10px;color:#2980b9">{_e(f.cve)}</td>
          <td style="font-family:monospace;font-size:10px">{_e(f.cvss)}</td>
          <td style="font-family:monospace;font-size:10px;color:#555">{_e(host_str)}</td>
        </tr>"""
        finding_details += f"""
        <div class="finding-card sev-{_e(f.severity)}">
          <div class="finding-header">
            <div>{_sev_badge(f.severity)}</div>
            <div class="finding-title">{_e(f.title)}</div>
          </div>
          {"<div class='meta-row'><span class='meta-label'>CVE</span><code>" + _e(f.cve) + "</code></div>" if f.cve else ""}
          {"<div class='meta-row'><span class='meta-label'>CVSS</span><code>" + _e(f.cvss) + "</code></div>" if f.cvss else ""}
          {"<div class='meta-row'><span class='meta-label'>Host</span><code>" + _e(host_str) + "</code></div>" if host_str else ""}
          {"<div class='section-label'>Description</div><div class='body-text'>" + _e(f.description) + "</div>" if f.description else ""}
          {"<div class='section-label'>Recommendation</div><div class='body-text recommendation'>" + _e(f.recommendation) + "</div>" if f.recommendation else ""}
          {"<div class='section-label'>Proof of Concept</div><pre class='code-block'>" + _e(f.proof) + "</pre>" if f.proof else ""}
        </div>"""

    # ── Hosts rows ───────────────────────────────────────────────────────
    host_rows = ""
    for h in non_attacker:
        ports_str = ", ".join(str(p) for p in (h.ports or [])[:12])
        status_style = "color:#c0392b;font-weight:700" if h.status in ("pwned", "owned") else "color:#555"
        host_rows += f"""
        <tr>
          <td style="font-family:monospace;font-size:10px">{_e(h.ip)}</td>
          <td>{_e(h.hostname)}</td>
          <td style="color:#555">{_e(h.os)}</td>
          <td style="font-family:monospace;font-size:10px;color:#2980b9">{_e(h.domain)}</td>
          <td style="{status_style}">{_e(h.status)}</td>
          <td style="font-family:monospace;font-size:9px;color:#888">{_e(ports_str)}</td>
        </tr>"""

    # ── Creds rows ───────────────────────────────────────────────────────
    cred_rows = ""
    for c in cracked:
        cred_rows += f"""
        <tr>
          <td style="font-family:monospace;font-weight:600">{_e(c.username)}</td>
          <td style="font-family:monospace;font-size:10px;color:#2980b9">{_e(c.domain)}</td>
          <td style="font-size:10px;color:#555">{_e(c.type)}</td>
          <td style="font-size:10px">{_e(c.service)}</td>
          <td style="font-family:monospace;font-size:10px;color:#888">{_e(c.host)}</td>
        </tr>"""

    # ── Attack path steps ─────────────────────────────────────────────
    attack_path_html = ""
    steps_by_path = {}
    for s in attack_steps:
        steps_by_path.setdefault(s.path_id, []).append(s)
    for path in attack_paths:
        steps = sorted(steps_by_path.get(path.id, []), key=lambda s: s.step_order)
        if not steps:
            continue
        step_items = ""
        for j, s in enumerate(steps):
            mitre_badge = (
                f'<span style="font-family:monospace;font-size:9px;color:#8e44ad;background:#8e44ad18;'
                f'border:1px solid #8e44ad44;border-radius:3px;padding:1px 5px">{_e(s.mitre_id)}</span>'
                if s.mitre_id else ""
            )
            connector = "" if j == len(steps) - 1 else '<div class="ap-arrow">↓</div>'
            step_items += f"""
            <div class="ap-step">
              <div class="ap-step-header">
                <span class="ap-num">{j + 1:02d}</span>
                <span class="ap-label">{_e(s.label)}</span>
                {mitre_badge}
              </div>
              {"<div class='ap-technique'>" + _e(s.technique) + "</div>" if s.technique else ""}
              {"<div class='ap-notes'>" + _e(s.sublabel) + "</div>" if s.sublabel else ""}
            </div>
            {connector}"""
        attack_path_html += f"""
        <div class="attack-path-block">
          <div class="ap-path-name">{_e(path.title or path.name or "Attack Path")}</div>
          {step_items}
        </div>"""

    # ── Scope rows ───────────────────────────────────────────────────────
    scope_rows = ""
    for s in scopes:
        scope_rows += f"""
        <tr>
          <td style="font-family:monospace">{_e(s.target)}</td>
          <td style="color:#555">{_e(s.scope_type)}</td>
          <td style="color:#555">{_e(s.description)}</td>
        </tr>"""

    # ── Severity summary boxes ───────────────────────────────────────────
    sev_boxes = ""
    for sev in SEV_ORDER:
        cnt = sev_counts[sev]
        if cnt > 0:
            c = SEV_COLOR[sev]
            sev_boxes += f"""
            <div style="text-align:center;background:{c}15;border:1px solid {c}55;border-radius:6px;padding:10px 16px;min-width:70px">
              <div style="font-size:24px;font-weight:700;color:{c};font-family:monospace">{cnt}</div>
              <div style="font-size:8px;color:{c};text-transform:uppercase;letter-spacing:.1em;margin-top:2px">{sev}</div>
            </div>"""

    proj_name = _e(project.name or "Untitled Project")
    proj_ip = _e(project.ip or "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{proj_name} — Security Report</title>
  <style>
    @page {{ size: A4; margin: 18mm 16mm 18mm 16mm; }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 11px; color: #1a1a2e; line-height: 1.5; background: #fff; }}

    /* Typography */
    h1 {{ font-size: 22px; font-weight: 700; color: #0f0f23; margin-bottom: 4px; }}
    h2 {{ font-size: 13px; font-weight: 700; color: #0f0f23; margin: 24px 0 10px;
          padding-bottom: 5px; border-bottom: 2px solid #e0e0e8; page-break-after: avoid; }}
    h3 {{ font-size: 11px; font-weight: 600; color: #333; margin: 12px 0 6px; }}
    code {{ font-family: 'Courier New', monospace; font-size: 10px; background: #f4f4f8; padding: 1px 4px; border-radius: 2px; }}
    pre {{ font-family: 'Courier New', monospace; font-size: 10px; background: #f4f4f8; padding: 10px 12px; border-radius: 4px; border-left: 3px solid #ccc; white-space: pre-wrap; word-break: break-all; margin: 6px 0; }}

    /* Header */
    .report-header {{ padding-bottom: 16px; border-bottom: 1px solid #dde; margin-bottom: 20px; }}
    .report-meta {{ font-size: 10px; color: #888; margin-top: 6px; }}
    .risk-badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; margin-top: 8px; }}

    /* Stats grid */
    .stats-grid {{ display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }}
    .stat-card {{ background: #f8f8fc; border: 1px solid #e0e0e8; border-radius: 6px; padding: 12px 16px; min-width: 90px; text-align: center; }}
    .stat-card .val {{ font-size: 24px; font-weight: 700; font-family: monospace; }}
    .stat-card .lbl {{ font-size: 9px; color: #888; text-transform: uppercase; letter-spacing: .08em; margin-top: 2px; }}

    /* Tables */
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 11px; page-break-inside: auto; }}
    th {{ background: #f4f4f8; padding: 7px 10px; text-align: left; font-size: 9px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; color: #666; border-bottom: 1px solid #dde; }}
    td {{ padding: 7px 10px; border-bottom: 1px solid #eef; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr {{ page-break-inside: avoid; }}

    /* Finding cards */
    .finding-card {{ border: 1px solid #e0e0e8; border-radius: 6px; padding: 12px 14px; margin-bottom: 12px; page-break-inside: avoid; }}
    .finding-card.sev-critical {{ border-left: 4px solid #c0392b; }}
    .finding-card.sev-high     {{ border-left: 4px solid #e67e22; }}
    .finding-card.sev-medium   {{ border-left: 4px solid #f39c12; }}
    .finding-card.sev-low      {{ border-left: 4px solid #2980b9; }}
    .finding-card.sev-info     {{ border-left: 4px solid #7f8c8d; }}
    .finding-header {{ display: flex; align-items: flex-start; gap: 8px; margin-bottom: 8px; }}
    .finding-title {{ font-size: 12px; font-weight: 600; color: #0f0f23; flex: 1; }}
    .meta-row {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; font-size: 10px; }}
    .meta-label {{ font-size: 9px; font-weight: 600; text-transform: uppercase; color: #888; width: 52px; flex-shrink: 0; }}
    .section-label {{ font-size: 9px; font-weight: 600; text-transform: uppercase; color: #888; margin: 8px 0 4px; letter-spacing: .05em; }}
    .body-text {{ font-size: 11px; color: #333; line-height: 1.6; white-space: pre-wrap; }}
    .recommendation {{ color: #1a5276; background: #eaf2ff; padding: 6px 10px; border-radius: 3px; border-left: 3px solid #2980b9; }}
    .code-block {{ font-size: 10px; background: #f8f8f8; border: 1px solid #dde; border-left: 3px solid #bbb; border-radius: 3px; padding: 8px 10px; }}

    /* Attack path */
    .attack-path-block {{ margin-bottom: 16px; page-break-inside: avoid; }}
    .ap-path-name {{ font-size: 11px; font-weight: 700; color: #0f0f23; margin-bottom: 8px; padding-bottom: 4px; border-bottom: 1px solid #e0e0e8; }}
    .ap-step {{ background: #f8f8fc; border: 1px solid #e0e0e8; border-radius: 5px; padding: 8px 12px; }}
    .ap-step-header {{ display: flex; align-items: center; gap: 8px; }}
    .ap-num {{ font-family: monospace; font-size: 9px; color: #888; width: 22px; flex-shrink: 0; }}
    .ap-label {{ font-size: 11px; font-weight: 600; flex: 1; }}
    .ap-technique {{ font-size: 10px; color: #8e44ad; font-family: monospace; padding-left: 30px; margin-top: 3px; }}
    .ap-notes {{ font-size: 10px; color: #888; padding-left: 30px; margin-top: 2px; font-style: italic; }}
    .ap-arrow {{ text-align: center; color: #bbb; font-size: 14px; line-height: 1.4; }}

    /* Severity summary */
    .sev-row {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }}

    /* Footer */
    .footer {{ margin-top: 32px; padding-top: 10px; border-top: 1px solid #e0e0e8; font-size: 9px; color: #aaa; text-align: center; }}

    /* Page break helpers */
    .page-break {{ page-break-before: always; }}
    .no-break {{ page-break-inside: avoid; }}
  </style>
</head>
<body>

  <!-- Cover / Header -->
  <div class="report-header">
    <div style="font-size:9px;color:#888;text-transform:uppercase;letter-spacing:.15em;margin-bottom:6px">Security Assessment Report</div>
    <h1>{proj_name}</h1>
    <div class="report-meta">
      {f"{proj_ip} · " if proj_ip else ""}{date_str}
    </div>
    <div>
      <span class="risk-badge" style="background:{risk_color}18;color:{risk_color};border:1px solid {risk_color}55">
        Risk: {risk_label}
      </span>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card"><div class="val" style="color:#8e44ad">{len(non_attacker)}</div><div class="lbl">Hosts</div></div>
    <div class="stat-card"><div class="val" style="color:#c0392b">{len(pwned)}</div><div class="lbl">Compromised</div></div>
    <div class="stat-card"><div class="val" style="color:#e67e22">{len(findings)}</div><div class="lbl">Findings</div></div>
    <div class="stat-card"><div class="val" style="color:#27ae60">{len(cracked)}</div><div class="lbl">Cracked creds</div></div>
    {f'<div class="stat-card"><div class="val" style="color:#2980b9">{len(scopes)}</div><div class="lbl">Scope targets</div></div>' if scopes else ''}
  </div>

  <!-- Executive Summary -->
  <h2>Executive Summary</h2>
  <p style="margin-bottom:10px;line-height:1.7">
    During this engagement <strong>{len(non_attacker)}</strong> host{"s were" if len(non_attacker) != 1 else " was"} identified
    in scope, of which <strong>{len(pwned)}</strong> {"were" if len(pwned) != 1 else "was"} compromised.
    <strong>{len(findings)}</strong> {"vulnerabilities were" if len(findings) != 1 else "vulnerability was"} discovered
    and <strong>{len(cracked)}</strong> credential{"s were" if len(cracked) != 1 else " was"} collected.
    The overall risk rating is assessed as <strong style="color:{risk_color}">{risk_label}</strong>.
  </p>

  {'<!-- Scope --><h2>Scope</h2><table><thead><tr><th>Target</th><th>Type</th><th>Description</th></tr></thead><tbody>' + scope_rows + '</tbody></table>' if scopes else ''}

  <!-- Findings summary -->
  {f"""
  <h2>Findings ({len(findings)})</h2>
  <div class="sev-row">{sev_boxes}</div>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>CVE</th><th>CVSS</th><th>Host</th></tr></thead>
    <tbody>{finding_rows}</tbody>
  </table>
  """ if findings else ""}

  <!-- Finding details -->
  {f'<h2>Finding Details</h2>{finding_details}' if findings else ''}

  <!-- Hosts -->
  {f"""
  <h2>Hosts ({len(non_attacker)})</h2>
  <table>
    <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Domain</th><th>Status</th><th>Open Ports</th></tr></thead>
    <tbody>{host_rows}</tbody>
  </table>
  """ if non_attacker else ""}

  <!-- Cracked Credentials -->
  {f"""
  <h2>Captured Credentials ({len(cracked)})</h2>
  <table>
    <thead><tr><th>Username</th><th>Domain</th><th>Type</th><th>Service</th><th>Host</th></tr></thead>
    <tbody>{cred_rows}</tbody>
  </table>
  """ if cracked else ""}

  <!-- Attack Paths -->
  {f'<h2>Attack Path</h2>{attack_path_html}' if attack_path_html else ''}

  <div class="footer">Generated by RootNotes &middot; {datetime.now(timezone.utc).isoformat()}</div>
</body>
</html>"""


@router.get("/api/projects/{pid}/report/pdf")
def generate_pdf_report(
    pid: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    check_pid_access(db, pid, user, "findings.read")

    project   = db.query(models.Project).filter(models.Project.id == pid).first()
    hosts     = db.query(models.Host).filter(models.Host.pid == pid).all()
    creds     = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    findings  = db.query(models.Finding).filter(models.Finding.pid == pid).all()
    scopes    = db.query(models.Scope).filter(models.Scope.pid == pid).all()
    paths     = db.query(models.AttackPath).filter(models.AttackPath.pid == pid).all()
    steps     = db.query(models.AttackStep).filter(models.AttackStep.pid == pid).all()
    notes     = db.query(models.Note).filter(models.Note.pid == pid).all()

    html_content = _build_html(project, hosts, creds, findings, scopes, paths, steps, notes)

    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html_content, base_url=None).write_pdf()
    except ImportError:
        return Response(
            content=html_content.encode(),
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="report_{pid}.html"'},
        )

    safe_name = (project.name or pid).replace(" ", "_").replace("/", "-")[:40]
    filename = f"{safe_name}_report_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
