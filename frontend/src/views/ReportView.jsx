import { useState } from 'react';
import Icon from '../components/Icon.jsx';
import { StatusDot, PhaseTag, HostStatusBadge, CredTypeBadge } from '../components/UI.jsx';
import { PHASES, PHASE_COLORS, NODE_STATUS, SEVERITY, FINDING_STATUS } from '../constants.js';
import { isAttackerHost } from '../utils/hostMeta.js';
import { api } from '../api.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS = {
  critical: '#cc2233', high: '#e8574a', medium: '#f09a3a', low: '#4a9eff', info: '#606570',
};

function riskScore(findings) {
  const weights = { critical: 10, high: 5, medium: 2, low: 1, info: 0 };
  const raw = findings.reduce((s, f) => s + (weights[f.severity] || 0), 0);
  if (raw === 0) return { label: 'None', color: '#404550', score: 0 };
  if (raw >= 30) return { label: 'Critical', color: '#cc2233', score: Math.min(raw, 100) };
  if (raw >= 15) return { label: 'High', color: '#e8574a', score: Math.min(raw, 100) };
  if (raw >= 6)  return { label: 'Medium', color: '#f09a3a', score: Math.min(raw, 100) };
  return { label: 'Low', color: '#4a9eff', score: Math.min(raw, 100) };
}

function mdEscape(s) { return (s || '').replace(/\|/g, '\\|'); }
function mdRow(...cells) { return '| ' + cells.map(c => mdEscape(String(c ?? ''))).join(' | ') + ' |'; }
function mdSep(n) { return '|' + ' --- |'.repeat(n); }

export default function ReportView({ projects, notes, hosts, creds, findings = [], hostActivities = [], selectedProject, accent, attackPaths = [], attackSteps = [] }) {
  const proj = projects.find(p => p.id === selectedProject);
  const pNotes = notes.filter(n => n.pid === selectedProject);
  const pHosts = hosts.filter(h => h.pid === selectedProject && !isAttackerHost(h));
  const pCreds = creds.filter(c => c.pid === selectedProject);
  const pFindings = [...(findings.filter(f => f.pid === selectedProject))].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const pActivities = [...hostActivities.filter(a => a.pid === selectedProject && pHosts.some(h => h.id === a.host_id))].sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));

  const phaseStat = PHASES.map(ph => ({ ph, count: pNotes.filter(n => n.phase === ph).length })).filter(x => x.count > 0);
  const hostsBySt = Object.entries(NODE_STATUS).map(([k, v]) => ({ ...v, key: k, count: pHosts.filter(h => h.status === k).length })).filter(x => x.count > 0);
  const critHosts = pHosts.filter(h => h.status === 'pwned' || h.status === 'owned');
  const crackedCreds = pCreds.filter(c => c.cracked);
  const risk = riskScore(pFindings);
  const date = new Date().toISOString().slice(0, 10);

  const [showMdPreview, setShowMdPreview] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);

  const exportPDF = async () => {
    if (!selectedProject) return;
    setPdfLoading(true);
    try {
      const blob = await api.downloadReportPDF(selectedProject);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const safeName = (proj?.name || 'report').replace(/[^a-z0-9]/gi, '_');
      a.href = url;
      a.download = `${safeName}_report_${date}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert('PDF generation failed: ' + e.message);
    } finally {
      setPdfLoading(false);
    }
  };

  // ── Markdown export ──────────────────────────────────────────────────

  const buildMarkdown = () => {
    const lines = [];
    const safeName = proj?.name || 'Project';

    // YAML frontmatter
    lines.push('---');
    lines.push(`title: "${safeName} — Pentest Report"`);
    lines.push(`date: ${date}`);
    lines.push(`project: "${safeName}"`);
    lines.push(`risk: ${risk.label}`);
    lines.push(`hosts: ${pHosts.length}`);
    lines.push(`findings: ${pFindings.length}`);
    lines.push(`credentials: ${pCreds.length}`);
    lines.push('tags: [pentest, report]');
    lines.push('---');
    lines.push('');

    // Title
    lines.push(`# ${safeName} — Security Assessment Report`);
    lines.push('');
    lines.push(`**Date:** ${date}  `);
    if (proj?.ip) lines.push(`**Target:** ${proj.ip}  `);
    lines.push(`**Overall Risk:** ${risk.label}  `);
    lines.push('');

    // Executive Summary
    lines.push('## Executive Summary');
    lines.push('');
    const pwnedCount = pHosts.filter(h => ['pwned', 'owned', 'access'].includes(h.status)).length;
    lines.push(`During this engagement **${pHosts.length} hosts** were identified, of which **${pwnedCount} were compromised**. **${pFindings.length} vulnerabilities** were discovered and **${pCreds.length} credentials** were collected.`);
    lines.push('');

    // Stats table
    lines.push('| Metric | Value |');
    lines.push('| --- | --- |');
    lines.push(`| Hosts in scope | ${pHosts.length} |`);
    lines.push(`| Compromised hosts | ${pwnedCount} |`);
    lines.push(`| Findings (total) | ${pFindings.length} |`);
    lines.push(`| Critical findings | ${pFindings.filter(f => f.severity === 'critical').length} |`);
    lines.push(`| High findings | ${pFindings.filter(f => f.severity === 'high').length} |`);
    lines.push(`| Credentials collected | ${pCreds.length} |`);
    lines.push('');

    // Findings
    if (pFindings.length > 0) {
      lines.push('## Findings');
      lines.push('');
      lines.push(mdRow('Severity', 'Title', 'CVE', 'CVSS', 'Status'));
      lines.push(mdSep(5));
      pFindings.forEach(f => {
        const st = FINDING_STATUS[f.status]?.label || f.status || 'open';
        lines.push(mdRow(f.severity?.toUpperCase() || '', f.title || '', f.cve || '', f.cvss || '', st));
      });
      lines.push('');

      // Finding details
      lines.push('### Finding Details');
      lines.push('');
      pFindings.forEach((f, i) => {
        const linkedHost = pHosts.find(h => h.id === f.host_id);
        lines.push(`#### ${i + 1}. [${(f.severity || 'info').toUpperCase()}] ${f.title || 'Untitled'}`);
        lines.push('');
        if (f.cve)  lines.push(`**CVE:** ${f.cve}  `);
        if (f.cvss) lines.push(`**CVSS:** ${f.cvss}  `);
        if (linkedHost) lines.push(`**Host:** ${linkedHost.ip}${linkedHost.hostname ? ` (${linkedHost.hostname})` : ''}  `);
        lines.push('');
        if (f.description) {
          lines.push('**Description:**');
          lines.push('');
          lines.push(f.description);
          lines.push('');
        }
        if (f.recommendation) {
          lines.push('**Recommendation:**');
          lines.push('');
          lines.push(f.recommendation);
          lines.push('');
        }
        if (f.proof) {
          lines.push('**Proof of Concept:**');
          lines.push('');
          lines.push('```');
          lines.push(f.proof);
          lines.push('```');
          lines.push('');
        }
        lines.push('---');
        lines.push('');
      });
    }

    // Hosts
    if (pHosts.length > 0) {
      lines.push('## Hosts');
      lines.push('');
      lines.push(mdRow('IP', 'Hostname', 'OS', 'Domain', 'Status', 'Open Ports'));
      lines.push(mdSep(6));
      pHosts.forEach(h => {
        const ports = (h.ports || []).slice(0, 10).join(', ');
        lines.push(mdRow(h.ip || '', h.hostname || '', h.os || '', h.domain || '', h.status || '', ports));
      });
      lines.push('');
    }

    // Credentials
    if (pCreds.length > 0) {
      lines.push('## Credentials');
      lines.push('');
      lines.push(mdRow('Username', 'Domain', 'Type', 'Service', 'Host', 'Notes'));
      lines.push(mdSep(6));
      pCreds.forEach(c => {
        lines.push(mdRow(c.username || '', c.domain || '', c.type || '', c.service || '', c.host || '', (c.notes || '').slice(0, 80)));
      });
      lines.push('');
    }

    // Activity log
    if (pActivities.length > 0) {
      lines.push('## Activity Log');
      lines.push('');
      lines.push(mdRow('Date', 'Host', 'Type', 'Title', 'Status'));
      lines.push(mdSep(5));
      pActivities.slice(0, 50).forEach(a => {
        const h = pHosts.find(x => x.id === a.host_id);
        const hostStr = h ? `${h.ip}${h.hostname ? ` (${h.hostname})` : ''}` : '';
        lines.push(mdRow(a.ts || '', hostStr, a.activity_type || '', a.title || '', a.status || ''));
      });
      lines.push('');
    }

    lines.push(`---`);
    lines.push(`*Generated by RootNotes on ${new Date().toISOString()}*`);
    return lines.join('\n');
  };

  const exportMarkdown = () => {
    const md = buildMarkdown();
    const safeName = (proj?.name || 'report').replace(/[^a-z0-9]/gi, '_');
    const blob = new Blob([md], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${safeName}_report_${date}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  // ── HTML export ──────────────────────────────────────────────────────

  const exportHTML = () => {
    const safeName = (proj?.name || 'report').replace(/[^a-z0-9]/gi, '_');

    const sevBadge = (sev) => {
      const c = SEV_COLORS[sev] || '#606570';
      return `<span style="font-size:10px;font-weight:700;color:${c};background:${c}22;border:1px solid ${c}55;border-radius:3px;padding:2px 7px;font-family:monospace;text-transform:uppercase">${sev || ''}</span>`;
    };

    const escHtml = (s) => (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    const findingsHtml = pFindings.map(f => {
      const linkedHost = pHosts.find(h => h.id === f.host_id);
      return `
      <div style="padding:14px 0;border-bottom:1px solid #1e2029">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
          ${sevBadge(f.severity)}
          <strong style="color:#e0e4ec;font-size:13px">${escHtml(f.title)}</strong>
        </div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px;font-size:11px;font-family:monospace">
          ${f.cve ? `<span style="color:#5b8af5">${escHtml(f.cve)}</span>` : ''}
          ${f.cvss ? `<span style="color:#808590">CVSS: ${escHtml(f.cvss)}</span>` : ''}
          ${linkedHost ? `<span style="color:#606570">${escHtml(linkedHost.ip)}${linkedHost.hostname ? ` (${escHtml(linkedHost.hostname)})` : ''}</span>` : ''}
        </div>
        ${f.description ? `<div style="font-size:11px;color:#9098a8;line-height:1.7;margin-bottom:8px;white-space:pre-wrap">${escHtml(f.description)}</div>` : ''}
        ${f.recommendation ? `<div style="font-size:11px;color:#6fc8f0;line-height:1.6"><strong>Recommendation:</strong> ${escHtml(f.recommendation)}</div>` : ''}
        ${f.proof ? `<pre style="margin-top:8px;background:#07080c;border:1px solid #1e2230;border-radius:4px;padding:8px 10px;color:#c8cfe0;font-size:11px;overflow-x:auto">${escHtml(f.proof)}</pre>` : ''}
      </div>`;
    }).join('');

    const hostsHtml = pHosts.map(h => `
      <tr>
        <td style="padding:7px 10px;font-family:monospace;font-size:11px;color:#9098a8">${escHtml(h.ip)}</td>
        <td style="padding:7px 10px;font-size:11px;color:#c8cdd6">${escHtml(h.hostname)}</td>
        <td style="padding:7px 10px;font-size:11px;color:#808590">${escHtml(h.os)}</td>
        <td style="padding:7px 10px;font-size:11px;color:#606570">${escHtml(h.domain)}</td>
        <td style="padding:7px 10px;font-size:11px;color:#808590">${escHtml(h.status)}</td>
        <td style="padding:7px 10px;font-size:11px;color:#505060;font-family:monospace">${escHtml((h.ports || []).slice(0, 12).join(', '))}</td>
      </tr>`).join('');

    const credsHtml = pCreds.map(c => `
      <tr>
        <td style="padding:7px 10px;font-family:monospace;font-size:11px;color:#c8cdd6">${escHtml(c.username)}</td>
        <td style="padding:7px 10px;font-size:11px;color:#5b8af5;font-family:monospace">${escHtml(c.domain)}</td>
        <td style="padding:7px 10px;font-size:11px;color:#808590">${escHtml(c.type)}</td>
        <td style="padding:7px 10px;font-size:11px;color:#606570">${escHtml(c.service)}</td>
        <td style="padding:7px 10px;font-size:11px;color:#9098a8;font-family:monospace">${escHtml(c.host)}</td>
      </tr>`).join('');

    const sevSummary = SEV_ORDER.map(s => {
      const cnt = pFindings.filter(f => f.severity === s).length;
      const c = SEV_COLORS[s];
      return cnt > 0 ? `<div style="text-align:center;background:${c}18;border:1px solid ${c}44;border-radius:6px;padding:10px 14px"><div style="font-size:22px;font-weight:700;color:${c};font-family:monospace">${cnt}</div><div style="font-size:9px;color:${c}cc;text-transform:uppercase;letter-spacing:.08em">${s}</div></div>` : '';
    }).join('');

    const pwnedCount = pHosts.filter(h => ['pwned', 'owned', 'access'].includes(h.status)).length;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escHtml(proj?.name || '')} — Security Report</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#08090b;color:#c8cdd6;font-family:system-ui,sans-serif;padding:40px 48px;line-height:1.5;max-width:960px;margin:0 auto}
    h1{font-size:26px;font-weight:700;color:#f0f2f6;margin-bottom:8px}
    h2{font-size:16px;font-weight:600;color:#e0e4ec;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #1e2029}
    .stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0 28px}
    .stat{background:#0d0f14;border:1px solid #1e2029;border-radius:8px;padding:14px 16px}
    .stat .val{font-size:26px;font-weight:700;font-family:monospace;margin-bottom:4px}
    .stat .lbl{font-size:10px;color:#606570;text-transform:uppercase;letter-spacing:.08em}
    table{width:100%;border-collapse:collapse;background:#0d0f14;border:1px solid #1e2029;border-radius:8px;overflow:hidden;margin-bottom:20px}
    th{padding:9px 10px;text-align:left;font-size:10px;color:#404550;text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid #1e2029}
    tr:not(:last-child) td{border-bottom:1px solid #14161b}
    .findings-block{background:#0d0f14;border:1px solid #1e2029;border-radius:8px;padding:18px;margin-bottom:20px}
    .sev-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
    .risk{display:inline-block;font-size:12px;font-weight:700;font-family:monospace;padding:3px 10px;border-radius:4px}
    .footer{margin-top:40px;padding-top:16px;border-top:1px solid #1a1c22;font-size:10px;color:#404550}
  </style>
</head>
<body>
  <div style="font-size:10px;color:#404550;text-transform:uppercase;letter-spacing:.15em;margin-bottom:8px">Security Assessment Report</div>
  <h1>${escHtml(proj?.name || '')}</h1>
  <div style="font-size:12px;color:#606570;margin-bottom:6px">${escHtml(proj?.ip || '')} · ${date}</div>
  <div style="margin-bottom:24px">
    <span class="risk" style="color:${risk.color};background:${risk.color}22;border:1px solid ${risk.color}44">Risk: ${risk.label}</span>
  </div>

  <div class="stats">
    <div class="stat"><div class="val" style="color:#c07af0">${pHosts.length}</div><div class="lbl">Hosts</div></div>
    <div class="stat"><div class="val" style="color:#cc2233">${pwnedCount}</div><div class="lbl">Compromised</div></div>
    <div class="stat"><div class="val" style="color:#e8574a">${pFindings.length}</div><div class="lbl">Findings</div></div>
    <div class="stat"><div class="val" style="color:#39d353">${pCreds.length}</div><div class="lbl">Credentials</div></div>
    <div class="stat"><div class="val" style="color:#6fc8f0">${pNotes.length}</div><div class="lbl">Notes</div></div>
  </div>

  ${pFindings.length > 0 ? `
  <h2>Findings (${pFindings.length})</h2>
  <div class="sev-row">${sevSummary}</div>
  <div class="findings-block">${findingsHtml}</div>` : ''}

  ${pHosts.length > 0 ? `
  <h2>Hosts (${pHosts.length})</h2>
  <table>
    <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Domain</th><th>Status</th><th>Ports</th></tr></thead>
    <tbody>${hostsHtml}</tbody>
  </table>` : ''}

  ${pCreds.length > 0 ? `
  <h2>Credentials (${pCreds.length})</h2>
  <table>
    <thead><tr><th>Username</th><th>Domain</th><th>Type</th><th>Service</th><th>Host</th></tr></thead>
    <tbody>${credsHtml}</tbody>
  </table>` : ''}

  <div class="footer">Generated by RootNotes · ${new Date().toISOString()}</div>
</body>
</html>`;

    const blob = new Blob([html], { type: 'text/html' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${safeName}_report_${date}.html`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const Row = ({ icon, label, value, color = '#9098a8' }) => (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #14161b' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Icon name={icon} size={12} color="#404550" /><span style={{ fontSize: 11, color: '#808590' }}>{label}</span></div>
      <span style={{ fontSize: 12, fontWeight: 600, color, fontFamily: 'JetBrains Mono' }}>{value}</span>
    </div>
  );

  const pwnedCount = pHosts.filter(h => ['pwned', 'owned', 'access'].includes(h.status)).length;

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px', maxWidth: 960 }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 4 }}>
          <div>
            <div style={{ fontSize: 9, color: '#404550', letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>Report · {new Date().toLocaleDateString('en')}</div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 6 }}>{proj?.name}</h1>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
              <StatusDot status={proj?.status} />
              {proj?.ip && <span style={{ fontSize: 11, color: '#606570' }}>{proj.ip}</span>}
              <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, background: risk.color + '22', color: risk.color, border: `1px solid ${risk.color}44` }}>
                Risk: {risk.label}
              </span>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0, marginTop: 4 }}>
            <button onClick={exportMarkdown}
              style={{ background: '#1e2230', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 14px', cursor: 'pointer', color: '#c8cdd6', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7 }}>
              <Icon name="export" size={12} color="#808590" /> MD
            </button>
            <button onClick={exportHTML}
              style={{ background: '#1e2230', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 14px', cursor: 'pointer', color: '#c8cdd6', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7 }}>
              <Icon name="export" size={12} color="#808590" /> HTML
            </button>
            <button
              onClick={exportPDF}
              disabled={pdfLoading}
              style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 14px', cursor: pdfLoading ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7, opacity: pdfLoading ? 0.6 : 1 }}>
              <Icon name="export" size={12} color="#fff" /> {pdfLoading ? 'Generating…' : 'Export PDF'}
            </button>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12, marginBottom: 24 }}>
        {[
          ['hosts', 'Hosts', pHosts.length, '#c07af0'],
          ['warning', 'Compromised', pwnedCount, '#cc2233'],
          ['bug', 'Findings', pFindings.length, '#e8574a'],
          ['person', 'Credentials', pCreds.length, '#39d353'],
          ['notes', 'Notes', pNotes.length, '#6fc8f0'],
        ].map(([icon, l, v, c]) => (
          <div key={l} style={{ background: '#0d0f14', border: `1px solid ${v > 0 && (l === 'Compromised' || l === 'Findings') ? c + '44' : '#1e2029'}`, borderRadius: 8, padding: '14px 16px' }}>
            <div style={{ fontSize: 26, fontWeight: 700, color: v > 0 ? c : '#303540', fontFamily: 'Space Grotesk', marginBottom: 4 }}>{v}</div>
            <div style={{ fontSize: 10, color: '#606570', display: 'flex', alignItems: 'center', gap: 6 }}><Icon name={icon} size={11} color="#404550" />{l}</div>
          </div>
        ))}
      </div>

      {/* Findings severity breakdown */}
      {pFindings.length > 0 && (
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 20 }}>
          {SEV_ORDER.map(s => {
            const cnt = pFindings.filter(f => f.severity === s).length;
            if (!cnt) return null;
            const sv = SEVERITY[s];
            return (
              <div key={s} style={{ background: sv.color + '18', border: `1px solid ${sv.color}44`, borderRadius: 6, padding: '8px 14px', textAlign: 'center', minWidth: 60 }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: sv.color, fontFamily: 'Space Grotesk' }}>{cnt}</div>
                <div style={{ fontSize: 9, color: sv.color + 'cc', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{sv.label}</div>
              </div>
            );
          })}
        </div>
      )}

      {/* Phase / host status charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 14 }}>Activity by phase</div>
          {phaseStat.map(({ ph, count }) => {
            const c = PHASE_COLORS[ph], max = Math.max(...phaseStat.map(x => x.count));
            return (
              <div key={ph} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <PhaseTag phase={ph} small /><span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{count}</span>
                </div>
                <div style={{ height: 4, background: '#1a1c22', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${(count / max) * 100}%`, background: c, borderRadius: 2, transition: 'width 0.5s' }} />
                </div>
              </div>
            );
          })}
          {phaseStat.length === 0 && <div style={{ fontSize: 11, color: '#404550' }}>No notes</div>}
        </div>

        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 14 }}>Host status</div>
          {hostsBySt.map(({ key, color, label, count }) => (
            <Row key={key} icon="hosts" label={label} value={count} color={color} />
          ))}
          {hostsBySt.length === 0 && <div style={{ fontSize: 11, color: '#404550' }}>No hosts</div>}
        </div>
      </div>

      {/* Compromised hosts */}
      {critHosts.length > 0 && (
        <div style={{ background: '#0d0f14', border: `1px solid ${accent}33`, borderRadius: 8, padding: 18, marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: accent, fontFamily: 'Space Grotesk', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="warning" size={13} color={accent} />Compromised hosts ({critHosts.length})
          </div>
          {critHosts.map(h => (
            <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 0', borderBottom: '1px solid #14161b' }}>
              <HostStatusBadge status={h.status} />
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#9098a8', width: 130, flexShrink: 0 }}>{h.ip}</span>
              <span style={{ fontSize: 11, color: '#c8cdd6', width: 160, flexShrink: 0 }}>{h.hostname}</span>
              {h.os && <span style={{ fontSize: 10, color: '#606570', width: 130, flexShrink: 0 }}>{h.os}</span>}
              {h.domain && <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: 'JetBrains Mono' }}>{h.domain}</span>}
            </div>
          ))}
        </div>
      )}

      {/* Cracked credentials */}
      {crackedCreds.length > 0 && (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18, marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="person" size={13} color="#39d353" />Cracked credentials ({crackedCreds.length})
          </div>
          {crackedCreds.map(c => (
            <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 0', borderBottom: '1px solid #14161b' }}>
              <CredTypeBadge type={c.type} />
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#c8cdd6', width: 160 }}>{c.username}</span>
              <span style={{ fontSize: 10, color: '#5b8af5', width: 110, fontFamily: 'JetBrains Mono' }}>{c.host}</span>
              <span style={{ fontSize: 10, color: '#606570' }}>{c.service}</span>
            </div>
          ))}
        </div>
      )}

      {/* Findings detail */}
      {pFindings.length > 0 && (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18, marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="bug" size={13} color="#e8574a" />Vulnerabilities ({pFindings.length})
          </div>
          {pFindings.map(f => {
            const sv = SEVERITY[f.severity] || SEVERITY.info;
            const st = FINDING_STATUS[f.status] || FINDING_STATUS.open;
            const linkedHost = pHosts.find(h => h.id === f.host_id);
            return (
              <div key={f.id} style={{ padding: '12px 0', borderBottom: '1px solid #14161b' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 9, fontWeight: 700, color: sv.color, background: sv.color + '22', border: `1px solid ${sv.color}55`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{sv.label}</span>
                  <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec', flex: 1 }}>{f.title}</span>
                  <span style={{ fontSize: 9, color: st.color, background: st.color + '18', border: `1px solid ${st.color}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{st.label}</span>
                </div>
                <div style={{ display: 'flex', gap: 12, marginBottom: 6, flexWrap: 'wrap' }}>
                  {f.cvss && <span style={{ fontSize: 10, color: '#808590', fontFamily: 'JetBrains Mono' }}>CVSS: {f.cvss}</span>}
                  {f.cve && <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: 'JetBrains Mono' }}>{f.cve}</span>}
                  {linkedHost && <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{linkedHost.ip}{linkedHost.hostname ? ` (${linkedHost.hostname})` : ''}</span>}
                </div>
                {f.description && <div style={{ fontSize: 11, color: '#808590', lineHeight: 1.6, marginBottom: f.recommendation ? 6 : 0, whiteSpace: 'pre-wrap' }}>{f.description}</div>}
                {f.recommendation && <div style={{ fontSize: 10, color: '#6fc8f0', lineHeight: 1.5, marginTop: 4 }}><span style={{ color: '#404550' }}>Rec: </span>{f.recommendation}</div>}
              </div>
            );
          })}
        </div>
      )}

      {/* Activity log */}
      {pActivities.length > 0 && (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18, marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="terminal" size={13} color={accent} />Host activity log
          </div>
          {pActivities.slice(0, 15).map(a => {
            const host = pHosts.find(h => h.id === a.host_id);
            return (
              <div key={a.id} style={{ padding: '10px 0', borderBottom: '1px solid #14161b' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 8, color: accent, background: accent + '18', border: `1px solid ${accent}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{a.activity_type}</span>
                  <span style={{ fontSize: 8, color: '#808590', background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{a.status}</span>
                  {host && <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: 'JetBrains Mono' }}>{host.ip}{host.hostname ? ` (${host.hostname})` : ''}</span>}
                  <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginLeft: 'auto' }}>{a.ts}</span>
                </div>
                <div style={{ fontSize: 11, color: '#e0e4ec', fontWeight: 600, marginBottom: 3 }}>{a.title || 'Untitled'}</div>
                {a.command && <div style={{ fontSize: 10, color: '#9098a8', fontFamily: 'JetBrains Mono', marginBottom: 3, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{a.command}</div>}
                {a.summary && <div style={{ fontSize: 10, color: '#808590', lineHeight: 1.5 }}>{a.summary}</div>}
              </div>
            );
          })}
          {pActivities.length > 15 && <div style={{ fontSize: 10, color: '#404550', paddingTop: 8 }}>+{pActivities.length - 15} more — export for full log</div>}
        </div>
      )}
    </div>
  );
}
