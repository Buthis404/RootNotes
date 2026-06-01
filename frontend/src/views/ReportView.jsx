import { useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { StatusDot, PhaseTag, HostStatusBadge, CredTypeBadge } from '../components/UI.jsx';
import { PHASES, PHASE_COLORS, NODE_STATUS, SEVERITY, FINDING_STATUS } from '../constants.js';
import { isAttackerHost } from '../utils/hostMeta.js';
import { api } from '../api.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function riskScore(findings) {
  const weights = { critical: 10, high: 5, medium: 2, low: 1, info: 0 };
  const raw = findings.reduce((s, f) => s + (weights[f.severity] || 0), 0);
  if (raw === 0) return { label: 'None', color: '#404550', score: 0 };
  if (raw >= 30) return { label: 'Critical', color: '#cc2233', score: Math.min(raw, 100) };
  if (raw >= 15) return { label: 'High', color: '#e8574a', score: Math.min(raw, 100) };
  if (raw >= 6)  return { label: 'Medium', color: '#f09a3a', score: Math.min(raw, 100) };
  return { label: 'Low', color: '#4a9eff', score: Math.min(raw, 100) };
}

function mdEscape(s) { return (s || '').replace(/\|/g, String.raw`\|`); }
function mdRow(...cells) { return '| ' + cells.map(c => mdEscape(String(c ?? ''))).join(' | ') + ' |'; }
function mdSep(n) { return '|' + ' --- |'.repeat(n); }

function ReportRow({ icon, label, value, color = '#9098a8' }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #14161b' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Icon name={icon} size={12} color="#404550" /><span style={{ fontSize: 11, color: '#808590' }}>{label}</span></div>
      <span style={{ fontSize: 12, fontWeight: 600, color, fontFamily: 'JetBrains Mono' }}>{value}</span>
    </div>
  );
}
ReportRow.propTypes = {
  icon: PropTypes.string,
  label: PropTypes.string,
  value: PropTypes.node,
  color: PropTypes.string,
};

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
    const pwnedCount = pHosts.filter(h => ['pwned', 'owned', 'access'].includes(h.status)).length;
    lines.push(
      '---', `title: "${safeName} — Pentest Report"`, `date: ${date}`, `project: "${safeName}"`, `risk: ${risk.label}`, `hosts: ${pHosts.length}`, `findings: ${pFindings.length}`, `credentials: ${pCreds.length}`, 'tags: [pentest, report]', '---', '',
      `# ${safeName} — Security Assessment Report`, '', `**Date:** ${date}  `, ...(proj?.ip ? [`**Target:** ${proj.ip}  `] : []), `**Overall Risk:** ${risk.label}  `, '',
      '## Executive Summary', '', `During this engagement **${pHosts.length} hosts** were identified, of which **${pwnedCount} were compromised**. **${pFindings.length} vulnerabilities** were discovered and **${pCreds.length} credentials** were collected.`, '',
      '| Metric | Value |', '| --- | --- |', `| Hosts in scope | ${pHosts.length} |`, `| Compromised hosts | ${pwnedCount} |`, `| Findings (total) | ${pFindings.length} |`, `| Critical findings | ${pFindings.filter(f => f.severity === 'critical').length} |`, `| High findings | ${pFindings.filter(f => f.severity === 'high').length} |`, `| Credentials collected | ${pCreds.length} |`, '',
    );

    // Findings
    if (pFindings.length > 0) {
      lines.push('## Findings', '', mdRow('Severity', 'Title', 'CVE', 'CVSS', 'Status'), mdSep(5));
      pFindings.forEach(f => {
        const st = FINDING_STATUS[f.status]?.label || f.status || 'open';
        lines.push(mdRow(f.severity?.toUpperCase() || '', f.title || '', f.cve || '', f.cvss || '', st));
      });
      lines.push('', '### Finding Details', '');
      pFindings.forEach((f, i) => {
        const linkedHost = pHosts.find(h => h.id === f.host_id);
        lines.push(`#### ${i + 1}. [${(f.severity || 'info').toUpperCase()}] ${f.title || 'Untitled'}`, '');
        if (f.cve)  lines.push(`**CVE:** ${f.cve}  `);
        if (f.cvss) lines.push(`**CVSS:** ${f.cvss}  `);
        if (linkedHost) {
          const hostInfo = linkedHost.hostname ? ` (${linkedHost.hostname})` : '';
          lines.push(`**Host:** ${linkedHost.ip}${hostInfo}  `);
        }
        lines.push('');
        if (f.description) {
          lines.push('**Description:**', '', f.description, '');
        }
        if (f.recommendation) {
          lines.push('**Recommendation:**', '', f.recommendation, '');
        }
        if (f.proof) {
          lines.push('**Proof of Concept:**', '', '```', f.proof, '```', '');
        }
        lines.push('---', '');
      });
    }

    // Hosts
    if (pHosts.length > 0) {
      lines.push('## Hosts', '', mdRow('IP', 'Hostname', 'OS', 'Domain', 'Status', 'Open Ports'), mdSep(6));
      pHosts.forEach(h => {
        const ports = (h.ports || []).slice(0, 10).join(', ');
        lines.push(mdRow(h.ip || '', h.hostname || '', h.os || '', h.domain || '', h.status || '', ports));
      });
      lines.push('');
    }

    // Credentials
    if (pCreds.length > 0) {
      lines.push('## Credentials', '', mdRow('Username', 'Domain', 'Type', 'Service', 'Host', 'Notes'), mdSep(6));
      pCreds.forEach(c => {
        lines.push(mdRow(c.username || '', c.domain || '', c.type || '', c.service || '', c.host || '', (c.notes || '').slice(0, 80)));
      });
      lines.push('');
    }

    // Activity log
    if (pActivities.length > 0) {
      lines.push('## Activity Log', '', mdRow('Date', 'Host', 'Type', 'Title', 'Status'), mdSep(5));
      pActivities.slice(0, 50).forEach(a => {
        const h = pHosts.find(x => x.id === a.host_id);
        const hostStr = h ? (() => {
          const suffix = h.hostname ? ` (${h.hostname})` : '';
          return `${h.ip}${suffix}`;
        })() : '';
        lines.push(mdRow(a.ts || '', hostStr, a.activity_type || '', a.title || '', a.status || ''));
      });
      lines.push('');
    }

    lines.push('---', `*Generated by RootNotes on ${new Date().toISOString()}*`);
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

  // ── HTML export (server-side, sanitized) ────────────────────────────

  const [htmlLoading, setHtmlLoading] = useState(false);

  const exportHTML = async () => {
    if (!selectedProject) return;
    setHtmlLoading(true);
    try {
      const { blob, filename } = await api.downloadReportHTML(selectedProject);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert('HTML export failed: ' + e.message);
    } finally {
      setHtmlLoading(false);
    }
  };

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
              disabled={htmlLoading}
              style={{ background: '#1e2230', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 14px', cursor: htmlLoading ? 'wait' : 'pointer', color: '#c8cdd6', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7, opacity: htmlLoading ? 0.6 : 1 }}>
              <Icon name="export" size={12} color="#808590" /> {htmlLoading ? 'Generating…' : 'HTML'}
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
            <ReportRow key={key} icon="hosts" label={label} value={count} color={color} />
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

ReportView.propTypes = {
  projects: PropTypes.array,
  notes: PropTypes.array,
  hosts: PropTypes.array,
  creds: PropTypes.array,
  findings: PropTypes.array,
  hostActivities: PropTypes.array,
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
  attackPaths: PropTypes.array,
  attackSteps: PropTypes.array,
};
