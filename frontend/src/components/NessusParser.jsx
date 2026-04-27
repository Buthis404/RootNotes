import { useState, useRef } from 'react';
import Icon from './Icon.jsx';

const SEV_MAP = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low', 0: 'info' };
const SEV_COLORS = { critical: '#cc2233', high: '#e8574a', medium: '#f09a3a', low: '#e8cc42', info: '#5b8af5' };

function parseNessus(text) {
  try {
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    if (doc.querySelector('parsererror')) return null;

    const findings = [];
    for (const host of doc.querySelectorAll('ReportHost')) {
      const ip = host.getAttribute('name') || '';
      const osTag = host.querySelector('tag[name="operating-system"]') || host.querySelector('tag[name="os"]');
      const os = osTag?.textContent || '';

      for (const item of host.querySelectorAll('ReportItem')) {
        const sev = parseInt(item.getAttribute('severity') || '0');
        if (sev === 0) continue; // skip info by default

        const severity = SEV_MAP[sev] || 'info';
        const title = item.getAttribute('pluginName') || 'Unknown';
        const pluginId = item.getAttribute('pluginID') || '';
        const port = item.getAttribute('port') || '';
        const protocol = item.getAttribute('protocol') || 'tcp';
        const svcName = item.getAttribute('svc_name') || '';

        const cveEl = item.querySelector('cve');
        const cvssEl = item.querySelector('cvss3_base_score') || item.querySelector('cvss_base_score');
        const descEl = item.querySelector('description');
        const solEl  = item.querySelector('solution');
        const synEl  = item.querySelector('synopsis');
        const outEl  = item.querySelector('plugin_output');

        const cve  = cveEl?.textContent?.trim() || '';
        const cvss = cvssEl?.textContent?.trim() || '';
        const description = [
          synEl?.textContent?.trim(),
          descEl?.textContent?.trim(),
        ].filter(Boolean).join('\n\n');
        const proof = outEl?.textContent?.trim() || '';
        const recommendation = solEl?.textContent?.trim() || '';

        findings.push({
          host_ip: ip,
          host_os: os,
          title: `${title}${port && port !== '0' ? ` [${port}/${protocol}]` : ''}`,
          severity, cvss, cve,
          description: description.slice(0, 2000),
          proof: proof.slice(0, 1000),
          recommendation: recommendation.slice(0, 1000),
          plugin_id: pluginId,
          port, protocol, svc: svcName,
        });
      }
    }

    findings.sort((a, b) => {
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      return order.indexOf(a.severity) - order.indexOf(b.severity);
    });

    return findings;
  } catch {
    return null;
  }
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export default function NessusParser({ pid, hosts, onImport, onClose, accent }) {
  const [raw, setRaw] = useState('');
  const [parsed, setParsed] = useState(null);
  const [skipInfo, setSkipInfo] = useState(true);
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const fileRef = useRef();

  const doParse = () => {
    setError('');
    const res = parseNessus(raw);
    if (!res) { setError('Could not parse file. Ensure it is .nessus (XML) format.'); return; }
    setParsed(res);
    setResult(null);
  };

  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => { setRaw(ev.target.result); setParsed(null); setResult(null); };
    reader.readAsText(file);
  };

  const filtered = parsed ? (skipInfo ? parsed.filter(f => f.severity !== 'info') : parsed) : [];

  const doImport = async () => {
    if (!filtered.length) return;
    setImporting(true);
    try {
      const res = await onImport(filtered, hosts);
      setResult(res);
    } catch (e) {
      setError(e.message);
    }
    setImporting(false);
  };

  const sevCounts = SEV_ORDER.reduce((acc, s) => {
    acc[s] = (parsed || []).filter(f => f.severity === s).length;
    return acc;
  }, {});

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, width: 780, maxHeight: '88vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 64px #00000099' }}>
        {/* Header */}
        <div style={{ padding: '18px 24px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <Icon name="bug" size={16} color={accent} />
          <span style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', flex: 1 }}>Nessus Import</span>
          <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>.nessus XML → Findings</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
            <Icon name="close" size={14} color="#606570" />
          </button>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '18px 24px' }}>
          {!parsed ? (
            <>
              {/* File pick */}
              <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center' }}>
                <button onClick={() => fileRef.current?.click()}
                  style={{ background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Icon name="export" size={12} color={accent} /> Select .nessus file
                </button>
                <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>or paste XML below</span>
                <input ref={fileRef} type="file" accept=".nessus,.xml" style={{ display: 'none' }} onChange={handleFile} />
              </div>
              <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>XML content</div>
              <textarea value={raw} onChange={e => setRaw(e.target.value)}
                placeholder={'<?xml version="1.0" encoding="UTF-8"?>\n<NessusClientData_v2>\n  <Report name="My Scan">\n    ...\n  </Report>\n</NessusClientData_v2>'}
                style={{ width: '100%', height: 240, background: '#07080b', border: '1px solid #2a2d35', borderRadius: 6, padding: '14px 16px', color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono', lineHeight: 1.6, resize: 'vertical', outline: 'none' }} />
              {error && <div style={{ marginTop: 10, fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>{error}</div>}
            </>
          ) : (
            <>
              {/* Summary */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 12, color: '#39d353', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                  Found: {parsed.length} vulnerabilities
                </span>
                {SEV_ORDER.map(s => sevCounts[s] > 0 && (
                  <span key={s} style={{ fontSize: 10, color: SEV_COLORS[s], background: SEV_COLORS[s] + '18', border: `1px solid ${SEV_COLORS[s]}44`, borderRadius: 4, padding: '2px 8px', fontFamily: 'JetBrains Mono' }}>
                    {s}: {sevCounts[s]}
                  </span>
                ))}
                <button onClick={() => { setParsed(null); setResult(null); setError(''); }}
                  style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                  Edit
                </button>
                <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>
                  <input type="checkbox" checked={skipInfo} onChange={e => setSkipInfo(e.target.checked)} />
                  Skip Info
                </label>
              </div>

              {result && (
                <div style={{ padding: '10px 14px', background: result.error ? '#cc223318' : '#39d35318', border: `1px solid ${result.error ? '#cc2233' : '#39d353'}44`, borderRadius: 6, marginBottom: 14, fontSize: 12, color: result.error ? '#cc2233' : '#39d353', fontFamily: 'JetBrains Mono' }}>
                  {result.error ? `Error: ${result.error}` : `Imported: ${result.added} findings`}
                </div>
              )}

              <div style={{ maxHeight: 360, overflowY: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                  <thead>
                    <tr style={{ background: '#0d0f14' }}>
                      {['Sev', 'IP', 'Title', 'CVE', 'CVSS'].map(h => (
                        <th key={h} style={{ padding: '6px 10px', textAlign: 'left', color: '#505560', fontFamily: 'JetBrains Mono', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid #1e2029' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((f, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid #14161b' }}
                        onMouseEnter={e => e.currentTarget.style.background = '#ffffff04'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                        <td style={{ padding: '6px 10px' }}>
                          <span style={{ fontSize: 9, fontWeight: 700, color: SEV_COLORS[f.severity], background: SEV_COLORS[f.severity] + '22', border: `1px solid ${SEV_COLORS[f.severity]}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{f.severity}</span>
                        </td>
                        <td style={{ padding: '6px 10px', color: '#5b8af5', fontFamily: 'JetBrains Mono', fontSize: 10 }}>{f.host_ip}</td>
                        <td style={{ padding: '6px 10px', color: '#c8cdd6', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</td>
                        <td style={{ padding: '6px 10px', color: '#5b8af5', fontFamily: 'JetBrains Mono', fontSize: 10 }}>{f.cve || '—'}</td>
                        <td style={{ padding: '6px 10px', color: '#808590', fontFamily: 'JetBrains Mono', fontSize: 10 }}>{f.cvss || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '14px 24px', borderTop: '1px solid #1e2029', display: 'flex', justifyContent: 'flex-end', gap: 8, flexShrink: 0 }}>
          <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Close</button>
          {!parsed ? (
            <button onClick={doParse} disabled={!raw.trim()}
              style={{ background: raw.trim() ? accent : '#2a2d35', border: 'none', borderRadius: 5, padding: '7px 18px', cursor: raw.trim() ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
              Parse
            </button>
          ) : (
            <button onClick={doImport} disabled={!filtered.length || importing || !!result}
              style={{ background: filtered.length && !result ? accent : '#2a2d35', border: 'none', borderRadius: 5, padding: '7px 18px', cursor: (filtered.length && !result) ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
              {importing ? 'Importing...' : result ? 'Imported ✓' : `Import ${filtered.length} findings`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
