import PropTypes from 'prop-types';
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
        const sev = Number.parseInt(item.getAttribute('severity') || '0');
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

        const portInfo = port && port !== '0' ? ` [${port}/${protocol}]` : '';
        findings.push({
          host_ip: ip,
          host_os: os,
          title: `${title}${portInfo}`,
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

function _calcSevCounts(parsed) {
  return SEV_ORDER.reduce((acc, s) => {
    acc[s] = (parsed || []).filter(f => f.severity === s).length;
    return acc;
  }, {});
}

function NessusFooter({ parsed, raw, filtered, importing, result, accent, onClose, doParse, doImport }) {
  if (!parsed) {
    const canParse = raw.trim();
    return (
      <div style={{ padding: '14px 24px', borderTop: '1px solid #1e2029', display: 'flex', justifyContent: 'flex-end', gap: 8, flexShrink: 0 }}>
        <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Close</button>
        <button onClick={doParse} disabled={!canParse}
          style={{ background: canParse ? accent : '#2a2d35', border: 'none', borderRadius: 5, padding: '7px 18px', cursor: canParse ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
          Parse
        </button>
      </div>
    );
  }
  const canImport = filtered.length && !result;
  const importActionLabel = result ? 'Imported ✓' : `Import ${filtered.length} findings`;
  const importLabel = importing ? 'Importing...' : importActionLabel;
  return (
    <div style={{ padding: '14px 24px', borderTop: '1px solid #1e2029', display: 'flex', justifyContent: 'flex-end', gap: 8, flexShrink: 0 }}>
      <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Close</button>
      <button onClick={doImport} disabled={!filtered.length || importing || !!result}
        style={{ background: canImport ? accent : '#2a2d35', border: 'none', borderRadius: 5, padding: '7px 18px', cursor: canImport ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
        {importLabel}
      </button>
    </div>
  );
}
NessusFooter.propTypes = {
  parsed: PropTypes.any,
  raw: PropTypes.any,
  filtered: PropTypes.any,
  importing: PropTypes.any,
  result: PropTypes.any,
  accent: PropTypes.any,
  onClose: PropTypes.any,
  doParse: PropTypes.any,
  doImport: PropTypes.any,
};

function _doParse(raw, setError, setParsed, setResult) {
  setError('');
  const res = parseNessus(raw);
  if (!res) { setError('Could not parse file. Ensure it is .nessus (XML) format.'); return; }
  setParsed(res);
  setResult(null);
}

function _handleFile(e, setRaw, setParsed, setResult) {
  const file = e.target.files?.[0];
  if (!file) return;
  file.text().then(text => { setRaw(text); setParsed(null); setResult(null); });
}

async function _doImport(filtered, hosts, onImport, setImporting, setResult, setError) {
  if (!filtered.length) return;
  setImporting(true);
  try {
    const res = await onImport(filtered, hosts);
    setResult(res);
  } catch (e) {
    setError(e.message);
  }
  setImporting(false);
}

function NessusUnparsedView({ raw, setRaw, fileRef, handleFile, error, accent }) {
  return (
    <>
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
  );
}
NessusUnparsedView.propTypes = {
  raw: PropTypes.any,
  setRaw: PropTypes.any,
  fileRef: PropTypes.any,
  handleFile: PropTypes.any,
  error: PropTypes.any,
  accent: PropTypes.any,
};

function NessusParsedView({ parsed, filtered, sevCounts, skipInfo, setSkipInfo, setParsed, setResult, setError, result }) {
  return (
    <>
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
          <input type="checkbox" checked={skipInfo} onChange={e => setSkipInfo(e.target.checked)} />{' '}
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
            {filtered.map((f) => (
              <tr key={f.plugin_id || `${f.host_ip}-${f.port}-${f.title}`} style={{ borderBottom: '1px solid #14161b' }}
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
  );
}
NessusParsedView.propTypes = {
  parsed: PropTypes.any,
  filtered: PropTypes.any,
  sevCounts: PropTypes.any,
  skipInfo: PropTypes.any,
  setSkipInfo: PropTypes.any,
  setParsed: PropTypes.any,
  setResult: PropTypes.any,
  setError: PropTypes.any,
  result: PropTypes.any,
};

export default function NessusParser({ pid, hosts, onImport, onClose, accent }) {
  const [raw, setRaw] = useState('');
  const [parsed, setParsed] = useState(null);
  const [skipInfo, setSkipInfo] = useState(true);
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const fileRef = useRef();

  const doParse = () => _doParse(raw, setError, setParsed, setResult);
  const handleFile = (e) => _handleFile(e, setRaw, setParsed, setResult);
  const doImport = () => _doImport(filtered, hosts, onImport, setImporting, setResult, setError);

  const activeParsed = parsed || [];
  const filtered = skipInfo ? activeParsed.filter(f => f.severity !== 'info') : activeParsed;
  const sevCounts = _calcSevCounts(parsed);

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, width: 780, maxHeight: '88vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 64px #00000099' }}>
        <div style={{ padding: '18px 24px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <Icon name="bug" size={16} color={accent} />
          <span style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', flex: 1 }}>Nessus Import</span>
          <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>.nessus XML → Findings</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
            <Icon name="close" size={14} color="#606570" />
          </button>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '18px 24px' }}>
          {parsed ? (
            <NessusParsedView parsed={parsed} filtered={filtered} sevCounts={sevCounts} skipInfo={skipInfo} setSkipInfo={setSkipInfo} setParsed={setParsed} setResult={setResult} setError={setError} result={result} />
          ) : (
            <NessusUnparsedView raw={raw} setRaw={setRaw} fileRef={fileRef} handleFile={handleFile} error={error} accent={accent} />
          )}
        </div>

        <NessusFooter parsed={parsed} raw={raw} filtered={filtered} importing={importing} result={result} accent={accent} onClose={onClose} doParse={doParse} doImport={doImport} />
      </div>
    </div>
  );
}
NessusParser.propTypes = {
  pid: PropTypes.any,
  hosts: PropTypes.any,
  onImport: PropTypes.any,
  onClose: PropTypes.any,
  accent: PropTypes.any,
};
