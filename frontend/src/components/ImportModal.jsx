import PropTypes from 'prop-types';
import { useState, useRef } from 'react';
import Icon from './Icon.jsx';
import { parseNmapXml, parseApsHtml, parseNetexecText } from '../utils/parsers.js';
import { api } from '../api.js';

const MODES = [
  {
    id: 'nmap',
    label: 'Nmap XML',
    icon: 'terminal',
    desc: '.xml file from nmap -oX',
    color: '#39d353',
    inputType: 'file',
    accept: '.xml',
  },
  {
    id: 'aps',
    label: 'Advanced Port Scanner',
    icon: 'hosts',
    desc: 'HTML report from APS',
    color: '#5b8af5',
    inputType: 'file',
    accept: '.html,.htm',
  },
  {
    id: 'netexec',
    label: 'NetExec / CME',
    icon: 'bolt',
    desc: 'Paste netexec or crackmapexec output',
    color: '#f09a3a',
    inputType: 'text',
  },
];

const TABS_NAV = [
  { id: 'parsers', label: 'Parsers' },
  { id: 'scanners', label: 'Scanners' },
];

async function _doNessusImport(projectId, nessusFile, setNessusLoading, setNessusError, setNessusResult, onImported) {
  if (!nessusFile) return;
  setNessusLoading(true);
  setNessusError('');
  setNessusResult(null);
  try {
    const res = await api.importNessus(projectId, nessusFile);
    setNessusResult(res);
    onImported();
  } catch (e) {
    setNessusError(e.message || 'Import failed');
  } finally {
    setNessusLoading(false);
  }
}

async function _doBurpImport(projectId, burpFile, setBurpLoading, setBurpError, setBurpResult, onImported) {
  if (!burpFile) return;
  setBurpLoading(true);
  setBurpError('');
  setBurpResult(null);
  try {
    const res = await api.importBurp(projectId, burpFile);
    setBurpResult(res);
    onImported();
  } catch (e) {
    setBurpError(e.message || 'Import failed');
  } finally {
    setBurpLoading(false);
  }
}

async function _doParse(mode, fileRef, text, setError, setPreview, setResult) {
  setError('');
  setPreview(null);
  setResult(null);
  try {
    const parsed = await parseFileInput(mode, fileRef, text);
    validateParsed(parsed);
    setPreview(parsed);
  } catch (e) {
    setError('Parse error: ' + e.message);
  }
}

async function _doImport(projectId, preview, setLoading, setError, setResult, onImported) {
  if (!preview) return;
  setLoading(true);
  setError('');
  try {
    const body = {
      hosts: preview.hosts.map(h => ({ ...h, pid: projectId })),
      creds: preview.creds.map(c => ({ ...c, pid: projectId })),
    };
    const res = await api.batchImport(projectId, body);
    setResult(res);
    onImported();
  } catch (e) {
    setError('Import error: ' + e.message);
  } finally {
    setLoading(false);
  }
}

async function parseFileInput(mode, fileRef, text) {
  const currentMode = MODES.find(m => m.id === mode);
  if (currentMode.inputType === 'file') {
    const file = fileRef.current?.files?.[0];
    if (!file) throw new Error('Select a file');
    const content = await file.text();
    if (mode === 'nmap') return parseNmapXml(content);
    return parseApsHtml(content);
  }
  if (!text.trim()) throw new Error('Enter text');
  return parseNetexecText(text);
}

function validateParsed(parsed) {
  if (parsed.hosts.length === 0 && parsed.creds.length === 0) {
    throw new Error('Nothing found in data. Check the format.');
  }
}

const NODE_STATUS_COLOR = {
  unknown: '#404550', alive: '#5b8af5', scanned: '#c07af0',
  access: '#f09a3a', pwned: '#cc2233', owned: '#39d353',
};

const SPINNER_STYLE = { width: 10, height: 10, border: '2px solid #ffffff44', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' };

function ScannerCard({ title, iconName, iconColor, desc, file, onFileChange, loading, result, error, fileRef, accept, onImport, importLabel, accent }) {
  const canImport = file && !loading;
  return (
    <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon name={iconName} size={14} color={iconColor} />
        <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>{title}</span>
      </div>
      <div style={{ fontSize: 10, color: '#606570' }}>{desc}</div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#0a0c10', border: '1px dashed #2a2d35', borderRadius: 6, padding: '10px 12px', cursor: 'pointer' }}
        onMouseEnter={e => e.currentTarget.style.borderColor = '#404550'}
        onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d35'}>
        <Icon name="export" size={13} color="#404550" />
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 10, color: file ? '#c8cdd6' : '#808590', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {file ? file.name : `Select ${accept} file`}
          </div>
        </div>
        <input ref={fileRef} type="file" accept={accept} style={{ display: 'none' }}
          onChange={onFileChange} />
      </label>
      {error && <div style={{ fontSize: 10, color: '#cc2233', background: '#cc223318', border: '1px solid #cc223344', borderRadius: 5, padding: '6px 10px' }}>{error}</div>}
      {result && (
        <div style={{ fontSize: 10, color: '#39d353', background: '#39d35318', border: '1px solid #39d35344', borderRadius: 5, padding: '6px 10px' }}>
          Imported: {result.hosts_created ?? result.hosts_added ?? '?'} hosts, {result.findings_created ?? result.findings_added ?? '?'} findings
        </div>
      )}
      <button onClick={onImport} disabled={!canImport}
        style={{ background: canImport ? accent : '#1e2029', border: 'none', borderRadius: 6, padding: '7px 14px', cursor: canImport ? 'pointer' : 'not-allowed', color: canImport ? '#fff' : '#404550', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, transition: 'all .15s' }}>
        {loading ? <><span style={SPINNER_STYLE} /> Importing...</> : importLabel}
      </button>
    </div>
  );
}
ScannerCard.propTypes = {
  title: PropTypes.any,
  iconName: PropTypes.any,
  iconColor: PropTypes.any,
  desc: PropTypes.any,
  file: PropTypes.any,
  onFileChange: PropTypes.any,
  loading: PropTypes.any,
  result: PropTypes.any,
  error: PropTypes.any,
  fileRef: PropTypes.any,
  accept: PropTypes.any,
  onImport: PropTypes.any,
  importLabel: PropTypes.any,
  accent: PropTypes.any,
};

function _onNessusFileChange(e, setNessusFile, setNessusResult, setNessusError) {
  setNessusFile(e.target.files?.[0] || null);
  setNessusResult(null);
  setNessusError('');
}

function _onBurpFileChange(e, setBurpFile, setBurpResult, setBurpError) {
  setBurpFile(e.target.files?.[0] || null);
  setBurpResult(null);
  setBurpError('');
}

function ScannersTab({ nessusFile, setNessusFile, nessusLoading, nessusResult, setNessusResult, nessusError, setNessusError, nessusRef, doNessusImport, burpFile, setBurpFile, burpLoading, burpResult, setBurpResult, burpError, setBurpError, burpRef, doBurpImport, accent }) {
  const onNessusChange = e => _onNessusFileChange(e, setNessusFile, setNessusResult, setNessusError);
  const onBurpChange = e => _onBurpFileChange(e, setBurpFile, setBurpResult, setBurpError);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      <ScannerCard title="Nessus" iconName="target" iconColor="#e8574a" desc="Import .nessus XML scan report"
        file={nessusFile} onFileChange={onNessusChange} loading={nessusLoading} result={nessusResult} error={nessusError}
        fileRef={nessusRef} accept=".xml,.nessus" onImport={doNessusImport} importLabel="Import Nessus" accent={accent} />
      <ScannerCard title="Burp Suite" iconName="bug" iconColor="#f09a3a" desc="Import Burp Suite XML scan report"
        file={burpFile} onFileChange={onBurpChange} loading={burpLoading} result={burpResult} error={burpError}
        fileRef={burpRef} accept=".xml" onImport={doBurpImport} importLabel="Import Burp" accent={accent} />
    </div>
  );
}
ScannersTab.propTypes = {
  nessusFile: PropTypes.any,
  setNessusFile: PropTypes.any,
  nessusLoading: PropTypes.any,
  nessusResult: PropTypes.any,
  setNessusResult: PropTypes.any,
  nessusError: PropTypes.any,
  setNessusError: PropTypes.any,
  nessusRef: PropTypes.any,
  doNessusImport: PropTypes.any,
  burpFile: PropTypes.any,
  setBurpFile: PropTypes.any,
  burpLoading: PropTypes.any,
  burpResult: PropTypes.any,
  setBurpResult: PropTypes.any,
  burpError: PropTypes.any,
  setBurpError: PropTypes.any,
  burpRef: PropTypes.any,
  doBurpImport: PropTypes.any,
  accent: PropTypes.any,
};

function ParsersInputArea({ currentMode, mode, fileRef, text, setText, setPreview, setError, setResult, error, parse, accent }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {currentMode.inputType === 'file' ? (
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>File ({currentMode.accept})</div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 10, background: '#0a0c10', border: '1px dashed #2a2d35', borderRadius: 6, padding: '14px 16px', cursor: 'pointer', transition: 'border-color .15s' }}
            onMouseEnter={e => e.currentTarget.style.borderColor = '#404550'}
            onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d35'}>
            <Icon name="export" size={16} color="#404550" />
            <div>
              <div style={{ fontSize: 11, color: '#9098a8' }}>Click to select or drag and drop a file</div>
              <div style={{ fontSize: 9, color: '#404550', marginTop: 2 }}>{currentMode.accept}</div>
            </div>
            <input ref={fileRef} type="file" accept={currentMode.accept} style={{ display: 'none' }}
              onChange={() => { setPreview(null); setError(''); setResult(null); }} />
          </label>
          {fileRef.current?.files?.[0] && (
            <div style={{ fontSize: 10, color: '#606570', marginTop: 6, fontFamily: 'JetBrains Mono' }}>
              {fileRef.current.files[0].name} · {(fileRef.current.files[0].size / 1024).toFixed(1)} KB
            </div>
          )}
        </div>
      ) : (
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            Output {mode === 'netexec' ? 'netexec / crackmapexec' : mode}
          </div>
          <textarea value={text}
            onChange={e => { setText(e.target.value); setPreview(null); setError(''); }}
            placeholder={`SMB  10.10.14.5  445  WEB-01   [*] Windows 10.0 Build 19041 (name:WEB-01) (domain:CORP)\nSMB  10.10.14.5  445  WEB-01   [+] CORP\\administrator:Password123! (Pwn3d!)\nSMB  10.10.14.6  445  APP-01   [-] CORP\\administrator:Password123! STATUS_LOGON_FAILURE\nSSH  10.10.14.10 22   BACKEND  [+] deploy:secretkey`}
            rows={9}
            style={{ width: '100%', background: '#080a0e', border: '1px solid #2a2d35', borderRadius: 6, padding: '10px 12px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', lineHeight: 1.6, resize: 'vertical' }} />
        </div>
      )}
      {error && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, background: '#cc223318', border: '1px solid #cc223344', borderRadius: 6, padding: '10px 12px' }}>
          <Icon name="warning" size={13} color="#cc2233" style={{ flexShrink: 0, marginTop: 1 }} />
          <span style={{ fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>{error}</span>
        </div>
      )}
      <button onClick={parse}
        style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7, alignSelf: 'flex-start', transition: 'opacity .1s' }}
        onMouseEnter={e => e.currentTarget.style.opacity = '.85'}
        onMouseLeave={e => e.currentTarget.style.opacity = '1'}>
        <Icon name="search" size={12} color="#fff" /> Parse
      </button>
    </div>
  );
}
ParsersInputArea.propTypes = {
  currentMode: PropTypes.any,
  mode: PropTypes.any,
  fileRef: PropTypes.any,
  text: PropTypes.any,
  setText: PropTypes.any,
  setPreview: PropTypes.any,
  setError: PropTypes.any,
  setResult: PropTypes.any,
  error: PropTypes.any,
  parse: PropTypes.any,
  accent: PropTypes.any,
};

function ParsersPreview({ preview, error, loading, doImport, setPreview, setError, accent }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10 }}>
        <div style={{ flex: 1, background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 7, padding: '12px 14px' }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#c07af0', fontFamily: 'Space Grotesk' }}>{preview.hosts.length}</div>
          <div style={{ fontSize: 10, color: '#606570', marginTop: 2 }}>hosts to import</div>
        </div>
        <div style={{ flex: 1, background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 7, padding: '12px 14px' }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#39d353', fontFamily: 'Space Grotesk' }}>{preview.creds.length}</div>
          <div style={{ fontSize: 10, color: '#606570', marginTop: 2 }}>credentials</div>
        </div>
      </div>
      {preview.hosts.length > 0 && <HostsPreviewTable hosts={preview.hosts} />}
      {preview.creds.length > 0 && <CredsPreviewTable creds={preview.creds} />}
      {error && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, background: '#cc223318', border: '1px solid #cc223344', borderRadius: 6, padding: '10px 12px' }}>
          <Icon name="warning" size={13} color="#cc2233" />
          <span style={{ fontSize: 11, color: '#cc2233' }}>{error}</span>
        </div>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={doImport} disabled={loading}
          style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 20px', cursor: loading ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7, opacity: loading ? .7 : 1, transition: 'opacity .1s' }}
          onMouseEnter={e => !loading && (e.currentTarget.style.opacity = '.85')}
          onMouseLeave={e => { e.currentTarget.style.opacity = loading ? '.7' : '1'; }}>
          <Icon name="export" size={12} color="#fff" />
          {loading ? 'Importing...' : 'Import'}
        </button>
        <button onClick={() => { setPreview(null); setError(''); }}
          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          Back
        </button>
      </div>
    </div>
  );
}
ParsersPreview.propTypes = {
  preview: PropTypes.any,
  error: PropTypes.any,
  loading: PropTypes.any,
  doImport: PropTypes.any,
  setPreview: PropTypes.any,
  setError: PropTypes.any,
  accent: PropTypes.any,
};

function HostsPreviewTable({ hosts }) {
  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 7, overflow: 'hidden' }}>
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
        Hosts ({Math.min(hosts.length, 8)} of {hosts.length})
      </div>
      <div style={{ maxHeight: 200, overflowY: 'auto' }}>
        {hosts.slice(0, 8).map((h) => {
          const statusColor = NODE_STATUS_COLOR[h.status] || '#404550';
          return (
            <div key={h.ip} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px', borderBottom: '1px solid #14161b' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: statusColor, flexShrink: 0 }} />
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#9098a8', width: 120, flexShrink: 0 }}>{h.ip}</span>
              <span style={{ fontSize: 10, color: '#c8cdd6', width: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.hostname || '—'}</span>
              <span style={{ fontSize: 9, color: '#505560' }}>{h.os}</span>
              <div style={{ display: 'flex', gap: 3, flex: 1, overflow: 'hidden' }}>
                {h.ports.slice(0, 5).map(p => (
                  <span key={p} style={{ fontSize: 9, color: statusColor, background: `${statusColor}11`, border: `1px solid ${statusColor}33`, borderRadius: 3, padding: '0 4px', fontFamily: 'JetBrains Mono' }}>{p}</span>
                ))}
                {h.ports.length > 5 && <span style={{ fontSize: 9, color: '#404550' }}>+{h.ports.length - 5}</span>}
              </div>
            </div>
          );
        })}
        {hosts.length > 8 && <div style={{ padding: '6px 12px', fontSize: 9, color: '#404550', textAlign: 'center' }}>... {hosts.length - 8} more hosts</div>}
      </div>
    </div>
  );
}
HostsPreviewTable.propTypes = {
  hosts: PropTypes.any,
};

function CredsPreviewTable({ creds }) {
  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 7, overflow: 'hidden' }}>
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
        Credentials
      </div>
      {creds.slice(0, 6).map((c) => (
        <div key={`${c.username}-${c.host}`} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px', borderBottom: '1px solid #14161b' }}>
          <span style={{ fontSize: 11, color: '#e0e4ec', fontFamily: 'JetBrains Mono', width: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.username}</span>
          <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: 'JetBrains Mono', width: 110 }}>{c.host}</span>
          <span style={{ fontSize: 9, color: '#606570' }}>{c.service}</span>
          <span style={{ fontSize: 9, color: '#39d353', marginLeft: 'auto' }}>✓ cracked</span>
        </div>
      ))}
      {creds.length > 6 && <div style={{ padding: '6px 12px', fontSize: 9, color: '#404550', textAlign: 'center' }}>... {creds.length - 6} more</div>}
    </div>
  );
}
CredsPreviewTable.propTypes = {
  creds: PropTypes.any,
};

function ParsersSuccess({ result, onClose, accent }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, padding: '20px 0' }}>
      <div style={{ width: 48, height: 48, borderRadius: '50%', background: '#39d35322', border: '1px solid #39d35366', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Icon name="check" size={24} color="#39d353" />
      </div>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 6 }}>Import complete</div>
        <div style={{ fontSize: 11, color: '#606570' }}>
          Hosts added: <strong style={{ color: '#c07af0' }}>{result.hosts_added}</strong>
          {' · '}
          Credentials: <strong style={{ color: '#39d353' }}>{result.creds_added}</strong>
          {' · '}
          Duplicates — merged
        </div>
      </div>
      <button onClick={onClose}
        style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 24px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
        Done
      </button>
    </div>
  );
}
ParsersSuccess.propTypes = {
  result: PropTypes.any,
  onClose: PropTypes.any,
  accent: PropTypes.any,
};

function ParsersTab({ mode, setMode, currentMode, fileRef, text, setText, preview, setPreview, error, setError, loading, result, setResult, doImport, parse, onClose, accent }) {
  const resetMode = id => { setMode(id); setPreview(null); setError(''); setResult(null); setText(''); if (fileRef.current) fileRef.current.value = ''; };
  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8 }}>
        {MODES.map(m => (
          <button key={m.id} onClick={() => resetMode(m.id)}
            style={{ background: mode === m.id ? `${m.color}15` : '#12141a', border: `1px solid ${mode === m.id ? m.color + '66' : '#2a2d35'}`, borderRadius: 7, padding: '10px 12px', cursor: 'pointer', textAlign: 'left', transition: 'all .15s' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
              <Icon name={m.icon} size={13} color={mode === m.id ? m.color : '#505560'} />
              <span style={{ fontSize: 11, fontWeight: 600, color: mode === m.id ? m.color : '#9098a8', fontFamily: 'JetBrains Mono' }}>{m.label}</span>
            </div>
            <div style={{ fontSize: 9, color: '#404550', lineHeight: 1.4 }}>{m.desc}</div>
          </button>
        ))}
      </div>
      {result && <ParsersSuccess result={result} onClose={onClose} accent={accent} />}
      {preview && !result && <ParsersPreview preview={preview} error={error} loading={loading} doImport={doImport} setPreview={setPreview} setError={setError} accent={accent} />}
      {!result && !preview && <ParsersInputArea currentMode={currentMode} mode={mode} fileRef={fileRef} text={text} setText={setText} setPreview={setPreview} setError={setError} setResult={setResult} error={error} parse={parse} accent={accent} />}
    </>
  );
}
ParsersTab.propTypes = {
  mode: PropTypes.any,
  setMode: PropTypes.any,
  currentMode: PropTypes.any,
  fileRef: PropTypes.any,
  text: PropTypes.any,
  setText: PropTypes.any,
  preview: PropTypes.any,
  setPreview: PropTypes.any,
  error: PropTypes.any,
  setError: PropTypes.any,
  loading: PropTypes.any,
  result: PropTypes.any,
  setResult: PropTypes.any,
  doImport: PropTypes.any,
  parse: PropTypes.any,
  onClose: PropTypes.any,
  accent: PropTypes.any,
};

export default function ImportModal({ projectId, onClose, onImported, accent }) {
  const [activeTab, setActiveTab] = useState('parsers');
  const [mode, setMode] = useState('nmap');
  const [text, setText] = useState('');
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const fileRef = useRef();

  const [nessusFile, setNessusFile] = useState(null);
  const [nessusLoading, setNessusLoading] = useState(false);
  const [nessusResult, setNessusResult] = useState(null);
  const [nessusError, setNessusError] = useState('');
  const [burpFile, setBurpFile] = useState(null);
  const [burpLoading, setBurpLoading] = useState(false);
  const [burpResult, setBurpResult] = useState(null);
  const [burpError, setBurpError] = useState('');
  const nessusRef = useRef();
  const burpRef = useRef();

  const doNessusImport = () => _doNessusImport(projectId, nessusFile, setNessusLoading, setNessusError, setNessusResult, onImported);
  const doBurpImport = () => _doBurpImport(projectId, burpFile, setBurpLoading, setBurpError, setBurpResult, onImported);
  const parse = () => _doParse(mode, fileRef, text, setError, setPreview, setResult);
  const doImport = () => _doImport(projectId, preview, setLoading, setError, setResult, onImported);

  const currentMode = MODES.find(m => m.id === mode);

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 500, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <button type="button" aria-label="Close import modal" onClick={onClose} style={{ position: 'absolute', inset: 0, background: 'transparent', border: 'none', cursor: 'default' }} />
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 10, width: 680, maxHeight: '86vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 80px #00000099' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Import scan data</div>
            <div style={{ fontSize: 10, color: '#505560', marginTop: 2 }}>Hosts and credentials will be added to the current project</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', padding: 4 }}>
            <Icon name="close" size={14} color="#606570" />
          </button>
        </div>

        <div style={{ display: 'flex', gap: 2, padding: '10px 20px 0', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
          {TABS_NAV.map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              style={{ background: 'none', border: 'none', borderBottom: activeTab === t.id ? `2px solid ${accent}` : '2px solid transparent', padding: '6px 14px 8px', cursor: 'pointer', fontSize: 11, fontWeight: 600, color: activeTab === t.id ? accent : '#606570', fontFamily: 'JetBrains Mono', transition: 'color .15s', marginBottom: -1 }}>
              {t.label}
            </button>
          ))}
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {activeTab === 'scanners' && (
            <ScannersTab nessusFile={nessusFile} setNessusFile={setNessusFile} nessusLoading={nessusLoading} nessusResult={nessusResult} setNessusResult={setNessusResult} nessusError={nessusError} setNessusError={setNessusError} nessusRef={nessusRef} doNessusImport={doNessusImport}
              burpFile={burpFile} setBurpFile={setBurpFile} burpLoading={burpLoading} burpResult={burpResult} setBurpResult={setBurpResult} burpError={burpError} setBurpError={setBurpError} burpRef={burpRef} doBurpImport={doBurpImport} accent={accent} />
          )}
          {activeTab === 'parsers' && (
            <ParsersTab mode={mode} setMode={setMode} currentMode={currentMode} fileRef={fileRef} text={text} setText={setText}
              preview={preview} setPreview={setPreview} error={error} setError={setError} loading={loading} result={result} setResult={setResult}
              doImport={doImport} parse={parse} onClose={onClose} accent={accent} />
          )}
        </div>
      </div>
    </div>
  );
}
ImportModal.propTypes = {
  projectId: PropTypes.any,
  onClose: PropTypes.any,
  onImported: PropTypes.any,
  accent: PropTypes.any,
};
