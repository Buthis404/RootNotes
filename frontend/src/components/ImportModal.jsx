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

export default function ImportModal({ projectId, onClose, onImported, accent }) {
  const [activeTab, setActiveTab] = useState('parsers');
  const [mode, setMode] = useState('nmap');
  const [text, setText] = useState('');
  const [preview, setPreview] = useState(null);   // { hosts, creds }
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);     // { hosts_added, creds_added }
  const fileRef = useRef();

  // Nessus/Burp scanner state
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

  const doNessusImport = async () => {
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
  };

  const doBurpImport = async () => {
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
  };

  const currentMode = MODES.find(m => m.id === mode);

  const parse = async () => {
    setError('');
    setPreview(null);
    setResult(null);
    try {
      let parsed;
      if (currentMode.inputType === 'file') {
        const file = fileRef.current?.files?.[0];
        if (!file) { setError('Select a file'); return; }
        const content = await file.text();
        if (mode === 'nmap') parsed = parseNmapXml(content);
        else parsed = parseApsHtml(content);
      } else {
        if (!text.trim()) { setError('Enter text'); return; }
        parsed = parseNetexecText(text);
      }

      if (parsed.hosts.length === 0 && parsed.creds.length === 0) {
        setError('Nothing found in data. Check the format.');
        return;
      }
      setPreview(parsed);
    } catch (e) {
      setError('Parse error: ' + e.message);
    }
  };

  const doImport = async () => {
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
  };

  const NODE_STATUS_COLOR = {
    unknown: '#404550', alive: '#5b8af5', scanned: '#c07af0',
    access: '#f09a3a', pwned: '#cc2233', owned: '#39d353',
  };

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 500,
      background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 10,
        width: 680, maxHeight: '86vh', display: 'flex', flexDirection: 'column',
        boxShadow: '0 24px 80px #00000099',
      }}>
        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Import scan data</div>
            <div style={{ fontSize: 10, color: '#505560', marginTop: 2 }}>Hosts and credentials will be added to the current project</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', padding: 4 }}>
            <Icon name="close" size={14} color="#606570" />
          </button>
        </div>

        {/* Tab nav */}
        <div style={{ display: 'flex', gap: 2, padding: '10px 20px 0', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
          {TABS_NAV.map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              style={{ background: 'none', border: 'none', borderBottom: activeTab === t.id ? `2px solid ${accent}` : '2px solid transparent', padding: '6px 14px 8px', cursor: 'pointer', fontSize: 11, fontWeight: 600, color: activeTab === t.id ? accent : '#606570', fontFamily: 'JetBrains Mono', transition: 'color .15s', marginBottom: -1 }}>
              {t.label}
            </button>
          ))}
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* ── Scanners tab ── */}
          {activeTab === 'scanners' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {/* Nessus */}
              <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Icon name="target" size={14} color="#e8574a" />
                  <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>Nessus</span>
                </div>
                <div style={{ fontSize: 10, color: '#606570' }}>Import .nessus XML scan report</div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#0a0c10', border: '1px dashed #2a2d35', borderRadius: 6, padding: '10px 12px', cursor: 'pointer' }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = '#404550'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d35'}>
                  <Icon name="export" size={13} color="#404550" />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 10, color: nessusFile ? '#c8cdd6' : '#808590', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {nessusFile ? nessusFile.name : 'Select .nessus / .xml file'}
                    </div>
                  </div>
                  <input ref={nessusRef} type="file" accept=".xml,.nessus" style={{ display: 'none' }}
                    onChange={e => { setNessusFile(e.target.files?.[0] || null); setNessusResult(null); setNessusError(''); }} />
                </label>
                {nessusError && (
                  <div style={{ fontSize: 10, color: '#cc2233', background: '#cc223318', border: '1px solid #cc223344', borderRadius: 5, padding: '6px 10px' }}>{nessusError}</div>
                )}
                {nessusResult && (
                  <div style={{ fontSize: 10, color: '#39d353', background: '#39d35318', border: '1px solid #39d35344', borderRadius: 5, padding: '6px 10px' }}>
                    Imported: {nessusResult.hosts_created ?? nessusResult.hosts_added ?? '?'} hosts, {nessusResult.findings_created ?? nessusResult.findings_added ?? '?'} findings
                  </div>
                )}
                <button onClick={doNessusImport} disabled={!nessusFile || nessusLoading}
                  style={{ background: nessusFile && !nessusLoading ? accent : '#1e2029', border: 'none', borderRadius: 6, padding: '7px 14px', cursor: nessusFile && !nessusLoading ? 'pointer' : 'not-allowed', color: nessusFile && !nessusLoading ? '#fff' : '#404550', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, transition: 'all .15s' }}>
                  {nessusLoading ? (
                    <><span style={{ width: 10, height: 10, border: '2px solid #ffffff44', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' }} /> Importing...</>
                  ) : 'Import Nessus'}
                </button>
              </div>

              {/* Burp Suite */}
              <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Icon name="bug" size={14} color="#f09a3a" />
                  <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>Burp Suite</span>
                </div>
                <div style={{ fontSize: 10, color: '#606570' }}>Import Burp Suite XML scan report</div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#0a0c10', border: '1px dashed #2a2d35', borderRadius: 6, padding: '10px 12px', cursor: 'pointer' }}
                  onMouseEnter={e => e.currentTarget.style.borderColor = '#404550'}
                  onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d35'}>
                  <Icon name="export" size={13} color="#404550" />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 10, color: burpFile ? '#c8cdd6' : '#808590', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {burpFile ? burpFile.name : 'Select .xml file'}
                    </div>
                  </div>
                  <input ref={burpRef} type="file" accept=".xml" style={{ display: 'none' }}
                    onChange={e => { setBurpFile(e.target.files?.[0] || null); setBurpResult(null); setBurpError(''); }} />
                </label>
                {burpError && (
                  <div style={{ fontSize: 10, color: '#cc2233', background: '#cc223318', border: '1px solid #cc223344', borderRadius: 5, padding: '6px 10px' }}>{burpError}</div>
                )}
                {burpResult && (
                  <div style={{ fontSize: 10, color: '#39d353', background: '#39d35318', border: '1px solid #39d35344', borderRadius: 5, padding: '6px 10px' }}>
                    Imported: {burpResult.hosts_created ?? burpResult.hosts_added ?? '?'} hosts, {burpResult.findings_created ?? burpResult.findings_added ?? '?'} findings
                  </div>
                )}
                <button onClick={doBurpImport} disabled={!burpFile || burpLoading}
                  style={{ background: burpFile && !burpLoading ? accent : '#1e2029', border: 'none', borderRadius: 6, padding: '7px 14px', cursor: burpFile && !burpLoading ? 'pointer' : 'not-allowed', color: burpFile && !burpLoading ? '#fff' : '#404550', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, transition: 'all .15s' }}>
                  {burpLoading ? (
                    <><span style={{ width: 10, height: 10, border: '2px solid #ffffff44', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' }} /> Importing...</>
                  ) : 'Import Burp'}
                </button>
              </div>
            </div>
          )}

          {/* ── Parsers tab ── */}
          {activeTab === 'parsers' && <>
          {/* Mode selector */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8 }}>
            {MODES.map(m => (
              <button key={m.id} onClick={() => { setMode(m.id); setPreview(null); setError(''); setResult(null); setText(''); if (fileRef.current) fileRef.current.value = ''; }}
                style={{
                  background: mode === m.id ? `${m.color}15` : '#12141a',
                  border: `1px solid ${mode === m.id ? m.color + '66' : '#2a2d35'}`,
                  borderRadius: 7, padding: '10px 12px', cursor: 'pointer',
                  textAlign: 'left', transition: 'all .15s',
                }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
                  <Icon name={m.icon} size={13} color={mode === m.id ? m.color : '#505560'} />
                  <span style={{ fontSize: 11, fontWeight: 600, color: mode === m.id ? m.color : '#9098a8', fontFamily: 'JetBrains Mono' }}>{m.label}</span>
                </div>
                <div style={{ fontSize: 9, color: '#404550', lineHeight: 1.4 }}>{m.desc}</div>
              </button>
            ))}
          </div>

          {/* Input area */}
          {!result && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {currentMode.inputType === 'file' ? (
                <div>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>File ({currentMode.accept})</div>
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    background: '#0a0c10', border: '1px dashed #2a2d35', borderRadius: 6,
                    padding: '14px 16px', cursor: 'pointer', transition: 'border-color .15s',
                  }}
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
                  <textarea
                    value={text}
                    onChange={e => { setText(e.target.value); setPreview(null); setError(''); }}
                    placeholder={
`SMB  10.10.14.5  445  WEB-01   [*] Windows 10.0 Build 19041 (name:WEB-01) (domain:CORP)
SMB  10.10.14.5  445  WEB-01   [+] CORP\\administrator:Password123! (Pwn3d!)
SMB  10.10.14.6  445  APP-01   [-] CORP\\administrator:Password123! STATUS_LOGON_FAILURE
SSH  10.10.14.10 22   BACKEND  [+] deploy:secretkey`}
                    rows={9}
                    style={{
                      width: '100%', background: '#080a0e', border: '1px solid #2a2d35',
                      borderRadius: 6, padding: '10px 12px', color: '#c8cdd6',
                      fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono',
                      lineHeight: 1.6, resize: 'vertical',
                    }}
                  />
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
          )}

          {/* Preview */}
          {preview && !result && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Summary */}
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

              {/* Host list preview */}
              {preview.hosts.length > 0 && (
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 7, overflow: 'hidden' }}>
                  <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                    Hosts ({Math.min(preview.hosts.length, 8)} of {preview.hosts.length})
                  </div>
                  <div style={{ maxHeight: 200, overflowY: 'auto' }}>
                    {preview.hosts.slice(0, 8).map((h, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px', borderBottom: '1px solid #14161b' }}>
                        <span style={{ width: 7, height: 7, borderRadius: '50%', background: NODE_STATUS_COLOR[h.status] || '#404550', flexShrink: 0 }} />
                        <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#9098a8', width: 120, flexShrink: 0 }}>{h.ip}</span>
                        <span style={{ fontSize: 10, color: '#c8cdd6', width: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.hostname || '—'}</span>
                        <span style={{ fontSize: 9, color: '#505560' }}>{h.os}</span>
                        <div style={{ display: 'flex', gap: 3, flex: 1, overflow: 'hidden' }}>
                          {h.ports.slice(0, 5).map(p => (
                            <span key={p} style={{ fontSize: 9, color: NODE_STATUS_COLOR[h.status], background: `${NODE_STATUS_COLOR[h.status]}11`, border: `1px solid ${NODE_STATUS_COLOR[h.status]}33`, borderRadius: 3, padding: '0 4px', fontFamily: 'JetBrains Mono' }}>{p}</span>
                          ))}
                          {h.ports.length > 5 && <span style={{ fontSize: 9, color: '#404550' }}>+{h.ports.length - 5}</span>}
                        </div>
                      </div>
                    ))}
                    {preview.hosts.length > 8 && (
                      <div style={{ padding: '6px 12px', fontSize: 9, color: '#404550', textAlign: 'center' }}>... {preview.hosts.length - 8} more hosts</div>
                    )}
                  </div>
                </div>
              )}

              {/* Creds preview */}
              {preview.creds.length > 0 && (
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 7, overflow: 'hidden' }}>
                  <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                    Credentials
                  </div>
                  {preview.creds.slice(0, 6).map((c, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px', borderBottom: '1px solid #14161b' }}>
                      <span style={{ fontSize: 11, color: '#e0e4ec', fontFamily: 'JetBrains Mono', width: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.username}</span>
                      <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: 'JetBrains Mono', width: 110 }}>{c.host}</span>
                      <span style={{ fontSize: 9, color: '#606570' }}>{c.service}</span>
                      <span style={{ fontSize: 9, color: '#39d353', marginLeft: 'auto' }}>✓ cracked</span>
                    </div>
                  ))}
                  {preview.creds.length > 6 && (
                    <div style={{ padding: '6px 12px', fontSize: 9, color: '#404550', textAlign: 'center' }}>... {preview.creds.length - 6} more</div>
                  )}
                </div>
              )}

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
                  onMouseLeave={e => (e.currentTarget.style.opacity = loading ? '.7' : '1')}>
                  <Icon name="export" size={12} color="#fff" />
                  {loading ? 'Importing...' : 'Import'}
                </button>
                <button onClick={() => { setPreview(null); setError(''); }}
                  style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
                  Back
                </button>
              </div>
            </div>
          )}

          {/* Success */}
          {result && (
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
          )}
          </>}
        </div>
      </div>
    </div>
  );
}
