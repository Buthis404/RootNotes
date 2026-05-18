import { useState, useEffect, useCallback, useMemo } from 'react';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';

const SCAN_TYPES = [
  { id: 'nmap',     label: 'Nmap',            icon: 'target',   color: '#5b8af5', desc: 'Port scan → auto-fill hosts & ports' },
  { id: 'nuclei',   label: 'Nuclei',          icon: 'bug',      color: '#e8574a', desc: 'Vuln templates → auto-create findings' },
  { id: 'cme',      label: 'CME / NetExec',   icon: 'hosts',    color: '#c07af0', desc: 'AD enum → auto-fill hosts & creds' },
  { id: 'donpapi',  label: 'DonPAPI',         icon: 'key',      color: '#ffa726', desc: 'DPAPI dump → auto-harvest creds & loot artefacts' },
  { id: 'bulk',     label: 'Bulk Host Import',icon: 'plus',     color: '#f09a3a', desc: 'IP list or CIDR → batch add hosts' },
  { id: 'c2',       label: 'C2 Integrations', icon: 'bolt',     color: '#cc2233', desc: 'Adaptix / Mythic / Sliver → auto-sync sessions' },
  { id: 'sessions', label: 'Live Sessions',   icon: 'eye',      color: '#39d353', desc: 'All live agents across every C2 integration' },
  { id: 'webhook',  label: 'C2 Webhook',      icon: 'shield',   color: '#39d353', desc: 'Receive push callbacks from any C2 framework' },
];

const FieldRow = ({ label, children }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 12 }}>
    <label style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</label>
    {children}
  </div>
);

const Input = ({ value, onChange, placeholder, monospace, multiline, rows = 3 }) => {
  const base = {
    background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 5,
    padding: '7px 10px', color: '#c8cdd6', fontSize: 12,
    fontFamily: monospace ? 'JetBrains Mono' : 'inherit',
    outline: 'none', width: '100%', boxSizing: 'border-box',
  };
  return multiline
    ? <textarea value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} rows={rows} style={{ ...base, resize: 'vertical' }} />
    : <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} style={base} />;
};

const ResultBox = ({ result, error }) => {
  if (!result && !error) return null;
  if (error) return (
    <div style={{ background: '#1a0508', border: '1px solid #cc223344', borderRadius: 6, padding: 12, marginTop: 12, fontSize: 12, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>
      {error}
    </div>
  );
  return (
    <div style={{ background: '#0a1208', border: '1px solid #39d35344', borderRadius: 6, padding: 12, marginTop: 12, fontSize: 11, fontFamily: 'JetBrains Mono', color: '#c8cdd6', whiteSpace: 'pre-wrap', overflowX: 'auto', maxHeight: 300, overflowY: 'auto' }}>
      {typeof result === 'string' ? result : JSON.stringify(result, null, 2)}
    </div>
  );
};

function ExecutionSourceRow({ executionSource, setExecutionSource, pivotObservationId, setPivotObservationId, pivotOptions = [], loading = false }) {
  return (
    <>
      <FieldRow label="Execution source">
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {[
            { id: 'attacker', label: 'Attacker host', color: '#5b8af5' },
            { id: 'pivot_listener', label: 'Pivot listener', color: '#e8cc42' },
          ].map(opt => (
            <button key={opt.id} onClick={() => setExecutionSource(opt.id)}
              style={{ background: executionSource === opt.id ? `${opt.color}22` : '#1a1c22', border: `1px solid ${executionSource === opt.id ? opt.color : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: executionSource === opt.id ? opt.color : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {opt.label}
            </button>
          ))}
        </div>
      </FieldRow>
      {executionSource === 'pivot_listener' && (
        <FieldRow label="Pivot listener">
          <select value={pivotObservationId} onChange={e => setPivotObservationId(e.target.value)} style={{ background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 12, fontFamily: 'JetBrains Mono', outline: 'none', width: '100%', boxSizing: 'border-box' }}>
            <option value="">{loading ? 'Loading listeners...' : 'Select pivot listener...'}</option>
            {pivotOptions.map(item => (
              <option key={item.id} value={item.id}>{item.label}</option>
            ))}
          </select>
        </FieldRow>
      )}
    </>
  );
}

// ── Nmap Panel ────────────────────────────────────────────────────────
function NmapPanel({ pid, accent }) {
  const [target, setTarget] = useState('');
  const [flags, setFlags] = useState('-sV -sC -T4 --open');
  const [timeout, setTimeout_] = useState(180);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [executionSource, setExecutionSource] = useState('attacker');
  const [pivotObservationId, setPivotObservationId] = useState('');
  const [pivotOptions, setPivotOptions] = useState([]);
  const [pivotLoading, setPivotLoading] = useState(false);

  useEffect(() => {
    if (executionSource !== 'pivot_listener' || !pid) return;
    setPivotLoading(true);
    api.listPivots(pid).then(data => {
      const items = (data?.items || []).filter(item => item.status === 'active' && item.bind_address && ['socks4', 'socks5'].some(kind => String(item.pivot_type || '').toLowerCase().includes(kind)));
      setPivotOptions(items.map(item => ({ id: item.id, label: `${item.tool || 'pivot'} :: ${item.bind_address}${item.route_cidr ? ` :: ${item.route_cidr}` : ''}` })));
    }).catch(() => setPivotOptions([])).finally(() => setPivotLoading(false));
  }, [executionSource, pid]);

  const run = async () => {
    if (!target.trim()) return;
    if (executionSource === 'pivot_listener' && !pivotObservationId) return;
    setRunning(true); setResult(null); setError('');
    try {
      const r = await api.runNmapScan(pid, { target, flags, execution_source: executionSource, pivot_observation_id: executionSource === 'pivot_listener' ? pivotObservationId : null, timeout_seconds: timeout });
      setResult(`Hosts found: ${r.hosts_found}\nCreated: ${r.hosts_created}\nUpdated: ${r.hosts_updated}${r.stderr ? '\n\nSTDERR:\n' + r.stderr : ''}`);
    } catch (e) {
      setError(e.message || 'Scan failed');
    }
    setRunning(false);
  };

  return (
    <div>
      <FieldRow label="Target (IP / CIDR / hostname)">
        <Input value={target} onChange={setTarget} placeholder="10.0.0.0/24 or 192.168.1.1" />
      </FieldRow>
      <FieldRow label="Nmap flags">
        <Input value={flags} onChange={setFlags} placeholder="-sV -sC -T4 --open" monospace />
      </FieldRow>
      <ExecutionSourceRow executionSource={executionSource} setExecutionSource={setExecutionSource} pivotObservationId={pivotObservationId} setPivotObservationId={setPivotObservationId} pivotOptions={pivotOptions} loading={pivotLoading} />
      <FieldRow label="Timeout (seconds)">
        <Input value={String(timeout)} onChange={v => setTimeout_(parseInt(v) || 180)} />
      </FieldRow>
      <button onClick={run} disabled={running || !target.trim()}
        style={{ background: running ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '8px 18px', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: running ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
        <Icon name="target" size={12} color="#fff" />
        {running ? 'Scanning...' : 'Run Nmap'}
      </button>
      <ResultBox result={result} error={error} />
    </div>
  );
}

// ── Nuclei Panel ──────────────────────────────────────────────────────
function NucleiPanel({ pid, accent }) {
  const [target, setTarget] = useState('');
  const [templates, setTemplates] = useState('');
  const [severity, setSeverity] = useState('critical,high,medium');
  const [extra, setExtra] = useState('');
  const [timeout, setTimeout_] = useState(300);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [executionSource, setExecutionSource] = useState('attacker');
  const [pivotObservationId, setPivotObservationId] = useState('');
  const [pivotOptions, setPivotOptions] = useState([]);
  const [pivotLoading, setPivotLoading] = useState(false);

  useEffect(() => {
    if (executionSource !== 'pivot_listener' || !pid) return;
    setPivotLoading(true);
    api.listPivots(pid).then(data => {
      const items = (data?.items || []).filter(item => item.status === 'active' && item.bind_address && ['socks4', 'socks5'].some(kind => String(item.pivot_type || '').toLowerCase().includes(kind)));
      setPivotOptions(items.map(item => ({ id: item.id, label: `${item.tool || 'pivot'} :: ${item.bind_address}${item.route_cidr ? ` :: ${item.route_cidr}` : ''}` })));
    }).catch(() => setPivotOptions([])).finally(() => setPivotLoading(false));
  }, [executionSource, pid]);

  const run = async () => {
    if (!target.trim()) return;
    if (executionSource === 'pivot_listener' && !pivotObservationId) return;
    setRunning(true); setResult(null); setError('');
    try {
      const r = await api.runNucleiScan(pid, { target, templates, severity, extra_flags: extra, execution_source: executionSource, pivot_observation_id: executionSource === 'pivot_listener' ? pivotObservationId : null, timeout_seconds: timeout });
      setResult(`Findings found: ${r.findings_found}\nCreated: ${r.findings_created}${r.stderr ? '\n\nSTDERR:\n' + r.stderr : ''}`);
    } catch (e) {
      setError(e.message || 'Scan failed');
    }
    setRunning(false);
  };

  return (
    <div>
      <FieldRow label="Target URL">
        <Input value={target} onChange={setTarget} placeholder="http://10.0.0.1 or https://target.example.com" />
      </FieldRow>
      <FieldRow label="Templates path (blank = default)">
        <Input value={templates} onChange={setTemplates} placeholder="/root/nuclei-templates/cves/" monospace />
      </FieldRow>
      <FieldRow label="Severity">
        <Input value={severity} onChange={setSeverity} placeholder="critical,high,medium,low" monospace />
      </FieldRow>
      <FieldRow label="Extra flags">
        <Input value={extra} onChange={setExtra} placeholder="-tags cve,rce" monospace />
      </FieldRow>
      <ExecutionSourceRow executionSource={executionSource} setExecutionSource={setExecutionSource} pivotObservationId={pivotObservationId} setPivotObservationId={setPivotObservationId} pivotOptions={pivotOptions} loading={pivotLoading} />
      <FieldRow label="Timeout (seconds)">
        <Input value={String(timeout)} onChange={v => setTimeout_(parseInt(v) || 300)} />
      </FieldRow>
      <button onClick={run} disabled={running || !target.trim()}
        style={{ background: running ? '#1a1c22' : '#e8574a', border: 'none', borderRadius: 5, padding: '8px 18px', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: running ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
        <Icon name="bug" size={12} color="#fff" />
        {running ? 'Scanning...' : 'Run Nuclei'}
      </button>
      <ResultBox result={result} error={error} />
    </div>
  );
}

// ── CME Panel ─────────────────────────────────────────────────────────
function CmePanel({ pid, accent }) {
  const [target, setTarget] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [domain, setDomain] = useState('');
  const [hash, setHash] = useState('');
  const [protocol, setProtocol] = useState('smb');
  const [extra, setExtra] = useState('--users');
  const [timeout, setTimeout_] = useState(120);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [executionSource, setExecutionSource] = useState('attacker');
  const [pivotObservationId, setPivotObservationId] = useState('');
  const [pivotOptions, setPivotOptions] = useState([]);
  const [pivotLoading, setPivotLoading] = useState(false);

  useEffect(() => {
    if (executionSource !== 'pivot_listener' || !pid) return;
    setPivotLoading(true);
    api.listPivots(pid).then(data => {
      const items = (data?.items || []).filter(item => item.status === 'active' && item.bind_address && ['socks4', 'socks5'].some(kind => String(item.pivot_type || '').toLowerCase().includes(kind)));
      setPivotOptions(items.map(item => ({ id: item.id, label: `${item.tool || 'pivot'} :: ${item.bind_address}${item.route_cidr ? ` :: ${item.route_cidr}` : ''}` })));
    }).catch(() => setPivotOptions([])).finally(() => setPivotLoading(false));
  }, [executionSource, pid]);

  const run = async () => {
    if (!target.trim()) return;
    if (executionSource === 'pivot_listener' && !pivotObservationId) return;
    setRunning(true); setResult(null); setError('');
    try {
      const r = await api.runCmeScan(pid, { target, username, password, domain, hash, protocol, extra_flags: extra, execution_source: executionSource, pivot_observation_id: executionSource === 'pivot_listener' ? pivotObservationId : null, timeout_seconds: timeout });
      setResult(`Hosts found: ${r.hosts_found} (created: ${r.hosts_created})\nCreds found: ${r.creds_found} (created: ${r.creds_created})${r.stdout ? '\n\nOutput:\n' + r.stdout : ''}${r.stderr ? '\n\nSTDERR:\n' + r.stderr : ''}`);
    } catch (e) {
      setError(e.message || 'Scan failed');
    }
    setRunning(false);
  };

  return (
    <div>
      <FieldRow label="Target (IP / CIDR / subnet)">
        <Input value={target} onChange={setTarget} placeholder="10.0.0.0/24 or 192.168.1.0/24" />
      </FieldRow>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
        <FieldRow label="Username"><Input value={username} onChange={setUsername} placeholder="administrator" /></FieldRow>
        <FieldRow label="Password"><Input value={password} onChange={setPassword} placeholder="Password123!" /></FieldRow>
        <FieldRow label="Domain"><Input value={domain} onChange={setDomain} placeholder="CORP.LOCAL" /></FieldRow>
        <FieldRow label="Hash (NT)"><Input value={hash} onChange={setHash} placeholder="aad3b435...31d6cfe0" monospace /></FieldRow>
      </div>
      <FieldRow label="Protocol">
        <div style={{ display: 'flex', gap: 6 }}>
          {['smb', 'winrm', 'rdp', 'ldap', 'mssql'].map(p => (
            <button key={p} onClick={() => setProtocol(p)}
              style={{ background: protocol === p ? `${accent}22` : '#1a1c22', border: `1px solid ${protocol === p ? accent : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: protocol === p ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {p}
            </button>
          ))}
        </div>
      </FieldRow>
      <FieldRow label="Extra flags">
        <Input value={extra} onChange={setExtra} placeholder="--users --groups --shares" monospace />
      </FieldRow>
      <ExecutionSourceRow executionSource={executionSource} setExecutionSource={setExecutionSource} pivotObservationId={pivotObservationId} setPivotObservationId={setPivotObservationId} pivotOptions={pivotOptions} loading={pivotLoading} />
      <button onClick={run} disabled={running || !target.trim()}
        style={{ background: running ? '#1a1c22' : '#c07af0', border: 'none', borderRadius: 5, padding: '8px 18px', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: running ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
        <Icon name="hosts" size={12} color="#fff" />
        {running ? 'Running...' : 'Run NetExec'}
      </button>
      <ResultBox result={result} error={error} />
    </div>
  );
}

// ── DonPAPI Panel ─────────────────────────────────────────────────────
function DonpapiPanel({ pid, accent }) {
  const [target, setTarget] = useState('');
  const [username, setUsername] = useState('');
  const [domain, setDomain] = useState('');
  const [password, setPassword] = useState('');
  const [nthash, setNthash] = useState('');
  const [extra, setExtra] = useState('');
  const [fetchLoot, setFetchLoot] = useState(true);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const run = async () => {
    if (!target.trim() || !username.trim() || (!password.trim() && !nthash.trim())) return;
    setRunning(true); setResult(null); setError('');
    try {
      const r = await api.runDonpapiScan(pid, {
        target: target.trim(), username: username.trim(), domain: domain.trim(),
        password, nthash: nthash.trim(), extra_flags: extra, fetch_loot: fetchLoot,
      });
      const parts = [`Creds harvested: ${r.creds_created}`];
      if (r.loot_id) parts.push(`Loot artefact: ${r.loot_id}`);
      if (r.output_dir) parts.push(`Output dir on attacker box: ${r.output_dir}`);
      setResult(parts.join('\n'));
    } catch (e) {
      setError(e.message || 'DonPAPI run failed');
    }
    setRunning(false);
  };

  return (
    <div>
      <FieldRow label="Target (IP or comma-list)">
        <Input value={target} onChange={setTarget} placeholder="10.0.0.5" />
      </FieldRow>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
        <FieldRow label="Username"><Input value={username} onChange={setUsername} placeholder="administrator" /></FieldRow>
        <FieldRow label="Domain"><Input value={domain} onChange={setDomain} placeholder="CORP.LOCAL" /></FieldRow>
        <FieldRow label="Password"><Input value={password} onChange={setPassword} placeholder="Password123!" /></FieldRow>
        <FieldRow label="NT hash (alt to password)"><Input value={nthash} onChange={setNthash} placeholder="aad3b435...31d6cfe0" monospace /></FieldRow>
      </div>
      <FieldRow label="Extra donpapi flags">
        <Input value={extra} onChange={setExtra} placeholder="--no-browser --no-vault" monospace />
      </FieldRow>
      <FieldRow label="Auto-fetch loot tarball">
        <button onClick={() => setFetchLoot(v => !v)}
          style={{ alignSelf: 'flex-start', background: fetchLoot ? `${accent}22` : '#1a1c22', border: `1px solid ${fetchLoot ? accent : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: fetchLoot ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {fetchLoot ? '✓ Fetch tarball' : 'Skip tarball'}
        </button>
      </FieldRow>
      <button onClick={run} disabled={running || !target.trim() || !username.trim() || (!password.trim() && !nthash.trim())}
        style={{ background: running ? '#1a1c22' : '#ffa726', border: 'none', borderRadius: 5, padding: '8px 18px', color: '#0a0c10', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: running ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
        <Icon name="key" size={12} color="#0a0c10" />
        {running ? 'Running...' : 'Run DonPAPI'}
      </button>
      <ResultBox result={result} error={error} />
    </div>
  );
}

// ── Bulk Import Panel ─────────────────────────────────────────────────
function BulkImportPanel({ pid, accent }) {
  const [text, setText] = useState('');
  const [tags, setTags] = useState('');
  const [os_, setOs_] = useState('Linux');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const run = async () => {
    if (!text.trim()) return;
    setLoading(true); setResult(null); setError('');
    try {
      const tagList = tags.split(',').map(t => t.trim()).filter(Boolean);
      const r = await api.bulkImportHosts({ pid, text, tags: tagList, os: os_ });
      setResult(`Created: ${r.created}\nSkipped (already exist): ${r.skipped}`);
    } catch (e) {
      setError(e.message || 'Import failed');
    }
    setLoading(false);
  };

  return (
    <div>
      <FieldRow label="IP addresses / CIDR ranges">
        <Input value={text} onChange={setText} placeholder={"192.168.1.0/24\n10.0.0.1\n172.16.0.1-10"} multiline rows={6} monospace />
      </FieldRow>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <FieldRow label="OS">
          <div style={{ display: 'flex', gap: 5 }}>
            {['Linux', 'Windows', 'Unknown'].map(o => (
              <button key={o} onClick={() => setOs_(o)}
                style={{ background: os_ === o ? `${accent}22` : '#1a1c22', border: `1px solid ${os_ === o ? accent : '#2a2d35'}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: os_ === o ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                {o}
              </button>
            ))}
          </div>
        </FieldRow>
        <FieldRow label="Tags (comma-separated)">
          <Input value={tags} onChange={setTags} placeholder="internal,web,ad" />
        </FieldRow>
      </div>
      <button onClick={run} disabled={loading || !text.trim()}
        style={{ background: loading ? '#1a1c22' : '#f09a3a', border: 'none', borderRadius: 5, padding: '8px 18px', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
        <Icon name="plus" size={12} color="#fff" />
        {loading ? 'Importing...' : 'Import Hosts'}
      </button>
      <ResultBox result={result} error={error} />
    </div>
  );
}

// ── Webhook Panel ─────────────────────────────────────────────────────
function WebhookPanel({ pid, accent }) {
  const [token, setToken] = useState('');
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(true);
  const [regenerating, setRegenerating] = useState(false);
  const [copied, setCopied] = useState('');

  const load = useCallback(async () => {
    if (!pid) return;
    try {
      const r = await api.getProjectWebhook(pid);
      setToken(r.token || '');
      setUrl(r.url || '');
    } catch {}
    setLoading(false);
  }, [pid]);

  useEffect(() => { load(); }, [load]);

  const regenerate = async () => {
    setRegenerating(true);
    try {
      const r = await api.regenerateProjectWebhook(pid);
      setToken(r.token);
      setUrl(r.url);
    } catch {}
    setRegenerating(false);
  };

  const copy = (text, key) => {
    navigator.clipboard.writeText(text).then(() => { setCopied(key); setTimeout(() => setCopied(''), 1500); });
  };

  const fullUrl = url ? `${window.location.origin}${url}` : '';

  const examplePayload = JSON.stringify({
    type: "beacon",
    ip: "10.0.0.45",
    hostname: "DC01",
    os: "Windows Server 2019",
    username: "CORP\\administrator",
    domain: "CORP.LOCAL",
    source: "adaptix",
  }, null, 2);

  return (
    <div>
      {loading ? (
        <div style={{ color: '#404550', fontSize: 12 }}>Loading...</div>
      ) : (
        <>
          <div style={{ background: '#0c0e13', border: '1px solid #1a1c22', borderRadius: 6, padding: 14, marginBottom: 14 }}>
            <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Webhook URL</div>
            {token ? (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <code style={{ flex: 1, fontSize: 11, color: '#a0c0ff', fontFamily: 'JetBrains Mono', wordBreak: 'break-all' }}>{fullUrl}</code>
                <button onClick={() => copy(fullUrl, 'url')}
                  style={{ background: copied === 'url' ? '#39d35322' : '#1a1c22', border: `1px solid ${copied === 'url' ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: copied === 'url' ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
                  {copied === 'url' ? 'Copied!' : 'Copy'}
                </button>
              </div>
            ) : (
              <div style={{ fontSize: 12, color: '#505560' }}>No webhook configured. Click Generate to create one.</div>
            )}
          </div>

          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <button onClick={regenerate} disabled={regenerating}
              style={{ background: regenerating ? '#1a1c22' : '#cc2233', border: 'none', borderRadius: 5, padding: '7px 14px', cursor: regenerating ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
              {regenerating ? 'Generating...' : token ? 'Regenerate token' : 'Generate token'}
            </button>
            {token && (
              <button onClick={() => copy(token, 'token')}
                style={{ background: copied === 'token' ? '#39d35322' : '#1a1c22', border: `1px solid ${copied === 'token' ? '#39d353' : '#2a2d35'}`, borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: copied === 'token' ? '#39d353' : '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
                {copied === 'token' ? 'Token copied!' : 'Copy token'}
              </button>
            )}
          </div>

          <div style={{ fontSize: 10, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Supported event types</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16 }}>
            {[
              { type: 'beacon', color: '#cc2233', desc: 'New implant / session — creates host + cred' },
              { type: 'implant', color: '#cc2233', desc: 'Alias for beacon' },
              { type: 'cred', color: '#c07af0', desc: 'Credential dump — creates cred record' },
              { type: 'hash', color: '#c07af0', desc: 'NTLM hash — creates cred with type=hash' },
              { type: 'finding', color: '#e8574a', desc: 'Vulnerability — creates finding' },
            ].map(({ type, color, desc }) => (
              <div key={type} title={desc}
                style={{ background: `${color}18`, border: `1px solid ${color}44`, borderRadius: 12, padding: '3px 10px', fontSize: 10, color, fontFamily: 'JetBrains Mono', cursor: 'default' }}>
                {type}
              </div>
            ))}
          </div>

          <div style={{ fontSize: 10, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Example payload (beacon)</div>
          <div style={{ position: 'relative' }}>
            <pre style={{ background: '#0c0e13', border: '1px solid #1a1c22', borderRadius: 6, padding: 12, fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono', overflowX: 'auto', margin: 0 }}>
              {examplePayload}
            </pre>
            <button onClick={() => copy(examplePayload, 'example')}
              style={{ position: 'absolute', top: 8, right: 8, background: copied === 'example' ? '#39d35322' : '#1a1c22', border: `1px solid ${copied === 'example' ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: copied === 'example' ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {copied === 'example' ? 'Copied!' : 'Copy'}
            </button>
          </div>

          <div style={{ marginTop: 14, fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', lineHeight: 1.8 }}>
            <div style={{ marginBottom: 4, color: '#505560' }}>Usage examples:</div>
            <div>curl -s -X POST {fullUrl || '<webhook_url>'} \</div>
            <div>&nbsp;&nbsp;-H 'Content-Type: application/json' \</div>
            <div>&nbsp;&nbsp;-d '{"{\"type\":\"beacon\",\"ip\":\"10.0.0.1\",\"username\":\"CORP\\\\admin\"}"}'</div>
          </div>
        </>
      )}
    </div>
  );
}

// ── C2 Integrations Panel ─────────────────────────────────────────────
const C2_TYPES = [
  { id: 'adaptix',       label: 'Adaptix',        color: '#c07af0', hint: 'REST API under /endpoint path. Username + password (or token). URL: https://host:port' },
  { id: 'mythic',        label: 'Mythic',         color: '#ffa726', hint: 'GraphQL API. Username + password OR apitoken (Settings → API Tokens). URL: https://host:7443' },
  { id: 'sliver',        label: 'Sliver',         color: '#5b8af5', hint: 'gRPC multiplayer. Paste the operator config JSON from sliver-server: `operator --name X --lhost ... --save .`' },
];

const EMPTY_FORM = { name: '', type: 'adaptix', url: '', token: '', username: '', password: '', endpoint: '/endpoint', verify_ssl: false, project_ids: [], enabled: true, sync_interval_minutes: 0, has_token: false, has_password: false };

const SESSION_STATUS = {
  true:  { color: '#39d353', label: 'Active' },
  false: { color: '#6a7080', label: 'Dead'   },
};

function C2SessionsPanel({ pid, accent, onNavigateToHost }) {
  const [sessions, setSessions] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [markingId, setMarkingId] = useState('');

  const load = useCallback(async () => {
    if (!pid) return;
    setLoading(true); setError('');
    try {
      const data = await api.getC2LiveSessions(pid);
      setSessions(data);
    } catch (e) {
      setError(e.message || 'Failed to fetch sessions');
    }
    setLoading(false);
  }, [pid]);

  useEffect(() => { load(); }, [load]);

  const markStatus = async (hostId, status) => {
    if (!hostId) return;
    setMarkingId(hostId);
    try {
      await api.updateHost(hostId, { status });
      // Refresh sessions to update matched_host_status
      setSessions(prev => prev ? prev.map(s => s.matched_host_id === hostId ? { ...s, matched_host_status: status } : s) : prev);
    } catch {}
    setMarkingId('');
  };

  const grouped = useMemo(() => {
    if (!sessions) return {};
    const map = {};
    for (const s of sessions) {
      const key = s.integration_name || s.integration_id;
      if (!map[key]) map[key] = { name: key, type: s.integration_type, sessions: [], error: null, deadCount: 0 };
      if (s.error) { map[key].error = s.error; continue; }
      if (s.alive === false) { map[key].deadCount++; continue; }
      map[key].sessions.push(s);
    }
    return map;
  }, [sessions]);

  const acc = accent || '#5b8af5';
  const typeColors = { adaptix: '#00bcd4', mythic: '#ffa726', sliver: '#8bc34a' };

  return (
    <div style={{ marginTop: 20, borderTop: '1px solid #1e2230', paddingTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec' }}>Live Sessions</span>
        <button onClick={load} disabled={loading}
          style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {loading ? 'Loading...' : 'Refresh'}
        </button>
        {sessions && <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>{sessions.filter(s => !s.error && s.alive !== false).length} live agent(s)</span>}
      </div>

      {error && <div style={{ fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono', marginBottom: 8 }}>{error}</div>}

      {sessions && Object.values(grouped).map(group => (
        <div key={group.name} style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
            <span style={{ fontSize: 10, color: typeColors[group.type] || '#808590', background: `${typeColors[group.type] || '#808590'}18`, border: `1px solid ${typeColors[group.type] || '#808590'}44`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{group.type}</span>
            <span style={{ fontSize: 11, color: '#808590' }}>{group.name}</span>
            {group.deadCount > 0 && <span title={`${group.deadCount} dead agents hidden`} style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>({group.deadCount} dead hidden)</span>}
          </div>
          {group.error && (
            <div style={{ fontSize: 10, color: '#cc2233', fontFamily: 'JetBrains Mono', padding: '6px 8px', background: '#1a0508', border: '1px solid #cc223333', borderRadius: 4 }}>{group.error}</div>
          )}
          {group.sessions.length === 0 && !group.error && (
            <div style={{ fontSize: 10, color: '#404550', padding: '6px 0', fontFamily: 'JetBrains Mono' }}>No active agents</div>
          )}
          {group.sessions.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1e2230' }}>
                  {['', 'Host', 'IP', 'Privilege', 'User', 'OS', 'Process / Listener', 'Last seen', 'Action'].map((h, i) => (
                    <th key={i} style={{ padding: '4px 8px', color: '#404550', fontWeight: 500, fontSize: 10, textAlign: 'left', fontFamily: 'JetBrains Mono' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {group.sessions.map((s, idx) => {
                  const stCfg = SESSION_STATUS[String(s.alive)] || SESSION_STATUS.true;
                  const userStr = [s.username, s.domain].filter(Boolean).join('@') || '—';
                  const os = [s.os, s.arch].filter(Boolean).join(' ') || '—';
                  const procListener = [s.process, s.listener].filter(Boolean).join(' / ') || '—';
                  const tier = s.privilege_tier || 'user';
                  const privColors = { system: '#cc2233', admin: '#f09a3a', user: '#5b8af5' };
                  const privColor = privColors[tier] || '#808590';
                  const suggestedStatus = s.suggested_status || (tier === 'user' ? 'access' : 'pwned');
                  const actionLabel = suggestedStatus === 'pwned' ? '→ pwned' : '→ access';
                  const actionColor = suggestedStatus === 'pwned' ? '#cc2233' : '#f09a3a';
                  const alreadyMarked = s.matched_host_status === suggestedStatus || s.matched_host_status === 'pwned' || s.matched_host_status === 'owned';
                  return (
                    <tr key={idx} style={{ borderBottom: '1px solid #14161b', opacity: s.alive ? 1 : 0.4 }}>
                      <td style={{ padding: '5px 8px' }}>
                        <span title={s.mark || stCfg.label} style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', background: stCfg.color }} />
                      </td>
                      <td style={{ padding: '5px 8px', color: '#c8cfe0', fontFamily: 'JetBrains Mono' }}>{s.hostname || '—'}</td>
                      <td style={{ padding: '5px 8px', color: '#808590', fontFamily: 'JetBrains Mono' }}>{s.ip || '—'}</td>
                      <td style={{ padding: '5px 8px' }}>
                        <span style={{ fontSize: 9, color: privColor, background: `${privColor}18`, border: `1px solid ${privColor}44`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
                          {s.privilege_label || tier}
                        </span>
                      </td>
                      <td style={{ padding: '5px 8px', color: '#c07af0', fontFamily: 'JetBrains Mono', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{userStr}</td>
                      <td style={{ padding: '5px 8px', color: '#606570', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis' }}>{os}</td>
                      <td style={{ padding: '5px 8px', color: '#404550', fontFamily: 'JetBrains Mono', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{procListener}</td>
                      <td style={{ padding: '5px 8px', color: '#404550', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', fontSize: 10 }}>{s.last_seen || '—'}</td>
                      <td style={{ padding: '5px 8px' }}>
                        {s.matched_host_id ? (
                          <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                            {s.alive && !alreadyMarked && (
                              <button onClick={() => markStatus(s.matched_host_id, suggestedStatus)} disabled={markingId === s.matched_host_id}
                                style={{ fontSize: 9, color: actionColor, background: `${actionColor}18`, border: `1px solid ${actionColor}44`, borderRadius: 3, padding: '1px 7px', cursor: 'pointer', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                                {markingId === s.matched_host_id ? '...' : actionLabel}
                              </button>
                            )}
                            {alreadyMarked && (
                              <span style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>{s.matched_host_status}</span>
                            )}
                          </div>
                        ) : (
                          <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>no match</span>
                        )}
                      </td>
                      <td style={{ padding: '5px 8px' }}>
                        {s.matched_host_id && onNavigateToHost && (
                          <button onClick={() => onNavigateToHost(s.matched_host_id)}
                            style={{ fontSize: 9, color: acc, background: `${acc}18`, border: `1px solid ${acc}44`, borderRadius: 3, padding: '1px 6px', cursor: 'pointer', fontFamily: 'JetBrains Mono' }}>
                            → host
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Live C2 sessions across all integrations ───────────────────────────
function SessionsPanel({ pid, accent }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadedAt, setLoadedAt] = useState(null);
  const [filter, setFilter] = useState({ type: '', tier: '', q: '', aliveOnly: true });
  const [autoRefresh, setAutoRefresh] = useState(false);

  const load = useCallback(async () => {
    if (!pid) return;
    setLoading(true);
    try {
      const data = await api.getC2LiveSessions(pid);
      setRows(Array.isArray(data) ? data : []);
      setLoadedAt(new Date());
    } catch (e) {
      console.error('Live sessions fetch failed:', e);
    }
    setLoading(false);
  }, [pid]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [autoRefresh, load]);

  // error rows come back inline; pull them out for a separate header strip
  const errorRows = rows.filter(r => r.error);
  const sessionRows = rows.filter(r => !r.error);

  // counters per integration
  const perIntegration = {};
  for (const r of sessionRows) {
    const k = r.integration_id;
    if (!perIntegration[k]) {
      perIntegration[k] = { name: r.integration_name, type: r.integration_type, total: 0, alive: 0 };
    }
    perIntegration[k].total++;
    if (r.alive) perIntegration[k].alive++;
  }

  const filtered = sessionRows.filter(r => {
    if (filter.aliveOnly && !r.alive) return false;
    if (filter.type && r.integration_type !== filter.type) return false;
    if (filter.tier && r.privilege_tier !== filter.tier) return false;
    if (filter.q) {
      const q = filter.q.toLowerCase();
      const blob = `${r.ip} ${r.hostname || ''} ${r.username || ''} ${r.domain || ''}`.toLowerCase();
      if (!blob.includes(q)) return false;
    }
    return true;
  });

  const tierColor = { system: '#cc2233', admin: '#f09a3a', user: '#5b8af5' };
  const typeColor = { adaptix: '#c07af0', mythic: '#ffa726', sliver: '#5b8af5' };

  return (
    <div>
      {/* Per-integration health */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 14 }}>
        {Object.entries(perIntegration).map(([id, info]) => (
          <div key={id} style={{ background: '#0c0e13', border: `1px solid ${typeColor[info.type] || '#2a2d35'}55`, borderRadius: 6, padding: '6px 12px', fontSize: 11, fontFamily: 'JetBrains Mono', color: '#c8cdd6', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: typeColor[info.type] || '#808590', fontWeight: 600 }}>{info.name}</span>
            <span style={{ color: '#39d353', fontSize: 10 }}>● {info.alive} live</span>
            <span style={{ color: '#505560', fontSize: 10 }}>{info.total} total</span>
          </div>
        ))}
        {errorRows.map((r, i) => (
          <div key={`err-${i}`} style={{ background: '#1a0508', border: '1px solid #cc223355', borderRadius: 6, padding: '6px 12px', fontSize: 11, fontFamily: 'JetBrains Mono', color: '#cc2233' }}>
            ⚠ {r.integration_name}: {r.error}
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
        <input type="text" placeholder="Search ip / hostname / user…" value={filter.q}
          onChange={e => setFilter(f => ({ ...f, q: e.target.value }))}
          style={{ flex: 1, minWidth: 200, padding: '6px 10px', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none' }} />
        <select value={filter.type} onChange={e => setFilter(f => ({ ...f, type: e.target.value }))}
          style={{ padding: '6px 10px', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          <option value="">All C2 types</option>
          <option value="adaptix">Adaptix</option>
          <option value="mythic">Mythic</option>
          <option value="sliver">Sliver</option>
        </select>
        <select value={filter.tier} onChange={e => setFilter(f => ({ ...f, tier: e.target.value }))}
          style={{ padding: '6px 10px', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          <option value="">All privileges</option>
          <option value="system">SYSTEM</option>
          <option value="admin">Admin</option>
          <option value="user">User</option>
        </select>
        <button onClick={() => setFilter(f => ({ ...f, aliveOnly: !f.aliveOnly }))}
          style={{ background: filter.aliveOnly ? '#1a3a1a' : '#1a1c22', border: `1px solid ${filter.aliveOnly ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: filter.aliveOnly ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {filter.aliveOnly ? '✓ Alive only' : 'Alive only'}
        </button>
        <button onClick={() => setAutoRefresh(v => !v)}
          style={{ background: autoRefresh ? '#0e1a2a' : '#1a1c22', border: `1px solid ${autoRefresh ? '#5b8af5' : '#2a2d35'}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: autoRefresh ? '#5b8af5' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {autoRefresh ? '↻ Auto (15s)' : 'Auto refresh'}
        </button>
        <button onClick={load} disabled={loading}
          style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 12px', cursor: loading ? 'not-allowed' : 'pointer', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
          <Icon name="reset" size={11} color="#c8cdd6" /> {loading ? 'Loading…' : 'Refresh'}
        </button>
        {loadedAt && (
          <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>
            updated {loadedAt.toTimeString().slice(0, 8)}
          </span>
        )}
      </div>

      {/* Sessions table */}
      {sessionRows.length === 0 && !loading && (
        <div style={{ padding: '32px 0', textAlign: 'center', color: '#353840', fontSize: 12, fontFamily: 'JetBrains Mono' }}>
          No live sessions. Configure a C2 integration and run a sync first.
        </div>
      )}
      {filtered.length > 0 && (
        <div style={{ background: '#0c0e13', border: '1px solid #1a1c22', borderRadius: 6, overflow: 'hidden' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '120px 160px 1fr 140px 90px 90px 100px', gap: 0, fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '8px 12px', borderBottom: '1px solid #1a1c22', background: '#0a0c10' }}>
            <div>IP</div><div>Hostname</div><div>User / Domain</div><div>Integration</div><div>Priv</div><div>Status</div><div>Last seen</div>
          </div>
          {filtered.map((r, i) => (
            <div key={`${r.integration_id}-${r.ip}-${r.privilege_tier}-${i}`}
              style={{ display: 'grid', gridTemplateColumns: '120px 160px 1fr 140px 90px 90px 100px', gap: 0, fontSize: 11, color: '#b0b5c2', fontFamily: 'JetBrains Mono', padding: '8px 12px', borderBottom: '1px solid #0e1016', alignItems: 'center', opacity: r.alive ? 1 : 0.5 }}>
              <div style={{ color: '#e0e4ec' }}>{r.ip}</div>
              <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.hostname}>
                {r.hostname || <span style={{ color: '#353840' }}>—</span>}
              </div>
              <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <span style={{ color: '#c8cdd6' }}>{r.username || '—'}</span>
                {r.domain && <span style={{ color: '#606570' }}> @ {r.domain}</span>}
              </div>
              <div>
                <span style={{ fontSize: 9, color: typeColor[r.integration_type] || '#808590', background: `${typeColor[r.integration_type] || '#808590'}18`, border: `1px solid ${typeColor[r.integration_type] || '#808590'}44`, borderRadius: 3, padding: '1px 6px' }}>
                  {r.integration_name}
                </span>
              </div>
              <div>
                <span style={{ fontSize: 9, fontWeight: 700, color: tierColor[r.privilege_tier] || '#808590', background: `${tierColor[r.privilege_tier] || '#808590'}18`, border: `1px solid ${tierColor[r.privilege_tier] || '#808590'}44`, borderRadius: 3, padding: '1px 6px', textTransform: 'uppercase' }}>
                  {r.privilege_label || r.privilege_tier}
                </span>
              </div>
              <div>
                {r.alive
                  ? <span style={{ color: '#39d353', fontSize: 10 }}>● alive</span>
                  : <span style={{ color: '#606570', fontSize: 10 }}>○ dead</span>}
              </div>
              <div style={{ fontSize: 10, color: '#505560' }} title={r.last_seen || ''}>
                {(r.last_seen || '').slice(0, 16).replace('T', ' ') || '—'}
              </div>
            </div>
          ))}
        </div>
      )}
      {filtered.length === 0 && sessionRows.length > 0 && (
        <div style={{ padding: '24px 0', textAlign: 'center', color: '#404550', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          {sessionRows.length} session(s) total — none match the current filter.
        </div>
      )}
    </div>
  );
}


function C2Panel({ pid, accent }) {
  const { role: projectRole, isSuperAdmin } = useProjectPermissions();
  const isProjectOwner = projectRole === 'owner';
  // Who can create / edit / delete an integration:
  //  - global admin: anything (scoped or global)
  //  - project owner: only integrations scoped to this project
  //  - everyone else: read-only
  const canManage = isSuperAdmin || isProjectOwner;
  const canManageIntegration = useCallback((cfg) => {
    if (isSuperAdmin) return true;
    if (!isProjectOwner) return false;
    const ids = cfg?.project_ids || [];
    return ids.length > 0 && pid && ids.includes(pid);
  }, [isSuperAdmin, isProjectOwner, pid]);

  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState('');
  const [syncing, setSyncing] = useState('');
  const [results, setResults] = useState({});
  const [errors, setErrors] = useState({});

  const load = useCallback(async () => {
    try {
      const r = pid ? await api.listC2ForProject(pid) : await api.listC2Integrations();
      setIntegrations(r);
    } catch (e) {
      if (e.message?.includes('403')) {
        setErrors({ global: 'You do not have permission to view C2 integrations in this project' });
      } else if (e.message) {
        setErrors({ global: e.message });
      }
    }
    setLoading(false);
  }, [pid]);

  useEffect(() => { load(); }, [load]);

  const setF = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const openNew = () => { setForm({ ...EMPTY_FORM, project_ids: pid ? [pid] : [] }); setEditing(null); setShowForm(true); };
  const openEdit = (cfg) => {
    setForm({ ...cfg, token: '', password: '' });
    setEditing(cfg.id);
    setShowForm(true);
  };
  const closeForm = () => { setShowForm(false); setEditing(null); };

  const save = async () => {
    if (!form.name.trim()) return;
    // URL is optional for Sliver (lhost/lport carried in operator config blob)
    if (form.type !== 'sliver' && !form.url.trim()) return;
    if (!isSuperAdmin && (!form.project_ids || form.project_ids.length === 0)) {
      setErrors(prev => ({ ...prev, form: 'Project owners must scope the integration to a project. Switch to "This project only".' }));
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        const patch = { ...form };
        if (!patch.token) delete patch.token;
        if (!patch.password) delete patch.password;
        const r = await api.updateC2Integration(editing, patch);
        setIntegrations(prev => prev.map(i => i.id === editing ? r : i));
      } else {
        const r = await api.createC2Integration(form);
        setIntegrations(prev => [...prev, r]);
      }
      closeForm();
    } catch (e) {
      setErrors(prev => ({ ...prev, form: e.message }));
    }
    setSaving(false);
  };

  const remove = async (id) => {
    await api.deleteC2Integration(id);
    setIntegrations(prev => prev.filter(i => i.id !== id));
  };

  const test = async (id) => {
    setTesting(id);
    setResults(prev => ({ ...prev, [id]: null }));
    setErrors(prev => ({ ...prev, [id]: '' }));
    try {
      const r = await api.testC2Integration(id);
      setResults(prev => ({ ...prev, [id]: `✓ Connected — ${r.hosts_found} sessions, ${r.creds_found} creds` }));
    } catch (e) {
      setErrors(prev => ({ ...prev, [id]: e.message || 'Connection failed' }));
    }
    setTesting('');
  };

  const sync = async (id) => {
    setSyncing(id);
    setResults(prev => ({ ...prev, [id + '_sync']: null }));
    setErrors(prev => ({ ...prev, [id + '_sync']: '' }));
    try {
      const r = await api.syncC2ToProject(id, pid);
      setResults(prev => ({ ...prev, [id + '_sync']: `Synced: ${r.hosts_created} new hosts, ${r.hosts_updated} updated, ${r.creds_created} creds` }));
    } catch (e) {
      setErrors(prev => ({ ...prev, [id + '_sync']: e.message || 'Sync failed' }));
    }
    setSyncing('');
  };

  const typeInfo = (type) => C2_TYPES.find(t => t.id === type) || C2_TYPES[0];

  if (loading) return <div style={{ color: '#404550', fontSize: 12 }}>Loading...</div>;

  return (
    <div>
      {errors.global && (
        <div style={{ background: '#1a0508', border: '1px solid #cc223344', borderRadius: 6, padding: 12, marginBottom: 16, fontSize: 12, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>
          {errors.global}
        </div>
      )}

      {/* Integrations list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
        {integrations.length === 0 && !showForm && (
          <div style={{ padding: '32px 0', textAlign: 'center', color: '#353840', fontSize: 12 }}>
            No C2 integrations configured. Add one to start syncing sessions.
          </div>
        )}

        {integrations.map(cfg => {
          const ti = typeInfo(cfg.type);
          const isSyncing = syncing === cfg.id;
          const isTesting = testing === cfg.id;
          return (
            <div key={cfg.id} style={{ background: '#0c0e13', border: `1px solid ${cfg.enabled ? '#1a1c22' : '#141618'}`, borderRadius: 8, padding: 14, opacity: cfg.enabled ? 1 : 0.5 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: cfg.enabled ? ti.color : '#353840', flexShrink: 0 }} />
                <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', flex: 1 }}>{cfg.name}</span>
                <span style={{ fontSize: 10, color: ti.color, fontFamily: 'JetBrains Mono', background: `${ti.color}18`, border: `1px solid ${ti.color}44`, borderRadius: 10, padding: '2px 8px' }}>
                  {ti.label}
                </span>
                {cfg.last_sync && (
                  <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>
                    last sync: {cfg.last_sync}
                  </span>
                )}
              </div>

              <div style={{ fontSize: 11, color: '#505560', fontFamily: 'JetBrains Mono', marginBottom: 10 }}>
                {cfg.url}
              </div>

              {/* Result / error for test */}
              {results[cfg.id] && (
                <div style={{ fontSize: 11, color: '#39d353', fontFamily: 'JetBrains Mono', marginBottom: 8, background: '#0a1208', border: '1px solid #39d35344', borderRadius: 4, padding: '6px 10px' }}>
                  {results[cfg.id]}
                </div>
              )}
              {errors[cfg.id] && (
                <div style={{ fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono', marginBottom: 8, background: '#1a0508', border: '1px solid #cc223344', borderRadius: 4, padding: '6px 10px' }}>
                  {errors[cfg.id]}
                </div>
              )}
              {/* Result / error for sync */}
              {results[cfg.id + '_sync'] && (
                <div style={{ fontSize: 11, color: '#39d353', fontFamily: 'JetBrains Mono', marginBottom: 8, background: '#0a1208', border: '1px solid #39d35344', borderRadius: 4, padding: '6px 10px' }}>
                  {results[cfg.id + '_sync']}
                </div>
              )}
              {errors[cfg.id + '_sync'] && (
                <div style={{ fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono', marginBottom: 8, background: '#1a0508', border: '1px solid #cc223344', borderRadius: 4, padding: '6px 10px' }}>
                  {errors[cfg.id + '_sync']}
                </div>
              )}

              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <button onClick={() => test(cfg.id)} disabled={isTesting || !cfg.enabled}
                  style={{ background: isTesting ? '#1a1c22' : '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 12px', cursor: isTesting || !cfg.enabled ? 'not-allowed' : 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Icon name="check" size={10} color="#808590" />
                  {isTesting ? 'Testing...' : 'Test'}
                </button>
                <button onClick={() => sync(cfg.id)} disabled={isSyncing || !cfg.enabled}
                  style={{ background: isSyncing ? '#1a1c22' : `${ti.color}22`, border: `1px solid ${ti.color}55`, borderRadius: 4, padding: '5px 12px', cursor: isSyncing || !cfg.enabled ? 'not-allowed' : 'pointer', color: ti.color, fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Icon name="reset" size={10} color={ti.color} />
                  {isSyncing ? 'Syncing...' : `Sync → project`}
                </button>
                {canManageIntegration(cfg) ? (
                  <>
                    <button onClick={() => openEdit(cfg)}
                      style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                      Edit
                    </button>
                    <button onClick={() => remove(cfg.id)}
                      style={{ background: 'transparent', border: '1px solid #cc233344', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#cc2233', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                      Delete
                    </button>
                  </>
                ) : (
                  <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', fontStyle: 'italic', alignSelf: 'center' }}>
                    {(cfg.project_ids || []).length === 0 ? 'managed globally (admin only)' : 'read-only'}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Add button */}
      {!showForm && canManage && (
        <button onClick={openNew}
          style={{ background: `${accent}22`, border: `1px solid ${accent}55`, borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Icon name="plus" size={11} color={accent} /> Add C2 Integration
        </button>
      )}
      {!showForm && !canManage && integrations.length > 0 && (
        <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', marginTop: 4 }}>
          Only the project owner or a global admin can register new C2 integrations.
        </div>
      )}

      {/* Form */}
      {showForm && (
        <div style={{ background: '#0c0e13', border: `1px solid ${accent}44`, borderRadius: 8, padding: 18, marginTop: 8 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec', marginBottom: 14 }}>
            {editing ? 'Edit Integration' : 'New C2 Integration'}
          </div>

          {/* Type selector */}
          <FieldRow label="C2 Framework">
            <div style={{ display: 'flex', gap: 6 }}>
              {C2_TYPES.map(t => (
                <button key={t.id} onClick={() => setF('type', t.id)} disabled={!!editing}
                  style={{ flex: 1, background: form.type === t.id ? `${t.color}22` : '#1a1c22', border: `1px solid ${form.type === t.id ? t.color : '#2a2d35'}`, borderRadius: 5, padding: '8px 6px', cursor: editing ? 'not-allowed' : 'pointer', color: form.type === t.id ? t.color : '#505560', fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, textAlign: 'center' }}>
                  {t.label}
                </button>
              ))}
            </div>
            <div style={{ fontSize: 10, color: '#404550', marginTop: 4 }}>{typeInfo(form.type).hint}</div>
          </FieldRow>

          {form.type === 'sliver' ? (
            <FieldRow label="Name">
              <Input value={form.name} onChange={v => setF('name', v)} placeholder="My Sliver" />
            </FieldRow>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <FieldRow label="Name">
                <Input value={form.name} onChange={v => setF('name', v)} placeholder="My TeamServer" />
              </FieldRow>
              <FieldRow label="URL">
                <Input value={form.url} onChange={v => setF('url', v)} placeholder="https://1.2.3.4:50050" monospace />
              </FieldRow>
            </div>
          )}

          {form.type === 'adaptix' ? (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <FieldRow label="Username">
                  <Input value={form.username} onChange={v => setF('username', v)} placeholder="operator1" />
                </FieldRow>
                <FieldRow label="Password">
                  <Input value={form.password} onChange={v => setF('password', v)} placeholder={editing && form.has_password ? 'Stored - enter new to replace' : 'teamserver password'} />
                </FieldRow>
              </div>
              <FieldRow label="Endpoint path">
                <Input value={form.endpoint || '/endpoint'} onChange={v => setF('endpoint', v)} placeholder="/endpoint" monospace />
              </FieldRow>
            </>
          ) : null}

          {form.type === 'mythic' ? (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <FieldRow label="Username (optional if API token set)">
                <Input value={form.username} onChange={v => setF('username', v)} placeholder="mythic_admin" />
              </FieldRow>
              <FieldRow label="Password">
                <Input value={form.password} onChange={v => setF('password', v)} placeholder={editing && form.has_password ? 'Stored - enter new to replace' : 'mythic password'} />
              </FieldRow>
            </div>
          ) : null}

          <FieldRow label={
            form.type === 'mythic' ? 'API Token (preferred — set in Mythic UI → Settings)' :
            form.type === 'sliver' ? 'Operator Config (paste the entire JSON from sliver-server operator --save)' :
            'API Token'
          }>
            <Input
              value={form.token}
              onChange={v => setF('token', v)}
              placeholder={editing && form.has_token ? 'Stored - enter new to replace' : (editing ? '(leave blank to keep existing)' : (form.type === 'sliver' ? '{"operator":"...","ca_certificate":"-----BEGIN CERTIFICATE-----..."}' : 'token...'))}
              monospace
              multiline={form.type === 'sliver'}
              rows={form.type === 'sliver' ? 8 : 3}
            />
          </FieldRow>
          {editing && ((form.type === 'adaptix' && form.has_password) || (form.type === 'mythic' && (form.has_password || form.has_token)) || (form.type !== 'adaptix' && form.type !== 'mythic' && form.has_token)) && (
            <div style={{ fontSize: 10, color: '#606570', marginBottom: 10, fontFamily: 'JetBrains Mono' }}>
              Stored integration secrets are write-only. Leave blank to keep current values.
            </div>
          )}

          <FieldRow label="Auto-sync interval (minutes, 0 = manual only)">
            <Input value={String(form.sync_interval_minutes ?? 0)} onChange={v => setF('sync_interval_minutes', parseInt(v) || 0)} placeholder="0" monospace />
          </FieldRow>

          <FieldRow label="Project scope">
            <div style={{ display: 'flex', gap: 6 }}>
              <button onClick={() => setF('project_ids', pid ? [pid] : [])}
                style={{ flex: 1, background: (form.project_ids?.length > 0) ? `${accent}22` : '#1a1c22', border: `1px solid ${(form.project_ids?.length > 0) ? accent + '88' : '#2a2d35'}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: (form.project_ids?.length > 0) ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                This project only
              </button>
              <button onClick={() => isSuperAdmin && setF('project_ids', [])}
                disabled={!isSuperAdmin}
                title={!isSuperAdmin ? 'Only global admins can create unscoped integrations' : ''}
                style={{ flex: 1, background: (form.project_ids?.length === 0) ? `${accent}22` : '#1a1c22', border: `1px solid ${(form.project_ids?.length === 0) ? accent + '88' : '#2a2d35'}`, borderRadius: 4, padding: '5px 10px', cursor: isSuperAdmin ? 'pointer' : 'not-allowed', color: (form.project_ids?.length === 0) ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', opacity: isSuperAdmin ? 1 : 0.5 }}>
                All projects {!isSuperAdmin && '🔒'}
              </button>
            </div>
            {!isSuperAdmin && (
              <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', marginTop: 4 }}>
                As project owner you can register C2 integrations bound to this project.
                Unscoped (cross-project) integrations require a global admin.
              </div>
            )}
          </FieldRow>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
            <button onClick={() => setF('verify_ssl', !form.verify_ssl)}
              style={{ background: form.verify_ssl ? '#1a3a1a' : '#1a1c22', border: `1px solid ${form.verify_ssl ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: form.verify_ssl ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {form.verify_ssl ? '✓ Verify SSL' : '✗ Ignore SSL (self-signed)'}
            </button>
            <button onClick={() => setF('enabled', !form.enabled)}
              style={{ background: form.enabled ? '#1a3a1a' : '#1a1c22', border: `1px solid ${form.enabled ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: form.enabled ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {form.enabled ? 'Enabled' : 'Disabled'}
            </button>
          </div>

          {errors.form && (
            <div style={{ color: '#cc2233', fontSize: 11, fontFamily: 'JetBrains Mono', marginBottom: 10 }}>{errors.form}</div>
          )}

          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={save} disabled={saving || !form.name.trim() || (form.type !== 'sliver' && !form.url.trim())}
              style={{ background: saving ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: saving ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
              {saving ? 'Saving...' : editing ? 'Save changes' : 'Add integration'}
            </button>
            <button onClick={closeForm}
              style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Live Sessions — shown when there are integrations */}
      {integrations.length > 0 && pid && (
        <C2SessionsPanel pid={pid} accent={accent} />
      )}
    </div>
  );
}

// ── Main ScansView ─────────────────────────────────────────────────────
export default function ScansView({ selectedProject, accent }) {
  const [activeType, setActiveType] = useState('nmap');
  const active = SCAN_TYPES.find(s => s.id === activeType);

  if (!selectedProject) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#404550', fontSize: 12, fontFamily: 'JetBrains Mono' }}>
      Select a project to use scans
    </div>
  );

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {/* Sidebar */}
      <div style={{ width: 200, background: '#0a0c10', borderRight: '1px solid #1a1c22', padding: '12px 0', flexShrink: 0 }}>
        <div style={{ fontSize: 9, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.12em', padding: '0 14px 8px' }}>Scan modules</div>
        {SCAN_TYPES.map(s => {
          const act = s.id === activeType;
          return (
            <button key={s.id} onClick={() => setActiveType(s.id)}
              style={{ width: '100%', padding: '10px 14px', border: 'none', cursor: 'pointer', background: act ? `${s.color}14` : 'transparent', borderLeft: act ? `2px solid ${s.color}` : '2px solid transparent', display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 2, transition: 'all .12s', textAlign: 'left' }}
              onMouseEnter={e => !act && (e.currentTarget.style.background = '#ffffff08')}
              onMouseLeave={e => !act && (e.currentTarget.style.background = 'transparent')}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon name={s.icon} size={13} color={act ? s.color : '#505560'} />
                <span style={{ fontSize: 11, fontWeight: 600, color: act ? s.color : '#808590', fontFamily: 'JetBrains Mono' }}>{s.label}</span>
              </div>
              <span style={{ fontSize: 10, color: '#404550', paddingLeft: 21, lineHeight: 1.4 }}>{s.desc}</span>
            </button>
          );
        })}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <Icon name={active.icon} size={18} color={active.color} />
            <span style={{ fontSize: 16, fontWeight: 700, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>{active.label}</span>
          </div>
          <div style={{ fontSize: 12, color: '#505560' }}>{active.desc}</div>
        </div>

        <div style={{ maxWidth: activeType === 'c2' ? 900 : 640 }}>
          {activeType === 'nmap'    && <NmapPanel    pid={selectedProject} accent={accent} />}
          {activeType === 'nuclei'  && <NucleiPanel  pid={selectedProject} accent={accent} />}
          {activeType === 'cme'     && <CmePanel     pid={selectedProject} accent={accent} />}
          {activeType === 'donpapi' && <DonpapiPanel pid={selectedProject} accent={accent} />}
          {activeType === 'bulk'    && <BulkImportPanel pid={selectedProject} accent={accent} />}
          {activeType === 'c2'       && <C2Panel       pid={selectedProject} accent={accent} />}
          {activeType === 'sessions' && <SessionsPanel pid={selectedProject} accent={accent} />}
          {activeType === 'webhook'  && <WebhookPanel  pid={selectedProject} accent={accent} />}
        </div>
      </div>
    </div>
  );
}
