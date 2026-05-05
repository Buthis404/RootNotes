import { useState, useEffect, useCallback, useMemo } from 'react';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';

const SCAN_TYPES = [
  { id: 'nmap',   label: 'Nmap',           icon: 'target',   color: '#5b8af5', desc: 'Port scan → auto-fill hosts & ports' },
  { id: 'nuclei', label: 'Nuclei',          icon: 'bug',      color: '#e8574a', desc: 'Vuln templates → auto-create findings' },
  { id: 'cme',    label: 'CME / NetExec',   icon: 'hosts',    color: '#c07af0', desc: 'AD enum → auto-fill hosts & creds' },
  { id: 'bulk',   label: 'Bulk Host Import',icon: 'plus',     color: '#f09a3a', desc: 'IP list or CIDR → batch add hosts' },
  { id: 'c2',     label: 'C2 Integrations', icon: 'bolt',     color: '#cc2233', desc: 'Cobalt Strike / Sliver / Adaptix → auto-sync sessions' },
  { id: 'webhook',label: 'C2 Webhook',      icon: 'shield',   color: '#39d353', desc: 'Receive push callbacks from any C2 framework' },
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

// ── Nmap Panel ────────────────────────────────────────────────────────
function NmapPanel({ pid, accent }) {
  const [target, setTarget] = useState('');
  const [flags, setFlags] = useState('-sV -sC -T4 --open');
  const [timeout, setTimeout_] = useState(180);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const run = async () => {
    if (!target.trim()) return;
    setRunning(true); setResult(null); setError('');
    try {
      const r = await api.runNmapScan(pid, { target, flags, timeout_seconds: timeout });
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

  const run = async () => {
    if (!target.trim()) return;
    setRunning(true); setResult(null); setError('');
    try {
      const r = await api.runNucleiScan(pid, { target, templates, severity, extra_flags: extra, timeout_seconds: timeout });
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

  const run = async () => {
    if (!target.trim()) return;
    setRunning(true); setResult(null); setError('');
    try {
      const r = await api.runCmeScan(pid, { target, username, password, domain, hash, protocol, extra_flags: extra, timeout_seconds: timeout });
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
      <button onClick={run} disabled={running || !target.trim()}
        style={{ background: running ? '#1a1c22' : '#c07af0', border: 'none', borderRadius: 5, padding: '8px 18px', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: running ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
        <Icon name="hosts" size={12} color="#fff" />
        {running ? 'Running...' : 'Run NetExec'}
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
    source: "cobalt_strike",
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
  { id: 'cobalt_strike', label: 'Cobalt Strike', color: '#cc2233', hint: 'Team Server REST API (4.7+). Token: CS Preferences → REST API' },
  { id: 'sliver',        label: 'Sliver',         color: '#5b8af5', hint: 'REST API (multiplayer mode). Token: sliver-client generate-token' },
  { id: 'adaptix',       label: 'Adaptix',        color: '#c07af0', hint: 'REST API under /endpoint path. Username + password (or token). URL: https://host:port' },
];

const EMPTY_FORM = { name: '', type: 'cobalt_strike', url: '', token: '', username: '', password: '', endpoint: '/endpoint', verify_ssl: false, project_ids: [], enabled: true, sync_interval_minutes: 0, has_token: false, has_password: false };

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
      if (!map[key]) map[key] = { name: key, type: s.integration_type, sessions: [], error: null };
      if (s.error) map[key].error = s.error;
      else map[key].sessions.push(s);
    }
    return map;
  }, [sessions]);

  const acc = accent || '#5b8af5';
  const typeColors = { adaptix: '#00bcd4', cobalt_strike: '#f44336', sliver: '#8bc34a' };

  return (
    <div style={{ marginTop: 20, borderTop: '1px solid #1e2230', paddingTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec' }}>Live Sessions</span>
        <button onClick={load} disabled={loading}
          style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {loading ? 'Loading...' : 'Refresh'}
        </button>
        {sessions && <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>{sessions.filter(s => !s.error).length} agent(s)</span>}
      </div>

      {error && <div style={{ fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono', marginBottom: 8 }}>{error}</div>}

      {sessions && Object.values(grouped).map(group => (
        <div key={group.name} style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
            <span style={{ fontSize: 10, color: typeColors[group.type] || '#808590', background: `${typeColors[group.type] || '#808590'}18`, border: `1px solid ${typeColors[group.type] || '#808590'}44`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{group.type}</span>
            <span style={{ fontSize: 11, color: '#808590' }}>{group.name}</span>
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

function C2Panel({ pid, accent }) {
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
      const r = await api.listC2Integrations();
      setIntegrations(r);
    } catch (e) {
      if (e.message?.includes('403') || e.message?.includes('admin')) {
        setErrors({ global: 'Admin access required to manage C2 integrations' });
      }
    }
    setLoading(false);
  }, []);

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
    if (!form.name.trim() || !form.url.trim()) return;
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
                <button onClick={() => openEdit(cfg)}
                  style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                  Edit
                </button>
                <button onClick={() => remove(cfg.id)}
                  style={{ background: 'transparent', border: '1px solid #cc233344', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#cc2233', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                  Delete
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Add button */}
      {!showForm && (
        <button onClick={openNew}
          style={{ background: `${accent}22`, border: `1px solid ${accent}55`, borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Icon name="plus" size={11} color={accent} /> Add C2 Integration
        </button>
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

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <FieldRow label="Name">
              <Input value={form.name} onChange={v => setF('name', v)} placeholder="My CS TeamServer" />
            </FieldRow>
            <FieldRow label="URL">
              <Input value={form.url} onChange={v => setF('url', v)} placeholder="https://1.2.3.4:50050" monospace />
            </FieldRow>
          </div>

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

          <FieldRow label={form.type === 'cobalt_strike' ? 'REST API Token (Bearer)' : 'API Token'}>
            <Input value={form.token} onChange={v => setF('token', v)} placeholder={editing && form.has_token ? 'Stored - enter new to replace' : (editing ? '(leave blank to keep existing)' : 'token...')} monospace />
          </FieldRow>
          {editing && ((form.type === 'adaptix' && form.has_password) || (form.type !== 'adaptix' && form.has_token)) && (
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
              <button onClick={() => setF('project_ids', [])}
                style={{ flex: 1, background: (form.project_ids?.length === 0) ? `${accent}22` : '#1a1c22', border: `1px solid ${(form.project_ids?.length === 0) ? accent + '88' : '#2a2d35'}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: (form.project_ids?.length === 0) ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                All projects
              </button>
            </div>
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
            <button onClick={save} disabled={saving || !form.name.trim() || !form.url.trim()}
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
          {activeType === 'bulk'    && <BulkImportPanel pid={selectedProject} accent={accent} />}
          {activeType === 'c2'      && <C2Panel      pid={selectedProject} accent={accent} />}
          {activeType === 'webhook' && <WebhookPanel pid={selectedProject} accent={accent} />}
        </div>
      </div>
    </div>
  );
}
