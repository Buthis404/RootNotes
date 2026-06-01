import { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { FieldRow, Input, ResultBox, ExecutionSourceRow, isSocksPivot } from './scans/ScanFormFields.jsx';
import C2Panel, { SessionsPanel } from './scans/C2Panel.jsx';
import WebhookPanel from './scans/WebhookPanel.jsx';

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

// ── Pivot options helper (shared by scan panels) ──────────────────────

function usePivotOptions(pid, enabled = true) {
  const [pivotOptions, setPivotOptions] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!pid || !enabled) return;
    let cancelled = false;
    setLoading(true);
    api.listPivots(pid)
      .then(r => {
        if (cancelled) return;
        const items = (Array.isArray(r) ? r : r?.items || []).filter(item => item.status === 'active' && isSocksPivot(item));
        setPivotOptions(items.map(item => ({
          id: item.id,
          label: `${item.tool || 'pivot'} → ${item.bind_address} (${item.pivot_host_ip || item.pivot_host_id?.slice(0, 8) || '?'})`,
        })));
      })
      .catch(() => {})
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [pid, enabled]);

  return { pivotOptions, loading };
}

// ── Nmap Panel ────────────────────────────────────────────────────────

function NmapPanel({ pid, accent }) {
  const [target, setTarget] = useState('');
  const [flags, setFlags] = useState('-sV -sC -T4 --open');
  const [timeoutSec, setTimeoutSec] = useState(180);
  const [targetId, setTargetId] = useState('');
  const [executionSource, setExecutionSource] = useState('attacker');
  const [pivotObservationId, setPivotObservationId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const { pivotOptions, loading: pivotsLoading } = usePivotOptions(pid);

  const run = async () => {
    if (!target.trim()) return;
    setLoading(true); setResult(null); setError('');
    try {
      const r = await api.runNmapScan(pid, { target, flags, timeout_seconds: timeoutSec, target_id: targetId || undefined, execution_source: executionSource, pivot_observation_id: executionSource === 'pivot_listener' ? pivotObservationId || undefined : undefined });
      setResult(r);
    } catch (e) {
      setError(e.message || 'Scan failed');
    }
    setLoading(false);
  };

  return (
    <div>
      <FieldRow label="Target">
        <Input value={target} onChange={setTarget} placeholder="10.0.0.0/24 or 192.168.1.1" monospace />
      </FieldRow>
      <FieldRow label="Flags">
        <Input value={flags} onChange={setFlags} placeholder="-sV -sC -T4 --open" monospace />
      </FieldRow>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <FieldRow label="Timeout (seconds)">
          <Input value={String(timeoutSec)} onChange={v => setTimeoutSec(Number.parseInt(v) || 180)} placeholder="180" monospace />
        </FieldRow>
        <FieldRow label="Attacker target id">
          <Input value={targetId} onChange={setTargetId} placeholder="(auto)" monospace />
        </FieldRow>
      </div>
      <ExecutionSourceRow executionSource={executionSource} setExecutionSource={setExecutionSource}
        pivotObservationId={pivotObservationId} setPivotObservationId={setPivotObservationId}
        pivotOptions={pivotOptions} loading={pivotsLoading} />
      <button onClick={run} disabled={loading || !target.trim()}
        style={{ background: loading ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '8px 18px', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
        <Icon name="target" size={12} color="#fff" />
        {loading ? 'Scanning...' : 'Run Nmap'}
      </button>
      <ResultBox result={result} error={error} />
    </div>
  );
}

NmapPanel.propTypes = {
  pid: PropTypes.string,
  accent: PropTypes.string,
};

// ── Nuclei Panel ──────────────────────────────────────────────────────

function NucleiPanel({ pid, accent }) {
  const [target, setTarget] = useState('');
  const [templates, setTemplates] = useState('');
  const [severity, setSeverity] = useState('critical,high,medium');
  const [extraFlags, setExtraFlags] = useState('');
  const [timeoutSec, setTimeoutSec] = useState(300);
  const [targetId, setTargetId] = useState('');
  const [executionSource, setExecutionSource] = useState('attacker');
  const [pivotObservationId, setPivotObservationId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const { pivotOptions, loading: pivotsLoading } = usePivotOptions(pid);

  const run = async () => {
    if (!target.trim()) return;
    setLoading(true); setResult(null); setError('');
    try {
      const r = await api.runNucleiScan(pid, { target, templates, severity, extra_flags: extraFlags, timeout_seconds: timeoutSec, target_id: targetId || undefined, execution_source: executionSource, pivot_observation_id: executionSource === 'pivot_listener' ? pivotObservationId || undefined : undefined });
      setResult(r);
    } catch (e) {
      setError(e.message || 'Scan failed');
    }
    setLoading(false);
  };

  return (
    <div>
      <FieldRow label="Target URL">
        <Input value={target} onChange={setTarget} placeholder="https://10.0.0.1" monospace />
      </FieldRow>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <FieldRow label="Templates path">
          <Input value={templates} onChange={setTemplates} placeholder="(default)" monospace />
        </FieldRow>
        <FieldRow label="Severity">
          <Input value={severity} onChange={setSeverity} placeholder="critical,high,medium" monospace />
        </FieldRow>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <FieldRow label="Extra flags">
          <Input value={extraFlags} onChange={setExtraFlags} placeholder="-t /custom/templates" monospace />
        </FieldRow>
        <FieldRow label="Timeout (seconds)">
          <Input value={String(timeoutSec)} onChange={v => setTimeoutSec(Number.parseInt(v) || 300)} placeholder="300" monospace />
        </FieldRow>
      </div>
      <FieldRow label="Attacker target id">
        <Input value={targetId} onChange={setTargetId} placeholder="(auto)" monospace />
      </FieldRow>
      <ExecutionSourceRow executionSource={executionSource} setExecutionSource={setExecutionSource}
        pivotObservationId={pivotObservationId} setPivotObservationId={setPivotObservationId}
        pivotOptions={pivotOptions} loading={pivotsLoading} />
      <button onClick={run} disabled={loading || !target.trim()}
        style={{ background: loading ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '8px 18px', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
        <Icon name="bug" size={12} color="#fff" />
        {loading ? 'Scanning...' : 'Run Nuclei'}
      </button>
      <ResultBox result={result} error={error} />
    </div>
  );
}

NucleiPanel.propTypes = {
  pid: PropTypes.string,
  accent: PropTypes.string,
};

// ── CME Panel ─────────────────────────────────────────────────────────

function CmePanel({ pid, accent }) {
  const [target, setTarget] = useState('');
  const [protocol, setProtocol] = useState('smb');
  const [extraFlags, setExtraFlags] = useState('--users --groups');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [domain, setDomain] = useState('');
  const [hash, setHash] = useState('');
  const [timeoutSec, setTimeoutSec] = useState(120);
  const [targetId, setTargetId] = useState('');
  const [executionSource, setExecutionSource] = useState('attacker');
  const [pivotObservationId, setPivotObservationId] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const { pivotOptions, loading: pivotsLoading } = usePivotOptions(pid);

  const run = async () => {
    if (!target.trim()) return;
    setLoading(true); setResult(null); setError('');
    try {
      const r = await api.runCmeScan(pid, { target, protocol, extra_flags: extraFlags, username, password, domain, hash, timeout_seconds: timeoutSec, target_id: targetId || undefined, execution_source: executionSource, pivot_observation_id: executionSource === 'pivot_listener' ? pivotObservationId || undefined : undefined });
      setResult(r);
    } catch (e) {
      setError(e.message || 'Scan failed');
    }
    setLoading(false);
  };

  return (
    <div>
      <FieldRow label="Target">
        <Input value={target} onChange={setTarget} placeholder="10.0.0.0/24 or 192.168.1.1" monospace />
      </FieldRow>
      <FieldRow label="Protocol">
        <div style={{ display: 'flex', gap: 5 }}>
          {['smb', 'winrm', 'rdp', 'ldap', 'mssql'].map(p => (
            <button key={p} onClick={() => setProtocol(p)}
              style={{ background: protocol === p ? `${accent}22` : '#1a1c22', border: `1px solid ${protocol === p ? accent : '#2a2d35'}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: protocol === p ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {p.toUpperCase()}
            </button>
          ))}
        </div>
      </FieldRow>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <FieldRow label="Extra flags">
          <Input value={extraFlags} onChange={setExtraFlags} placeholder="--users --groups" monospace />
        </FieldRow>
        <FieldRow label="Attacker target id">
          <Input value={targetId} onChange={setTargetId} placeholder="(auto)" monospace />
        </FieldRow>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <FieldRow label="Username">
          <Input value={username} onChange={setUsername} placeholder="administrator" />
        </FieldRow>
        <FieldRow label="Password">
          <Input value={password} onChange={setPassword} placeholder="password" />
        </FieldRow>
        <FieldRow label="Domain">
          <Input value={domain} onChange={setDomain} placeholder="CORP" />
        </FieldRow>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <FieldRow label="Hash (NTLM)">
          <Input value={hash} onChange={setHash} placeholder="aad3b435b51404ee..." monospace />
        </FieldRow>
        <FieldRow label="Timeout (seconds)">
          <Input value={String(timeoutSec)} onChange={v => setTimeoutSec(Number.parseInt(v) || 120)} placeholder="120" monospace />
        </FieldRow>
      </div>
      <ExecutionSourceRow executionSource={executionSource} setExecutionSource={setExecutionSource}
        pivotObservationId={pivotObservationId} setPivotObservationId={setPivotObservationId}
        pivotOptions={pivotOptions} loading={pivotsLoading} />
      <button onClick={run} disabled={loading || !target.trim()}
        style={{ background: loading ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '8px 18px', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
        <Icon name="hosts" size={12} color="#fff" />
        {loading ? 'Scanning...' : 'Run CME'}
      </button>
      <ResultBox result={result} error={error} />
    </div>
  );
}

CmePanel.propTypes = {
  pid: PropTypes.string,
  accent: PropTypes.string,
};

// ── DonPAPI Panel ──────────────────────────────────────────────────────

function DonpapiPanel({ pid, accent }) {
  const [target, setTarget] = useState('');
  const [username, setUsername] = useState('');
  const [domain, setDomain] = useState('');
  const [credId, setCredId] = useState('');
  const [password, setPassword] = useState('');
  const [nthash, setNthash] = useState('');
  const [extraFlags, setExtraFlags] = useState('');
  const [timeoutSec, setTimeoutSec] = useState(600);
  const [targetId, setTargetId] = useState('');
  const [fetchLoot, setFetchLoot] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const run = async () => {
    if (!target.trim()) return;
    setLoading(true); setResult(null); setError('');
    try {
      const r = await api.runDonpapiScan(pid, {
        target, username, domain, cred_id: credId || undefined,
        password, nthash, extra_flags: extraFlags,
        timeout_seconds: timeoutSec, target_id: targetId || undefined,
        fetch_loot: fetchLoot,
      });
      setResult(r);
    } catch (e) {
      setError(e.message || 'Scan failed');
    }
    setLoading(false);
  };

  return (
    <div>
      <FieldRow label="Target IP(s)">
        <Input value={target} onChange={setTarget} placeholder="10.0.0.5 or 10.0.0.1,10.0.0.2" monospace />
      </FieldRow>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <FieldRow label="Username">
          <Input value={username} onChange={setUsername} placeholder="administrator" />
        </FieldRow>
        <FieldRow label="Domain">
          <Input value={domain} onChange={setDomain} placeholder="CORP" />
        </FieldRow>
        <FieldRow label="Cred ID (preferred)">
          <Input value={credId} onChange={setCredId} placeholder="(optional)" monospace />
        </FieldRow>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <FieldRow label="Password">
          <Input value={password} onChange={setPassword} placeholder="(optional if cred_id set)" />
        </FieldRow>
        <FieldRow label="NT hash">
          <Input value={nthash} onChange={setNthash} placeholder="(optional)" monospace />
        </FieldRow>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <FieldRow label="Extra flags">
          <Input value={extraFlags} onChange={setExtraFlags} placeholder="" monospace />
        </FieldRow>
        <FieldRow label="Timeout (seconds)">
          <Input value={String(timeoutSec)} onChange={v => setTimeoutSec(Number.parseInt(v) || 600)} placeholder="600" monospace />
        </FieldRow>
        <FieldRow label="Attacker target id">
          <Input value={targetId} onChange={setTargetId} placeholder="(auto)" monospace />
        </FieldRow>
      </div>
      <div style={{ marginBottom: 12 }}>
        <button onClick={() => setFetchLoot(v => !v)}
          style={{ background: fetchLoot ? '#1a3a1a' : '#1a1c22', border: `1px solid ${fetchLoot ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: fetchLoot ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {fetchLoot ? '✓ Fetch loot' : 'Fetch loot'}
        </button>
      </div>
      <button onClick={run} disabled={loading || !target.trim()}
        style={{ background: loading ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '8px 18px', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
        <Icon name="key" size={12} color="#fff" />
        {loading ? 'Running...' : 'Run DonPAPI'}
      </button>
      <ResultBox result={result} error={error} />
    </div>
  );
}

DonpapiPanel.propTypes = {
  pid: PropTypes.string,
  accent: PropTypes.string,
};

// ── Bulk Import Panel ──────────────────────────────────────────────────

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

BulkImportPanel.propTypes = {
  pid: PropTypes.string,
  accent: PropTypes.string,
};

// ── ScansView (root) ──────────────────────────────────────────────────

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

ScansView.propTypes = {
  selectedProject: PropTypes.any,
  accent: PropTypes.string,
};
