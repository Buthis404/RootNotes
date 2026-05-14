import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { api } from '../api.js';
import { toastError } from '../components/Toast.jsx';

const STATUS_CFG = {
  queued:    { color: '#a0a8b8', label: 'Queued' },
  running:   { color: '#f09a3a', label: 'Running' },
  done:      { color: '#39d353', label: 'Done' },
  failed:    { color: '#cc2233', label: 'Failed' },
  cancelled: { color: '#6a7080', label: 'Cancelled' },
};

const TYPE_CFG = {
  nmap:     { color: '#5b8af5', label: 'nmap' },
  nuclei:   { color: '#e056c0', label: 'nuclei' },
  cme:      { color: '#f09a3a', label: 'netexec' },
  exec:     { color: '#39d353', label: 'exec' },
  cred_validate: { color: '#c07af0', label: 'cred-validate' },
  c2_sync:  { color: '#8f7af5', label: 'c2' },
  topology: { color: '#a0a8b8', label: 'topology' },
};

const OP_CFG = {
  scan:           { color: '#5b8af5', label: 'scan' },
  exec:           { color: '#39d353', label: 'exec' },
  bulk_exec:      { color: '#f09a3a', label: 'bulk' },
  cred_validate:  { color: '#c07af0', label: 'cred-validate' },
  sync:           { color: '#8f7af5', label: 'sync' },
  apply:          { color: '#a0a8b8', label: 'apply' },
  auto_build:     { color: '#6fc8f0', label: 'auto-build' },
  rebuild_layout: { color: '#808590', label: 'layout' },
};

function StatusBadge({ status }) {
  const cfg = STATUS_CFG[status] || { color: '#a0a8b8', label: status };
  return (
    <span style={{
      background: cfg.color + '22', color: cfg.color,
      border: `1px solid ${cfg.color}44`,
      borderRadius: 4, padding: '1px 7px', fontSize: 11, fontWeight: 600,
      whiteSpace: 'nowrap',
    }}>{cfg.label}</span>
  );
}

function TypeBadge({ type }) {
  const cfg = TYPE_CFG[type] || { color: '#a0a8b8', label: type };
  return (
    <span style={{
      background: cfg.color + '22', color: cfg.color,
      border: `1px solid ${cfg.color}44`,
      borderRadius: 4, padding: '1px 7px', fontSize: 11, fontWeight: 600,
      whiteSpace: 'nowrap',
    }}>{cfg.label}</span>
  );
}

function MetaBadge({ value, color = '#808590' }) {
  if (!value) return null;
  return (
    <span style={{
      background: color + '18', color,
      border: `1px solid ${color}33`,
      borderRadius: 4, padding: '1px 6px', fontSize: 10, fontWeight: 600,
      whiteSpace: 'nowrap', fontFamily: 'JetBrains Mono',
    }}>{value}</span>
  );
}

function summarizeResult(result) {
  if (!result || typeof result !== 'object') return '';
  if (result.structured?.summary) return result.structured.summary;
  const preferred = ['hosts_created', 'hosts_updated', 'links_added', 'findings_created', 'findings_found', 'creds_created', 'creds_found', 'hosts_valid', 'hosts_failed', 'nodes_repositioned', 'exit_code'];
  const parts = [];
  for (const key of preferred) {
    if (result[key] !== undefined && result[key] !== '') parts.push(`${key}=${result[key]}`);
  }
  return parts.join(' · ');
}

function StructuredBadges({ result }) {
  const s = result?.structured;
  if (!s) return null;
  const badges = [];

  if (s.auth_success === true) {
    badges.push(<span key="auth" style={{ fontSize: 9, color: '#39d353', background: '#39d35318', border: '1px solid #39d35333', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>✓ auth</span>);
  } else if (s.auth_success === false) {
    badges.push(<span key="auth" style={{ fontSize: 9, color: '#f87171', background: '#f8717118', border: '1px solid #f8717133', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>✗ auth</span>);
  }

  if (s.access_role) {
    const roleColor = s.access_role === 'local_admin' || s.access_role === 'domain_admin' ? '#f09a3a' : '#c07af0';
    badges.push(<span key="role" style={{ fontSize: 9, color: roleColor, background: roleColor + '18', border: `1px solid ${roleColor}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{s.access_role}</span>);
  }

  if (s.finding_candidates?.length > 0) {
    const hasHigh = s.finding_candidates.some(f => f.severity === 'critical' || f.severity === 'high');
    const fc = hasHigh ? '#f09a3a' : '#e0a820';
    badges.push(<span key="fc" style={{ fontSize: 9, color: fc, background: fc + '18', border: `1px solid ${fc}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>⚑ {s.finding_candidates.length} candidate{s.finding_candidates.length !== 1 ? 's' : ''}</span>);
  }

  if (s.host_changes?.length > 0) {
    badges.push(<span key="hc" style={{ fontSize: 9, color: '#5b8af5', background: '#5b8af518', border: '1px solid #5b8af533', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>Δ {s.host_changes.length} host{s.host_changes.length !== 1 ? 's' : ''}</span>);
  }

  if (badges.length === 0) return null;
  return <div style={{ marginTop: 3, display: 'flex', gap: 4, flexWrap: 'wrap' }}>{badges}</div>;
}

function calcDuration(job) {
  if (!job.started_at) return null;
  const s = new Date(job.started_at);
  const f = job.finished_at ? new Date(job.finished_at) : null;
  if (!f) return job.status === 'running' ? 'running…' : null;
  const sec = Math.round((f - s) / 1000);
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

const TOOL_COLORS = { nmap: '#5b8af5', netexec: '#f09a3a', secretsdump: '#c07af0', hydra: '#39d353' };

function LiveOutputPanel({ pid, jobId, accent, onClose }) {
  const [lines, setLines] = useState([]);
  const [done, setDone] = useState(false);
  const [finalStatus, setFinalStatus] = useState('');
  const bottomRef = useRef(null);
  const esRef = useRef(null);

  useEffect(() => {
    const url = api.streamJobOutput(pid, jobId);
    // EventSource sends cookies automatically for same-origin requests
    const es = new EventSource(url);
    esRef.current = es;
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.done) {
          setDone(true);
          setFinalStatus(data.status || '');
          es.close();
        } else if (data.line !== undefined) {
          setLines(prev => [...prev, data.line]);
        }
      } catch {}
    };
    es.onerror = () => {
      setDone(true);
      es.close();
    };
    return () => { es.close(); };
  }, [pid, jobId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  const statusColor = finalStatus === 'done' ? '#39d353' : finalStatus === 'failed' ? '#cc2233' : '#f09a3a';

  return (
    <div style={{ position: 'fixed', bottom: 20, right: 20, width: 640, maxHeight: '60vh', background: '#070a10', border: `1px solid ${accent}44`, borderRadius: 8, boxShadow: '0 8px 40px #00000099', zIndex: 300, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderBottom: '1px solid #1e2230', flexShrink: 0 }}>
        {!done && <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#f09a3a', animation: 'pulse 1.2s infinite', flexShrink: 0 }} />}
        {done && <span style={{ width: 7, height: 7, borderRadius: '50%', background: statusColor, flexShrink: 0 }} />}
        <span style={{ fontSize: 11, color: '#9098a8', fontFamily: 'JetBrains Mono', flex: 1 }}>
          {done ? `Finished · ${finalStatus}` : 'Live output'} · {lines.length} lines
        </span>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#606570', fontSize: 14 }}>✕</button>
      </div>
      <pre style={{ flex: 1, overflowY: 'auto', margin: 0, padding: '10px 12px', fontSize: 11, color: '#c8cfe0', fontFamily: 'JetBrains Mono', lineHeight: 1.5, background: 'transparent' }}>
        {lines.length === 0 && !done && <span style={{ color: '#404550' }}>Waiting for output…</span>}
        {lines.map((l, i) => <span key={i} style={{ display: 'block' }}>{l}</span>)}
        <span ref={bottomRef} />
      </pre>
      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }`}</style>
    </div>
  );
}

function EnrichmentPanel({ enrichment }) {
  if (!enrichment || (!enrichment.host_changes?.length && !enrichment.new_creds?.length)) return null;
  const color = TOOL_COLORS[enrichment.tool] || '#a0a8b8';
  return (
    <div style={{ marginBottom: 8, background: '#0a0c14', border: `1px solid ${color}33`, borderRadius: 4, padding: '8px 12px' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: enrichment.host_changes?.length || enrichment.new_creds?.length ? 6 : 0 }}>
        <span style={{ fontSize: 10, color, fontWeight: 700, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
          {enrichment.tool || 'auto'} enrichment
        </span>
        {enrichment.host_changes?.length > 0 && (
          <span style={{ fontSize: 10, color: '#39d353', background: '#39d35318', border: '1px solid #39d35333', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>
            {enrichment.host_changes.length} host field{enrichment.host_changes.length !== 1 ? 's' : ''} updated
          </span>
        )}
        {enrichment.new_creds?.length > 0 && (
          <span style={{ fontSize: 10, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>
            {enrichment.new_creds.length} cred{enrichment.new_creds.length !== 1 ? 's' : ''} saved
          </span>
        )}
      </div>
      {enrichment.host_changes?.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {enrichment.host_changes.map((ch, i) => (
            <span key={i} style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: '#808590', background: '#141620', borderRadius: 3, padding: '2px 6px' }}>
              <span style={{ color: '#505060' }}>{ch.field}: </span>
              <span style={{ color: '#39d353' }}>{String(ch.new ?? '').slice(0, 40)}</span>
            </span>
          ))}
        </div>
      )}
      {enrichment.new_creds?.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: enrichment.host_changes?.length ? 4 : 0 }}>
          {enrichment.new_creds.map((c, i) => (
            <span key={i} style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: '#c07af0', background: '#141620', borderRadius: 3, padding: '2px 6px' }}>
              {c.domain ? `${c.domain}\\` : ''}{c.username} <span style={{ color: '#505060' }}>({c.type})</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function renderHighlightedOutput(text, query) {
  if (!text) return null;
  if (!query) {
    return <pre style={{ background: '#070a10', border: '1px solid #1e2230', borderRadius: 4, padding: '8px 10px', color: '#c8cfe0', fontSize: 11, maxHeight: 300, overflow: 'auto', margin: 0 }}>{text}</pre>;
  }
  const qLower = query.toLowerCase();
  const lines = text.split('\n');
  let matchCount = 0;
  const rendered = lines.map((line, i) => {
    const lower = line.toLowerCase();
    const idx = lower.indexOf(qLower);
    if (idx === -1) {
      return <span key={i} style={{ display: 'block', opacity: 0.3 }}>{line || ' '}</span>;
    }
    matchCount++;
    return (
      <span key={i} style={{ display: 'block', background: '#2a2000' }}>
        {line.slice(0, idx)}
        <mark style={{ background: '#e0a820', color: '#0a0a0a', borderRadius: 2, padding: '0 1px' }}>{line.slice(idx, idx + query.length)}</mark>
        {line.slice(idx + query.length)}
      </span>
    );
  });
  return (
    <div>
      <div style={{ marginBottom: 4, fontSize: 10, color: '#e0a820', fontFamily: 'JetBrains Mono' }}>
        {matchCount} matching line{matchCount !== 1 ? 's' : ''}
      </div>
      <pre style={{ background: '#070a10', border: '1px solid #3a2800', borderRadius: 4, padding: '8px 10px', color: '#c8cfe0', fontSize: 11, maxHeight: 300, overflow: 'auto', margin: 0 }}>
        {rendered}
      </pre>
    </div>
  );
}

const ARTIFACT_TYPE_CFG = {
  hash_ntlm:   { color: '#f09a3a', label: 'NTLM' },
  hash_krb:    { color: '#c07af0', label: 'KRB' },
  secret:      { color: '#e8574a', label: 'Secret' },
  file_ref:    { color: '#5b8af5', label: 'File' },
  stdout_clip: { color: '#808590', label: 'Clip' },
  file:        { color: '#39d353', label: 'File' },
};

function ArtifactsPanel({ pid, jobId, accent }) {
  const [artifacts, setArtifacts] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!pid || !jobId) return;
    setLoading(true);
    api.getJobArtifacts(pid, jobId)
      .then(data => setArtifacts(data || []))
      .catch(() => setArtifacts([]))
      .finally(() => setLoading(false));
  }, [pid, jobId]);

  if (loading) return <div style={{ fontSize: 10, color: '#404550', marginBottom: 8 }}>Loading artifacts…</div>;
  if (!artifacts || artifacts.length === 0) return null;

  return (
    <div style={{ marginBottom: 8, padding: '6px 10px', background: '#0a1018', border: '1px solid #5b8af533', borderRadius: 4 }}>
      <div style={{ fontSize: 10, color: '#5b8af5', marginBottom: 6, fontFamily: 'JetBrains Mono' }}>
        Artifacts ({artifacts.length})
      </div>
      {artifacts.map((a, i) => {
        const cfg = ARTIFACT_TYPE_CFG[a.artifact_type] || ARTIFACT_TYPE_CFG.file;
        return (
          <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 5, paddingBottom: 5, borderBottom: i < artifacts.length - 1 ? '1px solid #1a1c22' : 'none' }}>
            <span style={{ fontSize: 8, color: cfg.color, background: cfg.color + '18', border: `1px solid ${cfg.color}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', flexShrink: 0, marginTop: 1 }}>{cfg.label}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono', wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>{a.value.length > 120 ? a.value.slice(0, 120) + '…' : a.value}</div>
              {a.description && <div style={{ fontSize: 9, color: '#505560', marginTop: 2 }}>{a.description}</div>}
              {a.sha256 && <div style={{ fontSize: 8, color: '#303540', fontFamily: 'JetBrains Mono', marginTop: 1 }}>sha256: {a.sha256.slice(0, 16)}…</div>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function JobRow({ job, pid, accent, onCancel, onDelete, onRerun, onRetry, onLive, outputSearchQuery, indent }) {
  const [expanded, setExpanded] = useState(false);
  const hasOutput = job.output || job.error_output;

  // Auto-expand when output search is active and job has matching output
  useEffect(() => {
    if (outputSearchQuery && hasOutput) setExpanded(true);
    if (!outputSearchQuery) setExpanded(false);
  }, [outputSearchQuery, hasOutput]);
  const duration = calcDuration(job);
  const playbookRunId = job.request_json?.playbook_run_id;
  const isLiveable = job.status === 'running' || job.status === 'done' || job.status === 'failed';

  return (
    <>
      <tr
        onClick={() => hasOutput && setExpanded(e => !e)}
        style={{ cursor: hasOutput ? 'pointer' : 'default', borderBottom: '1px solid #1e2230', background: indent ? '#ffffff02' : 'transparent' }}
      >
        <td style={{ padding: '8px 10px', paddingLeft: indent ? 22 : 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <TypeBadge type={job.type} />
            <span style={{ color: '#c8cfe0', fontSize: 13 }}>{job.title || '—'}</span>
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
            <MetaBadge value={job.connector_key || ''} color="#6fc8f0" />
            <MetaBadge value={OP_CFG[job.operation]?.label || job.operation} color={OP_CFG[job.operation]?.color || '#808590'} />
            <MetaBadge value={job.related_entity_type && job.related_entity_id ? `${job.related_entity_type}:${job.related_entity_id.slice(0, 8)}` : ''} color="#606570" />
            {job.priority >= 10 && <MetaBadge value="⬆ HIGH" color="#f09a3a" />}
            {job.priority <= -10 && <MetaBadge value="⬇ BULK" color="#808590" />}
            {job.retry_count > 0 && <MetaBadge value={`↻ retry ${job.retry_count}${job.max_retries > 0 ? `/${job.max_retries}` : ''}`} color="#c07af0" />}
          </div>
          {job.target && <div style={{ color: '#6a7080', fontSize: 11, marginTop: 2 }}>{job.target}</div>}
          <StructuredBadges result={job.result_json} />
        </td>
        <td style={{ padding: '8px 10px', whiteSpace: 'nowrap' }}>
          <StatusBadge status={job.status} />
        </td>
        <td style={{ padding: '8px 10px', color: '#6a7080', fontSize: 12, whiteSpace: 'nowrap' }}>
          {job.created_by || '—'}
        </td>
        <td style={{ padding: '8px 10px', color: '#6a7080', fontSize: 12, whiteSpace: 'nowrap' }}>
          {job.created_at ? job.created_at.slice(0, 16) : '—'}
        </td>
        <td style={{ padding: '8px 10px', color: '#6a7080', fontSize: 12, whiteSpace: 'nowrap' }}>
          {job.finished_at ? job.finished_at.slice(0, 16) : '—'}
        </td>
        <td style={{ padding: '8px 10px', color: '#6a7080', fontSize: 12, whiteSpace: 'nowrap' }}>
          {duration || '—'}
        </td>
        <td style={{ padding: '8px 10px', textAlign: 'right' }} onClick={e => e.stopPropagation()}>
          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
            {job.status === 'running' && (
              <button onClick={() => onLive(job)} style={{ ...btnStyle('#f09a3a'), fontWeight: 700 }}>⬤ Live</button>
            )}
            {(job.status === 'done' || job.status === 'failed') && isLiveable && (
              <button onClick={() => onLive(job)} style={btnStyle(accent)}>Output</button>
            )}
            {(job.status === 'queued' || job.status === 'running') && (
              <button onClick={() => onCancel(job.id)} style={btnStyle('#f09a3a')}>Cancel</button>
            )}
            {(job.status === 'failed' || job.status === 'cancelled') && (
              <button onClick={() => onRetry(job.id)} style={btnStyle('#c07af0')}>Retry</button>
            )}
            {job.status !== 'queued' && job.status !== 'running' && (
              <button onClick={() => onRerun(job.id)} style={btnStyle('#5b8af5')}>Rerun</button>
            )}
            <button onClick={() => onDelete(job.id)} style={btnStyle('#cc2233')}>Delete</button>
          </div>
        </td>
      </tr>
      {expanded && (
        <tr style={{ background: '#0d0f18' }}>
          <td colSpan={7} style={{ padding: '0 10px 10px' }}>
            {job.command && (
              <div style={{ marginBottom: 6 }}>
                <span style={{ color: '#6a7080', fontSize: 11 }}>Command: </span>
                <code style={{ color: '#a0a8b8', fontSize: 11 }}>{job.command}</code>
              </div>
            )}
            {(job.scope_type || job.scope_id || job.result_json || playbookRunId) && (
              <div style={{ marginBottom: 6, color: '#6a7080', fontSize: 11, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                {job.scope_type && <span>Scope: <code style={{ color: '#a0a8b8' }}>{job.scope_type}</code></span>}
                {job.scope_id && <span>Scope ID: <code style={{ color: '#a0a8b8' }}>{job.scope_id}</code></span>}
                {summarizeResult(job.result_json) && <span>Result: <code style={{ color: '#a0a8b8' }}>{summarizeResult(job.result_json)}</code></span>}
                {playbookRunId && <span>Playbook run: <code style={{ color: '#5b8af5', fontFamily: 'JetBrains Mono', fontSize: 10 }}>{playbookRunId}</code></span>}
                {job.retry_count > 0 && <span>Retry: <code style={{ color: '#c07af0' }}>{job.retry_count}{job.max_retries > 0 ? `/${job.max_retries}` : ''}</code></span>}
                {job.retry_of_job_id && <span>Retry of: <code style={{ color: '#c07af0', fontFamily: 'JetBrains Mono', fontSize: 10 }}>{job.retry_of_job_id.slice(0, 12)}</code></span>}
              </div>
            )}
            <EnrichmentPanel enrichment={job.result_json?.enrichment} />
            {job.status === 'done' && pid && <ArtifactsPanel pid={pid} jobId={job.id} accent={accent} />}
            {job.result_json?.structured?.finding_candidates?.length > 0 && (
              <div style={{ marginBottom: 8, padding: '6px 10px', background: '#1a1500', border: '1px solid #e0a82033', borderRadius: 4 }}>
                <div style={{ fontSize: 10, color: '#e0a820', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>Finding candidates</div>
                {job.result_json.structured.finding_candidates.map((fc, i) => (
                  <div key={i} style={{ fontSize: 11, color: '#c8cdd6', display: 'flex', gap: 8, alignItems: 'center', marginBottom: 2 }}>
                    <span style={{ fontSize: 9, color: fc.severity === 'critical' ? '#f87171' : fc.severity === 'high' ? '#f09a3a' : '#e0a820', background: (fc.severity === 'critical' ? '#f87171' : fc.severity === 'high' ? '#f09a3a' : '#e0a820') + '18', border: `1px solid ${fc.severity === 'critical' ? '#f87171' : fc.severity === 'high' ? '#f09a3a' : '#e0a820'}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{fc.severity}</span>
                    <span>{fc.title}</span>
                    {fc.details && <span style={{ color: '#6a7080', fontSize: 10 }}>{fc.details}</span>}
                  </div>
                ))}
              </div>
            )}
            {job.output && (
              <div style={{ marginBottom: job.error_output ? 8 : 0 }}>
                {renderHighlightedOutput(job.output, outputSearchQuery)}
              </div>
            )}
            {job.error_output && (
              <pre style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 4, padding: '8px 10px', color: '#f87171', fontSize: 11, maxHeight: 200, overflow: 'auto', margin: 0 }}>{job.error_output}</pre>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function btnStyle(color) {
  return {
    background: color + '22', color, border: `1px solid ${color}44`,
    borderRadius: 4, padding: '2px 10px', fontSize: 11, cursor: 'pointer',
    fontWeight: 600,
  };
}

function PlaybookRunGroup({ run, jobs, accent, pid, onCancel, onDelete, onRerun, onRetry, onLive, outputSearchQuery }) {
  const [open, setOpen] = useState(() => jobs.some(j => j.status === 'running' || j.status === 'failed'));

  const counts = { done: 0, failed: 0, running: 0, queued: 0, cancelled: 0 };
  for (const j of jobs) counts[j.status] = (counts[j.status] || 0) + 1;
  const groupStatus = counts.running > 0 ? 'running' : counts.failed > 0 ? 'failed' : counts.queued > 0 ? 'queued' : 'done';
  const cfg = STATUS_CFG[groupStatus] || STATUS_CFG.done;

  const doneJobs = jobs.filter(j => j.status === 'done').length;
  const totalJobs = jobs.length;

  return (
    <div style={{ marginBottom: 6, border: `1px solid ${cfg.color}28`, borderRadius: 6, overflow: 'hidden' }}>
      {/* Group header */}
      <div
        onClick={() => setOpen(v => !v)}
        style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: `${cfg.color}0c`, cursor: 'pointer', userSelect: 'none' }}
        onMouseEnter={e => e.currentTarget.style.background = `${cfg.color}16`}
        onMouseLeave={e => e.currentTarget.style.background = `${cfg.color}0c`}
      >
        <span style={{ fontSize: 10, color: cfg.color, transition: 'transform .15s', display: 'inline-block', transform: open ? 'rotate(90deg)' : 'rotate(0deg)' }}>▶</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <span style={{ fontSize: 13, color: '#c8cfe0', fontWeight: 600 }}>{run?.title || `Run ${(run?.id || '').slice(0, 8)}`}</span>
          {run?.playbook_id && <span style={{ fontSize: 10, color: '#505560', marginLeft: 8, fontFamily: 'JetBrains Mono' }}>{run.playbook_id}</span>}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <StatusBadge status={groupStatus} />
          <span style={{ fontSize: 11, color: '#606570', fontFamily: 'JetBrains Mono' }}>{doneJobs}/{totalJobs} jobs</span>
          {counts.failed > 0 && <MetaBadge value={`${counts.failed} failed`} color="#cc2233" />}
          {counts.running > 0 && <MetaBadge value={`${counts.running} running`} color="#f09a3a" />}
          {run?.created_at && <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>{run.created_at.slice(0, 16).replace('T', ' ')}</span>}
        </div>
      </div>
      {/* Child jobs */}
      {open && (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <tbody>
            {jobs.map(job => (
              <JobRow key={job.id} job={job} pid={pid} accent={accent} onCancel={onCancel} onDelete={onDelete} onRerun={onRerun} onRetry={onRetry} onLive={onLive} outputSearchQuery={outputSearchQuery} indent />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function JobsView({ selectedProject, accent, jobs: jobsProp, onJobUpdate, onJobDelete, initialFilter, onFilterConsumed }) {
  const [jobs, setJobs] = useState([]);
  const [filter, setFilter] = useState('all');
  const [liveJob, setLiveJob] = useState(null);
  const [typeFilter, setTypeFilter] = useState('all');
  const [connectorFilter, setConnectorFilter] = useState('all');
  const [playbookRunFilter, setPlaybookRunFilter] = useState('');
  const [searchText, setSearchText] = useState('');
  const [outputSearch, setOutputSearch] = useState('');
  const [outputSearchDebounced, setOutputSearchDebounced] = useState('');
  const [loading, setLoading] = useState(false);
  const [viewMode, setViewMode] = useState('flat'); // 'flat' | 'grouped'
  const [playbookRuns, setPlaybookRuns] = useState([]);
  const [workerStatus, setWorkerStatus] = useState(null);
  const pid = selectedProject;
  const pollRef = useRef(null);
  const outputDebounceRef = useRef(null);

  useEffect(() => {
    if (!initialFilter) return;
    if (initialFilter.playbookRunId) setPlaybookRunFilter(initialFilter.playbookRunId);
    if (onFilterConsumed) onFilterConsumed();
  }, [initialFilter]);

  // Debounce output search input → triggers re-fetch
  useEffect(() => {
    clearTimeout(outputDebounceRef.current);
    outputDebounceRef.current = setTimeout(() => setOutputSearchDebounced(outputSearch), 400);
    return () => clearTimeout(outputDebounceRef.current);
  }, [outputSearch]);

  const load = useCallback(() => {
    if (!pid) return;
    setLoading(true);
    const params = { limit: 200 };
    if (outputSearchDebounced) params.output_search = outputSearchDebounced;
    api.listJobs(pid, params).then(data => {
      setJobs(data);
    }).catch(() => {}).finally(() => setLoading(false));
    api.getWorkerStatus().then(setWorkerStatus).catch(() => {});
  }, [pid, outputSearchDebounced]);

  useEffect(() => { load(); }, [load]);

  // Merge WS updates from App.jsx without replacing the full API-loaded list
  const prevJobsPropRef = useRef([]);
  useEffect(() => {
    const curr = jobsProp || [];
    const prev = prevJobsPropRef.current;
    prevJobsPropRef.current = curr;

    const currMap = new Map(curr.map(j => [j.id, j]));
    const prevMap = new Map(prev.map(j => [j.id, j]));
    const upserts = curr.filter(j => {
      const p = prevMap.get(j.id);
      return !p || p.status !== j.status || p.output !== j.output || p.finished_at !== j.finished_at;
    });
    const deletedIds = new Set(prev.filter(p => !currMap.has(p.id)).map(p => p.id));

    if (upserts.length === 0 && deletedIds.size === 0) return;
    setJobs(localJobs => {
      let result = localJobs.filter(j => !deletedIds.has(j.id));
      const localMap = new Map(result.map(j => [j.id, j]));
      for (const u of upserts) localMap.set(u.id, u);
      return [...localMap.values()].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
    });
  }, [jobsProp]);

  // Auto-poll every 3s while running/queued jobs exist
  const hasActive = useMemo(() => jobs.some(j => j.status === 'running' || j.status === 'queued'), [jobs]);
  useEffect(() => {
    if (hasActive) {
      pollRef.current = setInterval(load, 3000);
    } else {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    return () => clearInterval(pollRef.current);
  }, [hasActive, load]);

  const handleCancel = async (jobId) => {
    try {
      const updated = await api.cancelJob(pid, jobId);
      setJobs(prev => prev.map(j => j.id === jobId ? updated : j));
      if (onJobUpdate) onJobUpdate(updated);
    } catch (e) {
      toastError(e.message || 'Failed to cancel job');
    }
  };

  const handleDelete = async (jobId) => {
    try {
      await api.deleteJob(pid, jobId);
      setJobs(prev => prev.filter(j => j.id !== jobId));
      if (onJobDelete) onJobDelete(jobId);
    } catch (e) {
      toastError(e.message || 'Failed to delete job');
    }
  };

  const handleRerun = async (jobId) => {
    try {
      const created = await api.rerunJob(pid, jobId);
      setJobs(prev => [created, ...prev.filter(j => j.id !== created.id)]);
      if (onJobUpdate) onJobUpdate(created);
    } catch (e) {
      toastError(e.message || 'Failed to rerun job');
    }
  };

  const handleRetry = async (jobId) => {
    try {
      const created = await api.retryJob(pid, jobId);
      setJobs(prev => [created, ...prev.filter(j => j.id !== created.id)]);
      if (onJobUpdate) onJobUpdate(created);
    } catch (e) {
      toastError(e.message || 'Failed to retry job');
    }
  };

  // Load playbook runs when switching to grouped mode
  useEffect(() => {
    if (viewMode !== 'grouped' || !pid) return;
    api.listPlaybookRuns(pid, { limit: 200 }).then(data => setPlaybookRuns(data?.runs || [])).catch(() => {});
  }, [viewMode, pid]);

  const connectorKeys = useMemo(() => {
    const seen = new Set();
    for (const j of jobs) if (j.connector_key) seen.add(j.connector_key);
    return [...seen].sort();
  }, [jobs]);

  const displayed = jobs.filter(j => {
    if (filter !== 'all' && j.status !== filter) return false;
    if (typeFilter !== 'all' && j.type !== typeFilter) return false;
    if (connectorFilter !== 'all' && j.connector_key !== connectorFilter) return false;
    if (playbookRunFilter && j.request_json?.playbook_run_id !== playbookRunFilter) return false;
    if (searchText) {
      const q = searchText.toLowerCase();
      if (!(j.title || '').toLowerCase().includes(q) && !(j.target || '').toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const counts = { all: jobs.length };
  for (const j of jobs) counts[j.status] = (counts[j.status] || 0) + 1;

  const acc = accent || '#5b8af5';

  if (!pid) {
    return (
      <div style={{ padding: 40, color: '#6a7080', textAlign: 'center' }}>
        Select a project to view jobs
      </div>
    );
  }

  return (
    <div style={{ padding: '20px 24px', height: '100%', overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2 style={{ color: '#c8cfe0', margin: 0, fontSize: 18 }}>Job Center</h2>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {/* Worker status */}
          {workerStatus && (
            <span title={`Worker pool: ${workerStatus.active}/${workerStatus.max_workers} active, ${workerStatus.queue_size} queued`}
              style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: workerStatus.active > 0 ? '#f09a3a' : '#404550', background: '#13161f', border: `1px solid ${workerStatus.active > 0 ? '#f09a3a44' : '#1e2230'}`, borderRadius: 4, padding: '3px 8px' }}>
              ⚙ {workerStatus.active}/{workerStatus.max_workers}
              {workerStatus.queue_size > 0 && ` +${workerStatus.queue_size}`}
            </span>
          )}
          {/* View mode toggle */}
          {['flat', 'grouped'].map(mode => (
            <button key={mode} onClick={() => setViewMode(mode)}
              style={{ background: viewMode === mode ? acc + '33' : '#13161f', color: viewMode === mode ? acc : '#6a7080', border: `1px solid ${viewMode === mode ? acc + '66' : '#1e2230'}`, borderRadius: 4, padding: '3px 10px', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>
              {mode === 'flat' ? '≡ Flat' : '⊞ Grouped'}
            </button>
          ))}
          <button onClick={load} style={{ background: acc + '22', color: acc, border: `1px solid ${acc}44`, borderRadius: 4, padding: '4px 14px', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}>
            Refresh
          </button>
        </div>
      </div>

      {/* Search + playbook run filter */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          value={searchText}
          onChange={e => setSearchText(e.target.value)}
          placeholder="Search title / target…"
          style={{ background: '#13161f', color: '#c8cfe0', border: '1px solid #1e2230', borderRadius: 4, padding: '4px 10px', fontSize: 12, width: 200 }}
        />
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
          <input
            value={outputSearch}
            onChange={e => setOutputSearch(e.target.value)}
            placeholder="Search in output…"
            style={{
              background: '#13161f', color: '#c8cfe0',
              border: `1px solid ${outputSearchDebounced ? '#e0a82066' : '#1e2230'}`,
              borderRadius: 4, padding: '4px 28px 4px 10px', fontSize: 12, width: 200,
              outline: outputSearchDebounced ? '1px solid #e0a82033' : 'none',
            }}
          />
          {outputSearch && (
            <button
              onClick={() => { setOutputSearch(''); setOutputSearchDebounced(''); }}
              style={{ position: 'absolute', right: 6, background: 'none', border: 'none', color: '#606570', cursor: 'pointer', fontSize: 13, lineHeight: 1, padding: 0 }}
            >×</button>
          )}
        </div>
        {outputSearchDebounced && (
          <span style={{ fontSize: 11, color: '#e0a820', fontFamily: 'JetBrains Mono' }}>
            output: "{outputSearchDebounced}" · {jobs.length} job{jobs.length !== 1 ? 's' : ''}
          </span>
        )}
        {playbookRunFilter && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: '#5b8af522', border: '1px solid #5b8af544', borderRadius: 4, padding: '2px 8px' }}>
            <span style={{ color: '#5b8af5', fontSize: 11, fontFamily: 'JetBrains Mono' }}>playbook: {playbookRunFilter.slice(0, 8)}…</span>
            <button onClick={() => setPlaybookRunFilter('')} style={{ background: 'none', border: 'none', color: '#5b8af5', cursor: 'pointer', fontSize: 13, lineHeight: 1, padding: 0 }}>×</button>
          </div>
        )}
      </div>

      {/* Status filter */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
        {['all', 'running', 'queued', 'done', 'failed', 'cancelled'].map(s => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            style={{
              background: filter === s ? (STATUS_CFG[s]?.color || acc) + '33' : '#13161f',
              color: filter === s ? (STATUS_CFG[s]?.color || acc) : '#6a7080',
              border: `1px solid ${filter === s ? (STATUS_CFG[s]?.color || acc) + '66' : '#1e2230'}`,
              borderRadius: 4, padding: '3px 12px', fontSize: 12, cursor: 'pointer', fontWeight: 600,
            }}
          >
            {s === 'all' ? 'All' : STATUS_CFG[s]?.label || s}
            {counts[s] > 0 && <span style={{ marginLeft: 5, opacity: 0.7 }}>{counts[s]}</span>}
          </button>
        ))}
      </div>

      {/* Type filter pills */}
      <div style={{ display: 'flex', gap: 5, marginBottom: 8, flexWrap: 'wrap' }}>
        <button
          onClick={() => setTypeFilter('all')}
          style={{ background: typeFilter === 'all' ? acc + '33' : '#13161f', color: typeFilter === 'all' ? acc : '#6a7080', border: `1px solid ${typeFilter === 'all' ? acc + '66' : '#1e2230'}`, borderRadius: 4, padding: '2px 10px', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}
        >All types</button>
        {Object.entries(TYPE_CFG).map(([k, v]) => (
          <button key={k} onClick={() => setTypeFilter(typeFilter === k ? 'all' : k)}
            style={{ background: typeFilter === k ? v.color + '33' : '#13161f', color: typeFilter === k ? v.color : '#6a7080', border: `1px solid ${typeFilter === k ? v.color + '66' : '#1e2230'}`, borderRadius: 4, padding: '2px 10px', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}
          >{v.label}</button>
        ))}
      </div>

      {/* Connector filter pills */}
      {connectorKeys.length > 0 && (
        <div style={{ display: 'flex', gap: 5, marginBottom: 12, flexWrap: 'wrap' }}>
          <button
            onClick={() => setConnectorFilter('all')}
            style={{ background: connectorFilter === 'all' ? '#6fc8f033' : '#13161f', color: connectorFilter === 'all' ? '#6fc8f0' : '#6a7080', border: `1px solid ${connectorFilter === 'all' ? '#6fc8f066' : '#1e2230'}`, borderRadius: 4, padding: '2px 10px', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}
          >All connectors</button>
          {connectorKeys.map(k => (
            <button key={k} onClick={() => setConnectorFilter(connectorFilter === k ? 'all' : k)}
              style={{ background: connectorFilter === k ? '#6fc8f033' : '#13161f', color: connectorFilter === k ? '#6fc8f0' : '#6a7080', border: `1px solid ${connectorFilter === k ? '#6fc8f066' : '#1e2230'}`, borderRadius: 4, padding: '2px 10px', fontSize: 11, cursor: 'pointer', fontWeight: 600, fontFamily: 'JetBrains Mono' }}
            >{k}</button>
          ))}
        </div>
      )}

      {loading && <div style={{ color: '#6a7080', fontSize: 13 }}>Loading...</div>}

      {!loading && displayed.length === 0 && (
        <div style={{ color: '#6a7080', fontSize: 13, padding: '20px 0' }}>
          No jobs found
        </div>
      )}

      {displayed.length > 0 && viewMode === 'flat' && (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #1e2230' }}>
              {['Job', 'Status', 'By', 'Created', 'Finished', 'Duration', ''].map((h, i) => (
                <th key={i} style={{ padding: '6px 10px', color: '#6a7080', fontWeight: 500, fontSize: 11, textAlign: i === 6 ? 'right' : 'left' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {displayed.map(job => (
              <JobRow key={job.id} job={job} pid={selectedProject} accent={acc} onCancel={handleCancel} onDelete={handleDelete} onRerun={handleRerun} onRetry={handleRetry} onLive={setLiveJob} outputSearchQuery={outputSearchDebounced} />
            ))}
          </tbody>
        </table>
      )}

      {displayed.length > 0 && viewMode === 'grouped' && (() => {
        const runsMap = new Map(playbookRuns.map(r => [r.id, r]));
        const grouped = new Map(); // runId → jobs[]
        const standalone = [];
        for (const j of displayed) {
          const runId = j.request_json?.playbook_run_id;
          if (runId) {
            if (!grouped.has(runId)) grouped.set(runId, []);
            grouped.get(runId).push(j);
          } else {
            standalone.push(j);
          }
        }
        // Sort groups: running first, then failed, then by newest job
        const sortedGroups = [...grouped.entries()].sort(([, ajobs], [, bjobs]) => {
          const aPri = ajobs.some(j => j.status === 'running') ? 0 : ajobs.some(j => j.status === 'failed') ? 1 : 2;
          const bPri = bjobs.some(j => j.status === 'running') ? 0 : bjobs.some(j => j.status === 'failed') ? 1 : 2;
          if (aPri !== bPri) return aPri - bPri;
          return (bjobs[0]?.created_at || '').localeCompare(ajobs[0]?.created_at || '');
        });
        return (
          <div>
            {sortedGroups.map(([runId, groupJobs]) => (
              <PlaybookRunGroup
                key={runId}
                run={runsMap.get(runId)}
                jobs={groupJobs}
                accent={acc}
                pid={selectedProject}
                onCancel={handleCancel}
                onDelete={handleDelete}
                onRerun={handleRerun}
                onRetry={handleRetry}
                onLive={setLiveJob}
                outputSearchQuery={outputSearchDebounced}
              />
            ))}
            {standalone.length > 0 && (
              <div style={{ marginTop: sortedGroups.length > 0 ? 16 : 0 }}>
                {sortedGroups.length > 0 && (
                  <div style={{ fontSize: 11, color: '#404550', fontFamily: 'JetBrains Mono', marginBottom: 6, paddingLeft: 2 }}>
                    standalone jobs ({standalone.length})
                  </div>
                )}
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <tbody>
                    {standalone.map(job => (
                      <JobRow key={job.id} job={job} pid={selectedProject} accent={acc} onCancel={handleCancel} onDelete={handleDelete} onRerun={handleRerun} onRetry={handleRetry} onLive={setLiveJob} outputSearchQuery={outputSearchDebounced} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })()}
      {liveJob && (
        <LiveOutputPanel
          pid={selectedProject}
          jobId={liveJob.id}
          accent={acc}
          onClose={() => setLiveJob(null)}
        />
      )}
    </div>
  );
}
