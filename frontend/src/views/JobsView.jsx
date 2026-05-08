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
  const preferred = ['hosts_created', 'hosts_updated', 'links_added', 'findings_created', 'findings_found', 'creds_created', 'creds_found', 'hosts_valid', 'hosts_failed', 'nodes_repositioned', 'exit_code'];
  const parts = [];
  for (const key of preferred) {
    if (result[key] !== undefined && result[key] !== '') parts.push(`${key}=${result[key]}`);
  }
  return parts.join(' · ');
}

function calcDuration(job) {
  if (!job.started_at) return null;
  const s = new Date(job.started_at);
  const f = job.finished_at ? new Date(job.finished_at) : null;
  if (!f) return job.status === 'running' ? 'running…' : null;
  const sec = Math.round((f - s) / 1000);
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function JobRow({ job, accent, onCancel, onDelete, onRerun, onRetry }) {
  const [expanded, setExpanded] = useState(false);
  const hasOutput = job.output || job.error_output;
  const duration = calcDuration(job);
  const playbookRunId = job.request_json?.playbook_run_id;

  return (
    <>
      <tr
        onClick={() => hasOutput && setExpanded(e => !e)}
        style={{ cursor: hasOutput ? 'pointer' : 'default', borderBottom: '1px solid #1e2230' }}
      >
        <td style={{ padding: '8px 10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <TypeBadge type={job.type} />
            <span style={{ color: '#c8cfe0', fontSize: 13 }}>{job.title || '—'}</span>
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
            <MetaBadge value={job.connector_key || ''} color="#6fc8f0" />
            <MetaBadge value={OP_CFG[job.operation]?.label || job.operation} color={OP_CFG[job.operation]?.color || '#808590'} />
            <MetaBadge value={job.related_entity_type && job.related_entity_id ? `${job.related_entity_type}:${job.related_entity_id.slice(0, 8)}` : ''} color="#606570" />
          </div>
          {job.target && <div style={{ color: '#6a7080', fontSize: 11, marginTop: 2 }}>{job.target}</div>}
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
              </div>
            )}
            {job.output && (
              <pre style={{ background: '#070a10', border: '1px solid #1e2230', borderRadius: 4, padding: '8px 10px', color: '#c8cfe0', fontSize: 11, maxHeight: 300, overflow: 'auto', margin: 0, marginBottom: job.error_output ? 8 : 0 }}>{job.output}</pre>
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

export default function JobsView({ selectedProject, accent, jobs: jobsProp, onJobUpdate, onJobDelete, initialFilter, onFilterConsumed }) {
  const [jobs, setJobs] = useState([]);
  const [filter, setFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [connectorFilter, setConnectorFilter] = useState('all');
  const [playbookRunFilter, setPlaybookRunFilter] = useState('');
  const [searchText, setSearchText] = useState('');
  const [loading, setLoading] = useState(false);
  const pid = selectedProject;
  const pollRef = useRef(null);

  useEffect(() => {
    if (!initialFilter) return;
    if (initialFilter.playbookRunId) setPlaybookRunFilter(initialFilter.playbookRunId);
    if (onFilterConsumed) onFilterConsumed();
  }, [initialFilter]);

  const load = useCallback(() => {
    if (!pid) return;
    setLoading(true);
    api.listJobs(pid, { limit: 200 }).then(data => {
      setJobs(data);
    }).catch(() => {}).finally(() => setLoading(false));
  }, [pid]);

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
        <button onClick={load} style={{ background: acc + '22', color: acc, border: `1px solid ${acc}44`, borderRadius: 4, padding: '4px 14px', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}>
          Refresh
        </button>
      </div>

      {/* Search + playbook run filter */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          value={searchText}
          onChange={e => setSearchText(e.target.value)}
          placeholder="Search title / target…"
          style={{ background: '#13161f', color: '#c8cfe0', border: '1px solid #1e2230', borderRadius: 4, padding: '4px 10px', fontSize: 12, width: 220 }}
        />
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

      {displayed.length > 0 && (
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
              <JobRow key={job.id} job={job} accent={acc} onCancel={handleCancel} onDelete={handleDelete} onRerun={handleRerun} onRetry={handleRetry} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
