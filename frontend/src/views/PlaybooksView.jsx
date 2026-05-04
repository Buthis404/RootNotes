import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api.js';

const RUN_STATUS = {
  queued: { color: '#a0a8b8', label: 'Queued' },
  running: { color: '#f09a3a', label: 'Running' },
  done: { color: '#39d353', label: 'Done' },
  failed: { color: '#cc2233', label: 'Failed' },
  cancelled: { color: '#6a7080', label: 'Cancelled' },
};

function StatusBadge({ status }) {
  const meta = RUN_STATUS[status] || { color: '#808590', label: status || 'unknown' };
  return <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: meta.color, background: meta.color + '18', border: `1px solid ${meta.color}33`, borderRadius: 4, padding: '2px 8px' }}>{meta.label}</span>;
}

function PlaybookCard({ playbook, accent, selected, onSelect }) {
  return (
    <button onClick={() => onSelect(playbook.id)} style={{ width: '100%', textAlign: 'left', background: selected ? `${accent}18` : '#0d0f14', border: `1px solid ${selected ? accent + '55' : '#1e2029'}`, borderRadius: 8, padding: '12px 14px', cursor: 'pointer' }}>
      <div style={{ fontSize: 13, color: selected ? '#f0f2f6' : '#e0e4ec', fontWeight: 600, marginBottom: 4 }}>{playbook.title}</div>
      <div style={{ fontSize: 10, color: '#606570', lineHeight: 1.5 }}>{playbook.description}</div>
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>
        {(playbook.steps || []).map((step, idx) => <span key={`${playbook.id}-${idx}`} style={{ fontSize: 9, color: '#808590', background: '#13161f', border: '1px solid #1e2230', borderRadius: 4, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{step.type}:{step.operation}</span>)}
      </div>
    </button>
  );
}

export default function PlaybooksView({ selectedProject, accent }) {
  const [playbooks, setPlaybooks] = useState([]);
  const [runs, setRuns] = useState([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState('');
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [form, setForm] = useState({ target: '', target_url: '', flags: '-sV -sC -T4 --open', severity: 'critical,high,medium', keep_manual_positions: true, create_missing_networks: true });

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    try {
      const [pb, runData] = await Promise.all([
        api.listPlaybooks(),
        api.listPlaybookRuns(selectedProject, { limit: 100 }),
      ]);
      setPlaybooks(pb.playbooks || []);
      setRuns(runData.runs || []);
      setSelectedPlaybookId(prev => prev || pb.playbooks?.[0]?.id || '');
    } catch (e) {
      setError(e.message || 'Failed to load playbooks');
    } finally {
      setLoading(false);
    }
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  const hasActiveRuns = useMemo(() => runs.some(run => run.status === 'queued' || run.status === 'running'), [runs]);
  useEffect(() => {
    if (!hasActiveRuns || !selectedProject) return;
    const iv = setInterval(() => {
      api.listPlaybookRuns(selectedProject, { limit: 100 }).then(data => setRuns(data.runs || [])).catch(() => {});
    }, 3000);
    return () => clearInterval(iv);
  }, [hasActiveRuns, selectedProject]);

  const selected = playbooks.find(p => p.id === selectedPlaybookId) || null;

  const runSelected = async () => {
    if (!selectedProject || !selected) return;
    setRunning(true);
    setError('');
    try {
      const res = await api.runPlaybook(selectedProject, selected.id, form);
      if (res.playbook_run) setRuns(prev => [res.playbook_run, ...prev.filter(r => r.id !== res.playbook_run.id)]);
    } catch (e) {
      setError(e.message || 'Failed to run playbook');
    } finally {
      setRunning(false);
    }
  };

  if (!selectedProject) return <div style={{ padding: 40, color: '#6a7080', textAlign: 'center' }}>Select a project to work with playbooks</div>;

  return (
    <div style={{ padding: '20px 24px', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ color: '#c8cfe0', margin: 0, fontSize: 18 }}>Playbooks</h2>
          <div style={{ fontSize: 11, color: '#6a7080', marginTop: 4 }}>Sequential orchestration layer built on top of jobs and connectors</div>
        </div>
        <button onClick={load} style={{ background: accent + '22', color: accent, border: `1px solid ${accent}44`, borderRadius: 4, padding: '4px 14px', fontSize: 12, cursor: 'pointer', fontWeight: 600 }}>Refresh</button>
      </div>

      {error && <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 12 }}>{error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 18, minHeight: 0 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {(playbooks || []).map(playbook => <PlaybookCard key={playbook.id} playbook={playbook} accent={accent} selected={selectedPlaybookId === playbook.id} onSelect={setSelectedPlaybookId} />)}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, padding: 16 }}>
            <div style={{ fontSize: 14, color: '#e0e4ec', fontWeight: 600, marginBottom: 12 }}>{selected?.title || 'Select a playbook'}</div>
            {selected && <div style={{ fontSize: 11, color: '#606570', lineHeight: 1.6, marginBottom: 14 }}>{selected.description}</div>}
            {selected && (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Target</div>
                    <input value={form.target} onChange={e => setForm(prev => ({ ...prev, target: e.target.value }))} placeholder="10.0.0.0/24" style={inp()} />
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Target URL</div>
                    <input value={form.target_url} onChange={e => setForm(prev => ({ ...prev, target_url: e.target.value }))} placeholder="https://target.example" style={inp()} />
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Nmap flags</div>
                    <input value={form.flags} onChange={e => setForm(prev => ({ ...prev, flags: e.target.value }))} style={inp()} />
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Nuclei severity</div>
                    <input value={form.severity} onChange={e => setForm(prev => ({ ...prev, severity: e.target.value }))} style={inp()} />
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                  <button onClick={() => setForm(prev => ({ ...prev, keep_manual_positions: !prev.keep_manual_positions }))} style={toggleBtn(form.keep_manual_positions, accent)}>{form.keep_manual_positions ? 'Keep manual positions' : 'Ignore manual positions'}</button>
                  <button onClick={() => setForm(prev => ({ ...prev, create_missing_networks: !prev.create_missing_networks }))} style={toggleBtn(form.create_missing_networks, accent)}>{form.create_missing_networks ? 'Create missing networks' : 'No auto-create'}</button>
                </div>
                <button onClick={runSelected} disabled={running} style={{ background: running ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '8px 16px', cursor: running ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{running ? 'Starting...' : 'Run playbook'}</button>
              </>
            )}
          </div>

          <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid #1e2029', background: '#090b0f', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 600 }}>Playbook Runs</div>
              <div style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{runs.length} total</div>
            </div>
            {loading ? <div style={{ padding: 16, color: '#505560', fontSize: 12 }}>Loading...</div> : runs.length === 0 ? <div style={{ padding: 16, color: '#505560', fontSize: 12 }}>No playbook runs yet.</div> : (
              <div>
                {runs.map((run, i) => (
                  <div key={run.id} style={{ padding: '12px 16px', borderBottom: i < runs.length - 1 ? '1px solid #14161b' : 'none' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 600 }}>{run.title}</span>
                      <StatusBadge status={run.status} />
                      <span style={{ fontSize: 10, color: '#6fc8f0', fontFamily: 'JetBrains Mono' }}>{run.playbook_id}</span>
                    </div>
                    <div style={{ fontSize: 10, color: '#606570', display: 'flex', gap: 12, flexWrap: 'wrap', fontFamily: 'JetBrains Mono', marginBottom: 6 }}>
                      <span>run: {run.id}</span>
                      {run.target && <span>target: {run.target}</span>}
                      <span>jobs: {(run.jobs_json || []).length}</span>
                      <span>by: {run.created_by || '—'}</span>
                      <span>created: {run.created_at?.slice(0, 16) || '—'}</span>
                    </div>
                    {(run.result_json?.completed_jobs?.length > 0 || run.error_output) && (
                      <div style={{ fontSize: 10, color: run.error_output ? '#f87171' : '#808590', lineHeight: 1.6, fontFamily: 'JetBrains Mono' }}>
                        {run.result_json?.completed_jobs?.length > 0 && <div>completed jobs: {run.result_json.completed_jobs.join(', ')}</div>}
                        {run.error_output && <div>{run.error_output}</div>}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function inp() {
  return { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };
}

function toggleBtn(active, accent) {
  return {
    background: active ? `${accent}22` : '#13161f',
    border: `1px solid ${active ? accent + '66' : '#1e2230'}`,
    borderRadius: 4,
    padding: '5px 10px',
    cursor: 'pointer',
    color: active ? accent : '#808590',
    fontSize: 10,
    fontFamily: 'JetBrains Mono',
  };
}
