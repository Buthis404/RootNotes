import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../api.js';

const RUN_STATUS = {
  queued: { color: '#a0a8b8', label: 'Queued' },
  running: { color: '#f09a3a', label: 'Running' },
  done: { color: '#39d353', label: 'Done' },
  failed: { color: '#cc2233', label: 'Failed' },
  cancelled: { color: '#6a7080', label: 'Cancelled' },
};

function emptyStep() {
  return { title: '', connector_key: 'nmap', operation: 'scan', params: {}, on_success: 'next', on_success_step: null, on_failure: 'stop', on_failure_step: null, result_conditions: [] };
}

function emptyPlaybook() {
  return { title: '', description: '', steps: [emptyStep()] };
}

function inp() {
  return { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };
}

function StatusBadge({ status }) {
  const meta = RUN_STATUS[status] || { color: '#808590', label: status || 'unknown' };
  return <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: meta.color, background: meta.color + '18', border: `1px solid ${meta.color}33`, borderRadius: 4, padding: '2px 8px' }}>{meta.label}</span>;
}

function buildStepFromTemplate(template) {
  return {
    title: template.title || '',
    connector_key: template.connector_key,
    operation: template.operation,
    params: Object.fromEntries((template.fields || []).map(field => [field.key, field.default ?? (field.type === 'boolean' ? false : '')])),
    on_success: 'next',
    on_success_step: null,
    on_failure: 'stop',
    on_failure_step: null,
    result_conditions: [],
  };
}

function templateLabel(template) {
  return `${template.connector_key}:${template.operation}`;
}

function emptyCondition() {
  return { when: 'success', result_key: '', operator: 'eq', value: '', action: 'stop', target_step: null };
}

function PlaybookCard({ playbook, accent, selected, onSelect }) {
  const stepCount = (playbook.steps || []).length;
  return (
    <button onClick={() => onSelect(playbook.id)} style={{ width: '100%', minHeight: 104, textAlign: 'left', background: selected ? `${accent}14` : '#0d0f14', border: `1px solid ${selected ? accent + '55' : '#1e2029'}`, borderRadius: 10, padding: '12px 13px', cursor: 'pointer', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: 10, overflow: 'hidden', transition: 'border-color .15s, background .15s' }}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7 }}>
          <div style={{ fontSize: 13, color: selected ? '#f0f2f6' : '#e0e4ec', fontWeight: 700, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{playbook.title}</div>
          <span style={{ fontSize: 9, fontFamily: 'JetBrains Mono', color: playbook.source === 'custom' ? '#c07af0' : '#5b8af5', background: playbook.source === 'custom' ? '#c07af018' : '#5b8af518', border: `1px solid ${playbook.source === 'custom' ? '#c07af033' : '#5b8af533'}`, borderRadius: 999, padding: '2px 7px', flexShrink: 0, textTransform: 'uppercase' }}>{playbook.source}</span>
        </div>
        <div style={{ fontSize: 10, color: '#606570', lineHeight: 1.45, height: 30, overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>{playbook.description || 'No description'}</div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minHeight: 20 }}>
        <span style={{ fontSize: 10, color: selected ? accent : '#9098a8', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>{stepCount} step{stepCount === 1 ? '' : 's'}</span>
        <div style={{ width: 1, height: 12, background: '#262a35' }} />
        <div style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono' }}>
          {(playbook.steps || []).slice(0, 2).map(step => `${step.connector_key}:${step.operation}`).join(' · ')}
          {stepCount > 2 ? ` · +${stepCount - 2}` : ''}
        </div>
      </div>
    </button>
  );
}

function StepEditor({ step, connectors, templates, stepCount, stepIndex, onChange, onDelete, disableDelete }) {
  const matchingConnectors = connectors.filter(c => c.key === step.connector_key);
  const connector = matchingConnectors[0] || null;
  const operations = connector?.supported_operations?.length ? connector.supported_operations : ['scan'];
  const template = templates.find(t => t.connector_key === step.connector_key && t.operation === step.operation) || null;
  const applyTemplate = (nextConnector, nextOperation) => {
    const nextTemplate = templates.find(t => t.connector_key === nextConnector && t.operation === nextOperation);
    if (!nextTemplate) {
      onChange({ ...step, connector_key: nextConnector, operation: nextOperation, params: {} });
      return;
    }
    onChange({
      ...step,
      title: step.title || nextTemplate.title,
      connector_key: nextTemplate.connector_key,
      operation: nextTemplate.operation,
      params: Object.fromEntries((nextTemplate.fields || []).map(field => [field.key, step.params?.[field.key] ?? field.default ?? (field.type === 'boolean' ? false : '')])),
    });
  };
  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 8, padding: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr 120px', gap: 8, marginBottom: 8 }}>
        <input value={step.title} onChange={e => onChange({ ...step, title: e.target.value })} placeholder="Step title" style={inp()} />
        <select value={step.connector_key} onChange={e => applyTemplate(e.target.value, '')} style={inp()}>
          {[...new Map(connectors.map(c => [c.key, c])).values()].map(c => <option key={c.key} value={c.key}>{c.title}</option>)}
        </select>
        <select value={step.operation} onChange={e => applyTemplate(step.connector_key, e.target.value)} style={inp()}>
          <option value="">Select operation</option>
          {operations.map(op => <option key={op} value={op}>{op}</option>)}
        </select>
        <div style={{ display: 'flex', gap: 6 }}>
          <select value={step.on_failure || 'stop'} onChange={e => onChange({ ...step, on_failure: e.target.value, on_failure_step: e.target.value === 'jump' ? (step.on_failure_step || Math.min(stepCount, stepIndex + 2)) : null })} style={inp()}>
            <option value="stop">stop</option>
            <option value="continue">continue</option>
            <option value="jump">jump</option>
          </select>
          <button onClick={onDelete} disabled={disableDelete} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '0 10px', cursor: disableDelete ? 'default' : 'pointer', color: '#cc2233', fontSize: 11, fontFamily: 'JetBrains Mono', opacity: disableDelete ? 0.5 : 1 }}>Delete</button>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 8, marginBottom: 8 }}>
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>On success</div>
          <select value={step.on_success || 'next'} onChange={e => onChange({ ...step, on_success: e.target.value, on_success_step: e.target.value === 'jump' ? (step.on_success_step || Math.min(stepCount, stepIndex + 2)) : null })} style={inp()}>
            <option value="next">next</option>
            <option value="stop">stop</option>
            <option value="jump">jump</option>
          </select>
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Success jump</div>
          <select value={step.on_success_step || ''} disabled={(step.on_success || 'next') !== 'jump'} onChange={e => onChange({ ...step, on_success_step: e.target.value ? Number(e.target.value) : null })} style={{ ...inp(), opacity: (step.on_success || 'next') === 'jump' ? 1 : 0.5 }}>
            <option value="">Select step</option>
            {Array.from({ length: stepCount }, (_, i) => i + 1).map(num => <option key={num} value={num}>Step {num}</option>)}
          </select>
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>On failure</div>
          <select value={step.on_failure || 'stop'} onChange={e => onChange({ ...step, on_failure: e.target.value, on_failure_step: e.target.value === 'jump' ? (step.on_failure_step || Math.min(stepCount, stepIndex + 2)) : null })} style={inp()}>
            <option value="stop">stop</option>
            <option value="continue">continue</option>
            <option value="jump">jump</option>
          </select>
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Failure jump</div>
          <select value={step.on_failure_step || ''} disabled={(step.on_failure || 'stop') !== 'jump'} onChange={e => onChange({ ...step, on_failure_step: e.target.value ? Number(e.target.value) : null })} style={{ ...inp(), opacity: (step.on_failure || 'stop') === 'jump' ? 1 : 0.5 }}>
            <option value="">Select step</option>
            {Array.from({ length: stepCount }, (_, i) => i + 1).map(num => <option key={num} value={num}>Step {num}</option>)}
          </select>
        </div>
      </div>
      {template ? (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {(template.fields || []).map(field => {
            const value = step.params?.[field.key] ?? field.default ?? (field.type === 'boolean' ? false : '');
            const sharedLabel = <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{field.label}{field.runtime_fallback ? ' (runtime ok)' : ''}</div>;
            return (
              <div key={field.key} style={{ gridColumn: field.type === 'textarea' ? '1 / -1' : 'auto' }}>
                {sharedLabel}
                {field.type === 'boolean' ? (
                  <button onClick={() => onChange({ ...step, params: { ...(step.params || {}), [field.key]: !value } })} style={{ width: '100%', ...toggleBtn(!!value, '#5b8af5') }}>{value ? 'Enabled' : 'Disabled'}</button>
                ) : field.type === 'select' ? (
                  <select value={value} onChange={e => onChange({ ...step, params: { ...(step.params || {}), [field.key]: e.target.value } })} style={inp()}>
                    {(field.options || []).map(option => <option key={option} value={option}>{option}</option>)}
                  </select>
                ) : field.type === 'textarea' ? (
                  <textarea value={value} onChange={e => onChange({ ...step, params: { ...(step.params || {}), [field.key]: e.target.value } })} rows={4} style={{ ...inp(), resize: 'vertical' }} />
                ) : field.type === 'number' ? (
                  <input type="number" value={value} onChange={e => onChange({ ...step, params: { ...(step.params || {}), [field.key]: Number(e.target.value) || 0 } })} style={inp()} />
                ) : (
                  <input value={value} onChange={e => onChange({ ...step, params: { ...(step.params || {}), [field.key]: e.target.value } })} style={inp()} />
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 11 }}>No step template exists for this connector/operation yet.</div>
      )}
      {template?.description && <div style={{ fontSize: 10, color: '#505560', marginTop: 8, lineHeight: 1.5 }}>{template.description}</div>}
      <div style={{ fontSize: 10, color: '#505560', marginTop: 6, lineHeight: 1.5 }}>Flow: success → <code>{step.on_success || 'next'}{step.on_success_step ? `:${step.on_success_step}` : ''}</code>, failure → <code>{step.on_failure || 'stop'}{step.on_failure_step ? `:${step.on_failure_step}` : ''}</code></div>
      <div style={{ marginTop: 10, background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Result conditions</div>
          <button onClick={() => onChange({ ...step, result_conditions: [...(step.result_conditions || []), emptyCondition()] })} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Add condition</button>
        </div>
        {(step.result_conditions || []).length === 0 ? (
          <div style={{ fontSize: 10, color: '#505560' }}>No result-based branching rules.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {(step.result_conditions || []).map((cond, idx) => (
              <div key={idx} style={{ display: 'grid', gridTemplateColumns: '110px 1fr 100px 120px 100px 110px 40px', gap: 6, alignItems: 'end' }}>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>When</div>
                  <select value={cond.when || 'success'} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, when: e.target.value } : item) })} style={inp()}>
                    <option value="success">success</option>
                    <option value="failure">failure</option>
                    <option value="always">always</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Result key</div>
                  <input value={cond.result_key || ''} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, result_key: e.target.value } : item) })} placeholder="findings_created" style={inp()} />
                </div>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Op</div>
                  <select value={cond.operator || 'eq'} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, operator: e.target.value } : item) })} style={inp()}>
                    {['eq','ne','gt','gte','lt','lte','contains'].map(op => <option key={op} value={op}>{op}</option>)}
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Value</div>
                  <input value={cond.value ?? ''} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, value: e.target.value } : item) })} placeholder="0" style={inp()} />
                </div>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Action</div>
                  <select value={cond.action || 'stop'} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, action: e.target.value, target_step: e.target.value === 'jump' ? (item.target_step || Math.min(stepCount, stepIndex + 2)) : null } : item) })} style={inp()}>
                    <option value="stop">stop</option>
                    <option value="next">next</option>
                    <option value="jump">jump</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Jump</div>
                  <select value={cond.target_step || ''} disabled={(cond.action || 'stop') !== 'jump'} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, target_step: e.target.value ? Number(e.target.value) : null } : item) })} style={{ ...inp(), opacity: (cond.action || 'stop') === 'jump' ? 1 : 0.5 }}>
                    <option value="">Step</option>
                    {Array.from({ length: stepCount }, (_, i) => i + 1).map(num => <option key={num} value={num}>Step {num}</option>)}
                  </select>
                </div>
                <button onClick={() => onChange({ ...step, result_conditions: step.result_conditions.filter((_, i) => i !== idx) })} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '7px 0', cursor: 'pointer', color: '#cc2233', fontSize: 10, fontFamily: 'JetBrains Mono' }}>×</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function PlaybooksView({ selectedProject, accent, onNavigate }) {
  const [playbooks, setPlaybooks] = useState([]);
  const [runs, setRuns] = useState([]);
  const [connectors, setConnectors] = useState([]);
  const [stepTemplates, setStepTemplates] = useState([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState('');
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [validation, setValidation] = useState({ errors: [], warnings: [] });
  const [editingMode, setEditingMode] = useState(false);
  const [editor, setEditor] = useState(emptyPlaybook());
  const [form, setForm] = useState({ target: '', target_url: '', flags: '-sV -sC -T4 --open', severity: 'critical,high,medium', keep_manual_positions: true, create_missing_networks: true });

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    try {
      const [pb, runData, connectorData, templateData] = await Promise.all([
        api.listPlaybooks(),
        api.listPlaybookRuns(selectedProject, { limit: 100 }),
        api.listConnectors().catch(() => ({ connectors: [] })),
        api.listPlaybookStepTemplates().catch(() => ({ templates: [] })),
      ]);
      setPlaybooks(pb.playbooks || []);
      setRuns(runData.runs || []);
      setConnectors(connectorData.connectors || []);
      setStepTemplates(templateData.templates || []);
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

  useEffect(() => {
    if (!selected || editingMode) return;
    setEditor({ title: selected.title || '', description: selected.description || '', steps: (selected.steps || []).map(step => ({ ...step, params: step.params || {} })) });
  }, [selected, editingMode]);

  const startCreate = () => {
    setEditingMode(true);
    setSelectedPlaybookId('');
    setEditor(emptyPlaybook());
    setError('');
    setValidation({ errors: [], warnings: [] });
  };

  const startEdit = () => {
    if (!selected?.editable) return;
    setEditingMode(true);
    setEditor({ title: selected.title || '', description: selected.description || '', steps: (selected.steps || []).map(step => ({ ...step, params: step.params || {} })) });
    setError('');
    setValidation({ errors: [], warnings: [] });
  };

  const cancelEdit = () => {
    setEditingMode(false);
    setValidation({ errors: [], warnings: [] });
    if (selected) setEditor({ title: selected.title || '', description: selected.description || '', steps: (selected.steps || []).map(step => ({ ...step, params: step.params || {} })) });
  };

  const savePlaybook = async () => {
    setSaving(true);
    setError('');
    try {
      const payload = {
        title: editor.title,
        description: editor.description,
        steps: (editor.steps || []).map(step => ({ title: step.title, connector_key: step.connector_key, operation: step.operation, params: step.params || {}, on_success: step.on_success || 'next', on_success_step: step.on_success_step ?? null, on_failure: step.on_failure || 'stop', on_failure_step: step.on_failure_step ?? null, result_conditions: step.result_conditions || [] })),
      };
      const validationRes = await api.validatePlaybook(payload);
      setValidation({ errors: validationRes.errors || [], warnings: validationRes.warnings || [] });
      if (!validationRes.ok) throw new Error('Playbook validation failed');
      let saved;
      const normalizedPayload = validationRes.normalized || payload;
      if (selected?.editable && selected.id) saved = await api.updateCustomPlaybook(selected.id, normalizedPayload);
      else saved = await api.createCustomPlaybook(normalizedPayload);
      await load();
      setSelectedPlaybookId(saved.id);
      setEditingMode(false);
    } catch (e) {
      setError(e.message || 'Failed to save playbook');
    } finally {
      setSaving(false);
    }
  };

  const deleteSelectedPlaybook = async () => {
    if (!selected?.editable) return;
    try {
      await api.deleteCustomPlaybook(selected.id);
      await load();
      setSelectedPlaybookId(prev => prev === selected.id ? '' : prev);
      setEditingMode(false);
    } catch (e) {
      setError(e.message || 'Failed to delete playbook');
    }
  };

  const runSelected = async () => {
    if (!selectedProject || !selected) return;
    setRunning(true);
    setError('');
    try {
      const res = await api.runPlaybook(selectedProject, selected.id, form);
      if (res.playbook_run) setRuns(prev => [res.playbook_run, ...prev.filter(r => r.id !== res.playbook_run.id)]);
      if (onNavigate) onNavigate('jobs');
    } catch (e) {
      setError(e.message || 'Failed to run playbook');
    } finally {
      setRunning(false);
    }
  };

  const cancelRun = async (runId) => {
    try {
      const updated = await api.cancelPlaybookRun(selectedProject, runId);
      setRuns(prev => prev.map(run => run.id === runId ? updated : run));
    } catch (e) {
      setError(e.message || 'Failed to cancel playbook run');
    }
  };

  const rerun = async (runId) => {
    try {
      const res = await api.rerunPlaybookRun(selectedProject, runId);
      if (res.playbook_run) setRuns(prev => [res.playbook_run, ...prev.filter(r => r.id !== res.playbook_run.id)]);
    } catch (e) {
      setError(e.message || 'Failed to rerun playbook');
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
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={load} style={toolbarBtn(accent, false)}>Refresh</button>
          <button onClick={startCreate} style={toolbarBtn(accent, true)}>New custom playbook</button>
        </div>
      </div>

      {error && <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 12 }}>{error}</div>}
      {editingMode && validation.errors.length > 0 && <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 12, lineHeight: 1.6 }}>{validation.errors.map((item, idx) => <div key={idx}>{item}</div>)}</div>}
      {editingMode && validation.warnings.length > 0 && <div style={{ background: '#1a1408', border: '1px solid #4a3410', borderRadius: 6, padding: '10px 12px', color: '#f09a3a', fontSize: 12, lineHeight: 1.6 }}>{validation.warnings.map((item, idx) => <div key={idx}>{item}</div>)}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '320px minmax(0, 1fr)', gap: 18, minHeight: 0, alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, position: 'sticky', top: 0 }}>
          {(playbooks || []).map(playbook => <PlaybookCard key={playbook.id} playbook={playbook} accent={accent} selected={selectedPlaybookId === playbook.id && !editingMode} onSelect={(id) => { setSelectedPlaybookId(id); setEditingMode(false); }} />)}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, minWidth: 0 }}>
          <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, padding: 16, minHeight: 420 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 14, color: '#e0e4ec', fontWeight: 600 }}>{editingMode ? (selected?.editable ? 'Edit custom playbook' : 'Create custom playbook') : (selected?.title || 'Select a playbook')}</div>
                {!editingMode && selected && <div style={{ fontSize: 10, color: '#606570', marginTop: 4, lineHeight: 1.55, maxWidth: 760 }}>{selected.description}</div>}
              </div>
              {!editingMode && selected?.editable && (
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={startEdit} style={toolbarBtn(accent, false)}>Edit</button>
                  <button onClick={deleteSelectedPlaybook} style={{ ...toolbarBtn('#cc2233', false), borderColor: '#cc223344', color: '#cc2233' }}>Delete</button>
                </div>
              )}
            </div>

            {editingMode ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <input value={editor.title} onChange={e => setEditor(prev => ({ ...prev, title: e.target.value }))} placeholder="Playbook title" style={inp()} />
                <textarea value={editor.description} onChange={e => setEditor(prev => ({ ...prev, description: e.target.value }))} placeholder="Description" rows={3} style={{ ...inp(), resize: 'vertical' }} />
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 8, padding: '12px 14px' }}>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Step templates</div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {stepTemplates.map(template => (
                      <button key={template.id} onClick={() => setEditor(prev => ({ ...prev, steps: [...prev.steps, buildStepFromTemplate(template)] }))} style={{ background: '#13161f', border: '1px solid #1e2230', borderRadius: 999, padding: '5px 10px', cursor: 'pointer', color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{template.title}</button>
                    ))}
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {editor.steps.map((step, idx) => (
                    <StepEditor
                      key={idx}
                      step={step}
                      connectors={connectors}
                      templates={stepTemplates}
                      stepCount={editor.steps.length}
                      stepIndex={idx}
                      onChange={(next) => setEditor(prev => ({ ...prev, steps: prev.steps.map((item, i) => i === idx ? next : item) }))}
                      onDelete={() => setEditor(prev => ({ ...prev, steps: prev.steps.filter((_, i) => i !== idx) }))}
                      disableDelete={editor.steps.length <= 1}
                    />
                  ))}
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={() => setEditor(prev => ({ ...prev, steps: [...prev.steps, stepTemplates[0] ? buildStepFromTemplate(stepTemplates[0]) : emptyStep()] }))} style={toolbarBtn(accent, false)}>Add step</button>
                  <button onClick={savePlaybook} disabled={saving} style={toolbarBtn(accent, true)}>{saving ? 'Saving...' : 'Save playbook'}</button>
                  <button onClick={cancelEdit} style={toolbarBtn('#808590', false)}>Cancel</button>
                </div>
              </div>
            ) : selected && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 8, padding: '12px 14px' }}>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Playbook steps</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {(selected.steps || []).map((step, idx) => (
                      <div key={`${selected.id}-${idx}`} style={{ display: 'grid', gridTemplateColumns: '36px minmax(0, 1fr) auto', gap: 10, alignItems: 'start', paddingBottom: idx < selected.steps.length - 1 ? 8 : 0, borderBottom: idx < selected.steps.length - 1 ? '1px solid #14161b' : 'none' }}>
                        <div style={{ width: 28, height: 28, borderRadius: 999, background: '#13161f', border: `1px solid ${accent}33`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: accent, fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 700 }}>{idx + 1}</div>
                        <div style={{ minWidth: 0 }}>
                          <div style={{ fontSize: 11, color: '#d9deea', fontWeight: 600, marginBottom: 3 }}>{step.title}</div>
                          <div style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono', marginBottom: 4 }}>{step.connector_key}:{step.operation}</div>
                          {step.params && Object.keys(step.params).length > 0 && <div style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', lineHeight: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{JSON.stringify(step.params)}</div>}
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ fontSize: 9, color: '#5b8af5', background: '#5b8af518', border: '1px solid #5b8af533', borderRadius: 999, padding: '2px 7px', fontFamily: 'JetBrains Mono' }}>ok:{step.on_success || 'next'}{step.on_success_step ? `:${step.on_success_step}` : ''}</span>
                          <span style={{ fontSize: 9, color: step.on_failure === 'jump' || step.on_failure === 'continue' ? '#f09a3a' : '#808590', background: step.on_failure === 'jump' || step.on_failure === 'continue' ? '#f09a3a18' : '#80859018', border: `1px solid ${step.on_failure === 'jump' || step.on_failure === 'continue' ? '#f09a3a33' : '#80859033'}`, borderRadius: 999, padding: '2px 7px', fontFamily: 'JetBrains Mono' }}>fail:{step.on_failure || 'stop'}{step.on_failure_step ? `:${step.on_failure_step}` : ''}</span>
                          {!!(step.result_conditions || []).length && <span style={{ fontSize: 9, color: '#39d353', background: '#39d35318', border: '1px solid #39d35333', borderRadius: 999, padding: '2px 7px', fontFamily: 'JetBrains Mono' }}>conditions:{step.result_conditions.length}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Target</div>
                    <input value={form.target} onChange={e => setForm(prev => ({ ...prev, target: e.target.value }))} placeholder="10.0.0.0/24" style={inp()} />
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Target URL</div>
                    <input value={form.target_url} onChange={e => setForm(prev => ({ ...prev, target_url: e.target.value }))} placeholder="https://target.example" style={inp()} />
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Nmap flags</div>
                    <input value={form.flags} onChange={e => setForm(prev => ({ ...prev, flags: e.target.value }))} style={inp()} />
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Nuclei severity</div>
                    <input value={form.severity} onChange={e => setForm(prev => ({ ...prev, severity: e.target.value }))} style={inp()} />
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button onClick={() => setForm(prev => ({ ...prev, keep_manual_positions: !prev.keep_manual_positions }))} style={toggleBtn(form.keep_manual_positions, accent)}>{form.keep_manual_positions ? 'Keep manual positions' : 'Ignore manual positions'}</button>
                  <button onClick={() => setForm(prev => ({ ...prev, create_missing_networks: !prev.create_missing_networks }))} style={toggleBtn(form.create_missing_networks, accent)}>{form.create_missing_networks ? 'Create missing networks' : 'No auto-create'}</button>
                </div>
                <button onClick={runSelected} disabled={running} style={{ background: running ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '8px 16px', cursor: running ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{running ? 'Starting...' : 'Run playbook'}</button>
              </div>
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
                    {!!(run.jobs_json || []).length && (
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 8 }}>
                        {(run.jobs_json || []).map(job => <button key={job.id} onClick={() => onNavigate?.('jobs')} style={{ background: '#13161f', border: '1px solid #1e2230', borderRadius: 4, padding: '2px 7px', cursor: 'pointer', color: '#a0a8b8', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{job.title} · {job.status}</button>)}
                      </div>
                    )}
                    {(run.result_json?.completed_jobs?.length > 0 || run.error_output) && (
                      <div style={{ fontSize: 10, color: run.error_output ? '#f87171' : '#808590', lineHeight: 1.6, fontFamily: 'JetBrains Mono', marginBottom: 8 }}>
                        {run.result_json?.completed_jobs?.length > 0 && <div>completed jobs: {run.result_json.completed_jobs.join(', ')}</div>}
                        {run.error_output && <div>{run.error_output}</div>}
                      </div>
                    )}
                    <div style={{ display: 'flex', gap: 8 }}>
                      {(run.status === 'queued' || run.status === 'running') && <button onClick={() => cancelRun(run.id)} style={toolbarBtn('#f09a3a', false)}>Cancel run</button>}
                      {run.status !== 'queued' && run.status !== 'running' && <button onClick={() => rerun(run.id)} style={toolbarBtn(accent, false)}>Rerun</button>}
                      {!!(run.jobs_json || []).length && <button onClick={() => onNavigate?.('jobs')} style={toolbarBtn('#5b8af5', false)}>Open Jobs</button>}
                    </div>
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

function toolbarBtn(color, solid) {
  return {
    background: solid ? color : 'transparent',
    color: solid ? '#fff' : color,
    border: solid ? 'none' : `1px solid ${color}44`,
    borderRadius: 5,
    padding: '7px 12px',
    cursor: 'pointer',
    fontSize: 11,
    fontFamily: 'JetBrains Mono',
    fontWeight: 600,
  };
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
