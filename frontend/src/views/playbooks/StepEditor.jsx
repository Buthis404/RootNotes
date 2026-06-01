/**
 * Step editor + advanced DAG/retry/precondition fields for playbook steps.
 *
 * Extracted from PlaybooksView.jsx.
 */
import { useState } from 'react';
import PropTypes from 'prop-types';
import { inp, toggleBtn } from './utils.js';

// ── Constants & helpers ──────────────────────────────────────────────

const STRUCTURED_KEYS = [
  'structured.ok',
  'structured.auth_success',
  'structured.access_role',
  'structured.summary',
  'structured.counts.hosts_found',
  'structured.counts.hosts_created',
  'structured.counts.hosts_valid',
  'structured.counts.hosts_failed',
  'structured.counts.hosts_pwned',
  'structured.counts.exit_code',
  'structured.counts.findings_created',
  'structured.counts.paths_found',
];

export const RESULT_KEYS_BY_CONNECTOR = {
  'nmap:scan':                  [...STRUCTURED_KEYS, 'hosts_found', 'hosts_created', 'hosts_updated'],
  'nuclei:scan':                [...STRUCTURED_KEYS, 'findings_found', 'findings_created'],
  'netexec:scan':               [...STRUCTURED_KEYS, 'hosts_found', 'hosts_created', 'hosts_updated'],
  'netexec:ldap_enum':          [...STRUCTURED_KEYS, 'hosts_found', 'hosts_created', 'hosts_updated'],
  'netexec:spray_smb':          [...STRUCTURED_KEYS, 'hosts_found', 'hosts_created', 'hosts_updated'],
  'netexec:spray_winrm':        [...STRUCTURED_KEYS, 'hosts_success', 'hosts_pwned', 'hosts_failed'],
  'netexec:spray_mssql':        [...STRUCTURED_KEYS, 'hosts_success', 'hosts_pwned', 'hosts_failed'],
  'netexec:spray_ldap':         [...STRUCTURED_KEYS, 'hosts_success', 'hosts_failed'],
  'netexec:spray_rdp':          [...STRUCTURED_KEYS, 'hosts_success', 'hosts_failed'],
  'attacker_ssh:cred_validate': [...STRUCTURED_KEYS, 'hosts_total', 'hosts_valid', 'hosts_failed'],
  'c2_integration:sync':        [...STRUCTURED_KEYS, 'hosts_found', 'hosts_created', 'hosts_updated', 'creds_created'],
  'topology:auto_build':        [...STRUCTURED_KEYS, 'hosts_created'],
  'topology:preview':           [...STRUCTURED_KEYS, 'hosts_created'],
  'attacker_ssh:exec':          [...STRUCTURED_KEYS, 'exit_code'],
  'attacker_ssh:bulk_exec':     [...STRUCTURED_KEYS, 'exit_code'],
  'attacker_ssh:kerberoast':    [...STRUCTURED_KEYS, 'exit_code'],
  'attacker_ssh:asreproast':    [...STRUCTURED_KEYS, 'exit_code'],
  'attacker_ssh:ldap_dump':     [...STRUCTURED_KEYS, 'exit_code'],
  'httpx:scan':                 [...STRUCTURED_KEYS, 'urls_found', 'hosts_found', 'activities_created'],
  'ffuf:scan':                  [...STRUCTURED_KEYS, 'paths_found', 'findings_created'],
};

export function resultKeysForSteps(steps) {
  const keys = new Set();
  for (const s of steps) {
    const ck = `${s.connector_key}:${s.operation}`;
    (RESULT_KEYS_BY_CONNECTOR[ck] || []).forEach(k => keys.add(k));
  }
  return [...keys];
}

export function emptyCondition() {
  return { when: 'success', result_key: '', operator: 'eq', value: '', action: 'stop', target_step: null };
}

// ── AdvancedStepFields (DAG · Retry · Precondition) ─────────────────

function AdvancedStepFields({ step, stepIndex, stepCount, onChange }) {
  const dagEnabled = (step.depends_on?.length > 0) || (Number(step.retry_count) || 0) > 0 || !!step.precondition;
  const [open, setOpen] = useState(dagEnabled);
  const stepNumbers = Array.from({ length: stepCount }, (_, i) => i + 1).filter(n => n !== stepIndex + 1);
  const depsSet = new Set((step.depends_on || []).map(Number));
  const toggleDep = (n) => {
    const next = new Set(depsSet);
    if (next.has(n)) { next.delete(n); } else { next.add(n); }
    onChange({ ...step, depends_on: [...next].sort((a, b) => a - b) });
  };
  const retryOnSet = new Set(step.retry_on || ['failed']);
  const toggleRetryOn = (k) => {
    const next = new Set(retryOnSet);
    if (next.has(k)) { next.delete(k); } else { next.add(k); }
    if (next.size === 0) next.add('failed');
    onChange({ ...step, retry_on: [...next] });
  };
  const pre = step.precondition || null;
  const setPre = (patch) => onChange({ ...step, precondition: { ...(pre || { step: stepIndex >= 1 ? stepIndex : null, result_key: '', operator: 'gt', value: '', negate: false }), ...patch } });
  return (
    <div style={{ marginTop: 10, background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 10 }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{ background: 'none', border: 'none', width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer', padding: 0, color: '#9098a8' }}
      >
        <span style={{ fontSize: 9, color: dagEnabled ? '#5b8af5' : '#404550', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'JetBrains Mono' }}>
          Advanced — DAG · Retry · Precondition {dagEnabled ? '(active)' : ''}
        </span>
        <span style={{ fontSize: 12, color: '#404550' }}>{open ? '−' : '+'}</span>
      </button>
      {open && (
        <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.08em' }}>depends_on (DAG predecessors)</div>
            {stepNumbers.length === 0 ? (
              <div style={{ fontSize: 10, color: '#505560' }}>No other steps to depend on.</div>
            ) : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {stepNumbers.map(n => (
                  <button key={n} onClick={() => toggleDep(n)}
                    style={{ background: depsSet.has(n) ? '#1a2e4a' : 'transparent', border: `1px solid ${depsSet.has(n) ? '#5b8af5' : '#2a2d35'}`, borderRadius: 4, padding: '3px 9px', cursor: 'pointer', color: depsSet.has(n) ? '#9bb7ff' : '#808590', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  >Step {n}</button>
                ))}
              </div>
            )}
            <div style={{ fontSize: 9, color: '#505560', marginTop: 4 }}>Any non-empty selection switches this playbook to DAG mode. Steps with the same predecessors run in parallel.</div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '90px 110px 1fr', gap: 8, alignItems: 'end' }}>
            <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Retry count</div>
              <input type="number" min={0} max={10} value={step.retry_count ?? 0} onChange={e => onChange({ ...step, retry_count: Math.max(0, Math.min(10, Number(e.target.value) || 0)) })} style={inp()} />
            </div>
            <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Delay (s)</div>
              <input type="number" min={0} max={3600} value={step.retry_delay_seconds ?? 5} onChange={e => onChange({ ...step, retry_delay_seconds: Math.max(0, Math.min(3600, Number(e.target.value) || 0)) })} style={inp()} />
            </div>
            <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Retry on</div>
              <div style={{ display: 'flex', gap: 6 }}>
                {['failed', 'cancelled', 'timeout'].map(k => (
                  <button key={k} onClick={() => toggleRetryOn(k)}
                    style={{ flex: 1, background: retryOnSet.has(k) ? '#1a2e1a' : 'transparent', border: `1px solid ${retryOnSet.has(k) ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '4px 0', cursor: 'pointer', color: retryOnSet.has(k) ? '#9bd9a8' : '#808590', fontSize: 10, fontFamily: 'JetBrains Mono' }}
                  >{k}</button>
                ))}
              </div>
            </div>
          </div>
          <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Precondition (skip step if false)</div>
              <button onClick={() => pre ? onChange({ ...step, precondition: null }) : setPre({})} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: pre ? '#cc2233' : '#808590', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{pre ? 'Remove' : 'Add precondition'}</button>
            </div>
            {pre ? (
              <div style={{ display: 'grid', gridTemplateColumns: '100px 1fr 80px 110px 80px', gap: 6 }}>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 3, textTransform: 'uppercase' }}>Of step</div>
                  <select value={pre.step ?? ''} onChange={e => setPre({ step: e.target.value ? Number(e.target.value) : null })} style={inp()}>
                    <option value="">(latest dep)</option>
                    {stepNumbers.map(n => <option key={n} value={n}>Step {n}</option>)}
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 3, textTransform: 'uppercase' }}>Result key</div>
                  <input value={pre.result_key || ''} onChange={e => setPre({ result_key: e.target.value })} placeholder="hosts_found" style={inp()} />
                </div>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 3, textTransform: 'uppercase' }}>Op</div>
                  <select value={pre.operator || 'eq'} onChange={e => setPre({ operator: e.target.value })} style={inp()}>
                    {['eq','ne','gt','gte','lt','lte','contains'].map(op => <option key={op} value={op}>{op}</option>)}
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 3, textTransform: 'uppercase' }}>Value</div>
                  <input value={pre.value ?? ''} onChange={e => setPre({ value: e.target.value })} placeholder="0 / true" style={inp()} />
                </div>
                <div>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 3, textTransform: 'uppercase' }}>Negate</div>
                  <button onClick={() => setPre({ negate: !pre.negate })} style={{ width: '100%', ...toggleBtn(!!pre.negate, '#cc7733') }}>{pre.negate ? 'NOT' : 'as-is'}</button>
                </div>
              </div>
            ) : (
              <div style={{ fontSize: 10, color: '#505560' }}>No precondition — step runs whenever its deps are satisfied.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

AdvancedStepFields.propTypes = {
  step: PropTypes.object,
  stepIndex: PropTypes.number,
  stepCount: PropTypes.number,
  onChange: PropTypes.func,
};

// ── StepEditor (full step editing panel) ─────────────────────────────

export function StepEditor({ step, connectors, templates, stepCount, stepIndex, onChange, onDelete, onDuplicate, onMoveUp, onMoveDown, disableDelete, allSteps }) {
  const suggestedResultKeys = resultKeysForSteps(allSteps || []);
  const connector = connectors.find(c => c.key === step.connector_key) || null;
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
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', background: '#0d0f15', borderBottom: '1px solid #1e2029' }}>
        <span style={{ width: 22, height: 22, borderRadius: '50%', background: '#1a1c28', border: '1px solid #2a2d45', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, color: '#9098c8', fontFamily: 'JetBrains Mono', fontWeight: 700, flexShrink: 0 }}>{stepIndex + 1}</span>
        <input value={step.title} onChange={e => onChange({ ...step, title: e.target.value })} placeholder="Step title…" style={{ ...inp(), flex: 1, background: 'transparent', border: 'none', padding: '2px 0', fontSize: 12, color: '#d0d4e0', fontWeight: 600, outline: 'none' }} />
        <div style={{ display: 'flex', gap: 3, flexShrink: 0 }}>
          <button onClick={onMoveUp} disabled={stepIndex === 0} title="Move up" style={{ background: 'none', border: 'none', cursor: stepIndex === 0 ? 'default' : 'pointer', color: '#505560', fontSize: 14, padding: '0 4px', opacity: stepIndex === 0 ? 0.25 : 1, lineHeight: 1 }}>↑</button>
          <button onClick={onMoveDown} disabled={stepIndex >= stepCount - 1} title="Move down" style={{ background: 'none', border: 'none', cursor: stepIndex >= stepCount - 1 ? 'default' : 'pointer', color: '#505560', fontSize: 14, padding: '0 4px', opacity: stepIndex >= stepCount - 1 ? 0.25 : 1, lineHeight: 1 }}>↓</button>
          <button onClick={onDuplicate} title="Duplicate" style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, cursor: 'pointer', color: '#606570', fontSize: 10, padding: '2px 7px', fontFamily: 'JetBrains Mono' }}>⧉</button>
          <button onClick={onDelete} disabled={disableDelete} title="Delete step" style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, cursor: disableDelete ? 'default' : 'pointer', color: disableDelete ? '#303540' : '#cc2233', fontSize: 10, padding: '2px 7px', fontFamily: 'JetBrains Mono', opacity: disableDelete ? 0.4 : 1 }}>✕</button>
        </div>
      </div>
      <div style={{ padding: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Connector</div>
          <select value={step.connector_key} onChange={e => applyTemplate(e.target.value, '')} style={inp()}>
            {[...new Map(connectors.map(c => [c.key, c])).values()].map(c => <option key={c.key} value={c.key}>{c.title}</option>)}
          </select>
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Operation</div>
          <select value={step.operation} onChange={e => applyTemplate(step.connector_key, e.target.value)} style={inp()}>
            <option value="">Select operation</option>
            {operations.map(op => <option key={op} value={op}>{op}</option>)}
          </select>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
        <div style={{ background: '#0d1a0d', border: '1px solid #1a2e1a', borderRadius: 6, padding: '8px 10px' }}>
          <div style={{ fontSize: 9, color: '#39d353', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'JetBrains Mono' }}>✓ On success</div>
          <div style={{ display: 'flex', gap: 6 }}>
            <select value={step.on_success || 'next'} onChange={e => onChange({ ...step, on_success: e.target.value, on_success_step: e.target.value === 'jump' ? (step.on_success_step || Math.min(stepCount, stepIndex + 2)) : null })} style={{ ...inp(), flex: 1 }}>
              <option value="next">next</option>
              <option value="stop">stop</option>
              <option value="jump">jump →</option>
            </select>
            {(step.on_success || 'next') === 'jump' && (
              <select value={step.on_success_step || ''} onChange={e => onChange({ ...step, on_success_step: e.target.value ? Number(e.target.value) : null })} style={{ ...inp(), width: 90 }}>
                <option value="">Step…</option>
                {Array.from({ length: stepCount }, (_, i) => i + 1).map(n => <option key={n} value={n}>Step {n}</option>)}
              </select>
            )}
          </div>
        </div>
        <div style={{ background: '#1a0d0d', border: '1px solid #2e1a1a', borderRadius: 6, padding: '8px 10px' }}>
          <div style={{ fontSize: 9, color: '#cc2233', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'JetBrains Mono' }}>✕ On failure</div>
          <div style={{ display: 'flex', gap: 6 }}>
            <select value={step.on_failure || 'stop'} onChange={e => onChange({ ...step, on_failure: e.target.value, on_failure_step: e.target.value === 'jump' ? (step.on_failure_step || Math.min(stepCount, stepIndex + 2)) : null })} style={{ ...inp(), flex: 1 }}>
              <option value="stop">stop</option>
              <option value="continue">continue</option>
              <option value="jump">jump →</option>
            </select>
            {(step.on_failure || 'stop') === 'jump' && (
              <select value={step.on_failure_step || ''} onChange={e => onChange({ ...step, on_failure_step: e.target.value ? Number(e.target.value) : null })} style={{ ...inp(), width: 90 }}>
                <option value="">Step…</option>
                {Array.from({ length: stepCount }, (_, i) => i + 1).map(n => <option key={n} value={n}>Step {n}</option>)}
              </select>
            )}
          </div>
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
                {(() => {
                  if (field.type === 'boolean') return <button onClick={() => onChange({ ...step, params: { ...step.params, [field.key]: !value } })} style={{ width: '100%', ...toggleBtn(!!value, '#5b8af5') }}>{value ? 'Enabled' : 'Disabled'}</button>;
                  if (field.type === 'select') return <select value={value} onChange={e => onChange({ ...step, params: { ...step.params, [field.key]: e.target.value } })} style={inp()}>{(field.options || []).map(option => <option key={option} value={option}>{option}</option>)}</select>;
                  if (field.type === 'textarea') return <textarea value={value} onChange={e => onChange({ ...step, params: { ...step.params, [field.key]: e.target.value } })} rows={4} style={{ ...inp(), resize: 'vertical' }} />;
                  if (field.type === 'number') return <input type="number" value={value} onChange={e => onChange({ ...step, params: { ...step.params, [field.key]: Number(e.target.value) || 0 } })} style={inp()} />;
                  return <input value={value} onChange={e => onChange({ ...step, params: { ...step.params, [field.key]: e.target.value } })} style={inp()} />;
                })()}
              </div>
            );
          })}
        </div>
      ) : (
        <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 11 }}>No step template exists for this connector/operation yet.</div>
      )}
      {template?.description && <div style={{ fontSize: 10, color: '#505560', marginTop: 8, lineHeight: 1.5 }}>{template.description}</div>}
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
              <div key={`cond-${cond.field || ''}-${cond.operator || ''}-${idx}`} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '100px 1fr 80px 110px', gap: 6, marginBottom: 6 }}>
                  <div>
                    <div style={{ fontSize: 8, color: '#404550', marginBottom: 3, textTransform: 'uppercase' }}>When</div>
                    <select value={cond.when || 'success'} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, when: e.target.value } : item) })} style={inp()}>
                      <option value="success">success</option>
                      <option value="failure">failure</option>
                      <option value="always">always</option>
                    </select>
                  </div>
                  <div>
                    <div style={{ fontSize: 8, color: '#404550', marginBottom: 3, textTransform: 'uppercase' }}>Result key</div>
                    <input value={cond.result_key || ''} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, result_key: e.target.value } : item) })} placeholder="structured.auth_success" list={`rk-list-${stepIndex}-${idx}`} style={inp()} autoComplete="off" />
                    <datalist id={`rk-list-${stepIndex}-${idx}`}>{suggestedResultKeys.map(k => <option key={k} value={k} />)}</datalist>
                  </div>
                  <div>
                    <div style={{ fontSize: 8, color: '#404550', marginBottom: 3, textTransform: 'uppercase' }}>Op</div>
                    <select value={cond.operator || 'eq'} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, operator: e.target.value } : item) })} style={inp()}>
                      {['eq','ne','gt','gte','lt','lte','contains'].map(op => <option key={op} value={op}>{op}</option>)}
                    </select>
                  </div>
                  <div>
                    <div style={{ fontSize: 8, color: '#404550', marginBottom: 3, textTransform: 'uppercase' }}>Value</div>
                    <input value={cond.value ?? ''} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, value: e.target.value } : item) })} placeholder="true / 0" style={inp()} />
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>→ action:</span>
                  <select value={cond.action || 'stop'} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, action: e.target.value, target_step: e.target.value === 'jump' ? (item.target_step || Math.min(stepCount, stepIndex + 2)) : null } : item) })} style={{ ...inp(), width: 110 }}>
                    <option value="stop">stop</option>
                    <option value="next">next</option>
                    <option value="jump">jump →</option>
                  </select>
                  {(cond.action || 'stop') === 'jump' && (
                    <select value={cond.target_step || ''} onChange={e => onChange({ ...step, result_conditions: step.result_conditions.map((item, i) => i === idx ? { ...item, target_step: e.target.value ? Number(e.target.value) : null } : item) })} style={{ ...inp(), width: 90 }}>
                      <option value="">Step…</option>
                      {Array.from({ length: stepCount }, (_, i) => i + 1).map(n => <option key={n} value={n}>Step {n}</option>)}
                    </select>
                  )}
                  <button onClick={() => onChange({ ...step, result_conditions: step.result_conditions.filter((_, i) => i !== idx) })} style={{ marginLeft: 'auto', background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: '#cc2233', fontSize: 10 }}>✕</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      <AdvancedStepFields step={step} stepIndex={stepIndex} stepCount={stepCount} onChange={onChange} />
      </div>
    </div>
  );
}

StepEditor.propTypes = {
  step: PropTypes.object,
  connectors: PropTypes.array,
  templates: PropTypes.array,
  stepCount: PropTypes.number,
  stepIndex: PropTypes.number,
  onChange: PropTypes.func,
  onDelete: PropTypes.func,
  onDuplicate: PropTypes.func,
  onMoveUp: PropTypes.func,
  onMoveDown: PropTypes.func,
  disableDelete: PropTypes.bool,
  allSteps: PropTypes.array,
};
