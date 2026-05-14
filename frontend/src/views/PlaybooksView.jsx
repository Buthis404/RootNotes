import React, { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api.js';
import ScheduledTab from './playbooks/ScheduledTab.jsx';
import { inp, toolbarBtn, toggleBtn } from './playbooks/utils.js';

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

// Structured result keys available for ALL connector types
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

const RESULT_KEYS_BY_CONNECTOR = {
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

function resultKeysForSteps(steps) {
  const keys = new Set();
  for (const s of steps) {
    const ck = `${s.connector_key}:${s.operation}`;
    (RESULT_KEYS_BY_CONNECTOR[ck] || []).forEach(k => keys.add(k));
  }
  return [...keys];
}

// ── Step flow diagram ────────────────────────────────────────────────────
function StepFlowDiagram({ steps, accent }) {
  if (!steps || steps.length === 0) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {steps.map((step, idx) => {
        const hasJump = step.on_success === 'jump' || step.on_failure === 'jump';
        const failStop = step.on_failure === 'stop';
        const failContinue = step.on_failure === 'continue' || step.on_failure === 'next';
        const isLast = idx === steps.length - 1;
        return (
          <div key={idx} style={{ display: 'flex', gap: 0 }}>
            {/* Spine + node */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 36, flexShrink: 0 }}>
              <div style={{ width: 28, height: 28, borderRadius: '50%', background: '#13161f', border: `1.5px solid ${accent}44`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: accent, fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 700, zIndex: 1 }}>{idx + 1}</div>
              {!isLast && <div style={{ width: 2, flex: 1, minHeight: 16, background: `${accent}22` }} />}
            </div>
            {/* Content */}
            <div style={{ flex: 1, paddingBottom: isLast ? 0 : 8, paddingLeft: 10, minWidth: 0 }}>
              <div style={{ fontSize: 11, color: '#d9deea', fontWeight: 600, marginBottom: 2, paddingTop: 4 }}>{step.title || `${step.connector_key}:${step.operation}`}</div>
              <div style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginBottom: 4 }}>{step.connector_key}:{step.operation}</div>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 9, color: '#39d353', background: '#39d35312', border: '1px solid #39d35330', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>
                  ✓ {step.on_success || 'next'}{step.on_success === 'jump' ? ` → step ${step.on_success_step}` : ''}
                </span>
                <span style={{ fontSize: 9, color: failStop ? '#606570' : failContinue ? '#f09a3a' : '#cc2233', background: failStop ? '#60657012' : failContinue ? '#f09a3a12' : '#cc223312', border: `1px solid ${failStop ? '#60657030' : failContinue ? '#f09a3a30' : '#cc223330'}`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>
                  ✕ {step.on_failure || 'stop'}{step.on_failure === 'jump' ? ` → step ${step.on_failure_step}` : ''}
                </span>
                {(step.result_conditions || []).length > 0 && (
                  <span style={{ fontSize: 9, color: '#6fc8f0', background: '#6fc8f012', border: '1px solid #6fc8f030', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>
                    {step.result_conditions.length} condition{step.result_conditions.length > 1 ? 's' : ''}
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Rollup summary ──────────────────────────────────────────────────────
const ROLLUP_META = {
  hosts_found:    { label: 'Hosts found',    color: '#5b8af5' },
  hosts_created:  { label: 'Hosts added',    color: '#5b8af5' },
  hosts_pwned:    { label: 'Compromised',    color: '#cc2233' },
  hosts_valid:    { label: 'Auth valid',     color: '#39d353' },
  findings_created: { label: 'Findings',     color: '#e8574a' },
  creds_created:  { label: 'Creds created',  color: '#c07af0' },
  paths_found:    { label: 'Paths found',    color: '#f09a3a' },
  urls_found:     { label: 'URLs found',     color: '#6fc8f0' },
};

function RunRollup({ run, accent }) {
  const rollup = run.result_json?.rollup || {};
  const completedCount = (run.result_json?.completed_jobs || run.jobs_json || []).length;
  const failedCount = (run.result_json?.failed_jobs || []).length;
  const hasRollup = Object.keys(rollup).length > 0;

  const duration = run.started_at && run.finished_at
    ? (() => { const s = new Date(run.started_at), f = new Date(run.finished_at); const sec = Math.round((f - s) / 1000); return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`; })()
    : null;

  return (
    <div style={{ background: '#090b0f', border: '1px solid #1e2029', borderRadius: 8, padding: '10px 14px' }}>
      <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8, fontFamily: 'JetBrains Mono' }}>Run summary</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: hasRollup ? 10 : 0 }}>
        <div style={{ textAlign: 'center', background: '#39d35312', border: '1px solid #39d35330', borderRadius: 6, padding: '6px 12px', minWidth: 64 }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#39d353', fontFamily: 'JetBrains Mono' }}>{completedCount}</div>
          <div style={{ fontSize: 8, color: '#39d353', textTransform: 'uppercase', letterSpacing: '0.08em' }}>done</div>
        </div>
        {failedCount > 0 && (
          <div style={{ textAlign: 'center', background: '#cc223312', border: '1px solid #cc223330', borderRadius: 6, padding: '6px 12px', minWidth: 64 }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>{failedCount}</div>
            <div style={{ fontSize: 8, color: '#cc2233', textTransform: 'uppercase', letterSpacing: '0.08em' }}>failed</div>
          </div>
        )}
        {duration && (
          <div style={{ textAlign: 'center', background: '#ffffff06', border: '1px solid #2a2d35', borderRadius: 6, padding: '6px 12px', minWidth: 64 }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: '#808590', fontFamily: 'JetBrains Mono' }}>{duration}</div>
            <div style={{ fontSize: 8, color: '#606570', textTransform: 'uppercase', letterSpacing: '0.08em' }}>duration</div>
          </div>
        )}
        {Object.entries(rollup).map(([k, v]) => {
          const meta = ROLLUP_META[k];
          if (!meta || !v) return null;
          return (
            <div key={k} style={{ textAlign: 'center', background: meta.color + '12', border: `1px solid ${meta.color}30`, borderRadius: 6, padding: '6px 12px', minWidth: 64 }}>
              <div style={{ fontSize: 18, fontWeight: 700, color: meta.color, fontFamily: 'JetBrains Mono' }}>{v}</div>
              <div style={{ fontSize: 8, color: meta.color, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{meta.label}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
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

function StepEditor({ step, connectors, templates, stepCount, stepIndex, onChange, onDelete, onDuplicate, onMoveUp, onMoveDown, disableDelete, allSteps }) {
  const suggestedResultKeys = resultKeysForSteps(allSteps || []);
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
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
      {/* Step header */}
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
              <div key={idx} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px' }}>
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
      </div>
    </div>
  );
}

function BatchHostSelector({ hosts, batchForm, onChange, accent }) {
  const allTags = [...new Set(hosts.flatMap(h => h.tags || []))].sort();
  const allStatuses = [...new Set(hosts.map(h => h.status).filter(Boolean))].sort();

  const filtered = hosts.filter(h => {
    if (batchForm.host_ids.length > 0) return batchForm.host_ids.includes(h.id);
    if (batchForm.host_tags.length > 0 && !batchForm.host_tags.some(t => (h.tags || []).includes(t))) return false;
    if (batchForm.host_status && h.status !== batchForm.host_status) return false;
    return true;
  });

  const toggleHost = (id) => onChange(prev => ({
    ...prev,
    host_ids: prev.host_ids.includes(id) ? prev.host_ids.filter(x => x !== id) : [...prev.host_ids, id],
  }));

  const toggleTag = (tag) => onChange(prev => ({
    ...prev,
    host_ids: [],
    host_tags: prev.host_tags.includes(tag) ? prev.host_tags.filter(t => t !== tag) : [...prev.host_tags, tag],
  }));

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
        Batch target hosts
        <span style={{ marginLeft: 8, color: accent, fontWeight: 600 }}>{filtered.length} selected</span>
      </div>

      {/* Tag filter */}
      {allTags.length > 0 && (
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 10, color: '#404550', marginRight: 2 }}>Tags:</span>
          {allTags.map(tag => (
            <button key={tag} onClick={() => toggleTag(tag)}
              style={{ background: batchForm.host_tags.includes(tag) ? accent + '33' : '#13161f', color: batchForm.host_tags.includes(tag) ? accent : '#6a7080', border: `1px solid ${batchForm.host_tags.includes(tag) ? accent + '66' : '#1e2230'}`, borderRadius: 4, padding: '1px 8px', fontSize: 10, cursor: 'pointer', fontFamily: 'JetBrains Mono' }}
            >{tag}</button>
          ))}
        </div>
      )}

      {/* Status filter */}
      {allStatuses.length > 0 && (
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 10, color: '#404550', marginRight: 2 }}>Status:</span>
          {allStatuses.map(s => (
            <button key={s} onClick={() => onChange(prev => ({ ...prev, host_ids: [], host_status: prev.host_status === s ? '' : s }))}
              style={{ background: batchForm.host_status === s ? '#f09a3a33' : '#13161f', color: batchForm.host_status === s ? '#f09a3a' : '#6a7080', border: `1px solid ${batchForm.host_status === s ? '#f09a3a66' : '#1e2230'}`, borderRadius: 4, padding: '1px 8px', fontSize: 10, cursor: 'pointer' }}
            >{s}</button>
          ))}
        </div>
      )}

      {/* Parallelism */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 10, color: '#505560' }}>Parallelism:</span>
        {[1, 2, 3, 5, 10].map(n => (
          <button key={n} onClick={() => onChange(prev => ({ ...prev, parallelism: n }))}
            style={{ background: batchForm.parallelism === n ? '#6fc8f033' : '#13161f', color: batchForm.parallelism === n ? '#6fc8f0' : '#505560', border: `1px solid ${batchForm.parallelism === n ? '#6fc8f066' : '#1e2230'}`, borderRadius: 4, padding: '1px 8px', fontSize: 10, cursor: 'pointer', fontFamily: 'JetBrains Mono' }}
          >{n}</button>
        ))}
        <span style={{ fontSize: 10, color: '#303540' }}>concurrent</span>
      </div>

      {/* Host list (compact) */}
      {hosts.length > 0 && (
        <div style={{ maxHeight: 160, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 2 }}>
          {hosts.filter(h => {
            if (batchForm.host_tags.length > 0 && !batchForm.host_tags.some(t => (h.tags || []).includes(t))) return false;
            if (batchForm.host_status && h.status !== batchForm.host_status) return false;
            return true;
          }).map(h => {
            const checked = batchForm.host_ids.length === 0 || batchForm.host_ids.includes(h.id);
            return (
              <div key={h.id} onClick={() => toggleHost(h.id)} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 4px', borderRadius: 3, cursor: 'pointer', background: checked && batchForm.host_ids.length > 0 ? accent + '11' : 'transparent' }}>
                <div style={{ width: 12, height: 12, border: `1px solid ${checked ? accent : '#303540'}`, borderRadius: 2, background: checked ? accent + '33' : 'transparent', flexShrink: 0 }} />
                <span style={{ fontSize: 10, color: '#a0a8b8', fontFamily: 'JetBrains Mono' }}>{h.ip}</span>
                {h.hostname && <span style={{ fontSize: 10, color: '#505560' }}>{h.hostname}</span>}
                {(h.tags || []).map(t => <span key={t} style={{ fontSize: 9, color: '#505560', background: '#13161f', border: '1px solid #1e2230', borderRadius: 3, padding: '0 4px' }}>{t}</span>)}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── PickerInput ─────────────────────────────────────────────────────────
// Text input + inline dropdown of selectable options from project data.
function PickerInput({ value, onChange, placeholder, label, options, type = 'text' }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  React.useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <div style={{ display: 'flex', gap: 0 }}>
        <input
          type={type}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          style={{ ...inp(), borderRadius: options?.length ? '5px 0 0 5px' : 5, flex: 1 }}
        />
        {options?.length > 0 && (
          <button
            onClick={() => setOpen(v => !v)}
            title="Pick from project data"
            style={{ background: open ? '#1e2230' : '#13161f', border: '1px solid #2a2d35', borderLeft: 'none', borderRadius: '0 5px 5px 0', padding: '0 8px', cursor: 'pointer', color: '#606570', fontSize: 10, flexShrink: 0 }}
          >▾</button>
        )}
      </div>
      {open && options?.length > 0 && (
        <div style={{ position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 100, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, marginTop: 2, maxHeight: 220, overflowY: 'auto', boxShadow: '0 8px 24px #00000099' }}>
          {options.map((opt, i) => (
            <div
              key={i}
              onClick={() => { onChange(opt.value); setOpen(false); }}
              style={{ padding: '7px 12px', cursor: 'pointer', borderBottom: i < options.length - 1 ? '1px solid #1a1c22' : 'none' }}
              onMouseEnter={e => e.currentTarget.style.background = '#ffffff08'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <div style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>{opt.value}</div>
              {opt.label && <div style={{ fontSize: 9, color: '#505560', marginTop: 1 }}>{opt.label}</div>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── CredPicker ───────────────────────────────────────────────────────────
// Button that opens a dropdown to pick a credential and fill multiple fields.
function CredPicker({ creds, onPick, accent }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  React.useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  if (!creds?.length) return null;
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button onClick={() => setOpen(v => !v)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '5px 10px', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>
        From creds ▾
      </button>
      {open && (
        <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 100, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, marginTop: 2, minWidth: 280, maxHeight: 280, overflowY: 'auto', boxShadow: '0 8px 24px #00000099' }}>
          {creds.map((c, i) => (
            <div
              key={c.id}
              onClick={() => { onPick(c); setOpen(false); }}
              style={{ padding: '8px 12px', cursor: 'pointer', borderBottom: i < creds.length - 1 ? '1px solid #1a1c22' : 'none' }}
              onMouseEnter={e => e.currentTarget.style.background = '#ffffff08'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <div style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                {c.domain ? `${c.domain}\\` : ''}{c.username}
              </div>
              <div style={{ fontSize: 9, color: '#505560', marginTop: 1, display: 'flex', gap: 8 }}>
                <span style={{ color: c.type === 'hash' || c.type === 'ntlm' ? '#c07af0' : '#5b8af5' }}>{c.type}</span>
                {c.service && <span>{c.service}</span>}
                {c.tags?.length > 0 && <span>{c.tags.join(', ')}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


const TAG_COLORS = { recon: '#5b8af5', web: '#6fc8f0', ad: '#c07af0', enum: '#5b8af5', creds: '#e8574a', lateral: '#e8cc42', smb: '#f09a3a', impacket: '#c07af0', nmap: '#39d353', 'post-exploitation': '#e8574a' };
function tagColor(t) { return TAG_COLORS[t] || '#606570'; }

function PacksPanel({ packs, accent, onInsert, onDelete, onClose }) {
  const [filter, setFilter] = useState('');
  const filtered = packs.filter(p => !filter || p.name.toLowerCase().includes(filter.toLowerCase()) || (p.tags || []).some(t => t.includes(filter.toLowerCase())));
  const builtin = filtered.filter(p => p.is_builtin);
  const custom = filtered.filter(p => !p.is_builtin);

  const PackCard = ({ pack }) => (
    <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: '12px 14px', marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 600, marginBottom: 4 }}>{pack.name}</div>
          {pack.description && <div style={{ fontSize: 10, color: '#606570', lineHeight: 1.5, marginBottom: 6 }}>{pack.description}</div>}
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 6 }}>
            {(pack.tags || []).map(t => <span key={t} style={{ fontSize: 8, color: tagColor(t), background: tagColor(t) + '18', border: `1px solid ${tagColor(t)}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{t}</span>)}
            <span style={{ fontSize: 8, color: '#404550', background: '#ffffff08', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{pack.steps.length} step{pack.steps.length !== 1 ? 's' : ''}</span>
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {pack.steps.map((s, i) => <span key={i} style={{ fontSize: 8, color: '#505560', fontFamily: 'JetBrains Mono' }}>{i + 1}. {s.title || s.operation}</span>)}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flexShrink: 0 }}>
          <button onClick={() => onInsert(pack)} style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>Insert</button>
          {!pack.is_builtin && <button onClick={() => onDelete(pack.id)} style={{ background: 'transparent', border: '1px solid #cc233344', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#cc2233', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Delete</button>}
        </div>
      </div>
    </div>
  );

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'flex-start', justifyContent: 'flex-end', zIndex: 2000, paddingTop: 60, paddingRight: 24 }} onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{ background: '#0c0e13', border: '1px solid #2a2d35', borderRadius: 10, width: 460, maxHeight: '80vh', display: 'flex', flexDirection: 'column', boxShadow: '0 8px 40px rgba(0,0,0,0.6)' }}>
        <div style={{ padding: '16px 18px 12px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <div style={{ flex: 1, fontSize: 13, fontWeight: 700, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>Operation Packs</div>
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter…" style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', width: 140 }} />
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 16, padding: 0, lineHeight: 1 }}>×</button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
          {builtin.length > 0 && <>
            <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Built-in packs</div>
            {builtin.map(p => <PackCard key={p.id} pack={p} />)}
          </>}
          {custom.length > 0 && <>
            <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', margin: '12px 0 8px' }}>Custom packs</div>
            {custom.map(p => <PackCard key={p.id} pack={p} />)}
          </>}
          {filtered.length === 0 && <div style={{ fontSize: 11, color: '#404550', textAlign: 'center', padding: 32 }}>No packs found</div>}
        </div>
      </div>
    </div>
  );
}

function SavePackModal({ steps, accent, onClose, onSaved }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState('');
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState('');

  const save = async () => {
    if (!name.trim()) { setErr('Name is required'); return; }
    setSaving(true); setErr('');
    try {
      const pack = await api.createOperationPack({
        name: name.trim(),
        description: description.trim(),
        steps: steps.map(s => ({ ...s })),
        tags: tags.split(',').map(t => t.trim()).filter(Boolean),
      });
      onSaved(pack);
      onClose();
    } catch (e) { setErr(e?.message || 'Failed to save'); }
    finally { setSaving(false); }
  };

  const inp2 = { background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', width: '100%', boxSizing: 'border-box' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2100 }} onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{ background: '#0c0e13', border: '1px solid #2a2d35', borderRadius: 8, padding: 24, width: 380, boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 18 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: '#e0e4ec', fontFamily: 'Space Grotesk', flex: 1 }}>Save as Operation Pack</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 16, padding: 0 }}>×</button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Pack name *</div>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. My Recon Pack" style={inp2} autoFocus />
          </div>
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Description</div>
            <textarea value={description} onChange={e => setDescription(e.target.value)} rows={2} placeholder="What does this pack do?" style={{ ...inp2, resize: 'vertical' }} />
          </div>
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Tags (comma separated)</div>
            <input value={tags} onChange={e => setTags(e.target.value)} placeholder="recon, web, ad" style={inp2} />
          </div>
          <div style={{ fontSize: 10, color: '#505560' }}>{steps.length} step{steps.length !== 1 ? 's' : ''} will be saved</div>
          {err && <div style={{ fontSize: 10, color: '#cc2233' }}>{err}</div>}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
            <button onClick={onClose} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
            <button onClick={save} disabled={saving} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 16px', cursor: saving ? 'default' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', opacity: saving ? 0.7 : 1 }}>
              {saving ? 'Saving…' : 'Save Pack'}
            </button>
          </div>
        </div>
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
  const [expandedRunId, setExpandedRunId] = useState(null);
  const [runJobsCache, setRunJobsCache] = useState({}); // runId → Job[]
  const runPollRef = useRef(null);
  const [runMode, setRunMode] = useState('single'); // 'single' | 'batch'
  const [batchForm, setBatchForm] = useState({ host_ids: [], host_tags: [], host_status: '', parallelism: 3 });
  const [hosts, setHosts] = useState([]);
  const [creds, setCreds] = useState([]);
  const [scopes, setScopes] = useState([]);
  const [batchResult, setBatchResult] = useState(null);
  const [activeTab, setActiveTab] = useState('playbooks'); // 'playbooks' | 'scheduled'
  const [importing, setImporting] = useState(false);
  const [packs, setPacks] = useState([]);
  const [showPacksPanel, setShowPacksPanel] = useState(false);
  const [showSavePackModal, setShowSavePackModal] = useState(false);

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    try {
      const [pb, runData, connectorData, templateData, hostData, credData, scopeData, packData] = await Promise.all([
        api.listPlaybooks(),
        api.listPlaybookRuns(selectedProject, { limit: 100 }),
        api.listConnectors().catch(() => ({ connectors: [] })),
        api.listPlaybookStepTemplates().catch(() => ({ templates: [] })),
        api.getHosts(selectedProject).catch(() => []),
        api.getCreds(selectedProject).catch(() => []),
        api.getScopes(selectedProject).catch(() => []),
        api.listOperationPacks().catch(() => ({ packs: [] })),
      ]);
      setPlaybooks(pb.playbooks || []);
      setRuns(runData.runs || []);
      setConnectors(connectorData.connectors || []);
      setStepTemplates(templateData.templates || []);
      setHosts(Array.isArray(hostData) ? hostData : []);
      setCreds(Array.isArray(credData) ? credData : []);
      setScopes(Array.isArray(scopeData) ? scopeData : []);
      setPacks(packData.packs || []);
      setSelectedPlaybookId(prev => prev || pb.playbooks?.[0]?.id || '');
    } catch (e) {
      setError(e.message || 'Failed to load playbooks');
    } finally {
      setLoading(false);
    }
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const handler = (e) => {
      const { action, data } = e.detail;
      setRuns(prev => {
        if (action === 'create') return prev.some(r => r.id === data.id) ? prev : [data, ...prev];
        if (action === 'update') return prev.map(r => r.id === data.id ? data : r);
        return prev;
      });
    };
    window.addEventListener('rt:playbook_run', handler);
    return () => window.removeEventListener('rt:playbook_run', handler);
  }, []);

  const selected = playbooks.find(p => p.id === selectedPlaybookId) || null;

  // Load full job list when a run is expanded; poll while running
  const loadRunJobs = useCallback(async (runId) => {
    if (!selectedProject || !runId) return;
    try {
      const data = await api.listJobs(selectedProject, { playbook_run_id: runId, limit: 50 });
      setRunJobsCache(prev => ({ ...prev, [runId]: data || [] }));
    } catch {}
  }, [selectedProject]);

  useEffect(() => {
    if (!expandedRunId) { clearInterval(runPollRef.current); return; }
    loadRunJobs(expandedRunId);
    const run = runs.find(r => r.id === expandedRunId);
    if (run?.status === 'running' || run?.status === 'queued') {
      runPollRef.current = setInterval(() => loadRunJobs(expandedRunId), 2000);
    }
    return () => clearInterval(runPollRef.current);
  }, [expandedRunId, runs, loadRunJobs]);

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

  const batchRunSelected = async () => {
    if (!selectedProject || !selected) return;
    setRunning(true);
    setError('');
    setBatchResult(null);
    try {
      const payload = {
        ...batchForm,
        target_url: form.target_url,
        flags: form.flags,
        severity: form.severity,
        keep_manual_positions: form.keep_manual_positions,
        create_missing_networks: form.create_missing_networks,
        username: form.username || '',
        password: form.password || '',
        domain: form.domain || '',
        hash: form.hash || '',
      };
      const res = await api.batchRunPlaybook(selectedProject, selected.id, payload);
      setBatchResult({ batchId: res.batch_id, total: res.total });
      if (res.runs) setRuns(prev => {
        const newIds = new Set(res.runs.map(r => r.id));
        return [...res.runs, ...prev.filter(r => !newIds.has(r.id))];
      });
    } catch (e) {
      setError(e.message || 'Failed to start batch run');
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

  const exportPlaybooks = async () => {
    try {
      const blob = await api.exportPlaybooks();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `playbooks-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setError(e.message); }
  };

  const importPlaybooks = async (file) => {
    setImporting(true);
    try {
      await api.importPlaybooks(file);
      await load();
    } catch (e) { setError(e.message); }
    finally { setImporting(false); }
  };

  return (
    <div style={{ padding: '20px 24px', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 18 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ color: '#c8cfe0', margin: 0, fontSize: 18 }}>Playbooks</h2>
          <div style={{ fontSize: 11, color: '#6a7080', marginTop: 4 }}>Sequential orchestration layer built on top of jobs and connectors</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={load} style={toolbarBtn(accent, false)}>Refresh</button>
          {activeTab === 'playbooks' && <>
            <label style={{ ...toolbarBtn(accent, false), cursor: importing ? 'wait' : 'pointer', opacity: importing ? 0.7 : 1, display: 'inline-flex', alignItems: 'center' }}>
              {importing ? 'Importing…' : 'Import'}
              <input type="file" accept="application/json,.json" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && importPlaybooks(e.target.files[0])} disabled={importing} />
            </label>
            <button onClick={exportPlaybooks} style={toolbarBtn(accent, false)}>Export</button>
            <button onClick={startCreate} style={toolbarBtn(accent, true)}>New custom playbook</button>
          </>}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid #1e2029', paddingBottom: 0 }}>
        {[{ id: 'playbooks', label: 'Playbooks' }, { id: 'scheduled', label: 'Scheduled' }].map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{ background: 'transparent', border: 'none', borderBottom: activeTab === t.id ? `2px solid ${accent}` : '2px solid transparent', padding: '6px 14px', cursor: 'pointer', color: activeTab === t.id ? accent : '#606570', fontSize: 12, fontFamily: 'JetBrains Mono', marginBottom: -1 }}>{t.label}</button>
        ))}
      </div>

      {error && <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 12 }}>{error}</div>}
      {editingMode && validation.errors.length > 0 && <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 12, lineHeight: 1.6 }}>{validation.errors.map((item, idx) => <div key={idx}>{item}</div>)}</div>}
      {editingMode && validation.warnings.length > 0 && <div style={{ background: '#1a1408', border: '1px solid #4a3410', borderRadius: 6, padding: '10px 12px', color: '#f09a3a', fontSize: 12, lineHeight: 1.6 }}>{validation.warnings.map((item, idx) => <div key={idx}>{item}</div>)}</div>}

      {activeTab === 'scheduled' && <ScheduledTab selectedProject={selectedProject} accent={accent} playbooks={playbooks} hosts={hosts} creds={creds} scopes={scopes} />}

      {activeTab === 'playbooks' && <div style={{ display: 'grid', gridTemplateColumns: '320px minmax(0, 1fr)', gap: 18, minHeight: 0, alignItems: 'start' }}>
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
                      allSteps={editor.steps}
                      onChange={(next) => setEditor(prev => ({ ...prev, steps: prev.steps.map((item, i) => i === idx ? next : item) }))}
                      onDelete={() => setEditor(prev => ({ ...prev, steps: prev.steps.filter((_, i) => i !== idx) }))}
                      onDuplicate={() => setEditor(prev => {
                        const copy = JSON.parse(JSON.stringify(prev.steps[idx]));
                        const next = [...prev.steps];
                        next.splice(idx + 1, 0, copy);
                        return { ...prev, steps: next };
                      })}
                      onMoveUp={() => setEditor(prev => {
                        if (idx === 0) return prev;
                        const next = [...prev.steps];
                        [next[idx - 1], next[idx]] = [next[idx], next[idx - 1]];
                        return { ...prev, steps: next };
                      })}
                      onMoveDown={() => setEditor(prev => {
                        if (idx >= prev.steps.length - 1) return prev;
                        const next = [...prev.steps];
                        [next[idx], next[idx + 1]] = [next[idx + 1], next[idx]];
                        return { ...prev, steps: next };
                      })}
                      disableDelete={editor.steps.length <= 1}
                    />
                  ))}
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={() => setEditor(prev => ({ ...prev, steps: [...prev.steps, stepTemplates[0] ? buildStepFromTemplate(stepTemplates[0]) : emptyStep()] }))} style={toolbarBtn(accent, false)}>Add step</button>
                  <button onClick={() => setShowPacksPanel(true)} style={toolbarBtn('#e8cc42', false)}>Packs</button>
                  {editor.steps.length > 0 && <button onClick={() => setShowSavePackModal(true)} style={toolbarBtn('#c07af0', false)}>Save as pack</button>}
                  <button onClick={savePlaybook} disabled={saving} style={toolbarBtn(accent, true)}>{saving ? 'Saving...' : 'Save playbook'}</button>
                  <button onClick={cancelEdit} style={toolbarBtn('#808590', false)}>Cancel</button>
                </div>
              </div>
            ) : selected && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 8, padding: '12px 14px' }}>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Playbook steps</div>
                  <StepFlowDiagram steps={selected.steps || []} accent={accent} />
                </div>

                {/* Run mode toggle */}
                <div style={{ display: 'flex', gap: 6 }}>
                  {['single', 'batch'].map(mode => (
                    <button key={mode} onClick={() => setRunMode(mode)} style={{ background: runMode === mode ? accent + '33' : '#13161f', color: runMode === mode ? accent : '#6a7080', border: `1px solid ${runMode === mode ? accent + '66' : '#1e2230'}`, borderRadius: 4, padding: '3px 14px', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>
                      {mode === 'single' ? 'Single run' : 'Batch run'}
                    </button>
                  ))}
                </div>

                {runMode === 'single' ? (
                  <>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                      <div>
                        <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Target</div>
                        <PickerInput
                          value={form.target}
                          onChange={v => setForm(prev => ({ ...prev, target: v }))}
                          placeholder="10.0.0.0/24"
                          options={[
                            ...hosts.filter(h => !h.is_attacker).map(h => ({ value: h.ip, label: (h.hostname ? `${h.hostname} · ` : '') + (h.os || '') + (h.tags?.length ? ' [' + h.tags.join(',') + ']' : '') })),
                            ...scopes.filter(s => s.in_scope && ['cidr','hostname'].includes(s.scope_type)).map(s => ({ value: s.value, label: `scope · ${s.description || s.scope_type}` })),
                          ]}
                        />
                      </div>
                      <div>
                        <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Target URL</div>
                        <PickerInput
                          value={form.target_url}
                          onChange={v => setForm(prev => ({ ...prev, target_url: v }))}
                          placeholder="https://target.example"
                          options={[
                            ...hosts.filter(h => !h.is_attacker && (h.tags?.includes('web') || h.ports?.some(p => ['80','443','8080','8443'].includes(String(p).split('/')[0])))).map(h => ({ value: `http${h.tags?.includes('web') && h.ports?.some(p => ['443','8443'].includes(String(p).split('/')[0])) ? 's' : ''}://${h.hostname || h.ip}`, label: h.hostname || h.ip })),
                            ...scopes.filter(s => s.in_scope && s.scope_type === 'url').map(s => ({ value: s.value, label: `scope · ${s.description || ''}` })),
                          ]}
                        />
                      </div>
                    </div>
                  </>
                ) : (
                  <>
                    <BatchHostSelector hosts={hosts} batchForm={batchForm} onChange={setBatchForm} accent={accent} />
                    {batchResult && (
                      <div style={{ background: '#0a1a0a', border: '1px solid #39d35344', borderRadius: 6, padding: '8px 12px', fontSize: 11, color: '#39d353', fontFamily: 'JetBrains Mono' }}>
                        Batch started: {batchResult.total} runs · id: {batchResult.batchId}
                      </div>
                    )}
                  </>
                )}

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

                {/* AD / Auth fields */}
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span>Auth / AD credentials <span style={{ color: '#303540' }}>(optional)</span></span>
                    <CredPicker accent={accent} creds={creds} onPick={c => setForm(prev => ({
                      ...prev,
                      username: c.username.includes('\\') ? c.username.split('\\')[1] : c.username,
                      domain: c.domain || (c.username.includes('\\') ? c.username.split('\\')[0] : ''),
                      password: (c.type === 'plain' || c.type === 'token') ? (c.secret || '') : '',
                      hash: (c.type === 'hash' || c.type === 'ntlm') ? (c.secret || '') : '',
                    }))} />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                    <div>
                      <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Domain</div>
                      <PickerInput
                        value={form.domain || ''}
                        onChange={v => setForm(prev => ({ ...prev, domain: v }))}
                        placeholder="CORP"
                        options={[...new Set(creds.filter(c => c.domain).map(c => c.domain))].map(d => ({ value: d }))}
                      />
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Username</div>
                      <PickerInput
                        value={form.username || ''}
                        onChange={v => setForm(prev => ({ ...prev, username: v }))}
                        placeholder="administrator"
                        options={creds.map(c => ({ value: c.username.includes('\\') ? c.username.split('\\')[1] : c.username, label: c.domain ? `${c.domain} · ${c.type}` : c.type }))}
                      />
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Password</div>
                      <input type="password" value={form.password || ''} onChange={e => setForm(prev => ({ ...prev, password: e.target.value }))} placeholder="••••••••" style={inp()} />
                    </div>
                    <div>
                      <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>NTLM Hash</div>
                      <PickerInput
                        value={form.hash || ''}
                        onChange={v => setForm(prev => ({ ...prev, hash: v }))}
                        placeholder="aad3b435b51404eeaad3b435b51404ee:..."
                        options={creds.filter(c => c.type === 'hash' || c.type === 'ntlm').map(c => ({ value: c.secret || '', label: `${c.username} · ${c.type}` }))}
                      />
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <button onClick={() => setForm(prev => ({ ...prev, keep_manual_positions: !prev.keep_manual_positions }))} style={toggleBtn(form.keep_manual_positions, accent)}>{form.keep_manual_positions ? 'Keep manual positions' : 'Ignore manual positions'}</button>
                  <button onClick={() => setForm(prev => ({ ...prev, create_missing_networks: !prev.create_missing_networks }))} style={toggleBtn(form.create_missing_networks, accent)}>{form.create_missing_networks ? 'Create missing networks' : 'No auto-create'}</button>
                </div>
                {runMode === 'single'
                  ? <button onClick={runSelected} disabled={running} style={{ background: running ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '8px 16px', cursor: running ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{running ? 'Starting...' : 'Run playbook'}</button>
                  : <button onClick={batchRunSelected} disabled={running} style={{ background: running ? '#1a1c22' : '#f09a3a', border: 'none', borderRadius: 5, padding: '8px 16px', cursor: running ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{running ? 'Starting...' : `Run on ${batchForm.host_ids.length > 0 ? batchForm.host_ids.length : 'filtered'} hosts`}</button>
                }
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
                {runs.map((run, i) => {
                  const isExpanded = expandedRunId === run.id;
                  const duration = run.started_at && run.finished_at
                    ? (() => { const s = new Date(run.started_at), f = new Date(run.finished_at); const sec = Math.round((f - s) / 1000); return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`; })()
                    : run.started_at && !run.finished_at ? 'running…' : null;
                  const resultKeys = Object.entries(run.result_json || {}).filter(([k]) => !['completed_jobs', 'failed_jobs', 'cancelled_jobs'].includes(k));
                  return (
                    <div key={run.id} style={{ borderBottom: i < runs.length - 1 ? '1px solid #14161b' : 'none' }}>
                      <div
                        onClick={() => setExpandedRunId(prev => prev === run.id ? null : run.id)}
                        style={{ padding: '12px 16px', cursor: 'pointer', userSelect: 'none' }}
                        onMouseEnter={e => e.currentTarget.style.background = '#ffffff04'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                          <span style={{ fontSize: 10, color: isExpanded ? accent : '#505560', fontFamily: 'JetBrains Mono', flexShrink: 0 }}>{isExpanded ? '▾' : '▸'}</span>
                          <span style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 600 }}>{run.title}</span>
                          <StatusBadge status={run.status} />
                          {duration && <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>⏱ {duration}</span>}
                          {run.request_json?.batch_id && <span style={{ fontSize: 9, color: '#f09a3a', background: '#f09a3a18', border: '1px solid #f09a3a33', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>batch</span>}
                        </div>
                        <div style={{ fontSize: 10, color: '#606570', display: 'flex', gap: 12, flexWrap: 'wrap', fontFamily: 'JetBrains Mono', paddingLeft: 18 }}>
                          {run.target && <span>target: {run.target}</span>}
                          <span>{(run.jobs_json || []).length} step{(run.jobs_json || []).length === 1 ? '' : 's'}</span>
                          <span>by: {run.created_by || '—'}</span>
                          <span>{run.created_at?.slice(0, 16) || '—'}</span>
                        </div>
                      </div>

                      {isExpanded && (
                        <div style={{ padding: '0 16px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
                          <div style={{ background: '#090b0f', border: '1px solid #1e2029', borderRadius: 8, overflow: 'hidden' }}>
                            <div style={{ padding: '8px 12px', borderBottom: '1px solid #14161b', fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: 8 }}>
                              Steps
                              {run.status === 'running' && <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f09a3a', animation: 'pulse 1.2s infinite', display: 'inline-block' }} />}
                            </div>
                            {(() => {
                              const liveJobs = runJobsCache[run.id];
                              const steps = run.jobs_json || [];
                              return steps.map((snapshot, idx) => {
                                const liveJob = liveJobs?.find(j => j.id === snapshot.id);
                                const job = liveJob || snapshot;
                                const statusCfg = RUN_STATUS[job.status] || RUN_STATUS.queued;
                                const isRunning = job.status === 'running';
                                const isFailed = job.status === 'failed';
                                const dur = liveJob?.started_at ? (() => {
                                  const s = new Date(liveJob.started_at);
                                  const f = liveJob.finished_at ? new Date(liveJob.finished_at) : new Date();
                                  const sec = Math.round((f - s) / 1000);
                                  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
                                })() : null;
                                const summary = liveJob?.result_json?.structured?.summary || '';
                                const lastLines = liveJob?.output?.split('\n').filter(Boolean).slice(-3) || [];
                                return (
                                  <div key={job.id} style={{ borderBottom: idx < steps.length - 1 ? '1px solid #12141a' : 'none', background: isRunning ? '#f09a3a06' : isFailed ? '#cc223306' : 'transparent' }}>
                                    <div style={{ padding: '8px 12px', display: 'flex', alignItems: 'center', gap: 10 }}>
                                      <div style={{ width: 20, height: 20, borderRadius: '50%', background: job.status === 'done' ? '#39d35322' : isRunning ? '#f09a3a22' : isFailed ? '#cc223322' : '#13161f', border: `1px solid ${statusCfg.color}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: statusCfg.color, fontSize: 9, fontFamily: 'JetBrains Mono', fontWeight: 700, flexShrink: 0 }}>
                                        {isRunning ? <span style={{ animation: 'pulse 1.2s infinite' }}>●</span> : job.status === 'done' ? '✓' : isFailed ? '✗' : idx + 1}
                                      </div>
                                      <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{ fontSize: 11, color: '#c8cdd6', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{job.title}</div>
                                        <div style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginTop: 2, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                          {liveJob?.connector_key && <span style={{ color: '#6fc8f0' }}>{liveJob.connector_key}</span>}
                                          {liveJob?.operation && <span>{liveJob.operation}</span>}
                                          {liveJob?.target && <span>→ {liveJob.target}</span>}
                                          {summary && <span style={{ color: '#808590' }}>{summary}</span>}
                                        </div>
                                      </div>
                                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                                        <StatusBadge status={job.status} />
                                        {dur && <span style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>⏱{dur}</span>}
                                      </div>
                                    </div>
                                    {(isRunning || isFailed) && lastLines.length > 0 && (
                                      <div style={{ padding: '0 12px 8px 42px' }}>
                                        <pre style={{ margin: 0, fontSize: 9, color: isFailed ? '#f87171' : '#606570', fontFamily: 'JetBrains Mono', lineHeight: 1.5, background: '#07080c', borderRadius: 4, padding: '4px 8px', overflow: 'hidden' }}>
                                          {lastLines.join('\n')}
                                        </pre>
                                      </div>
                                    )}
                                  </div>
                                );
                              });
                            })()}
                          </div>

                          {(run.status === 'done' || run.status === 'failed') && (
                            <RunRollup run={run} accent={accent} />
                          )}

                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 10, fontFamily: 'JetBrains Mono', color: '#606570' }}>
                            {run.started_at && <div><span style={{ color: '#404550' }}>started: </span>{run.started_at.slice(0, 16)}</div>}
                            {run.finished_at && <div><span style={{ color: '#404550' }}>finished: </span>{run.finished_at.slice(0, 16)}</div>}
                            <div><span style={{ color: '#404550' }}>run id: </span>{run.id}</div>
                            <div><span style={{ color: '#404550' }}>playbook: </span>{run.playbook_id}</div>
                          </div>

                          {run.error_output && (
                            <div style={{ background: '#130808', border: '1px solid #3a1010', borderRadius: 6, padding: '8px 12px', fontSize: 10, color: '#f87171', fontFamily: 'JetBrains Mono', lineHeight: 1.6 }}>{run.error_output}</div>
                          )}

                          <div style={{ display: 'flex', gap: 8 }}>
                            {(run.status === 'queued' || run.status === 'running') && <button onClick={() => cancelRun(run.id)} style={toolbarBtn('#f09a3a', false)}>Cancel run</button>}
                            {run.status !== 'queued' && run.status !== 'running' && <button onClick={() => rerun(run.id)} style={toolbarBtn(accent, false)}>Rerun</button>}
                            {!!(run.jobs_json || []).length && <button onClick={() => onNavigate?.('jobs', { playbookRunId: run.id })} style={toolbarBtn('#5b8af5', false)}>Open Jobs</button>}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>}

      {showPacksPanel && (
        <PacksPanel
          packs={packs}
          accent={accent}
          onInsert={(pack) => {
            const newSteps = (pack.steps || []).map(s => ({ ...s }));
            setEditor(prev => ({ ...prev, steps: [...prev.steps, ...newSteps] }));
            setShowPacksPanel(false);
          }}
          onDelete={async (packId) => {
            await api.deleteOperationPack(packId).catch(() => {});
            setPacks(prev => prev.filter(p => p.id !== packId));
          }}
          onClose={() => setShowPacksPanel(false)}
        />
      )}

      {showSavePackModal && (
        <SavePackModal
          steps={editor.steps}
          accent={accent}
          onClose={() => setShowSavePackModal(false)}
          onSaved={(pack) => setPacks(prev => [...prev, pack])}
        />
      )}
    </div>
  );
}

