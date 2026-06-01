import React, { useEffect, useRef, useState } from 'react';
import PropTypes from 'prop-types';

import { api } from '../api.js';
import { isWsConnected } from '../hooks/useSync.js';
import ScheduledTab from './playbooks/ScheduledTab.jsx';
import { inp, toolbarBtn, toggleBtn } from './playbooks/utils.js';
import { StepFlowDiagram, DagPreview } from './playbooks/DagGraphs.jsx';
import { StepEditor } from './playbooks/StepEditor.jsx';
import { PlaybookCard, PlaybookRunsList } from './playbooks/RunViews.jsx';

// ── Pure state helpers ───────────────────────────────────────────────

function _applyRunAction(prev, action, data) {
  if (action === 'upsert') {
    const idx = prev.findIndex(r => r.id === data.id);
    if (idx >= 0) { const next = [...prev]; next[idx] = data; return next; }
    return [data, ...prev];
  }
  if (action === 'remove') return prev.filter(r => r.id !== data.id);
  return prev;
}

function _updateStep(steps, idx, next) { return steps.map((s, i) => i === idx ? next : s); }
function _deleteStep(steps, idx) { return steps.filter((_, i) => i !== idx); }
function _duplicateStep(steps, idx) { return [...steps.slice(0, idx + 1), { ...steps[idx], title: steps[idx].title ? steps[idx].title + ' (copy)' : '' }, ...steps.slice(idx + 1)]; }
function _moveStep(steps, idx, dir) {
  const target = idx + dir;
  if (target < 0 || target >= steps.length) return steps;
  const next = [...steps];
  [next[idx], next[target]] = [next[target], next[idx]];
  return next;
}

function emptyStep() {
  return { title: '', connector_key: 'nmap', operation: 'scan', params: {}, on_success: 'next', on_success_step: null, on_failure: 'stop', on_failure_step: null, result_conditions: [], depends_on: [], retry_count: 0, retry_delay_seconds: 5, retry_on: ['failed'], precondition: null };
}

function emptyPlaybook() {
  return { title: '', description: '', steps: [emptyStep()] };
}

function buildStepFromTemplate(template) {
  return {
    title: template.title || '',
    connector_key: template.connector_key,
    operation: template.operation,
    params: Object.fromEntries((template.fields || []).map(field => [field.key, field.default ?? (field.type === 'boolean' ? false : '')])),
    on_success: 'next', on_success_step: null, on_failure: 'stop', on_failure_step: null,
    result_conditions: [], depends_on: [], retry_count: 0, retry_delay_seconds: 5, retry_on: ['failed'], precondition: null,
  };
}

function _editorFromPlaybook(pb) {
  return { title: pb.title || '', description: pb.description || '', steps: (pb.steps || []).map(step => ({ ...step, params: step.params || {} })) };
}

function _findPlaybook(playbooks, id) { return playbooks.find(p => p.id === id) || null; }

// ── Option builders for pickers ──────────────────────────────────────

function _hostTargetOptions(hosts, scopes) {
  const hostOpts = hosts.filter(h => !h.is_attacker).map(h => ({ value: h.ip, label: (h.hostname ? `${h.hostname} · ` : '') + (h.os || '') + (h.tags?.length ? ' [' + h.tags.join(',') + ']' : '') }));
  const scopeOpts = scopes.filter(s => s.in_scope && (s.scope_type === 'cidr' || s.scope_type === 'hostname')).map(s => ({ value: s.value, label: `scope · ${s.description || s.scope_type}` }));
  return [...hostOpts, ...scopeOpts];
}

function _isWebPort(p) { return ['80', '443', '8080', '8443'].includes(String(p).split('/')[0]); }
function _isSslPort(p) { return ['443', '8443'].includes(String(p).split('/')[0]); }

function _hostUrlOptions(hosts, scopes) {
  const hostOpts = hosts.filter(h => !h.is_attacker && (h.tags?.includes('web') || h.ports?.some(_isWebPort))).map(h => {
    const isHttps = h.tags?.includes('web') && h.ports?.some(_isSslPort);
    return { value: `http${isHttps ? 's' : ''}://${h.hostname || h.ip}`, label: h.hostname || h.ip };
  });
  const scopeOpts = scopes.filter(s => s.in_scope && s.scope_type === 'url').map(s => ({ value: s.value, label: `scope · ${s.description || ''}` }));
  return [...hostOpts, ...scopeOpts];
}

function _credPickToForm(c) {
  const usernameRaw = c.username.includes('\\') ? c.username.split('\\')[1] : c.username;
  const domain = c.domain || (c.username.includes('\\') ? c.username.split('\\')[0] : '');
  const password = (c.type === 'plain' || c.type === 'token') ? (c.secret || '') : '';
  const hash = (c.type === 'hash' || c.type === 'ntlm') ? (c.secret || '') : '';
  return { username: usernameRaw, domain, password, hash };
}

// ── PickerInput ──────────────────────────────────────────────────────

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
        <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} style={{ ...inp(), borderRadius: options?.length ? '5px 0 0 5px' : 5, flex: 1 }} />
        {options?.length > 0 && (
          <button onClick={() => setOpen(v => !v)} title="Pick from project data" style={{ background: open ? '#1e2230' : '#13161f', border: '1px solid #2a2d35', borderLeft: 'none', borderRadius: '0 5px 5px 0', padding: '0 8px', cursor: 'pointer', color: '#606570', fontSize: 10, flexShrink: 0 }}>▾</button>
        )}
      </div>
      {open && options?.length > 0 && (
        <div style={{ position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 100, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, marginTop: 2, maxHeight: 220, overflowY: 'auto', boxShadow: '0 8px 24px #00000099' }}>
          {options.map((opt, i) => (
            <button type="button" key={opt.value || `opt-${i}`} onClick={() => { onChange(opt.value); setOpen(false); }}
              style={{ padding: '7px 12px', cursor: 'pointer', borderBottom: i < options.length - 1 ? '1px solid #1a1c22' : 'none', width: '100%', textAlign: 'left', background: 'transparent', borderTop: 'none', borderLeft: 'none', borderRight: 'none' }}
              onMouseEnter={e => e.currentTarget.style.background = '#ffffff08'} onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <div style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>{opt.value}</div>
              {opt.label && <div style={{ fontSize: 9, color: '#505560', marginTop: 1 }}>{opt.label}</div>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

PickerInput.propTypes = {
  value: PropTypes.string,
  onChange: PropTypes.func,
  placeholder: PropTypes.string,
  label: PropTypes.string,
  options: PropTypes.arrayOf(PropTypes.shape({ value: PropTypes.any, label: PropTypes.string })),
  type: PropTypes.string,
};

// ── CredPicker ───────────────────────────────────────────────────────

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
      <button onClick={() => setOpen(v => !v)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '5px 10px', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>From creds ▾</button>
      {open && (
        <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 100, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, marginTop: 2, minWidth: 280, maxHeight: 280, overflowY: 'auto', boxShadow: '0 8px 24px #00000099' }}>
          {creds.map((c, i) => (
            <button type="button" key={c.id} onClick={() => { onPick(c); setOpen(false); }}
              style={{ padding: '8px 12px', cursor: 'pointer', borderBottom: i < creds.length - 1 ? '1px solid #1a1c22' : 'none', width: '100%', textAlign: 'left', background: 'transparent', borderTop: 'none', borderLeft: 'none', borderRight: 'none' }}
              onMouseEnter={e => e.currentTarget.style.background = '#ffffff08'} onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <div style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{c.domain ? `${c.domain}\\` : ''}{c.username}</div>
              <div style={{ fontSize: 9, color: '#505560', marginTop: 1, display: 'flex', gap: 8 }}>
                <span style={{ color: c.type === 'hash' || c.type === 'ntlm' ? '#c07af0' : '#5b8af5' }}>{c.type}</span>
                {c.service && <span>{c.service}</span>}
                {c.tags?.length > 0 && <span>{c.tags.join(', ')}</span>}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

CredPicker.propTypes = {
  creds: PropTypes.array,
  onPick: PropTypes.func,
  accent: PropTypes.string,
};

// ── BatchHostSelector ────────────────────────────────────────────────

function BatchHostSelector({ hosts, batchForm, onChange, accent }) {
  const allTags = [...new Set(hosts.flatMap(h => h.tags || []))].sort((a, b) => a.localeCompare(b));
  const allStatuses = [...new Set(hosts.map(h => h.status).filter(Boolean))].sort((a, b) => a.localeCompare(b));

  const filtered = hosts.filter(h => {
    if (batchForm.host_ids.length > 0) return batchForm.host_ids.includes(h.id);
    if (batchForm.host_tags.length > 0 && !batchForm.host_tags.some(t => (h.tags || []).includes(t))) return false;
    if (batchForm.host_status && h.status !== batchForm.host_status) return false;
    return true;
  });

  const toggleHost = (id) => onChange(prev => ({ ...prev, host_ids: prev.host_ids.includes(id) ? prev.host_ids.filter(x => x !== id) : [...prev.host_ids, id] }));
  const toggleTag = (tag) => onChange(prev => ({ ...prev, host_ids: [], host_tags: prev.host_tags.includes(tag) ? prev.host_tags.filter(t => t !== tag) : [...prev.host_tags, tag] }));

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Batch target hosts <span style={{ marginLeft: 8, color: accent, fontWeight: 600 }}>{filtered.length} selected</span></div>
      {allTags.length > 0 && (
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 10, color: '#404550', marginRight: 2 }}>Tags:</span>
          {allTags.map(tag => <button key={tag} onClick={() => toggleTag(tag)} style={{ background: batchForm.host_tags.includes(tag) ? accent + '33' : '#13161f', color: batchForm.host_tags.includes(tag) ? accent : '#6a7080', border: `1px solid ${batchForm.host_tags.includes(tag) ? accent + '66' : '#1e2230'}`, borderRadius: 4, padding: '1px 8px', fontSize: 10, cursor: 'pointer', fontFamily: 'JetBrains Mono' }}>{tag}</button>)}
        </div>
      )}
      {allStatuses.length > 0 && (
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 10, color: '#404550', marginRight: 2 }}>Status:</span>
          {allStatuses.map(s => <button key={s} onClick={() => onChange(prev => ({ ...prev, host_ids: [], host_status: prev.host_status === s ? '' : s }))} style={{ background: batchForm.host_status === s ? '#f09a3a33' : '#13161f', color: batchForm.host_status === s ? '#f09a3a' : '#6a7080', border: `1px solid ${batchForm.host_status === s ? '#f09a3a66' : '#1e2230'}`, borderRadius: 4, padding: '1px 8px', fontSize: 10, cursor: 'pointer' }}>{s}</button>)}
        </div>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 10, color: '#505560' }}>Parallelism:</span>
        {[1, 2, 3, 5, 10].map(n => <button key={n} onClick={() => onChange(prev => ({ ...prev, parallelism: n }))} style={{ background: batchForm.parallelism === n ? '#6fc8f033' : '#13161f', color: batchForm.parallelism === n ? '#6fc8f0' : '#505560', border: `1px solid ${batchForm.parallelism === n ? '#6fc8f066' : '#1e2230'}`, borderRadius: 4, padding: '1px 8px', fontSize: 10, cursor: 'pointer', fontFamily: 'JetBrains Mono' }}>{n}</button>)}
        <span style={{ fontSize: 10, color: '#303540' }}>concurrent</span>
      </div>
      {hosts.length > 0 && (
        <div style={{ maxHeight: 160, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 2 }}>
          {hosts.filter(h => {
            if (batchForm.host_tags.length > 0 && !batchForm.host_tags.some(t => (h.tags || []).includes(t))) return false;
            if (batchForm.host_status && h.status !== batchForm.host_status) return false;
            return true;
          }).map(h => {
            const checked = batchForm.host_ids.length === 0 || batchForm.host_ids.includes(h.id);
            return (
              <button key={h.id} type="button" onClick={() => toggleHost(h.id)} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 4px', borderRadius: 3, cursor: 'pointer', background: checked && batchForm.host_ids.length > 0 ? accent + '11' : 'transparent', border: 'none', width: '100%', textAlign: 'left' }}>
                <div style={{ width: 12, height: 12, border: `1px solid ${checked ? accent : '#303540'}`, borderRadius: 2, background: checked ? accent + '33' : 'transparent', flexShrink: 0 }} />
                <span style={{ fontSize: 10, color: '#a0a8b8', fontFamily: 'JetBrains Mono' }}>{h.ip}</span>
                {h.hostname && <span style={{ fontSize: 10, color: '#505560' }}>{h.hostname}</span>}
                {(h.tags || []).map(t => <span key={t} style={{ fontSize: 9, color: '#505560', background: '#13161f', border: '1px solid #1e2230', borderRadius: 3, padding: '0 4px' }}>{t}</span>)}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

BatchHostSelector.propTypes = {
  hosts: PropTypes.array,
  batchForm: PropTypes.object,
  onChange: PropTypes.func,
  accent: PropTypes.string,
};

// ── Packs ────────────────────────────────────────────────────────────

const TAG_COLORS = { recon: '#5b8af5', web: '#6fc8f0', ad: '#c07af0', enum: '#5b8af5', creds: '#e8574a', lateral: '#e8cc42', smb: '#f09a3a', impacket: '#c07af0', nmap: '#39d353', 'post-exploitation': '#e8574a' };
function tagColor(t) { return TAG_COLORS[t] || '#606570'; }

function PackCard({ pack, accent, onInsert, onDelete }) {
  return (
    <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: '12px 14px', marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 600, marginBottom: 4 }}>{pack.name}</div>
          {pack.description && <div style={{ fontSize: 10, color: '#606570', lineHeight: 1.5, marginBottom: 6 }}>{pack.description}</div>}
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 6 }}>
            {(pack.tags || []).map(t => <span key={t} style={{ fontSize: 8, color: tagColor(t), background: tagColor(t) + '18', border: `1px solid ${tagColor(t)}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{t}</span>)}
            <span style={{ fontSize: 8, color: '#404550', background: '#ffffff08', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{pack.steps.length} step{pack.steps.length === 1 ? '' : 's'}</span>
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {pack.steps.map((s, i) => <span key={`${i}-${s.title || s.operation}`} style={{ fontSize: 8, color: '#505560', fontFamily: 'JetBrains Mono' }}>{i + 1}. {s.title || s.operation}</span>)}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flexShrink: 0 }}>
          <button onClick={() => onInsert(pack)} style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>Insert</button>
          {!pack.is_builtin && <button onClick={() => onDelete(pack.id)} style={{ background: 'transparent', border: '1px solid #cc233344', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#cc2233', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Delete</button>}
        </div>
      </div>
    </div>
  );
}

PackCard.propTypes = {
  pack: PropTypes.object,
  accent: PropTypes.string,
  onInsert: PropTypes.func,
  onDelete: PropTypes.func,
};

function PacksPanel({ packs, accent, onInsert, onDelete, onClose }) {
  const [filter, setFilter] = useState('');
  const filtered = packs.filter(p => !filter || p.name.toLowerCase().includes(filter.toLowerCase()) || (p.tags || []).some(t => t.includes(filter.toLowerCase())));
  const builtin = filtered.filter(p => p.is_builtin);
  const custom = filtered.filter(p => !p.is_builtin);
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'flex-start', justifyContent: 'flex-end', zIndex: 2000, paddingTop: 60, paddingRight: 24 }}>
      <button type="button" aria-label="Close operation packs" onClick={onClose} style={{ position: 'absolute', inset: 0, background: 'transparent', border: 'none', cursor: 'default' }} />
      <div style={{ background: '#0c0e13', border: '1px solid #2a2d35', borderRadius: 10, width: 460, maxHeight: '80vh', display: 'flex', flexDirection: 'column', boxShadow: '0 8px 40px rgba(0,0,0,0.6)' }}>
        <div style={{ padding: '16px 18px 12px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <div style={{ flex: 1, fontSize: 13, fontWeight: 700, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>Operation Packs</div>
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter…" style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', width: 140 }} />
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 16, padding: 0, lineHeight: 1 }}>×</button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px' }}>
          {builtin.length > 0 && <><div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Built-in packs</div>{builtin.map(p => <PackCard key={p.id} pack={p} accent={accent} onInsert={onInsert} onDelete={onDelete} />)}</>}
          {custom.length > 0 && <><div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', margin: '12px 0 8px' }}>Custom packs</div>{custom.map(p => <PackCard key={p.id} pack={p} accent={accent} onInsert={onInsert} onDelete={onDelete} />)}</>}
          {filtered.length === 0 && <div style={{ fontSize: 11, color: '#404550', textAlign: 'center', padding: 32 }}>No packs found</div>}
        </div>
      </div>
    </div>
  );
}

PacksPanel.propTypes = {
  packs: PropTypes.array,
  accent: PropTypes.string,
  onInsert: PropTypes.func,
  onDelete: PropTypes.func,
  onClose: PropTypes.func,
};

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
      const pack = await api.createOperationPack({ name: name.trim(), description: description.trim(), steps: steps.map(s => ({ ...s })), tags: tags.split(',').map(t => t.trim()).filter(Boolean) });
      onSaved(pack); onClose();
    } catch (e) { setErr(e?.message || 'Failed to save'); } finally { setSaving(false); }
  };
  const inp2 = { background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', width: '100%', boxSizing: 'border-box' };
  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2100 }}>
      <button type="button" aria-label="Close save pack modal" onClick={onClose} style={{ position: 'absolute', inset: 0, background: 'transparent', border: 'none', cursor: 'default' }} />
      <div style={{ background: '#0c0e13', border: '1px solid #2a2d35', borderRadius: 8, padding: 24, width: 380, boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 18 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: '#e0e4ec', fontFamily: 'Space Grotesk', flex: 1 }}>Save as Operation Pack</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 16, padding: 0 }}>×</button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Pack name *</div><input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. My Recon Pack" style={inp2} autoFocus /></div>
          <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Description</div><textarea value={description} onChange={e => setDescription(e.target.value)} rows={2} placeholder="What does this pack do?" style={{ ...inp2, resize: 'vertical' }} /></div>
          <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Tags (comma separated)</div><input value={tags} onChange={e => setTags(e.target.value)} placeholder="recon, web, ad" style={inp2} /></div>
          <div style={{ fontSize: 10, color: '#505560' }}>{steps.length} step{steps.length === 1 ? '' : 's'} will be saved</div>
          {err && <div style={{ fontSize: 10, color: '#cc2233' }}>{err}</div>}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
            <button onClick={onClose} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
            <button onClick={save} disabled={saving} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 16px', cursor: saving ? 'default' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', opacity: saving ? 0.7 : 1 }}>{saving ? 'Saving…' : 'Save Pack'}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

SavePackModal.propTypes = {
  steps: PropTypes.array,
  accent: PropTypes.string,
  onClose: PropTypes.func,
  onSaved: PropTypes.func,
};

// ── Async action helpers ─────────────────────────────────────────────

function _buildSavePayload(editor) {
  return {
    title: editor.title, description: editor.description,
    steps: (editor.steps || []).map(step => ({
      title: step.title, connector_key: step.connector_key, operation: step.operation, params: step.params || {},
      on_success: step.on_success || 'next', on_success_step: step.on_success_step ?? null,
      on_failure: step.on_failure || 'stop', on_failure_step: step.on_failure_step ?? null,
      result_conditions: step.result_conditions || [], depends_on: (step.depends_on || []).map(Number),
      retry_count: Number(step.retry_count) || 0, retry_delay_seconds: Number(step.retry_delay_seconds) || 0,
      retry_on: step.retry_on?.length ? step.retry_on : ['failed'], precondition: step.precondition || null,
    })),
  };
}

async function _doSavePlaybook({ editor, selected, load, setSelectedPlaybookId, setEditingMode, setSaving, setError, setValidation }) {
  setSaving(true); setError('');
  try {
    const payload = _buildSavePayload(editor);
    const validationRes = await api.validatePlaybook(payload);
    setValidation({ errors: validationRes.errors || [], warnings: validationRes.warnings || [] });
    if (!validationRes.ok) throw new Error('Playbook validation failed');
    const normalizedPayload = validationRes.normalized || payload;
    let saved;
    if (selected?.editable && selected.id) { saved = await api.updateCustomPlaybook(selected.id, normalizedPayload); }
    else { saved = await api.createCustomPlaybook(normalizedPayload); }
    await load(); setSelectedPlaybookId(saved.id); setEditingMode(false);
  } catch (e) { setError(e.message || 'Failed to save playbook'); } finally { setSaving(false); }
}

async function _doDeletePlaybook({ selected, load, setSelectedPlaybookId, setEditingMode, setError }) {
  if (!selected?.editable) return;
  try { await api.deleteCustomPlaybook(selected.id); await load(); setSelectedPlaybookId(prev => prev === selected.id ? '' : prev); setEditingMode(false); }
  catch (e) { setError(e.message || 'Failed to delete playbook'); }
}

async function _doRunPlaybook({ selectedProject, selected, form, setRunning, setError, setRuns, onNavigate }) {
  if (!selectedProject || !selected) return;
  setRunning(true); setError('');
  try {
    const res = await api.runPlaybook(selectedProject, selected.id, form);
    if (res.playbook_run) setRuns(prev => [res.playbook_run, ...prev.filter(r => r.id !== res.playbook_run.id)]);
    if (onNavigate) onNavigate('jobs');
  } catch (e) { setError(e.message || 'Failed to run playbook'); } finally { setRunning(false); }
}

async function _doBatchRun({ selectedProject, selected, form, batchForm, setRunning, setError, setBatchResult, setRuns }) {
  if (!selectedProject || !selected) return;
  setRunning(true); setError(''); setBatchResult(null);
  try {
    const payload = { ...batchForm, target_url: form.target_url, flags: form.flags, severity: form.severity, keep_manual_positions: form.keep_manual_positions, create_missing_networks: form.create_missing_networks, username: form.username || '', password: form.password || '', domain: form.domain || '', hash: form.hash || '' };
    const res = await api.batchRunPlaybook(selectedProject, selected.id, payload);
    setBatchResult({ batchId: res.batch_id, total: res.total });
    if (res.runs) setRuns(prev => { const newIds = new Set(res.runs.map(r => r.id)); return [...res.runs, ...prev.filter(r => !newIds.has(r.id))]; });
  } catch (e) { setError(e.message || 'Failed to start batch run'); } finally { setRunning(false); }
}

async function _doCancelRun(selectedProject, runId, setRuns, setError) {
  try { const updated = await api.cancelPlaybookRun(selectedProject, runId); setRuns(prev => prev.map(run => run.id === runId ? updated : run)); }
  catch (e) { setError(e.message || 'Failed to cancel playbook run'); }
}

async function _doRerun(selectedProject, runId, setRuns, setError) {
  try { const res = await api.rerunPlaybookRun(selectedProject, runId); if (res.playbook_run) setRuns(prev => [res.playbook_run, ...prev.filter(r => r.id !== res.playbook_run.id)]); }
  catch (e) { setError(e.message || 'Failed to rerun playbook'); }
}

async function _doExportPlaybooks(setError) {
  try { const blob = await api.exportPlaybooks(); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `playbooks-export-${Date.now()}.json`; a.click(); URL.revokeObjectURL(url); }
  catch (e) { setError(e.message); }
}

async function _doImportPlaybooks(file, load, setImporting, setError) {
  setImporting(true);
  try { await api.importPlaybooks(file); await load(); } catch (e) { setError(e.message); } finally { setImporting(false); }
}

async function _loadRunJobsData(selectedProject, runId, setRunJobsCache) {
  if (!selectedProject || !runId) return;
  try { const data = await api.listJobs(selectedProject, { playbook_run_id: runId, limit: 50 }); setRunJobsCache(prev => ({ ...prev, [runId]: data || [] })); } catch {}
}

function _setupRunPolling(expandedRunId, runs, runPollRef, selectedProject, setRunJobsCache) {
  const loadRunJobs = (runId) => _loadRunJobsData(selectedProject, runId, setRunJobsCache);
  if (!expandedRunId) { clearInterval(runPollRef.current); return undefined; }
  loadRunJobs(expandedRunId);
  const run = runs.find(r => r.id === expandedRunId);
  const active = run?.status === 'running' || run?.status === 'queued';
  if (!active) return () => clearInterval(runPollRef.current);
  const schedule = () => { clearInterval(runPollRef.current); runPollRef.current = setInterval(() => loadRunJobs(expandedRunId), isWsConnected() ? 20000 : 2000); };
  schedule();
  const onWs = () => schedule();
  globalThis.addEventListener('rt:ws-state', onWs);
  return () => { clearInterval(runPollRef.current); globalThis.removeEventListener('rt:ws-state', onWs); };
}

function _setupPlaybookRunListener(setRuns) {
  const handler = (e) => { const { action, data } = e.detail; setRuns(prev => _applyRunAction(prev, action, data)); };
  globalThis.addEventListener('rt:playbook_run', handler);
  return () => globalThis.removeEventListener('rt:playbook_run', handler);
}

function _syncEditorFromSelected(selected, editingMode, setEditor) {
  if (!selected || editingMode) return;
  setEditor(_editorFromPlaybook(selected));
}

function _startEditPlaybook(selected, setEditingMode, setEditor, setError, setValidation) {
  if (!selected?.editable) return;
  setEditingMode(true); setEditor(_editorFromPlaybook(selected)); setError(''); setValidation({ errors: [], warnings: [] });
}

function _cancelEditPlaybook(selected, setEditingMode, setEditor, setValidation) {
  setEditingMode(false); setValidation({ errors: [], warnings: [] });
  if (selected) setEditor(_editorFromPlaybook(selected));
}

async function _loadPlaybooksData({ selectedProject, setLoading, setPlaybooks, setRuns, setConnectors, setStepTemplates, setHosts, setCreds, setScopes, setPacks, setSelectedPlaybookId, setError }) {
  if (!selectedProject) return;
  setLoading(true);
  try {
    const [pb, runData, connectorData, templateData, hostData, credData, scopeData, packData] = await Promise.all([
      api.listPlaybooks(), api.listPlaybookRuns(selectedProject, { limit: 100 }),
      api.listConnectors().catch(() => ({ connectors: [] })), api.listPlaybookStepTemplates().catch(() => ({ templates: [] })),
      api.getHosts(selectedProject).catch(() => []), api.getCreds(selectedProject).catch(() => []),
      api.getScopes(selectedProject).catch(() => []), api.listOperationPacks().catch(() => ({ packs: [] })),
    ]);
    setPlaybooks(pb.playbooks || []); setRuns(runData.runs || []); setConnectors(connectorData.connectors || []);
    setStepTemplates(templateData.templates || []); setHosts(Array.isArray(hostData) ? hostData : []); setCreds(Array.isArray(credData) ? credData : []);
    setScopes(Array.isArray(scopeData) ? scopeData : []); setPacks(packData.packs || []);
    setSelectedPlaybookId(prev => prev || pb.playbooks?.[0]?.id || '');
  } catch (e) { setError(e.message || 'Failed to load playbooks'); } finally { setLoading(false); }
}

// ── Layout sub-components ────────────────────────────────────────────

function PlaybookStepList({ editor, setEditor, connectors, stepTemplates }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {editor.steps.map((step, idx) => (
        <StepEditor key={`step-${idx}-${step.title || step.operation}`} step={step} connectors={connectors} templates={stepTemplates} stepCount={editor.steps.length} stepIndex={idx} allSteps={editor.steps}
          onChange={(next) => setEditor(prev => ({ ...prev, steps: _updateStep(prev.steps, idx, next) }))}
          onDelete={() => setEditor(prev => ({ ...prev, steps: _deleteStep(prev.steps, idx) }))}
          onDuplicate={() => setEditor(prev => ({ ...prev, steps: _duplicateStep(prev.steps, idx) }))}
          onMoveUp={() => setEditor(prev => ({ ...prev, steps: _moveStep(prev.steps, idx, -1) }))}
          onMoveDown={() => setEditor(prev => ({ ...prev, steps: _moveStep(prev.steps, idx, 1) }))}
          disableDelete={editor.steps.length <= 1}
        />
      ))}
    </div>
  );
}

PlaybookStepList.propTypes = {
  editor: PropTypes.object,
  setEditor: PropTypes.func,
  connectors: PropTypes.array,
  stepTemplates: PropTypes.array,
};

function PlaybookEditorSection({ editor, setEditor, connectors, stepTemplates, savePlaybook, cancelEdit, saving, setShowPacksPanel, setShowSavePackModal, accent }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <input value={editor.title} onChange={e => setEditor(prev => ({ ...prev, title: e.target.value }))} placeholder="Playbook title" style={inp()} />
      <textarea value={editor.description} onChange={e => setEditor(prev => ({ ...prev, description: e.target.value }))} placeholder="Description" rows={3} style={{ ...inp(), resize: 'vertical' }} />
      <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 8, padding: '12px 14px' }}>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Step templates</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {stepTemplates.map(template => <button key={template.id} onClick={() => setEditor(prev => ({ ...prev, steps: [...prev.steps, buildStepFromTemplate(template)] }))} style={{ background: '#13161f', border: '1px solid #1e2230', borderRadius: 999, padding: '5px 10px', cursor: 'pointer', color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{template.title}</button>)}
        </div>
      </div>
      <DagPreview steps={editor.steps} accent={accent} />
      <PlaybookStepList editor={editor} setEditor={setEditor} connectors={connectors} stepTemplates={stepTemplates} />
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={() => setEditor(prev => ({ ...prev, steps: [...prev.steps, stepTemplates[0] ? buildStepFromTemplate(stepTemplates[0]) : emptyStep()] }))} style={toolbarBtn(accent, false)}>Add step</button>
        <button onClick={() => setShowPacksPanel(true)} style={toolbarBtn('#e8cc42', false)}>Packs</button>
        {editor.steps.length > 0 && <button onClick={() => setShowSavePackModal(true)} style={toolbarBtn('#c07af0', false)}>Save as pack</button>}
        <button onClick={savePlaybook} disabled={saving} style={toolbarBtn(accent, true)}>{saving ? 'Saving...' : 'Save playbook'}</button>
        <button onClick={cancelEdit} style={toolbarBtn('#808590', false)}>Cancel</button>
      </div>
    </div>
  );
}

PlaybookEditorSection.propTypes = {
  editor: PropTypes.object,
  setEditor: PropTypes.func,
  connectors: PropTypes.array,
  stepTemplates: PropTypes.array,
  savePlaybook: PropTypes.func,
  cancelEdit: PropTypes.func,
  saving: PropTypes.bool,
  setShowPacksPanel: PropTypes.func,
  setShowSavePackModal: PropTypes.func,
  accent: PropTypes.string,
};

function AuthSection({ form, setForm, creds, accent }) {
  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px' }}>
      <div style={{ fontSize: 9, color: '#404550', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span>Auth / AD credentials <span style={{ color: '#303540' }}>(optional)</span></span>
        <CredPicker accent={accent} creds={creds} onPick={c => setForm(prev => ({ ...prev, ..._credPickToForm(c) }))} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Domain</div><PickerInput value={form.domain || ''} onChange={v => setForm(prev => ({ ...prev, domain: v }))} placeholder="CORP" options={[...new Set(creds.filter(c => c.domain).map(c => c.domain))].map(d => ({ value: d }))} /></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Username</div><PickerInput value={form.username || ''} onChange={v => setForm(prev => ({ ...prev, username: v }))} placeholder="administrator" options={creds.map(c => ({ value: c.username.includes('\\') ? c.username.split('\\')[1] : c.username, label: c.domain ? `${c.domain} · ${c.type}` : c.type }))} /></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Password</div><input type="password" value={form.password || ''} onChange={e => setForm(prev => ({ ...prev, password: e.target.value }))} placeholder="••••••••" style={inp()} /></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>NTLM Hash</div><PickerInput value={form.hash || ''} onChange={v => setForm(prev => ({ ...prev, hash: v }))} placeholder="aad3b435b51404eeaad3b435b51404ee:..." options={creds.filter(c => c.type === 'hash' || c.type === 'ntlm').map(c => ({ value: c.secret || '', label: `${c.username} · ${c.type}` }))} /></div>
      </div>
    </div>
  );
}

AuthSection.propTypes = {
  form: PropTypes.object,
  setForm: PropTypes.func,
  creds: PropTypes.array,
  accent: PropTypes.string,
};

function RunModeTarget({ runMode, form, setForm, batchForm, setBatchForm, hosts, scopes, batchResult, accent }) {
  if (runMode === 'single') {
    return (
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Target</div><PickerInput value={form.target} onChange={v => setForm(prev => ({ ...prev, target: v }))} placeholder="x.x.x.x/24" options={_hostTargetOptions(hosts, scopes)} /></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Target URL</div><PickerInput value={form.target_url} onChange={v => setForm(prev => ({ ...prev, target_url: v }))} placeholder="https://target.example" options={_hostUrlOptions(hosts, scopes)} /></div>
      </div>
    );
  }
  return (
    <>
      <BatchHostSelector hosts={hosts} batchForm={batchForm} onChange={setBatchForm} accent={accent} />
      {batchResult && <div style={{ background: '#0a1a0a', border: '1px solid #39d35344', borderRadius: 6, padding: '8px 12px', fontSize: 11, color: '#39d353', fontFamily: 'JetBrains Mono' }}>Batch started: {batchResult.total} runs · id: {batchResult.batchId}</div>}
    </>
  );
}

RunModeTarget.propTypes = {
  runMode: PropTypes.string,
  form: PropTypes.object,
  setForm: PropTypes.func,
  batchForm: PropTypes.object,
  setBatchForm: PropTypes.func,
  hosts: PropTypes.array,
  scopes: PropTypes.array,
  batchResult: PropTypes.object,
  accent: PropTypes.string,
};

function RunActionButton({ runMode, running, runSelected, batchRunSelected, hostCountLabel, accent }) {
  if (runMode === 'single') {
    return <button onClick={runSelected} disabled={running} style={{ background: running ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '8px 16px', cursor: running ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{running ? 'Starting...' : 'Run playbook'}</button>;
  }
  return <button onClick={batchRunSelected} disabled={running} style={{ background: running ? '#1a1c22' : '#f09a3a', border: 'none', borderRadius: 5, padding: '8px 16px', cursor: running ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{running ? 'Starting...' : `Run on ${hostCountLabel} hosts`}</button>;
}

RunActionButton.propTypes = {
  runMode: PropTypes.string,
  running: PropTypes.bool,
  runSelected: PropTypes.func,
  batchRunSelected: PropTypes.func,
  hostCountLabel: PropTypes.string,
  accent: PropTypes.string,
};

function PlaybookRunnerSection({ selected, form, setForm, batchForm, setBatchForm, runMode, setRunMode, hosts, scopes, creds, runSelected, batchRunSelected, running, batchResult, accent }) {
  const hostCountLabel = batchForm.host_ids.length > 0 ? String(batchForm.host_ids.length) : 'filtered';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 8, padding: '12px 14px' }}>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Playbook steps</div>
        <StepFlowDiagram steps={selected.steps || []} accent={accent} />
      </div>
      <div style={{ display: 'flex', gap: 6 }}>
        {['single', 'batch'].map(mode => <button key={mode} onClick={() => setRunMode(mode)} style={{ background: runMode === mode ? accent + '33' : '#13161f', color: runMode === mode ? accent : '#6a7080', border: `1px solid ${runMode === mode ? accent + '66' : '#1e2230'}`, borderRadius: 4, padding: '3px 14px', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}>{mode === 'single' ? 'Single run' : 'Batch run'}</button>)}
      </div>
      <RunModeTarget runMode={runMode} form={form} setForm={setForm} batchForm={batchForm} setBatchForm={setBatchForm} hosts={hosts} scopes={scopes} batchResult={batchResult} accent={accent} />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Nmap flags</div><input value={form.flags} onChange={e => setForm(prev => ({ ...prev, flags: e.target.value }))} style={inp()} /></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Nuclei severity</div><input value={form.severity} onChange={e => setForm(prev => ({ ...prev, severity: e.target.value }))} style={inp()} /></div>
      </div>
      <AuthSection form={form} setForm={setForm} creds={creds} accent={accent} />
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button onClick={() => setForm(prev => ({ ...prev, keep_manual_positions: !prev.keep_manual_positions }))} style={toggleBtn(form.keep_manual_positions, accent)}>{form.keep_manual_positions ? 'Keep manual positions' : 'Ignore manual positions'}</button>
        <button onClick={() => setForm(prev => ({ ...prev, create_missing_networks: !prev.create_missing_networks }))} style={toggleBtn(form.create_missing_networks, accent)}>{form.create_missing_networks ? 'Create missing networks' : 'No auto-create'}</button>
      </div>
      <RunActionButton runMode={runMode} running={running} runSelected={runSelected} batchRunSelected={batchRunSelected} hostCountLabel={hostCountLabel} accent={accent} />
    </div>
  );
}

PlaybookRunnerSection.propTypes = {
  selected: PropTypes.object,
  form: PropTypes.object,
  setForm: PropTypes.func,
  batchForm: PropTypes.object,
  setBatchForm: PropTypes.func,
  runMode: PropTypes.string,
  setRunMode: PropTypes.func,
  hosts: PropTypes.array,
  scopes: PropTypes.array,
  creds: PropTypes.array,
  runSelected: PropTypes.func,
  batchRunSelected: PropTypes.func,
  running: PropTypes.bool,
  batchResult: PropTypes.object,
  accent: PropTypes.string,
};

function PlaybooksViewBody({ selectedProject, accent, onNavigate, playbooks, runs, connectors, stepTemplates, selectedPlaybookId, setSelectedPlaybookId, loading, running, saving, error, validation, editingMode, setEditingMode, editor, setEditor, form, setForm, expandedRunId, setExpandedRunId, runJobsCache, runMode, setRunMode, batchForm, setBatchForm, hosts, creds, scopes, batchResult, activeTab, setActiveTab, importing, packs, setPacks, showPacksPanel, setShowPacksPanel, showSavePackModal, setShowSavePackModal, selected, startEdit, cancelEdit, savePlaybook, deleteSelectedPlaybook, runSelected, batchRunSelected, cancelRun, rerun, exportPlaybooks, importPlaybooks, load }) {
  if (!selectedProject) return <div style={{ padding: 40, color: '#6a7080', textAlign: 'center' }}>Select a project to work with playbooks</div>;
  let headerTitle;
  if (editingMode) {
    headerTitle = selected?.editable ? 'Edit custom playbook' : 'Create custom playbook';
  } else {
    headerTitle = selected?.title || 'Select a playbook';
  }
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
            <button onClick={() => { setEditingMode(true); setSelectedPlaybookId(''); setEditor(emptyPlaybook()); }} style={toolbarBtn(accent, true)}>New custom playbook</button>
          </>}
        </div>
      </div>
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid #1e2029', paddingBottom: 0 }}>
        {[{ id: 'playbooks', label: 'Playbooks' }, { id: 'scheduled', label: 'Scheduled' }].map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{ background: 'transparent', border: 'none', borderBottom: activeTab === t.id ? `2px solid ${accent}` : '2px solid transparent', padding: '6px 14px', cursor: 'pointer', color: activeTab === t.id ? accent : '#606570', fontSize: 12, fontFamily: 'JetBrains Mono', marginBottom: -1 }}>{t.label}</button>
        ))}
      </div>
      {error && <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 12 }}>{error}</div>}
      {editingMode && validation.errors.length > 0 && <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 12, lineHeight: 1.6 }}>{validation.errors.map((item, idx) => <div key={`err-${idx}-${item}`}>{item}</div>)}</div>}
      {editingMode && validation.warnings.length > 0 && <div style={{ background: '#1a1408', border: '1px solid #4a3410', borderRadius: 6, padding: '10px 12px', color: '#f09a3a', fontSize: 12, lineHeight: 1.6 }}>{validation.warnings.map((item, idx) => <div key={`warn-${idx}-${item}`}>{item}</div>)}</div>}
      {activeTab === 'scheduled' && <ScheduledTab selectedProject={selectedProject} accent={accent} playbooks={playbooks} hosts={hosts} creds={creds} scopes={scopes} />}
      {activeTab === 'playbooks' && (
        <div style={{ display: 'grid', gridTemplateColumns: '320px minmax(0, 1fr)', gap: 18, minHeight: 0, alignItems: 'start' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, position: 'sticky', top: 0 }}>
            {(playbooks || []).map(playbook => <PlaybookCard key={playbook.id} playbook={playbook} accent={accent} selected={selectedPlaybookId === playbook.id && !editingMode} onSelect={(id) => { setSelectedPlaybookId(id); setEditingMode(false); }} />)}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, minWidth: 0 }}>
            <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, padding: 16, minHeight: 420 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 12 }}>
                <div>
                  <div style={{ fontSize: 14, color: '#e0e4ec', fontWeight: 600 }}>{headerTitle}</div>
                  {!editingMode && selected && <div style={{ fontSize: 10, color: '#606570', marginTop: 4, lineHeight: 1.55, maxWidth: 760 }}>{selected.description}</div>}
                </div>
                {!editingMode && selected?.editable && (
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={startEdit} style={toolbarBtn(accent, false)}>Edit</button>
                    <button onClick={deleteSelectedPlaybook} style={{ ...toolbarBtn('#cc2233', false), borderColor: '#cc223344', color: '#cc2233' }}>Delete</button>
                  </div>
                )}
              </div>
              {editingMode ? <PlaybookEditorSection editor={editor} setEditor={setEditor} connectors={connectors} stepTemplates={stepTemplates} savePlaybook={savePlaybook} cancelEdit={cancelEdit} saving={saving} setShowPacksPanel={setShowPacksPanel} setShowSavePackModal={setShowSavePackModal} accent={accent} />
                : (selected && <PlaybookRunnerSection selected={selected} form={form} setForm={setForm} batchForm={batchForm} setBatchForm={setBatchForm} runMode={runMode} setRunMode={setRunMode} hosts={hosts} scopes={scopes} creds={creds} runSelected={runSelected} batchRunSelected={batchRunSelected} running={running} batchResult={batchResult} accent={accent} />)}
            </div>
            <PlaybookRunsList runs={runs} loading={loading} accent={accent} expandedRunId={expandedRunId} setExpandedRunId={setExpandedRunId} runJobsCache={runJobsCache} playbooks={playbooks} cancelRun={cancelRun} rerun={rerun} onNavigate={onNavigate} />
          </div>
        </div>
      )}
      {showPacksPanel && (
        <>
          <PacksPanel packs={packs} accent={accent} onInsert={(pack) => { setEditor(prev => ({ ...prev, steps: [...prev.steps, ...(pack.steps || []).map(s => ({ ...s }))] })); setShowPacksPanel(false); }} onDelete={async (packId) => { await api.deleteOperationPack(packId).catch(() => {}); setPacks(prev => prev.filter(p => p.id !== packId)); }} onClose={() => setShowPacksPanel(false)} />
          {showSavePackModal && <SavePackModal steps={editor.steps} accent={accent} onClose={() => setShowSavePackModal(false)} onSaved={(pack) => setPacks(prev => [...prev, pack])} />}
        </>
      )}
    </div>
  );
}

PlaybooksViewBody.propTypes = {
  selectedProject: PropTypes.any,
  accent: PropTypes.string,
  onNavigate: PropTypes.func,
  playbooks: PropTypes.array,
  runs: PropTypes.array,
  connectors: PropTypes.array,
  stepTemplates: PropTypes.array,
  selectedPlaybookId: PropTypes.string,
  setSelectedPlaybookId: PropTypes.func,
  loading: PropTypes.bool,
  running: PropTypes.bool,
  saving: PropTypes.bool,
  error: PropTypes.string,
  validation: PropTypes.object,
  editingMode: PropTypes.bool,
  setEditingMode: PropTypes.func,
  editor: PropTypes.object,
  setEditor: PropTypes.func,
  form: PropTypes.object,
  setForm: PropTypes.func,
  expandedRunId: PropTypes.string,
  setExpandedRunId: PropTypes.func,
  runJobsCache: PropTypes.object,
  runMode: PropTypes.string,
  setRunMode: PropTypes.func,
  batchForm: PropTypes.object,
  setBatchForm: PropTypes.func,
  hosts: PropTypes.array,
  creds: PropTypes.array,
  scopes: PropTypes.array,
  batchResult: PropTypes.object,
  activeTab: PropTypes.string,
  setActiveTab: PropTypes.func,
  importing: PropTypes.bool,
  packs: PropTypes.array,
  setPacks: PropTypes.func,
  showPacksPanel: PropTypes.bool,
  setShowPacksPanel: PropTypes.func,
  showSavePackModal: PropTypes.bool,
  setShowSavePackModal: PropTypes.func,
  selected: PropTypes.object,
  startEdit: PropTypes.func,
  cancelEdit: PropTypes.func,
  savePlaybook: PropTypes.func,
  deleteSelectedPlaybook: PropTypes.func,
  runSelected: PropTypes.func,
  batchRunSelected: PropTypes.func,
  cancelRun: PropTypes.func,
  rerun: PropTypes.func,
  exportPlaybooks: PropTypes.func,
  importPlaybooks: PropTypes.func,
  load: PropTypes.func,
};

// ── Root component ───────────────────────────────────────────────────

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
  const [runJobsCache, setRunJobsCache] = useState({});
  const runPollRef = useRef(null);
  const [runMode, setRunMode] = useState('single');
  const [batchForm, setBatchForm] = useState({ host_ids: [], host_tags: [], host_status: '', parallelism: 3 });
  const [hosts, setHosts] = useState([]);
  const [creds, setCreds] = useState([]);
  const [scopes, setScopes] = useState([]);
  const [batchResult, setBatchResult] = useState(null);
  const [activeTab, setActiveTab] = useState('playbooks');
  const [importing, setImporting] = useState(false);
  const [packs, setPacks] = useState([]);
  const [showPacksPanel, setShowPacksPanel] = useState(false);
  const [showSavePackModal, setShowSavePackModal] = useState(false);

  useEffect(() => { _loadPlaybooksData({ selectedProject, setLoading, setPlaybooks, setRuns, setConnectors, setStepTemplates, setHosts, setCreds, setScopes, setPacks, setSelectedPlaybookId, setError }); }, [selectedProject]);
  useEffect(() => _setupPlaybookRunListener(setRuns), []);

  const selected = _findPlaybook(playbooks, selectedPlaybookId);

  useEffect(() => _setupRunPolling(expandedRunId, runs, runPollRef, selectedProject, setRunJobsCache), [expandedRunId, runs]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { _syncEditorFromSelected(selected, editingMode, setEditor); }, [selected, editingMode]);

  const _ctx = { editor, selected, setSelectedPlaybookId, setEditingMode, setEditor, setSaving, setError, setValidation, setRunning, setRuns, setBatchResult, setImporting, onNavigate, selectedProject, form, batchForm };

  const startEdit = () => _startEditPlaybook(selected, setEditingMode, setEditor, setError, setValidation);
  const cancelEdit = () => _cancelEditPlaybook(selected, setEditingMode, setEditor, setValidation);
  const savePlaybook = () => _doSavePlaybook(_ctx);
  const deleteSelectedPlaybook = () => _doDeletePlaybook(_ctx);
  const runSelected = () => _doRunPlaybook(_ctx);
  const batchRunSelected = () => _doBatchRun(_ctx);
  const cancelRun = (runId) => _doCancelRun(selectedProject, runId, setRuns, setError);
  const rerun = (runId) => _doRerun(selectedProject, runId, setRuns, setError);
  const exportPlaybooks = () => _doExportPlaybooks(setError);
  const load = () => _loadPlaybooksData({ selectedProject, setLoading, setPlaybooks, setRuns, setConnectors, setStepTemplates, setHosts, setCreds, setScopes, setPacks, setSelectedPlaybookId, setError });
  const importPlaybooks = (file) => _doImportPlaybooks(file, load, setImporting, setError);

  return <PlaybooksViewBody selectedProject={selectedProject} accent={accent} onNavigate={onNavigate} playbooks={playbooks} runs={runs} connectors={connectors} stepTemplates={stepTemplates} selectedPlaybookId={selectedPlaybookId} setSelectedPlaybookId={setSelectedPlaybookId} loading={loading} running={running} saving={saving} error={error} validation={validation} editingMode={editingMode} setEditingMode={setEditingMode} editor={editor} setEditor={setEditor} form={form} setForm={setForm} expandedRunId={expandedRunId} setExpandedRunId={setExpandedRunId} runJobsCache={runJobsCache} runMode={runMode} setRunMode={setRunMode} batchForm={batchForm} setBatchForm={setBatchForm} hosts={hosts} creds={creds} scopes={scopes} batchResult={batchResult} activeTab={activeTab} setActiveTab={setActiveTab} importing={importing} packs={packs} setPacks={setPacks} showPacksPanel={showPacksPanel} setShowPacksPanel={setShowPacksPanel} showSavePackModal={showSavePackModal} setShowSavePackModal={setShowSavePackModal} selected={selected} startEdit={startEdit} cancelEdit={cancelEdit} savePlaybook={savePlaybook} deleteSelectedPlaybook={deleteSelectedPlaybook} runSelected={runSelected} batchRunSelected={batchRunSelected} cancelRun={cancelRun} rerun={rerun} exportPlaybooks={exportPlaybooks} importPlaybooks={importPlaybooks} load={load} />;
}

PlaybooksView.propTypes = {
  selectedProject: PropTypes.any,
  accent: PropTypes.string.isRequired,
  onNavigate: PropTypes.func,
};
