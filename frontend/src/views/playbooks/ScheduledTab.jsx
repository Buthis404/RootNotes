import React, { useState, useRef, useEffect } from 'react';
import PropTypes from 'prop-types';
import { api } from '../../api.js';
import { inp, toolbarBtn, CRON_PRESETS } from './utils.js';

function PickerInput({ value, onChange, placeholder, options, type = 'text' }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  React.useEffect(() => {
    if (!open) {
      return;
    }
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <div style={{ display: 'flex', gap: 0 }}>
        <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
          style={{ ...inp(), borderRadius: options?.length ? '5px 0 0 5px' : 5, flex: 1 }} />
        {options?.length > 0 && (
          <button onClick={() => setOpen(v => !v)} style={{ background: open ? '#1e2230' : '#13161f', border: '1px solid #2a2d35', borderLeft: 'none', borderRadius: '0 5px 5px 0', padding: '0 8px', cursor: 'pointer', color: '#606570', fontSize: 10, flexShrink: 0 }}>▾</button>
        )}
      </div>
      {open && options?.length > 0 && (
        <div style={{ position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 100, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, marginTop: 2, maxHeight: 220, overflowY: 'auto', boxShadow: '0 8px 24px #00000099' }}>
          {options.map((opt, i) => (
            <button type="button" key={opt.value || i} onClick={() => { onChange(opt.value); setOpen(false); }}
              style={{ padding: '7px 12px', cursor: 'pointer', borderBottom: i < options.length - 1 ? '1px solid #1a1c22' : 'none', width: '100%', textAlign: 'left', background: 'transparent', borderTop: 'none', borderLeft: 'none', borderRight: 'none', outline: 'none', color: 'inherit', font: 'inherit' }}
              onMouseEnter={e => e.currentTarget.style.background = '#ffffff08'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <div style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>{opt.value}</div>
              {opt.label && <div style={{ fontSize: 9, color: '#505560', marginTop: 1 }}>{opt.label}</div>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
PickerInput.propTypes = { value: PropTypes.any, onChange: PropTypes.any, placeholder: PropTypes.any, options: PropTypes.any, type: PropTypes.any };

function CredPicker({ creds, onPick, accent }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  React.useEffect(() => {
    if (!open) {
      return;
    }
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);
  if (!creds?.length) {
    return null;
  }
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button onClick={() => setOpen(v => !v)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '5px 10px', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>From creds ▾</button>
      {open && (
        <div style={{ position: 'absolute', top: '100%', right: 0, zIndex: 100, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, marginTop: 2, minWidth: 280, maxHeight: 280, overflowY: 'auto', boxShadow: '0 8px 24px #00000099' }}>
          {creds.map((c, i) => (
            <button type="button" key={c.id} onClick={() => { onPick(c); setOpen(false); }}
              style={{ padding: '8px 12px', cursor: 'pointer', borderBottom: i < creds.length - 1 ? '1px solid #1a1c22' : 'none', width: '100%', textAlign: 'left', background: 'transparent', borderTop: 'none', borderLeft: 'none', borderRight: 'none', outline: 'none', color: 'inherit', font: 'inherit' }}
              onMouseEnter={e => e.currentTarget.style.background = '#ffffff08'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <div style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{c.domain ? `${c.domain}\\` : ''}{c.username}</div>
              <div style={{ fontSize: 9, color: '#505560', marginTop: 1, display: 'flex', gap: 8 }}>
                <span style={{ color: c.type === 'hash' || c.type === 'ntlm' ? '#c07af0' : '#5b8af5' }}>{c.type}</span>
                {c.service && <span>{c.service}</span>}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
CredPicker.propTypes = { creds: PropTypes.any, onPick: PropTypes.any, accent: PropTypes.any };

export default function ScheduledTab({ selectedProject, accent, playbooks, hosts, creds, scopes }) {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [form, setForm] = useState({ playbook_id: '', title: '', cron_expr: '0 * * * *', enabled: true, body_json: {} });
  const [creating, setCreating] = useState(false);
  const [saving, setSaving] = useState(false);

  const load = async () => {
    if (!selectedProject) {
      return;
    }
    setLoading(true);
    try {
      const data = await api.listSchedules(selectedProject);
      setSchedules(Array.isArray(data) ? data : []);
    } catch (e) {
      setError(e.message || 'Failed to load schedules');
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); }, [selectedProject]);

  const save = async () => {
    if (!form.playbook_id) { setError('Select a playbook'); return; }
    setSaving(true); setError('');
    try {
      const data = await api.createSchedule({ ...form, pid: selectedProject });
      setSchedules(prev => [data, ...prev]);
      setCreating(false);
      setForm({ playbook_id: '', title: '', cron_expr: '0 * * * *', enabled: true, body_json: {} });
    } catch (e) {
      setError(e.message || 'Failed to create schedule');
    } finally {
      setSaving(false);
    }
  };

  const toggle = async (sched) => {
    try {
      const updated = await api.updateSchedule(sched.id, { enabled: !sched.enabled });
      setSchedules(prev => prev.map(s => s.id === sched.id ? updated : s));
    } catch (e) { setError(e.message); }
  };

  const del = async (id) => {
    if (!globalThis.confirm('Delete schedule?')) {
      return;
    }
    try { await api.deleteSchedule(id); setSchedules(prev => prev.filter(s => s.id !== id)); }
    catch (e) { setError(e.message); }
  };

  const trigger = async (id) => {
    try { await api.triggerSchedule(id); } catch (e) { setError(e.message); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ fontSize: 13, color: '#c8cfe0', fontWeight: 600 }}>Scheduled Playbooks</div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={load} style={toolbarBtn(accent, false)}>Refresh</button>
          <button onClick={() => { setCreating(true); setError(''); }} style={toolbarBtn(accent, true)}>New schedule</button>
        </div>
      </div>
      {error && <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '8px 12px', color: '#f87171', fontSize: 12 }}>{error}</div>}

      {creating && (
        <div style={{ background: '#0d0f14', border: `1px solid ${accent}44`, borderRadius: 10, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: 11, color: accent, fontWeight: 600, marginBottom: 4 }}>New Schedule</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: '#606570', marginBottom: 4 }}>Playbook</div>
              <select value={form.playbook_id} onChange={e => setForm(p => ({ ...p, playbook_id: e.target.value }))} style={{ ...inp(), width: '100%' }}>
                <option value="">Select playbook…</option>
                {playbooks.map(pb => <option key={pb.id} value={pb.id}>{pb.title}</option>)}
              </select>
            </div>
            <div>
              <div style={{ fontSize: 10, color: '#606570', marginBottom: 4 }}>Label</div>
              <input value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))} placeholder="Optional label" style={inp()} />
            </div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: '#606570', marginBottom: 4 }}>Cron expression <span style={{ color: '#404550' }}>minute hour dom month dow</span></div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input value={form.cron_expr} onChange={e => setForm(p => ({ ...p, cron_expr: e.target.value }))} placeholder="0 * * * *" style={{ ...inp(), flex: 1 }} />
              <div style={{ display: 'flex', gap: 4 }}>
                {CRON_PRESETS.map(p => (
                  <button key={p.value} onClick={() => setForm(prev => ({ ...prev, cron_expr: p.value }))} style={{ ...toolbarBtn(accent, form.cron_expr === p.value), fontSize: 10, padding: '4px 8px' }}>{p.label}</button>
                ))}
              </div>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: '#606570', marginBottom: 4 }}>Target</div>
              <PickerInput value={form.body_json?.target || ''} onChange={v => setForm(p => ({ ...p, body_json: { ...p.body_json, target: v } }))} placeholder="x.x.x.x/24"
                options={[...(hosts || []).filter(h => !h.is_attacker).map(h => ({ value: h.ip, label: h.hostname || '' })), ...(scopes || []).filter(s => s.in_scope && ['cidr','hostname'].includes(s.scope_type)).map(s => ({ value: s.value, label: 'scope' }))]} />
            </div>
            <div>
              <div style={{ fontSize: 10, color: '#606570', marginBottom: 4 }}>Target URL</div>
              <PickerInput value={form.body_json?.target_url || ''} onChange={v => setForm(p => ({ ...p, body_json: { ...p.body_json, target_url: v } }))} placeholder="https://example.com"
                options={[...(hosts || []).filter(h => !h.is_attacker && h.tags?.includes('web')).map(h => ({ value: `https://${h.hostname || h.ip}`, label: h.hostname || h.ip })), ...(scopes || []).filter(s => s.in_scope && s.scope_type === 'url').map(s => ({ value: s.value, label: 'scope' }))]} />
            </div>
          </div>
          <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px' }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span>Auth / AD credentials <span style={{ color: '#303540' }}>(optional)</span></span>
              <CredPicker accent={accent} creds={creds || []} onPick={c => setForm(p => ({ ...p, body_json: { ...p.body_json, username: c.username.includes('\\') ? c.username.split('\\')[1] : c.username, domain: c.domain || (c.username.includes('\\') ? c.username.split('\\')[0] : ''), password: (c.type === 'plain' || c.type === 'token') ? (c.secret || '') : '', hash: (c.type === 'hash' || c.type === 'ntlm') ? (c.secret || '') : '' } }))} />
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Domain</div>
                <PickerInput value={form.body_json?.domain || ''} onChange={v => setForm(p => ({ ...p, body_json: { ...p.body_json, domain: v } }))} placeholder="CORP" options={[...new Set((creds || []).filter(c => c.domain).map(c => c.domain))].map(d => ({ value: d }))} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Username</div>
                <PickerInput value={form.body_json?.username || ''} onChange={v => setForm(p => ({ ...p, body_json: { ...p.body_json, username: v } }))} placeholder="administrator" options={(creds || []).map(c => ({ value: c.username.includes('\\') ? c.username.split('\\')[1] : c.username, label: c.domain || c.type }))} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Password</div>
                <input type="password" value={form.body_json?.password || ''} onChange={e => setForm(p => ({ ...p, body_json: { ...p.body_json, password: e.target.value } }))} placeholder="••••••••" style={inp()} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>NTLM Hash</div>
                <PickerInput value={form.body_json?.hash || ''} onChange={v => setForm(p => ({ ...p, body_json: { ...p.body_json, hash: v } }))} placeholder="aad3b435..." options={(creds || []).filter(c => c.type === 'hash' || c.type === 'ntlm').map(c => ({ value: c.secret || '', label: c.username }))} />
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button onClick={() => setCreating(false)} style={toolbarBtn('#808590', false)}>Cancel</button>
            <button onClick={save} disabled={saving} style={toolbarBtn(accent, true)}>{saving ? 'Saving…' : 'Create'}</button>
          </div>
        </div>
      )}

      {(() => {
        if (loading) {
          return <div style={{ color: '#505560', fontSize: 12 }}>Loading…</div>;
        }
        if (schedules.length === 0) {
          return (
            <div style={{ color: '#505560', fontSize: 12, padding: '20px 0', textAlign: 'center' }}>No scheduled playbooks. Create one to automate execution.</div>
          );
        }
        return (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
          {schedules.map((sched, i) => (
            <div key={sched.id} style={{ padding: '12px 16px', borderBottom: i < schedules.length - 1 ? '1px solid #14161b' : 'none', display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                  <span style={{ fontSize: 12, color: '#c8cdd6', fontWeight: 600 }}>{sched.title || playbooks.find(p => p.id === sched.playbook_id)?.title || sched.playbook_id}</span>
                  <span style={{ fontSize: 9, color: sched.enabled ? '#39d353' : '#606570', background: sched.enabled ? '#39d35318' : '#13161f', border: `1px solid ${sched.enabled ? '#39d35333' : '#1e2230'}`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{sched.enabled ? 'active' : 'paused'}</span>
                </div>
                <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono', display: 'flex', gap: 14, flexWrap: 'wrap' }}>
                  <span style={{ color: '#808590' }}>{sched.cron_expr}</span>
                  {sched.body_json?.target && <span>target: {sched.body_json.target}</span>}
                  {sched.body_json?.username && <span>user: {sched.body_json.domain ? `${sched.body_json.domain}\\` : ''}{sched.body_json.username}</span>}
                  {sched.next_run_at && <span>next: {sched.next_run_at.slice(0, 16)}</span>}
                  {sched.last_run_at && <span>last: {sched.last_run_at.slice(0, 16)}</span>}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button onClick={() => trigger(sched.id)} style={{ ...toolbarBtn(accent, false), padding: '4px 10px', fontSize: 10 }}>▶ Run now</button>
                <button onClick={() => toggle(sched)} style={{ ...toolbarBtn(sched.enabled ? '#f09a3a' : '#39d353', false), padding: '4px 10px', fontSize: 10 }}>{sched.enabled ? 'Pause' : 'Enable'}</button>
                <button onClick={() => del(sched.id)} style={{ ...toolbarBtn('#cc2233', false), padding: '4px 10px', fontSize: 10 }}>Delete</button>
              </div>
             </div>
           ))}
         </div>
      ); })()}
    </div>
  );
}
ScheduledTab.propTypes = { selectedProject: PropTypes.any, accent: PropTypes.any, playbooks: PropTypes.any, hosts: PropTypes.any, creds: PropTypes.any, scopes: PropTypes.any };
