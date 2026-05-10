import { useState, useEffect } from 'react';
import { api } from '../api.js';
import Icon from './Icon.jsx';

const FILTER_PRESETS = [
  { label: 'Windows hosts',     filters: { os_contains: 'windows', exclude_attacker: true } },
  { label: 'Linux hosts',       filters: { os_contains: 'linux', exclude_attacker: true } },
  { label: 'With C2 agent',     filters: { has_c2: true, exclude_attacker: true } },
  { label: 'Domain joined',     filters: { tags: ['domain'], tags_mode: 'any', exclude_attacker: true } },
  { label: 'Domain controllers',filters: { role: ['dc'], exclude_attacker: true } },
  { label: 'Alive hosts',       filters: { status: ['alive'], exclude_attacker: true } },
  { label: 'Compromised',       filters: { status: ['access', 'pwned', 'owned'], exclude_attacker: true } },
];

const STATUS_OPTIONS = ['alive', 'unknown', 'access', 'pwned', 'owned', 'dead'];
const ROLE_OPTIONS = ['unknown', 'workstation', 'server', 'dc', 'router', 'firewall', 'printer', 'iot'];

function FilterEditor({ value, onChange, accent }) {
  const f = value;
  const set = (k, v) => onChange({ ...f, [k]: v });

  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none', boxSizing: 'border-box' };
  const lbl = { fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4, display: 'block' };
  const chip = (val, arr, key) => (
    <span key={val} onClick={() => set(key, arr.filter(x => x !== val))}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 3, padding: '2px 7px', fontSize: 10, color: accent, cursor: 'pointer', fontFamily: 'JetBrains Mono' }}>
      {val} ×
    </span>
  );

  const [tagInput, setTagInput] = useState('');
  const [portInput, setPortInput] = useState('');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Tags */}
      <div>
        <span style={lbl}>Tags (host must match)</span>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
          {(f.tags || []).map(t => chip(t, f.tags || [], 'tags'))}
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input value={tagInput} onChange={e => setTagInput(e.target.value)}
            onKeyDown={e => { if ((e.key === 'Enter' || e.key === ',') && tagInput.trim()) { set('tags', [...(f.tags || []), tagInput.trim()]); setTagInput(''); e.preventDefault(); } }}
            placeholder="type tag + Enter" style={{ ...inp, flex: 1 }} />
          <select value={f.tags_mode || 'any'} onChange={e => set('tags_mode', e.target.value)}
            style={{ ...inp, width: 60 }}>
            <option value="any">any</option>
            <option value="all">all</option>
          </select>
        </div>
      </div>

      {/* Status */}
      <div>
        <span style={lbl}>Status</span>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {STATUS_OPTIONS.map(s => {
            const active = (f.status || []).includes(s);
            return (
              <button key={s} onClick={() => set('status', active ? (f.status || []).filter(x => x !== s) : [...(f.status || []), s])}
                style={{ background: active ? accent + '22' : 'transparent', border: `1px solid ${active ? accent + '66' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: active ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                {s}
              </button>
            );
          })}
        </div>
      </div>

      {/* Role */}
      <div>
        <span style={lbl}>Role</span>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {ROLE_OPTIONS.map(r => {
            const active = (f.role || []).includes(r);
            return (
              <button key={r} onClick={() => set('role', active ? (f.role || []).filter(x => x !== r) : [...(f.role || []), r])}
                style={{ background: active ? accent + '22' : 'transparent', border: `1px solid ${active ? accent + '66' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: active ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                {r}
              </button>
            );
          })}
        </div>
      </div>

      {/* OS / Domain / Subnet */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
        <div>
          <span style={lbl}>OS contains</span>
          <input value={f.os_contains || ''} onChange={e => set('os_contains', e.target.value)} placeholder="windows" style={inp} />
        </div>
        <div>
          <span style={lbl}>Domain contains</span>
          <input value={f.domain_contains || ''} onChange={e => set('domain_contains', e.target.value)} placeholder="corp.local" style={inp} />
        </div>
        <div>
          <span style={lbl}>Subnet (CIDR)</span>
          <input value={f.subnet || ''} onChange={e => set('subnet', e.target.value)} placeholder="10.0.0.0/24" style={inp} />
        </div>
      </div>

      {/* Ports */}
      <div>
        <span style={lbl}>Open ports (any of)</span>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
          {(f.ports_open || []).map(p => chip(p, f.ports_open || [], 'ports_open'))}
        </div>
        <input value={portInput} onChange={e => setPortInput(e.target.value)}
          onKeyDown={e => { if ((e.key === 'Enter' || e.key === ',') && portInput.trim()) { set('ports_open', [...(f.ports_open || []), portInput.trim()]); setPortInput(''); e.preventDefault(); } }}
          placeholder="445, 22, 3389 — type + Enter" style={inp} />
      </div>

      {/* C2 + exclude_attacker */}
      <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          <input type="checkbox" checked={f.exclude_attacker !== false} onChange={e => set('exclude_attacker', e.target.checked)} />
          <span style={{ fontSize: 11, color: '#9098a8' }}>Exclude attacker hosts</span>
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          <input type="checkbox" checked={f.has_c2 === true} onChange={e => set('has_c2', e.target.checked ? true : null)} />
          <span style={{ fontSize: 11, color: '#9098a8' }}>Must have C2 agent</span>
        </label>
      </div>
    </div>
  );
}

function PreviewBadge({ count, loading, accent }) {
  if (loading) return <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>…</span>;
  return (
    <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: count > 0 ? accent : '#606570' }}>
      {count} host{count !== 1 ? 's' : ''}
    </span>
  );
}

// ── Main CollectionSelector ──────────────────────────────────────────

export default function CollectionSelector({ pid, accent, onSelect, selectedIds = [], onClear }) {
  const [collections, setCollections] = useState([]);
  const [showPanel, setShowPanel] = useState(false);
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState(null);

  // form state
  const [name, setName] = useState('');
  const [color, setColor] = useState('#4f8ef7');
  const [filters, setFilters] = useState({ exclude_attacker: true, tags: [], status: [], role: [], ports_open: [] });
  const [preview, setPreview] = useState({ count: 0, hosts: [] });
  const [previewLoading, setPreviewLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    if (pid) loadCollections();
  }, [pid]);

  const loadCollections = () =>
    api.listCollections(pid).then(setCollections).catch(() => {});

  const runPreview = async (f) => {
    setPreviewLoading(true);
    try {
      const r = await api.previewCollection(pid, f);
      setPreview(r);
    } catch { setPreview({ count: 0, hosts: [] }); }
    finally { setPreviewLoading(false); }
  };

  useEffect(() => {
    if (showPanel && creating) {
      const t = setTimeout(() => runPreview(filters), 400);
      return () => clearTimeout(t);
    }
  }, [filters, showPanel, creating]);

  const startCreate = () => {
    setCreating(true); setEditingId(null); setMsg('');
    setName(''); setColor('#4f8ef7');
    setFilters({ exclude_attacker: true, tags: [], status: [], role: [], ports_open: [] });
    setPreview({ count: 0, hosts: [] });
  };

  const startEdit = (coll) => {
    setEditingId(coll.id); setCreating(false); setMsg('');
    setName(coll.name); setColor(coll.color || '#4f8ef7');
    setFilters(coll.filters || {});
    runPreview(coll.filters || {});
  };

  const saveCollection = async () => {
    if (!name.trim()) { setMsg('Name is required'); return; }
    setSaving(true); setMsg('');
    try {
      if (editingId) {
        await api.updateCollection(pid, editingId, { name, color, filters });
      } else {
        await api.createCollection(pid, { name, color, filters });
      }
      await loadCollections();
      setCreating(false); setEditingId(null);
    } catch (e) { setMsg(e.message || 'Save failed'); }
    finally { setSaving(false); }
  };

  const deleteCollection = async (id) => {
    try { await api.deleteCollection(pid, id); await loadCollections(); } catch {}
  };

  const applyCollection = async (coll) => {
    try {
      const r = await api.resolveCollection(pid, coll.id);
      onSelect(r.host_ids, coll.name);
      setShowPanel(false);
    } catch {}
  };

  const applyPreset = async (preset) => {
    setCreating(true);
    setName(preset.label);
    setFilters({ exclude_attacker: true, tags: [], status: [], role: [], ports_open: [], ...preset.filters });
    runPreview({ exclude_attacker: true, tags: [], status: [], role: [], ports_open: [], ...preset.filters });
  };

  const btnStyle = (active) => ({
    background: active ? accent + '22' : 'transparent',
    border: `1px solid ${active ? accent + '66' : '#2a2d35'}`,
    borderRadius: 4, padding: '5px 10px', cursor: 'pointer',
    color: active ? accent : '#606570', fontSize: 11,
    fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5,
  });

  return (
    <div style={{ position: 'relative' }}>
      <button onClick={() => setShowPanel(v => !v)} style={btnStyle(showPanel || selectedIds.length > 0)}>
        <Icon name="database" size={12} color={showPanel ? accent : '#606570'} />
        Collections
        {selectedIds.length > 0 && (
          <span style={{ background: accent, color: '#fff', borderRadius: '50%', width: 16, height: 16, fontSize: 9, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {selectedIds.length > 99 ? '99+' : selectedIds.length}
          </span>
        )}
      </button>

      {showPanel && (
        <div style={{ position: 'absolute', top: '100%', left: 0, zIndex: 200, marginTop: 4, background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 8, width: 520, maxHeight: '80vh', overflowY: 'auto', boxShadow: '0 8px 40px #00000099' }}>
          <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec' }}>Host Collections</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={startCreate} style={{ ...btnStyle(creating), padding: '3px 10px', fontSize: 10 }}>+ New</button>
              <button onClick={() => setShowPanel(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#606570' }}>✕</button>
            </div>
          </div>

          {/* Saved collections list */}
          {!creating && !editingId && (
            <div style={{ padding: '8px 0' }}>
              {collections.length === 0 && (
                <div style={{ padding: '16px 14px', fontSize: 11, color: '#505560', textAlign: 'center' }}>
                  No collections yet. Create one or pick a preset.
                </div>
              )}
              {collections.map(c => (
                <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px', borderBottom: '1px solid #1a1c22' }}>
                  <span style={{ width: 10, height: 10, borderRadius: '50%', background: c.color, flexShrink: 0 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, color: '#c8cdd6', fontWeight: 500 }}>{c.name}</div>
                    {c.description && <div style={{ fontSize: 10, color: '#505560' }}>{c.description}</div>}
                  </div>
                  <button onClick={() => applyCollection(c)} style={{ ...btnStyle(false), padding: '3px 10px', fontSize: 10, color: accent, borderColor: accent + '44' }}>
                    Select
                  </button>
                  <button onClick={() => startEdit(c)} style={{ ...btnStyle(false), padding: '3px 8px', fontSize: 10 }}>Edit</button>
                  <button onClick={() => deleteCollection(c.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#605060', fontSize: 10, padding: '3px 6px' }}>✕</button>
                </div>
              ))}

              {/* Presets */}
              <div style={{ padding: '10px 14px 4px', fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Quick presets</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, padding: '4px 14px 12px' }}>
                {FILTER_PRESETS.map(p => (
                  <button key={p.label} onClick={() => applyPreset(p)}
                    style={{ ...btnStyle(false), padding: '3px 10px', fontSize: 10 }}>
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Create / Edit form */}
          {(creating || editingId) && (
            <div style={{ padding: 14 }}>
              <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
                <input value={color} type="color" onChange={e => setColor(e.target.value)}
                  style={{ width: 36, height: 28, border: 'none', background: 'none', cursor: 'pointer', padding: 0 }} />
                <input value={name} onChange={e => setName(e.target.value)} placeholder="Collection name"
                  style={{ flex: 1, background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#e0e4ec', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono' }} />
              </div>

              <FilterEditor value={filters} onChange={f => { setFilters(f); runPreview(f); }} accent={accent} />

              <div style={{ marginTop: 12, padding: '8px 10px', background: '#0a0c10', borderRadius: 4, border: '1px solid #1e2029', fontSize: 11, color: '#9098a8' }}>
                Preview: <PreviewBadge count={preview.count} loading={previewLoading} accent={accent} />
                {preview.hosts && preview.hosts.length > 0 && (
                  <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {preview.hosts.slice(0, 8).map(h => (
                      <span key={h.id} style={{ fontSize: 9, fontFamily: 'JetBrains Mono', color: '#606570', background: '#1a1c22', padding: '2px 6px', borderRadius: 3 }}>
                        {h.ip}{h.hostname ? ` (${h.hostname})` : ''}
                      </span>
                    ))}
                    {preview.hosts.length > 8 && <span style={{ fontSize: 9, color: '#404550' }}>+{preview.hosts.length - 8} more</span>}
                  </div>
                )}
              </div>

              {msg && <div style={{ marginTop: 8, fontSize: 11, color: '#f87171' }}>{msg}</div>}

              <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                <button onClick={saveCollection} disabled={saving}
                  style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                  {saving ? 'Saving…' : editingId ? 'Update' : 'Save'}
                </button>
                {preview.count > 0 && !editingId && (
                  <button onClick={() => { onSelect(preview.hosts.map(h => h.id), name || 'Unsaved filter'); setShowPanel(false); }}
                    style={{ ...btnStyle(true), color: accent }}>
                    Use without saving ({preview.count})
                  </button>
                )}
                <button onClick={() => { setCreating(false); setEditingId(null); }}
                  style={{ ...btnStyle(false), color: '#606570' }}>
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
