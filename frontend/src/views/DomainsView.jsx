import { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';

function inp() {
  return { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };
}
function btn(color, solid) {
  return { background: solid ? color : 'transparent', color: solid ? '#fff' : color, border: solid ? 'none' : `1px solid ${color}44`, borderRadius: 5, padding: '6px 12px', cursor: 'pointer', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 };
}

const EMPTY = { name: '', aliases: '', notes: '' };

export default function DomainsView({ selectedProject, accent }) {
  const [domains, setDomains] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [form, setForm] = useState(EMPTY);
  const [showAdd, setShowAdd] = useState(false);
  const [editing, setEditing] = useState(null); // domain id being edited
  const [editForm, setEditForm] = useState(EMPTY);
  const [saving, setSaving] = useState(false);
  const [search, setSearch] = useState('');

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    try {
      const data = await api.listDomains(selectedProject);
      setDomains(Array.isArray(data) ? data : []);
    } catch (e) {
      setError(e.message || 'Failed to load domains');
    } finally {
      setLoading(false);
    }
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  const add = async () => {
    if (!form.name.trim()) { setError('Domain name is required'); return; }
    setSaving(true);
    setError('');
    try {
      const created = await api.createDomain({
        pid: selectedProject,
        name: form.name.trim(),
        aliases: form.aliases.split(',').map(a => a.trim()).filter(Boolean),
        notes: form.notes.trim(),
      });
      setDomains(prev => [...prev, created]);
      setForm(EMPTY);
      setShowAdd(false);
    } catch (e) {
      setError(e.message || 'Failed to create domain');
    } finally {
      setSaving(false);
    }
  };

  const save = async (id) => {
    setSaving(true);
    setError('');
    try {
      const updated = await api.updateDomain(id, {
        name: editForm.name.trim(),
        aliases: editForm.aliases.split(',').map(a => a.trim()).filter(Boolean),
        notes: editForm.notes.trim(),
      });
      setDomains(prev => prev.map(d => d.id === id ? updated : d));
      setEditing(null);
    } catch (e) {
      setError(e.message || 'Failed to update domain');
    } finally {
      setSaving(false);
    }
  };

  const del = async (id) => {
    if (!window.confirm('Delete this domain?')) return;
    try {
      await api.deleteDomain(id);
      setDomains(prev => prev.filter(d => d.id !== id));
    } catch (e) {
      setError(e.message || 'Failed to delete domain');
    }
  };

  const startEdit = (domain) => {
    setEditing(domain.id);
    setEditForm({ name: domain.name, aliases: (domain.aliases || []).join(', '), notes: domain.notes || '' });
    setError('');
  };

  const filtered = domains.filter(d =>
    !search || d.name.toLowerCase().includes(search.toLowerCase()) ||
    (d.aliases || []).some(a => a.toLowerCase().includes(search.toLowerCase())) ||
    (d.notes || '').toLowerCase().includes(search.toLowerCase())
  );

  if (!selectedProject) return <div style={{ padding: 40, color: '#6a7080', textAlign: 'center' }}>Select a project</div>;

  return (
    <div style={{ padding: '20px 24px', height: '100%', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ color: '#c8cfe0', margin: 0, fontSize: 18 }}>Domain Inventory</h2>
          <div style={{ fontSize: 11, color: '#6a7080', marginTop: 4 }}>Track domains, subdomains, and aliases per project</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={load} style={btn(accent, false)}>Refresh</button>
          <button onClick={() => { setShowAdd(true); setError(''); }} style={btn(accent, true)}>+ Add domain</button>
        </div>
      </div>

      {error && <div style={{ background: '#1a0808', border: '1px solid #3a1010', borderRadius: 6, padding: '10px 12px', color: '#f87171', fontSize: 12 }}>{error}</div>}

      {showAdd && (
        <div style={{ background: '#0d0f14', border: `1px solid ${accent}44`, borderRadius: 10, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: 11, color: accent, fontWeight: 600 }}>New Domain</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: '#606570', marginBottom: 4 }}>Domain name *</div>
              <input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="example.com" style={inp()} autoFocus />
            </div>
            <div>
              <div style={{ fontSize: 10, color: '#606570', marginBottom: 4 }}>Aliases <span style={{ color: '#404550' }}>(comma-separated)</span></div>
              <input value={form.aliases} onChange={e => setForm(p => ({ ...p, aliases: e.target.value }))} placeholder="sub1.example.com, sub2.example.com" style={inp()} />
            </div>
          </div>
          <div>
            <div style={{ fontSize: 10, color: '#606570', marginBottom: 4 }}>Notes</div>
            <textarea value={form.notes} onChange={e => setForm(p => ({ ...p, notes: e.target.value }))} placeholder="Purpose, owner, tech stack..." rows={2} style={{ ...inp(), resize: 'vertical' }} />
          </div>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button onClick={() => { setShowAdd(false); setForm(EMPTY); }} style={btn('#808590', false)}>Cancel</button>
            <button onClick={add} disabled={saving} style={btn(accent, true)}>{saving ? 'Adding…' : 'Add'}</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 10 }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search domains…" style={{ ...inp(), maxWidth: 300, flex: 'none' }} />
        <div style={{ fontSize: 11, color: '#505560', alignSelf: 'center' }}>{filtered.length} / {domains.length}</div>
      </div>

      {loading ? (
        <div style={{ color: '#505560', fontSize: 12, padding: '20px 0', textAlign: 'center' }}>Loading…</div>
      ) : filtered.length === 0 ? (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, padding: '30px 0', textAlign: 'center', color: '#505560', fontSize: 12 }}>
          {domains.length === 0 ? 'No domains yet. Add your first domain above.' : 'No results for current search.'}
        </div>
      ) : (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '8px 16px', borderBottom: '1px solid #1e2029', background: '#090b0f', display: 'grid', gridTemplateColumns: '2fr 2fr 2fr auto', gap: 12, fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            <div>Domain</div><div>Aliases</div><div>Notes</div><div />
          </div>
          {filtered.map((d, i) => (
            <div key={d.id} style={{ borderBottom: i < filtered.length - 1 ? '1px solid #14161b' : 'none' }}>
              {editing === d.id ? (
                <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                    <div>
                      <div style={{ fontSize: 10, color: '#606570', marginBottom: 3 }}>Domain</div>
                      <input value={editForm.name} onChange={e => setEditForm(p => ({ ...p, name: e.target.value }))} style={inp()} autoFocus />
                    </div>
                    <div>
                      <div style={{ fontSize: 10, color: '#606570', marginBottom: 3 }}>Aliases</div>
                      <input value={editForm.aliases} onChange={e => setEditForm(p => ({ ...p, aliases: e.target.value }))} placeholder="sub1.example.com, sub2.example.com" style={inp()} />
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: '#606570', marginBottom: 3 }}>Notes</div>
                    <textarea value={editForm.notes} onChange={e => setEditForm(p => ({ ...p, notes: e.target.value }))} rows={2} style={{ ...inp(), resize: 'vertical' }} />
                  </div>
                  <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                    <button onClick={() => setEditing(null)} style={btn('#808590', false)}>Cancel</button>
                    <button onClick={() => save(d.id)} disabled={saving} style={btn(accent, true)}>{saving ? 'Saving…' : 'Save'}</button>
                  </div>
                </div>
              ) : (
                <div style={{ padding: '10px 16px', display: 'grid', gridTemplateColumns: '2fr 2fr 2fr auto', gap: 12, alignItems: 'start' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#ffffff03'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <div>
                    <div style={{ fontSize: 12, color: accent, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{d.name}</div>
                    <div style={{ fontSize: 9, color: '#404550', marginTop: 2 }}>{d.created_at?.slice(0, 16)}</div>
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {(d.aliases || []).map(a => (
                      <span key={a} style={{ fontSize: 10, color: '#c8cdd6', background: '#13161f', border: '1px solid #1e2230', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{a}</span>
                    ))}
                    {(d.aliases || []).length === 0 && <span style={{ fontSize: 10, color: '#404550' }}>—</span>}
                  </div>
                  <div style={{ fontSize: 11, color: '#808590', lineHeight: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{d.notes || '—'}</div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button onClick={() => startEdit(d)} style={{ ...btn(accent, false), padding: '4px 10px', fontSize: 10 }}>Edit</button>
                    <button onClick={() => del(d.id)} style={{ ...btn('#cc2233', false), padding: '4px 10px', fontSize: 10 }}>Del</button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
