import { useState, useRef } from 'react';
import Icon from '../components/Icon.jsx';
import { FieldInput } from '../components/UI.jsx';
import { OS_ICONS } from '../constants.js';
import { api } from '../api.js';

const sEl = (val, opts, onChange, style = {}) => (
  <select value={val} onChange={e => onChange(e.target.value)}
    style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', width: '100%', ...style }}>
    {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
  </select>
);

export default function ProjectsView({ projects, notes, hosts, creds, selectedProject, onSelect, accent, onAdd, onUpdate, onDelete, onImport, onProjectImported }) {
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ name: '', ip: '', os: 'Linux', status: 'active', description: '' });
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [editId, setEditId] = useState(null);
  const [editForm, setEditForm] = useState({});
  const [exportingId, setExportingId] = useState(null);
  const [importing, setImporting] = useState(false);
  const importFileRef = useRef();

  const handleExport = async (e, pid, pname) => {
    e.stopPropagation();
    setExportingId(pid);
    try {
      const blob = await api.exportProject(pid);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${pname.replace(/[^a-zA-Z0-9_-]/g, '_')}_export.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Export error: ' + err.message);
    } finally {
      setExportingId(null);
    }
  };

  const handleImportFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';
    setImporting(true);
    try {
      const result = await api.importProject(file);
      onProjectImported?.(result);
    } catch (err) {
      alert('Import error: ' + err.message);
    } finally {
      setImporting(false);
    }
  };

  const stats = pid => ({
    notes: notes.filter(n => n.pid === pid).length,
    hosts: hosts.filter(h => h.pid === pid).length,
    creds: creds.filter(c => c.pid === pid).length,
    pwned: hosts.filter(h => h.pid === pid && (h.status === 'pwned' || h.status === 'owned')).length,
  });
  const statusColor = { active: '#39d353', paused: '#f09a3a', done: '#555' };

  const handleAdd = () => {
    if (!form.name.trim()) return;
    onAdd({ ...form, added: new Date().toISOString().slice(0, 10) });
    setForm({ name: '', ip: '', os: 'Linux', status: 'active', description: '' });
    setShowAdd(false);
  };

  const startEdit = (p) => {
    setEditId(p.id);
    setEditForm({ name: p.name, ip: p.ip, os: p.os, status: p.status, description: p.description });
  };
  const saveEdit = () => {
    onUpdate(editId, editForm);
    setEditId(null);
  };

  const inp = (label, key, placeholder, textarea = false) => (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 9, color: '#505560', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '.1em' }}>{label}</div>
      {textarea
        ? <textarea value={editForm[key] || ''} onChange={e => setEditForm(f => ({ ...f, [key]: e.target.value }))} rows={3} placeholder={placeholder}
            style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical' }} />
        : <input value={editForm[key] || ''} onChange={e => setEditForm(f => ({ ...f, [key]: e.target.value }))} placeholder={placeholder}
            style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }} />}
    </div>
  );

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {/* Left: project grid */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>

        {/* Confirm delete */}
        {confirmDelete && (() => {
          const proj = projects.find(p => p.id === confirmDelete);
          const s = stats(confirmDelete);
          return (
            <div style={{ position: 'fixed', inset: 0, zIndex: 400, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
              onClick={e => e.target === e.currentTarget && setConfirmDelete(null)}>
              <div style={{ background: '#0e1016', border: '1px solid #cc233344', borderRadius: 10, padding: 28, width: 400, boxShadow: '0 20px 60px #00000099' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                  <div style={{ width: 36, height: 36, borderRadius: '50%', background: '#cc233318', border: '1px solid #cc233344', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <Icon name="trash" size={16} color="#cc2233" />
                  </div>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Delete project?</div>
                    <div style={{ fontSize: 11, color: '#606570', marginTop: 2 }}>«{proj?.name}»</div>
                  </div>
                </div>
                <div style={{ background: '#cc233311', border: '1px solid #cc233333', borderRadius: 6, padding: '10px 14px', marginBottom: 20, fontSize: 11, color: '#cc2233', lineHeight: 1.6 }}>
                  Will delete: {s.notes} notes, {s.hosts} hosts, {s.creds} credentials. This action is irreversible.
                </div>
                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                  <button onClick={() => setConfirmDelete(null)}
                    style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 6, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
                  <button onClick={() => { onDelete(confirmDelete); setConfirmDelete(null); if (editId === confirmDelete) setEditId(null); }}
                    style={{ background: '#cc2233', border: 'none', borderRadius: 6, padding: '7px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Icon name="trash" size={11} color="#fff" /> Delete
                  </button>
                </div>
              </div>
            </div>
          );
        })()}

        <div style={{ marginBottom: 20, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 4 }}>Projects</h1>
            <p style={{ fontSize: 11, color: '#505560' }}>{projects.length} engagements active</p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <label title="Import project from ZIP"
              style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 14px', cursor: importing ? 'wait' : 'pointer', color: importing ? '#606570' : '#808590', fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, opacity: importing ? 0.6 : 1, transition: 'all .12s' }}
              onMouseEnter={e => { if (!importing) { e.currentTarget.style.borderColor = accent; e.currentTarget.style.color = accent; } }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = importing ? '#606570' : '#808590'; }}>
              <Icon name="export" size={11} color="currentColor" />
              {importing ? 'Importing...' : 'Import ZIP'}
              <input ref={importFileRef} type="file" accept=".zip" style={{ display: 'none' }} onChange={handleImportFile} disabled={importing} />
            </label>
            <button onClick={() => setShowAdd(v => !v)}
              style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="plus" size={11} color="#fff" /> New project
            </button>
          </div>
        </div>

        {showAdd && (
          <div style={{ background: '#0d0f14', border: `1px solid ${accent}44`, borderRadius: 8, padding: 18, marginBottom: 18, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              {[['Name', 'name', '200px'], ['IP / CIDR', 'ip', '160px']].map(([l, k, w]) => (
                <div key={k} style={{ width: w }}>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>{l}</div>
                  <input value={form[k]} onChange={e => setForm(f => ({ ...f, [k]: e.target.value }))}
                    onKeyDown={e => e.key === 'Enter' && handleAdd()}
                    style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }} />
                </div>
              ))}
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>OS</div>
                <select value={form.os} onChange={e => setForm(f => ({ ...f, os: e.target.value }))}
                  style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
                  {['Linux', 'Windows', 'macOS', 'Various', 'Unknown'].map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Status</div>
                <select value={form.status} onChange={e => setForm(f => ({ ...f, status: e.target.value }))}
                  style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
                  {[['active', 'Active'], ['paused', 'Paused'], ['done', 'Done']].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Description</div>
              <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} rows={2}
                style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical' }} />
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={handleAdd} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>Create</button>
              <button onClick={() => setShowAdd(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
            </div>
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(300px,1fr))', gap: 14 }}>
          {projects.map(p => {
            const s = stats(p.id);
            const isActive = p.id === selectedProject;
            const isEdit = p.id === editId;
            const sc = statusColor[p.status] || '#555';
            return (
              <div key={p.id}
                style={{ background: isActive ? '#12141a' : '#0d0f14', border: `1px solid ${isEdit ? accent + '88' : isActive ? accent + '44' : '#1e2029'}`, borderRadius: 8, padding: 18, transition: 'all .15s', position: 'relative', overflow: 'hidden' }}>
                {isActive && !isEdit && <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg,${accent},${accent}00)` }} />}

                {isEdit ? (
                  /* ── Edit mode ── */
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 600, color: accent, fontFamily: 'Space Grotesk', marginBottom: 12 }}>Editing</div>
                    {inp('Name', 'name', 'Corp VPN Breach')}
                    {inp('IP / CIDR', 'ip', '10.10.0.0/24')}
                    {inp('Description', 'description', 'Target description...', true)}
                    <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 9, color: '#505560', marginBottom: 4, textTransform: 'uppercase' }}>OS</div>
                        {sEl(editForm.os, [['Linux','Linux'],['Windows','Windows'],['macOS','macOS'],['Various','Various'],['Unknown','Unknown']], v => setEditForm(f => ({ ...f, os: v })))}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 9, color: '#505560', marginBottom: 4, textTransform: 'uppercase' }}>Status</div>
                        {sEl(editForm.status, [['active','Active'],['paused','Paused'],['done','Done']], v => setEditForm(f => ({ ...f, status: v })))}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button onClick={saveEdit} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', flex: 1 }}>Save</button>
                      <button onClick={() => setEditId(null)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
                    </div>
                  </div>
                ) : (
                  /* ── View mode ── */
                  <div onClick={() => onSelect(p.id)} style={{ cursor: 'pointer' }}
                    onMouseEnter={e => { if (!isActive) { e.currentTarget.parentElement.style.borderColor = '#2a2d35'; e.currentTarget.parentElement.style.background = '#0f1116'; } }}
                    onMouseLeave={e => { if (!isActive) { e.currentTarget.parentElement.style.borderColor = '#1e2029'; e.currentTarget.parentElement.style.background = '#0d0f14'; } }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 14, fontWeight: 600, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.name}</div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 9, color: sc, background: `${sc}18`, border: `1px solid ${sc}44`, borderRadius: 3, padding: '1px 7px', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600 }}>
                            <span style={{ width: 5, height: 5, borderRadius: '50%', background: sc, boxShadow: `0 0 4px ${sc}` }} />
                            {p.status === 'active' ? 'Active' : p.status === 'paused' ? 'Paused' : 'Done'}
                          </span>
                          <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono' }}>{OS_ICONS[p.os] || '?'} {p.os}</span>
                        </div>
                      </div>
                      {/* Action buttons */}
                      <div style={{ display: 'flex', gap: 3, marginLeft: 8, flexShrink: 0 }} onClick={e => e.stopPropagation()}>
                        <button onClick={() => onImport(p.id)} title="Import scan"
                          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 7px', cursor: 'pointer', color: '#404550', display: 'flex', alignItems: 'center', gap: 3, fontSize: 9, fontFamily: 'JetBrains Mono', transition: 'all .12s' }}
                          onMouseEnter={e => { e.currentTarget.style.borderColor = accent; e.currentTarget.style.color = accent; }}
                          onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                          <Icon name="export" size={10} color="currentColor" /> Import
                        </button>
                        <button onClick={e => handleExport(e, p.id, p.name)} title="Export project to ZIP"
                          disabled={exportingId === p.id}
                          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 7px', cursor: exportingId === p.id ? 'wait' : 'pointer', color: '#404550', display: 'flex', alignItems: 'center', gap: 3, fontSize: 9, fontFamily: 'JetBrains Mono', transition: 'all .12s', opacity: exportingId === p.id ? 0.5 : 1 }}
                          onMouseEnter={e => { if (exportingId !== p.id) { e.currentTarget.style.borderColor = '#39d353'; e.currentTarget.style.color = '#39d353'; } }}
                          onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                          <Icon name="export" size={10} color="currentColor" /> {exportingId === p.id ? '...' : 'ZIP'}
                        </button>
                        <button onClick={() => startEdit(p)} title="Edit"
                          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#404550', display: 'flex', transition: 'all .12s' }}
                          onMouseEnter={e => { e.currentTarget.style.borderColor = '#5b8af5'; e.currentTarget.style.color = '#5b8af5'; }}
                          onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                          <Icon name="edit" size={11} color="currentColor" />
                        </button>
                        <button onClick={() => setConfirmDelete(p.id)} title="Delete"
                          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#404550', display: 'flex', transition: 'all .12s' }}
                          onMouseEnter={e => { e.currentTarget.style.borderColor = '#cc2233'; e.currentTarget.style.color = '#cc2233'; }}
                          onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                          <Icon name="trash" size={11} color="currentColor" />
                        </button>
                      </div>
                    </div>
                    <div style={{ fontSize: 10, color: '#606570', marginBottom: 12, lineHeight: 1.5 }}>{p.description}</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12 }}>
                      <Icon name="target" size={10} color="#404550" />
                      <span style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono' }}>{p.ip || '—'}</span>
                      <span style={{ fontSize: 9, color: '#303540', marginLeft: 'auto', fontFamily: 'JetBrains Mono' }}>{p.added}</span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 8, borderTop: '1px solid #1e2029', paddingTop: 12 }}>
                      {[['notes', 'Notes', s.notes, '#6fc8f0'], ['hosts', 'Hosts', s.hosts, '#c07af0'], ['creds', 'Creds', s.creds, '#39d353'], ['target', 'Pwned', s.pwned, '#cc2233']].map(([icon, label, val, c]) => (
                        <div key={label} style={{ textAlign: 'center' }}>
                          <div style={{ fontSize: 18, fontWeight: 700, color: val > 0 ? c : '#303540', fontFamily: 'Space Grotesk' }}>{val}</div>
                          <div style={{ fontSize: 9, color: '#404550', marginTop: 2 }}>{label}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
