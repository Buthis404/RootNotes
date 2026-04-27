import { useState } from 'react';
import Icon from '../components/Icon.jsx';
import { OBJECTIVE_CATEGORY, OBJECTIVE_STATUS } from '../constants.js';

const CAT_OPTS = [
  { value: 'flag',      label: '🚩 Flag' },
  { value: 'bas',       label: '💼 BAS' },
  { value: 'objective', label: '🎯 Objective' },
];

const STATUS_OPTS = [
  { value: 'not_started', label: 'Not Started' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'captured',    label: 'Captured' },
  { value: 'submitted',   label: 'Submitted' },
];

const INP = { background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none', width: '100%' };

function ObjectiveForm({ initial, hosts, pid, accent, onSave, onClose }) {
  const [form, setForm] = useState(initial || { title: '', description: '', category: 'flag', points: 0, status: 'not_started', flag_value: '', host_id: '' });
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const save = () => {
    if (!form.title.trim()) return;
    onSave({ ...form, pid, points: Number(form.points) || 0 });
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, padding: '28px 32px', width: 500, boxShadow: '0 24px 64px #00000099' }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 20 }}>
          {initial?.id ? 'Edit Objective' : 'New Objective'}
        </div>

        <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Category</div>
            <select value={form.category} onChange={e => set('category', e.target.value)} style={{ ...INP, cursor: 'pointer' }}>
              {CAT_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <div style={{ width: 90 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Points</div>
            <input type="number" value={form.points} onChange={e => set('points', e.target.value)} style={INP} min={0} />
          </div>
        </div>

        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Title *</div>
          <input value={form.title} onChange={e => set('title', e.target.value)} style={INP} placeholder="Flag capture / Domain compromise / ..." autoFocus />
        </div>

        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Status</div>
          <select value={form.status} onChange={e => set('status', e.target.value)} style={{ ...INP, cursor: 'pointer' }}>
            {STATUS_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>

        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Flag value</div>
          <input value={form.flag_value} onChange={e => set('flag_value', e.target.value)} style={{ ...INP, fontFamily: 'JetBrains Mono', letterSpacing: '0.05em' }} placeholder="flag{...}" />
        </div>

        <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Host</div>
            <select value={form.host_id || ''} onChange={e => set('host_id', e.target.value || null)} style={{ ...INP, cursor: 'pointer' }}>
              <option value="">— Not linked —</option>
              {hosts.filter(h => h.pid === pid).map(h => (
                <option key={h.id} value={h.id}>{h.ip}{h.hostname ? ` (${h.hostname})` : ''}</option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Description / condition</div>
          <textarea value={form.description} onChange={e => set('description', e.target.value)}
            style={{ ...INP, resize: 'vertical', minHeight: 80, lineHeight: 1.6 }}
            placeholder="Completion conditions, path to flag, details..." />
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
          <button onClick={save} disabled={!form.title.trim()}
            style={{ background: form.title.trim() ? accent : '#2a2d35', border: 'none', borderRadius: 5, padding: '7px 18px', cursor: form.title.trim() ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ObjectivesView({ objectives, hosts, onAdd, onUpdate, onDelete, selectedProject, accent, currentUser }) {
  const [form, setForm] = useState(null);
  const [filterStatus, setFilterStatus] = useState(null);
  const [filterCat, setFilterCat] = useState(null);
  const [captureConfirm, setCaptureConfirm] = useState(null);

  const proj = objectives.filter(o => o.pid === selectedProject);

  const filtered = proj.filter(o =>
    (!filterStatus || o.status === filterStatus) &&
    (!filterCat    || o.category === filterCat)
  );

  const totalPoints  = proj.filter(o => o.status === 'captured' || o.status === 'submitted').reduce((s, o) => s + (o.points || 0), 0);
  const maxPoints    = proj.reduce((s, o) => s + (o.points || 0), 0);
  const capturedCnt  = proj.filter(o => o.status === 'captured' || o.status === 'submitted').length;
  const submittedCnt = proj.filter(o => o.status === 'submitted').length;
  const inProgressCnt= proj.filter(o => o.status === 'in_progress').length;

  const handleSave = async (data) => {
    if (data.id) {
      await onUpdate(data.id, data);
    } else {
      await onAdd(data);
    }
    setForm(null);
  };

  const doCapture = async (obj) => {
    await onUpdate(obj.id, {
      status: 'captured',
      captured_by: currentUser?.username || '',
      captured_at: new Date().toLocaleString('en'),
    });
    setCaptureConfirm(null);
  };

  const cycleStatus = async (obj) => {
    const order = ['not_started', 'in_progress', 'captured', 'submitted'];
    const next = order[(order.indexOf(obj.status) + 1) % order.length];
    if (next === 'captured') { setCaptureConfirm(obj); return; }
    await onUpdate(obj.id, {
      status: next,
      ...(next === 'captured' ? { captured_by: currentUser?.username || '', captured_at: new Date().toLocaleString('en') } : {}),
    });
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {form && (
        <ObjectiveForm initial={form === true ? null : form} hosts={hosts} pid={selectedProject}
          accent={accent} onSave={handleSave} onClose={() => setForm(null)} />
      )}

      {/* Capture confirm */}
      {captureConfirm && (
        <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
          <div style={{ background: '#0e1016', border: `1px solid ${accent}44`, borderRadius: 12, padding: '28px 36px', width: 400, textAlign: 'center', boxShadow: '0 24px 64px #00000099' }}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>🚩</div>
            <div style={{ fontSize: 15, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 8 }}>Target Captured!</div>
            <div style={{ fontSize: 12, color: '#808590', marginBottom: 6 }}>{captureConfirm.title}</div>
            {captureConfirm.points > 0 && (
              <div style={{ fontSize: 22, fontWeight: 700, color: accent, fontFamily: 'Space Grotesk', marginBottom: 18 }}>+{captureConfirm.points} pts</div>
            )}
            <div style={{ display: 'flex', gap: 10, justifyContent: 'center' }}>
              <button onClick={() => setCaptureConfirm(null)} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
              <button onClick={() => doCapture(captureConfirm)} style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 22px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>Capture!</button>
            </div>
          </div>
        </div>
      )}

      {/* Stats bar */}
      <div style={{ padding: '14px 24px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 24, flexShrink: 0, flexWrap: 'wrap' }}>
        {[
          ['Total', proj.length, '#808590'],
          ['In Progress', inProgressCnt, '#f09a3a'],
          ['Captured', capturedCnt, '#cc2233'],
          ['Submitted', submittedCnt, '#39d353'],
        ].map(([l, v, c]) => (
          <div key={l} style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: v > 0 ? c : '#303540', fontFamily: 'Space Grotesk' }}>{v}</div>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{l}</div>
          </div>
        ))}
        <div style={{ flex: 1 }} />
        {maxPoints > 0 && (
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 22, fontWeight: 700, color: accent, fontFamily: 'Space Grotesk' }}>{totalPoints} / {maxPoints}</div>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Points</div>
          </div>
        )}
        <button onClick={() => setForm(true)}
          style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Icon name="plus" size={11} color="#fff" /> Add
        </button>
      </div>

      {/* Filters */}
      <div style={{ padding: '10px 24px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', gap: 6, flexWrap: 'wrap', flexShrink: 0 }}>
        <button onClick={() => setFilterStatus(null)}
          style={{ background: !filterStatus ? accent + '22' : 'transparent', border: `1px solid ${!filterStatus ? accent + '66' : '#2a2d35'}`, borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: !filterStatus ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          All
        </button>
        {STATUS_OPTS.map(s => {
          const st = OBJECTIVE_STATUS[s.value];
          const active = filterStatus === s.value;
          return (
            <button key={s.value} onClick={() => setFilterStatus(active ? null : s.value)}
              style={{ background: active ? st.color + '22' : 'transparent', border: `1px solid ${active ? st.color + '66' : '#2a2d35'}`, borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: active ? st.color : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {s.label} ({proj.filter(o => o.status === s.value).length})
            </button>
          );
        })}
        <div style={{ width: 1, background: '#2a2d35', margin: '0 4px' }} />
        {CAT_OPTS.map(c => {
          const active = filterCat === c.value;
          const cat = OBJECTIVE_CATEGORY[c.value];
          return (
            <button key={c.value} onClick={() => setFilterCat(active ? null : c.value)}
              style={{ background: active ? cat.color + '22' : 'transparent', border: `1px solid ${active ? cat.color + '66' : '#2a2d35'}`, borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: active ? cat.color : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {c.label}
            </button>
          );
        })}
      </div>

      {/* Objectives list */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 24px' }}>
        {filtered.length === 0 && (
          <div style={{ textAlign: 'center', padding: '60px 0', color: '#303540' }}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>🎯</div>
            <div style={{ fontSize: 13, marginBottom: 6 }}>No objectives</div>
            <div style={{ fontSize: 11, color: '#252830' }}>Add flags and objectives for this project</div>
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 10 }}>
          {filtered.map(obj => {
            const st = OBJECTIVE_STATUS[obj.status] || OBJECTIVE_STATUS.not_started;
            const cat = OBJECTIVE_CATEGORY[obj.category] || OBJECTIVE_CATEGORY.flag;
            const linkedHost = hosts.find(h => h.id === obj.host_id);
            const isCaptured = obj.status === 'captured' || obj.status === 'submitted';

            return (
              <div key={obj.id}
                style={{ background: isCaptured ? `${st.color}0a` : '#0d0f14', border: `1px solid ${isCaptured ? st.color + '44' : '#1e2029'}`, borderRadius: 10, padding: '14px 16px', position: 'relative', transition: 'border-color .15s' }}
                onMouseEnter={e => !isCaptured && (e.currentTarget.style.borderColor = '#2a2d35')}
                onMouseLeave={e => !isCaptured && (e.currentTarget.style.borderColor = '#1e2029')}>

                {/* Header */}
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 8 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                      <span style={{ fontSize: 9, color: cat.color, background: cat.color + '18', border: `1px solid ${cat.color}44`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>
                        {cat.label}
                      </span>
                      {obj.points > 0 && (
                        <span style={{ fontSize: 9, color: accent, background: accent + '18', border: `1px solid ${accent}44`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
                          {obj.points} pts
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 13, fontWeight: 600, color: isCaptured ? st.color : '#e0e4ec', fontFamily: 'Space Grotesk', lineHeight: 1.3 }}>{obj.title}</div>
                  </div>

                  <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                    <button onClick={() => setForm(obj)} title="Edit"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 3, display: 'flex' }}>
                      <Icon name="edit" size={12} color="#404550" />
                    </button>
                    <button onClick={() => onDelete(obj.id)} title="Delete"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 3, display: 'flex' }}>
                      <Icon name="trash" size={12} color="#404550" />
                    </button>
                  </div>
                </div>

                {/* Description */}
                {obj.description && (
                  <div style={{ fontSize: 11, color: '#606570', lineHeight: 1.5, marginBottom: 8, overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>
                    {obj.description}
                  </div>
                )}

                {/* Flag value */}
                {obj.flag_value && (
                  <div style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: accent, background: accent + '11', border: `1px solid ${accent}33`, borderRadius: 4, padding: '4px 8px', marginBottom: 8, wordBreak: 'break-all' }}>
                    {obj.flag_value}
                  </div>
                )}

                {/* Meta row */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                  {linkedHost && (
                    <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: 'JetBrains Mono' }}>{linkedHost.ip}</span>
                  )}
                  {obj.captured_by && (
                    <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>by {obj.captured_by}</span>
                  )}
                  {obj.captured_at && (
                    <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>{obj.captured_at}</span>
                  )}
                </div>

                {/* Status + action row */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <button onClick={() => cycleStatus(obj)}
                    style={{ flex: 1, padding: '5px 10px', border: `1px solid ${st.color}55`, borderRadius: 5, background: st.color + '15', cursor: 'pointer', color: st.color, fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, textAlign: 'center', transition: 'all .15s' }}>
                    {st.label} →
                  </button>
                  {!isCaptured && (
                    <button onClick={() => setCaptureConfirm(obj)}
                      style={{ background: '#cc2233', border: 'none', borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 700, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
                      <Icon name="flag" size={10} color="#fff" /> Capture
                    </button>
                  )}
                  {obj.status === 'captured' && (
                    <button onClick={() => onUpdate(obj.id, { status: 'submitted' })}
                      style={{ background: '#39d353', border: 'none', borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
                      Submit
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
