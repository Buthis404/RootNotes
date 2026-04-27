import { useState, useEffect, useRef } from 'react';
import Icon from '../components/Icon.jsx';

const NODE_TYPES = {
  external: { label: 'External',  color: '#808590', icon: 'globe'  },
  host:     { label: 'Host',      color: '#5b8af5', icon: 'server' },
  dc:       { label: 'DC',        color: '#c07af0', icon: 'shield' },
  user:     { label: 'User',      color: '#f09a3a', icon: 'person' },
  pivot:    { label: 'Pivot',     color: '#e8cc42', icon: 'link'   },
  goal:     { label: 'Goal',      color: '#39d353', icon: 'target' },
};

const EMPTY_STEP = { node_type: 'host', label: '', sublabel: '', technique: '', mitre_id: '', notes: '' };

// ── Step edit modal ───────────────────────────────────────────────────
function StepModal({ step, isNew, onSave, onClose, accent }) {
  const [form, setForm] = useState(step ? { ...step } : { ...EMPTY_STEP });
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
  const inp = (k, placeholder, multiline) => {
    const s = { width: '100%', background: '#07080b', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#d0d4dc', fontSize: 12, fontFamily: multiline ? 'JetBrains Mono' : 'inherit', outline: 'none', resize: multiline ? 'vertical' : 'none', boxSizing: 'border-box' };
    return multiline
      ? <textarea value={form[k]} onChange={e => set(k, e.target.value)} placeholder={placeholder} rows={3} style={s} />
      : <input value={form[k]} onChange={e => set(k, e.target.value)} placeholder={placeholder} style={s} />;
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, width: 520, maxHeight: '88vh', overflow: 'auto', boxShadow: '0 24px 64px #00000099' }}>
        <div style={{ padding: '16px 22px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Icon name="attackpath" size={15} color={accent} />
          <span style={{ fontSize: 13, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', flex: 1 }}>
            {isNew ? 'Add step' : 'Edit step'}
          </span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
            <Icon name="close" size={13} color="#606570" />
          </button>
        </div>

        <div style={{ padding: '18px 22px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Node type */}
          <div>
            <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Node type</div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {Object.entries(NODE_TYPES).map(([k, t]) => {
                const active = form.node_type === k;
                return (
                  <button key={k} onClick={() => set('node_type', k)}
                    style={{ padding: '5px 12px', borderRadius: 5, border: `1px solid ${active ? t.color : '#2a2d35'}`, background: active ? t.color + '22' : 'transparent', color: active ? t.color : '#606570', cursor: 'pointer', fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5, transition: 'all .12s' }}>
                    <Icon name={t.icon} size={11} color={active ? t.color : '#606570'} />
                    {t.label}
                  </button>
                );
              })}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Label (IP / hostname / user)</div>
              {inp('label', 'e.g. 10.10.10.1')}
            </div>
            <div>
              <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Sublabel (OS / role)</div>
              {inp('sublabel', 'e.g. Windows DC')}
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Technique (how accessed)</div>
              {inp('technique', 'e.g. Kerberoasting')}
            </div>
            <div>
              <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>MITRE ID</div>
              {inp('mitre_id', 'e.g. T1558.003')}
            </div>
          </div>

          <div>
            <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Notes</div>
            {inp('notes', 'Additional context...', true)}
          </div>
        </div>

        <div style={{ padding: '12px 22px', borderTop: '1px solid #1e2029', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
          <button onClick={() => onSave(form)} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
            {isNew ? 'Add' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Connector arrow between nodes ─────────────────────────────────────
function Connector({ technique, mitre_id }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', width: 90, flexShrink: 0, gap: 3, position: 'relative' }}>
      {technique && (
        <div style={{ fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono', textAlign: 'center', maxWidth: 85, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{technique}</div>
      )}
      <svg width="90" height="18" viewBox="0 0 90 18" fill="none">
        <line x1="4" y1="9" x2="78" y2="9" stroke="#2a2d35" strokeWidth="1.5"/>
        <polyline points="70,4 80,9 70,14" stroke="#2a2d35" strokeWidth="1.5" fill="none" strokeLinejoin="round"/>
      </svg>
      {mitre_id && (
        <div style={{ fontSize: 8, color: '#404550', fontFamily: 'JetBrains Mono', textAlign: 'center' }}>{mitre_id}</div>
      )}
    </div>
  );
}

// ── Single node card ──────────────────────────────────────────────────
function NodeCard({ step, onEdit, onDelete, onMoveLeft, onMoveRight, canLeft, canRight, accent }) {
  const [hov, setHov] = useState(false);
  const t = NODE_TYPES[step.node_type] || NODE_TYPES.host;

  return (
    <div onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{ position: 'relative', width: 140, flexShrink: 0 }}>
      <div style={{ background: hov ? '#13151c' : '#0e1016', border: `1px solid ${hov ? t.color + '66' : '#1e2029'}`, borderRadius: 10, padding: '12px 10px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, cursor: 'pointer', transition: 'all .15s', height: 110, justifyContent: 'center' }}
        onClick={() => onEdit(step)}>
        <div style={{ width: 34, height: 34, borderRadius: 8, background: t.color + '18', border: `1px solid ${t.color}44`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Icon name={t.icon} size={16} color={t.color} />
        </div>
        <div style={{ fontSize: 11, fontWeight: 600, color: '#d0d4dc', textAlign: 'center', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: step.label.match(/^\d/) ? 'JetBrains Mono' : 'inherit' }}>
          {step.label || '—'}
        </div>
        {step.sublabel && (
          <div style={{ fontSize: 9, color: '#606570', textAlign: 'center', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {step.sublabel}
          </div>
        )}
        <span style={{ fontSize: 8, color: t.color, background: t.color + '18', border: `1px solid ${t.color}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          {t.label}
        </span>
      </div>

      {/* Action buttons on hover */}
      {hov && (
        <div style={{ position: 'absolute', top: -12, left: '50%', transform: 'translateX(-50%)', display: 'flex', gap: 3, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, padding: '2px 4px' }}>
          <button onClick={() => onMoveLeft(step)} disabled={!canLeft}
            style={{ background: 'none', border: 'none', cursor: canLeft ? 'pointer' : 'default', opacity: canLeft ? 1 : 0.3, display: 'flex', padding: '2px 3px' }}>
            <svg width="10" height="10" viewBox="0 0 16 16" fill="none" stroke="#808590" strokeWidth="2"><polyline points="10,4 6,8 10,12"/></svg>
          </button>
          <button onClick={() => onEdit(step)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', padding: '2px 3px' }}>
            <Icon name="edit" size={10} color={accent} />
          </button>
          <button onClick={() => onDelete(step.id)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', padding: '2px 3px' }}>
            <Icon name="trash" size={10} color="#cc2233" />
          </button>
          <button onClick={() => onMoveRight(step)} disabled={!canRight}
            style={{ background: 'none', border: 'none', cursor: canRight ? 'pointer' : 'default', opacity: canRight ? 1 : 0.3, display: 'flex', padding: '2px 3px' }}>
            <svg width="10" height="10" viewBox="0 0 16 16" fill="none" stroke="#808590" strokeWidth="2"><polyline points="6,4 10,8 6,12"/></svg>
          </button>
        </div>
      )}
    </div>
  );
}

// ── Path name inline editor ───────────────────────────────────────────
function PathNameEditor({ path, onSave }) {
  const [editing, setEditing] = useState(false);
  const [val, setVal] = useState(path.name);
  const ref = useRef();

  useEffect(() => { setVal(path.name); }, [path.name]);

  const commit = () => {
    setEditing(false);
    if (val.trim() && val !== path.name) onSave(val.trim());
  };

  if (editing) return (
    <input ref={ref} value={val} onChange={e => setVal(e.target.value)}
      onBlur={commit} onKeyDown={e => { if (e.key === 'Enter') commit(); if (e.key === 'Escape') setEditing(false); }}
      autoFocus
      style={{ background: '#07080b', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 8px', color: '#f0f2f6', fontSize: 14, fontWeight: 700, fontFamily: 'Space Grotesk', outline: 'none', width: 220 }} />
  );

  return (
    <span style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', cursor: 'text', display: 'flex', alignItems: 'center', gap: 6 }}
      onClick={() => setEditing(true)} title="Click to rename">
      {path.name}
      <Icon name="edit" size={11} color="#404550" />
    </span>
  );
}

// ── Main view ─────────────────────────────────────────────────────────
export default function AttackPathView({ attackPaths, attackSteps, onCreatePath, onUpdatePath, onDeletePath, onCreateStep, onUpdateStep, onDeleteStep, selectedProject, accent }) {
  const [activePath, setActivePath] = useState(null);
  const [modal, setModal] = useState(null); // null | { mode:'new'|'edit', step }
  const chainRef = useRef();

  const paths = attackPaths.filter(p => p.pid === selectedProject);
  const steps = attackSteps
    .filter(s => activePath && s.path_id === activePath.id)
    .sort((a, b) => a.step_order - b.step_order);

  // Auto-select first path when project or paths list changes
  useEffect(() => {
    if (!paths.length) { setActivePath(null); return; }
    if (!activePath || !paths.find(p => p.id === activePath.id)) {
      setActivePath(paths[0]);
    }
  }, [selectedProject, paths.map(p => p.id).join()]);

  const handleCreatePath = async () => {
    const ap = await onCreatePath({ pid: selectedProject, name: 'Attack Path ' + (paths.length + 1) });
    setActivePath(ap);
  };

  const handleDeletePath = async (id) => {
    if (!confirm('Delete attack path along with all steps?')) return;
    await onDeletePath(id);
    const remaining = paths.filter(p => p.id !== id);
    setActivePath(remaining[0] || null);
  };

  const handleAddStep = async (form) => {
    const maxOrder = steps.length ? Math.max(...steps.map(s => s.step_order)) : -1;
    await onCreateStep({ ...form, path_id: activePath.id, pid: selectedProject, step_order: maxOrder + 1 });
    setModal(null);
    setTimeout(() => chainRef.current?.scrollTo({ left: 99999, behavior: 'smooth' }), 100);
  };

  const handleEditStep = async (form) => {
    await onUpdateStep(modal.step.id, form);
    setModal(null);
  };

  const handleMoveLeft = async (step) => {
    const idx = steps.findIndex(s => s.id === step.id);
    if (idx <= 0) return;
    const prev = steps[idx - 1];
    await Promise.all([
      onUpdateStep(step.id, { step_order: prev.step_order }),
      onUpdateStep(prev.id, { step_order: step.step_order }),
    ]);
  };

  const handleMoveRight = async (step) => {
    const idx = steps.findIndex(s => s.id === step.id);
    if (idx >= steps.length - 1) return;
    const next = steps[idx + 1];
    await Promise.all([
      onUpdateStep(step.id, { step_order: next.step_order }),
      onUpdateStep(next.id, { step_order: step.step_order }),
    ]);
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#08090b' }}>
      {/* Header */}
      <div style={{ padding: '14px 20px', borderBottom: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
        <Icon name="attackpath" size={16} color={accent} />
        <div style={{ fontSize: 11, color: '#404550', fontFamily: 'Space Grotesk', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Attack Path</div>
        <div style={{ flex: 1 }} />
        <button onClick={handleCreatePath}
          style={{ background: accent + '18', border: `1px solid ${accent}44`, borderRadius: 6, padding: '6px 14px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Icon name="plus" size={11} color={accent} /> New path
        </button>
      </div>

      {/* Path tabs */}
      {paths.length > 0 && (
        <div style={{ padding: '0 20px', borderBottom: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0, overflowX: 'auto' }}>
          {paths.map(p => {
            const active = activePath?.id === p.id;
            return (
              <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
                <button onClick={() => setActivePath(p)}
                  style={{ padding: '10px 14px', border: 'none', borderBottom: active ? `2px solid ${accent}` : '2px solid transparent', background: 'transparent', cursor: 'pointer', color: active ? accent : '#505560', fontSize: 12, fontFamily: 'Space Grotesk', fontWeight: active ? 600 : 400, whiteSpace: 'nowrap', transition: 'all .15s' }}>
                  {p.name}
                </button>
                {active && (
                  <button onClick={() => handleDeletePath(p.id)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', display: 'flex', opacity: 0.4 }}
                    onMouseEnter={e => e.currentTarget.style.opacity = 1}
                    onMouseLeave={e => e.currentTarget.style.opacity = 0.4}>
                    <Icon name="close" size={10} color="#cc2233" />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Main chain area */}
      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {!activePath ? (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16, color: '#404550' }}>
            <Icon name="attackpath" size={42} color="#2a2d35" />
            <div style={{ fontSize: 13, color: '#505560', fontFamily: 'Space Grotesk' }}>No attack paths</div>
            <div style={{ fontSize: 11, color: '#404550', textAlign: 'center', maxWidth: 320 }}>Create a new path and add steps — from initial access to DA</div>
            <button onClick={handleCreatePath}
              style={{ background: accent + '18', border: `1px solid ${accent}44`, borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: accent, fontSize: 12, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="plus" size={12} color={accent} /> Create attack path
            </button>
          </div>
        ) : (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            {/* Path name + description */}
            <div style={{ padding: '16px 24px 12px', display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
              <PathNameEditor path={activePath} onSave={name => onUpdatePath(activePath.id, { name })} />
              <span style={{ fontSize: 10, color: '#353840', fontFamily: 'JetBrains Mono' }}>
                {steps.length} step{steps.length === 1 ? '' : 's'}
              </span>
            </div>

            {/* Chain */}
            <div ref={chainRef} style={{ flex: 1, overflowX: 'auto', overflowY: 'hidden', padding: '20px 24px 24px', display: 'flex', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 0, minHeight: 140 }}>
                {steps.length === 0 ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 16, color: '#404550' }}>
                    <div style={{ fontSize: 11, color: '#353840', fontFamily: 'JetBrains Mono' }}>← add first step</div>
                  </div>
                ) : (
                  steps.map((step, i) => (
                    <div key={step.id} style={{ display: 'flex', alignItems: 'center' }}>
                      {i > 0 && (
                        <Connector
                          technique={step.technique}
                          mitre_id={step.mitre_id}
                        />
                      )}
                      <NodeCard
                        step={step}
                        accent={accent}
                        canLeft={i > 0}
                        canRight={i < steps.length - 1}
                        onEdit={s => setModal({ mode: 'edit', step: s })}
                        onDelete={async id => { if (confirm('Delete step?')) await onDeleteStep(id); }}
                        onMoveLeft={handleMoveLeft}
                        onMoveRight={handleMoveRight}
                      />
                    </div>
                  ))
                )}

                {/* Add step button */}
                {steps.length > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Connector technique="" mitre_id="" />
                  </div>
                )}
                <button onClick={() => setModal({ mode: 'new', step: null })}
                  style={{ width: 56, height: 56, borderRadius: '50%', background: accent + '14', border: `1.5px dashed ${accent}55`, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, transition: 'all .15s' }}
                  onMouseEnter={e => { e.currentTarget.style.background = accent + '28'; e.currentTarget.style.borderColor = accent; }}
                  onMouseLeave={e => { e.currentTarget.style.background = accent + '14'; e.currentTarget.style.borderColor = accent + '55'; }}>
                  <Icon name="plus" size={18} color={accent} />
                </button>
              </div>
            </div>

            {/* Legend */}
            <div style={{ padding: '10px 24px', borderTop: '1px solid #13151c', display: 'flex', alignItems: 'center', gap: 16, flexShrink: 0 }}>
              {Object.entries(NODE_TYPES).map(([k, t]) => (
                <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: t.color }} />
                  <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{t.label}</span>
                </div>
              ))}
              <div style={{ flex: 1 }} />
              <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>← → move steps</span>
            </div>
          </div>
        )}
      </div>

      {modal && (
        <StepModal
          step={modal.step}
          isNew={modal.mode === 'new'}
          accent={accent}
          onClose={() => setModal(null)}
          onSave={modal.mode === 'new' ? handleAddStep : handleEditStep}
        />
      )}
    </div>
  );
}
