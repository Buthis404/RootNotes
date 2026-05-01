import { useState, useEffect, useCallback, useMemo } from 'react';
import Icon from '../components/Icon.jsx';
import { PHASES, PHASE_COLORS, CHECKLIST_DEFAULTS } from '../constants.js';
import { api } from '../api.js';

export default function ChecklistView({ selectedProject, accent }) {
  const [phase, setPhase] = useState('recon');
  const [allItems, setAllItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [newText, setNewText] = useState('');

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    try {
      const data = await api.getChecklist(selectedProject);
      setAllItems(data);
    } catch {}
    setLoading(false);
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  const items = useMemo(
    () => allItems.filter(item => item.phase === phase).sort((a, b) => a.order_idx - b.order_idx),
    [allItems, phase],
  );

  const phaseStats = useMemo(() => Object.fromEntries(
    PHASES.map(ph => {
      const phaseItems = allItems.filter(item => item.phase === ph);
      const total = phaseItems.length;
      const done = phaseItems.filter(item => item.done).length;
      const pct = total > 0 ? Math.round((done / total) * 100) : 0;
      return [ph, { total, done, pct }];
    }),
  ), [allItems]);

  const loadDefaults = async () => {
    const defaults = CHECKLIST_DEFAULTS[phase] || [];
    const existing = new Set(items.map(i => i.text.toLowerCase()));
    const toAdd = defaults.filter(t => !existing.has(t.toLowerCase()));
    if (!toAdd.length) return;
    const payload = toAdd.map((text, i) => ({ pid: selectedProject, phase, text, done: false, order_idx: items.length + i }));
    const created = await api.bulkCreateChecklist(payload);
    setAllItems(prev => [...prev, ...created]);
  };

  const toggle = async (item) => {
    const updated = await api.updateChecklistItem(item.id, { done: !item.done });
    setAllItems(prev => prev.map(i => i.id === item.id ? updated : i));
  };

  const addItem = async () => {
    if (!newText.trim()) return;
    const [created] = await api.bulkCreateChecklist([{ pid: selectedProject, phase, text: newText.trim(), done: false, order_idx: items.length }]);
    setAllItems(prev => [...prev, created]);
    setNewText('');
  };

  const deleteItem = async (id) => {
    await api.deleteChecklistItem(id);
    setAllItems(prev => prev.filter(i => i.id !== id));
  };

   const done = phaseStats[phase]?.done || 0;
   const total = phaseStats[phase]?.total || 0;
   const pct = phaseStats[phase]?.pct || 0;

  const phaseColor = PHASE_COLORS[phase] || accent;

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Phase tabs */}
      <div style={{ background: '#0a0c10', borderBottom: '1px solid #1a1c22', padding: '10px 20px', display: 'flex', gap: 6, flexWrap: 'wrap', flexShrink: 0 }}>
        {PHASES.map(ph => {
          const act = ph === phase;
          const c = PHASE_COLORS[ph];
          return (
            <button key={ph} onClick={() => setPhase(ph)}
              style={{ background: act ? `${c}22` : 'transparent', border: `1px solid ${act ? c + '88' : '#2a2d35'}`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: act ? 700 : 400, color: act ? c : '#606570', textTransform: 'uppercase', letterSpacing: '0.08em', transition: 'all .12s' }}>
              {ph}
            </button>
          );
        })}
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Checklist */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Progress */}
          <div style={{ padding: '14px 24px 10px', borderBottom: '1px solid #1a1c22', background: '#0c0e13', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 13, fontWeight: 700, color: phaseColor, fontFamily: 'Space Grotesk', textTransform: 'capitalize' }}>{phase}</span>
                <span style={{ fontSize: 11, color: '#505560', fontFamily: 'JetBrains Mono' }}>{done}/{total} done</span>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button onClick={loadDefaults}
                  style={{ background: 'none', border: `1px solid ${phaseColor}55`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: phaseColor, fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Icon name="list" size={10} color={phaseColor} /> Load defaults
                </button>
              </div>
            </div>
            {/* Progress bar */}
            <div style={{ height: 4, background: '#1a1c22', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${pct}%`, background: pct === 100 ? '#39d353' : phaseColor, borderRadius: 2, transition: 'width .3s ease' }} />
            </div>
            <div style={{ fontSize: 9, color: pct === 100 ? '#39d353' : '#505560', marginTop: 4, textAlign: 'right', fontFamily: 'JetBrains Mono' }}>{pct}%</div>
          </div>

          {/* Items */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '10px 24px' }}>
            {loading && <div style={{ padding: 20, textAlign: 'center', color: '#404550', fontSize: 11 }}>Loading...</div>}
            {!loading && items.length === 0 && (
              <div style={{ padding: '40px 0', textAlign: 'center', color: '#303540' }}>
                <Icon name="list" size={32} color="#2a2d35" />
                <div style={{ fontSize: 12, marginTop: 12 }}>No items. Load defaults or add manually.</div>
              </div>
            )}
            {items.map((item, idx) => (
              <div key={item.id}
                style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: idx < items.length - 1 ? '1px solid #14161b' : 'none' }}>
                <button onClick={() => toggle(item)}
                  style={{ width: 18, height: 18, borderRadius: 4, border: `1.5px solid ${item.done ? phaseColor : '#303540'}`, background: item.done ? phaseColor + '33' : 'transparent', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, transition: 'all .15s' }}>
                  {item.done && <Icon name="check" size={10} color={phaseColor} />}
                </button>
                <span style={{ flex: 1, fontSize: 12, color: item.done ? '#404550' : '#b0b5c2', textDecoration: item.done ? 'line-through' : 'none', lineHeight: 1.5, transition: 'all .15s' }}>
                  {item.text}
                </span>
                <button onClick={() => deleteItem(item.id)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: '#303540', opacity: 0, display: 'flex' }}
                  onMouseEnter={e => e.currentTarget.style.opacity = 1}
                  onMouseLeave={e => e.currentTarget.style.opacity = 0}>
                  <Icon name="close" size={11} color="#cc2233" />
                </button>
              </div>
            ))}
          </div>

          {/* Add item */}
          <div style={{ padding: '12px 24px', borderTop: '1px solid #1a1c22', background: '#0c0e13', display: 'flex', gap: 8, flexShrink: 0 }}>
            <input value={newText} onChange={e => setNewText(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addItem()}
              placeholder="Add checklist item..."
              style={{ flex: 1, background: '#0d0f14', border: `1px solid #2a2d35`, borderRadius: 5, padding: '7px 12px', color: '#c8cdd6', fontSize: 12, fontFamily: 'JetBrains Mono', outline: 'none' }} />
            <button onClick={addItem}
              style={{ background: phaseColor, border: 'none', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4 }}>
              <Icon name="plus" size={11} color="#fff" />
            </button>
          </div>
        </div>

        {/* Sidebar: all phases overview */}
        <div style={{ width: 180, background: '#0a0c10', borderLeft: '1px solid #1a1c22', padding: '16px 14px', flexShrink: 0, overflowY: 'auto' }}>
          <div style={{ fontSize: 9, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 12 }}>Progress</div>
          {PHASES.map(ph => {
            const c = PHASE_COLORS[ph];
            const stat = phaseStats[ph] || { total: 0, done: 0, pct: 0 };
            return (
              <div key={ph} onClick={() => setPhase(ph)} style={{ marginBottom: 12, cursor: 'pointer', padding: '6px 8px', borderRadius: 5, background: ph === phase ? `${c}12` : 'transparent', border: `1px solid ${ph === phase ? c + '44' : 'transparent'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontSize: 9, fontFamily: 'JetBrains Mono', fontWeight: 600, color: c, textTransform: 'uppercase' }}>{ph}</span>
                  <span style={{ fontSize: 9, color: stat.pct === 100 && stat.total > 0 ? '#39d353' : '#505560', fontFamily: 'JetBrains Mono' }}>{stat.done}/{stat.total}</span>
                </div>
                <div style={{ height: 3, background: '#1a1c22', borderRadius: 2 }}>
                  <div style={{ height: '100%', width: `${stat.pct}%`, background: stat.pct === 100 && stat.total > 0 ? '#39d353' : c, borderRadius: 2, transition: 'width .2s ease' }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
