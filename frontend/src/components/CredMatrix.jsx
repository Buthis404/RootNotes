import { useState, useEffect, useRef } from 'react';
import { api } from '../api.js';
import { toastError } from './Toast.jsx';

// ── Cell colours ─────────────────────────────────────────────────────────────
// green  = access granted (access array has entries)
// red    = tried, no access
// gray   = not tried
const cellStyle = (state) => {
  if (state === 'success') return { bg: '#39d35322', border: '#39d35366', dot: '#39d353' };
  if (state === 'failed')  return { bg: '#cc223322', border: '#cc223366', dot: '#cc2233' };
  return                          { bg: 'transparent', border: '#1a1d24',  dot: '#2a2d35' };
};

function CellTooltip({ visible, x, y, content }) {
  if (!visible || !content) return null;
  return (
    <div style={{
      position: 'fixed', left: x + 12, top: y + 12, zIndex: 9999,
      background: '#131620', border: '1px solid #2a2d35', borderRadius: 6,
      padding: '8px 10px', maxWidth: 280, pointerEvents: 'none',
      boxShadow: '0 4px 16px #00000066',
    }}>
      {content.access?.length > 0 && (
        <div style={{ marginBottom: 4 }}>
          {content.access.map(a => (
            <span key={a} style={{ display: 'inline-block', marginRight: 4, marginBottom: 2, fontSize: 10, background: '#39d35322', color: '#39d353', border: '1px solid #39d35344', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{a}</span>
          ))}
        </div>
      )}
      {content.notes && (
        <div style={{ fontSize: 10, color: '#8892a0', fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', maxHeight: 120, overflow: 'auto' }}>{content.notes}</div>
      )}
      {!content.access?.length && !content.notes && (
        <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono' }}>Tried — no access</div>
      )}
    </div>
  );
}

export default function CredMatrix({ pid, accent = '#5b8af5' }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [tooltip, setTooltip] = useState({ visible: false, x: 0, y: 0, content: null });
  const [filter, setFilter] = useState('all'); // all | success | tried | untried
  const [search, setSearch] = useState('');
  const containerRef = useRef(null);

  useEffect(() => {
    if (!pid) return;
    setLoading(true);
    api.getCredMatrix(pid)
      .then(d => setData(d))
      .catch(e => toastError('Не удалось загрузить матрицу: ' + e.message))
      .finally(() => setLoading(false));
  }, [pid]);

  if (loading) return (
    <div style={{ padding: 40, textAlign: 'center', color: '#505560', fontFamily: 'JetBrains Mono', fontSize: 12 }}>
      Загрузка матрицы...
    </div>
  );

  if (!data) return null;

  const { creds, hosts, matrix } = data;

  const getCellState = (credId, hostId) => {
    const key = `${credId}:${hostId}`;
    const cell = matrix[key];
    if (!cell) return 'untried';
    if (cell.access?.length > 0) return 'success';
    return 'failed';
  };

  // Filter creds by search
  const filteredCreds = creds.filter(c => {
    const label = [c.username, c.domain, c.service].filter(Boolean).join(' ').toLowerCase();
    if (search && !label.includes(search.toLowerCase())) return false;
    if (filter === 'success') return hosts.some(h => getCellState(c.id, h.id) === 'success');
    if (filter === 'tried')   return hosts.some(h => getCellState(c.id, h.id) !== 'untried');
    return true;
  });

  // Stats
  const totalCells = creds.length * hosts.length;
  const successCells = Object.values(matrix).filter(m => m.access?.length > 0).length;
  const triedCells = Object.keys(matrix).length;

  const handleMouseEnter = (e, credId, hostId) => {
    const key = `${credId}:${hostId}`;
    const cell = matrix[key];
    if (!cell) return;
    setTooltip({ visible: true, x: e.clientX, y: e.clientY, content: cell });
  };
  const handleMouseMove = (e) => {
    if (tooltip.visible) setTooltip(t => ({ ...t, x: e.clientX, y: e.clientY }));
  };
  const handleMouseLeave = () => setTooltip(t => ({ ...t, visible: false }));

  const CELL_SIZE = 24;
  const HEADER_WIDTH = 180;
  const COL_WIDTH = Math.max(CELL_SIZE, Math.min(CELL_SIZE, 32));

  if (creds.length === 0 || hosts.length === 0) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: '#505560', fontFamily: 'JetBrains Mono', fontSize: 12 }}>
        {creds.length === 0 ? 'Нет учётных данных в проекте.' : 'Нет хостов в проекте.'}
      </div>
    );
  }

  return (
    <div ref={containerRef} onMouseMove={handleMouseMove} style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', flexShrink: 0, flexWrap: 'wrap' }}>
        {/* Stats */}
        <div style={{ display: 'flex', gap: 8 }}>
          <StatBadge label="Хосты" value={hosts.length} color="#5b8af5" />
          <StatBadge label="Учёт. данные" value={creds.length} color="#c07af0" />
          <StatBadge label="Успешно" value={successCells} color="#39d353" />
          <StatBadge label="Проверено" value={triedCells} color="#f09a3a" />
          <StatBadge label="Всего ячеек" value={totalCells} color="#505560" />
        </div>
        <div style={{ flex: 1 }} />
        {/* Filter */}
        {['all', 'success', 'tried'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            style={{ padding: '3px 9px', borderRadius: 4, fontSize: 10, fontFamily: 'JetBrains Mono', cursor: 'pointer', border: `1px solid ${filter === f ? accent : '#2a2d35'}`, background: filter === f ? accent + '22' : 'transparent', color: filter === f ? accent : '#8892a0', transition: 'all .15s' }}>
            {f === 'all' ? 'Все' : f === 'success' ? 'Успешные' : 'Проверенные'}
          </button>
        ))}
        {/* Search */}
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Поиск cred..."
          style={{ padding: '4px 9px', borderRadius: 4, background: '#0a0c10', border: '1px solid #2a2d35', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none', width: 140 }} />
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 8, flexShrink: 0 }}>
        <LegendItem color="#39d353" label="Доступ получен" />
        <LegendItem color="#cc2233" label="Проверено — отказ" />
        <LegendItem color="#2a2d35" label="Не проверялось" />
      </div>

      {/* Scrollable matrix */}
      <div style={{ flex: 1, overflow: 'auto', position: 'relative' }}>
        <table style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: HEADER_WIDTH + hosts.length * COL_WIDTH }}>
          <thead>
            <tr>
              {/* Empty corner */}
              <th style={{ width: HEADER_WIDTH, minWidth: HEADER_WIDTH, position: 'sticky', top: 0, left: 0, zIndex: 20, background: '#0d0f16', borderBottom: '1px solid #1a1d24', borderRight: '1px solid #1a1d24' }} />
              {hosts.map(h => (
                <th key={h.id} style={{ width: COL_WIDTH, minWidth: COL_WIDTH, maxWidth: COL_WIDTH, position: 'sticky', top: 0, zIndex: 10, background: '#0d0f16', borderBottom: '1px solid #1a1d24', padding: '4px 2px', verticalAlign: 'bottom' }}>
                  <div style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', fontSize: 9, color: '#8892a0', fontFamily: 'JetBrains Mono', height: 80, display: 'flex', alignItems: 'center', justifyContent: 'flex-start', overflow: 'hidden', textOverflow: 'ellipsis', maxHeight: 80, whiteSpace: 'nowrap' }}
                    title={h.hostname || h.ip}>
                    {h.hostname || h.ip}
                  </div>
                  <div style={{ fontSize: 8, color: '#404550', fontFamily: 'JetBrains Mono', textAlign: 'center', marginTop: 2 }}>{h.ip}</div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredCreds.map((cred, ri) => {
              const credLabel = cred.domain ? `${cred.domain}\\${cred.username}` : cred.username;
              const rowSuccesses = hosts.filter(h => getCellState(cred.id, h.id) === 'success').length;
              return (
                <tr key={cred.id} style={{ background: ri % 2 === 0 ? '#0a0c10' : '#0d0f14' }}>
                  {/* Cred label — sticky left */}
                  <td style={{ position: 'sticky', left: 0, zIndex: 5, background: ri % 2 === 0 ? '#0a0c10' : '#0d0f14', borderRight: '1px solid #1a1d24', borderBottom: '1px solid #12151c', padding: '2px 8px', whiteSpace: 'nowrap' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono', maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis' }} title={credLabel}>{credLabel}</span>
                      {cred.service && <span style={{ fontSize: 8, color: '#505560', background: '#1a1d24', borderRadius: 3, padding: '1px 4px', fontFamily: 'JetBrains Mono' }}>{cred.service}</span>}
                      {rowSuccesses > 0 && <span style={{ fontSize: 8, color: '#39d353', marginLeft: 'auto', fontFamily: 'JetBrains Mono' }}>{rowSuccesses}</span>}
                    </div>
                  </td>
                  {/* Cells */}
                  {hosts.map(host => {
                    const state = getCellState(cred.id, host.id);
                    const cs = cellStyle(state);
                    return (
                      <td key={host.id}
                        style={{ padding: 2, borderBottom: '1px solid #12151c', textAlign: 'center' }}
                        onMouseEnter={e => handleMouseEnter(e, cred.id, host.id)}
                        onMouseLeave={handleMouseLeave}>
                        <div style={{ width: CELL_SIZE - 4, height: CELL_SIZE - 4, borderRadius: 3, background: cs.bg, border: `1px solid ${cs.border}`, display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: state !== 'untried' ? 'pointer' : 'default', transition: 'all .1s' }}>
                          {state !== 'untried' && (
                            <div style={{ width: 6, height: 6, borderRadius: '50%', background: cs.dot }} />
                          )}
                        </div>
                      </td>
                    );
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
        {filteredCreds.length === 0 && (
          <div style={{ padding: 20, textAlign: 'center', color: '#505560', fontFamily: 'JetBrains Mono', fontSize: 11 }}>
            Нет результатов
          </div>
        )}
      </div>

      <CellTooltip {...tooltip} />
    </div>
  );
}

function StatBadge({ label, value, color }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, background: color + '11', border: `1px solid ${color}33`, borderRadius: 4, padding: '2px 8px' }}>
      <span style={{ fontSize: 13, fontWeight: 700, color, fontFamily: 'JetBrains Mono' }}>{value}</span>
      <span style={{ fontSize: 9, color: '#506070', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
    </div>
  );
}

function LegendItem({ color, label }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
      <div style={{ width: 10, height: 10, borderRadius: 2, background: color + '33', border: `1px solid ${color}66` }}>
        <div style={{ width: 4, height: 4, borderRadius: '50%', background: color, margin: '2px auto' }} />
      </div>
      <span style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>{label}</span>
    </div>
  );
}
