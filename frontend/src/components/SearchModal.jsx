import { useState, useEffect, useRef, useCallback } from 'react';
import Icon from './Icon.jsx';
import { api } from '../api.js';

const SEVERITY_COLOR = { critical: '#cc2233', high: '#e8574a', medium: '#f09a3a', low: '#e8cc42', info: '#5b8af5' };
const LOOT_TYPE_COLOR = { file: '#5b8af5', hash: '#c07af0', secret: '#e8574a', env: '#f09a3a', token: '#39d353', key: '#6fc8f0', config: '#e8cc42', other: '#606570' };

function ResultSection({ title, icon, color, items, renderItem }) {
  if (!items.length) return null;
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, padding: '0 16px' }}>
        <Icon name={icon} size={11} color={color} />
        <span style={{ fontSize: 9, color, textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 700, fontFamily: 'JetBrains Mono' }}>{title}</span>
        <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>({items.length})</span>
      </div>
      {items.map(renderItem)}
    </div>
  );
}

export default function SearchModal({ accent, selectedProject, projects, onNavigate, onClose }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scopeAll, setScopeAll] = useState(false);
  const inputRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  useEffect(() => {
    if (!query.trim() || query.length < 2) { setResults(null); return; }
    setLoading(true);
    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(async () => {
      try {
        const pid = scopeAll ? '' : selectedProject;
        const r = await api.search(query, pid);
        setResults(r);
      } catch { setResults(null); }
      setLoading(false);
    }, 250);
    return () => clearTimeout(timerRef.current);
  }, [query, scopeAll, selectedProject]);

  const total = results ? (results.hosts?.length + results.creds?.length + results.notes?.length + results.findings?.length + results.loots?.length) : 0;
  const projName = id => projects.find(p => p.id === id)?.name || id;

  const Row = ({ children, onClick }) => (
    <div onClick={onClick} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 16px', cursor: onClick ? 'pointer' : 'default', borderBottom: '1px solid #13151c' }}
      onMouseEnter={e => { if (onClick) e.currentTarget.style.background = '#ffffff06'; }}
      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
      {children}
    </div>
  );

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', zIndex: 2000, paddingTop: '10vh', backdropFilter: 'blur(4px)' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ width: 680, maxHeight: '75vh', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 32px 80px #00000099', overflow: 'hidden' }}>
        {/* Search input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 18px', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
          <Icon name="search" size={16} color={loading ? accent : '#404550'} />
          <input ref={inputRef} value={query} onChange={e => setQuery(e.target.value)}
            placeholder="Search hosts, creds, notes, findings, loot..."
            style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', color: '#e0e4ec', fontSize: 14, fontFamily: 'JetBrains Mono' }} />
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
            <button onClick={() => setScopeAll(v => !v)}
              style={{ background: scopeAll ? accent + '22' : 'transparent', border: `1px solid ${scopeAll ? accent + '66' : '#2a2d35'}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: scopeAll ? accent : '#505560', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
              All projects
            </button>
            <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>ESC</span>
          </div>
        </div>

        {/* Results */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {!query.trim() && (
            <div style={{ padding: '32px 18px', textAlign: 'center', color: '#303540' }}>
              <Icon name="search" size={28} color="#2a2d35" />
              <div style={{ marginTop: 10, fontSize: 12, color: '#404550' }}>Start typing your query (min. 2 chars)</div>
              <div style={{ marginTop: 6, fontSize: 10, color: '#303540', fontFamily: 'JetBrains Mono' }}>Ctrl+K — open / ESC — close</div>
            </div>
          )}

          {results && total === 0 && (
            <div style={{ padding: '32px 18px', textAlign: 'center', color: '#404550' }}>
              <div style={{ fontSize: 12 }}>Nothing found for «{query}»</div>
            </div>
          )}

          {results && total > 0 && (
            <div style={{ paddingTop: 12 }}>
              <ResultSection title="Hosts" icon="hosts" color="#5b8af5" items={results.hosts || []}
                renderItem={h => (
                  <Row key={h.id} onClick={() => { onNavigate('hosts'); onClose(); }}>
                    <Icon name="hosts" size={12} color="#5b8af5" />
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: '#c8cdd6', flex: 1 }}>{h.ip}</span>
                    {h.hostname && <span style={{ fontSize: 11, color: '#606570' }}>{h.hostname}</span>}
                    <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>{h.os}</span>
                    {!scopeAll ? null : <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>{projName(h.pid)}</span>}
                  </Row>
                )}
              />
              <ResultSection title="Creds" icon="creds" color="#c07af0" items={results.creds || []}
                renderItem={c => (
                  <Row key={c.id} onClick={() => { onNavigate('creds'); onClose(); }}>
                    <Icon name="creds" size={12} color="#c07af0" />
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: '#c8cdd6', flex: 1 }}>{c.username}</span>
                    {c.service && <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{c.service}</span>}
                    <span style={{ fontSize: 9, color: c.cracked ? '#39d353' : '#404550', fontFamily: 'JetBrains Mono' }}>{c.type}{c.cracked ? ' ✓' : ''}</span>
                    {!scopeAll ? null : <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>{projName(c.pid)}</span>}
                  </Row>
                )}
              />
              <ResultSection title="Notes" icon="notes" color="#f09a3a" items={results.notes || []}
                renderItem={n => (
                  <Row key={n.id} onClick={() => { onNavigate('notes'); onClose(); }}>
                    <Icon name="notes" size={12} color="#f09a3a" />
                    <span style={{ fontSize: 12, color: '#c8cdd6', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.title}</span>
                    <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>{n.phase}</span>
                    {n.starred && <span style={{ fontSize: 9, color: '#f09a3a' }}>★</span>}
                    {!scopeAll ? null : <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>{projName(n.pid)}</span>}
                  </Row>
                )}
              />
              <ResultSection title="Findings" icon="bug" color="#cc2233" items={results.findings || []}
                renderItem={f => (
                  <Row key={f.id} onClick={() => { onNavigate('findings'); onClose(); }}>
                    <Icon name="bug" size={12} color={SEVERITY_COLOR[f.severity] || '#cc2233'} />
                    <span style={{ fontSize: 12, color: '#c8cdd6', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</span>
                    <span style={{ fontSize: 9, color: SEVERITY_COLOR[f.severity], fontFamily: 'JetBrains Mono', textTransform: 'uppercase', fontWeight: 700 }}>{f.severity}</span>
                    {f.cve && <span style={{ fontSize: 9, color: '#5b8af5', fontFamily: 'JetBrains Mono' }}>{f.cve}</span>}
                    {!scopeAll ? null : <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>{projName(f.pid)}</span>}
                  </Row>
                )}
              />
              <ResultSection title="Loot" icon="loot" color="#39d353" items={results.loots || []}
                renderItem={l => (
                  <Row key={l.id} onClick={() => { onNavigate('loot'); onClose(); }}>
                    <Icon name="loot" size={12} color={LOOT_TYPE_COLOR[l.loot_type] || '#39d353'} />
                    <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#808590', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', filter: 'blur(4px)', userSelect: 'none' }}>{l.value}</span>
                    {l.description && <span style={{ fontSize: 10, color: '#606570', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160 }}>{l.description}</span>}
                    <span style={{ fontSize: 9, color: LOOT_TYPE_COLOR[l.loot_type] || '#39d353', fontFamily: 'JetBrains Mono' }}>{l.loot_type}</span>
                    {!scopeAll ? null : <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>{projName(l.pid)}</span>}
                  </Row>
                )}
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '8px 18px', borderTop: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
          <span style={{ fontSize: 9, color: '#303540', fontFamily: 'JetBrains Mono' }}>↵ navigate</span>
          <span style={{ fontSize: 9, color: '#303540', fontFamily: 'JetBrains Mono' }}>ESC close</span>
          {results && <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', marginLeft: 'auto' }}>{total} results</span>}
        </div>
      </div>
    </div>
  );
}
