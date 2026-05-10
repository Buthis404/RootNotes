import { useState, useEffect, useRef, useCallback } from 'react';
import Icon from './Icon.jsx';
import { api } from '../api.js';

const TYPE_CFG = {
  host:    { icon: 'hosts',    color: '#5b8af5', label: 'Host' },
  cred:    { icon: 'creds',    color: '#c07af0', label: 'Cred' },
  note:    { icon: 'notes',    color: '#f09a3a', label: 'Note' },
  finding: { icon: 'bug',      color: '#cc2233', label: 'Finding' },
  loot:    { icon: 'loot',     color: '#39d353', label: 'Loot' },
  job:     { icon: 'jobs',     color: '#6fc8f0', label: 'Job' },
};

const SEV_COLOR = { critical: '#cc2233', high: '#e8574a', medium: '#f09a3a', low: '#e8cc42', info: '#5b8af5' };
const JOB_STATUS_COLOR = { done: '#39d353', running: '#f09a3a', failed: '#cc2233', pending: '#606570' };

const FILTER_KEYS = ['type', 'severity', 'status', 'service', 'role', 'source', 'connector'];

function parseTokens(raw) {
  const filters = {};
  const words = [];
  for (const tok of raw.trim().split(/\s+/)) {
    const m = tok.match(/^(\w+):(\S+)$/);
    if (m && FILTER_KEYS.includes(m[1])) {
      filters[m[1]] = m[2];
    } else if (tok) {
      words.push(tok);
    }
  }
  return { filters, clean: words.join(' ') };
}

function Badge({ label, color }) {
  return (
    <span style={{
      fontSize: 8, fontFamily: 'JetBrains Mono', fontWeight: 700,
      color, border: `1px solid ${color}44`, borderRadius: 3,
      padding: '1px 5px', textTransform: 'uppercase', letterSpacing: '0.08em', flexShrink: 0,
    }}>{label}</span>
  );
}

function FilterChip({ k, v, accent, onRemove }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      background: `${accent}18`, border: `1px solid ${accent}44`,
      borderRadius: 4, padding: '2px 7px', fontSize: 10,
      fontFamily: 'JetBrains Mono', color: accent,
    }}>
      <span style={{ color: '#606570' }}>{k}:</span>{v}
      <span onClick={onRemove} style={{ cursor: 'pointer', opacity: 0.6, marginLeft: 2 }}>×</span>
    </span>
  );
}

function ResultRow({ item, active, onClick, projName, showPid }) {
  const cfg = TYPE_CFG[item.type] || { icon: 'search', color: '#606570', label: item.type };
  const ref = useRef(null);

  useEffect(() => {
    if (active) ref.current?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  let metaBadge = null;
  if (item.type === 'finding') {
    const sev = item.meta?.severity;
    metaBadge = sev ? <Badge label={sev} color={SEV_COLOR[sev] || '#606570'} /> : null;
  } else if (item.type === 'job') {
    const st = item.meta?.status;
    metaBadge = st ? <Badge label={st} color={JOB_STATUS_COLOR[st] || '#606570'} /> : null;
  } else if (item.type === 'cred' && item.meta?.cracked) {
    metaBadge = <Badge label="cracked" color="#39d353" />;
  }

  return (
    <div
      ref={ref}
      onClick={onClick}
      style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '8px 16px',
        cursor: 'pointer', borderBottom: '1px solid #13151c',
        background: active ? '#ffffff0c' : 'transparent', transition: 'background .08s',
      }}
      onMouseEnter={e => { if (!active) e.currentTarget.style.background = '#ffffff06'; }}
      onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
    >
      {/* type dot */}
      <div style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.color, flexShrink: 0 }} />

      {/* main content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: '#c8cdd6', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {item.type === 'loot'
              ? <span style={{ filter: 'blur(3px)', userSelect: 'none' }}>{item.title}</span>
              : item.title}
          </span>
          {item.subtitle && (
            <span style={{ fontSize: 11, color: '#505560', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {item.subtitle}
            </span>
          )}
        </div>
        {item.snippet && (
          <div style={{ fontSize: 10, color: '#404550', marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {item.snippet}
          </div>
        )}
      </div>

      {/* badges */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
        {metaBadge}
        <Badge label={cfg.label} color={cfg.color} />
        {showPid && <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>{projName(item.pid)}</span>}
      </div>
    </div>
  );
}

const TYPE_TO_VIEW = {
  host: 'hosts', cred: 'creds', note: 'notes',
  finding: 'findings', loot: 'loot', job: 'jobs',
};

export default function SearchModal({ accent, selectedProject, projects, onNavigate, onClose }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scopeAll, setScopeAll] = useState(false);
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  useEffect(() => {
    const q = query.trim();
    if (!q || q.length < 2) { setResults(null); setActiveIdx(0); return; }
    setLoading(true);
    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(async () => {
      try {
        const pid = scopeAll ? '' : selectedProject;
        const r = await api.search(query, pid);
        setResults(r);
        setActiveIdx(0);
      } catch { setResults(null); }
      setLoading(false);
    }, 220);
    return () => clearTimeout(timerRef.current);
  }, [query, scopeAll, selectedProject]);

  const items = results?.items || [];
  const { filters } = parseTokens(query);

  const removeFilter = useCallback((key) => {
    setQuery(q => {
      return q.split(/\s+/).filter(tok => {
        const m = tok.match(/^(\w+):/);
        return !(m && m[1] === key);
      }).join(' ');
    });
  }, []);

  const handleKey = useCallback((e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIdx(i => Math.min(i + 1, items.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIdx(i => Math.max(i - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const item = items[activeIdx];
      if (item) { onNavigate(TYPE_TO_VIEW[item.type] || item.type); onClose(); }
    }
  }, [items, activeIdx, onNavigate, onClose]);

  const projName = id => projects.find(p => p.id === id)?.name || id;
  const filterEntries = Object.entries(filters);
  const total = results?.total ?? 0;
  const facets = results?.facets?.type || {};

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', zIndex: 2000, paddingTop: '8vh', backdropFilter: 'blur(4px)' }}
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      <div style={{ width: 700, maxHeight: '78vh', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 32px 80px #00000099', overflow: 'hidden' }}>

        {/* Input row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 18px', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
          <Icon name="search" size={16} color={loading ? accent : '#505560'} />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Search… type:host severity:critical status:open …"
            style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', color: '#e0e4ec', fontSize: 13, fontFamily: 'JetBrains Mono' }}
          />
          <button
            onClick={() => setScopeAll(v => !v)}
            style={{ background: scopeAll ? accent + '22' : 'transparent', border: `1px solid ${scopeAll ? accent + '66' : '#2a2d35'}`, borderRadius: 4, padding: '3px 9px', cursor: 'pointer', color: scopeAll ? accent : '#505560', fontSize: 9, fontFamily: 'JetBrains Mono', flexShrink: 0 }}
          >
            All projects
          </button>
          <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>ESC</span>
        </div>

        {/* Filter chips */}
        {filterEntries.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, padding: '8px 18px', borderBottom: '1px solid #1a1c22', flexShrink: 0 }}>
            {filterEntries.map(([k, v]) => (
              <FilterChip key={k} k={k} v={v} accent={accent} onRemove={() => removeFilter(k)} />
            ))}
          </div>
        )}

        {/* Facet summary bar */}
        {results && total > 0 && (
          <div style={{ display: 'flex', gap: 12, padding: '6px 18px', borderBottom: '1px solid #13151c', flexShrink: 0 }}>
            {Object.entries(facets).map(([t, n]) => {
              const cfg = TYPE_CFG[t] || {};
              return (
                <button key={t} onClick={() => setQuery(q => {
                  const clean = q.split(/\s+/).filter(tok => !tok.startsWith('type:')).join(' ');
                  return `type:${t} ${clean}`.trim();
                })} style={{ background: 'transparent', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, padding: 0 }}>
                  <span style={{ fontSize: 9, color: cfg.color || '#606570', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>{t}</span>
                  <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>{n}</span>
                </button>
              );
            })}
          </div>
        )}

        {/* Results list */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {!query.trim() && (
            <div style={{ padding: '36px 18px', textAlign: 'center' }}>
              <Icon name="search" size={28} color="#2a2d35" />
              <div style={{ marginTop: 10, fontSize: 12, color: '#404550' }}>Type to search hosts, creds, notes, findings, loot, jobs</div>
              <div style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 6, justifyContent: 'center' }}>
                {['type:host', 'type:finding severity:critical', 'type:cred service:smb', 'status:open', 'type:job status:done'].map(ex => (
                  <button key={ex} onClick={() => setQuery(ex)} style={{ background: '#ffffff06', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: '#505560', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{ex}</button>
                ))}
              </div>
            </div>
          )}

          {results && total === 0 && query.trim() && (
            <div style={{ padding: '36px 18px', textAlign: 'center', color: '#404550', fontSize: 12 }}>
              Nothing found for «{query}»
            </div>
          )}

          {items.map((item, idx) => (
            <ResultRow
              key={`${item.type}-${item.id}`}
              item={item}
              active={idx === activeIdx}
              projName={projName}
              showPid={scopeAll}
              onClick={() => { onNavigate(TYPE_TO_VIEW[item.type] || item.type); onClose(); }}
            />
          ))}
        </div>

        {/* Footer */}
        <div style={{ padding: '7px 18px', borderTop: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 14, flexShrink: 0 }}>
          <span style={{ fontSize: 9, color: '#303540', fontFamily: 'JetBrains Mono' }}>↑↓ navigate</span>
          <span style={{ fontSize: 9, color: '#303540', fontFamily: 'JetBrains Mono' }}>↵ open</span>
          <span style={{ fontSize: 9, color: '#303540', fontFamily: 'JetBrains Mono' }}>ESC close</span>
          <span style={{ fontSize: 9, color: '#303540', fontFamily: 'JetBrains Mono', marginLeft: 8 }}>
            filter: <span style={{ color: '#505560' }}>type: severity: status: service: role: source:</span>
          </span>
          {results && (
            <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginLeft: 'auto' }}>
              {total} result{total !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
