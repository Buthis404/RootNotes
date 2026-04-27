import { useState, useMemo } from 'react';
import Icon from '../components/Icon.jsx';
import { SNIPPETS } from '../constants.js';

const CUSTOM_KEY = 'rt_custom_snippets_v1';

function loadCustom() {
  try { return JSON.parse(localStorage.getItem(CUSTOM_KEY) || '[]'); } catch { return []; }
}

function saveCustom(items) {
  localStorage.setItem(CUSTOM_KEY, JSON.stringify(items));
}

function extractVars(cmd) {
  const matches = cmd.match(/\{\{([A-Z_]+)\}\}/g) || [];
  return [...new Set(matches.map(m => m.slice(2, -2)))];
}

function fillVars(cmd, vals) {
  return cmd.replace(/\{\{([A-Z_]+)\}\}/g, (_, k) => vals[k] || `{{${k}}}`);
}

const HOST_VAR_HINTS = ['IP', 'HOST', 'TARGET', 'RHOST', 'LHOST', 'DOMAIN', 'DC'];
const CRED_VAR_HINTS = ['USER', 'PASS', 'HASH', 'SECRET', 'CRED', 'PASSWORD', 'NT', 'LM', 'NTLM'];

function varHint(varName) {
  const up = varName.toUpperCase();
  if (HOST_VAR_HINTS.some(h => up.includes(h))) return 'host';
  if (CRED_VAR_HINTS.some(h => up.includes(h))) return 'cred';
  return null;
}

function applyHostToVars(host, vars, setVals) {
  const updates = {};
  for (const v of vars) {
    const up = v.toUpperCase();
    if (up === 'DOMAIN' || up === 'DC' || up === 'FQDN_DOMAIN') {
      updates[v] = host.domain || host.hostname || host.ip;
    } else if (up.includes('IP') || up === 'RHOST' || up === 'LHOST' || up.includes('TARGET')) {
      updates[v] = host.ip;
    } else if (up.includes('HOST') || up.includes('FQDN')) {
      updates[v] = host.hostname || host.ip;
    } else if (up.includes('DOMAIN') || up.includes('_DC')) {
      updates[v] = host.domain || host.hostname || host.ip;
    }
  }
  if (Object.keys(updates).length) setVals(prev => ({ ...prev, ...updates }));
}

function applyCredToVars(cred, vars, setVals) {
  const updates = {};
  for (const v of vars) {
    const up = v.toUpperCase();
    if (up.includes('USER')) updates[v] = cred.username;
    else if (up.includes('PASS') || up.includes('SECRET') || up.includes('CRED')) updates[v] = cred.secret;
    else if (up.includes('HASH') || up.includes('NT') || up.includes('LM')) updates[v] = cred.secret;
  }
  if (Object.keys(updates).length) setVals(prev => ({ ...prev, ...updates }));
}

function VarModal({ snippet, accent, onClose, hosts = [], creds = [] }) {
  const vars = useMemo(() => extractVars(snippet.command), [snippet.command]);
  const [vals, setVals] = useState({});
  const [copied, setCopied] = useState(false);
  const result = fillVars(snippet.command, vals);

  const hasHostVars = vars.some(v => varHint(v) === 'host');
  const hasCredVars = vars.some(v => varHint(v) === 'cred');

  const copy = () => {
    navigator.clipboard.writeText(result).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  const sel = { background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 8px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none', width: '100%', cursor: 'pointer' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, padding: '28px 32px', width: 560, boxShadow: '0 24px 64px #00000099', maxHeight: '80vh', overflow: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>{snippet.title}</div>
            <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono', marginTop: 2 }}>{snippet.category}</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
            <Icon name="close" size={14} color="#606570" />
          </button>
        </div>

        {snippet.opsec && (
          <div style={{ padding: '8px 12px', background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 6, marginBottom: 16, display: 'flex', alignItems: 'flex-start', gap: 8 }}>
            <Icon name="opsec" size={13} color="#f09a3a" />
            <div>
              <div style={{ fontSize: 9, color: '#f09a3a', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 2 }}>OPSEC</div>
              <div style={{ fontSize: 11, color: '#c07a30', lineHeight: 1.5 }}>{snippet.opsec}</div>
            </div>
          </div>
        )}

        {(hasHostVars && hosts.length > 0) || (hasCredVars && creds.length > 0) ? (
          <div style={{ marginBottom: 16, padding: '10px 12px', background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 8 }}>Quick fill from project</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {hasHostVars && hosts.length > 0 && (
                <div style={{ flex: 1, minWidth: 180 }}>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Target host</div>
                  <select style={sel} onChange={e => {
                    const h = hosts.find(h => h.id === e.target.value);
                    if (h) applyHostToVars(h, vars, setVals);
                  }}>
                    <option value="">— pick a host —</option>
                    {hosts.map(h => <option key={h.id} value={h.id}>{h.ip}{h.hostname ? ` (${h.hostname})` : ''}</option>)}
                  </select>
                </div>
              )}
              {hasCredVars && creds.length > 0 && (
                <div style={{ flex: 1, minWidth: 180 }}>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Credentials</div>
                  <select style={sel} onChange={e => {
                    const c = creds.find(c => c.id === e.target.value);
                    if (c) applyCredToVars(c, vars, setVals);
                  }}>
                    <option value="">— pick a cred —</option>
                    {creds.map(c => <option key={c.id} value={c.id}>{c.username}{c.host ? `@${c.host}` : ''}{c.is_domain ? ' [AD]' : ''}</option>)}
                  </select>
                </div>
              )}
            </div>
          </div>
        ) : null}

        {vars.length > 0 && (
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 10 }}>Variables</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {vars.map(v => (
                <div key={v} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: accent, minWidth: 110, fontWeight: 600 }}>{'{{' + v + '}}'}</span>
                  <input value={vals[v] || ''} onChange={e => setVals(prev => ({ ...prev, [v]: e.target.value }))}
                    placeholder={v}
                    style={{ flex: 1, background: '#0d0f14', border: `1px solid ${vals[v] ? accent + '44' : '#2a2d35'}`, borderRadius: 4, padding: '5px 10px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none' }} />
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 8 }}>Command</div>
          <pre style={{ background: '#07080b', border: '1px solid #1e2029', borderRadius: 6, padding: '14px 16px', fontFamily: 'JetBrains Mono', fontSize: 12, color: '#c8cdd6', lineHeight: 1.7, whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
            {result.split(/(\{\{[A-Z_]+\}\})/g).map((part, i) =>
              part.match(/^\{\{[A-Z_]+\}\}$/)
                ? <span key={i} style={{ color: accent, background: accent + '22', borderRadius: 2, padding: '0 2px' }}>{part}</span>
                : <span key={i}>{part}</span>
            )}
          </pre>
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Close</button>
          <button onClick={copy}
            style={{ background: copied ? '#39d353' : accent, border: 'none', borderRadius: 5, padding: '7px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, transition: 'background .2s' }}>
            <Icon name={copied ? 'check' : 'copy'} size={12} color="#fff" />
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
      </div>
    </div>
  );
}

function AddCustomModal({ accent, onAdd, onClose }) {
  const [form, setForm] = useState({ title: '', category: 'Misc', command: '' });
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
  const inp = { background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 12, fontFamily: 'JetBrains Mono', outline: 'none', width: '100%' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, padding: '28px 32px', width: 480, boxShadow: '0 24px 64px #00000099' }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 20 }}>Add snippet</div>
        {[['Title', 'title', 'input'], ['Category', 'category', 'input'], ['Command', 'command', 'textarea']].map(([lbl, key, type]) => (
          <div key={key} style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>{lbl}</div>
            {type === 'textarea'
              ? <textarea style={{ ...inp, resize: 'vertical', minHeight: 100, lineHeight: 1.6 }} value={form[key]} onChange={e => set(key, e.target.value)} placeholder="Use {{VAR}} for variables" />
              : <input style={inp} value={form[key]} onChange={e => set(key, e.target.value)} />
            }
          </div>
        ))}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
          <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
          <button onClick={() => { if (form.title && form.command) { onAdd(form); onClose(); } }}
            style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

export default function CheatsheetView({ accent, hosts = [], creds = [], selectedProject }) {
  const [search, setSearch] = useState('');
  const [selectedCat, setSelectedCat] = useState(null);
  const [modalSnippet, setModalSnippet] = useState(null);
  const [showAddCustom, setShowAddCustom] = useState(false);
  const [custom, setCustom] = useState(loadCustom);

  const allSnippets = [...SNIPPETS, ...custom.map(s => ({ ...s, id: `custom-${s.title}`, isCustom: true }))];

  const categories = useMemo(() => {
    const cats = [...new Set(allSnippets.map(s => s.category))];
    return cats;
  }, [custom]);

  const filtered = useMemo(() => {
    let list = selectedCat ? allSnippets.filter(s => s.category === selectedCat) : allSnippets;
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(s => s.title.toLowerCase().includes(q) || s.command.toLowerCase().includes(q) || s.tags?.some(t => t.includes(q)) || s.category.toLowerCase().includes(q));
    }
    return list;
  }, [search, selectedCat, custom]);

  const grouped = useMemo(() => {
    const g = {};
    for (const s of filtered) (g[s.category] = g[s.category] || []).push(s);
    return g;
  }, [filtered]);

  const addCustom = (item) => {
    const updated = [...custom, item];
    setCustom(updated);
    saveCustom(updated);
  };

  const deleteCustom = (title) => {
    const updated = custom.filter(s => s.title !== title);
    setCustom(updated);
    saveCustom(updated);
  };

  const quickCopy = (e, cmd) => {
    e.stopPropagation();
    navigator.clipboard.writeText(cmd);
  };

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {modalSnippet && <VarModal snippet={modalSnippet} accent={accent} onClose={() => setModalSnippet(null)}
        hosts={(hosts || []).filter(h => h.pid === selectedProject)}
        creds={(creds || []).filter(c => c.pid === selectedProject)} />}
      {showAddCustom && <AddCustomModal accent={accent} onAdd={addCustom} onClose={() => setShowAddCustom(false)} />}

      {/* Category sidebar */}
      <div style={{ width: 160, background: '#0a0c10', borderRight: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
        <div style={{ padding: '12px 12px 6px', fontSize: 9, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.14em' }}>Categories</div>
        <button onClick={() => setSelectedCat(null)}
          style={{ width: '100%', padding: '8px 12px', background: !selectedCat ? `${accent}18` : 'transparent', borderLeft: !selectedCat ? `2px solid ${accent}` : '2px solid transparent', border: 'none', cursor: 'pointer', textAlign: 'left', color: !selectedCat ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          All ({allSnippets.length})
        </button>
        {categories.map(cat => {
          const cnt = allSnippets.filter(s => s.category === cat).length;
          const act = selectedCat === cat;
          return (
            <button key={cat} onClick={() => setSelectedCat(act ? null : cat)}
              style={{ width: '100%', padding: '7px 12px', background: act ? `${accent}18` : 'transparent', borderLeft: act ? `2px solid ${accent}` : '2px solid transparent', border: 'none', cursor: 'pointer', textAlign: 'left', color: act ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', justifyContent: 'space-between', alignItems: 'center', transition: 'all .12s' }}>
              <span>{cat}</span>
              <span style={{ fontSize: 9, color: act ? accent + 'aa' : '#303540' }}>{cnt}</span>
            </button>
          );
        })}
      </div>

      {/* Main area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Toolbar */}
        <div style={{ padding: '10px 20px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <Icon name="search" size={12} color="#404550" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search commands..."
              style={{ width: '100%', background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 6, padding: '7px 10px 7px 32px', color: '#c8cdd6', fontSize: 12, fontFamily: 'JetBrains Mono', outline: 'none' }} />
          </div>
          <button onClick={() => setShowAddCustom(true)}
            style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
            <Icon name="plus" size={11} color="#fff" /> Custom snippet
          </button>
        </div>

        {/* Snippets list */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 20px' }}>
          {Object.entries(grouped).map(([cat, snips]) => (
            <div key={cat} style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 10, color: accent, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                {cat}
                <div style={{ flex: 1, height: 1, background: accent + '22' }} />
                <span style={{ fontSize: 9, color: accent + '88', fontWeight: 400 }}>{snips.length}</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 8 }}>
                {snips.map(s => {
                  const vars = extractVars(s.command);
                  return (
                    <div key={s.id} onClick={() => setModalSnippet(s)}
                      style={{ background: s.opsec ? '#1a0d0a' : '#0d0f14', border: `1px solid ${s.opsec ? '#cc223333' : '#1e2029'}`, borderRadius: 8, padding: '10px 14px', cursor: 'pointer', transition: 'border-color .12s', position: 'relative' }}
                      onMouseEnter={e => e.currentTarget.style.borderColor = s.opsec ? '#cc223366' : accent + '66'}
                      onMouseLeave={e => e.currentTarget.style.borderColor = s.opsec ? '#cc223333' : '#1e2029'}>
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 6, gap: 6 }}>
                        <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', lineHeight: 1.3 }}>{s.title}</span>
                        <div style={{ display: 'flex', gap: 4, flexShrink: 0, alignItems: 'center' }}>
                          {s.opsec && (
                            <span title={`OPSEC: ${s.opsec}`} style={{ cursor: 'help', display: 'flex' }}>
                              <Icon name="opsec" size={12} color="#f09a3a" />
                            </span>
                          )}
                          {s.isCustom && (
                            <button onClick={e => { e.stopPropagation(); deleteCustom(s.title); }}
                              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: '#cc2233', display: 'flex' }}>
                              <Icon name="trash" size={11} color="currentColor" />
                            </button>
                          )}
                          <button onClick={e => quickCopy(e, s.command)}
                            style={{ background: 'none', border: `1px solid #2a2d35`, borderRadius: 3, cursor: 'pointer', padding: '2px 6px', fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 3 }}>
                            <Icon name="copy" size={9} color="#505560" /> copy
                          </button>
                        </div>
                      </div>
                      <pre style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: '#808590', lineHeight: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, maxHeight: 60, overflow: 'hidden' }}>
                        {s.command}
                      </pre>
                      {vars.length > 0 && (
                        <div style={{ marginTop: 6, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {vars.map(v => (
                            <span key={v} style={{ fontSize: 8, color: accent, background: accent + '18', border: `1px solid ${accent}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>
                              {v}
                            </span>
                          ))}
                        </div>
                      )}
                      {s.isCustom && (
                        <span style={{ position: 'absolute', top: 8, right: 8, fontSize: 8, color: '#39d353', background: '#39d35318', border: '1px solid #39d35333', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>custom</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
          {Object.keys(grouped).length === 0 && (
            <div style={{ padding: '60px 0', textAlign: 'center', color: '#303540' }}>
              <Icon name="terminal" size={40} color="#2a2d35" />
              <div style={{ fontSize: 13, marginTop: 12 }}>Nothing found</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
