import React, { useState, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { api } from '../api.js';
import { toastError } from '../components/Toast.jsx';

const MITRE_CATEGORY = 'MITRE ATT&CK';

const CATEGORIES = [
  'General', 'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Lateral Movement', 'Collection', 'Exfiltration',
  'Command & Control', 'Defense Evasion', MITRE_CATEGORY,
];

const TACTIC_ORDER = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection',
  'Command and Control', 'Exfiltration', 'Impact',
];

const TACTIC_COLOR = {
  'Reconnaissance':       '#808590',
  'Initial Access':       '#cc2233',
  'Execution':            '#e8574a',
  'Persistence':          '#f09a3a',
  'Privilege Escalation': '#e8cc42',
  'Defense Evasion':      '#6fc8f0',
  'Credential Access':    '#c07af0',
  'Discovery':            '#5b8af5',
  'Lateral Movement':     '#39d353',
  'Collection':           '#3bc9c9',
  'Command and Control':  '#f07080',
  'Exfiltration':         '#a8d8a8',
  'Impact':               '#cc2233',
};

const CATEGORY_COLORS = {
  'General': '#6fc8f0',
  'Reconnaissance': '#5b8af5',
  'Initial Access': '#f09a3a',
  'Execution': '#cc2233',
  'Persistence': '#c07af0',
  'Privilege Escalation': '#e8574a',
  'Lateral Movement': '#e8cc42',
  'Collection': '#39d353',
  'Exfiltration': '#f09a3a',
  'Command & Control': '#cc2233',
  'Defense Evasion': '#808590',
  [MITRE_CATEGORY]: '#c07af0',
};

function categoryColor(cat) {
  return CATEGORY_COLORS[cat] || '#606570';
}

const inp = () => ({
  width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5,
  padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none',
  fontFamily: 'JetBrains Mono', boxSizing: 'border-box',
});

// ── MITRE article → {id, name, tactic}
function parseMitreArticle(a) {
  const mid = (a.tags || []).find(t => /^T\d{4}/.test(t)) || '';
  const name = a.title.includes(' — ') ? a.title.split(' — ')[1] : a.title;
  const tacticTag = (a.tags || []).find(t => t !== 'mitre' && !/^T\d/.test(t));
  const tactic = tacticTag
    ? tacticTag.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
    : '';
  return { id: mid, name, tactic, kb_id: a.id, article: a };
}

// ── Coverage matrix panel ──────────────────────────────────────────────
function MitreMatrix({ techniques, usedIds, usedNames, accent, onSelectArticle, collapsed, setCollapsed }) {
  const byTactic = {};
  for (const t of techniques) {
    const key = t.tactic || 'Other';
    if (!byTactic[key]) byTactic[key] = [];
    byTactic[key].push(t);
  }

  const order = [...TACTIC_ORDER, 'Other'].filter(k => byTactic[k]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {order.map(tactic => {
        const techs = byTactic[tactic] || [];
        const color = TACTIC_COLOR[tactic] || '#606570';
        const usedCount = techs.filter(t =>
          usedIds.has(t.id.toUpperCase()) ||
          [...usedNames].some(n => n.includes(t.name.toLowerCase()) || t.name.toLowerCase().includes(n))
        ).length;
        const isCollapsed = collapsed[tactic];

        return (
          <div key={tactic} style={{ border: '1px solid #1e2029', borderRadius: 6, overflow: 'hidden' }}>
            {/* Tactic header — clickable to collapse */}
            <div
              onClick={() => setCollapsed(p => ({ ...p, [tactic]: !p[tactic] }))}
              style={{
                display: 'flex', alignItems: 'center', gap: 8, padding: '7px 12px',
                cursor: 'pointer', background: '#0d0f14', userSelect: 'none',
                borderBottom: isCollapsed ? 'none' : '1px solid #1e2029',
              }}
            >
              <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', width: 10 }}>
                {isCollapsed ? '▶' : '▼'}
              </span>
              <span style={{ fontSize: 10, fontWeight: 700, color, textTransform: 'uppercase', letterSpacing: '0.08em', flex: 1 }}>
                {tactic}
              </span>
              <span style={{ fontSize: 9, fontFamily: 'JetBrains Mono', color: usedCount > 0 ? color : '#404550' }}>
                {usedCount}/{techs.length}
              </span>
              {usedCount > 0 && (
                <div style={{ width: 40, height: 4, background: '#1e2029', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${(usedCount / techs.length) * 100}%`, background: color, borderRadius: 2 }} />
                </div>
              )}
            </div>

            {/* Technique tiles */}
            {!isCollapsed && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, padding: '8px 10px' }}>
                {techs.map(t => {
                  const used = usedIds.has(t.id.toUpperCase()) ||
                    [...usedNames].some(n => n.includes(t.name.toLowerCase()) || t.name.toLowerCase().includes(n));
                  return (
                    <div
                      key={t.id}
                      onClick={() => t.article && onSelectArticle(t.article)}
                      style={{
                        padding: '3px 7px', borderRadius: 4, cursor: t.article ? 'pointer' : 'default',
                        border: used ? `1px solid ${color}66` : '1px solid #1e2029',
                        background: used ? `${color}14` : 'transparent',
                        display: 'flex', alignItems: 'center', gap: 5,
                      }}
                    >
                      <span style={{ fontSize: 8, fontFamily: 'JetBrains Mono', color: used ? color : '#404550', flexShrink: 0 }}>
                        {t.id}
                      </span>
                      <span style={{ fontSize: 9, color: used ? '#c8cdd6' : '#505560', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {t.name}
                      </span>
                      {used && <span style={{ width: 5, height: 5, borderRadius: '50%', background: color, flexShrink: 0 }} />}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Attack path steps flow ─────────────────────────────────────────────
function StepsFlow({ attackSteps, techniques, accent }) {
  const usedSteps = attackSteps.filter(s => s.technique || s.mitre_id);

  if (usedSteps.length === 0) {
    return (
      <div style={{ padding: '24px 16px', textAlign: 'center', color: '#404550', fontSize: 11, lineHeight: 1.6 }}>
        No attack path steps with techniques yet.<br />
        Add techniques in Attack Path → step editor.
      </div>
    );
  }

  // Group by tactic (via matching KB techniques)
  const techMap = {};
  for (const t of techniques) {
    techMap[t.id.toUpperCase()] = t;
    if (t.name) techMap[t.name.toLowerCase()] = t;
  }

  const enriched = usedSteps.map(s => {
    const mid = (s.mitre_id || '').toUpperCase();
    const name = (s.technique || '').toLowerCase();
    const tech = techMap[mid] || techMap[name] || null;
    return { ...s, _tech: tech };
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {enriched.map((s, i) => {
        const tech = s._tech;
        const color = tech ? (TACTIC_COLOR[tech.tactic] || accent) : accent;
        const isLast = i === enriched.length - 1;
        return (
          <div key={s.id} style={{ display: 'flex', gap: 0 }}>
            {/* Timeline spine */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 24, flexShrink: 0 }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', border: `2px solid ${color}`, background: '#0d0f14', flexShrink: 0, marginTop: 10, zIndex: 1 }} />
              {!isLast && <div style={{ width: 2, flex: 1, background: '#1e2029', minHeight: 16 }} />}
            </div>

            {/* Step card */}
            <div style={{
              flex: 1, margin: '4px 0 4px 8px',
              padding: '8px 12px', borderRadius: 6,
              border: `1px solid ${color}33`,
              background: `${color}08`,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                <span style={{ fontSize: 8, fontFamily: 'JetBrains Mono', color: '#404550', width: 18 }}>
                  {String(i + 1).padStart(2, '0')}
                </span>
                <span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', flex: 1 }}>
                  {s.label || s.sublabel || '(unnamed step)'}
                </span>
                {s.mitre_id && (
                  <span style={{ fontSize: 8, fontFamily: 'JetBrains Mono', color, background: `${color}18`, border: `1px solid ${color}44`, borderRadius: 3, padding: '1px 5px' }}>
                    {s.mitre_id}
                  </span>
                )}
              </div>
              {s.technique && (
                <div style={{ fontSize: 10, color: color, fontFamily: 'JetBrains Mono', paddingLeft: 24 }}>
                  {s.technique}
                  {tech?.tactic && <span style={{ color: '#505560' }}> · {tech.tactic}</span>}
                </div>
              )}
              {s.notes && (
                <div style={{ fontSize: 10, color: '#505560', paddingLeft: 24, marginTop: 2, fontStyle: 'italic' }}>
                  {s.notes.slice(0, 80)}{s.notes.length > 80 ? '…' : ''}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── MITRE panel (replaces article list when MITRE ATT&CK selected) ─────
function MitrePanel({ articles, attackSteps, accent, onSelectArticle, selectedProject }) {
  const [mode, setMode] = useState('matrix'); // matrix | steps
  const [seeding, setSeeding] = useState(false);
  const [collapsedTactics, setCollapsedTactics] = useState({});
  const [coverage, setCoverage] = useState(null);

  const techniques = articles.map(parseMitreArticle);
  const kbSeeded = techniques.length > 0;

  // Compute used IDs and names from attack steps
  const usedIds = new Set(
    attackSteps.map(s => (s.mitre_id || '').toUpperCase()).filter(Boolean)
  );
  const usedNames = new Set(
    attackSteps.map(s => (s.technique || '').toLowerCase()).filter(Boolean)
  );

  const usedCount = techniques.filter(t =>
    usedIds.has(t.id.toUpperCase()) ||
    [...usedNames].some(n => n.includes(t.name.toLowerCase()) || t.name.toLowerCase().includes(n))
  ).length;

  const pct = techniques.length ? Math.round((usedCount / techniques.length) * 100) : 0;

  const seedToKB = async () => {
    setSeeding(true);
    try {
      const r = await api.seedMitreKB();
      window.location.reload();
    } catch (e) {
      toastError('Seed failed: ' + e.message);
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Sub-header */}
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
        {kbSeeded ? (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <div style={{ flex: 1, height: 4, background: '#1e2029', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: '#c07af0', borderRadius: 2, transition: 'width .3s' }} />
              </div>
              <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
                {usedCount}/{techniques.length} · {pct}%
              </span>
            </div>
            <div style={{ display: 'flex', gap: 4 }}>
              {['matrix', 'steps'].map(m => (
                <button key={m} onClick={() => setMode(m)} style={{
                  flex: 1, background: mode === m ? '#c07af022' : 'transparent',
                  border: `1px solid ${mode === m ? '#c07af066' : '#2a2d35'}`,
                  borderRadius: 4, padding: '4px 0', cursor: 'pointer',
                  color: mode === m ? '#c07af0' : '#505560',
                  fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase',
                }}>{m === 'matrix' ? 'Matrix' : 'Attack Path'}</button>
              ))}
            </div>
          </>
        ) : (
          <div style={{ fontSize: 10, color: '#505560', lineHeight: 1.5, marginBottom: 6 }}>
            MITRE ATT&CK library not seeded to KB.
          </div>
        )}
        <button
          onClick={seedToKB}
          disabled={seeding}
          style={{
            width: '100%', marginTop: 4,
            background: kbSeeded ? 'transparent' : '#c07af022',
            border: `1px solid ${kbSeeded ? '#2a2d35' : '#c07af066'}`,
            borderRadius: 4, padding: '4px 0', cursor: 'pointer',
            color: kbSeeded ? '#404550' : '#c07af0',
            fontSize: 9, fontFamily: 'JetBrains Mono',
            opacity: seeding ? 0.5 : 1,
          }}
        >
          {seeding ? 'Seeding…' : kbSeeded ? 'Re-seed MITRE' : '⬡ Seed MITRE ATT&CK to KB'}
        </button>
      </div>

      {/* Content */}
      {kbSeeded && (
        <div style={{ flex: 1, overflowY: 'auto', padding: '8px' }}>
          {mode === 'matrix' ? (
            <MitreMatrix
              techniques={techniques}
              usedIds={usedIds}
              usedNames={usedNames}
              accent={accent}
              onSelectArticle={onSelectArticle}
              collapsed={collapsedTactics}
              setCollapsed={setCollapsedTactics}
            />
          ) : (
            <StepsFlow
              attackSteps={attackSteps}
              techniques={techniques}
              accent={accent}
            />
          )}
        </div>
      )}
    </div>
  );
}

// ── Main KBView ────────────────────────────────────────────────────────
export default function KBView({ selectedProject, accent, currentUser, attackSteps = [] }) {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [selectedCat, setSelectedCat] = useState('');
  const [selectedArticle, setSelectedArticle] = useState(null);
  const [editing, setEditing] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [importing, setImporting] = useState(false);

  const [editTitle, setEditTitle] = useState('');
  const [editCategory, setEditCategory] = useState('General');
  const [editTags, setEditTags] = useState('');
  const [editContent, setEditContent] = useState('');

  const [newTitle, setNewTitle] = useState('');
  const [newCategory, setNewCategory] = useState('General');
  const [newTags, setNewTags] = useState('');
  const [newContent, setNewContent] = useState('');
  const [newScope, setNewScope] = useState('project');
  const [saving, setSaving] = useState(false);

  const isMitre = selectedCat === MITRE_CATEGORY;

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = {};
      if (selectedProject) params.pid = selectedProject;
      const data = await api.listKBArticles(params);
      setArticles(Array.isArray(data) ? data : (data.articles || []));
    } catch (e) {
      setError(e.message || 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  const catCounts = {};
  articles.forEach(a => { catCounts[a.category] = (catCounts[a.category] || 0) + 1; });
  const totalCount = articles.length;

  const mitreArticles = articles.filter(a => a.category === MITRE_CATEGORY);

  const filtered = articles.filter(a => {
    if (selectedCat && a.category !== selectedCat) return false;
    if (search) {
      const q = search.toLowerCase();
      return a.title?.toLowerCase().includes(q) || a.content?.toLowerCase().includes(q) || (a.tags || []).some(t => t.toLowerCase().includes(q));
    }
    return true;
  });

  const startEdit = (art) => {
    setEditTitle(art.title || '');
    setEditCategory(art.category || 'General');
    setEditTags((art.tags || []).join(', '));
    setEditContent(art.content || '');
    setEditing(true);
  };

  const saveEdit = async () => {
    setSaving(true);
    try {
      const updated = await api.updateKBArticle(selectedArticle.id, {
        title: editTitle, category: editCategory,
        tags: editTags.split(',').map(t => t.trim()).filter(Boolean),
        content: editContent,
      });
      setArticles(prev => prev.map(a => a.id === updated.id ? updated : a));
      setSelectedArticle(updated);
      setEditing(false);
    } catch (e) { toastError(e.message); }
    finally { setSaving(false); }
  };

  const doDelete = async () => {
    try {
      await api.deleteKBArticle(selectedArticle.id);
      setArticles(prev => prev.filter(a => a.id !== selectedArticle.id));
      setSelectedArticle(null);
      setConfirmDelete(false);
    } catch (e) { toastError(e.message); }
  };

  const exportKB = async () => {
    try {
      const blob = await api.exportKB(selectedProject);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `kb-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { toastError(e.message); }
  };

  const importKB = async (file) => {
    setImporting(true);
    try {
      await api.importKB(file, selectedProject);
      await load();
    } catch (e) { toastError(e.message); }
    finally { setImporting(false); }
  };

  const createArticle = async () => {
    setSaving(true);
    try {
      const data = {
        title: newTitle, category: newCategory,
        tags: newTags.split(',').map(t => t.trim()).filter(Boolean),
        content: newContent,
      };
      if (newScope === 'project' && selectedProject) data.pid = selectedProject;
      const created = await api.createKBArticle(data);
      setArticles(prev => [created, ...prev]);
      setShowCreate(false);
      setNewTitle(''); setNewCategory('General'); setNewTags(''); setNewContent(''); setNewScope('project');
      setSelectedArticle(created);
    } catch (e) { toastError(e.message); }
    finally { setSaving(false); }
  };

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden', background: '#090b0f' }}>

      {/* ── Left sidebar: categories ── */}
      <div style={{ width: 220, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        <div style={{ padding: '14px 14px 10px', borderBottom: '1px solid #1e2029' }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 10 }}>Knowledge Base</div>
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setSelectedArticle(null); setEditing(false); }}
            placeholder="Search…"
            style={{ ...inp(), fontSize: 11 }}
          />
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: '6px 0' }}>
          <div
            onClick={() => { setSelectedCat(''); setSelectedArticle(null); setEditing(false); }}
            style={{ padding: '6px 14px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: !selectedCat ? accent + '18' : 'transparent', borderLeft: !selectedCat ? `2px solid ${accent}` : '2px solid transparent' }}
          >
            <span style={{ fontSize: 11, color: !selectedCat ? accent : '#c8cdd6' }}>All articles</span>
            <span style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>{totalCount}</span>
          </div>
          {CATEGORIES.map(cat => {
            const count = catCounts[cat] || 0;
            const active = selectedCat === cat;
            const col = categoryColor(cat);
            return (
              <div
                key={cat}
                onClick={() => { setSelectedCat(active ? '' : cat); setSelectedArticle(null); setEditing(false); }}
                style={{ padding: '6px 14px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: active ? col + '18' : 'transparent', borderLeft: active ? `2px solid ${col}` : '2px solid transparent' }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.background = '#ffffff06'; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
              >
                <span style={{ fontSize: 11, color: active ? col : '#808590' }}>{cat}</span>
                {count > 0 && <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono' }}>{count}</span>}
              </div>
            );
          })}
        </div>
        {/* Export / Import */}
        <div style={{ padding: '8px 10px', borderTop: '1px solid #1e2029', display: 'flex', gap: 6, flexShrink: 0 }}>
          <label style={{ flex: 1, background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 0', cursor: importing ? 'wait' : 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, opacity: importing ? 0.7 : 1 }}>
            {importing ? 'Importing…' : 'Import'}
            <input type="file" accept="application/json,.json" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && importKB(e.target.files[0])} disabled={importing} />
          </label>
          <button onClick={exportKB} style={{ flex: 1, background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 0', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
            Export
          </button>
        </div>
      </div>

      {/* ── Middle panel: MITRE matrix OR article list ── */}
      <div style={{ width: isMitre ? 380 : 270, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0, transition: 'width .15s' }}>
        {isMitre ? (
          <MitrePanel
            articles={mitreArticles}
            attackSteps={attackSteps}
            accent={accent}
            onSelectArticle={a => { setSelectedArticle(a); setEditing(false); setShowCreate(false); }}
            selectedProject={selectedProject}
          />
        ) : (
          <>
            <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
              <div style={{ flex: 1, fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono' }}>
                {filtered.length} article{filtered.length !== 1 ? 's' : ''}
              </div>
              <button
                onClick={() => { setShowCreate(v => !v); setSelectedArticle(null); setEditing(false); }}
                style={{ background: showCreate ? accent + '33' : accent, border: 'none', borderRadius: 4, padding: '4px 9px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono' }}
              >+ New</button>
            </div>
            {error && <div style={{ margin: '6px 10px', background: '#cc233318', border: '1px solid #cc233344', borderRadius: 4, padding: '5px 8px', fontSize: 10, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>{error}</div>}
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {loading && <div style={{ color: '#404550', fontSize: 11, textAlign: 'center', padding: 32 }}>Loading…</div>}
              {!loading && filtered.length === 0 && (
                <div style={{ color: '#404550', fontSize: 11, textAlign: 'center', padding: 32, lineHeight: 1.6 }}>No articles.<br />Click "+ New" to create.</div>
              )}
              {filtered.map(art => {
                const isSel = selectedArticle?.id === art.id;
                const col = categoryColor(art.category);
                return (
                  <div
                    key={art.id}
                    onClick={() => { setSelectedArticle(art); setEditing(false); setConfirmDelete(false); setShowCreate(false); }}
                    style={{ padding: '9px 12px', cursor: 'pointer', borderBottom: '1px solid #14161b', borderLeft: isSel ? `2px solid ${accent}` : '2px solid transparent', background: isSel ? accent + '10' : 'transparent' }}
                    onMouseEnter={e => { if (!isSel) e.currentTarget.style.background = '#ffffff06'; }}
                    onMouseLeave={e => { if (!isSel) e.currentTarget.style.background = 'transparent'; }}
                  >
                    <div style={{ fontSize: 12, fontWeight: 600, color: isSel ? '#f0f2f6' : '#c8cdd6', fontFamily: 'Space Grotesk', marginBottom: 4, lineHeight: 1.3 }}>{art.title}</div>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 8, background: col + '18', border: `1px solid ${col}33`, borderRadius: 2, padding: '1px 5px', color: col, fontFamily: 'JetBrains Mono' }}>{art.category}</span>
                      <span style={{ fontSize: 8, background: art.pid ? accent + '18' : '#c07af018', border: `1px solid ${art.pid ? accent + '33' : '#c07af033'}`, borderRadius: 2, padding: '1px 5px', color: art.pid ? accent : '#c07af0', fontFamily: 'JetBrains Mono' }}>{art.pid ? 'PROJECT' : 'GLOBAL'}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>

      {/* ── Right panel: article viewer / editor / create ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* New article button for MITRE mode */}
        {isMitre && !selectedArticle && !showCreate && (
          <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', display: 'flex', gap: 8, flexShrink: 0 }}>
            <button
              onClick={() => { setShowCreate(true); setSelectedArticle(null); }}
              style={{ background: accent, border: 'none', borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono' }}
            >+ New Article</button>
          </div>
        )}

        {/* Create form */}
        {showCreate && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 16 }}>New Article</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Title</div>
                <input value={newTitle} onChange={e => setNewTitle(e.target.value)} placeholder="Article title" autoFocus style={inp()} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Category</div>
                  <select value={newCategory} onChange={e => setNewCategory(e.target.value)} style={{ ...inp(), cursor: 'pointer' }}>
                    {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Tags</div>
                  <input value={newTags} onChange={e => setNewTags(e.target.value)} placeholder="tag1, tag2" style={inp()} />
                </div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Scope</div>
                <div style={{ display: 'flex', gap: 8 }}>
                  {['project', 'global'].map(s => (
                    <label key={s} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer', fontSize: 11, color: newScope === s ? accent : '#606570' }}>
                      <input type="radio" name="scope" value={s} checked={newScope === s} onChange={() => setNewScope(s)} style={{ accentColor: accent }} />
                      {s === 'project' ? 'Project' : 'Global'}
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Content (Markdown)</div>
                <textarea value={newContent} onChange={e => setNewContent(e.target.value)} placeholder="# Title&#10;&#10;Content..." rows={16} style={{ ...inp(), resize: 'vertical', lineHeight: 1.6 }} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={createArticle} disabled={saving || !newTitle.trim()} style={{ background: newTitle.trim() ? accent : '#1a1c22', border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                  {saving ? 'Creating…' : 'Create'}
                </button>
                <button onClick={() => setShowCreate(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
              </div>
            </div>
          </div>
        )}

        {/* Article viewer / editor */}
        {selectedArticle && !showCreate && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '20px 28px' }}>
            {editing ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 4 }}>Edit Article</div>
                <div>
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Title</div>
                  <input value={editTitle} onChange={e => setEditTitle(e.target.value)} style={inp()} />
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Category</div>
                    <select value={editCategory} onChange={e => setEditCategory(e.target.value)} style={{ ...inp(), cursor: 'pointer' }}>
                      {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                  <div>
                    <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Tags</div>
                    <input value={editTags} onChange={e => setEditTags(e.target.value)} placeholder="tag1, tag2" style={inp()} />
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Content (Markdown)</div>
                  <textarea value={editContent} onChange={e => setEditContent(e.target.value)} rows={20} style={{ ...inp(), resize: 'vertical', lineHeight: 1.6 }} />
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={saveEdit} disabled={saving} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{saving ? 'Saving…' : 'Save'}</button>
                  <button onClick={() => setEditing(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
                </div>
              </div>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 16, paddingBottom: 16, borderBottom: '1px solid #1e2029' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 10, lineHeight: 1.2 }}>{selectedArticle.title}</div>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
                      <span style={{ fontSize: 10, background: categoryColor(selectedArticle.category) + '22', border: `1px solid ${categoryColor(selectedArticle.category)}44`, borderRadius: 3, padding: '2px 8px', color: categoryColor(selectedArticle.category), fontFamily: 'JetBrains Mono' }}>
                        {selectedArticle.category}
                      </span>
                      <span style={{ fontSize: 10, background: selectedArticle.pid ? accent + '22' : '#c07af022', border: `1px solid ${selectedArticle.pid ? accent + '44' : '#c07af044'}`, borderRadius: 3, padding: '2px 8px', color: selectedArticle.pid ? accent : '#c07af0', fontFamily: 'JetBrains Mono' }}>
                        {selectedArticle.pid ? 'PROJECT' : 'GLOBAL'}
                      </span>
                      {(selectedArticle.tags || []).map(t => (
                        <span key={t} style={{ fontSize: 10, background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 6px', color: '#808590', fontFamily: 'JetBrains Mono' }}>{t}</span>
                      ))}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    <button onClick={() => startEdit(selectedArticle)} style={{ background: 'transparent', border: `1px solid ${accent}44`, borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: 'JetBrains Mono' }}>Edit</button>
                    <button onClick={() => setConfirmDelete(true)} style={{ background: 'transparent', border: '1px solid #cc233344', borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: '#cc2233', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Delete</button>
                  </div>
                </div>
                <div className="kb-markdown" style={{ color: '#c8cdd6', lineHeight: 1.8, fontSize: 13 }}>
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {selectedArticle.content || '*(empty)*'}
                  </ReactMarkdown>
                </div>
              </>
            )}
            {confirmDelete && (
              <div style={{ marginTop: 20, background: '#cc233318', border: '1px solid #cc233344', borderRadius: 6, padding: '12px 14px' }}>
                <div style={{ fontSize: 12, color: '#f0f2f6', marginBottom: 10 }}>Delete "{selectedArticle.title}"?</div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={doDelete} style={{ background: '#cc2233', border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>Delete</button>
                  <button onClick={() => setConfirmDelete(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Empty state */}
        {!selectedArticle && !showCreate && !isMitre && (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: '#303540' }}>
            <div style={{ fontSize: 32 }}>📖</div>
            <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono', color: '#404550' }}>Select an article to read</div>
          </div>
        )}
        {!selectedArticle && !showCreate && isMitre && (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 8, color: '#303540' }}>
            <div style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: '#404550' }}>Click a technique to read its article</div>
          </div>
        )}
      </div>
    </div>
  );
}
