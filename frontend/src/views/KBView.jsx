import React, { useState, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { api } from '../api.js';
import { toastError } from '../components/Toast.jsx';

const CATEGORIES = [
  'General', 'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Lateral Movement', 'Collection', 'Exfiltration',
  'Command & Control', 'Defense Evasion', 'MITRE ATT&CK',
];

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
  'MITRE ATT&CK': '#c07af0',
};

function categoryColor(cat) {
  return CATEGORY_COLORS[cat] || '#606570';
}

const inp = () => ({
  width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5,
  padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none',
  fontFamily: 'JetBrains Mono', boxSizing: 'border-box',
});

export default function KBView({ selectedProject, accent, currentUser }) {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [selectedCat, setSelectedCat] = useState('');
  const [selectedArticle, setSelectedArticle] = useState(null);
  const [editing, setEditing] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  // Edit form state
  const [editTitle, setEditTitle] = useState('');
  const [editCategory, setEditCategory] = useState('General');
  const [editTags, setEditTags] = useState('');
  const [editContent, setEditContent] = useState('');

  // Create form state
  const [newTitle, setNewTitle] = useState('');
  const [newCategory, setNewCategory] = useState('General');
  const [newTags, setNewTags] = useState('');
  const [newContent, setNewContent] = useState('');
  const [newScope, setNewScope] = useState('project');

  const [saving, setSaving] = useState(false);

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

  // Category counts
  const catCounts = {};
  articles.forEach(a => {
    catCounts[a.category] = (catCounts[a.category] || 0) + 1;
  });
  const totalCount = articles.length;

  // Filtered articles
  const filtered = articles.filter(a => {
    if (selectedCat && a.category !== selectedCat) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        a.title?.toLowerCase().includes(q) ||
        a.content?.toLowerCase().includes(q) ||
        (a.tags || []).some(t => t.toLowerCase().includes(q))
      );
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
        title: editTitle,
        category: editCategory,
        tags: editTags.split(',').map(t => t.trim()).filter(Boolean),
        content: editContent,
      });
      setArticles(prev => prev.map(a => a.id === updated.id ? updated : a));
      setSelectedArticle(updated);
      setEditing(false);
    } catch (e) {
      toastError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const doDelete = async () => {
    try {
      await api.deleteKBArticle(selectedArticle.id);
      setArticles(prev => prev.filter(a => a.id !== selectedArticle.id));
      setSelectedArticle(null);
      setConfirmDelete(false);
    } catch (e) {
      toastError(e.message);
    }
  };

  const createArticle = async () => {
    setSaving(true);
    try {
      const data = {
        title: newTitle,
        category: newCategory,
        tags: newTags.split(',').map(t => t.trim()).filter(Boolean),
        content: newContent,
      };
      if (newScope === 'project' && selectedProject) data.pid = selectedProject;
      const created = await api.createKBArticle(data);
      setArticles(prev => [created, ...prev]);
      setShowCreate(false);
      setNewTitle(''); setNewCategory('General'); setNewTags(''); setNewContent(''); setNewScope('project');
      setSelectedArticle(created);
    } catch (e) {
      toastError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const sectionBox = { background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10 };

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden', background: '#090b0f' }}>
      {/* Left sidebar */}
      <div style={{ width: 260, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        <div style={{ padding: '14px 16px', borderBottom: '1px solid #1e2029' }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 10 }}>Knowledge Base</div>
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setSelectedArticle(null); setEditing(false); }}
            placeholder="Search articles…"
            style={{ ...inp(), fontSize: 11 }}
          />
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: '8px 0' }}>
          {/* All */}
          <div
            onClick={() => { setSelectedCat(''); setSelectedArticle(null); setEditing(false); }}
            style={{ padding: '7px 16px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: !selectedCat ? accent + '18' : 'transparent', borderLeft: !selectedCat ? `2px solid ${accent}` : '2px solid transparent' }}
            onMouseEnter={e => { if (selectedCat) e.currentTarget.style.background = '#ffffff08'; }}
            onMouseLeave={e => { if (selectedCat) e.currentTarget.style.background = 'transparent'; }}
          >
            <span style={{ fontSize: 12, color: !selectedCat ? accent : '#c8cdd6' }}>All articles</span>
            <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{totalCount}</span>
          </div>
          {/* Categories */}
          {CATEGORIES.map(cat => {
            const count = catCounts[cat] || 0;
            const active = selectedCat === cat;
            const col = categoryColor(cat);
            return (
              <div
                key={cat}
                onClick={() => { setSelectedCat(cat === selectedCat ? '' : cat); setSelectedArticle(null); setEditing(false); }}
                style={{ padding: '7px 16px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: active ? col + '18' : 'transparent', borderLeft: active ? `2px solid ${col}` : '2px solid transparent' }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.background = '#ffffff06'; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
              >
                <span style={{ fontSize: 11, color: active ? col : '#808590' }}>{cat}</span>
                {count > 0 && <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono' }}>{count}</span>}
              </div>
            );
          })}
        </div>
      </div>

      {/* Article list panel */}
      <div style={{ width: 280, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <div style={{ flex: 1, fontSize: 11, color: '#505560', fontFamily: 'JetBrains Mono' }}>
            {filtered.length} article{filtered.length !== 1 ? 's' : ''}
          </div>
          <button
            onClick={() => { setShowCreate(v => !v); setSelectedArticle(null); setEditing(false); }}
            style={{ background: showCreate ? accent + '33' : accent, border: 'none', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono' }}
          >
            + New
          </button>
        </div>
        {error && <div style={{ margin: '8px 12px', background: '#cc233318', border: '1px solid #cc233344', borderRadius: 4, padding: '6px 10px', fontSize: 10, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>{error}</div>}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading && <div style={{ color: '#404550', fontSize: 11, fontFamily: 'JetBrains Mono', textAlign: 'center', padding: 32 }}>Loading…</div>}
          {!loading && filtered.length === 0 && (
            <div style={{ color: '#404550', fontSize: 11, fontFamily: 'JetBrains Mono', textAlign: 'center', padding: 32, lineHeight: 1.6 }}>
              No articles.<br />Click "+ New" to create.
            </div>
          )}
          {filtered.map(art => {
            const isSel = selectedArticle?.id === art.id;
            const col = categoryColor(art.category);
            return (
              <div
                key={art.id}
                onClick={() => { setSelectedArticle(art); setEditing(false); setConfirmDelete(false); setShowCreate(false); }}
                style={{ padding: '10px 14px', cursor: 'pointer', borderBottom: '1px solid #14161b', borderLeft: isSel ? `2px solid ${accent}` : '2px solid transparent', background: isSel ? accent + '10' : 'transparent', transition: 'background .1s' }}
                onMouseEnter={e => { if (!isSel) e.currentTarget.style.background = '#ffffff06'; }}
                onMouseLeave={e => { if (!isSel) e.currentTarget.style.background = 'transparent'; }}
              >
                <div style={{ fontSize: 12, fontWeight: 600, color: isSel ? '#f0f2f6' : '#c8cdd6', fontFamily: 'Space Grotesk', marginBottom: 5, lineHeight: 1.3 }}>{art.title}</div>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                  <span style={{ fontSize: 8, background: col + '18', border: `1px solid ${col}33`, borderRadius: 2, padding: '1px 5px', color: col, fontFamily: 'JetBrains Mono' }}>{art.category}</span>
                  <span style={{ fontSize: 8, background: art.pid ? accent + '18' : '#c07af018', border: `1px solid ${art.pid ? accent + '33' : '#c07af033'}`, borderRadius: 2, padding: '1px 5px', color: art.pid ? accent : '#c07af0', fontFamily: 'JetBrains Mono' }}>{art.pid ? 'PROJECT' : 'GLOBAL'}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Right panel: viewer / editor / create form */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
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
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Tags (comma-separated)</div>
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
                <textarea value={newContent} onChange={e => setNewContent(e.target.value)} placeholder="# Title&#10;&#10;Content in **markdown**..." rows={18} style={{ ...inp(), resize: 'vertical', lineHeight: 1.6 }} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={createArticle} disabled={saving || !newTitle.trim()} style={{ background: newTitle.trim() ? accent : '#1a1c22', border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                  {saving ? 'Creating…' : 'Create'}
                </button>
                <button onClick={() => setShowCreate(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
                  Cancel
                </button>
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
                {/* Header */}
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
                      {selectedArticle.created_at && (
                        <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', marginLeft: 4 }}>{new Date(selectedArticle.created_at).toLocaleDateString()}</span>
                      )}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    <button onClick={() => startEdit(selectedArticle)} style={{ background: 'transparent', border: `1px solid ${accent}44`, borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: 'JetBrains Mono' }}>Edit</button>
                    <button onClick={() => setConfirmDelete(true)} style={{ background: 'transparent', border: '1px solid #cc233344', borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: '#cc2233', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Delete</button>
                  </div>
                </div>
                {/* Content */}
                <div className="kb-markdown" style={{ color: '#c8cdd6', lineHeight: 1.8, fontSize: 13 }}>
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {selectedArticle.content || '*(empty)*'}
                  </ReactMarkdown>
                </div>
              </>
            )}
            {/* Confirm delete dialog */}
            {confirmDelete && (
              <div style={{ marginTop: 20, background: '#cc233318', border: '1px solid #cc233344', borderRadius: 6, padding: '12px 14px' }}>
                <div style={{ fontSize: 12, color: '#f0f2f6', marginBottom: 10 }}>Delete "{selectedArticle.title}"? Cannot be undone.</div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button onClick={doDelete} style={{ background: '#cc2233', border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>Delete</button>
                  <button onClick={() => setConfirmDelete(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Empty state */}
        {!selectedArticle && !showCreate && (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: '#303540' }}>
            <div style={{ fontSize: 32 }}>📖</div>
            <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono', color: '#404550' }}>Select an article to read</div>
          </div>
        )}
      </div>
    </div>
  );
}
