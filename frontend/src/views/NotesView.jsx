import { useEffect, useRef, useState } from 'react';
import { toastError } from '../components/Toast.jsx';
import Icon from '../components/Icon.jsx';
import MdEditor from '../components/MdEditor.jsx';
import { PhaseTag, Btn, SearchBar } from '../components/UI.jsx';
import { PHASES, PHASE_COLORS } from '../constants.js';
import { api } from '../api.js';

// Deterministic color from username
function userColor(name) {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) & 0xffffff;
  return `hsl(${h % 360}, 60%, 55%)`;
}

function UserDot({ name, size = 18 }) {
  const color = userColor(name);
  const initials = name.slice(0, 2).toUpperCase();
  return (
    <span title={name} style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: size, height: size, borderRadius: '50%', background: color + '33', border: `1px solid ${color}88`, color, fontSize: size * 0.44, fontWeight: 700, fontFamily: 'JetBrains Mono', flexShrink: 0, letterSpacing: 0 }}>
      {initials}
    </span>
  );
}

function PhaseDropdown({ value, onChange }) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, [open]);
  return (
    <div style={{ position: 'relative' }} onClick={e => e.stopPropagation()}>
      <div onClick={() => setOpen(v => !v)} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5 }}>
        <PhaseTag phase={value} small />
        <Icon name="chevron" size={10} color="#404550" />
      </div>
      {open && (
        <div style={{ position: 'absolute', top: '100%', left: 0, marginTop: 4, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, padding: 6, zIndex: 200, display: 'flex', flexDirection: 'column', gap: 3, minWidth: 120, boxShadow: '0 8px 24px #00000066' }}>
          {PHASES.map(ph => (
            <button key={ph} onClick={() => { onChange(ph); setOpen(false); }} style={{ background: value === ph ? `${PHASE_COLORS[ph]}22` : 'transparent', border: `1px solid ${value === ph ? PHASE_COLORS[ph] + '66' : 'transparent'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', textAlign: 'left' }}>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, color: PHASE_COLORS[ph], textTransform: 'uppercase' }}>{ph}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function AttachmentBar({ attachments, uploading, accent, onRemove }) {
  if (!attachments.length && !uploading) return null;
  const typeIcon = (ct = '', fn = '') => {
    const ext = fn.split('.').pop().toLowerCase();
    if (ct.startsWith('image/')) return '🖼';
    if (ct.startsWith('video/')) return '🎬';
    if (ct.startsWith('audio/')) return '🎵';
    if (ext === 'pdf') return '📄';
    const codeExts = ['py','js','ts','sh','bash','ps1','go','rb','java','c','cpp','cs','php','sql','json','xml','yaml','yml'];
    if (codeExts.includes(ext)) return '📋';
    return '📎';
  };
  return (
    <div style={{ padding: '5px 20px', borderBottom: '1px solid #14161b', background: '#070809', display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', flexShrink: 0 }}>
      <span style={{ fontSize: 9, color: '#303540', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', marginRight: 4 }}>Attachments</span>
      {attachments.map(att => (
        <div key={att.id} style={{ display: 'flex', alignItems: 'center', gap: 5, background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 5, padding: '3px 8px' }}>
          <span style={{ fontSize: 12 }}>{typeIcon(att.content_type, att.filename)}</span>
          <a href={att.public_url} target="_blank" rel="noreferrer" style={{ color: '#6fc8f0', fontSize: 10, fontFamily: 'JetBrains Mono', textDecoration: 'none', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {att.filename}
          </a>
          <button onClick={() => onRemove(att)} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'flex', color: '#404550' }}>
            <Icon name="close" size={9} color="currentColor" />
          </button>
        </div>
      ))}
      {uploading && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: accent, fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          <div style={{ width: 10, height: 10, border: `2px solid ${accent}33`, borderTopColor: accent, borderRadius: '50%', animation: 'spin 0.6s linear infinite' }} />
          Uploading...
        </div>
      )}
    </div>
  );
}

function UnsavedDialog({ accent, onSave, onDiscard, onCancel }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 10, padding: '28px 32px', width: 360, boxShadow: '0 20px 60px #00000088' }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 8 }}>Unsaved changes</div>
        <div style={{ fontSize: 12, color: '#808590', lineHeight: 1.6, marginBottom: 24 }}>
          The note has been modified. Save changes before leaving?
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onCancel} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
          <button onClick={onDiscard} style={{ background: 'none', border: '1px solid #cc223366', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#cc2233', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Discard</button>
          <button onClick={onSave} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>Save</button>
        </div>
      </div>
    </div>
  );
}

function ConflictDialog({ accent, myContent, serverNote, onOverwrite, onLoadServer, onCancel }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #cc233344', borderRadius: 12, padding: '28px 32px', width: 560, boxShadow: '0 24px 64px #00000099' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <Icon name="warning" size={18} color="#cc2233" />
          <div style={{ fontSize: 15, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Version conflict</div>
        </div>
        <div style={{ fontSize: 12, color: '#808590', lineHeight: 1.7, marginBottom: 18 }}>
          While you were editing, another user saved this note. Choose how to proceed:
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 22 }}>
          <div style={{ background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '10px 12px' }}>
            <div style={{ fontSize: 9, color: '#606570', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Your version</div>
            <div style={{ fontSize: 10, color: '#9098a8', fontFamily: 'JetBrains Mono', lineHeight: 1.5, maxHeight: 100, overflow: 'hidden', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {myContent.slice(0, 300)}{myContent.length > 300 ? '...' : ''}
            </div>
          </div>
          <div style={{ background: '#0a0c10', border: '1px solid #cc233333', borderRadius: 6, padding: '10px 12px' }}>
            <div style={{ fontSize: 9, color: '#cc2233', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Server version · v{serverNote.version}</div>
            <div style={{ fontSize: 10, color: '#9098a8', fontFamily: 'JetBrains Mono', lineHeight: 1.5, maxHeight: 100, overflow: 'hidden', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {(serverNote.content || '').slice(0, 300)}{(serverNote.content || '').length > 300 ? '...' : ''}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onCancel} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Continue editing</button>
          <button onClick={onLoadServer} style={{ background: 'none', border: '1px solid #5b8af566', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#5b8af5', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Load their version</button>
          <button onClick={onOverwrite} style={{ background: '#cc2233', border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>Overwrite with mine</button>
        </div>
      </div>
    </div>
  );
}

export default function NotesView({ notes, onAdd, onUpdate, onDelete, projects, selectedProject, accent, fs, presence = [], onFocus, username }) {
  const [search, setSearch] = useState('');
  const [filterPhase, setFilterPhase] = useState(null);
  const [selectedNote, setSelectedNote] = useState(null);
  const [editing, setEditing] = useState(false);
  const [editContent, setEditContent] = useState('');
  const [editTitle, setEditTitle] = useState('');
  const [editPhase, setEditPhase] = useState('recon');
  const [editTags, setEditTags] = useState('');
  const [attachments, setAttachments] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [pendingNoteId, setPendingNoteId] = useState(null);
  const [baseVersion, setBaseVersion] = useState(null);
  const [remoteUpdated, setRemoteUpdated] = useState(false);
  const [conflictNote, setConflictNote] = useState(null);
  const prevVersionRef = useRef(null);

  const selNote = notes.find(n => n.id === selectedNote);

  const isDirty = editing && selNote && (
    editContent !== (selNote.content || '') ||
    editTitle   !== (selNote.title   || '') ||
    editPhase   !== (selNote.phase   || 'recon') ||
    editTags    !== (selNote.tags || []).join(', ')
  );

  // Detect external update while editing
  useEffect(() => {
    if (!editing || !selNote || baseVersion === null) {
      prevVersionRef.current = selNote?.version ?? null;
      return;
    }
    const prev = prevVersionRef.current;
    prevVersionRef.current = selNote.version;
    if (prev !== null && selNote.version > prev) {
      setRemoteUpdated(true);
    }
  }, [selNote?.version, editing, baseVersion]);

  const trySelectNote = (id) => {
    if (isDirty && id !== selectedNote) {
      setPendingNoteId(id);
      return;
    }
    selectNote(id);
  };

  const selectNote = (id) => {
    setSelectedNote(id);
    setEditing(false);
    setBaseVersion(null);
    setRemoteUpdated(false);
    setConflictNote(null);
    onFocus?.(id);
  };

  const proj = projects.find(p => p.id === selectedProject);
  const filtered = notes
    .filter(n => n.pid === selectedProject)
    .filter(n => !filterPhase || n.phase === filterPhase)
    .filter(n => !search || [n.title, (n.tags || []).join(' '), n.content].join(' ').toLowerCase().includes(search.toLowerCase()));

  useEffect(() => {
    if (!selNote) return;
    setEditContent(selNote.content || '');
    setEditTitle(selNote.title || '');
    setEditPhase(selNote.phase || 'recon');
    setEditTags((selNote.tags || []).join(', '));
    api.getNoteAttachments(selNote.id).then(setAttachments).catch(() => setAttachments([]));
  }, [selectedNote, selNote?.id]);

  const startEditing = () => {
    setBaseVersion(selNote?.version ?? 0);
    setRemoteUpdated(false);
    setConflictNote(null);
    setEditing(true);
    setEditContent(selNote.content || '');
    setEditTitle(selNote.title || '');
    setEditPhase(selNote.phase || 'recon');
    setEditTags((selNote.tags || []).join(', '));
  };

  const saveNote = async (thenGoTo = null, forceVersion = null) => {
    const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
    try {
      await onUpdate(selectedNote, {
        content: editContent, title: editTitle,
        phase: editPhase,
        tags: editTags.split(',').map(t => t.trim()).filter(Boolean),
        ts,
        client_version: forceVersion !== null ? forceVersion : baseVersion,
      });
      setEditing(false);
      setBaseVersion(null);
      setRemoteUpdated(false);
      setConflictNote(null);
      if (thenGoTo) { setSelectedNote(thenGoTo); setPendingNoteId(null); onFocus?.(thenGoTo); }
    } catch (err) {
      if (err.status === 409) {
        setConflictNote(err.serverNote);
      } else {
        toastError(`Save error: ${err.message}`);
      }
    }
  };

  const addNote = () => {
    const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
    onAdd({ pid: selectedProject, title: 'New note', phase: 'recon', tags: [], content: '# New note\n\n', ts, starred: false });
  };

  const uploadAttachment = async (file) => {
    if (!selNote || !file) return;
    setUploading(true);
    try {
      const att = await api.uploadNoteAttachment(selNote.id, file);
      setAttachments(prev => [...prev, att]);
      const ct = att.content_type || '';
      const snippet = ct.startsWith('image/') ? `\n![${att.filename}](${att.public_url})\n` : `\n[${att.filename}](${att.public_url})\n`;
      const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
      if (editing) {
        const newContent = editContent + snippet;
        setEditContent(newContent);
        onUpdate(selNote.id, { content: newContent, ts });
      } else {
        const newContent = (selNote.content || '') + snippet;
        onUpdate(selNote.id, { content: newContent, ts });
        setEditContent(newContent);
        setEditing(true);
      }
    } catch (err) {
      toastError(`Upload error: ${err.message}`);
    } finally {
      setUploading(false);
    }
  };

  const removeAttachment = async (att) => {
    await api.deleteAttachment(att.id);
    setAttachments(prev => prev.filter(x => x.id !== att.id));
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (!selNote) return;
    for (const file of Array.from(e.dataTransfer.files)) await uploadAttachment(file);
  };

  // Build presence map: note_id -> list of users (excluding self)
  const presenceMap = {};
  for (const u of presence) {
    if (u.note_id && u.name !== username) {
      (presenceMap[u.note_id] = presenceMap[u.note_id] || []).push(u.name);
    }
  }

  // Other users editing the currently selected note
  const editingHere = selNote ? (presenceMap[selNote.id] || []) : [];

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {pendingNoteId && (
        <UnsavedDialog
          accent={accent}
          onSave={() => saveNote(pendingNoteId)}
          onDiscard={() => { setEditing(false); selectNote(pendingNoteId); setPendingNoteId(null); }}
          onCancel={() => setPendingNoteId(null)}
        />
      )}

      {conflictNote && (
        <ConflictDialog
          accent={accent}
          myContent={editContent}
          serverNote={conflictNote}
          onOverwrite={() => saveNote(null, conflictNote.version)}
          onLoadServer={() => {
            setEditContent(conflictNote.content || '');
            setEditTitle(conflictNote.title || selNote?.title || '');
            setBaseVersion(conflictNote.version);
            setConflictNote(null);
            setRemoteUpdated(false);
          }}
          onCancel={() => setConflictNote(null)}
        />
      )}

      {/* ── Note list ── */}
      <div style={{ width: 272, background: '#0a0c10', borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        <div style={{ padding: '12px 14px', borderBottom: '1px solid #1a1c22' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: fs, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
              {proj?.name}
            </span>
            <button onClick={addNote} style={{ background: accent, border: 'none', borderRadius: 4, padding: '3px 9px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'JetBrains Mono', flexShrink: 0, marginLeft: 8 }}>
              <Icon name="plus" size={10} color="#fff" />
            </button>
          </div>
          <SearchBar value={search} onChange={setSearch} />
        </div>
        <div style={{ padding: '6px 12px', borderBottom: '1px solid #1a1c22', display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {PHASES.map(ph => {
            const cnt = notes.filter(n => n.pid === selectedProject && n.phase === ph).length;
            if (!cnt) return null;
            const active = filterPhase === ph;
            const c = PHASE_COLORS[ph];
            return (
              <button key={ph} onClick={() => setFilterPhase(active ? null : ph)} style={{ background: active ? `${c}22` : 'transparent', border: `1px solid ${active ? c + '88' : '#2a2d35'}`, borderRadius: 3, padding: '2px 6px', cursor: 'pointer', fontSize: 9, color: active ? c : '#505560', fontFamily: 'JetBrains Mono', fontWeight: 600, textTransform: 'uppercase' }}>
                {ph}
              </button>
            );
          })}
        </div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {filtered.length === 0 && <div style={{ padding: 20, textAlign: 'center', color: '#404550', fontSize: 11 }}>No notes</div>}
          {filtered.map(note => {
            const active = note.id === selectedNote;
            const viewers = presenceMap[note.id] || [];
            return (
              <div
                key={note.id}
                onClick={() => trySelectNote(note.id)}
                style={{ padding: '11px 14px', cursor: 'pointer', background: active ? '#ffffff0a' : 'transparent', borderBottom: '1px solid #14161b', borderLeft: active ? `2px solid ${accent}` : '2px solid transparent', transition: 'background .1s' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <PhaseTag phase={note.phase} small />
                  {note.starred && <Icon name="star" size={10} color="#f09a3a" />}
                  {viewers.length > 0 && (
                    <div style={{ marginLeft: 'auto', display: 'flex', gap: 2 }}>
                      {viewers.slice(0, 3).map(n => <UserDot key={n} name={n} size={16} />)}
                    </div>
                  )}
                </div>
                <div style={{ fontSize: fs - 1, color: active ? '#f0f2f6' : '#b0b5c2', marginBottom: 4, lineHeight: 1.4, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                  {note.title}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: 9, color: '#404550' }}>{note.ts}</span>
                  <div style={{ display: 'flex', gap: 4 }}>
                    {(note.tags || []).slice(0, 2).map(t => (
                      <span key={t} style={{ fontSize: 9, color: '#505560', background: '#1a1c22', padding: '1px 5px', borderRadius: 3 }}>{t}</span>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Note content ── */}
      {selNote ? (
        <div
          style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, position: 'relative' }}
          onDrop={handleDrop}
          onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={e => { if (!e.currentTarget.contains(e.relatedTarget)) setIsDragging(false); }}
        >
          {isDragging && (
            <div style={{ position: 'absolute', inset: 0, background: `${accent}18`, border: `2px dashed ${accent}`, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100, pointerEvents: 'none', backdropFilter: 'blur(2px)' }}>
              <div style={{ fontSize: 15, fontWeight: 600, color: accent, fontFamily: 'Space Grotesk' }}>Drop to upload</div>
            </div>
          )}

          {/* Header */}
          <div style={{ padding: '10px 20px', borderBottom: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 10, background: '#0a0c10', flexShrink: 0 }}>
            {editing
              ? <input value={editTitle} onChange={e => setEditTitle(e.target.value)} style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', fontSize: 15, fontWeight: 600, color: '#f0f2f6', fontFamily: 'Space Grotesk' }} />
              : <div style={{ flex: 1, fontSize: 15, fontWeight: 600, color: '#f0f2f6', fontFamily: 'Space Grotesk', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selNote.title}</div>
            }
            {/* Who's here */}
            {editingHere.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                {editingHere.slice(0, 4).map(n => <UserDot key={n} name={n} size={20} />)}
              </div>
            )}
            {isDirty && <span title="Unsaved changes" style={{ width: 7, height: 7, borderRadius: '50%', background: accent, display: 'inline-block', flexShrink: 0, boxShadow: `0 0 6px ${accent}` }} />}
            {!editing && (
              <>
                <Btn icon="terminal" onClick={startEditing}>Edit</Btn>
                <button onClick={() => onUpdate(selNote.id, { starred: !selNote.starred })} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 4, display: 'flex' }}>
                  <Icon name={selNote.starred ? 'star' : 'starO'} size={15} color={selNote.starred ? '#f09a3a' : '#404550'} />
                </button>
                <button onClick={() => { onDelete(selNote.id); setSelectedNote(null); onFocus?.(null); }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 4, display: 'flex', color: '#404550' }}>
                  <Icon name="trash" size={14} color="currentColor" />
                </button>
              </>
            )}
          </div>

          {/* Remote update banner */}
          {remoteUpdated && editing && !conflictNote && (
            <div style={{ padding: '7px 20px', background: '#f09a3a18', borderBottom: '1px solid #f09a3a44', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
              <Icon name="warning" size={12} color="#f09a3a" />
              <span style={{ fontSize: 11, color: '#f09a3a', flex: 1 }}>Another user modified this note. Saving may cause a conflict.</span>
              <button onClick={() => setRemoteUpdated(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'flex' }}>
                <Icon name="close" size={10} color="#f09a3a" />
              </button>
            </div>
          )}

          {/* Meta bar */}
          <div style={{ padding: '6px 20px', borderBottom: '1px solid #14161b', background: '#080a0e', display: 'flex', alignItems: 'center', gap: 16, flexShrink: 0, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="target" size={11} color="#404550" />
              <span style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono' }}>{proj?.ip || '—'}</span>
            </div>
            {editing
              ? <select value={editPhase} onChange={e => setEditPhase(e.target.value)} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                  {PHASES.map(ph => <option key={ph} value={ph}>{ph}</option>)}
                </select>
              : <PhaseDropdown value={selNote.phase} onChange={v => onUpdate(selNote.id, { phase: v, ts: new Date().toISOString().slice(0, 16).replace('T', ' ') })} />
            }
            {editing
              ? <input value={editTags} onChange={e => setEditTags(e.target.value)} placeholder="tag1, tag2" style={{ background: 'transparent', border: 'none', borderBottom: `1px solid ${accent}44`, outline: 'none', color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono', width: 220 }} />
              : <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{(selNote.tags || []).map(t => <span key={t} style={{ fontSize: 9, color: '#505560', background: '#1a1c22', padding: '1px 6px', borderRadius: 3 }}>{t}</span>)}</div>
            }
            <div style={{ marginLeft: 'auto', fontSize: 9, color: '#303540' }}>{selNote.ts}</div>
          </div>

          {/* Attachments bar */}
          <AttachmentBar attachments={attachments} uploading={uploading} accent={accent} onRemove={removeAttachment} />

          {/* Content area */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
            {editing ? (
              <MdEditor
                value={editContent}
                onChange={setEditContent}
                accent={accent}
                onUpload={uploadAttachment}
                uploading={uploading}
                onSave={() => saveNote()}
                onCancel={() => { setEditing(false); setBaseVersion(null); setRemoteUpdated(false); }}
              />
            ) : (
              <MdEditor value={selNote.content || ''} accent={accent} readOnly />
            )}
          </div>
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12, color: '#303540' }}>
          <Icon name="notes" size={36} color="#2a2d35" />
          <div style={{ fontSize: 13 }}>Select a note or create a new one</div>
        </div>
      )}
    </div>
  );
}
