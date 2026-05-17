import { useEffect, useRef, useState } from 'react';
import { api, downloadUrl } from '../api.js';
import Icon from '../components/Icon.jsx';
import { SearchBar } from '../components/UI.jsx';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';

// Filename helpers
const _hasExt = (name) => typeof name === 'string' && /\.[a-z0-9]{1,8}$/i.test(name);
const _extOf = (name) => {
  if (typeof name !== 'string') return '';
  const m = name.match(/\.([a-z0-9]{1,8})$/i);
  return m ? m[1].toLowerCase() : '';
};

/** Build the final download filename without clobbering an existing extension. */
function _downloadFilename(loot, isFileBlob) {
  const fname = (loot.filename || '').trim();
  if (fname) {
    // Always honour the user-stored filename — it's the truth even when
    // there's no public_url (e.g. a text-loot the operator named report.yaml).
    return fname;
  }
  const sourceTail = (loot.source_path || '').split('/').pop() || '';
  if (sourceTail && _hasExt(sourceTail)) return sourceTail;
  // No filename and no extension hint — value-based loot is text, file is bin.
  return isFileBlob ? 'loot.bin' : 'loot.txt';
}

async function downloadLoot(loot) {
  if (loot.public_url) {
    // Real file on disk — fetch with auth and trigger blob download.
    // Backend sets Content-Disposition with the right filename already, but
    // we override here so the operator sees a predictable name.
    const url = downloadUrl(loot.public_url);
    try {
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`${resp.status}`);
      const blob = await resp.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = _downloadFilename(loot, true);
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    } catch (e) {
      alert(`Download failed: ${e.message}`);
    }
  } else {
    // No file — serialize the value as bytes and download.
    const content = loot.value || loot.description || '';
    const blob = new Blob([content], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = _downloadFilename(loot, false);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  }
}

// ── Preview classification ────────────────────────────────────────────
const PREVIEW_EXT = {
  image: new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg', 'ico']),
  pdf:   new Set(['pdf']),
  text:  new Set([
    'txt', 'log', 'md', 'json', 'xml', 'yaml', 'yml', 'csv', 'tsv',
    'conf', 'cnf', 'cfg', 'ini', 'env', 'toml',
    'sh', 'bash', 'zsh', 'ps1', 'py', 'js', 'ts', 'jsx', 'tsx',
    'go', 'rs', 'java', 'c', 'cpp', 'h', 'hpp', 'rb', 'php', 'sql',
    'html', 'htm', 'css',
  ]),
  audio: new Set(['mp3', 'wav', 'ogg', 'flac', 'm4a']),
  video: new Set(['mp4', 'webm', 'mov', 'mkv', 'avi']),
};

function _previewKind(loot) {
  // For attached files: prefer content_type, fall back to extension.
  if (loot.public_url) {
    const ct = (loot.content_type || '').toLowerCase();
    if (ct.startsWith('image/')) return 'image';
    if (ct === 'application/pdf') return 'pdf';
    if (ct.startsWith('text/')) return 'text';
    if (ct.startsWith('audio/')) return 'audio';
    if (ct.startsWith('video/')) return 'video';
    if (ct === 'application/json' || ct === 'application/xml') return 'text';
    const ext = _extOf(loot.filename);
    if (PREVIEW_EXT.image.has(ext)) return 'image';
    if (PREVIEW_EXT.pdf.has(ext))   return 'pdf';
    if (PREVIEW_EXT.text.has(ext))  return 'text';
    if (PREVIEW_EXT.audio.has(ext)) return 'audio';
    if (PREVIEW_EXT.video.has(ext)) return 'video';
    return 'binary';
  }
  // Value-based loot is always text.
  if (loot.value) return 'text';
  return 'none';
}

function _previewable(loot) {
  const k = _previewKind(loot);
  return k !== 'binary' && k !== 'none';
}

const LOOT_TYPES = {
  file:   { label: 'File',    color: '#5b8af5' },
  hash:   { label: 'Hash',    color: '#c07af0' },
  secret: { label: 'Secret',  color: '#e8574a' },
  env:    { label: 'ENV',     color: '#f09a3a' },
  token:  { label: 'Token',   color: '#39d353' },
  key:    { label: 'Key',     color: '#6fc8f0' },
  config: { label: 'Config',  color: '#e8cc42' },
  other:  { label: 'Other',   color: '#606570' },
};

// ── Preview modal ─────────────────────────────────────────────────────
function LootPreviewModal({ loot, onClose }) {
  const kind = _previewKind(loot);
  const [textContent, setTextContent] = useState(loot.public_url ? null : (loot.value || ''));
  const [textError, setTextError] = useState('');

  // Lock body scroll while open
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, []);

  // Close on Esc
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // For file-text previews, fetch the file body lazily.
  useEffect(() => {
    if (kind !== 'text' || !loot.public_url) return;
    let cancelled = false;
    (async () => {
      try {
        const resp = await fetch(downloadUrl(loot.public_url));
        if (!resp.ok) throw new Error(`${resp.status}`);
        const text = await resp.text();
        if (!cancelled) setTextContent(text);
      } catch (e) {
        if (!cancelled) setTextError(e.message || 'Failed to load');
      }
    })();
    return () => { cancelled = true; };
  }, [kind, loot.public_url]);

  const fileUrl = loot.public_url ? downloadUrl(loot.public_url) : '';
  const titleFile = loot.filename || loot.source_path || 'loot';

  return (
    <div onClick={onClose}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.78)', zIndex: 5000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 40 }}>
      <div onClick={e => e.stopPropagation()}
        style={{ background: '#0c0e13', border: '1px solid #2a2d35', borderRadius: 10, width: '100%', maxWidth: 1100, maxHeight: '92vh', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 10px 40px rgba(0,0,0,0.6)' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12, color: '#e0e4ec', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={titleFile}>
              {titleFile}
            </div>
            <div style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono', marginTop: 2 }}>
              {kind} · {loot.content_type || (loot.public_url ? 'binary' : 'text/plain')}
              {loot.file_size ? ` · ${_formatBytes(loot.file_size)}` : ''}
            </div>
          </div>
          <button onClick={() => downloadLoot(loot)} title="Download"
            style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
            <Icon name="export" size={11} color="#9098a8" /> Download
          </button>
          <button onClick={onClose} title="Close (Esc)"
            style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', cursor: 'pointer', display: 'flex' }}>
            <Icon name="close" size={11} color="#9098a8" />
          </button>
        </div>
        {/* Body */}
        <div style={{ flex: 1, overflow: 'auto', background: '#07080b', display: 'flex', alignItems: 'stretch', justifyContent: 'center' }}>
          {kind === 'image' && (
            <img src={fileUrl} alt={titleFile} style={{ maxWidth: '100%', maxHeight: '86vh', objectFit: 'contain', alignSelf: 'center', margin: 'auto', display: 'block' }} />
          )}
          {kind === 'pdf' && (
            <iframe title={titleFile} src={fileUrl} style={{ width: '100%', height: '86vh', border: 'none', background: '#0a0c10' }} />
          )}
          {kind === 'text' && textContent != null && (
            <pre style={{ width: '100%', margin: 0, padding: 16, color: '#c8cdd6', fontSize: 12, fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflow: 'auto' }}>
              {textContent}
            </pre>
          )}
          {kind === 'text' && textContent == null && !textError && (
            <div style={{ padding: 40, color: '#505560', fontSize: 12, fontFamily: 'JetBrains Mono' }}>Loading…</div>
          )}
          {kind === 'text' && textError && (
            <div style={{ padding: 40, color: '#cc2233', fontSize: 12, fontFamily: 'JetBrains Mono' }}>Failed to load: {textError}</div>
          )}
          {kind === 'audio' && (
            <audio controls src={fileUrl} style={{ alignSelf: 'center', margin: 'auto', width: '60%' }} />
          )}
          {kind === 'video' && (
            <video controls src={fileUrl} style={{ maxWidth: '100%', maxHeight: '86vh', alignSelf: 'center', margin: 'auto' }} />
          )}
          {(kind === 'binary' || kind === 'none') && (
            <div style={{ padding: 60, color: '#606570', fontSize: 12, fontFamily: 'JetBrains Mono', textAlign: 'center', alignSelf: 'center', margin: 'auto' }}>
              <div style={{ fontSize: 36, marginBottom: 14 }}>📦</div>
              <div style={{ marginBottom: 6, color: '#9098a8' }}>No inline preview available for this file type.</div>
              <div>Use the Download button to retrieve the original.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function _formatBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

function TypeBadge({ type }) {
  const t = LOOT_TYPES[type] || LOOT_TYPES.other;
  return (
    <span style={{ fontSize: 9, fontWeight: 700, color: t.color, background: t.color + '22', border: `1px solid ${t.color}44`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
      {t.label}
    </span>
  );
}

const EMPTY = { loot_type: 'file', value: '', description: '', source_path: '', host_id: null };

export default function LootView({ loots, hosts, onAdd, onUpdate, onDelete, selectedProject, accent, fs = 14 }) {
  const { can, isSuperAdmin } = useProjectPermissions();
  const canReadSecret = isSuperAdmin || can('credentials.read_secret');
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [newLoot, setNewLoot] = useState(EMPTY);
  const [selectedId, setSelectedId] = useState(null);
  const [previewLootId, setPreviewLootId] = useState(null);
  const [showValues, setShowValues] = useState({});
  const [copied, setCopied] = useState(null);
  const [uploading, setUploading] = useState(false);
  const addFileRef = useRef(null);
  const editFileRef = useRef(null);

  const projectLoots = loots.filter(l => l.pid === selectedProject);
  const projectHosts = (hosts || []).filter(h => h.pid === selectedProject);

  const filtered = projectLoots
    .filter(l => !filterType || l.loot_type === filterType)
    .filter(l => !search || [l.value, l.description, l.source_path].join(' ').toLowerCase().includes(search.toLowerCase()));

  const selLoot = projectLoots.find(l => l.id === selectedId);

  const typeCounts = Object.keys(LOOT_TYPES).reduce((acc, k) => {
    acc[k] = projectLoots.filter(l => l.loot_type === k).length;
    return acc;
  }, {});

  const copy = (text, id) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  };

  const addLoot = () => {
    if (!newLoot.value.trim() && !newLoot.description.trim()) return;
    onAdd({ pid: selectedProject, ...newLoot });
    setNewLoot(EMPTY);
    setShowAdd(false);
  };

  const uploadFileForLoot = async (lootId, file) => {
    if (!file) return;
    setUploading(true);
    try {
      const updated = await api.uploadLootFile(lootId, file);
      await onUpdate(lootId, updated);
    } finally {
      setUploading(false);
    }
  };

  const createLootWithFile = async (file) => {
    if (!file) return;
    setUploading(true);
    try {
      const loot = await onAdd({ pid: selectedProject, ...newLoot, loot_type: 'file', value: file.name || newLoot.value || 'uploaded file' });
      await uploadFileForLoot(loot.id, file);
      setNewLoot(EMPTY);
      setShowAdd(false);
    } finally {
      setUploading(false);
    }
  };

  const hostLabel = (host_id) => {
    const h = projectHosts.find(h => h.id === host_id);
    return h ? (h.hostname || h.ip) : null;
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <div style={{ flex: 1 }}>
          <span style={{ fontSize: fs + 1, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>loot</span>
          <span style={{ fontSize: Math.max(10, fs - 2), color: '#404550', marginLeft: 10 }}>{filtered.length} of {projectLoots.length}</span>
        </div>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {Object.entries(LOOT_TYPES).map(([k, v]) => {
            if (!typeCounts[k]) return null;
            return (
              <button key={k} onClick={() => setFilterType(filterType === k ? null : k)}
                style={{ background: filterType === k ? v.color + '22' : 'transparent', border: `1px solid ${filterType === k ? v.color + '88' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: filterType === k ? v.color : '#505560', fontFamily: 'JetBrains Mono', transition: 'all .12s' }}>
                {v.label} {typeCounts[k]}
              </button>
            );
          })}
        </div>
        <div style={{ width: 200 }}><SearchBar value={search} onChange={setSearch} placeholder="Value, description..." /></div>
        <button onClick={() => setShowAdd(v => !v)}
          style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
          <Icon name="plus" size={10} color="#fff" /> Add
        </button>
      </div>

      {/* Quick add */}
      {showAdd && (
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0c0e13', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Type</div>
            <select value={newLoot.loot_type} onChange={e => setNewLoot(l => ({ ...l, loot_type: e.target.value }))}
              style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              {Object.entries(LOOT_TYPES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
          </div>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Value</div>
            <input value={newLoot.value} onChange={e => setNewLoot(l => ({ ...l, value: e.target.value }))} autoFocus
              placeholder="Password, hash, file path..."
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
          </div>
          <div style={{ width: 160 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Description</div>
            <input value={newLoot.description} onChange={e => setNewLoot(l => ({ ...l, description: e.target.value }))}
              placeholder="Where from, what is it..."
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
          </div>
          <div style={{ width: 140 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Path / source</div>
            <input value={newLoot.source_path} onChange={e => setNewLoot(l => ({ ...l, source_path: e.target.value }))}
              placeholder="/etc/shadow"
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
          </div>
          <div style={{ width: 140 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Host</div>
            <select value={newLoot.host_id || ''} onChange={e => setNewLoot(l => ({ ...l, host_id: e.target.value || null }))}
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              <option value="">—</option>
              {projectHosts.map(h => <option key={h.id} value={h.id}>{h.hostname || h.ip}</option>)}
            </select>
          </div>
          <input ref={addFileRef} type="file" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && createLootWithFile(e.target.files[0])} />
          <button onClick={addLoot}
            style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
            Save
          </button>
          <button onClick={() => addFileRef.current?.click()}
            style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 12px', cursor: 'pointer', color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
            {uploading ? 'Uploading…' : 'Upload file'}
          </button>
          <button onClick={() => setShowAdd(false)}
            style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
            Cancel
          </button>
        </div>
      )}

      {/* Table header */}
      <div style={{ display: 'flex', alignItems: 'center', padding: '8px 18px', borderBottom: '1px solid #1a1c22', background: '#090b0f', flexShrink: 0, gap: 12 }}>
        {[['Type', 80], ['Value', 0], ['Description', 200], ['Source', 160], ['Host', 120]].map(([l, w]) => (
          <div key={l} style={{ width: w || undefined, flex: w ? undefined : 1, fontSize: Math.max(9, fs - 4), color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{l}</div>
        ))}
        <div style={{ width: 60 }} />
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && (
            <div style={{ padding: 48, textAlign: 'center', color: '#303540' }}>
              <Icon name="loot" size={36} color="#2a2d35" />
              <div style={{ marginTop: 12, fontSize: 13, color: '#404550' }}>No loot. Add the first trophy.</div>
            </div>
          )}
          {filtered.map(loot => {
            const shown = showValues[loot.id];
            const isSel = selectedId === loot.id;
            const isCopied = copied === loot.id;
            const hl = hostLabel(loot.host_id);
            return (
              <div key={loot.id} onClick={() => setSelectedId(isSel ? null : loot.id)}
                style={{ display: 'flex', alignItems: 'center', minHeight: 44, padding: '8px 18px', borderBottom: '1px solid #14161b', gap: 12, cursor: 'pointer', background: isSel ? '#ffffff06' : 'transparent', borderLeft: isSel ? `2px solid ${accent}` : '2px solid transparent', transition: 'background .1s' }}
                onMouseEnter={e => !isSel && (e.currentTarget.style.background = '#ffffff04')}
                onMouseLeave={e => !isSel && (e.currentTarget.style.background = 'transparent')}>
                <div style={{ width: 80, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <TypeBadge type={loot.loot_type} />
                  {loot.artifact_type && loot.artifact_type !== 'file' && (
                    <span style={{ fontSize: 8, color: '#808590', background: '#80859018', border: '1px solid #80859033', borderRadius: 3, padding: '1px 4px', fontFamily: 'JetBrains Mono' }}>{loot.artifact_type.replace('_', ' ')}</span>
                  )}
                </div>
                <div style={{ flex: 1, minWidth: 0, fontFamily: 'JetBrains Mono', fontSize: Math.max(10, fs - 3), color: shown ? '#c8cdd6' : '#606570', filter: (canReadSecret && shown) ? 'none' : 'blur(5px)', transition: 'filter .2s', userSelect: (canReadSecret && shown) ? 'text' : 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {canReadSecret ? (loot.value || '(empty)') : '••••••••'}
                </div>
                <div style={{ width: 200, flexShrink: 0, fontSize: Math.max(10, fs - 3), color: '#808590', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {loot.description || '—'}
                </div>
                 <div style={{ width: 160, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: '#505560', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                   {loot.filename || loot.source_path || '—'}
                </div>
                <div style={{ width: 120, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: '#5b8af5', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {hl || '—'}
                </div>
                <div style={{ width: 60, display: 'flex', gap: 4, alignItems: 'center' }} onClick={e => e.stopPropagation()}>
                  {canReadSecret && (
                    <button onClick={() => setShowValues(p => ({ ...p, [loot.id]: !p[loot.id] }))} title={shown ? 'Hide' : 'Show'}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', display: 'flex', padding: 2 }}
                      onMouseEnter={e => e.currentTarget.style.color = '#9098a8'}
                      onMouseLeave={e => e.currentTarget.style.color = '#404550'}>
                      <Icon name={shown ? 'eyeOff' : 'eye'} size={12} color="currentColor" />
                    </button>
                  )}
                  {canReadSecret && (
                    <button onClick={() => copy(loot.value, loot.id)} title="Copy"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: isCopied ? '#39d353' : '#404550', display: 'flex', padding: 2 }}>
                      <Icon name={isCopied ? 'check' : 'copy'} size={12} color="currentColor" />
                    </button>
                  )}
                  {_previewable(loot) && (
                    <button onClick={() => setPreviewLootId(loot.id)} title="Preview"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', display: 'flex', padding: 2 }}
                      onMouseEnter={e => e.currentTarget.style.color = '#c07af0'}
                      onMouseLeave={e => e.currentTarget.style.color = '#404550'}>
                      <Icon name="eye" size={12} color="currentColor" />
                    </button>
                  )}
                  <button onClick={() => downloadLoot(loot)} title="Download"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: loot.public_url ? '#5b8af5' : '#404550', display: 'flex', padding: 2 }}
                    onMouseEnter={e => e.currentTarget.style.color = '#5b8af5'}
                    onMouseLeave={e => e.currentTarget.style.color = loot.public_url ? '#5b8af5' : '#404550'}>
                    <Icon name="export" size={12} color="currentColor" />
                  </button>
                  <button onClick={() => { onDelete(loot.id); if (selectedId === loot.id) setSelectedId(null); }}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', padding: 2 }}
                    onMouseEnter={e => e.currentTarget.style.color = '#cc2233'}
                    onMouseLeave={e => e.currentTarget.style.color = '#303540'}>
                    <Icon name="trash" size={12} color="currentColor" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Edit panel */}
        {selLoot && (
          <div style={{ width: 280, background: '#0c0e13', borderLeft: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
            <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>Edit</span>
              <button onClick={() => setSelectedId(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
                <Icon name="close" size={12} color="#606570" />
              </button>
            </div>
            <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Type</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {Object.entries(LOOT_TYPES).map(([k, v]) => (
                    <button key={k} onClick={() => onUpdate(selLoot.id, { loot_type: k })}
                      style={{ background: selLoot.loot_type === k ? v.color + '22' : '#0e1016', border: `1px solid ${selLoot.loot_type === k ? v.color + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: selLoot.loot_type === k ? v.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
                      {v.label}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Value</div>
                <textarea value={selLoot.value} onChange={e => onUpdate(selLoot.id, { value: e.target.value })} rows={4}
                  style={{ width: '100%', background: '#07080b', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box' }} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Description</div>
                <input value={selLoot.description} onChange={e => onUpdate(selLoot.id, { description: e.target.value })}
                  style={{ width: '100%', background: '#07080b', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Source / path</div>
                <input value={selLoot.source_path} onChange={e => onUpdate(selLoot.id, { source_path: e.target.value })}
                  placeholder="/etc/shadow, proc memory..."
                  style={{ width: '100%', background: '#07080b', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Host</div>
                <select value={selLoot.host_id || ''} onChange={e => onUpdate(selLoot.id, { host_id: e.target.value || null })}
                  style={{ width: '100%', background: '#07080b', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
                  <option value="">— not linked —</option>
                  {projectHosts.map(h => <option key={h.id} value={h.id}>{h.hostname || h.ip}</option>)}
                </select>
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Attached file</div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                  <input ref={editFileRef} type="file" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && uploadFileForLoot(selLoot.id, e.target.files[0])} />
                  <button onClick={() => editFileRef.current?.click()} style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{uploading ? 'Uploading…' : 'Upload / replace'}</button>
                  {_previewable(selLoot) && (
                    <button onClick={() => setPreviewLootId(selLoot.id)} style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#c07af0', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
                      <Icon name="eye" size={11} color="#c07af0" /> Preview
                    </button>
                  )}
                  <button onClick={() => downloadLoot(selLoot)} style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: selLoot.public_url ? '#5b8af5' : '#808590', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                    Download{selLoot.filename ? ` (${(_extOf(selLoot.filename) || (selLoot.public_url ? 'bin' : 'txt')).toUpperCase()})` : (selLoot.public_url ? '' : ' (TXT)')}
                  </button>
                </div>
                <div style={{ fontSize: 10, color: '#606570', marginTop: 6, fontFamily: 'JetBrains Mono' }}>{selLoot.filename ? `${selLoot.filename}${selLoot.file_size ? ` · ${selLoot.file_size} bytes` : ''}` : 'No file attached'}</div>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button onClick={() => { navigator.clipboard?.writeText(selLoot.value).catch(() => {}); setCopied('panel'); setTimeout(() => setCopied(null), 1500); }}
                  style={{ flex: 1, background: copied === 'panel' ? '#39d35322' : '#1a1c22', border: `1px solid ${copied === 'panel' ? '#39d35366' : '#2a2d35'}`, borderRadius: 4, padding: '6px', cursor: 'pointer', color: copied === 'panel' ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5 }}>
                  <Icon name={copied === 'panel' ? 'check' : 'copy'} size={11} color="currentColor" />
                  {copied === 'panel' ? 'Copied' : 'Copy'}
                </button>
              </div>
              {selLoot.sha256 && (
                <div style={{ fontSize: 8, color: '#303540', fontFamily: 'JetBrains Mono', wordBreak: 'break-all' }}>sha256: {selLoot.sha256}</div>
              )}
              {selLoot.job_id && (
                <div style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>Source job: <span style={{ color: '#5b8af5' }}>{selLoot.job_id}</span></div>
              )}
              <div style={{ fontSize: 9, color: '#303540', fontFamily: 'JetBrains Mono' }}>{selLoot.ts}</div>
            </div>
          </div>
        )}
      </div>
      {/* Preview modal */}
      {previewLootId && (() => {
        const pl = loots.find(l => l.id === previewLootId);
        if (!pl) return null;
        return <LootPreviewModal loot={pl} onClose={() => setPreviewLootId(null)} />;
      })()}
    </div>
  );
}
