import { useState, useMemo, useEffect } from 'react';
import { toastError } from '../components/Toast.jsx';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import CredMatrix from '../components/CredMatrix.jsx';
import { Badge, CredTypeBadge, SearchBar, FieldInput, TagEditor } from '../components/UI.jsx';
import { CRED_TYPES } from '../constants.js';
import { getCredBadges, getCredTagMeta, normalizeDomain, domainsMatch } from '../utils/hostMeta.js';
import { useColumnResize } from '../hooks/useColumnResize.js';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import ValidateCredPanel from './creds/ValidateCredPanel.jsx';

const COMMON_SERVICES = ['SSH','SMB','RDP','HTTP','HTTPS','FTP','MySQL','PostgreSQL','MSSQL','Oracle','WinRM','LDAP','Kerberos','VNC','Telnet','WebApp'];

const isWindows = h => h.os === 'Windows' || (h.os || '').toLowerCase().includes('windows');
const sanitizeDomainDraft = (value) => /^\.+$/.test(String(value || '').trim()) ? '' : value;

// Returns { confirmed: Host[], predicted: Host[] } for a cred
function getApplicableHosts(cred, projectHosts) {
  const confirmed = projectHosts.filter(h => (cred.host_ids || []).includes(h.id));
  const credDomain = normalizeDomain(cred.domain || '');
  const predicted = cred.is_domain
    ? projectHosts.filter(h => !confirmed.some(c => c.id === h.id) && isWindows(h) && normalizeDomain(h.domain || '') && domainsMatch(h.domain || '', credDomain))
    : [];
  return { confirmed, predicted };
}

const sel = (val, opts, onChange, style = {}) => (
  <select value={val} onChange={e => onChange(e.target.value)}
    style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', ...style }}>
    {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
  </select>
);

// ── Domain toggle button ──────────────────────────────────────────────
function DomainToggle({ value, onChange, size = 'normal' }) {
  const small = size === 'small';
  return (
    <button onClick={() => onChange(!value)}
      title={value ? 'Domain cred — remove flag' : 'Mark as domain (works on all Windows machines in domain)'}
      style={{ display: 'flex', alignItems: 'center', gap: small ? 4 : 5, padding: small ? '2px 7px' : '4px 10px', borderRadius: 4, border: `1px solid ${value ? '#c07af077' : '#2a2d35'}`, background: value ? '#c07af018' : 'transparent', cursor: 'pointer', color: value ? '#c07af0' : '#505560', fontSize: small ? 9 : 10, fontFamily: 'JetBrains Mono', transition: 'all .15s', whiteSpace: 'nowrap' }}>
      <Icon name="globe" size={small ? 10 : 11} color={value ? '#c07af0' : '#505560'} />
      {value ? 'Domain' : 'Domain?'}
    </button>
  );
}

// ── Host chips display ────────────────────────────────────────────────
function HostChips({ cred, projectHosts, maxVisible = 2 }) {
  const { confirmed, predicted } = getApplicableHosts(cred, projectHosts);
  const total = confirmed.length + predicted.length;

  if (cred.is_domain && total === 0 && confirmed.length === 0) {
    return <span style={{ fontSize: 9, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>Domain</span>;
  }

  if (cred.is_domain) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'nowrap' }}>
        <span style={{ fontSize: 9, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>
          Domain
        </span>
        {total > 0 && (
          <span style={{ fontSize: 9, color: '#808590', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>
            ≈{total} host{total === 1 ? '' : 's'}
          </span>
        )}
      </div>
    );
  }

  if (confirmed.length === 0) {
    return <span style={{ fontSize: 10, color: '#353840', fontFamily: 'JetBrains Mono' }}>{cred.host || '—'}</span>;
  }

  const visible = confirmed.slice(0, maxVisible);
  const rest = confirmed.length - maxVisible;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 3, flexWrap: 'nowrap', overflow: 'hidden' }}>
      {visible.map(h => (
        <span key={h.id} title={h.hostname || h.ip}
          style={{ fontSize: 9, color: '#5b8af5', background: '#5b8af518', border: '1px solid #5b8af533', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', maxWidth: 80, overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {h.hostname || h.ip}
        </span>
      ))}
      {rest > 0 && (
        <span style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>+{rest}</span>
      )}
    </div>
  );
}

// ── Multi-host selector in edit panel ────────────────────────────────
function HostSelector({ selectedIds, onChange, projectHosts, domainFilter = '' }) {
  if (!projectHosts.length) return <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>No hosts in project</div>;
  return (
    <div style={{ maxHeight: 160, overflowY: 'auto', border: '1px solid #2a2d35', borderRadius: 5, background: '#07080b' }}>
      {projectHosts.map(h => {
        const checked = selectedIds.includes(h.id);
        const domainLocked = !!domainFilter;
        const matchesDomain = !domainLocked || domainsMatch(h.domain || '', domainFilter);
        return (
          <label key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', cursor: 'pointer', borderBottom: '1px solid #13151c' }}
            onMouseEnter={e => e.currentTarget.style.background = matchesDomain ? '#ffffff04' : '#301214'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
            <input type="checkbox" checked={checked} disabled={!matchesDomain}
              onChange={() => matchesDomain && onChange(checked ? selectedIds.filter(id => id !== h.id) : [...selectedIds, h.id])}
              style={{ accentColor: '#5b8af5', flexShrink: 0 }} />
            <span style={{ fontSize: 10, color: matchesDomain ? '#9098a8' : '#90545a', fontFamily: 'JetBrains Mono', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {h.ip}{h.hostname ? ` — ${h.hostname}` : ''}
            </span>
            <span style={{ fontSize: 9, color: '#404550' }}>{h.os}</span>
            {domainLocked && h.domain && <span style={{ fontSize: 8, color: matchesDomain ? '#39d353' : '#cc2233' }}>{matchesDomain ? 'match' : 'other'}</span>}
            {checked && isWindows(h) && (
              <span style={{ fontSize: 8, color: '#39d353' }}>✓</span>
            )}
          </label>
        );
      })}
    </div>
  );
}

export default function CredsView({ creds, onAdd, onUpdate, onDelete, selectedProject, accent, hosts, fs = 14 }) {
  const { can, isSuperAdmin } = useProjectPermissions();
  const canReadSecret = isSuperAdmin || can('credentials.read_secret');
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState(null);
  const [filterDomain, setFilterDomain] = useState(false);
  const [filterTag, setFilterTag] = useState(null);
  const [showSecrets, setShowSecrets] = useState({});
  const [showAdd, setShowAdd] = useState(false);
  const [showBulk, setShowBulk] = useState(false);
  const [showBulkEdit, setShowBulkEdit] = useState(false);
  const [newCred, setNewCred] = useState({ username: '', secret: '', type: 'plain', service: '', host: '', domain: '', cracked: false, notes: '', tags: [], is_domain: false, host_ids: [] });
  const [bulkDelimiter, setBulkDelimiter] = useState(';');
  const [bulkText, setBulkText] = useState('');
  const [bulkEditFields, setBulkEditFields] = useState({ type: '', service: '', domain: '', is_domain: '', cracked: '', addTags: '', removeTags: '' });
  const [copied, setCopied] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [checkedIds, setCheckedIds] = useState([]);
  const [showValidate, setShowValidate] = useState(false);
  const [viewMode, setViewMode] = useState('list'); // 'list' | 'matrix'
  const { widths, startResize } = useColumnResize({ username: 150, type: 90, service: 90, hosts: 160, tags: 160, cracked: 70 });
  const colBorder = '1px solid #14161b';

  const projectHosts = (hosts || []).filter(h => h.pid === selectedProject);
  const windowsHosts = projectHosts.filter(isWindows);
  const hostIps = projectHosts.map(h => h.ip);

  const filtered = creds
    .filter(c => c.pid === selectedProject)
    .filter(c => !filterType || c.type === filterType)
    .filter(c => !filterDomain || c.is_domain)
    .filter(c => !filterTag || (c.tags || []).includes(filterTag))
    .filter(c => !search || [c.username, c.service, c.host, c.notes, (c.tags || []).join(' ')].join(' ').toLowerCase().includes(search.toLowerCase()));

  const selCred = creds.find(c => c.id === selectedId);
  const crackedCount = filtered.filter(c => c.cracked).length;
  const domainCount = creds.filter(c => c.pid === selectedProject && c.is_domain).length;
  const tagCounts = useMemo(() => {
    const counts = new Map();
    creds.filter(c => c.pid === selectedProject).forEach(c => {
      (c.tags || []).forEach(tag => counts.set(tag, (counts.get(tag) || 0) + 1));
    });
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [creds, selectedProject]);

  const copy = (text, id) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  };
  const toggleSecret = id => setShowSecrets(p => ({ ...p, [id]: !p[id] }));

  const addCred = () => {
    if (!newCred.username.trim()) return;
    onAdd({ pid: selectedProject, ...newCred });
    setNewCred({ username: '', secret: '', type: 'plain', service: '', host: '', domain: '', cracked: false, notes: '', tags: [], is_domain: false, host_ids: [] });
    setShowAdd(false);
  };

  const handleExportCsv = async () => {
    try {
      const blob = await api.exportCredsCsv(selectedProject);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `creds_${selectedProject?.slice(0, 8) || 'project'}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      toastError(e.message || 'Failed to export credentials CSV');
    }
  };

  const importBulkCreds = async () => {
    const delim = bulkDelimiter === '\t' ? '\t' : bulkDelimiter;
    const lines = bulkText.split('\n').map(l => l.trim()).filter(Boolean);
    for (const line of lines) {
      const parts = line.split(delim).map(x => x.trim());
      if (parts.length < 2) continue;
      const [username, secret, type = 'plain', service = '', host = '', cracked = 'false', notes = '', tags = ''] = parts;
      await onAdd({ pid: selectedProject, username, secret, type: type || 'plain', service, host, domain: '', cracked: ['1','true','yes','y','+'].includes(String(cracked).toLowerCase()), notes, tags: tags.split(',').map(t => t.trim()).filter(Boolean), host_ids: [], is_domain: false });
    }
    setBulkText('');
    setShowBulk(false);
  };

  const applyBulkEdit = async () => {
    const f = bulkEditFields;
    const basePatch = {};
    if (f.type) basePatch.type = f.type;
    if (f.service !== '') basePatch.service = f.service;
    if (f.domain !== '') basePatch.domain = f.domain;
    if (f.is_domain !== '') basePatch.is_domain = f.is_domain === 'true';
    if (f.cracked !== '') basePatch.cracked = f.cracked === 'true';
    const addTags = f.addTags.split(',').map(t => t.trim()).filter(Boolean);
    const removeTags = f.removeTags.split(',').map(t => t.trim()).filter(Boolean);
    for (const id of checkedIds) {
      const cred = creds.find(c => c.id === id);
      if (!cred) continue;
      const patch = { ...basePatch };
      if (addTags.length || removeTags.length) {
        const current = cred.tags || [];
        patch.tags = [...new Set([...current.filter(t => !removeTags.includes(t)), ...addTags])];
      }
      if (Object.keys(patch).length) await onUpdate(id, patch);
    }
    setBulkEditFields({ type: '', service: '', domain: '', is_domain: '', cracked: '', addTags: '', removeTags: '' });
    setShowBulkEdit(false);
    setCheckedIds([]);
  };

  const inp = (label, val, onChange, opts = {}) => (
    <div>
      {label && <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>{label}</div>}
      <input value={val} onChange={e => onChange(e.target.value)} {...opts}
        style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
    </div>
  );

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <div style={{ flex: 1 }}>
          <span style={{ fontSize: fs + 1, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>creds</span>
          <span style={{ fontSize: Math.max(10, fs - 2), color: '#404550', marginLeft: 10 }}>{filtered.length} entries · {crackedCount} cracked</span>
          {domainCount > 0 && (
            <span style={{ fontSize: Math.max(9, fs - 4), color: '#c07af0', marginLeft: 8, fontFamily: 'JetBrains Mono' }}>· {domainCount} domain</span>
          )}
          {checkedIds.length > 0 && (
            <span style={{ fontSize: Math.max(9, fs - 4), color: accent, marginLeft: 8, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>· {checkedIds.length} selected</span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {Object.entries(CRED_TYPES).map(([k, v]) => {
            const cnt = creds.filter(c => c.pid === selectedProject && c.type === k).length;
            if (!cnt) return null;
            return <button key={k} onClick={() => setFilterType(filterType === k ? null : k)}
              style={{ background: filterType === k ? `${v.color}22` : 'transparent', border: `1px solid ${filterType === k ? v.color + '88' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: filterType === k ? v.color : '#505560', fontFamily: 'JetBrains Mono', transition: 'all .12s' }}>
              {v.label} {cnt}
            </button>;
          })}
          {domainCount > 0 && (
            <button onClick={() => setFilterDomain(v => !v)}
              style={{ background: filterDomain ? '#c07af022' : 'transparent', border: `1px solid ${filterDomain ? '#c07af088' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: filterDomain ? '#c07af0' : '#505560', fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4, transition: 'all .12s' }}>
              <Icon name="globe" size={10} color={filterDomain ? '#c07af0' : '#505560'} /> Domain
            </button>
          )}
        </div>
        <div style={{ width: 180 }}><SearchBar value={search} onChange={setSearch} placeholder="Username, host..." /></div>
        <button onClick={() => setShowAdd(v => !v)}
          style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
          <Icon name="plus" size={10} color="#fff" /> Add
        </button>
        {checkedIds.length > 0 && (
          <>
            <button onClick={() => { setShowBulkEdit(v => !v); setShowAdd(false); setShowBulk(false); }}
              style={{ background: showBulkEdit ? `${accent}22` : 'transparent', border: `1px solid ${showBulkEdit ? accent + '88' : '#2a2d35'}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: showBulkEdit ? accent : '#808590', fontSize: Math.max(10, fs - 3), fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4 }}>
              <Icon name="edit" size={10} color="currentColor" /> Edit {checkedIds.length}
            </button>
            <button onClick={() => {
              const text = filtered.filter(c => checkedIds.includes(c.id)).map(c => `${c.username};${c.secret};${c.type};${c.service};${c.host}`).join('\n');
              navigator.clipboard?.writeText(text).catch(() => {});
            }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#808590', fontSize: Math.max(10, fs - 3), fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4 }}>
              <Icon name="copy" size={10} color="currentColor" /> Copy
            </button>
            <button onClick={async () => {
              if (!window.confirm(`Delete ${checkedIds.length} credential(s)?`)) return;
              for (const id of checkedIds) await onDelete(id);
              setCheckedIds([]);
              setShowBulkEdit(false);
            }} style={{ background: '#cc233322', border: '1px solid #cc233344', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#cc2233', fontSize: Math.max(10, fs - 3), fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4 }}>
              <Icon name="trash" size={10} color="currentColor" /> Delete {checkedIds.length}
            </button>
            <button onClick={() => { setCheckedIds([]); setShowBulkEdit(false); }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 8px', cursor: 'pointer', color: '#505560', fontSize: Math.max(9, fs - 4), fontFamily: 'JetBrains Mono' }}>✗</button>
          </>
        )}
        <button onClick={() => setShowBulk(v => !v)}
          style={{ background: 'transparent', border: `1px solid ${accent}66`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: accent, fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
          <Icon name="export" size={10} color="currentColor" /> Bulk
        </button>
        <button onClick={handleExportCsv}
          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#808590', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
          <Icon name="export" size={10} color="currentColor" /> CSV
        </button>
        <button onClick={() => setViewMode(v => v === 'matrix' ? 'list' : 'matrix')}
          title="Matrix: credentials × hosts"
          style={{ background: viewMode === 'matrix' ? `${accent}22` : 'transparent', border: `1px solid ${viewMode === 'matrix' ? accent + '88' : '#2a2d35'}`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: viewMode === 'matrix' ? accent : '#808590', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
          ⊞ Matrix
        </button>
      </div>

      {tagCounts.length > 0 && (
        <div style={{ padding: '8px 18px', borderBottom: '1px solid #1a1c22', background: '#0c0e13', display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Tags</span>
          {tagCounts.map(([tag, count]) => {
            const meta = getCredTagMeta(tag);
            const active = filterTag === tag;
            return (
              <button key={tag} onClick={() => setFilterTag(active ? null : tag)}
                style={{ background: active ? `${meta.color}22` : '#0e1016', border: `1px solid ${active ? meta.color + '88' : '#2a2d35'}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: active ? meta.color : '#808590', fontSize: 9, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
                <span>{meta.label}</span>
                <span style={{ opacity: 0.75 }}>{count}</span>
              </button>
            );
          })}
          {filterTag && <button onClick={() => setFilterTag(null)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>Clear</button>}
        </div>
      )}

      {/* Bulk import */}
      {showBulk && (
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0c0e13' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <div style={{ fontSize: 10, color: '#808590' }}>Format: username secret type service host cracked notes tags</div>
            <select value={bulkDelimiter} onChange={e => setBulkDelimiter(e.target.value)} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
              {[';', ',', '|', '\t'].map(d => <option key={d} value={d}>{d === '\t' ? 'TAB' : d}</option>)}
            </select>
          </div>
          <textarea value={bulkText} onChange={e => setBulkText(e.target.value)} rows={5}
            placeholder={'admin;Password123!;plain;SMB;10.0.0.5;true;local admin;shared,prod\nDOMAIN\\user1;aad3b435:ntlmhash;ntlm;SMB;;false;BH import;domain-admin,kerberoastable'}
            style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 10px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box' }} />
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button onClick={importBulkCreds} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>Import</button>
            <button onClick={() => setShowBulk(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
          </div>
        </div>
      )}

      {/* Bulk edit panel */}
      {showBulkEdit && checkedIds.length > 0 && (
        <div style={{ padding: '12px 18px', borderBottom: '1px solid #1a1c22', background: '#0c0e13', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ fontSize: 9, color: accent, fontFamily: 'JetBrains Mono', fontWeight: 600, alignSelf: 'center', whiteSpace: 'nowrap' }}>{checkedIds.length} selected</div>

          {/* Type */}
          <div style={{ width: 110 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Type</div>
            <select value={bulkEditFields.type} onChange={e => setBulkEditFields(f => ({ ...f, type: e.target.value }))}
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              <option value="">No change</option>
              {Object.entries(CRED_TYPES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
          </div>

          {/* Service */}
          <div style={{ width: 120 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Service</div>
            <select value={COMMON_SERVICES.includes(bulkEditFields.service) ? bulkEditFields.service : (bulkEditFields.service ? '__custom' : '')}
              onChange={e => setBulkEditFields(f => ({ ...f, service: e.target.value === '__custom' ? '' : e.target.value }))}
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              <option value="">No change</option>
              {COMMON_SERVICES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          {/* Domain */}
          <div style={{ width: 140 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Domain</div>
            <input value={bulkEditFields.domain} onChange={e => setBulkEditFields(f => ({ ...f, domain: e.target.value }))}
              placeholder="No change"
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
          </div>

          {/* Domain flag */}
          <div style={{ width: 130 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Domain flag</div>
            <select value={bulkEditFields.is_domain} onChange={e => setBulkEditFields(f => ({ ...f, is_domain: e.target.value }))}
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              <option value="">No change</option>
              <option value="true">Mark as Domain</option>
              <option value="false">Remove Domain flag</option>
            </select>
          </div>

          {/* Cracked */}
          <div style={{ width: 130 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Cracked</div>
            <select value={bulkEditFields.cracked} onChange={e => setBulkEditFields(f => ({ ...f, cracked: e.target.value }))}
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              <option value="">No change</option>
              <option value="true">✓ Mark cracked</option>
              <option value="false">Unmark cracked</option>
            </select>
          </div>

          {/* Add tags */}
          <div style={{ width: 150 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Add tags</div>
            <input value={bulkEditFields.addTags} onChange={e => setBulkEditFields(f => ({ ...f, addTags: e.target.value }))}
              placeholder="domain-admin, kerberoastable"
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
          </div>

          {/* Remove tags */}
          <div style={{ width: 130 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Remove tags</div>
            <input value={bulkEditFields.removeTags} onChange={e => setBulkEditFields(f => ({ ...f, removeTags: e.target.value }))}
              placeholder="old-tag, stale"
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
          </div>

          <button onClick={applyBulkEdit}
            style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
            Apply to {checkedIds.length}
          </button>
          <button onClick={() => { setShowBulkEdit(false); setBulkEditFields({ type: '', service: '', domain: '', is_domain: '', cracked: '', addTags: '', removeTags: '' }); }}
            style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
            Cancel
          </button>
        </div>
      )}

      {/* Quick add form */}
      {showAdd && (
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0c0e13', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ width: 150 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Username</div>
            <input value={newCred.username} onChange={e => setNewCred(c => ({ ...c, username: e.target.value }))} autoFocus
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
          </div>
          <div style={{ flex: 1, minWidth: 160 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Secret / Hash</div>
            <input value={newCred.secret} onChange={e => setNewCred(c => ({ ...c, secret: e.target.value }))}
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
          </div>
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Type</div>
            <select value={newCred.type} onChange={e => setNewCred(c => ({ ...c, type: e.target.value }))}
              style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              {Object.entries(CRED_TYPES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
          </div>
          <div style={{ width: 120 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Host (quick)</div>
            <select value={hostIps.includes(newCred.host) ? newCred.host : (newCred.host ? '__custom' : '')}
              onChange={e => setNewCred(c => ({ ...c, host: e.target.value === '__custom' ? '' : e.target.value }))}
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              <option value="">—</option>
              {projectHosts.map(h => <option key={h.id} value={h.ip}>{h.ip}{h.hostname ? ` (${h.hostname})` : ''}</option>)}
            </select>
          </div>
          <div style={{ width: 150 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Domain</div>
            <input value={newCred.domain} onChange={e => setNewCred(c => ({ ...c, domain: sanitizeDomainDraft(e.target.value) }))}
              style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
          </div>
          {/* Domain toggle */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase' }}>Flags</div>
            <DomainToggle value={newCred.is_domain} onChange={v => setNewCred(c => ({ ...c, is_domain: v }))} />
          </div>
          <button onClick={addCred}
            style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
            Save
          </button>
          <button onClick={() => setShowAdd(false)}
            style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
            Cancel
          </button>
        </div>
      )}

      {/* Matrix view */}
      {viewMode === 'matrix' && (
        <div style={{ flex: 1, overflow: 'hidden', padding: '8px 18px', display: 'flex', flexDirection: 'column' }}>
          <CredMatrix pid={selectedProject} accent={accent} />
        </div>
      )}

      {/* Table header */}
      {viewMode === 'list' && <div style={{ display: 'flex', alignItems: 'stretch', padding: '8px 18px', borderBottom: '1px solid #1a1c22', background: '#090b0f', flexShrink: 0 }}>
        <div style={{ width: 28, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
          <input type="checkbox" checked={checkedIds.length === filtered.length && filtered.length > 0}
            onChange={e => setCheckedIds(e.target.checked ? filtered.map(c => c.id) : [])}
            style={{ width: 13, height: 13, cursor: 'pointer', accentColor: accent }} />
        </div>
        {[
          ['Username', 'username', widths.username],
          ['Type', 'type', widths.type],
          ['Service', 'service', widths.service],
          ['Hosts', 'hosts', widths.hosts],
          ['Tags', 'tags', widths.tags],
        ].map(([label, key, width]) => (
          <div key={key} style={{ width, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', position: 'relative', minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
            {label}
            <span onMouseDown={(e) => startResize(key, e)} style={{ position: 'absolute', right: -6, top: -8, bottom: -8, width: 12, cursor: 'col-resize' }} />
          </div>
        ))}
        <div style={{ flex: 1, minWidth: 0, fontSize: Math.max(9, fs - 4), color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>Secret / Hash</div>
        <div style={{ width: widths.cracked, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', position: 'relative', borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', textAlign: 'center', overflow: 'hidden', whiteSpace: 'nowrap' }}>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>Cracked</span>
          <span onMouseDown={(e) => startResize('cracked', e)} style={{ position: 'absolute', right: -6, top: -8, bottom: -8, width: 12, cursor: 'col-resize' }} />
        </div>
        <div style={{ width: 56 }} />
      </div>}

      {viewMode === 'list' && <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Rows */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && <div style={{ padding: 32, textAlign: 'center', color: '#404550', fontSize: 12 }}>No credentials</div>}
          {filtered.map(cred => {
            const shown = showSecrets[cred.id];
            const isCopied = copied === cred.id;
            const isSel = selectedId === cred.id;
            const { confirmed, predicted } = getApplicableHosts(cred, projectHosts);
            return (
              <div key={cred.id} onClick={(e) => { if (e.target.type !== 'checkbox') setSelectedId(isSel ? null : cred.id); }}
                style={{ display: 'flex', alignItems: 'stretch', minHeight: 44, padding: '8px 18px', borderBottom: '1px solid #14161b', transition: 'background .1s', cursor: 'pointer', background: isSel ? '#ffffff06' : checkedIds.includes(cred.id) ? '#ffffff04' : 'transparent', borderLeft: isSel ? `2px solid ${accent}` : cred.is_domain ? '2px solid #c07af033' : '2px solid transparent' }}
                onMouseEnter={e => !isSel && (e.currentTarget.style.background = '#ffffff04')}
                onMouseLeave={e => !isSel && !checkedIds.includes(cred.id) && (e.currentTarget.style.background = 'transparent')}>

                {/* Checkbox */}
                <div style={{ width: 28, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRight: colBorder, paddingRight: 12, marginRight: 12 }} onClick={e => e.stopPropagation()}>
                  <input type="checkbox" checked={checkedIds.includes(cred.id)}
                    onChange={e => setCheckedIds(prev => e.target.checked ? [...prev, cred.id] : prev.filter(id => id !== cred.id))}
                    style={{ width: 13, height: 13, cursor: 'pointer', accentColor: accent }} />
                </div>

                {/* Username + notes */}
                <div style={{ width: widths.username, flexShrink: 0, minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                  <div style={{ fontSize: Math.max(11, fs - 1), color: '#e0e4ec', fontFamily: 'JetBrains Mono', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {cred.username}
                  </div>
                  {cred.notes && <div style={{ fontSize: Math.max(9, fs - 4), color: '#404550', marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.notes}</div>}
                </div>

                {/* Type */}
                <div style={{ width: widths.type, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center', overflow: 'hidden' }}><CredTypeBadge type={cred.type} /></div>

                {/* Service */}
                <div style={{ width: widths.service, flexShrink: 0, fontSize: Math.max(10, fs - 3), color: '#606570', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center' }}>{cred.service || '—'}</div>

                {/* Hosts column */}
                <div style={{ width: widths.hosts, flexShrink: 0, minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                  <HostChips cred={cred} projectHosts={projectHosts} maxVisible={2} />
                  {/* Predicted count hint */}
                  {cred.is_domain && predicted.length > 0 && (
                    <div style={{ fontSize: 8, color: '#505560', fontFamily: 'JetBrains Mono', marginTop: 1 }}>
                      +{predicted.length} Windows (predicted)
                    </div>
                  )}
                </div>

                {/* Tags */}
                <div style={{ width: widths.tags, flexShrink: 0, minWidth: 0, display: 'flex', gap: 3, flexWrap: 'nowrap', alignItems: 'center', overflow: 'hidden', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
                  {(cred.tags || []).length === 0 && <span style={{ fontSize: Math.max(9, fs - 4), color: '#303540', fontFamily: 'JetBrains Mono' }}>—</span>}
                  {(cred.tags || []).slice(0, 3).map(tag => (
                    (() => {
                      const meta = getCredTagMeta(tag);
                      return <span key={tag} style={{ fontSize: Math.max(9, fs - 4), color: meta.color, background: `${meta.color}18`, border: `1px solid ${meta.color}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>{meta.label}</span>;
                    })()
                  ))}
                  {(cred.tags || []).length > 3 && <span style={{ fontSize: Math.max(9, fs - 4), color: '#505560', fontFamily: 'JetBrains Mono' }}>+{cred.tags.length - 3}</span>}
                </div>

                {/* Secret */}
                <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, overflow: 'hidden' }}>
                  {canReadSecret ? (
                    <span style={{ fontSize: Math.max(10, fs - 3), color: shown ? '#c8cdd6' : '#404550', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1, filter: shown ? 'none' : 'blur(4px)', transition: 'filter .2s', userSelect: shown ? 'text' : 'none' }}>
                      {cred.secret || '(empty)'}
                    </span>
                  ) : (
                    <span style={{ fontSize: Math.max(10, fs - 3), color: '#303540', fontFamily: 'JetBrains Mono', flex: 1 }}>••••••••</span>
                  )}
                </div>

                {/* Cracked */}
                <div style={{ width: widths.cracked, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
                  {cred.cracked
                    ? <span style={{ maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9, color: '#39d353', background: '#39d35322', border: '1px solid #39d35344', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>✓ cracked</span>
                    : <button onClick={e => { e.stopPropagation(); onUpdate(cred.id, { cracked: true }); }}
                        style={{ maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9, color: '#404550', background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', cursor: 'pointer' }}>hash</button>}
                </div>

                {/* Actions */}
                <div style={{ width: 56, display: 'flex', alignItems: 'center', gap: 4 }} onClick={e => e.stopPropagation()}>
                  {canReadSecret && (
                    <button onClick={() => toggleSecret(cred.id)} title={shown ? 'Hide' : 'Show'}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', display: 'flex', padding: 2 }}
                      onMouseEnter={e => e.currentTarget.style.color = '#9098a8'}
                      onMouseLeave={e => e.currentTarget.style.color = '#404550'}>
                      <Icon name={shown ? 'eyeOff' : 'eye'} size={13} color="currentColor" />
                    </button>
                  )}
                  {canReadSecret && (
                    <button onClick={() => copy(cred.secret, cred.id)} title="Copy"
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: isCopied ? '#39d353' : '#404550', display: 'flex', padding: 2 }}
                      onMouseEnter={e => !isCopied && (e.currentTarget.style.color = '#9098a8')}
                      onMouseLeave={e => !isCopied && (e.currentTarget.style.color = '#404550')}>
                      <Icon name={isCopied ? 'check' : 'copy'} size={13} color="currentColor" />
                    </button>
                  )}
                  <button onClick={() => { onDelete(cred.id); if (selectedId === cred.id) setSelectedId(null); }}
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

        {/* ── Edit panel ─────────────────────────────────────────────── */}
        {selCred && (
          <div style={{ width: 300, background: '#0c0e13', borderLeft: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
            <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>Edit</span>
              <button onClick={() => setSelectedId(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
                <Icon name="close" size={12} color="#606570" />
              </button>
            </div>

            <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {getCredBadges(selCred).map(b => <Badge key={b.label} label={b.label} color={b.color} />)}
              </div>
              <FieldInput label="Username" value={selCred.username} onChange={v => onUpdate(selCred.id, { username: v })} placeholder="DOMAIN\admin" />
              {canReadSecret
                ? <FieldInput label="Secret / Password / Hash" value={selCred.secret} onChange={v => onUpdate(selCred.id, { secret: v })} placeholder="P@ssw0rd or NTLM" />
                : <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', padding: '6px 0' }}>Secret / Hash — <span style={{ color: '#303540' }}>access restricted</span></div>
              }

              {/* Type */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Type</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {Object.entries(CRED_TYPES).map(([k, v]) => (
                    <button key={k} onClick={() => onUpdate(selCred.id, { type: k })}
                      style={{ background: selCred.type === k ? `${v.color}22` : '#0e1016', border: `1px solid ${selCred.type === k ? v.color + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: selCred.type === k ? v.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', transition: 'all .1s' }}>
                      {v.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Domain toggle */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Scope</div>
                <DomainToggle value={selCred.is_domain} onChange={v => onUpdate(selCred.id, { is_domain: v })} />
                {selCred.is_domain && (
                  <div style={{ marginTop: 6, fontSize: 10, color: '#808590', lineHeight: 1.5 }}>
                    Applies to all Windows machines in domain.
                    {windowsHosts.length > 0 && (
                      <span style={{ color: '#c07af0' }}> ≈{windowsHosts.length} host{windowsHosts.length === 1 ? '' : 's'} in project.</span>
                    )}
                  </div>
                )}
              </div>

              {/* Multi-host selector */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>
                  Confirmed hosts
                  {(selCred.host_ids || []).length > 0 && (
                    <span style={{ color: '#5b8af5', marginLeft: 6 }}>{(selCred.host_ids || []).length}</span>
                  )}
                </div>
                <HostSelector
                  selectedIds={selCred.host_ids || []}
                  onChange={ids => onUpdate(selCred.id, { host_ids: ids })}
                  projectHosts={projectHosts}
                  domainFilter={selCred.is_domain ? normalizeDomain(selCred.domain || '') : ''}
                />
                {(selCred.host_ids || []).length > 0 && selCred.is_domain && (
                  <div style={{ marginTop: 4, fontSize: 9, color: '#39d353', fontFamily: 'JetBrains Mono' }}>
                    ✓ {(selCred.host_ids || []).length} confirmed + ≈{windowsHosts.filter(h => !(selCred.host_ids || []).includes(h.id)).length} predicted
                  </div>
                )}
              </div>

              {/* Legacy single host (free text) */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Additional host (text)</div>
                <input value={selCred.host || ''} onChange={e => onUpdate(selCred.id, { host: e.target.value })} placeholder="10.0.0.1 or any text"
                  style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
              </div>

              <FieldInput label="Domain" value={selCred.domain || ''} onChange={v => onUpdate(selCred.id, { domain: sanitizeDomainDraft(v) })} placeholder="edu or edu.local" />

              {/* Service */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Service</div>
                <select value={COMMON_SERVICES.includes(selCred.service) ? selCred.service : '__custom'}
                  onChange={e => { if (e.target.value !== '__custom') onUpdate(selCred.id, { service: e.target.value }); }}
                  style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', marginBottom: 5 }}>
                  <option value="__custom">— enter manually —</option>
                  {COMMON_SERVICES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <input value={selCred.service || ''} onChange={e => onUpdate(selCred.id, { service: e.target.value })} placeholder="SSH"
                  style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
              </div>

              <TagEditor label="Tags" tags={selCred.tags || []} onChange={tags => onUpdate(selCred.id, { tags })} placeholder="domain-admin, kerberoastable" />

              {/* Cracked */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Status</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {[[false, 'Hash/token', '#404550'], [true, '✓ Cracked', '#39d353']].map(([v, l, c]) => (
                    <button key={String(v)} onClick={() => onUpdate(selCred.id, { cracked: v })}
                      style={{ flex: 1, background: selCred.cracked === v ? `${c}18` : 'transparent', border: `1px solid ${selCred.cracked === v ? c + '66' : '#2a2d35'}`, borderRadius: 4, padding: '5px 8px', cursor: 'pointer', color: selCred.cracked === v ? c : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', transition: 'all .1s' }}>
                      {l}
                    </button>
                  ))}
                </div>
              </div>

              <FieldInput label="Notes" value={selCred.notes || ''} onChange={v => onUpdate(selCred.id, { notes: v })} placeholder="Where found, context..." textarea />

              {/* Validate button — only when username + secret are filled */}
              {selCred.username?.trim() && selCred.secret?.trim() && (
              <div>
                <button onClick={() => setShowValidate(v => !v)}
                  style={{ width: '100%', background: showValidate ? `${accent || '#5b8af5'}22` : '#0e1016', border: `1px solid ${showValidate ? (accent || '#5b8af5') + '66' : '#2a2d35'}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: showValidate ? (accent || '#5b8af5') : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'center' }}>
                  <Icon name="terminal" size={11} color="currentColor" />
                  {showValidate ? 'Hide validator' : 'Validate credential'}
                </button>
                {showValidate && (
                  <ValidateCredPanel
                    cred={selCred}
                    projectHosts={projectHosts}
                    selectedProject={selectedProject}
                    accent={accent}
                    onClose={() => setShowValidate(false)}
                  />
                )}
              </div>
              )}

              {/* Summary */}
              {(() => {
                const { confirmed, predicted } = getApplicableHosts(selCred, projectHosts);
                if (!confirmed.length && !predicted.length) return null;
                return (
                  <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px' }}>
                    <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '.1em', marginBottom: 8 }}>Potential access</div>
                    {confirmed.map(h => (
                      <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#39d353', flexShrink: 0 }} />
                        <span style={{ fontSize: 10, color: '#9098a8', fontFamily: 'JetBrains Mono' }}>{h.ip}{h.hostname ? ` (${h.hostname})` : ''}</span>
                        <span style={{ fontSize: 8, color: '#39d353' }}>✓ confirmed</span>
                      </div>
                    ))}
                    {predicted.map(h => (
                      <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#c07af066', flexShrink: 0 }} />
                        <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{h.ip}{h.hostname ? ` (${h.hostname})` : ''}</span>
                        <span style={{ fontSize: 8, color: '#c07af0' }}>~ domain</span>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </div>
          </div>
        )}
      </div>}
    </div>
  );
}
