import { useMemo, useState, useEffect } from 'react';
import Icon from '../components/Icon.jsx';
import { HostStatusBadge, SearchBar, FieldInput } from '../components/UI.jsx';
import { NODE_STATUS, OS_ICONS, PORT_SERVICES, serviceColor } from '../constants.js';
import NmapParser from '../components/NmapParser.jsx';
import BloodHoundParser from '../components/BloodHoundParser.jsx';
import { api } from '../api.js';

const ACCESS_ROLES = [
  { id: 'local_admin', label: 'LA', title: 'Local Admin' },
  { id: 'domain_admin', label: 'DA', title: 'Domain Admin' },
  { id: 'rdp', label: 'RDP', title: 'RDP access' },
  { id: 'ssh', label: 'SSH', title: 'SSH access' },
  { id: 'winrm', label: 'WRM', title: 'WinRM access' },
  { id: 'no_rights', label: 'None', title: 'No rights' },
];

function CredPanel({ cred, host, accent, pid, linkType }) {
  const [open, setOpen] = useState(false);
  const [chn, setChn] = useState(null);
  const [notes, setNotes] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    api.getCredHostNotes({ cred_id: cred.id, host_id: host.id }).then(list => {
      const found = list[0] || null;
      setChn(found);
      setNotes(found?.notes || '');
    }).catch(() => {});
  }, [open, cred.id, host.id]);

  const toggleAccess = async (roleId) => {
    const current = chn?.access || [];
    const next = current.includes(roleId) ? current.filter(r => r !== roleId) : [...current, roleId];
    await saveNote(notes, next);
  };

  const saveNote = async (newNotes, newAccess) => {
    setSaving(true);
    try {
      const body = { cred_id: cred.id, host_id: host.id, pid, notes: newNotes, access: newAccess ?? chn?.access ?? [] };
      const result = chn
        ? await api.updateCredHostNote(chn.id, { notes: newNotes, access: newAccess ?? chn.access })
        : await api.upsertCredHostNote(body);
      setChn(result);
      setNotes(result.notes);
    } catch {}
    setSaving(false);
  };

  const linkColors = { ip: '#5b8af5', domain: '#c07af0', 'domain?': '#f09a3a', linked: '#39d353' };
  const linkLabels = { ip: 'IP', domain: 'domain', 'domain?': 'domain?', linked: 'linked' };
  const linkTitles = { ip: 'Linked by IP', domain: 'Domain credential (host is domain-joined)', 'domain?': 'Domain credential — set host domain to confirm', linked: 'Linked via host_ids' };

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, marginBottom: 6 }}>
      <div onClick={() => setOpen(v => !v)} style={{ padding: '6px 8px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ fontSize: 11, color: '#e0e4ec', fontFamily: 'JetBrains Mono', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.username}</span>
            <div style={{ display: 'flex', gap: 3, flexShrink: 0, alignItems: 'center' }}>
              <span title={linkTitles[linkType]} style={{ fontSize: 8, color: linkColors[linkType], background: linkColors[linkType] + '22', border: `1px solid ${linkColors[linkType]}44`, borderRadius: 3, padding: '1px 4px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>{linkLabels[linkType]}</span>
              {cred.is_domain && <span style={{ fontSize: 8, color: '#f09a3a', background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 3, padding: '1px 4px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>AD</span>}
              {(chn?.access || []).slice(0, 2).map(r => {
                const role = ACCESS_ROLES.find(a => a.id === r);
                return role ? <span key={r} style={{ fontSize: 8, color: accent, background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 3, padding: '1px 4px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>{role.label}</span> : null;
              })}
            </div>
          </div>
          <div style={{ fontSize: 9, color: '#606570', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.service || '—'} · {cred.type}{cred.cracked ? ' · cracked' : ''}</div>
        </div>
        <Icon name="chevron" size={10} color="#606570" style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform .12s', flexShrink: 0 }} />
      </div>
      {open && (
        <div style={{ padding: '8px', borderTop: '1px solid #1e2029' }}>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 4 }}>Secret</div>
          <div style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', wordBreak: 'break-all', marginBottom: 8 }}>{cred.secret || '(empty)'}</div>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 4 }}>Access on this host</div>
          <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginBottom: 8 }}>
            {ACCESS_ROLES.map(role => {
              const active = (chn?.access || []).includes(role.id);
              return (
                <button key={role.id} onClick={() => toggleAccess(role.id)} title={role.title}
                  style={{ background: active ? accent + '22' : '#0e1016', border: `1px solid ${active ? accent + '66' : '#2a2d35'}`, borderRadius: 3, padding: '3px 7px', cursor: 'pointer', color: active ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
                  {role.label}
                </button>
              );
            })}
          </div>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 4 }}>Notes on this host</div>
          <textarea value={notes} onChange={e => setNotes(e.target.value)} onBlur={() => saveNote(notes)}
            placeholder="e.g. can't RDP, needs relay, password expired..."
            style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono', lineHeight: 1.5, resize: 'vertical', outline: 'none', minHeight: 54, boxSizing: 'border-box' }} />
          {cred.notes && <div style={{ fontSize: 9, color: '#606570', marginTop: 6, lineHeight: 1.5 }}>Cred notes: {cred.notes}</div>}
        </div>
      )}
    </div>
  );
}

export default function HostsView({ hosts, creds, onAdd, onUpdate, onDelete, selectedProject, accent, onImport, onAddCred, fs = 14 }) {
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState(null);
  const [sortBy, setSortBy] = useState('ip');
  const [selected, setSelected] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [showNmap, setShowNmap] = useState(false);
  const [showBloodHound, setShowBloodHound] = useState(false);
  const [newHost, setNewHost] = useState({ ip: '', hostname: '', os: 'Linux', status: 'unknown', ports: '', services: '', tags: '', notes: '' });
  const [selectedIds, setSelectedIds] = useState([]);
  const [showBulkEdit, setShowBulkEdit] = useState(false);
  const [bulkOs, setBulkOs] = useState('');
  const [bulkStatus, setBulkStatus] = useState('');
  const [bulkTags, setBulkTags] = useState('');
  const [draftPorts, setDraftPorts] = useState([]);
  const [draftServices, setDraftServices] = useState([]);

  const projectHosts = hosts.filter(h => h.pid === selectedProject);
  const filtered = projectHosts
    .filter(h => !filterStatus || h.status === filterStatus)
    .filter(h => !search || [h.ip, h.hostname, h.notes, (h.tags || []).join(' ')].join(' ').toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => (String(a[sortBy] || '').localeCompare(String(b[sortBy] || ''))));

  const selHost = projectHosts.find(h => h.id === selected);
  const hostCreds = useMemo(() => {
    if (!selHost) return [];
    const isDomainHost = !!(selHost.domain && selHost.domain.trim());
    return (creds || []).filter(c => c.pid === selectedProject && (
      c.host === selHost.ip ||
      (selHost.hostname && c.host === selHost.hostname) ||
      (c.host_ids || []).includes(selHost.id) ||
      c.is_domain
    )).map(c => ({
      ...c,
      _linkType: c.host === selHost.ip || (selHost.hostname && c.host === selHost.hostname) ? 'ip'
        : (c.host_ids || []).includes(selHost.id) ? 'linked'
        : isDomainHost ? 'domain' : 'domain?',
    }));
  }, [creds, selHost, selectedProject]);

  useEffect(() => {
    if (selHost) {
      setDraftPorts(selHost.ports || []);
      setDraftServices(selHost.services || []);
    }
  }, [selHost?.id]);

  const savePortsServices = (ports, services) => {
    const maxLen = Math.max(ports.length, services.length);
    const cleanPorts = [];
    const cleanServices = [];
    for (let i = 0; i < maxLen; i++) {
      const p = ports[i] || '';
      const s = services[i] || '';
      if (p || s) { cleanPorts.push(p); cleanServices.push(s); }
    }
    onUpdate(selHost.id, { ports: cleanPorts, services: cleanServices });
    setDraftPorts(cleanPorts);
    setDraftServices(cleanServices);
  };

  const addHost = () => {
    onAdd({
      pid: selectedProject,
      ...newHost,
      ports: newHost.ports.split(',').map(p => p.trim()).filter(Boolean),
      services: newHost.services.split(',').map(s => s.trim()).filter(Boolean),
      tags: newHost.tags.split(',').map(t => t.trim()).filter(Boolean),
    });
    setNewHost({ ip: '', hostname: '', os: 'Linux', status: 'unknown', ports: '', services: '', tags: '', notes: '' });
    setShowAdd(false);
  };

  const Col = ({ label, field, w = 100 }) => (
    <div onClick={() => setSortBy(field)} style={{ width: w, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: sortBy === field ? accent : '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', cursor: 'pointer', userSelect: 'none', display: 'flex', alignItems: 'center', gap: 4 }}>
      {label}{sortBy === field && <span style={{ color: accent }}>↑</span>}
    </div>
  );

  return (
    <>
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <div style={{ flex: 1 }}>
          <span style={{ fontSize: fs + 1, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>hosts</span>
          <span style={{ fontSize: Math.max(10, fs - 2), color: '#404550', marginLeft: 10 }}>{filtered.length} of {projectHosts.length}</span>
          {selectedIds.length > 0 && <span style={{ fontSize: Math.max(10, fs - 2), color: accent, marginLeft: 10, fontWeight: 600 }}>({selectedIds.length} selected)</span>}
        </div>
        {selectedIds.length > 0 && <button onClick={() => setShowBulkEdit(v => !v)} style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="terminal" size={10} color="#fff" /> Bulk edit</button>}
        {selectedIds.length > 0 && <button onClick={() => setSelectedIds([])} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#606570', fontSize: Math.max(10, fs - 3), fontFamily: 'JetBrains Mono' }}>Deselect all</button>}
        <div style={{ display: 'flex', gap: 4 }}>
          {Object.entries(NODE_STATUS).map(([k, v]) => {
            const cnt = projectHosts.filter(h => h.status === k).length;
            if (!cnt) return null;
            return <button key={k} onClick={() => setFilterStatus(filterStatus === k ? null : k)} style={{ background: filterStatus === k ? `${v.color}22` : 'transparent', border: `1px solid ${filterStatus === k ? v.color + '88' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: filterStatus === k ? v.color : '#505560', fontFamily: 'JetBrains Mono' }}>{v.label} <span style={{ opacity: .6 }}>{cnt}</span></button>;
          })}
        </div>
        <div style={{ width: 220 }}><SearchBar value={search} onChange={setSearch} placeholder="IP, hostname..." /></div>
        <button onClick={() => setShowNmap(true)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#808590', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="terminal" size={10} color="currentColor" /> Nmap</button>
        <button onClick={() => setShowBloodHound(true)} style={{ background: 'transparent', border: '1px solid #c07af044', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#c07af0', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>🩸 BloodHound</button>
        {onImport && <button onClick={onImport} style={{ background: 'transparent', border: `1px solid ${accent}66`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: accent, fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="export" size={10} color="currentColor" /> Import</button>}
        <button onClick={() => setShowAdd(v => !v)} style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="plus" size={10} color="#fff" /> Add</button>
      </div>

      {showAdd && (
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0c0e13', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          {[['IP', 'ip', '120px'], ['Hostname', 'hostname', '150px'], ['OS', 'os', '100px'], ['Ports', 'ports', '120px'], ['Tags', 'tags', '120px']].map(([l, k, w]) => (
            <div key={k} style={{ width: w, display: 'flex', flexDirection: 'column' }}>
              <div style={{ fontSize: Math.max(9, fs - 4), color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>{l}</div>
              <input value={newHost[k]} onChange={e => setNewHost(h => ({ ...h, [k]: e.target.value }))} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: Math.max(11, fs - 2), outline: 'none', fontFamily: 'JetBrains Mono' }} />
            </div>
          ))}
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: Math.max(9, fs - 4), color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Status</div>
            <select value={newHost.status} onChange={e => setNewHost(h => ({ ...h, status: e.target.value }))} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: Math.max(11, fs - 2), outline: 'none', fontFamily: 'JetBrains Mono' }}>{Object.keys(NODE_STATUS).map(s => <option key={s} value={s}>{NODE_STATUS[s].label}</option>)}</select>
          </div>
          <button onClick={addHost} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: Math.max(11, fs - 2), fontWeight: 600, fontFamily: 'JetBrains Mono', alignSelf: 'flex-end' }}>Save</button>
          <button onClick={() => setShowAdd(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: Math.max(11, fs - 2), fontFamily: 'JetBrains Mono', alignSelf: 'flex-end' }}>Cancel</button>
        </div>
      )}

      {showBulkEdit && selectedIds.length > 0 && (
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0c0e13', display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ width: 120 }}>
            <div style={{ fontSize: Math.max(9, fs - 4), color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>OS</div>
            <select value={bulkOs} onChange={e => setBulkOs(e.target.value)} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: Math.max(11, fs - 2), outline: 'none', fontFamily: 'JetBrains Mono' }}>
              <option value="">No change</option>
              {['Linux', 'Windows', 'macOS', 'Various', 'Unknown'].map(os => <option key={os} value={os}>{os}</option>)}
            </select>
          </div>
          <div style={{ width: 140 }}>
            <div style={{ fontSize: Math.max(9, fs - 4), color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Status</div>
            <select value={bulkStatus} onChange={e => setBulkStatus(e.target.value)} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: Math.max(11, fs - 2), outline: 'none', fontFamily: 'JetBrains Mono' }}>
              <option value="">No change</option>
              {Object.entries(NODE_STATUS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
          </div>
          <div style={{ width: 160 }}>
            <div style={{ fontSize: Math.max(9, fs - 4), color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Add tags</div>
            <input value={bulkTags} onChange={e => setBulkTags(e.target.value)} placeholder="web, apache" style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: Math.max(11, fs - 2), outline: 'none', fontFamily: 'JetBrains Mono' }} />
          </div>
          <button onClick={() => {
            const updates = {};
            if (bulkOs) updates.os = bulkOs;
            if (bulkStatus) updates.status = bulkStatus;
            selectedIds.forEach(id => {
              const host = hosts.find(h => h.id === id);
              const newTags = bulkTags ? [...new Set([...(host.tags || []), ...bulkTags.split(',').map(t => t.trim()).filter(Boolean)])] : host.tags;
              onUpdate(id, { ...updates, ...(bulkTags ? { tags: newTags } : {}) });
            });
            setBulkOs(''); setBulkStatus(''); setBulkTags('');
            setSelectedIds([]);
            setShowBulkEdit(false);
          }} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: Math.max(11, fs - 2), fontWeight: 600, fontFamily: 'JetBrains Mono' }}>Apply to {selectedIds.length} hosts</button>
          <button onClick={() => setShowBulkEdit(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: Math.max(11, fs - 2), fontFamily: 'JetBrains Mono' }}>Cancel</button>
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', padding: '8px 16px', borderBottom: '1px solid #1a1c22', background: '#090b0f', position: 'sticky', top: 0, zIndex: 2, gap: 12 }}>
            <div style={{ width: 32, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <input type="checkbox" checked={selectedIds.length === filtered.length && filtered.length > 0} onChange={e => setSelectedIds(e.target.checked ? filtered.map(h => h.id) : [])} style={{ width: 14, height: 14, cursor: 'pointer', accentColor: accent }} />
            </div>
            <Col label="IP" field="ip" w={120} />
            <Col label="Hostname" field="hostname" w={140} />
            <Col label="OS" field="os" w={90} />
            <Col label="Status" field="status" w={130} />
            <div style={{ flex: 1, fontSize: Math.max(9, fs - 4), color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Services / Ports</div>
            <div style={{ width: 70, fontSize: Math.max(9, fs - 4), color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>creds</div>
            <div style={{ width: 110, fontSize: Math.max(9, fs - 4), color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Tags</div>
            <div style={{ width: 28 }} />
          </div>
          {filtered.length === 0 && <div style={{ padding: 32, textAlign: 'center', color: '#404550', fontSize: Math.max(12, fs - 1) }}>No hosts. Add the first one.</div>}
          {filtered.map(host => {
            const isSel = selected === host.id;
            const isChecked = selectedIds.includes(host.id);
            const sc = NODE_STATUS[host.status]?.color || '#404550';
            const credCount = (creds || []).filter(c => c.pid === selectedProject && (
                  c.host === host.ip ||
                  (host.hostname && c.host === host.hostname) ||
                  (c.host_ids || []).includes(host.id) ||
                  c.is_domain
                )).length;
            return (
              <div key={host.id} onClick={(e) => { if (e.target.type !== 'checkbox') setSelected(isSel ? null : host.id); }} style={{ display: 'flex', alignItems: 'center', minHeight: 48, padding: '9px 16px', borderBottom: '1px solid #14161b', cursor: 'pointer', background: isSel ? '#ffffff0a' : isChecked ? '#ffffff05' : 'transparent', borderLeft: isSel ? `2px solid ${accent}` : isChecked ? `2px solid ${accent}88` : '2px solid transparent', gap: 12 }}>
                <div style={{ width: 32, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <input type="checkbox" checked={isChecked} onChange={e => {
                    e.stopPropagation();
                    setSelectedIds(prev => e.target.checked ? [...prev, host.id] : prev.filter(id => id !== host.id));
                  }} style={{ width: 14, height: 14, cursor: 'pointer', accentColor: accent }} />
                </div>
                <div style={{ width: 120, flexShrink: 0, fontFamily: 'JetBrains Mono', fontSize: Math.max(11, fs - 1), color: isSel ? accent : '#9098a8', fontWeight: isSel ? 600 : 400 }}>{host.ip}</div>
                <div style={{ width: 140, flexShrink: 0, fontSize: Math.max(11, fs - 1), color: '#c8cdd6', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{host.hostname || <span style={{ color: '#303540' }}>—</span>}</div>
                <div style={{ width: 90, flexShrink: 0, fontSize: Math.max(10, fs - 2), color: '#606570', display: 'flex', alignItems: 'center', gap: 4 }}>
                  {OS_ICONS[host.os]} {host.os}
                  {host.domain && <span title={host.domain} style={{ fontSize: 8, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af044', borderRadius: 3, padding: '1px 3px', fontFamily: 'JetBrains Mono', flexShrink: 0 }}>AD</span>}
                </div>
                <div style={{ width: 130, flexShrink: 0 }}><HostStatusBadge status={host.status} /></div>
                <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden', flexWrap: 'nowrap' }}>
                  {(() => {
                    const svcs = host.services || [];
                    const ports = host.ports || [];
                    const maxLen = Math.max(svcs.length, ports.length);
                    if (maxLen === 0) return <span style={{ fontSize: Math.max(10, fs - 3), color: '#303540' }}>—</span>;
                    return Array.from({ length: Math.min(maxLen, 4) }).map((_, i) => {
                      const svc = svcs[i] || '';
                      const port = ports[i] || '';
                      const label = svc && port ? `${svc}:${port}` : svc || port;
                      const color = serviceColor(svc || PORT_SERVICES[parseInt(port)] || port);
                      return <span key={i} style={{ fontSize: Math.max(9, fs - 4), color, background: `${color}18`, border: `1px solid ${color}44`, borderRadius: 3, padding: '2px 6px', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>{label}</span>;
                    }).concat(maxLen > 4 ? [<span key="more" style={{ fontSize: Math.max(9, fs - 4), color: '#404550', fontFamily: 'JetBrains Mono' }}>+{maxLen - 4}</span>] : []);
                  })()}
                </div>
                <div style={{ width: 70, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  {credCount > 0
                    ? <span style={{ fontSize: Math.max(9, fs - 4), color: '#39d353', background: '#39d35322', border: '1px solid #39d35344', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{credCount}</span>
                    : <span style={{ fontSize: Math.max(9, fs - 4), color: '#303540', fontFamily: 'JetBrains Mono' }}>—</span>}
                </div>
                <div style={{ width: 110, display: 'flex', gap: 3, overflow: 'hidden', alignItems: 'center', flexWrap: 'nowrap' }}>{(host.tags || []).slice(0, 2).map(t => <span key={t} style={{ fontSize: Math.max(9, fs - 4), color: '#505560', background: '#1a1c22', borderRadius: 3, padding: '1px 5px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 50 }}>{t}</span>)}</div>
                <button onClick={e => { e.stopPropagation(); onDelete(host.id); setSelected(null); }} style={{ width: 28, background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', justifyContent: 'center' }}><Icon name="trash" size={12} color="currentColor" /></button>
              </div>
            );
          })}
        </div>

        {selHost && (
          <div style={{ width: 300, background: '#0c0e13', borderLeft: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
            <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: Math.max(11, fs - 2), fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>{selHost.ip}</span>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={12} color="#606570" /></button>
            </div>
            <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>IP / CIDR addresses</span>
                  <button onClick={() => {
                    // Get current IPs, fallback to ip field if ips is empty
                    let currentIps = (selHost.ips && selHost.ips.length > 0) ? selHost.ips : (selHost.ip ? [selHost.ip] : []);
                    onUpdate(selHost.id, { ips: [...currentIps, ''] });
                  }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>+ Add</button>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {(() => {
                    // Get current IPs for display
                    let displayIps = (selHost.ips && selHost.ips.length > 0) ? selHost.ips : (selHost.ip ? [selHost.ip] : ['']);
                    return displayIps.map((ip, i) => (
                      <div key={i} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        <input value={ip || ''} onChange={e => {
                          const currentIps = (selHost.ips && selHost.ips.length > 0) ? [...selHost.ips] : (selHost.ip ? [selHost.ip] : ['']);
                          const next = [...currentIps];
                          next[i] = e.target.value;
                          const filtered = next.filter(x => x && x.trim());
                          onUpdate(selHost.id, { ips: filtered, ip: filtered[0] || '' });
                        }} placeholder="192.168.1.1 or 10.10.10.0/24" style={{ flex: 1, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 8px', color: '#c8cdd6', fontSize: Math.max(10, fs - 3), outline: 'none', fontFamily: 'JetBrains Mono' }} />
                        {displayIps.length > 1 && (
                          <button onClick={() => {
                            const currentIps = (selHost.ips && selHost.ips.length > 0) ? [...selHost.ips] : (selHost.ip ? [selHost.ip] : []);
                            const next = currentIps.filter((_, idx) => idx !== i);
                            onUpdate(selHost.id, { ips: next, ip: next[0] || '' });
                          }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 2, display: 'flex' }}>
                            <Icon name="trash" size={11} color="#404550" />
                          </button>
                        )}
                      </div>
                    ));
                  })()}
                </div>
              </div>
              <FieldInput label="Hostname" value={selHost.hostname} onChange={v => onUpdate(selHost.id, { hostname: v })} placeholder="server-01" />
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>Domain</span>
                  {selHost.domain && <span style={{ fontSize: 8, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af044', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>joined</span>}
                </div>
                <input
                  value={selHost.domain || ''}
                  onChange={e => onUpdate(selHost.id, { domain: e.target.value })}
                  placeholder="acme.local (leave empty if not domain-joined)"
                  style={{ width: '100%', background: '#0e1016', border: `1px solid ${selHost.domain ? '#c07af066' : '#2a2d35'}`, borderRadius: 4, padding: '5px 8px', color: selHost.domain ? '#c07af0' : '#c8cdd6', fontSize: Math.max(10, fs - 3), outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }}
                />
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>OS</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{['Linux', 'Windows', 'macOS', 'Various', 'Unknown'].map(os => <button key={os} onClick={() => onUpdate(selHost.id, { os })} style={{ background: selHost.os === os ? `${accent}22` : '#0e1016', border: `1px solid ${selHost.os === os ? accent + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: selHost.os === os ? accent : '#606570', fontSize: Math.max(10, fs - 3), fontFamily: 'JetBrains Mono' }}>{OS_ICONS[os] || '?'} {os}</button>)}</div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>{Object.entries(NODE_STATUS).map(([k, v]) => <button key={k} onClick={() => onUpdate(selHost.id, { status: k })} style={{ background: selHost.status === k ? `${v.color}18` : 'transparent', border: `1px solid ${selHost.status === k ? v.color + '66' : '#2a2d35'}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 7, textAlign: 'left' }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: v.color, flexShrink: 0 }} /><span style={{ fontSize: Math.max(10, fs - 3), color: selHost.status === k ? v.color : '#606570', fontFamily: 'JetBrains Mono' }}>{v.label}</span></button>)}</div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>Ports and Services</span>
                  <button onClick={() => {
                    setDraftPorts(p => [...p, '']);
                    setDraftServices(s => [...s, '']);
                  }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>+ Add</button>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {draftPorts.length === 0 && draftServices.length === 0 && (
                    <div style={{ fontSize: Math.max(10, fs - 3), color: '#404550', fontStyle: 'italic' }}>No ports or services</div>
                  )}
                  {Array.from({ length: Math.max(draftPorts.length, draftServices.length) }).map((_, i) => (
                    <div key={i} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                      <input
                        value={draftPorts[i] ?? ''}
                        onChange={e => {
                          const val = e.target.value;
                          setDraftPorts(prev => { const n = [...prev]; while (n.length <= i) n.push(''); n[i] = val; return n; });
                          // Auto-fill service name from port if service is empty
                          const suggested = PORT_SERVICES[parseInt(val)];
                          if (suggested && !(draftServices[i] || '').trim()) {
                            setDraftServices(prev => { const n = [...prev]; while (n.length <= i) n.push(''); n[i] = suggested; return n; });
                          }
                        }}
                        onBlur={() => savePortsServices(draftPorts, draftServices)}
                        placeholder="Port"
                        style={{ width: 70, flexShrink: 0, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 6px', color: '#c8cdd6', fontSize: Math.max(10, fs - 3), outline: 'none', fontFamily: 'JetBrains Mono' }}
                      />
                      <input
                        value={draftServices[i] ?? ''}
                        onChange={e => setDraftServices(prev => { const n = [...prev]; while (n.length <= i) n.push(''); n[i] = e.target.value; return n; })}
                        onBlur={() => savePortsServices(draftPorts, draftServices)}
                        placeholder="HTTP, SSH, SMB..."
                        style={{ flex: 1, minWidth: 0, background: '#0e1016', border: `1px solid ${serviceColor(draftServices[i] || '') !== '#606570' ? serviceColor(draftServices[i] || '') + '55' : '#2a2d35'}`, borderRadius: 4, padding: '4px 6px', color: draftServices[i] ? serviceColor(draftServices[i]) : '#606570', fontSize: Math.max(10, fs - 3), outline: 'none', fontFamily: 'JetBrains Mono', transition: 'border-color .15s, color .15s' }}
                      />
                      <button onClick={() => {
                        const nextPorts = draftPorts.filter((_, idx) => idx !== i);
                        const nextServices = draftServices.filter((_, idx) => idx !== i);
                        setDraftPorts(nextPorts);
                        setDraftServices(nextServices);
                        savePortsServices(nextPorts, nextServices);
                      }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 2, display: 'flex', flexShrink: 0 }}>
                        <Icon name="trash" size={11} color="#404550" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
              <FieldInput label="Tags" value={(selHost.tags || []).join(', ')} onChange={v => onUpdate(selHost.id, { tags: v.split(',').map(t => t.trim()).filter(Boolean) })} placeholder="nginx, rce" />
              <FieldInput label="Notes" value={selHost.notes || ''} onChange={v => onUpdate(selHost.id, { notes: v })} placeholder="CVE, details..." textarea />
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  Linked creds
                  {hostCreds.length > 0 && <span style={{ marginLeft: 6, color: accent }}>{hostCreds.length}</span>}
                </div>
                {hostCreds.length === 0 && <div style={{ fontSize: Math.max(10, fs - 3), color: '#404550' }}>No linked credentials</div>}
                {hostCreds.map(c => (
                  <CredPanel key={c.id} cred={c} host={selHost} accent={accent} pid={selectedProject} linkType={c._linkType} />
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
    {showNmap && (
      <NmapParser
        pid={selectedProject}
        accent={accent}
        onClose={() => setShowNmap(false)}
        onImport={async (parsedHosts) => {
          const payload = parsedHosts.map(h => ({ ...h, pid: selectedProject, ips: [], tags: [], notes: '' }));
          return api.batchImport(selectedProject, { hosts: payload, creds: [] });
        }}
      />
    )}
    {showBloodHound && (
      <BloodHoundParser
        pid={selectedProject}
        accent={accent}
        onClose={() => setShowBloodHound(false)}
        onDone={() => window.dispatchEvent(new Event('rt:refresh'))}
      />
    )}
    </>
  );
}
