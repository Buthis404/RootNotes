import { useMemo, useState, useEffect, useCallback } from 'react';
import Icon from '../components/Icon.jsx';
import { HostStatusBadge, SearchBar, FieldInput, Badge, TagEditor } from '../components/UI.jsx';
import { NODE_STATUS, OS_ICONS, PORT_SERVICES, serviceColor } from '../constants.js';
import NmapParser from '../components/NmapParser.jsx';
import BloodHoundParser from '../components/BloodHoundParser.jsx';
import { api } from '../api.js';
import { getCredBadges, getHostBadges, summarizeCreds, HOST_ROLES, normalizeDomain, domainsMatch } from '../utils/hostMeta.js';
import { useColumnResize } from '../hooks/useColumnResize.js';

const BULK_TEMPLATES = {
  nmap:    { label: 'Nmap quick',  cmd: 'nmap -sV -sC -T4 {target}',       type: 'nmap',  activity: 'recon' },
  nmap_f:  { label: 'Nmap full',   cmd: 'nmap -p- -T4 --open {target}',    type: 'nmap',  activity: 'recon' },
  cme:     { label: 'NetExec SMB', cmd: 'netexec smb {target}',            type: 'cme',   activity: 'recon' },
  cme_all: { label: 'NetExec ALL', cmd: 'netexec all {target}',            type: 'cme',   activity: 'recon' },
  exec:    { label: 'Custom',      cmd: '',                                 type: 'exec',  activity: 'postex' },
};

function BulkRunPanel({ selectedIds, hosts, selectedProject, accent, onClose }) {
  const [moduleOk, setModuleOk] = useState(null);
  const [attackerTargets, setAttackerTargets] = useState(null); // { project_hosts, global_targets }
  const [selectedAttacker, setSelectedAttacker] = useState('');  // 'project:{id}' | 'global:{id}'
  const [templateKey, setTemplateKey] = useState('nmap');
  const [command, setCommand] = useState(BULK_TEMPLATES.nmap.cmd);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [timeoutSec, setTimeoutSec] = useState(60);

  useEffect(() => {
    api.listModules().then(({ modules }) => {
      const m = (modules || []).find(m => m.name === 'attacker_ssh');
      setModuleOk(m ? m.enabled !== false : false);
    }).catch(() => setModuleOk(false));

    api.listAttackerExecutionTargets(selectedProject).then(data => {
      setAttackerTargets(data);
      // Auto-select first available
      if (data.project_hosts?.length > 0) {
        setSelectedAttacker(`project:${data.project_hosts[0].id}`);
      } else if (data.global_targets?.length > 0) {
        setSelectedAttacker(`global:${data.global_targets[0].id}`);
      }
    }).catch(() => {});
  }, [selectedProject]);

  const pickTemplate = (key) => {
    setTemplateKey(key);
    if (BULK_TEMPLATES[key].cmd) setCommand(BULK_TEMPLATES[key].cmd);
  };

  const run = async () => {
    if (!command.trim()) return;
    setRunning(true);
    setResults(null);
    try {
      const tpl = BULK_TEMPLATES[templateKey] || BULK_TEMPLATES.exec;
      const [kind, id] = selectedAttacker.split(':');
      const res = await api.bulkExec(selectedProject, {
        host_ids: selectedIds,
        command_template: command,
        scan_type: tpl.type,
        activity_type: tpl.activity,
        timeout_seconds: timeoutSec,
        attacker_host_id: kind === 'project' ? id : null,
        attacker_target_id: kind === 'global' ? id : null,
      });
      setResults(res.results || []);
    } catch (e) {
      setResults([{ error: e.message || 'Request failed', ok: false }]);
    }
    setRunning(false);
  };

  const selectedHosts = hosts.filter(h => selectedIds.includes(h.id));
  const acc = accent || '#5b8af5';
  const allTargets = [
    ...(attackerTargets?.project_hosts || []).map(h => ({ value: `project:${h.id}`, label: `${h.name || h.host} (project)` })),
    ...(attackerTargets?.global_targets || []).map(t => ({ value: `global:${t.id}`, label: `${t.name || t.host} (global)` })),
  ];
  const noTargets = attackerTargets !== null && allTargets.length === 0;

  return (
    <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>Bulk Run</span>
        <span style={{ fontSize: 11, color: '#606570' }}>→ {selectedIds.length} hosts</span>
        {moduleOk === false && (
          <span style={{ fontSize: 10, color: '#f09a3a', background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 4, padding: '2px 8px', fontFamily: 'JetBrains Mono' }}>
            ⚠ Attacker SSH module is disabled
          </span>
        )}
        {noTargets && moduleOk && (
          <span style={{ fontSize: 10, color: '#cc2233', background: '#cc223318', border: '1px solid #cc223344', borderRadius: 4, padding: '2px 8px', fontFamily: 'JetBrains Mono' }}>
            No attacker hosts configured
          </span>
        )}
        <button onClick={onClose} style={{ marginLeft: 'auto', background: 'transparent', border: 'none', cursor: 'pointer', color: '#606570', display: 'flex' }}>
          <Icon name="close" size={12} color="currentColor" />
        </button>
      </div>

      {/* Attacker host selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>Run from:</span>
        <select
          value={selectedAttacker}
          onChange={e => setSelectedAttacker(e.target.value)}
          style={{ flex: 1, background: '#0e1016', border: `1px solid ${acc}44`, borderRadius: 4, padding: '5px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none' }}
        >
          {allTargets.length === 0 && <option value="">— no attacker hosts available —</option>}
          {allTargets.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
      </div>

      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
        {Object.entries(BULK_TEMPLATES).map(([key, tpl]) => (
          <button key={key} onClick={() => pickTemplate(key)}
            style={{ background: templateKey === key ? `${acc}22` : '#13161f', border: `1px solid ${templateKey === key ? acc + '66' : '#1e2230'}`, borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: templateKey === key ? acc : '#606570', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
            {tpl.label}
          </button>
        ))}
        <input
          type="number" min={5} max={300} value={timeoutSec}
          onChange={e => setTimeoutSec(Number(e.target.value))}
          style={{ width: 60, background: '#13161f', border: '1px solid #1e2230', borderRadius: 4, padding: '3px 8px', color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none' }}
          title="Timeout (seconds)"
        />
        <span style={{ fontSize: 10, color: '#404550' }}>sec</span>
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <input
          value={command} onChange={e => setCommand(e.target.value)}
          placeholder="nmap -sV {target} — use {target} for host IP"
          style={{ flex: 1, background: '#0e1016', border: `1px solid ${acc}44`, borderRadius: 4, padding: '6px 10px', color: '#c8cfe0', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono' }}
        />
        <button onClick={run} disabled={running || !moduleOk || !command.trim() || !selectedAttacker || noTargets}
          style={{ background: (moduleOk && command.trim() && selectedAttacker && !noTargets) ? acc : '#1e2230', border: 'none', borderRadius: 4, padding: '6px 16px', cursor: 'pointer', color: '#fff', fontSize: 12, fontWeight: 600, fontFamily: 'JetBrains Mono', opacity: running ? 0.7 : 1 }}>
          {running ? 'Running…' : `Run on ${selectedIds.length} hosts`}
        </button>
      </div>

      <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>
        Targets: {selectedHosts.slice(0, 6).map(h => h.ip || h.hostname).join(', ')}{selectedHosts.length > 6 ? ` +${selectedHosts.length - 6} more` : ''}
      </div>

      {results && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 200, overflowY: 'auto' }}>
          {results.map((r, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', background: r.ok ? '#39d35310' : r.error ? '#f09a3a10' : '#cc223310', border: `1px solid ${r.ok ? '#39d35333' : r.error ? '#f09a3a33' : '#cc223333'}`, borderRadius: 4 }}>
              <span style={{ fontSize: 10, color: r.ok ? '#39d353' : '#cc2233', fontFamily: 'JetBrains Mono', minWidth: 16 }}>{r.ok ? '✓' : '✗'}</span>
              <span style={{ fontSize: 10, color: '#9098a8', fontFamily: 'JetBrains Mono', flex: 1 }}>{r.ip || r.error || '?'}</span>
              {r.exit_code !== undefined && <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>exit {r.exit_code}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const ACCESS_ROLES = [
  { id: 'local_admin', label: 'LA', title: 'Local Admin' },
  { id: 'domain_admin', label: 'DA', title: 'Domain Admin' },
  { id: 'rdp', label: 'RDP', title: 'RDP access' },
  { id: 'ssh', label: 'SSH', title: 'SSH access' },
  { id: 'winrm', label: 'WRM', title: 'WinRM access' },
  { id: 'no_rights', label: 'None', title: 'No rights' },
];

const ACTIVITY_TYPES = {
  recon:   { label: 'Recon', color: '#5b8af5' },
  scan:    { label: 'Scan', color: '#6fc8f0' },
  exploit: { label: 'Exploit', color: '#e8574a' },
  privesc: { label: 'PrivEsc', color: '#f09a3a' },
  lateral: { label: 'Lateral', color: '#e8cc42' },
  postex:  { label: 'PostEx', color: '#39d353' },
  note:    { label: 'Note', color: '#808590' },
};

const ACTIVITY_STATUS = {
  planned: { label: 'Planned', color: '#5b8af5' },
  running: { label: 'Running', color: '#f09a3a' },
  done:    { label: 'Done', color: '#39d353' },
  failed:  { label: 'Failed', color: '#cc2233' },
};

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

export default function HostsView({ hosts, creds, hostActivities = [], onAdd, onUpdate, onDelete, onAddActivity, onUpdateActivity, onDeleteActivity, selectedProject, accent, onImport, onAddCred, fs = 14 }) {
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
  const [showBulkRun, setShowBulkRun] = useState(false);
  const [filterTag, setFilterTag] = useState(null);
  const [bulkOs, setBulkOs] = useState('');
  const [bulkStatus, setBulkStatus] = useState('');
  const [bulkTags, setBulkTags] = useState('');
  const [draftPorts, setDraftPorts] = useState([]);
  const [draftServices, setDraftServices] = useState([]);
  const [newActivity, setNewActivity] = useState({ title: '', activity_type: 'recon', command: '', summary: '', output: '', status: 'done' });
  const [editingActivityId, setEditingActivityId] = useState(null);
  const [showActivityComposer, setShowActivityComposer] = useState(false);
  const [activityTypeFilter, setActivityTypeFilter] = useState(null);
  const [activityStatusFilter, setActivityStatusFilter] = useState(null);

  const { widths, startResize } = useColumnResize({ ip: 120, hostname: 140, os: 110, status: 160, services: 0, creds: 70, tags: 140 });
  const colBorder = '1px solid #14161b';

  const projectHosts = hosts.filter(h => h.pid === selectedProject);
  const getHostCredCount = (host) => {
    const hostDomain = normalizeDomain(host.domain || '');
    return (creds || []).filter(c => c.pid === selectedProject && (
      c.host === host.ip ||
      (host.hostname && c.host === host.hostname) ||
      (c.host_ids || []).includes(host.id) ||
      (c.is_domain && hostDomain && domainsMatch(c.domain || '', hostDomain))
    )).length;
  };
  const getSortValue = (host) => {
    if (sortBy === 'credCount') return getHostCredCount(host);
    if (sortBy === 'tagText') return (host.tags || []).join(' ');
    return host[sortBy] || '';
  };
  const hostTagCounts = useMemo(() => {
    const counts = new Map();
    projectHosts.forEach(h => (h.tags || []).forEach(tag => counts.set(tag, (counts.get(tag) || 0) + 1)));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [projectHosts]);
  const filtered = projectHosts
    .filter(h => !filterStatus || h.status === filterStatus)
    .filter(h => !filterTag || (h.tags || []).includes(filterTag))
    .filter(h => !search || [h.ip, h.hostname, h.notes, (h.tags || []).join(' ')].join(' ').toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      const av = getSortValue(a);
      const bv = getSortValue(b);
      if (typeof av === 'number' || typeof bv === 'number') return Number(av) - Number(bv);
      return String(av).localeCompare(String(bv));
    });

  const selHost = projectHosts.find(h => h.id === selected);
  const hostCreds = useMemo(() => {
    if (!selHost) return [];
    const isDomainHost = !!(selHost.domain && selHost.domain.trim());
    const hostDomain = normalizeDomain(selHost.domain || '');
    return (creds || []).filter(c => c.pid === selectedProject && (
      (c.host_ids || []).includes(selHost.id) ||
      c.host === selHost.ip ||
      (selHost.hostname && c.host === selHost.hostname) ||
      (c.is_domain && hostDomain && domainsMatch(c.domain || '', hostDomain))
    )).map(c => ({
      ...c,
      _linkType: (c.host_ids || []).includes(selHost.id) ? 'linked'
        : c.host === selHost.ip || (selHost.hostname && c.host === selHost.hostname) ? 'ip'
        : isDomainHost ? 'domain' : 'domain?',
    }));
  }, [creds, selHost, selectedProject]);
  const hostCredSummary = useMemo(() => summarizeCreds(hostCreds), [hostCreds]);
  const selHostActivities = useMemo(() => {
    if (!selHost) return [];
    return hostActivities
      .filter(a => a.host_id === selHost.id)
      .filter(a => !activityTypeFilter || a.activity_type === activityTypeFilter)
      .filter(a => !activityStatusFilter || a.status === activityStatusFilter)
      .sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));
  }, [hostActivities, selHost, activityTypeFilter, activityStatusFilter]);

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
    <div style={{ width: w || undefined, flex: w ? undefined : 1, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: sortBy === field ? accent : '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', userSelect: 'none', display: 'flex', alignItems: 'center', gap: 4, position: 'relative', minWidth: 0 }}>
      <span onClick={() => setSortBy(field)} style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 4 }}>{label}{sortBy === field && <span style={{ color: accent }}>↑</span>}</span>
      {w ? <span onMouseDown={(e) => startResize(field, e)} style={{ position: 'absolute', right: -6, top: -8, bottom: -8, width: 12, cursor: 'col-resize' }} /> : null}
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
        {selectedIds.length > 0 && <button onClick={() => { setShowBulkRun(v => !v); setShowBulkEdit(false); }} style={{ background: '#39d35322', border: '1px solid #39d35344', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#39d353', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="terminal" size={10} color="currentColor" /> Bulk Run</button>}
        {selectedIds.length > 0 && <button onClick={() => { setShowBulkEdit(v => !v); setShowBulkRun(false); }} style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="terminal" size={10} color="#fff" /> Bulk edit</button>}
        {selectedIds.length > 0 && <button onClick={async () => {
          if (!window.confirm(`Delete ${selectedIds.length} selected host(s)?`)) return;
          for (const id of selectedIds) await onDelete(id);
          setSelectedIds([]);
          setSelected(null);
          setShowBulkEdit(false);
        }} style={{ background: 'transparent', border: '1px solid #cc223366', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#cc2233', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="trash" size={10} color="currentColor" /> Delete selected</button>}
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

      {showBulkRun && selectedIds.length > 0 && (
        <BulkRunPanel
          selectedIds={selectedIds}
          hosts={hosts}
          selectedProject={selectedProject}
          accent={accent}
          onClose={() => setShowBulkRun(false)}
        />
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

      {hostTagCounts.length > 0 && (
        <div style={{ padding: '8px 18px', borderBottom: '1px solid #1a1c22', background: '#0c0e13', display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: Math.max(9, fs - 4), color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Tags</span>
          {hostTagCounts.map(([tag, count]) => (
            <button key={tag} onClick={() => setFilterTag(filterTag === tag ? null : tag)}
              style={{ background: filterTag === tag ? `${accent}22` : '#0e1016', border: `1px solid ${filterTag === tag ? accent + '88' : '#2a2d35'}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: filterTag === tag ? accent : '#808590', fontSize: Math.max(9, fs - 4), fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
              <span>{tag}</span>
              <span style={{ opacity: 0.75 }}>{count}</span>
            </button>
          ))}
          {filterTag && <button onClick={() => setFilterTag(null)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: '#606570', fontSize: Math.max(9, fs - 4), fontFamily: 'JetBrains Mono' }}>Clear</button>}
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'stretch', padding: '8px 16px', borderBottom: '1px solid #1a1c22', background: '#090b0f', position: 'sticky', top: 0, zIndex: 2 }}>
            <div style={{ width: 32, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
              <input type="checkbox" checked={selectedIds.length === filtered.length && filtered.length > 0} onChange={e => setSelectedIds(e.target.checked ? filtered.map(h => h.id) : [])} style={{ width: 14, height: 14, cursor: 'pointer', accentColor: accent }} />
            </div>
            <div style={{ width: widths.ip, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><Col label="IP" field="ip" w={widths.ip} /></div>
            <div style={{ width: widths.hostname, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><Col label="Hostname" field="hostname" w={widths.hostname} /></div>
            <div style={{ width: widths.os, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><Col label="OS" field="os" w={widths.os} /></div>
            <div style={{ width: widths.status, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><Col label="Status" field="status" w={widths.status} /></div>
            <div style={{ flex: 1, minWidth: 0, fontSize: Math.max(9, fs - 4), color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', position: 'relative', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>Services / Ports</div>
            <div style={{ width: widths.creds, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><Col label="Creds" field="credCount" w={widths.creds} /></div>
            <div style={{ width: widths.tags, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><Col label="Tags" field="tagText" w={widths.tags} /></div>
            <div style={{ width: 28 }} />
          </div>
          {filtered.length === 0 && <div style={{ padding: 32, textAlign: 'center', color: '#404550', fontSize: Math.max(12, fs - 1) }}>No hosts. Add the first one.</div>}
          {filtered.map(host => {
            const isSel = selected === host.id;
            const isChecked = selectedIds.includes(host.id);
            const intelBadges = getHostBadges(host);
            const credCount = getHostCredCount(host);
            return (
              <div key={host.id} onClick={(e) => { if (e.target.type !== 'checkbox') setSelected(isSel ? null : host.id); }} style={{ display: 'flex', alignItems: 'stretch', minHeight: 48, padding: '9px 16px', borderBottom: '1px solid #14161b', cursor: 'pointer', background: isSel ? '#ffffff0a' : isChecked ? '#ffffff05' : 'transparent', borderLeft: isSel ? `2px solid ${accent}` : isChecked ? `2px solid ${accent}88` : '2px solid transparent' }}>
                <div style={{ width: 32, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
                  <input type="checkbox" checked={isChecked} onChange={e => {
                    e.stopPropagation();
                    setSelectedIds(prev => e.target.checked ? [...prev, host.id] : prev.filter(id => id !== host.id));
                  }} style={{ width: 14, height: 14, cursor: 'pointer', accentColor: accent }} />
                </div>
                <div style={{ width: widths.ip, flexShrink: 0, fontFamily: 'JetBrains Mono', fontSize: Math.max(11, fs - 1), color: isSel ? accent : '#9098a8', fontWeight: isSel ? 600 : 400, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center' }}>{host.ip}</div>
                <div style={{ width: widths.hostname, flexShrink: 0, fontSize: Math.max(11, fs - 1), color: '#c8cdd6', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center' }}>{host.hostname || <span style={{ color: '#303540' }}>—</span>}</div>
                <div style={{ width: widths.os, flexShrink: 0, fontSize: Math.max(10, fs - 2), color: '#606570', display: 'flex', alignItems: 'center', gap: 4, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
                  {OS_ICONS[host.os]} {host.os}
                </div>
                <div style={{ width: widths.status, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4, minWidth: 0, overflow: 'hidden', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
                  <HostStatusBadge status={host.status} />
                  {host.domain && <span title={host.domain} style={{ fontSize: 8, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af044', borderRadius: 3, padding: '1px 4px', fontFamily: 'JetBrains Mono', lineHeight: 1.2, display: 'inline-flex', alignItems: 'center' }}>AD</span>}
                </div>
                <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden', flexWrap: 'nowrap', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
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
                <div style={{ width: widths.creds, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
                  {credCount > 0
                    ? <span style={{ fontSize: Math.max(9, fs - 4), color: '#39d353', background: '#39d35322', border: '1px solid #39d35344', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{credCount}</span>
                    : <span style={{ fontSize: Math.max(9, fs - 4), color: '#303540', fontFamily: 'JetBrains Mono' }}>—</span>}
                </div>
                <div style={{ width: widths.tags, display: 'flex', gap: 3, overflow: 'hidden', alignItems: 'center', flexWrap: 'nowrap', minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
                  {intelBadges.slice(0, 2).map(b => <span key={b.label} style={{ fontSize: Math.max(9, fs - 4), color: b.color, background: `${b.color}18`, border: `1px solid ${b.color}44`, borderRadius: 3, padding: '1px 5px', whiteSpace: 'nowrap' }}>{b.label}</span>)}
                  {host.import_source && (() => {
                    const srcColors = { adaptix: '#00bcd4', cobalt_strike: '#f44336', cs: '#f44336', sliver: '#8bc34a', nmap: '#4caf50', bloodhound: '#c07af0', bh: '#c07af0' };
                    const c = srcColors[host.import_source] || '#f09a3a';
                    return <span title={`Imported from: ${host.import_source}`} style={{ fontSize: Math.max(9, fs - 4), color: c, background: `${c}18`, border: `1px solid ${c}44`, borderRadius: 3, padding: '1px 5px', whiteSpace: 'nowrap', fontFamily: 'JetBrains Mono' }}>{host.import_source}</span>;
                  })()}
                </div>
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
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {getHostBadges(selHost).map(b => <Badge key={b.label} label={b.label} color={b.color} />)}
              </div>
              {hostCredSummary.total > 0 && (
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, padding: '7px 9px' }}>
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 5 }}>Known credentials</div>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    <Badge label={`${hostCredSummary.total} linked`} color={accent} />
                    {hostCredSummary.withSecrets > 0 && <Badge label={`${hostCredSummary.withSecrets} secrets`} color="#39d353" />}
                    {hostCredSummary.passwords > 0 && <Badge label={`${hostCredSummary.passwords} passwords`} color="#5b8af5" />}
                    {hostCredSummary.hashes > 0 && <Badge label={`${hostCredSummary.hashes} hashes`} color="#c07af0" />}
                    {hostCredSummary.keys > 0 && <Badge label={`${hostCredSummary.keys} keys/tokens`} color="#f09a3a" />}
                  </div>
                </div>
              )}
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
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Role</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {Object.entries(HOST_ROLES).map(([role, meta]) => <button key={role} onClick={() => onUpdate(selHost.id, { role, is_attacker: role === 'attacker' })} style={{ background: selHost.role === role ? `${meta.color}22` : '#0e1016', border: `1px solid ${selHost.role === role ? meta.color + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: selHost.role === role ? meta.color : '#606570', fontSize: Math.max(10, fs - 3), fontFamily: 'JetBrains Mono' }}>{meta.label}</button>)}
                </div>
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
              <TagEditor label="Tags" tags={selHost.tags || []} onChange={tags => onUpdate(selHost.id, { tags })} placeholder="nginx, rce" />
              <FieldInput label="Notes" value={selHost.notes || ''} onChange={v => onUpdate(selHost.id, { notes: v })} placeholder="CVE, details..." textarea />
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Host activity log</div>
                  <button onClick={() => {
                    setShowActivityComposer(v => !v);
                    if (!showActivityComposer && !editingActivityId) setNewActivity({ title: '', activity_type: 'recon', command: '', summary: '', output: '', status: 'done' });
                  }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#808590', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{showActivityComposer || editingActivityId ? 'Hide form' : 'Add activity'}</button>
                </div>
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 8 }}>
                  {Object.entries(ACTIVITY_TYPES).map(([key, meta]) => (
                    <button key={key} onClick={() => setActivityTypeFilter(activityTypeFilter === key ? null : key)} style={{ background: activityTypeFilter === key ? `${meta.color}22` : 'transparent', border: `1px solid ${activityTypeFilter === key ? meta.color + '88' : '#2a2d35'}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: activityTypeFilter === key ? meta.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{meta.label}</button>
                  ))}
                </div>
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 10 }}>
                  {Object.entries(ACTIVITY_STATUS).map(([key, meta]) => (
                    <button key={key} onClick={() => setActivityStatusFilter(activityStatusFilter === key ? null : key)} style={{ background: activityStatusFilter === key ? `${meta.color}22` : 'transparent', border: `1px solid ${activityStatusFilter === key ? meta.color + '88' : '#2a2d35'}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: activityStatusFilter === key ? meta.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{meta.label}</button>
                  ))}
                  {(activityTypeFilter || activityStatusFilter) && <button onClick={() => { setActivityTypeFilter(null); setActivityStatusFilter(null); }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>Clear</button>}
                </div>
                {(showActivityComposer || editingActivityId) && <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: 10, marginBottom: 10 }}>
                  <input value={newActivity.title} onChange={e => setNewActivity(a => ({ ...a, title: e.target.value }))} placeholder="Title: SMB enum, nmap, exploit run..." style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box', marginBottom: 6 }} />
                  <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                    <select value={newActivity.activity_type} onChange={e => setNewActivity(a => ({ ...a, activity_type: e.target.value }))} style={{ flex: 1, minWidth: 0, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }}>
                      {['recon','scan','exploit','privesc','lateral','postex','note'].map(v => <option key={v} value={v}>{v}</option>)}
                    </select>
                    <select value={newActivity.status} onChange={e => setNewActivity(a => ({ ...a, status: e.target.value }))} style={{ flex: 1, minWidth: 0, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }}>
                      {['planned','running','done','failed'].map(v => <option key={v} value={v}>{v}</option>)}
                    </select>
                  </div>
                  <textarea value={newActivity.command} onChange={e => setNewActivity(a => ({ ...a, command: e.target.value }))} placeholder="Command or technique used" rows={2} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} />
                  <textarea value={newActivity.summary} onChange={e => setNewActivity(a => ({ ...a, summary: e.target.value }))} placeholder="Short summary of what was done / observed" rows={2} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} />
                  <textarea value={newActivity.output} onChange={e => setNewActivity(a => ({ ...a, output: e.target.value }))} placeholder="Raw output / findings / IOC / next steps" rows={4} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} />
                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, flexWrap: 'wrap', marginTop: 2 }}>
                    <button onClick={() => { setEditingActivityId(null); setShowActivityComposer(false); setNewActivity({ title: '', activity_type: 'recon', command: '', summary: '', output: '', status: 'done' }); }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{editingActivityId ? 'Cancel edit' : 'Cancel'}</button>
                    <button onClick={async () => {
                      if (!newActivity.title.trim() && !newActivity.command.trim() && !newActivity.summary.trim() && !newActivity.output.trim()) return;
                      if (editingActivityId) {
                        await onUpdateActivity?.(editingActivityId, { ...newActivity, ts: new Date().toISOString().slice(0,16).replace('T',' ') });
                      } else {
                        await onAddActivity?.({ pid: selectedProject, host_id: selHost.id, ...newActivity, ts: new Date().toISOString().slice(0,16).replace('T',' ') });
                      }
                      setNewActivity({ title: '', activity_type: 'recon', command: '', summary: '', output: '', status: 'done' });
                      setEditingActivityId(null);
                      setShowActivityComposer(false);
                    }} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>{editingActivityId ? 'Update activity' : 'Save activity'}</button>
                  </div>
                </div>}
                {selHostActivities.length === 0 && <div style={{ fontSize: Math.max(10, fs - 3), color: '#404550' }}>No recorded actions for this host</div>}
                {selHostActivities.map(act => (
                  <div key={act.id} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px', marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                      <span style={{ fontSize: 8, color: ACTIVITY_TYPES[act.activity_type]?.color || accent, background: (ACTIVITY_TYPES[act.activity_type]?.color || accent) + '18', border: `1px solid ${(ACTIVITY_TYPES[act.activity_type]?.color || accent)}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{ACTIVITY_TYPES[act.activity_type]?.label || act.activity_type}</span>
                      <span style={{ fontSize: 8, color: ACTIVITY_STATUS[act.status]?.color || '#606570', background: '#ffffff08', border: '1px solid #2a2d35', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{ACTIVITY_STATUS[act.status]?.label || act.status}</span>
                      <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginLeft: 'auto' }}>{act.ts}</span>
                    </div>
                    <div style={{ fontSize: 11, color: '#e0e4ec', fontFamily: 'Space Grotesk', fontWeight: 600, marginBottom: 4 }}>{act.title || 'Untitled activity'}</div>
                    {act.command && <div style={{ fontSize: 9, color: '#5b8af5', fontFamily: 'JetBrains Mono', marginBottom: 4, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{act.command}</div>}
                    {act.summary && <div style={{ fontSize: 10, color: '#9098a8', lineHeight: 1.5, marginBottom: act.output ? 4 : 0 }}>{act.summary}</div>}
                    {act.output && <pre style={{ margin: 0, fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 120, overflowY: 'auto', background: '#0e1016', border: '1px solid #1e2029', borderRadius: 4, padding: '8px 9px' }}>{act.output}</pre>}
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, marginTop: 6 }}>
                      <button onClick={() => { setEditingActivityId(act.id); setShowActivityComposer(true); setNewActivity({ title: act.title || '', activity_type: act.activity_type || 'recon', command: act.command || '', summary: act.summary || '', output: act.output || '', status: act.status || 'done' }); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: accent, display: 'flex', padding: 2 }}><Icon name="edit" size={11} color="currentColor" /></button>
                      <button onClick={() => onDeleteActivity?.(act.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', padding: 2 }}><Icon name="trash" size={11} color="currentColor" /></button>
                    </div>
                  </div>
                ))}
              </div>
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  Linked creds
                  {hostCreds.length > 0 && <span style={{ marginLeft: 6, color: accent }}>{hostCreds.length}</span>}
                </div>
                {hostCreds.length === 0 && <div style={{ fontSize: Math.max(10, fs - 3), color: '#404550' }}>No linked credentials</div>}
                {hostCreds.map(c => (
                  <div key={c.id} style={{ marginBottom: 6 }}>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>
                      {getCredBadges(c).slice(0, 5).map(b => <Badge key={`${c.id}-${b.label}`} label={b.label} color={b.color} />)}
                    </div>
                    <CredPanel cred={c} host={selHost} accent={accent} pid={selectedProject} linkType={c._linkType} />
                  </div>
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
          return api.batchImport(selectedProject, { hosts: payload, creds: [], source: 'nmap' });
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
