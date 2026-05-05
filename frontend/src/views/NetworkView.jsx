import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Icon from '../components/Icon.jsx';
import { FieldInput, Badge } from '../components/UI.jsx';
import { NODE_STATUS, NODE_TYPES, OS_ICONS } from '../constants.js';
import { api } from '../api.js';
import AttackVectorAnalyzer from '../components/AttackVectorAnalyzer.jsx';
import C2HostActionsPanel from '../components/C2HostActionsPanel.jsx';
import { getCredBadges, getHostBadges, summarizeCreds, normalizeDomain, domainsMatch, HOST_ROLES, isAttackerHost } from '../utils/hostMeta.js';
import TopologyBuilderModal from '../components/TopologyBuilderModal.jsx';
import CredPanel from './network-map/CredPanel.jsx';
import AddFromProjectPanel from './network-map/AddFromProjectPanel.jsx';
import { NodeShape, guessNodeType, inferAllRoles } from './network-map/NodeVisuals.jsx';
import { ACTIVITY_TYPES, ACTIVITY_STATUS, NETWORK_BACKGROUNDS, REGION_FILL, REGION_STROKE, EMPTY_ACTIVITY, INSPECTOR_TABS, ROLE_ICON } from './network-map/constants.js';

const CommitFieldInput = memo(function CommitFieldInput({ label, value, onCommit, placeholder, mono = true, textarea = false }) {
  const [draft, setDraft] = useState(value || '');

  useEffect(() => {
    setDraft(value || '');
  }, [value]);

  const commit = useCallback(() => {
    if ((value || '') !== draft) onCommit(draft);
  }, [draft, onCommit, value]);

  const commonProps = {
    value: draft,
    onChange: (e) => setDraft(e.target.value),
    onBlur: commit,
    placeholder,
    style: {
      width: '100%',
      background: '#0e1016',
      border: '1px solid #2a2d35',
      borderRadius: 4,
      padding: '6px 8px',
      color: '#c8cdd6',
      fontSize: 11,
      outline: 'none',
      fontFamily: mono ? 'JetBrains Mono' : 'Space Grotesk',
      boxSizing: 'border-box',
    },
  };

  return (
    <div>
      <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
      {textarea
        ? <textarea {...commonProps} rows={3} style={{ ...commonProps.style, resize: 'vertical' }} />
        : <input {...commonProps} onKeyDown={(e) => { if (e.key === 'Enter') e.currentTarget.blur(); }} />}
    </div>
  );
});

function NetworkInspector({ projectId, accent, selectedNode, selectedRegion, hostObj, edges, nodeById, updateNode, updateEdge, updateRegion, deleteEdge, onClose, onAddActivity, onUpdateActivity, onDeleteActivity }) {
  const [activeTab, setActiveTab] = useState('details');
  const [creds, setCreds] = useState(null);
  const [credsLoading, setCredsLoading] = useState(false);
  const [activityCache, setActivityCache] = useState({});
  const [activitiesLoading, setActivitiesLoading] = useState({});
  const [newActivity, setNewActivity] = useState(EMPTY_ACTIVITY);
  const [editingActivityId, setEditingActivityId] = useState(null);
  const [showActivityComposer, setShowActivityComposer] = useState(false);
  const [activityTypeFilter, setActivityTypeFilter] = useState(null);
  const [activityStatusFilter, setActivityStatusFilter] = useState(null);

  useEffect(() => {
    setActiveTab('details');
    setNewActivity(EMPTY_ACTIVITY);
    setEditingActivityId(null);
    setShowActivityComposer(false);
    setActivityTypeFilter(null);
    setActivityStatusFilter(null);
  }, [selectedNode?.id, selectedRegion?.id]);

  const ensureCredsLoaded = useCallback(async () => {
    if (credsLoading || creds) return creds;
    setCredsLoading(true);
    try {
      const list = await api.getCreds(projectId);
      setCreds(list);
      return list;
    } finally {
      setCredsLoading(false);
    }
  }, [creds, credsLoading, projectId]);

  const loadHostActivities = useCallback(async (hostId, { force = false } = {}) => {
    if (!hostId) return [];
    if (!force && activityCache[hostId]) return activityCache[hostId];
    setActivitiesLoading(prev => ({ ...prev, [hostId]: true }));
    try {
      const list = await api.getHostActivities(projectId, hostId);
      setActivityCache(prev => ({ ...prev, [hostId]: list }));
      return list;
    } finally {
      setActivitiesLoading(prev => ({ ...prev, [hostId]: false }));
    }
  }, [activityCache, projectId]);

  useEffect(() => {
    if (!selectedNode || !hostObj) return;
    if (activeTab === 'credentials') ensureCredsLoaded().catch(() => {});
    if (activeTab === 'activity') loadHostActivities(hostObj.id).catch(() => {});
  }, [activeTab, ensureCredsLoaded, hostObj, loadHostActivities, selectedNode]);

  const isDomainHost = !!(hostObj?.domain && hostObj.domain.trim());
  const nodeCreds = useMemo(() => {
    if (!selectedNode || !hostObj || !creds) return [];
    const nodeIps = new Set(selectedNode.ips && selectedNode.ips.length > 0 ? selectedNode.ips : (selectedNode.ip ? [selectedNode.ip] : []));
    const hostDomain = normalizeDomain(hostObj?.domain || '');
    return creds.filter(c => c.pid === projectId && (
      (c.host_ids || []).includes(hostObj.id) ||
      nodeIps.has(c.host) ||
      (hostObj.hostname && c.host === hostObj.hostname) ||
      (c.is_domain && hostDomain && domainsMatch(c.domain || '', hostDomain))
    )).map(c => ({
      ...c,
      _linkType: (c.host_ids || []).includes(hostObj.id) ? 'linked'
        : (nodeIps.has(c.host) || (hostObj.hostname && c.host === hostObj.hostname)) ? 'ip'
        : isDomainHost ? 'domain' : 'domain?',
    }));
  }, [creds, hostObj, isDomainHost, projectId, selectedNode]);

  const nodeCredSummary = useMemo(() => summarizeCreds(nodeCreds), [nodeCreds]);
  const hostActivities = hostObj ? (activityCache[hostObj.id] || []) : [];
  const selNodeActivities = useMemo(() => {
    return hostActivities
      .filter(a => !activityTypeFilter || a.activity_type === activityTypeFilter)
      .filter(a => !activityStatusFilter || a.status === activityStatusFilter)
      .sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));
  }, [activityStatusFilter, activityTypeFilter, hostActivities]);
  const selectedNodeEdges = useMemo(
    () => selectedNode ? edges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id) : [],
    [edges, selectedNode],
  );

  if (!selectedNode && !selectedRegion) return null;

  return (
    <div style={{ width: 320, background: '#0c0e13', borderLeft: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
      <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}><span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>{selectedRegion ? 'Region / subnet' : 'Node'}</span><button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={12} color="#606570" /></button></div>
      <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
        {selectedRegion ? <>
          <CommitFieldInput label="Subnet name" value={selectedRegion.label || ''} onCommit={(v) => updateRegion(selectedRegion.id, { label: v })} placeholder="10.10.10.0/24" />
          <CommitFieldInput label="Short note" value={selectedRegion.note || ''} onCommit={(v) => updateRegion(selectedRegion.id, { note: v })} placeholder="VPN segment" textarea />
          <div style={{ display: 'flex', gap: 10 }}>
            <div style={{ flex: 1 }}><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase' }}>Fill</div><input type="color" value={(selectedRegion.fill || '#5b8af522').slice(0, 7)} onChange={e => updateRegion(selectedRegion.id, { fill: e.target.value + '22' })} style={{ width: '100%', height: 34, background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4 }} /></div>
            <div style={{ flex: 1 }}><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase' }}>Outline</div><input type="color" value={selectedRegion.stroke || '#5b8af5'} onChange={e => updateRegion(selectedRegion.id, { stroke: e.target.value })} style={{ width: '100%', height: 34, background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4 }} /></div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <FieldInput label="X" value={String(Math.round(selectedRegion.x || 0))} onChange={v => updateRegion(selectedRegion.id, { x: Number(v) || 0 })} placeholder="0" />
            <FieldInput label="Y" value={String(Math.round(selectedRegion.y || 0))} onChange={v => updateRegion(selectedRegion.id, { y: Number(v) || 0 })} placeholder="0" />
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <FieldInput label="Width" value={String(Math.round(selectedRegion.w || 0))} onChange={v => updateRegion(selectedRegion.id, { w: Math.max(40, Number(v) || 40) })} placeholder="320" />
            <FieldInput label="Height" value={String(Math.round(selectedRegion.h || 0))} onChange={v => updateRegion(selectedRegion.id, { h: Math.max(40, Number(v) || 40) })} placeholder="180" />
          </div>
        </> : <>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {INSPECTOR_TABS.map(tab => {
              const active = activeTab === tab;
              return <button key={tab} onClick={() => setActiveTab(tab)} style={{ background: active ? `${accent}22` : 'transparent', border: `1px solid ${active ? accent + '66' : '#2a2d35'}`, borderRadius: 4, padding: '4px 9px', cursor: 'pointer', color: active ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{tab}</button>;
            })}
          </div>

          {activeTab === 'details' && <>
            <CommitFieldInput label="Name" value={selectedNode.label || ''} onCommit={(v) => updateNode(selectedNode.id, { label: v })} placeholder="HOST-01" />
            <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>IP / CIDR addresses</span>
                <button onClick={() => {
                  const currentIps = (selectedNode.ips && selectedNode.ips.length > 0) ? selectedNode.ips : (selectedNode.ip ? [selectedNode.ip] : []);
                  updateNode(selectedNode.id, { ips: [...currentIps, ''] });
                }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>+</button>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {(() => {
                  const displayIps = (selectedNode.ips && selectedNode.ips.length > 0) ? selectedNode.ips : (selectedNode.ip ? [selectedNode.ip] : ['']);
                  return displayIps.map((ip, i) => (
                    <div key={i} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                      <input value={ip || ''} onChange={e => {
                        const currentIps = (selectedNode.ips && selectedNode.ips.length > 0) ? [...selectedNode.ips] : (selectedNode.ip ? [selectedNode.ip] : ['']);
                        const next = [...currentIps];
                        next[i] = e.target.value;
                        const filtered = next.filter(x => x && x.trim());
                        updateNode(selectedNode.id, { ips: filtered, ip: filtered[0] || '' });
                      }} placeholder="192.168.1.1 or 10.0.0.0/24" style={{ flex: 1, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }} />
                      {displayIps.length > 1 && <button onClick={() => {
                        const currentIps = (selectedNode.ips && selectedNode.ips.length > 0) ? [...selectedNode.ips] : (selectedNode.ip ? [selectedNode.ip] : []);
                        const next = currentIps.filter((_, idx) => idx !== i);
                        updateNode(selectedNode.id, { ips: next, ip: next[0] || '' });
                      }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 2, display: 'flex' }}><Icon name="trash" size={11} color="#404550" /></button>}
                    </div>
                  ));
                })()}
              </div>
            </div>
            <CommitFieldInput label="Notes" value={selectedNode.notes || ''} onCommit={(v) => updateNode(selectedNode.id, { notes: v })} placeholder="VPN jump host" textarea />
            <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Role</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {Object.entries(HOST_ROLES).map(([role, meta]) => {
                  const active = (hostObj?.role || selectedNode.role) === role;
                  return <button key={role} onClick={() => updateNode(selectedNode.id, { role, type: meta.nodeType, is_attacker: role === 'attacker' })} style={{ background: active ? `${meta.color}22` : '#0e1016', border: `1px solid ${active ? meta.color + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: active ? meta.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4 }}><Icon name={ROLE_ICON[role] || 'server'} size={10} color={active ? meta.color : '#505560'} />{meta.label}</button>;
                })}
              </div>
            </div>
            {hostObj && <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>OS</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{['Linux', 'Windows', 'macOS', 'Various', 'Unknown'].map(os => <button key={os} onClick={() => updateNode(selectedNode.id, { os })} style={{ background: hostObj.os === os ? `${accent}22` : '#0e1016', border: `1px solid ${hostObj.os === os ? accent + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: hostObj.os === os ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{OS_ICONS[os] || '?'} {os}</button>)}</div>
            </div>}
            {hostObj && <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase' }}>Tags</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 5 }}>{(hostObj.tags || []).map(tag => <span key={tag} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 10, padding: '2px 7px', fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono' }}>{tag}<button onClick={() => updateNode(selectedNode.id, { tags: (hostObj.tags || []).filter(t => t !== tag) })} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: '#404550', display: 'flex', lineHeight: 1 }}>×</button></span>)}</div>
              <input placeholder="Add tag (Enter)" style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} onKeyDown={e => {
                if (e.key === 'Enter' && e.currentTarget.value.trim()) {
                  const newTag = e.currentTarget.value.trim();
                  updateNode(selectedNode.id, { tags: [...new Set([...(hostObj.tags || []), newTag])] });
                  e.currentTarget.value = '';
                }
              }} />
            </div>}
            <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Node type (icon)</div><div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{Object.entries(NODE_TYPES).map(([k, v]) => <button key={k} onClick={() => updateNode(selectedNode.id, { type: k })} style={{ background: selectedNode.type === k ? `${accent}22` : '#0e1016', border: `1px solid ${selectedNode.type === k ? accent + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: selectedNode.type === k ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{v.label}</button>)}</div></div>
            <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Status</div><div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>{Object.entries(NODE_STATUS).map(([k, v]) => <button key={k} onClick={() => updateNode(selectedNode.id, { status: k })} style={{ background: selectedNode.status === k ? `${v.color}18` : 'transparent', border: `1px solid ${selectedNode.status === k ? v.color + '66' : '#2a2d35'}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: v.color }} /><span style={{ fontSize: 9, color: selectedNode.status === k ? v.color : '#606570', fontFamily: 'JetBrains Mono' }}>{v.label}</span></button>)}</div></div>
            <CommitFieldInput label="Ports" value={(selectedNode.ports || []).join(', ')} onCommit={(v) => updateNode(selectedNode.id, { ports: v.split(',').map(p => p.trim()).filter(Boolean) })} placeholder="22, 80, 443" />
            {hostObj && <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>{getHostBadges(hostObj).map(b => <Badge key={b.label} label={b.label} color={b.color} />)}</div>}
            {hostObj?.domain && <div style={{ background: '#c07af011', border: '1px solid #c07af033', borderRadius: 4, padding: '5px 9px', display: 'flex', alignItems: 'center', gap: 6 }}><span style={{ fontSize: 9, color: '#c07af0', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>AD</span><span style={{ fontSize: 10, color: '#c07af0', fontFamily: 'JetBrains Mono' }}>{hostObj.domain}</span></div>}
            {(selectedNode.subnet || hostObj?.ip) && (
              <div style={{ background: '#5b8af511', border: '1px solid #5b8af533', borderRadius: 4, padding: '6px 9px', display: 'flex', flexDirection: 'column', gap: 4 }}>
                <div style={{ fontSize: 9, color: '#5b8af5', fontFamily: 'JetBrains Mono', fontWeight: 600, textTransform: 'uppercase' }}>Subnet context</div>
                <div style={{ fontSize: 10, color: '#9db8ff', fontFamily: 'JetBrains Mono' }}>{selectedNode.subnet || 'Unknown subnet'}</div>
                {hostObj?.ip && <div style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>Primary IP: {hostObj.ip}</div>}
              </div>
            )}
            {hostObj && <C2HostActionsPanel pid={projectId} host={hostObj} accent={accent} />}
            <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Links / Connections</div>
              {selectedNodeEdges.length === 0 && <div style={{ fontSize: 10, color: '#404550' }}>No connections for this host</div>}
              {selectedNodeEdges.map(edge => {
                const peer = nodeById.get(edge.from === selectedNode.id ? edge.to : edge.from) || {};
                return (
                  <div key={edge.id} style={{ display: 'flex', flexDirection: 'column', gap: 5, padding: '8px 0', borderBottom: '1px solid #14161b' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontSize: 10, color: '#9098a8', flex: 1 }}>{peer.label || '?'}</span>
                      <select value={edge.style} onChange={e => updateEdge(edge.id, { style: e.target.value })} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 3, color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '1px 4px' }}>{['normal', 'exploit', 'lateral', 'tunnel'].map(s => <option key={s} value={s}>{s}</option>)}</select>
                      <button onClick={() => deleteEdge(edge.id)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, color: '#cc2233', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '2px 6px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}><Icon name="trash" size={10} color="#cc2233" />Delete</button>
                    </div>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 9, color: '#6fc8f0', background: '#6fc8f018', border: '1px solid #6fc8f033', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{edge.type || 'link'}</span>
                      <span style={{ fontSize: 9, color: '#f09a3a', background: '#f09a3a18', border: '1px solid #f09a3a33', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{edge.state || (edge.is_manual ? 'manual' : 'inferred')}</span>
                      <span style={{ fontSize: 9, color: edge.verified ? '#39d353' : '#808590', background: (edge.verified ? '#39d35318' : '#80859018'), border: `1px solid ${edge.verified ? '#39d35333' : '#80859033'}`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{edge.verified ? 'verified' : 'unverified'}</span>
                      {edge.confidence != null && <span style={{ fontSize: 9, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{Math.round(Number(edge.confidence) * 100)}%</span>}
                    </div>
                    <input value={edge.label || ''} onChange={e => updateEdge(edge.id, { label: e.target.value })} placeholder="VPN / SMB / trust" style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 6px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
                    <div style={{ display: 'flex', gap: 6 }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 8, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>State</div>
                        <select value={edge.state || (edge.is_manual ? 'manual' : 'inferred')} onChange={e => updateEdge(edge.id, { state: e.target.value })} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 3, color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '4px 6px' }}>
                          {['manual', 'inferred', 'observed', 'blocked'].map(s => <option key={s} value={s}>{s}</option>)}
                        </select>
                      </div>
                      <div style={{ width: 96 }}>
                        <div style={{ fontSize: 8, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Verified</div>
                        <button onClick={() => updateEdge(edge.id, { verified: !edge.verified })} style={{ width: '100%', background: edge.verified ? '#39d35322' : '#0e1016', border: `1px solid ${edge.verified ? '#39d35366' : '#2a2d35'}`, borderRadius: 3, color: edge.verified ? '#39d353' : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '4px 6px', cursor: 'pointer' }}>{edge.verified ? 'Yes' : 'No'}</button>
                      </div>
                    </div>
                    <textarea value={edge.reason || ''} onChange={e => updateEdge(edge.id, { reason: e.target.value })} placeholder="Why this edge exists: same subnet, observed route, manual trust, pivot path..." style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 6px', color: '#9aa1b2', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box', resize: 'vertical', minHeight: 54 }} />
                  </div>
                );
              })}
            </div>
            <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, padding: '7px 9px' }}><div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 5 }}>Lazy data</div><div style={{ fontSize: 10, color: '#606570' }}>Credentials and activity stay out of the render path until their tab is opened.</div></div>
          </>}

          {activeTab === 'activity' && hostObj && <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}><div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Host activity log</div><button onClick={() => { setShowActivityComposer(v => !v); if (!showActivityComposer && !editingActivityId) setNewActivity(EMPTY_ACTIVITY); }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#808590', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{showActivityComposer || editingActivityId ? 'Hide form' : 'Add activity'}</button></div>
            <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 6 }}>{Object.entries(ACTIVITY_TYPES).map(([key, meta]) => <button key={key} onClick={() => setActivityTypeFilter(activityTypeFilter === key ? null : key)} style={{ background: activityTypeFilter === key ? `${meta.color}22` : 'transparent', border: `1px solid ${activityTypeFilter === key ? meta.color + '88' : '#2a2d35'}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: activityTypeFilter === key ? meta.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{meta.label}</button>)}</div>
            <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 8 }}>{Object.entries(ACTIVITY_STATUS).map(([key, meta]) => <button key={key} onClick={() => setActivityStatusFilter(activityStatusFilter === key ? null : key)} style={{ background: activityStatusFilter === key ? `${meta.color}22` : 'transparent', border: `1px solid ${activityStatusFilter === key ? meta.color + '88' : '#2a2d35'}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: activityStatusFilter === key ? meta.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{meta.label}</button>)}{(activityTypeFilter || activityStatusFilter) && <button onClick={() => { setActivityTypeFilter(null); setActivityStatusFilter(null); }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>Clear</button>}</div>
            {(showActivityComposer || editingActivityId) && <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: 10, marginBottom: 10 }}><input value={newActivity.title} onChange={e => setNewActivity(a => ({ ...a, title: e.target.value }))} placeholder="Title: SMB enum, nmap, exploit..." style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box', marginBottom: 6 }} /><div style={{ display: 'flex', gap: 6, marginBottom: 6 }}><select value={newActivity.activity_type} onChange={e => setNewActivity(a => ({ ...a, activity_type: e.target.value }))} style={{ flex: 1, minWidth: 0, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }}>{['recon','scan','exploit','privesc','lateral','postex','note'].map(v => <option key={v} value={v}>{v}</option>)}</select><select value={newActivity.status} onChange={e => setNewActivity(a => ({ ...a, status: e.target.value }))} style={{ flex: 1, minWidth: 0, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }}>{['planned','running','done','failed'].map(v => <option key={v} value={v}>{v}</option>)}</select></div><textarea value={newActivity.command} onChange={e => setNewActivity(a => ({ ...a, command: e.target.value }))} placeholder="Command or technique used" rows={2} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} /><textarea value={newActivity.summary} onChange={e => setNewActivity(a => ({ ...a, summary: e.target.value }))} placeholder="Short summary of what was observed" rows={2} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} /><textarea value={newActivity.output} onChange={e => setNewActivity(a => ({ ...a, output: e.target.value }))} placeholder="Raw output / findings / IOC / next steps" rows={3} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} /><div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, flexWrap: 'wrap' }}><button onClick={() => { setEditingActivityId(null); setShowActivityComposer(false); setNewActivity(EMPTY_ACTIVITY); }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{editingActivityId ? 'Cancel edit' : 'Cancel'}</button><button onClick={async () => {
              if (!newActivity.title.trim() && !newActivity.command.trim() && !newActivity.summary.trim() && !newActivity.output.trim()) return;
              if (editingActivityId) {
                const updated = await onUpdateActivity?.(editingActivityId, { ...newActivity, ts: new Date().toISOString().slice(0, 16).replace('T', ' ') });
                if (updated) setActivityCache(prev => ({ ...prev, [hostObj.id]: (prev[hostObj.id] || []).map(item => item.id === editingActivityId ? updated : item) }));
              } else {
                const created = await onAddActivity?.({ pid: projectId, host_id: hostObj.id, ...newActivity, ts: new Date().toISOString().slice(0, 16).replace('T', ' ') });
                if (created) setActivityCache(prev => ({ ...prev, [hostObj.id]: prev[hostObj.id] ? [created, ...prev[hostObj.id]] : [created] }));
              }
              setNewActivity(EMPTY_ACTIVITY);
              setEditingActivityId(null);
              setShowActivityComposer(false);
            }} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>{editingActivityId ? 'Update activity' : 'Save activity'}</button></div></div>}
            {activitiesLoading[hostObj.id] && <div style={{ fontSize: 10, color: '#404550' }}>Loading activity…</div>}
            {!activitiesLoading[hostObj.id] && selNodeActivities.length === 0 && !showActivityComposer && !editingActivityId && <div style={{ fontSize: 10, color: '#404550' }}>No recorded actions for this host</div>}
            {selNodeActivities.map(act => <div key={act.id} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px', marginBottom: 8 }}><div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}><span style={{ fontSize: 8, color: ACTIVITY_TYPES[act.activity_type]?.color || accent, background: (ACTIVITY_TYPES[act.activity_type]?.color || accent) + '18', border: `1px solid ${(ACTIVITY_TYPES[act.activity_type]?.color || accent)}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{ACTIVITY_TYPES[act.activity_type]?.label || act.activity_type}</span><span style={{ fontSize: 8, color: ACTIVITY_STATUS[act.status]?.color || '#606570', background: '#ffffff08', border: '1px solid #2a2d35', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{ACTIVITY_STATUS[act.status]?.label || act.status}</span><span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginLeft: 'auto' }}>{act.ts}</span></div><div style={{ fontSize: 11, color: '#e0e4ec', fontFamily: 'Space Grotesk', fontWeight: 600, marginBottom: 4 }}>{act.title || 'Untitled activity'}</div>{act.command && <div style={{ fontSize: 9, color: '#5b8af5', fontFamily: 'JetBrains Mono', marginBottom: 4, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{act.command}</div>}{act.summary && <div style={{ fontSize: 10, color: '#9098a8', lineHeight: 1.5, marginBottom: act.output ? 4 : 0 }}>{act.summary}</div>}{act.output && <pre style={{ margin: 0, fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 120, overflowY: 'auto', background: '#0e1016', border: '1px solid #1e2029', borderRadius: 4, padding: '8px 9px' }}>{act.output}</pre>}<div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, marginTop: 6 }}><button onClick={() => { setEditingActivityId(act.id); setShowActivityComposer(true); setNewActivity({ title: act.title || '', activity_type: act.activity_type || 'recon', command: act.command || '', summary: act.summary || '', output: act.output || '', status: act.status || 'done' }); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: accent, display: 'flex', padding: 2 }}><Icon name="edit" size={11} color="currentColor" /></button><button onClick={async () => { await onDeleteActivity?.(act.id); setActivityCache(prev => ({ ...prev, [hostObj.id]: (prev[hostObj.id] || []).filter(item => item.id !== act.id) })); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', padding: 2 }}><Icon name="trash" size={11} color="currentColor" /></button></div></div>)}
          </div>}

          {activeTab === 'credentials' && hostObj && <div>
            {credsLoading && <div style={{ fontSize: 10, color: '#404550', marginBottom: 8 }}>Loading credentials…</div>}
            {!credsLoading && nodeCredSummary.total > 0 && <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, padding: '7px 9px', marginBottom: 10 }}><div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 5 }}>Known credentials</div><div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}><Badge label={`${nodeCredSummary.total} linked`} color={accent} />{nodeCredSummary.withSecrets > 0 && <Badge label={`${nodeCredSummary.withSecrets} secrets`} color="#39d353" />}{nodeCredSummary.passwords > 0 && <Badge label={`${nodeCredSummary.passwords} passwords`} color="#5b8af5" />}{nodeCredSummary.hashes > 0 && <Badge label={`${nodeCredSummary.hashes} hashes`} color="#c07af0" />}</div></div>}
            {!credsLoading && nodeCreds.length === 0 && <div style={{ fontSize: 10, color: '#404550' }}>No linked credentials</div>}
            {hostObj ? nodeCreds.map(c => <div key={c.id} style={{ marginBottom: 6 }}><div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>{getCredBadges(c).slice(0, 5).map(b => <Badge key={`${c.id}-${b.label}`} label={b.label} color={b.color} />)}</div><CredPanel cred={c} host={hostObj} accent={accent} pid={projectId} linkType={c._linkType} /></div>) : null}
          </div>}
        </>}
      </div>
    </div>
  );
}

function NetworkCanvas({ projectId, net, onUpdate, onCreateHost, onUpdateHost, onSyncHostByIp, accent, accentGreen, hosts, onAddActivity, onUpdateActivity, onDeleteActivity, markLocalOp, animateLinks, overlayData }) {
  const [selectedNodeIds, setSelectedNodeIds] = useState([]);
  const [selectedRegionId, setSelectedRegionId] = useState(null);
  const [connecting, setConnecting] = useState(null);
  const [showOverlay, setShowOverlay] = useState(false);
  const [pan, setPan] = useState({ x: 40, y: 40 });
  const [zoom, setZoom] = useState(1);
  const [draggingNode, setDraggingNode] = useState(null);
  const [draggingRegion, setDraggingRegion] = useState(null);
  const [resizingRegion, setResizingRegion] = useState(null);
  const [draggingCanvas, setDraggingCanvas] = useState(null);
  const [showAddFromProject, setShowAddFromProject] = useState(false);
  const [showAttackAnalyzer, setShowAttackAnalyzer] = useState(false);
  const [showCreateNode, setShowCreateNode] = useState(false);
  const [nodeDraft, setNodeDraft] = useState({ ip: '', hostname: '', os: 'Unknown', role: 'unknown', status: 'unknown', domain: '' });
  const [edgeMenu, setEdgeMenu] = useState(null);
  const [regionEditMode, setRegionEditMode] = useState(false);
  const [selectBox, setSelectBox] = useState(null);
  const [analysisCreds, setAnalysisCreds] = useState(null);
  const [analysisCredsLoading, setAnalysisCredsLoading] = useState(false);
  const [historyState, setHistoryState] = useState({ past: [], future: [] });
  const svgRef = useRef();
  const dragOffset = useRef({ x: 0, y: 0 });
  const canvasGroupRef = useRef(null);
  const panRef = useRef({ x: 40, y: 40 });
  const commitTimerRef = useRef(null);
  const draftNetRef = useRef(net || { nodes: [], edges: [], regions: [] });
  const hostSyncTimersRef = useRef({});
  const pendingHostPatchesRef = useRef({});
  const pendingHostNodesRef = useRef({});
  const renderCountRef = useRef(0);
  const interactionStartRef = useRef(null);
  const lastPositionSyncRef = useRef(0);
  const netIdRef = useRef(net?.id || null);

  renderCountRef.current += 1;

  const [draftNet, setDraftNet] = useState(() => net || { nodes: [], edges: [], regions: [] });

  const cloneNet = useCallback((value) => JSON.parse(JSON.stringify(value || { nodes: [], edges: [], regions: [] })), []);
  const sameNet = useCallback((a, b) => JSON.stringify(a || {}) === JSON.stringify(b || {}), []);

  useEffect(() => {
    const next = net || { nodes: [], edges: [], regions: [] };
    const nextClone = cloneNet(next);
    if (netIdRef.current !== (net?.id || null)) {
      netIdRef.current = net?.id || null;
      draftNetRef.current = nextClone;
      setDraftNet(nextClone);
      interactionStartRef.current = null;
      setHistoryState({ past: [], future: [] });
      return;
    }
    if (sameNet(nextClone, draftNetRef.current)) return;
    setHistoryState(state => ({ past: [...state.past, cloneNet(draftNetRef.current)], future: [] }));
    draftNetRef.current = nextClone;
    setDraftNet(nextClone);
    interactionStartRef.current = null;
  }, [cloneNet, net, sameNet]);

  const nodes = draftNet?.nodes || [];
  const edges = draftNet?.edges || [];
  const regions = draftNet?.regions || [];

  const flushNetUpdate = useCallback((next = draftNetRef.current) => {
    if (commitTimerRef.current) {
      clearTimeout(commitTimerRef.current);
      commitTimerRef.current = null;
    }
    onUpdate(next);
  }, [onUpdate]);

  const pushHistorySnapshot = useCallback((previous, next) => {
    if (sameNet(previous, next)) return;
    setHistoryState(state => ({
      past: [...state.past, cloneNet(previous)],
      future: [],
    }));
  }, [cloneNet, sameNet]);

  const applySnapshot = useCallback((snapshot) => {
    if (commitTimerRef.current) {
      clearTimeout(commitTimerRef.current);
      commitTimerRef.current = null;
    }
    const next = cloneNet(snapshot);
    draftNetRef.current = next;
    setDraftNet(next);
    onUpdate(next);
  }, [cloneNet, onUpdate]);

  const emit = useCallback((patch, { immediate = false, history = 'push', persist = true } = {}) => {
    setDraftNet(prev => {
      const next = { ...(prev || { nodes: [], edges: [], regions: [] }), ...patch };
      if (history === 'push') pushHistorySnapshot(prev, next);
      draftNetRef.current = next;
      if (persist) {
        if (commitTimerRef.current) clearTimeout(commitTimerRef.current);
        if (immediate) {
          queueMicrotask(() => onUpdate(next));
        } else {
          commitTimerRef.current = setTimeout(() => {
            commitTimerRef.current = null;
            onUpdate(draftNetRef.current);
          }, 240);
        }
      }
      return next;
    });
  }, [onUpdate, pushHistorySnapshot]);

  const newLocalMutationId = useCallback(() => `nm_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`, []);

  // O(1) lookups — avoid O(n) find() in render loops
  const nodeById = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes]);
  const hostById = useMemo(() => new Map((hosts || []).map(h => [h.id, h])), [hosts]);

  // Viewport culling — only render nodes/edges visible on screen (+buffer)
  const { visibleNodes, visibleEdges } = useMemo(() => {
    const el = svgRef.current;
    if (!el) return { visibleNodes: nodes, visibleEdges: edges };
    const { width, height } = el.getBoundingClientRect();
    const buf = 250;
    const L = (-pan.x - buf) / zoom;
    const T = (-pan.y - buf) / zoom;
    const R = (width  - pan.x + buf) / zoom;
    const B = (height - pan.y + buf) / zoom;
    const vn = nodes.filter(n => n.x > L && n.x < R && n.y > T && n.y < B);
    const vnSet = new Set(vn.map(n => n.id));
    const ve = edges.filter(e => vnSet.has(e.from) || vnSet.has(e.to));
    return { visibleNodes: vn, visibleEdges: ve };
  }, [nodes, edges, pan, zoom]);

  // Pre-compute role badges once per nodes change — not per render
  const roleBadgesByNodeId = useMemo(() => {
    const m = new Map();
    nodes.forEach(node => {
      const host = hostById.get(node.host_id);
      m.set(node.id, inferAllRoles(host || (node.role ? { role: node.role, tags: [], ports: node.ports || [] } : null)));
    });
    return m;
  }, [nodes, hostById]);

  const selectedNodeSet = useMemo(() => new Set(selectedNodeIds), [selectedNodeIds]);
  const selectedNode = useMemo(() => selectedNodeIds.length === 1 ? nodeById.get(selectedNodeIds[0]) ?? null : null, [selectedNodeIds, nodeById]);

  const attackPathSet = useMemo(() => {
    if (!showOverlay || selectedNodeIds.length === 0) return null;

    // Use ALL nodes/edges so path through off-screen nodes works
    const adj = new Map();
    for (const e of edges) {
      if (!adj.has(e.from)) adj.set(e.from, []);
      if (!adj.has(e.to)) adj.set(e.to, []);
      adj.get(e.from).push({ node: e.to, eid: e.id });
      adj.get(e.to).push({ node: e.from, eid: e.id });
    }

    // BFS shortest path from a set of starts to a single target; returns path nodes+edges or null
    const bfsPath = (startSet, targetId) => {
      if (startSet.has(targetId)) return { pathNodes: new Set([targetId]), pathEdges: new Set() };
      const parent = new Map();
      for (const id of startSet) parent.set(id, null);
      const queue = [...startSet];
      while (queue.length) {
        const cur = queue.shift();
        for (const { node, eid } of (adj.get(cur) || [])) {
          if (!parent.has(node)) {
            parent.set(node, { from: cur, eid });
            if (node === targetId) {
              const pathNodes = new Set();
              const pathEdges = new Set();
              let n = node;
              while (n != null) {
                pathNodes.add(n);
                const p = parent.get(n);
                if (p) { pathEdges.add(p.eid); n = p.from; } else break;
              }
              return { pathNodes, pathEdges };
            }
            queue.push(node);
          }
        }
      }
      return null;
    };

    const attackerNodeIds = new Set(
      nodes
        .filter(n => {
          const h = (hosts || []).find(x => x.id === n.host_id || (n.ip && x.ip === n.ip));
          return h && isAttackerHost(h);
        })
        .map(n => n.id)
    );

    const pathNodes = new Set(selectedNodeSet);
    const pathEdges = new Set();

    if (attackerNodeIds.size > 0) {
      for (const targetId of selectedNodeIds) {
        const result = bfsPath(attackerNodeIds, targetId);
        if (result) {
          for (const n of result.pathNodes) pathNodes.add(n);
          for (const e of result.pathEdges) pathEdges.add(e);
          for (const id of attackerNodeIds) pathNodes.add(id);
        } else {
          // No path to this target — show its direct neighbours
          for (const { node, eid } of (adj.get(targetId) || [])) {
            pathNodes.add(node);
            pathEdges.add(eid);
          }
        }
      }
    } else {
      // No attacker on map — selected + direct neighbours
      for (const id of selectedNodeSet) {
        for (const { node, eid } of (adj.get(id) || [])) {
          pathNodes.add(node);
          pathEdges.add(eid);
        }
      }
    }

    return { nodes: pathNodes, edges: pathEdges };
  }, [showOverlay, selectedNodeIds, selectedNodeSet, nodes, edges, hosts]);
  const selectedRegion = regions.find(r => r.id === selectedRegionId) || null;
  const hostObj = useMemo(() => {
    if (!selectedNode) return null;
    if (selectedNode.host_id) return (hosts || []).find(h => h.id === selectedNode.host_id) || null;
    const nodeIps = selectedNode.ips && selectedNode.ips.length > 0 ? selectedNode.ips : (selectedNode.ip ? [selectedNode.ip] : []);
    return (hosts || []).find(h => nodeIps.includes(h.ip)) || null;
  }, [selectedNode, hosts]);

  useEffect(() => {
    setSelectedNodeIds(prev => prev.filter(id => nodeById.has(id)));
    if (selectedRegionId && !regions.find(region => region.id === selectedRegionId)) setSelectedRegionId(null);
  }, [nodeById, regions, selectedRegionId]);

  useEffect(() => { setSelectedNodeIds([]); setSelectedRegionId(null); setConnecting(null); setEdgeMenu(null); }, [net?.id]);
  const nodesRef = useRef(nodes);
  useEffect(() => {
    nodesRef.current = nodes;
  }, [nodes]);

  useEffect(() => {
    const onKeyDown = (e) => {
      const key = e.key.toLowerCase();
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && key === 'z') {
        e.preventDefault();
        setHistoryState(state => {
          if (!state.past.length) return state;
          const previous = state.past[state.past.length - 1];
          const current = cloneNet(draftNetRef.current);
          queueMicrotask(() => applySnapshot(previous));
          return { past: state.past.slice(0, -1), future: [current, ...state.future] };
        });
        return;
      }
      if ((e.ctrlKey || e.metaKey) && ((e.shiftKey && key === 'z') || key === 'y')) {
        e.preventDefault();
        setHistoryState(state => {
          if (!state.future.length) return state;
          const next = state.future[0];
          const current = cloneNet(draftNetRef.current);
          queueMicrotask(() => applySnapshot(next));
          return { past: [...state.past, current], future: state.future.slice(1) };
        });
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a') {
        e.preventDefault();
        setSelectedNodeIds(nodesRef.current.map(n => n.id));
        setSelectedRegionId(null);
      }
      if (e.key === 'Escape') {
        setSelectedNodeIds([]);
        setSelectedRegionId(null);
        setConnecting(null);
        setEdgeMenu(null);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [applySnapshot, cloneNet]);

  const getSVGPt = useCallback((e) => {
    const r = svgRef.current.getBoundingClientRect();
    return { x: (e.clientX - r.left - pan.x) / zoom, y: (e.clientY - r.top - pan.y) / zoom };
  }, [pan.x, pan.y, zoom]);

  const flushHostSync = useCallback(async (key) => {
    const patch = pendingHostPatchesRef.current[key];
    const node = pendingHostNodesRef.current[key];
    delete pendingHostPatchesRef.current[key];
    delete pendingHostNodesRef.current[key];
    delete hostSyncTimersRef.current[key];
    if (!patch || !node) return;
    const linkedHost = node.host_id ? hosts.find(h => h.id === node.host_id) : null;
    if (linkedHost && Object.keys(patch).length) {
      await onUpdateHost?.(linkedHost.id, patch);
    } else if (node.ip && Object.keys(patch).length) {
      await onSyncHostByIp?.(node.ip, patch);
    }
  }, [hosts, onSyncHostByIp, onUpdateHost]);

  const syncDraggedNodePositions = useCallback((nodeIds, { force = false } = {}) => {
    const now = Date.now();
    if (!force && now - lastPositionSyncRef.current < 140) return;
    lastPositionSyncRef.current = now;
    const movedNodes = (draftNetRef.current.nodes || []).filter(item => nodeIds.has(item.id));
    movedNodes.forEach((node) => {
      const lid = newLocalMutationId();
      markLocalOp?.(lid);
      api.updateNetworkNodePosition(projectId, node.id, net.id, {
        x: node.x,
        y: node.y,
        manually_positioned: true,
        client_mutation_id: lid,
      }).catch(() => {});
    });
  }, [markLocalOp, net.id, newLocalMutationId, projectId]);

  const scheduleHostSync = useCallback((node, hostPatch) => {
    const key = node?.host_id || node?.ip;
    if (!key || !hostPatch || !Object.keys(hostPatch).length) return;
    pendingHostPatchesRef.current[key] = { ...(pendingHostPatchesRef.current[key] || {}), ...hostPatch };
    pendingHostNodesRef.current[key] = { ...node, ...hostPatch };
    if (hostSyncTimersRef.current[key]) clearTimeout(hostSyncTimersRef.current[key]);
    hostSyncTimersRef.current[key] = setTimeout(() => {
      flushHostSync(key).catch(() => {});
    }, 350);
  }, [flushHostSync]);

  const updateNode = useCallback((id, patch) => {
    const node = nodes.find(n => n.id === id);
    emit({ nodes: nodes.map(n => n.id === id ? { ...n, ...patch } : n) }, { persist: false });
    const hostPatch = {};
    if (patch.status !== undefined) hostPatch.status = patch.status;
    if (patch.ip !== undefined) hostPatch.ip = patch.ip;
    if (patch.ips !== undefined) hostPatch.ips = patch.ips;
    if (patch.label !== undefined) hostPatch.hostname = patch.label;
    if (patch.os !== undefined) hostPatch.os = patch.os;
    if (patch.tags !== undefined) hostPatch.tags = patch.tags;
    if (patch.role !== undefined) {
      hostPatch.role = patch.role;
      hostPatch.is_attacker = patch.role === 'attacker';
    }
    if (patch.is_attacker !== undefined) hostPatch.is_attacker = patch.is_attacker;
    if (patch.type !== undefined) {
      const roleEntry = Object.entries(HOST_ROLES).find(([, meta]) => meta.nodeType === patch.type) || (patch.type === 'dc' ? ['domain_controller', HOST_ROLES.domain_controller] : null);
      if (roleEntry && patch.role === undefined) {
        hostPatch.role = roleEntry[0];
        hostPatch.is_attacker = roleEntry[0] === 'attacker';
      }
    }
    scheduleHostSync({ ...node, ...patch }, hostPatch);
    const lid = newLocalMutationId();
    markLocalOp?.(lid);
    api.updateNetworkNode(projectId, id, net.id, { ...patch, client_mutation_id: lid }).catch(() => {});
  }, [emit, markLocalOp, net.id, newLocalMutationId, nodes, projectId, scheduleHostSync]);
  const updateEdge = useCallback((id, patch) => {
    emit({ edges: edges.map(e => e.id === id ? { ...e, ...patch } : e) }, { persist: false });
    const lid = newLocalMutationId();
    markLocalOp?.(lid);
    api.updateNetworkLink(projectId, id, net.id, { ...patch, client_mutation_id: lid }).catch(() => {});
  }, [edges, emit, markLocalOp, net.id, newLocalMutationId, projectId]);
  const updateRegion = useCallback((id, patch) => {
    emit({ regions: regions.map(r => r.id === id ? { ...r, ...patch } : r) }, { persist: false });
    const lid = newLocalMutationId();
    markLocalOp?.(lid);
    api.updateNetworkRegion(projectId, id, net.id, { ...patch, client_mutation_id: lid }).catch(() => {});
  }, [emit, markLocalOp, net.id, newLocalMutationId, projectId, regions]);
  const deleteEdge = useCallback(async (id) => {
    emit({ edges: edges.filter(e => e.id !== id) }, { persist: false });
    await api.deleteNetworkLink(projectId, id, net.id).catch(() => {});
  }, [edges, emit, net.id, projectId]);

  const onNodeMouseDown = async (e, nid) => {
    e.stopPropagation();
    
    if (connecting) {
      // Create edges from all selected nodes to the clicked node
      const sourceNodes = selectedNodeIds.length > 0 ? selectedNodeIds : [connecting];
      const newEdges = sourceNodes
        .filter(srcId => srcId !== nid) // Don't create self-loop
        .map(srcId => ({ 
          from_node_id: srcId,
          to_node_id: nid,
          label: 'link', 
          style: 'normal' 
        }));
      if (newEdges.length > 0) {
        const created = await Promise.all(newEdges.map(async (edge) => {
          const lid = newLocalMutationId();
          markLocalOp?.(lid);
          const result = await api.createNetworkLink(projectId, { network_id: net.id, ...edge, client_mutation_id: lid });
          return result.link;
        })).catch(() => []);
        if (created.length > 0) emit({ edges: [...edges, ...created] }, { persist: false });
      }
      setConnecting(null);
      return;
    }
    
    // If Shift/Ctrl/Meta is held, toggle selection without starting drag
    if (e.shiftKey || e.ctrlKey || e.metaKey) {
      setSelectedNodeIds(prev => prev.includes(nid) ? prev.filter(x => x !== nid) : [...prev, nid]);
      setSelectedRegionId(null);
      return;
    }
    
    // Otherwise, select this node and start dragging
    if (!selectedNodeIds.includes(nid)) {
      setSelectedNodeIds([nid]);
    }
    setSelectedRegionId(null);
    const node = nodes.find(n => n.id === nid);
    const pt = getSVGPt(e);
    dragOffset.current = { x: pt.x - node.x, y: pt.y - node.y };
    interactionStartRef.current = cloneNet(draftNetRef.current);
    setDraggingNode(nid);
  };

  const onRegionMouseDown = (e, rid) => {
    // If Shift is held, allow drag-select to work - don't stop propagation
    if (e.shiftKey) return;
    
    e.stopPropagation();
    // Allow dragging with LKM only in region edit mode or when region is already selected
    if (!regionEditMode && selectedRegionId !== rid) return;
    const region = regions.find(r => r.id === rid);
    setSelectedRegionId(rid);
    setSelectedNodeIds([]);
    const pt = getSVGPt(e);
    dragOffset.current = { x: pt.x - region.x, y: pt.y - region.y };
    interactionStartRef.current = cloneNet(draftNetRef.current);
    setDraggingRegion(rid);
  };
  
  const onRegionContextMenu = (e, rid) => {
    e.preventDefault();
    e.stopPropagation();
    setSelectedRegionId(rid);
    setSelectedNodeIds([]);
    setRegionEditMode(true);
  };

  const onSVGMouseDown = (e) => {
    if (e.button === 2) return; // Ignore right click on canvas
    
    // If shift key is held, start drag-select instead of panning
    if (e.shiftKey) {
      const pt = getSVGPt(e);
      setSelectBox({ startX: pt.x, startY: pt.y, endX: pt.x, endY: pt.y });
      setEdgeMenu(null);
      setRegionEditMode(false);
      return;
    }
    
    setSelectedNodeIds([]);
    setSelectedRegionId(null);
    setEdgeMenu(null);
    setRegionEditMode(false);
    setDraggingCanvas({ startX: e.clientX - pan.x, startY: e.clientY - pan.y });
  };

  const onMouseMove = (e) => {
    if (selectBox) {
      const pt = getSVGPt(e);
      setSelectBox(prev => ({ ...prev, endX: pt.x, endY: pt.y }));
      
      // Calculate selected nodes within box
      const minX = Math.min(selectBox.startX, pt.x);
      const maxX = Math.max(selectBox.startX, pt.x);
      const minY = Math.min(selectBox.startY, pt.y);
      const maxY = Math.max(selectBox.startY, pt.y);
      
      const nodesInBox = nodes.filter(n => 
        n.x >= minX && n.x <= maxX && n.y >= minY && n.y <= maxY
      );
      setSelectedNodeIds(nodesInBox.map(n => n.id));
    } else if (draggingNode) {
      const pt = getSVGPt(e);
      const lead = nodes.find(n => n.id === draggingNode);
      const dx = pt.x - dragOffset.current.x - lead.x;
      const dy = pt.y - dragOffset.current.y - lead.y;
      emit({ nodes: nodes.map(n => selectedNodeSet.has(n.id) ? { ...n, x: n.x + dx, y: n.y + dy } : n) }, { history: 'skip', persist: false });
      syncDraggedNodePositions(selectedNodeSet);
    } else if (draggingRegion) {
      const pt = getSVGPt(e);
      const region = regions.find(r => r.id === draggingRegion);
      emit({ regions: regions.map(r => r.id === draggingRegion ? { ...r, x: pt.x - dragOffset.current.x, y: pt.y - dragOffset.current.y, w: region.w, h: region.h } : r) }, { history: 'skip', persist: false });
    } else if (resizingRegion) {
      const pt = getSVGPt(e);
      const region = regions.find(r => r.id === resizingRegion.id);
      if (!region) return;
      const min = 40;
      let patch = {};
      if (resizingRegion.corner === 'se') {
        patch = { w: Math.max(min, pt.x - region.x), h: Math.max(min, pt.y - region.y) };
      } else if (resizingRegion.corner === 'sw') {
        const newX = Math.min(region.x + region.w - min, pt.x);
        patch = { x: newX, w: Math.max(min, region.x + region.w - newX), h: Math.max(min, pt.y - region.y) };
      } else if (resizingRegion.corner === 'ne') {
        const newY = Math.min(region.y + region.h - min, pt.y);
        patch = { y: newY, h: Math.max(min, region.y + region.h - newY), w: Math.max(min, pt.x - region.x) };
      } else if (resizingRegion.corner === 'nw') {
        const newX = Math.min(region.x + region.w - min, pt.x);
        const newY = Math.min(region.y + region.h - min, pt.y);
        patch = { x: newX, y: newY, w: Math.max(min, region.x + region.w - newX), h: Math.max(min, region.y + region.h - newY) };
      }
      emit({ regions: regions.map(r => r.id === region.id ? { ...r, ...patch } : r) }, { history: 'skip', persist: false });
    } else if (draggingCanvas) {
      const newPan = { x: e.clientX - draggingCanvas.startX, y: e.clientY - draggingCanvas.startY };
      panRef.current = newPan;
      if (canvasGroupRef.current) {
        canvasGroupRef.current.setAttribute('transform', `translate(${newPan.x},${newPan.y}) scale(${zoom})`);
      }
    }
  };

  const onMouseUp = () => {
    if (draggingCanvas) setPan(panRef.current);
    if (draggingNode || draggingRegion || resizingRegion) {
      if (interactionStartRef.current) {
        pushHistorySnapshot(interactionStartRef.current, draftNetRef.current);
        interactionStartRef.current = null;
      }
      if (draggingNode) {
        syncDraggedNodePositions(selectedNodeSet, { force: true });
      } else if (draggingRegion || resizingRegion) {
        const regionId = draggingRegion || resizingRegion?.id;
        const region = draftNetRef.current.regions?.find(item => item.id === regionId);
        if (region) {
          const lid = newLocalMutationId();
          markLocalOp?.(lid);
          api.updateNetworkRegion(projectId, region.id, net.id, {
            x: region.x,
            y: region.y,
            w: region.w,
            h: region.h,
            client_mutation_id: lid,
          }).catch(() => {});
        }
      } else {
        flushNetUpdate();
      }
    }
    setDraggingNode(null);
    setDraggingRegion(null);
    setResizingRegion(null);
    setDraggingCanvas(null);
    setSelectBox(null);
  };
  const onWheel = (e) => { e.preventDefault(); setZoom(z => Math.min(3, Math.max(0.3, z * (e.deltaY < 0 ? 1.1 : 0.91)))); };

  useEffect(() => {
    return () => {
      if (commitTimerRef.current) {
        clearTimeout(commitTimerRef.current);
        onUpdate(draftNetRef.current);
      }
      Object.values(hostSyncTimersRef.current).forEach(clearTimeout);
      hostSyncTimersRef.current = {};
      pendingHostPatchesRef.current = {};
      pendingHostNodesRef.current = {};
    };
  }, [onUpdate]);

  useEffect(() => {
    if (!import.meta.env.DEV) return undefined;
    window.measureNetworkMapPerformance = () => ({
      renderCount: renderCountRef.current,
      nodeCount: nodes.length,
      edgeCount: edges.length,
      regionCount: regions.length,
      visibleNodeCount: visibleNodes.length,
      visibleEdgeCount: visibleEdges.length,
      selectedNodeCount: selectedNodeIds.length,
      zoom,
    });
    return () => {
      if (window.measureNetworkMapPerformance) delete window.measureNetworkMapPerformance;
    };
  }, [edges.length, nodes.length, regions.length, selectedNodeIds.length, visibleEdges.length, visibleNodes.length, zoom]);

  useEffect(() => {
    if (!showAttackAnalyzer || analysisCreds || analysisCredsLoading) return;
    setAnalysisCredsLoading(true);
    api.getCreds(projectId)
      .then(setAnalysisCreds)
      .finally(() => setAnalysisCredsLoading(false));
  }, [analysisCreds, analysisCredsLoading, projectId, showAttackAnalyzer]);

  const addNode = async () => {
    const ip = nodeDraft.ip.trim();
    const hostname = nodeDraft.hostname.trim();
    if (!ip && !hostname) return;
    let host = hosts.find(h => h.pid === projectId && ((ip && h.ip === ip) || (hostname && h.hostname?.toLowerCase() === hostname.toLowerCase())));
    if (host) {
      host = await onUpdateHost?.(host.id, { hostname: hostname || host.hostname, ip: ip || host.ip, os: nodeDraft.os, role: nodeDraft.role, is_attacker: nodeDraft.role === 'attacker', status: nodeDraft.role === 'attacker' ? 'attacker' : nodeDraft.status, domain: nodeDraft.domain }) || host;
    } else {
      host = await onCreateHost({ pid: projectId, ip: ip || `0.0.0.${Math.floor(Math.random() * 200 + 20)}`, hostname: hostname || 'new-host', os: nodeDraft.os, role: nodeDraft.role, is_attacker: nodeDraft.role === 'attacker', domain: nodeDraft.domain, status: nodeDraft.role === 'attacker' ? 'attacker' : nodeDraft.status, ports: [], services: [], tags: [], notes: '' });
    }
    const existingNode = nodes.find(n => (n.host_id && n.host_id === host.id) || n.ip === host.ip);
    if (existingNode) {
      updateNode(existingNode.id, { host_id: host.id, label: host.hostname || host.ip, ip: host.ip, ips: host.ips || [host.ip], type: guessNodeType(host), status: isAttackerHost(host) ? 'attacker' : host.status, ports: host.ports || [], notes: host.notes || '' });
      setSelectedNodeIds([existingNode.id]);
    } else {
      const lid = newLocalMutationId();
      markLocalOp?.(lid);
      const result = await api.createNetworkNode(projectId, {
        network_id: net.id,
        host_id: host.id,
        x: (300 - pan.x) / zoom,
        y: (200 - pan.y) / zoom,
        label: host.hostname || host.ip,
        ip: host.ip,
        ips: host.ips || [host.ip],
        type: guessNodeType(host),
        status: isAttackerHost(host) ? 'attacker' : host.status,
        ports: host.ports || [],
        notes: host.notes || '',
        role: host.role,
        is_attacker: host.is_attacker,
        client_mutation_id: lid,
      });
      emit({ nodes: [...nodes, result.node] }, { persist: false });
      setSelectedNodeIds([result.node.id]);
    }
    setNodeDraft({ ip: '', hostname: '', os: 'Unknown', role: 'unknown', status: 'unknown', domain: '' });
    setShowCreateNode(false);
  };

  const addRegion = () => {
    const i = regions.length % REGION_FILL.length;
    const lid = newLocalMutationId();
    markLocalOp?.(lid);
    api.createNetworkRegion(projectId, {
      network_id: net.id,
      x: 80,
      y: 80,
      w: 320,
      h: 180,
      label: `Subnet ${regions.length + 1}`,
      note: '',
      fill: REGION_FILL[i],
      stroke: REGION_STROKE[i],
      client_mutation_id: lid,
    }).then((result) => {
      emit({ regions: [...regions, result.region] }, { persist: false });
      setSelectedRegionId(result.region.id);
      setSelectedNodeIds([]);
    }).catch(() => {});
  };

  const deleteSelected = () => {
    if (selectedRegionId) {
      emit({ regions: regions.filter(r => r.id !== selectedRegionId) }, { persist: false });
      api.deleteNetworkRegion(projectId, selectedRegionId, net.id).catch(() => {});
      setSelectedRegionId(null);
      return;
    }
    if (!selectedNodeIds.length) return;
    emit({ nodes: nodes.filter(n => !selectedNodeSet.has(n.id)), edges: edges.filter(e => !selectedNodeSet.has(e.from) && !selectedNodeSet.has(e.to)) }, { persist: false });
    Promise.all(selectedNodeIds.map(async (nodeId) => {
      await api.deleteNetworkNode(projectId, nodeId, net.id).catch(() => {});
    })).finally(() => setSelectedNodeIds([]));
  };

  const existingIps = useMemo(() => new Set(nodes.map(n => n.ip)), [nodes]);
  const unplaced = useMemo(() => hosts.filter(h => !existingIps.has(h.ip)), [existingIps, hosts]);
  const largeGraphMode = nodes.length >= 120 || edges.length >= 200;
  const simplifiedNodes = largeGraphMode && zoom < 0.85;
  const animateEdges = animateLinks && (!largeGraphMode || zoom >= 0.85);
  const addFromProject = (selectedIps) => {
    const toAdd = hosts.filter(h => selectedIps.has(h.ip));
    const cols = Math.ceil(Math.sqrt(toAdd.length + 1));
    Promise.all(toAdd.map(async (h, i) => {
      const lid = newLocalMutationId();
      markLocalOp?.(lid);
      const result = await api.createNetworkNode(projectId, {
        network_id: net.id,
        host_id: h.id,
        x: 120 + (i % cols) * 140,
        y: 120 + Math.floor(i / cols) * 140,
        label: h.hostname || h.ip,
        ip: h.ip,
        ips: h.ips || [],
        type: guessNodeType(h),
        status: isAttackerHost(h) ? 'attacker' : h.status || 'alive',
        ports: h.ports || [],
        notes: h.notes || '',
        role: h.role,
        is_attacker: h.is_attacker,
        client_mutation_id: lid,
      });
      return result.node;
    })).then((created) => {
      emit({ nodes: [...nodes, ...created.filter(Boolean)] }, { persist: false });
    }).finally(() => setShowAddFromProject(false));
    setShowAddFromProject(false);
  };

  const edgeStyle = (s) => ({ exploit: { stroke: '#cc2233', sw: 2, dash: '6 3', anim: true }, lateral: { stroke: '#e8cc42', sw: 1.5, dash: '4 4', anim: true }, tunnel: { stroke: '#5b8af5', sw: 2, dash: '8 4', anim: true }, normal: { stroke: '#39d353', sw: 1.5, dash: '4 6', anim: false } }[s] || { stroke: '#39d353', sw: 1.5, dash: '4 6', anim: false });
  const markerFor = (s) => ({ exploit: 'url(#me)', lateral: 'url(#ml)', tunnel: 'url(#mt)', normal: 'url(#mgreen)' }[s] || 'url(#mgreen)');
  const canUndo = historyState.past.length > 0;
  const canRedo = historyState.future.length > 0;

  const undo = useCallback(() => {
    setHistoryState(state => {
      if (!state.past.length) return state;
      const previous = state.past[state.past.length - 1];
      const current = cloneNet(draftNetRef.current);
      queueMicrotask(() => applySnapshot(previous));
      return { past: state.past.slice(0, -1), future: [current, ...state.future] };
    });
  }, [applySnapshot, cloneNet]);

  const redo = useCallback(() => {
    setHistoryState(state => {
      if (!state.future.length) return state;
      const next = state.future[0];
      const current = cloneNet(draftNetRef.current);
      queueMicrotask(() => applySnapshot(next));
      return { past: [...state.past, current], future: state.future.slice(1) };
    });
  }, [applySnapshot, cloneNet]);

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ padding: '7px 14px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 7, flexShrink: 0 }}>
        <span style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono', flex: 1 }}>{nodes.length} nodes · {edges.length} edges · {regions.length} regions</span>
        <button onClick={() => setZoom(z => Math.min(3, z * 1.2))} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#606570', cursor: 'pointer' }}><Icon name="zoomin" size={12} color="currentColor" /></button>
        <button onClick={() => setZoom(z => Math.max(0.3, z / 1.2))} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#606570', cursor: 'pointer' }}><Icon name="zoomout" size={12} color="currentColor" /></button>
        <button onClick={() => { setZoom(1); setPan({ x: 40, y: 40 }); }} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#606570', cursor: 'pointer' }}><Icon name="reset" size={12} color="currentColor" /></button>
        <button onClick={undo} disabled={!canUndo} title="Undo (Ctrl/Cmd+Z)" style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: canUndo ? '#9098a8' : '#404550', cursor: canUndo ? 'pointer' : 'default', opacity: canUndo ? 1 : 0.5, fontSize: 10, fontFamily: 'JetBrains Mono' }}>Undo</button>
        <button onClick={redo} disabled={!canRedo} title="Redo (Ctrl/Cmd+Shift+Z / Ctrl/Cmd+Y)" style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: canRedo ? '#9098a8' : '#404550', cursor: canRedo ? 'pointer' : 'default', opacity: canRedo ? 1 : 0.5, fontSize: 10, fontFamily: 'JetBrains Mono' }}>Redo</button>
        <span style={{ fontSize: 9, color: '#404550' }}>{Math.round(zoom * 100)}%</span>
        <div style={{ width: 1, height: 16, background: '#2a2d35' }} />
        {unplaced.length > 0 && <button onClick={() => setShowAddFromProject(v => !v)} style={{ background: 'none', border: `1px solid ${accent}66`, borderRadius: 4, padding: '4px 10px', color: accent, cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>+ from project ({unplaced.length})</button>}
        <button onClick={() => setShowAttackAnalyzer(true)} style={{ background: 'none', border: '1px solid #cc223366', borderRadius: 4, padding: '4px 10px', color: '#cc2233', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>⚡ Attack paths</button>
        {overlayData && <button onClick={() => setShowOverlay(v => !v)} style={{ background: showOverlay ? '#f09a3a22' : 'none', border: `1px solid ${showOverlay ? '#f09a3a88' : '#2a2d3566'}`, borderRadius: 4, padding: '4px 10px', color: showOverlay ? '#f09a3a' : '#606570', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }} title="Toggle threat overlay">🔍 Overlay</button>}
        <button onClick={addRegion} style={{ background: 'none', border: `1px solid ${accentGreen}66`, borderRadius: 4, padding: '4px 10px', color: accentGreen, cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Region</button>
        <button onClick={() => setShowCreateNode(v => !v)} style={{ background: accent, border: 'none', borderRadius: 4, padding: '4px 10px', color: '#fff', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Node</button>
        {selectedNodeIds.length > 0 && <><button onClick={() => setConnecting(selectedNodeIds[0])} title={selectedNodeIds.length > 1 ? `Create edges from ${selectedNodeIds.length} nodes` : 'Create edge'} style={{ background: connecting ? `${accentGreen}22` : 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: connecting ? accentGreen : '#606570', cursor: 'pointer' }}><Icon name="link" size={12} color="currentColor" />{selectedNodeIds.length > 1 && <span style={{ fontSize: 9, marginLeft: 4, fontFamily: 'JetBrains Mono' }}>×{selectedNodeIds.length}</span>}</button><button onClick={deleteSelected} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#cc2233', cursor: 'pointer' }}><Icon name="trash" size={12} color="currentColor" /></button></>}
        {selectedRegionId && regionEditMode && <><button onClick={deleteSelected} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#cc2233', cursor: 'pointer' }}><Icon name="trash" size={12} color="currentColor" /></button><button onClick={() => { setRegionEditMode(false); setSelectedRegionId(null); }} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 10px', color: '#606570', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Done</button></>}
      </div>

      {largeGraphMode && (
        <div style={{ padding: '8px 14px', borderBottom: '1px solid #1a1c22', background: '#0b1016', color: '#6fc8f0', fontSize: 10, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
          Large graph mode enabled: labels and badges are simplified while zoomed out to keep idle CPU low.
        </div>
      )}

      {showAddFromProject && unplaced.length > 0 && <AddFromProjectPanel hosts={unplaced} accent={accent} onAdd={addFromProject} onClose={() => setShowAddFromProject(false)} />}
      {showCreateNode && <div style={{ background: '#0c0e13', borderBottom: '1px solid #2a2d35', padding: '10px 14px', display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <div style={{ width: 150 }}><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>IP</div><input value={nodeDraft.ip} onChange={e => setNodeDraft(d => ({ ...d, ip: e.target.value }))} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }} /></div>
        <div style={{ width: 150 }}><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Hostname</div><input value={nodeDraft.hostname} onChange={e => setNodeDraft(d => ({ ...d, hostname: e.target.value }))} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }} /></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>OS</div><select value={nodeDraft.os} onChange={e => setNodeDraft(d => ({ ...d, os: e.target.value }))} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{['Unknown','Windows','Linux','macOS','Various'].map(v => <option key={v} value={v}>{v}</option>)}</select></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Role</div><select value={nodeDraft.role} onChange={e => setNodeDraft(d => ({ ...d, role: e.target.value }))} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{Object.entries(HOST_ROLES).map(([key, meta]) => <option key={key} value={key}>{meta.label}</option>)}</select></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Status</div><select value={nodeDraft.status} onChange={e => setNodeDraft(d => ({ ...d, status: e.target.value }))} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{Object.keys(NODE_STATUS).map(v => <option key={v} value={v}>{NODE_STATUS[v].label}</option>)}</select></div>
        <div style={{ width: 160 }}><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Domain</div><input value={nodeDraft.domain} onChange={e => setNodeDraft(d => ({ ...d, domain: e.target.value }))} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }} /></div>
        <button onClick={addNode} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 12px', color: '#fff', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Save node</button>
        <button onClick={() => setShowCreateNode(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', color: '#606570', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Cancel</button>
      </div>}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, position: 'relative', overflow: 'hidden', background: draftNet?.background || '#07080b' }} onMouseMove={onMouseMove} onMouseUp={onMouseUp} onMouseLeave={onMouseUp} onContextMenu={e => e.preventDefault()}>
          <svg ref={svgRef} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }} onMouseDown={onSVGMouseDown} onWheel={onWheel}>
            <style>{`.map-node .node-hov{opacity:0}.map-node:hover .node-hov{opacity:.5}.map-node-sel .node-hov{opacity:0!important}`}</style>
            <defs>
              <pattern id="sg" width="20" height="20" patternUnits="userSpaceOnUse"><path d="M 20 0 L 0 0 0 20" fill="none" stroke="#ffffff05" strokeWidth="1" /></pattern>
              <pattern id="lg" width="100" height="100" patternUnits="userSpaceOnUse"><path d="M 100 0 L 0 0 0 100" fill="none" stroke="#ffffff09" strokeWidth="1" /></pattern>
              {[['mgreen', '#39d353'], ['me', '#cc2233'], ['ml', '#e8cc42'], ['mt', '#5b8af5']].map(([id, c]) => <marker key={id} id={id} markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill={c} /></marker>)}
            </defs>
            <g ref={canvasGroupRef} transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
              <rect x="-50000" y="-50000" width="100000" height="100000" fill="url(#sg)" style={{ pointerEvents: 'none' }} />
              <rect x="-50000" y="-50000" width="100000" height="100000" fill="url(#lg)" style={{ pointerEvents: 'none' }} />
              {regions.map(region => <g key={region.id} transform={`translate(${region.x},${region.y})`} onMouseDown={(e) => onRegionMouseDown(e, region.id)} onContextMenu={(e) => onRegionContextMenu(e, region.id)} style={{ cursor: regionEditMode && selectedRegionId === region.id ? 'move' : 'default' }}>
                <rect x="0" y="0" width={region.w} height={region.h} rx="12" fill={region.fill || '#5b8af522'} stroke={region.stroke || '#5b8af5'} strokeWidth={selectedRegionId === region.id ? 2.5 : 1.5} strokeDasharray={selectedRegionId === region.id ? '8 4' : undefined} />
                <text x="14" y="22" fontSize="12" fill={region.stroke || '#5b8af5'} fontFamily="Space Grotesk" fontWeight="700" style={{ pointerEvents: 'none' }}>{region.label}</text>
                {region.note ? <text x="14" y="38" fontSize="9" fill="#c8cdd6" fontFamily="JetBrains Mono" style={{ pointerEvents: 'none' }}>{region.note}</text> : null}
                {selectedRegionId === region.id && regionEditMode && ['nw','ne','sw','se'].map(corner => {
                  const pos = {
                    nw: { x: 0, y: 0 },
                    ne: { x: region.w, y: 0 },
                    sw: { x: 0, y: region.h },
                    se: { x: region.w, y: region.h },
                  }[corner];
                  return <circle key={corner} cx={pos.x} cy={pos.y} r="5" fill={region.stroke || '#5b8af5'} stroke="#0e1016" strokeWidth="1.5" style={{ cursor: `${corner}-resize` }} onMouseDown={(e) => { e.stopPropagation(); interactionStartRef.current = cloneNet(draftNetRef.current); setResizingRegion({ id: region.id, corner }); }} />;
                })}
              </g>)}
              {visibleEdges.map(edge => {
                const fn = nodeById.get(edge.from); const tn = nodeById.get(edge.to); if (!fn || !tn) return null;
                const ep = edgeStyle(edge.style);
                const mx = (fn.x + tn.x) / 2;
                const my = (fn.y + tn.y) / 2;
                const edgeLabel = String(edge.label || '').trim();
                const edgeDimmed = attackPathSet ? !attackPathSet.edges.has(edge.id) : false;
                return <g key={edge.id} style={{ opacity: edgeDimmed ? 0.08 : 1, transition: 'opacity .2s' }}><line x1={fn.x} y1={fn.y} x2={tn.x} y2={tn.y} stroke={ep.stroke} strokeWidth={ep.sw} strokeDasharray={animateLinks ? (ep.dash === 'none' ? undefined : ep.dash) : undefined} markerEnd={markerFor(edge.style)} opacity=".9" style={animateEdges && ep.anim ? { animation: 'dash 1.5s linear infinite' } : undefined} />{edgeLabel && !simplifiedNodes && <><rect x={mx - edgeLabel.length * 3 - 4} y={my - 8} width={edgeLabel.length * 6 + 8} height={14} rx="3" fill="#0e1016" stroke={ep.stroke} strokeWidth="0.5" opacity=".95" /><text x={mx} y={my + 3} textAnchor="middle" fontSize="9" fill={ep.stroke} fontFamily="JetBrains Mono">{edgeLabel}</text></>}<line x1={fn.x} y1={fn.y} x2={tn.x} y2={tn.y} stroke="transparent" strokeWidth={14} style={{ cursor: 'default' }} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setEdgeMenu({ x: e.clientX, y: e.clientY, edgeId: edge.id }); }} /></g>;
              })}
              {visibleNodes.map(node => {
                const sc = NODE_STATUS[node.status]?.color || '#404550';
                const isSel = selectedNodeSet.has(node.id);
                const isDimmed = attackPathSet ? !attackPathSet.nodes.has(node.id) : false;
                const displayIps = node.ips && node.ips.length > 0 ? node.ips : (node.ip ? [node.ip] : []);
                const overlayEntry = showOverlay && overlayData ? (
                  overlayData.get(node.host_id) || overlayData.get(node.ip) || null
                ) : null;
                return <g key={node.id} className={`map-node${isSel ? ' map-node-sel' : ''}`} transform={`translate(${node.x - 20},${node.y - 20})`} onMouseDown={(e) => onNodeMouseDown(e, node.id)} style={{ '--sc': sc, cursor: 'pointer', userSelect: 'none', opacity: isDimmed ? 0.15 : 1, filter: isDimmed ? 'grayscale(0.7)' : undefined, transition: 'opacity .2s, filter .2s' }}>
                  {isSel && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${accent}18`} stroke={accent} strokeWidth="1.5" />}
                  {overlayEntry && isSel && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${overlayEntry.color}33`} stroke={overlayEntry.color} strokeWidth="3" />}
                  {overlayEntry && !isSel && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${overlayEntry.color}22`} stroke={overlayEntry.color} strokeWidth="2" strokeDasharray="4 2" opacity=".9" />}
                  <rect className="node-hov" x="-3" y="-3" width="46" height="46" rx="9" fill="#ffffff08" stroke="var(--sc)" strokeWidth="1" style={{ pointerEvents: 'none' }} />
                  <NodeShape type={node.type} status={node.status} size={40} selected={isSel} accent={accent} />
                  {overlayEntry && <circle cx="4" cy="4" r="5" fill={overlayEntry.color} opacity=".95" style={{ filter: `drop-shadow(0 0 4px ${overlayEntry.color})` }} />}
                  <circle cx="36" cy="4" r="4" fill={sc} opacity=".9" style={{ filter: `drop-shadow(0 0 3px ${sc})` }} />
                  {(!simplifiedNodes || isSel) && <text x="20" y="53" textAnchor="middle" fontSize="10" fill={isSel ? '#f0f2f6' : '#9098a8'} fontFamily="JetBrains Mono" fontWeight={isSel ? 600 : 400}>{node.label}</text>}
                  {!simplifiedNodes && displayIps.map((ip, idx) => (
                    <text key={idx} x="20" y={64 + (idx * 9)} textAnchor="middle" fontSize="8" fill={sc} fontFamily="JetBrains Mono" opacity=".8">{ip}</text>
                  ))}
                  {!simplifiedNodes && (() => {
                    const roleBadges = roleBadgesByNodeId.get(node.id) || [];
                    if (!roleBadges.length) return null;
                    const ipCount = displayIps.length;
                    const badgeY = 64 + ipCount * 9 + 4;
                    const bw = 20, gap = 2;
                    const totalW = roleBadges.length * (bw + gap) - gap;
                    const startX = 20 - totalW / 2;
                    return roleBadges.map((r, i) => (
                      <g key={r.id} transform={`translate(${startX + i * (bw + gap)},${badgeY})`}>
                        <rect x="0" y="0" width={bw} height="10" rx="2.5" fill={r.color + '22'} stroke={r.color + '66'} strokeWidth=".8"/>
                        <text x={bw / 2} y="7.5" textAnchor="middle" fontSize="6" fill={r.color} fontFamily="JetBrains Mono" fontWeight="600">{r.short}</text>
                      </g>
                    ));
                  })()}
                </g>;
              })}
              
              {/* Selection box visualization */}
              {selectBox && (() => {
                const minX = Math.min(selectBox.startX, selectBox.endX);
                const minY = Math.min(selectBox.startY, selectBox.endY);
                const width = Math.abs(selectBox.endX - selectBox.startX);
                const height = Math.abs(selectBox.endY - selectBox.startY);
                return <rect x={minX} y={minY} width={width} height={height} fill={`${accent}15`} stroke={accent} strokeWidth="1.5" strokeDasharray="4 4" />;
              })()}
            </g>
          </svg>
          {connecting && <div style={{ position: 'absolute', top: 12, left: '50%', transform: 'translateX(-50%)', background: `${accentGreen}22`, border: `1px solid ${accentGreen}`, borderRadius: 6, padding: '8px 16px', zIndex: 200, backdropFilter: 'blur(4px)' }}>
            <div style={{ fontSize: 11, color: accentGreen, fontFamily: 'Space Grotesk', fontWeight: 600, textAlign: 'center' }}>
              Edge creation mode {selectedNodeIds.length > 1 && `(from ${selectedNodeIds.length} nodes)`}
            </div>
            <div style={{ fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono', marginTop: 4, textAlign: 'center' }}>
              Click the target node or press ESC to cancel
            </div>
          </div>}
          {edgeMenu && <div style={{ position: 'fixed', top: edgeMenu.y, left: edgeMenu.x, zIndex: 300, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, padding: 6, boxShadow: '0 8px 24px #00000088' }}><button onClick={() => { deleteEdge(edgeMenu.edgeId); setEdgeMenu(null); }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#cc2233', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, padding: '4px 8px' }}><Icon name="trash" size={11} color="#cc2233" /> Delete edge</button></div>}
          <div style={{ position: 'absolute', bottom: 12, left: 12, background: '#0c0e13cc', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 12px', backdropFilter: 'blur(4px)', display: 'flex', gap: 16 }}>
            <div>
              <div style={{ fontSize: 8, color: '#404550', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 5 }}>Status</div>
              {Object.entries(NODE_STATUS).map(([k, v]) => <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: v.color, display: 'inline-block' }} /><span style={{ fontSize: 9, color: '#606570' }}>{v.label}</span></div>)}
            </div>
            <div>
              <div style={{ fontSize: 8, color: '#404550', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 5 }}>Edges</div>
              {[['Normal', '#39d353'], ['Exploit', '#cc2233'], ['Lateral', '#e8cc42'], ['Tunnel', '#5b8af5']].map(([l, c]) => <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}><span style={{ width: 14, height: 1.5, background: c, display: 'inline-block' }} /><span style={{ fontSize: 9, color: '#606570' }}>{l}</span></div>)}
            </div>
            <div>
              <div style={{ fontSize: 8, color: '#404550', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 5 }}>Keyboard shortcuts</div>
              <div style={{ fontSize: 9, color: '#606570', marginBottom: 3 }}><kbd style={{ background: '#1a1c22', padding: '1px 4px', borderRadius: 2, fontFamily: 'JetBrains Mono' }}>Shift</kbd> + drag — select area</div>
              <div style={{ fontSize: 9, color: '#606570', marginBottom: 3 }}><kbd style={{ background: '#1a1c22', padding: '1px 4px', borderRadius: 2, fontFamily: 'JetBrains Mono' }}>Ctrl+A</kbd> — select all</div>
              <div style={{ fontSize: 9, color: '#606570' }}><kbd style={{ background: '#1a1c22', padding: '1px 4px', borderRadius: 2, fontFamily: 'JetBrains Mono' }}>Esc</kbd> — deselect</div>
            </div>
          </div>
        </div>

        {showAttackAnalyzer && analysisCredsLoading && (
          <div style={{ width: 320, background: '#0c0e13', borderLeft: '1px solid #1e2029', padding: 14, color: '#404550', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
            Loading attack path data…
          </div>
        )}
        {showAttackAnalyzer && analysisCreds && (
          <AttackVectorAnalyzer
            projectId={projectId}
            hosts={hosts}
            creds={analysisCreds}
            nodes={nodes}
            existingEdges={edges}
            accent={accent}
            onApply={async (newEdges) => {
              const created = await Promise.all(newEdges.map(async (edge) => {
                const lid = newLocalMutationId();
                markLocalOp?.(lid);
                const result = await api.createNetworkLink(projectId, {
                  network_id: net.id,
                  from_node_id: edge.from,
                  to_node_id: edge.to,
                  style: edge.style || 'normal',
                  label: edge.label || '',
                  source: edge.source || 'manual',
                  type: edge.type,
                  confidence: edge.confidence,
                  client_mutation_id: lid,
                });
                return result.link;
              })).catch(() => []);
              if (created.length) emit({ edges: [...edges, ...created] }, { persist: false });
            }}
            onClose={() => setShowAttackAnalyzer(false)}
          />
        )}
        <NetworkInspector
          projectId={projectId}
          accent={accent}
          selectedNode={selectedNode}
          selectedRegion={selectedRegion}
          hostObj={hostObj}
          edges={edges}
          nodeById={nodeById}
          updateNode={updateNode}
          updateEdge={updateEdge}
          updateRegion={updateRegion}
          deleteEdge={deleteEdge}
          onClose={() => { setSelectedNodeIds([]); setSelectedRegionId(null); }}
          onAddActivity={onAddActivity}
          onUpdateActivity={onUpdateActivity}
          onDeleteActivity={onDeleteActivity}
        />
      </div>
    </div>
  );
}

export default function NetworkView({ projectId, accent, accentGreen, networks, onCreateNetwork, onUpdateNetwork, onDeleteNetwork, onCreateHost, onUpdateHost, onSyncHostByIp, hosts, onAddActivity, onUpdateActivity, onDeleteActivity, onRefreshHosts, onRefreshNetworks, markLocalOp, animateLinks = true, findings = [], objectives = [], creds = [], attackSteps = [] }) {
  const [activeNetId, setActiveNetId] = useState(null);
  const [editingName, setEditingName] = useState(null);
  const [nameVal, setNameVal] = useState('');
  const [showTopologyBuilder, setShowTopologyBuilder] = useState(false);
  const [autoBuilding, setAutoBuilding] = useState(false);
  const [topologyEnabled, setTopologyEnabled] = useState(true);

  useEffect(() => {
    if (networks.length > 0) {
      if (!activeNetId || !networks.find(n => n.id === activeNetId)) setActiveNetId(networks[0].id);
    } else {
      setActiveNetId(null);
    }
  }, [projectId, networks, activeNetId]);

  useEffect(() => {
    let cancelled = false;
    api.listModules().then(({ modules }) => {
      if (cancelled) return;
      const topology = (modules || []).find(mod => mod.name === 'topology');
      setTopologyEnabled(topology ? topology.enabled !== false : true);
    }).catch(() => {
      if (!cancelled) setTopologyEnabled(true);
    });
    return () => { cancelled = true; };
  }, [projectId]);

  const activeNet = networks.find(n => n.id === activeNetId);
  const projectHosts = hosts;

  // Compute overlay map: host_id|ip → { color, label, priority }
  const overlayData = useMemo(() => {
    const map = new Map();
    const set = (key, entry) => {
      if (!key) return;
      const existing = map.get(key);
      if (!existing || entry.priority > existing.priority) map.set(key, entry);
    };

    // Creds linked to hosts → green (lowest priority)
    for (const cred of creds) {
      for (const hid of (cred.host_ids || [])) set(hid, { color: '#39d353', label: 'Has creds', priority: 1 });
    }

    // Captured objectives on hosts
    for (const obj of objectives) {
      if (obj.host_id && (obj.status === 'captured' || obj.status === 'submitted')) {
        set(obj.host_id, { color: '#f09a3a', label: 'Objective captured', priority: 3 });
      }
    }

    // Findings (critical/high) on hosts
    for (const f of findings) {
      if (f.host_id) {
        if (f.severity === 'critical') set(f.host_id, { color: '#e8574a', label: 'Critical finding', priority: 5 });
        else if (f.severity === 'high') set(f.host_id, { color: '#f09a3a', label: 'High finding', priority: 4 });
        else if (f.severity === 'medium') set(f.host_id, { color: '#e8cc42', label: 'Medium finding', priority: 2 });
      }
    }

    // Attack steps referencing hosts (by label/IP match) — mark as blue
    for (const step of attackSteps) {
      if (!step.label) continue;
      for (const host of projectHosts) {
        if (step.label === host.ip || step.label === host.hostname || step.sublabel === host.ip) {
          set(host.id, { color: '#5b8af5', label: 'In attack path', priority: 3 });
          break;
        }
      }
    }

    return map;
  }, [creds, objectives, findings, attackSteps, projectHosts]);

  const mappedIps = useMemo(
    () => new Set((activeNet?.nodes || []).map(n => n.ip).filter(Boolean)),
    [activeNet],
  );
  const unmappedHosts = useMemo(
    () => projectHosts.filter(h => h.ip && !mappedIps.has(h.ip)),
    [projectHosts, mappedIps],
  );

  const handleAutoBuild = async () => {
    setAutoBuilding(true);
    try {
      await api.topologyAutoBuild(projectId, { keep_manual_positions: true });
      await onRefreshNetworks?.();
    } catch (e) {
      console.error('Auto-build failed:', e);
    } finally {
      setAutoBuilding(false);
    }
  };

  const startRename = (net) => { setEditingName(net.id); setNameVal(net.name); };
  const commitRename = (id) => { if (nameVal.trim()) onUpdateNetwork(id, { name: nameVal.trim() }); setEditingName(null); };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', background: '#0a0b0f', borderBottom: '1px solid #1a1c22', flexShrink: 0, paddingLeft: 4 }}>
        <div style={{ display: 'flex', flex: 1, overflowX: 'auto' }}>
          {networks.map(net => { const isActive = net.id === activeNetId; return <div key={net.id} style={{ display: 'flex', alignItems: 'center', borderRight: '1px solid #1a1c22', flexShrink: 0 }}><span style={{ width: 8, alignSelf: 'stretch', background: net.background || '#07080b' }} />{editingName === net.id ? <input autoFocus value={nameVal} onChange={e => setNameVal(e.target.value)} onBlur={() => commitRename(net.id)} onKeyDown={e => { if (e.key === 'Enter') commitRename(net.id); if (e.key === 'Escape') setEditingName(null); }} style={{ background: '#0e1016', border: '1px solid ' + accent, outline: 'none', color: '#f0f2f6', fontSize: 11, fontFamily: 'JetBrains Mono', padding: '6px 10px', width: 140 }} /> : <button onClick={() => setActiveNetId(net.id)} onDoubleClick={() => startRename(net)} style={{ background: isActive ? '#12141a' : 'transparent', border: 'none', borderBottom: isActive ? `2px solid ${accent}` : '2px solid transparent', padding: '9px 14px', cursor: 'pointer', color: isActive ? '#f0f2f6' : '#606570', fontSize: 11, fontFamily: 'JetBrains Mono', fontWeight: isActive ? 600 : 400 }}>{net.name}<span style={{ fontSize: 9, color: isActive ? accent + '99' : '#404550', marginLeft: 6 }}>{net.nodes?.length || 0}</span></button>}{isActive && networks.length > 1 && <button onClick={() => onDeleteNetwork(net.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', padding: '0 6px', display: 'flex' }}><Icon name="close" size={10} color="currentColor" /></button>}</div>; })}
        </div>
        {activeNet && <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingRight: 10 }}>{NETWORK_BACKGROUNDS.map(bg => <button key={bg} onClick={() => onUpdateNetwork(activeNet.id, { background: bg })} style={{ width: 14, height: 14, borderRadius: 3, background: bg, border: `1px solid ${(activeNet.background || '#07080b') === bg ? accent : '#2a2d35'}`, cursor: 'pointer' }} />)}</div>}
        <button onClick={() => onCreateNetwork({ pid: projectId, name: `Network ${networks.length + 1}`, background: NETWORK_BACKGROUNDS[networks.length % NETWORK_BACKGROUNDS.length] })} style={{ background: 'transparent', border: 'none', borderLeft: '1px solid #1a1c22', padding: '9px 14px', cursor: 'pointer', color: '#404550', display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'JetBrains Mono' }}><Icon name="plus" size={11} color="currentColor" /> Network</button>

        {/* Auto-layout button — amber when unmapped hosts exist */}
        {topologyEnabled && projectHosts.length > 0 && (
          <button
            onClick={handleAutoBuild}
            disabled={autoBuilding}
            title={unmappedHosts.length > 0
              ? `Place ${unmappedHosts.length} unmapped hosts on map and re-run layout`
              : 'Re-run layout algorithm for all nodes'}
            style={{ background: 'transparent', border: 'none', borderLeft: '1px solid #1a1c22', padding: '9px 14px', cursor: autoBuilding ? 'default' : 'pointer', color: unmappedHosts.length > 0 ? '#f09a3a' : '#404550', display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'JetBrains Mono', opacity: autoBuilding ? 0.6 : 1, transition: 'color .15s' }}
          >
            <Icon name="reset" size={11} color="currentColor" />
            {autoBuilding ? 'Building…' : 'Auto-layout'}
            {unmappedHosts.length > 0 && !autoBuilding && (
              <span style={{ background: '#f09a3a22', border: '1px solid #f09a3a55', borderRadius: 10, padding: '1px 6px', fontSize: 9, color: '#f09a3a', fontFamily: 'JetBrains Mono' }}>
                +{unmappedHosts.length}
              </span>
            )}
          </button>
        )}

        {topologyEnabled && <button onClick={() => setShowTopologyBuilder(true)} title="Build topology from scan" style={{ background: 'transparent', border: 'none', borderLeft: '1px solid #1a1c22', padding: '9px 14px', cursor: 'pointer', color: '#5b8af5', display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, fontFamily: 'JetBrains Mono' }}><Icon name="target" size={11} color="currentColor" /> Topology</button>}
      </div>

      {topologyEnabled && showTopologyBuilder && (
        <TopologyBuilderModal
          projectId={projectId}
          accent={accent}
          onClose={() => setShowTopologyBuilder(false)}
          onApplied={() => { setShowTopologyBuilder(false); onRefreshHosts?.(); onRefreshNetworks?.(); }}
        />
      )}

      {/* Banner: network exists but has zero nodes and project has hosts */}
      {topologyEnabled && activeNet && (activeNet.nodes || []).length === 0 && projectHosts.length > 0 && (
        <div style={{ padding: '10px 16px', background: '#0c0e13', borderBottom: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f09a3a', flexShrink: 0 }} />
          <span style={{ fontSize: 10, color: '#707580', fontFamily: 'JetBrains Mono', flex: 1 }}>
            {projectHosts.length} project hosts are not on this map
          </span>
          <button
            onClick={handleAutoBuild}
            disabled={autoBuilding}
            style={{ background: '#f09a3a', border: 'none', borderRadius: 5, padding: '6px 14px', cursor: autoBuilding ? 'default' : 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, opacity: autoBuilding ? 0.7 : 1 }}
          >
            <Icon name="reset" size={11} color="#fff" />
            {autoBuilding ? 'Building…' : `Auto-layout ${projectHosts.length} hosts`}
          </button>
        </div>
      )}

      {activeNet
        ? <NetworkCanvas key={activeNet.id} projectId={projectId} net={activeNet} onUpdate={(data) => onUpdateNetwork(activeNet.id, data)} onCreateHost={onCreateHost} onUpdateHost={onUpdateHost} onSyncHostByIp={onSyncHostByIp} accent={accent} accentGreen={accentGreen} hosts={projectHosts} onAddActivity={onAddActivity} onUpdateActivity={onUpdateActivity} onDeleteActivity={onDeleteActivity} markLocalOp={markLocalOp} animateLinks={animateLinks} overlayData={overlayData} />
        : (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 14, color: '#303540' }}>
            <Icon name="network" size={40} color="#2a2d35" />
            <div style={{ fontSize: 13, color: '#404550' }}>No network maps</div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => onCreateNetwork({ pid: projectId, name: 'Main network', background: '#07080b' })} style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7 }}>
                <Icon name="plus" size={12} color="currentColor" /> Create empty map
              </button>
              {topologyEnabled && projectHosts.length > 0 && (
                <button onClick={handleAutoBuild} disabled={autoBuilding} style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 18px', cursor: autoBuilding ? 'default' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7, opacity: autoBuilding ? 0.7 : 1 }}>
                  <Icon name="reset" size={12} color="#fff" />
                  {autoBuilding ? 'Building…' : `Auto-build from ${projectHosts.length} hosts`}
                </button>
              )}
            </div>
          </div>
        )
      }
    </div>
  );
}
