import { useEffect, useMemo, useRef, useState } from 'react';
import Icon from '../components/Icon.jsx';
import { FieldInput } from '../components/UI.jsx';
import { NODE_STATUS, NODE_TYPES, OS_ICONS } from '../constants.js';
import { api } from '../api.js';
import AttackVectorAnalyzer from '../components/AttackVectorAnalyzer.jsx';

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

const NETWORK_BACKGROUNDS = ['#07080b', '#0b1116', '#100c16', '#161008', '#0a1511', '#120a0f'];
const REGION_FILL = ['#5b8af522', '#c07af022', '#39d35322', '#f09a3a22', '#e8574a22', '#6fc8f022'];
const REGION_STROKE = ['#5b8af5', '#c07af0', '#39d353', '#f09a3a', '#e8574a', '#6fc8f0'];

const NodeShape = ({ type, status, size = 40, selected, accent }) => {
  const sc = NODE_STATUS[status]?.color || '#404550';
  const W = size, H = size;
  const base = { filter: `drop-shadow(0 0 5px ${sc}55)` };
  
  // SQUARE-BASED NODES: server, web, dc, workstation, attacker
  if (['server', 'web', 'dc', 'workstation', 'attacker'].includes(type)) {
    const isAtt = type === 'attacker';
    const isDC = type === 'dc';
    return (
      <svg width={W} height={H} viewBox="0 0 40 40" style={base}>
        {selected && <rect x="1" y="1" width="38" height="38" rx="7" fill="none" stroke={accent} strokeWidth="2" opacity=".7" />}
        <rect x="4" y="4" width="32" height="32" rx="6" fill={isAtt ? `${sc}33` : '#12141a'} stroke={sc} strokeWidth={isAtt ? 2 : 1.5} />
        {isAtt && <><line x1="20" y1="10" x2="20" y2="30" stroke={sc} strokeWidth="1.5" opacity=".6" /><line x1="10" y1="20" x2="30" y2="20" stroke={sc} strokeWidth="1.5" opacity=".6" /><circle cx="20" cy="20" r="4" fill={sc} opacity=".9" /></>}
        {type === 'server' && <><rect x="10" y="13" width="20" height="5" rx="1.5" fill={sc} opacity=".3" /><rect x="10" y="22" width="20" height="5" rx="1.5" fill={sc} opacity=".2" /><circle cx="14" cy="15.5" r="1.2" fill={sc} opacity=".8" /><circle cx="14" cy="24.5" r="1.2" fill={sc} opacity=".5" /></>}
        {type === 'web' && <><ellipse cx="20" cy="20" rx="8" ry="8" fill="none" stroke={sc} strokeWidth="1.2" opacity=".5" /><line x1="12" y1="20" x2="28" y2="20" stroke={sc} strokeWidth="1" opacity=".5" /><path d="M16 13a12 8 0 010 14" fill="none" stroke={sc} strokeWidth="1" opacity=".4" /></>}
        {type === 'workstation' && <><rect x="10" y="12" width="20" height="13" rx="2" fill="none" stroke={sc} strokeWidth="1.2" opacity=".6" /><rect x="16" y="25" width="8" height="3" rx="1" fill={sc} opacity=".4" /></>}
        {isDC && <><path d="M13 16 L20 12 L27 16 L27 24 L20 28 L13 24Z" fill="none" stroke={sc} strokeWidth="1.3" opacity=".7" /><circle cx="20" cy="20" r="2.5" fill={sc} opacity=".8" /></>}
      </svg>
    );
  }
  
  // FIREWALL: shield with lightning
  if (type === 'firewall') {
    return (
      <svg width={W} height={H} viewBox="0 0 40 40" style={base}>
        {selected && <circle cx="20" cy="20" r="19" fill="none" stroke={accent} strokeWidth="2" opacity=".7" />}
        <path d="M20 4 L34 11 L34 24 C34 31 20 36 20 36 C20 36 6 31 6 24 L6 11Z" fill="#12141a" stroke={sc} strokeWidth="1.5" />
        <path d="M14 19 L18 14 L18 21 L22 16 L22 26 L26 21" fill="none" stroke={sc} strokeWidth="1.5" strokeLinecap="round" opacity=".8" />
      </svg>
    );
  }
  
  // DEFAULT/ROUTER/CLOUD: circle with radiating lines
  return (
    <svg width={W} height={H} viewBox="0 0 40 40" style={base}>
      {selected && <circle cx="20" cy="20" r="19" fill="none" stroke={accent} strokeWidth="2" opacity=".7" />}
      <circle cx="20" cy="20" r="15" fill="#12141a" stroke={sc} strokeWidth="1.5" />
      <circle cx="20" cy="20" r="8" fill="none" stroke={sc} strokeWidth="1" opacity=".4" />
      <circle cx="20" cy="20" r="3" fill={sc} opacity=".8" />
      {[0, 60, 120, 180, 240, 300].map(a => {
        const r = a * Math.PI / 180;
        return <line key={a} x1={20 + 8 * Math.cos(r)} y1={20 + 8 * Math.sin(r)} x2={20 + 15 * Math.cos(r)} y2={20 + 15 * Math.sin(r)} stroke={sc} strokeWidth="1.2" opacity=".6" />;
      })}
    </svg>
  );
};

function guessNodeType(host) {
  const tags = (host.tags || []).map(t => t.toLowerCase());
  const svc = (host.services || []).map(s => s.toLowerCase());
  const ports = host.ports || [];
  if (tags.includes('attacker')) return 'attacker';
  if (tags.includes('firewall') || tags.includes('fw')) return 'firewall';
  if (tags.includes('dc') || tags.includes('ad') || svc.includes('kerberos') || ports.includes('88')) return 'dc';
  if (tags.includes('web') || svc.some(s => s.includes('http')) || ports.some(p => ['80', '443', '8080', '8443'].includes(p))) return 'web';
  if (tags.includes('workstation') || tags.includes('ws') || tags.includes('rdp') || ports.includes('3389')) return 'workstation';
  return 'server';
}

function AddFromProjectPanel({ hosts, accent, onAdd, onClose }) {
  const [sel, setSel] = useState(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  const toggle = (ip) => setSel(prev => { const next = new Set(prev); next.has(ip) ? next.delete(ip) : next.add(ip); return next; });
  
  // Filter hosts by search query
  const filteredHosts = searchQuery.trim() 
    ? hosts.filter(h => 
        (h.ip && h.ip.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (h.hostname && h.hostname.toLowerCase().includes(searchQuery.toLowerCase()))
      )
    : hosts;
  
  const selectAll = () => setSel(new Set(filteredHosts.map(h => h.ip)));
  
  return (
    <div style={{ background: '#0c0e13', borderBottom: '1px solid #2a2d35', flexShrink: 0, maxHeight: 280, display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '8px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', flex: 1 }}>Add hosts from project</span>
        <button onClick={selectAll} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>All{searchQuery && ` (${filteredHosts.length})`}</button>
        <button onClick={() => sel.size > 0 && onAdd(sel)} style={{ background: sel.size ? accent : '#1a1c22', border: 'none', borderRadius: 3, padding: '3px 12px', cursor: sel.size ? 'pointer' : 'default', color: '#fff', fontSize: 9, fontWeight: 600, fontFamily: 'JetBrains Mono', opacity: sel.size ? 1 : .4 }}>Add {sel.size ? `(${sel.size})` : ''}</button>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={12} color="#606570" /></button>
      </div>
      <div style={{ padding: '6px 14px', borderBottom: '1px solid #1e2029' }}>
        <input 
          type="text" 
          placeholder="Search by IP or hostname..."
          value={searchQuery} 
          onChange={e => setSearchQuery(e.target.value)}
          style={{ 
            width: '100%',
            background: '#12141a', 
            border: '1px solid #2a2d35', 
            borderRadius: 4, 
            padding: '5px 10px', 
            color: '#c8cdd6', 
            fontSize: 10, 
            fontFamily: 'JetBrains Mono',
            outline: 'none'
          }}
        />
      </div>
      <div style={{ overflowY: 'auto', flex: 1 }}>
        {filteredHosts.length === 0 ? (
          <div style={{ padding: '20px', textAlign: 'center', color: '#404550', fontSize: 10 }}>No results</div>
        ) : (
          filteredHosts.map(h => <div key={h.ip} onClick={() => toggle(h.ip)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '5px 14px', cursor: 'pointer', background: sel.has(h.ip) ? `${accent}10` : 'transparent', borderLeft: sel.has(h.ip) ? `2px solid ${accent}` : '2px solid transparent' }}><div style={{ width: 12, height: 12, borderRadius: 2, border: `1px solid ${sel.has(h.ip) ? accent : '#404550'}`, background: sel.has(h.ip) ? accent : 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{sel.has(h.ip) && <Icon name="check" size={9} color="#fff" />}</div><span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#9098a8', width: 120 }}>{h.ip}</span><span style={{ fontSize: 10, color: '#c8cdd6', width: 110, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.hostname || '—'}</span></div>)
        )}
      </div>
    </div>
  );
}

function NetworkCanvas({ projectId, net, onUpdate, onCreateHost, onSyncHostByIp, accent, accentGreen, hosts, creds }) {
  const [selectedNodeIds, setSelectedNodeIds] = useState([]);
  const [selectedRegionId, setSelectedRegionId] = useState(null);
  const [hoveredNodeId, setHoveredNodeId] = useState(null);
  const [connecting, setConnecting] = useState(null);
  const [pan, setPan] = useState({ x: 40, y: 40 });
  const [zoom, setZoom] = useState(1);
  const [draggingNode, setDraggingNode] = useState(null);
  const [draggingRegion, setDraggingRegion] = useState(null);
  const [resizingRegion, setResizingRegion] = useState(null);
  const [draggingCanvas, setDraggingCanvas] = useState(null);
  const [showAddFromProject, setShowAddFromProject] = useState(false);
  const [showAttackAnalyzer, setShowAttackAnalyzer] = useState(false);
  const [edgeMenu, setEdgeMenu] = useState(null);
  const [regionEditMode, setRegionEditMode] = useState(false);
  const [selectBox, setSelectBox] = useState(null);
  const svgRef = useRef();
  const dragOffset = useRef({ x: 0, y: 0 });

  const nodes = net?.nodes || [];
  const edges = net?.edges || [];
  const regions = net?.regions || [];
  
  const selectedNodeSet = new Set(selectedNodeIds);
  const selectedNode = selectedNodeIds.length === 1 ? nodes.find(n => n.id === selectedNodeIds[0]) : null;
  const selectedRegion = regions.find(r => r.id === selectedRegionId) || null;
  const hostObj = useMemo(() => {
    if (!selectedNode) return null;
    const nodeIps = selectedNode.ips && selectedNode.ips.length > 0 ? selectedNode.ips : (selectedNode.ip ? [selectedNode.ip] : []);
    return (hosts || []).find(h => nodeIps.includes(h.ip)) || null;
  }, [selectedNode, hosts]);
  const isDomainHost = !!(hostObj?.domain && hostObj.domain.trim());
  const nodeCreds = useMemo(() => {
    if (!selectedNode) return [];
    const nodeIps = new Set(selectedNode.ips && selectedNode.ips.length > 0 ? selectedNode.ips : (selectedNode.ip ? [selectedNode.ip] : []));
    return (creds || []).filter(c => c.pid === projectId && (
      nodeIps.has(c.host) ||
      (hostObj?.hostname && c.host === hostObj.hostname) ||
      (hostObj && (c.host_ids || []).includes(hostObj.id)) ||
      c.is_domain
    )).map(c => ({
      ...c,
      _linkType: (nodeIps.has(c.host) || (hostObj?.hostname && c.host === hostObj.hostname)) ? 'ip'
        : (hostObj && (c.host_ids || []).includes(hostObj.id)) ? 'linked'
        : isDomainHost ? 'domain' : 'domain?',
    }));
  }, [selectedNode, creds, projectId, hostObj, isDomainHost]);

  useEffect(() => { setSelectedNodeIds([]); setSelectedRegionId(null); setConnecting(null); setEdgeMenu(null); }, [net?.id]);
  useEffect(() => {
    const onKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a') {
        e.preventDefault();
        setSelectedNodeIds(nodes.map(n => n.id));
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
  }, [nodes]);

  const getSVGPt = (e) => {
    const r = svgRef.current.getBoundingClientRect();
    return { x: (e.clientX - r.left - pan.x) / zoom, y: (e.clientY - r.top - pan.y) / zoom };
  };

  const emit = (patch) => onUpdate({ nodes, edges, regions, ...patch });
  const updateNode = async (id, patch) => {
    const node = nodes.find(n => n.id === id);
    emit({ nodes: nodes.map(n => n.id === id ? { ...n, ...patch } : n) });
    if (node?.ip && (patch.status !== undefined || patch.ip !== undefined)) {
      await onSyncHostByIp?.(node.ip, { ...(patch.status !== undefined ? { status: patch.status } : {}), ...(patch.ip !== undefined ? { ip: patch.ip } : {}) });
    }
  };
  const updateEdge = (id, patch) => emit({ edges: edges.map(e => e.id === id ? { ...e, ...patch } : e) });
  const updateRegion = (id, patch) => emit({ regions: regions.map(r => r.id === id ? { ...r, ...patch } : r) });
  const deleteEdge = (id) => emit({ edges: edges.filter(e => e.id !== id) });

  const onNodeMouseDown = (e, nid) => {
    e.stopPropagation();
    
    if (connecting) {
      // Create edges from all selected nodes to the clicked node
      const sourceNodes = selectedNodeIds.length > 0 ? selectedNodeIds : [connecting];
      const newEdges = sourceNodes
        .filter(srcId => srcId !== nid) // Don't create self-loop
        .map(srcId => ({ 
          id: 'e' + Date.now() + '_' + srcId, 
          from: srcId, 
          to: nid, 
          label: 'link', 
          style: 'normal' 
        }));
      if (newEdges.length > 0) {
        emit({ edges: [...edges, ...newEdges] });
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
      emit({ nodes: nodes.map(n => selectedNodeSet.has(n.id) ? { ...n, x: n.x + dx, y: n.y + dy } : n) });
    } else if (draggingRegion) {
      const pt = getSVGPt(e);
      const region = regions.find(r => r.id === draggingRegion);
      updateRegion(draggingRegion, { x: pt.x - dragOffset.current.x, y: pt.y - dragOffset.current.y, w: region.w, h: region.h });
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
      updateRegion(region.id, patch);
    } else if (draggingCanvas) {
      setPan({ x: e.clientX - draggingCanvas.startX, y: e.clientY - draggingCanvas.startY });
    }
  };

  const onMouseUp = () => { 
    setDraggingNode(null); 
    setDraggingRegion(null); 
    setResizingRegion(null); 
    setDraggingCanvas(null); 
    setSelectBox(null);
  };
  const onWheel = (e) => { e.preventDefault(); setZoom(z => Math.min(3, Math.max(0.3, z * (e.deltaY < 0 ? 1.1 : 0.91)))); };

  const addNode = async () => {
    const host = await onCreateHost({ pid: projectId, ip: `0.0.0.${Math.floor(Math.random() * 200 + 20)}`, hostname: 'new-host', os: 'Unknown', status: 'unknown', ports: [], services: [], tags: [], notes: '' });
    const id = 'h' + Date.now();
    emit({ nodes: [...nodes, { id, x: (300 - pan.x) / zoom, y: (200 - pan.y) / zoom, label: host.hostname || host.ip, ip: host.ip, type: guessNodeType(host), status: host.status, ports: host.ports || [], notes: host.notes || '' }] });
    setSelectedNodeIds([id]);
  };

  const addRegion = () => {
    const i = regions.length % REGION_FILL.length;
    const id = 'r' + Date.now();
    emit({ regions: [...regions, { id, x: 80, y: 80, w: 320, h: 180, label: `Subnet ${regions.length + 1}`, note: '', fill: REGION_FILL[i], stroke: REGION_STROKE[i] }] });
    setSelectedRegionId(id);
    setSelectedNodeIds([]);
  };

  const deleteSelected = () => {
    if (selectedRegionId) {
      emit({ regions: regions.filter(r => r.id !== selectedRegionId) });
      setSelectedRegionId(null);
      return;
    }
    if (!selectedNodeIds.length) return;
    emit({ nodes: nodes.filter(n => !selectedNodeSet.has(n.id)), edges: edges.filter(e => !selectedNodeSet.has(e.from) && !selectedNodeSet.has(e.to)) });
    setSelectedNodeIds([]);
  };

  const existingIps = new Set(nodes.map(n => n.ip));
  const unplaced = hosts.filter(h => !existingIps.has(h.ip));
  const addFromProject = (selectedIps) => {
    const toAdd = hosts.filter(h => selectedIps.has(h.ip));
    const cols = Math.ceil(Math.sqrt(toAdd.length + 1));
    const newNodes = toAdd.map((h, i) => ({ id: 'h' + Date.now() + i, x: 120 + (i % cols) * 140, y: 120 + Math.floor(i / cols) * 140, label: h.hostname || h.ip, ip: h.ip, type: guessNodeType(h), status: h.status || 'alive', ports: h.ports || [], notes: h.notes || '' }));
    emit({ nodes: [...nodes, ...newNodes] });
    setShowAddFromProject(false);
  };

  const edgeStyle = (s) => ({ exploit: { stroke: '#cc2233', sw: 2, dash: '6 3', anim: true }, lateral: { stroke: '#e8cc42', sw: 1.5, dash: '4 4', anim: true }, tunnel: { stroke: '#5b8af5', sw: 2, dash: '8 4', anim: true }, normal: { stroke: '#39d353', sw: 1.5, dash: '4 6', anim: true } }[s] || { stroke: '#39d353', sw: 1.5, dash: '4 6', anim: true });
  const markerFor = (s) => ({ exploit: 'url(#me)', lateral: 'url(#ml)', tunnel: 'url(#mt)', normal: 'url(#mgreen)' }[s] || 'url(#mgreen)');

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ padding: '7px 14px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 7, flexShrink: 0 }}>
        <span style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono', flex: 1 }}>{nodes.length} nodes · {edges.length} edges · {regions.length} regions</span>
        <button onClick={() => setZoom(z => Math.min(3, z * 1.2))} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#606570', cursor: 'pointer' }}><Icon name="zoomin" size={12} color="currentColor" /></button>
        <button onClick={() => setZoom(z => Math.max(0.3, z / 1.2))} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#606570', cursor: 'pointer' }}><Icon name="zoomout" size={12} color="currentColor" /></button>
        <button onClick={() => { setZoom(1); setPan({ x: 40, y: 40 }); }} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#606570', cursor: 'pointer' }}><Icon name="reset" size={12} color="currentColor" /></button>
        <span style={{ fontSize: 9, color: '#404550' }}>{Math.round(zoom * 100)}%</span>
        <div style={{ width: 1, height: 16, background: '#2a2d35' }} />
        {unplaced.length > 0 && <button onClick={() => setShowAddFromProject(v => !v)} style={{ background: 'none', border: `1px solid ${accent}66`, borderRadius: 4, padding: '4px 10px', color: accent, cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>+ from project ({unplaced.length})</button>}
        <button onClick={() => setShowAttackAnalyzer(true)} style={{ background: 'none', border: '1px solid #cc223366', borderRadius: 4, padding: '4px 10px', color: '#cc2233', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>⚡ Attack paths</button>
        <button onClick={addRegion} style={{ background: 'none', border: `1px solid ${accentGreen}66`, borderRadius: 4, padding: '4px 10px', color: accentGreen, cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Region</button>
        <button onClick={addNode} style={{ background: accent, border: 'none', borderRadius: 4, padding: '4px 10px', color: '#fff', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Node</button>
        {selectedNodeIds.length > 0 && <><button onClick={() => setConnecting(selectedNodeIds[0])} title={selectedNodeIds.length > 1 ? `Create edges from ${selectedNodeIds.length} nodes` : 'Create edge'} style={{ background: connecting ? `${accentGreen}22` : 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: connecting ? accentGreen : '#606570', cursor: 'pointer' }}><Icon name="link" size={12} color="currentColor" />{selectedNodeIds.length > 1 && <span style={{ fontSize: 9, marginLeft: 4, fontFamily: 'JetBrains Mono' }}>×{selectedNodeIds.length}</span>}</button><button onClick={deleteSelected} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#cc2233', cursor: 'pointer' }}><Icon name="trash" size={12} color="currentColor" /></button></>}
        {selectedRegionId && regionEditMode && <><button onClick={deleteSelected} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#cc2233', cursor: 'pointer' }}><Icon name="trash" size={12} color="currentColor" /></button><button onClick={() => { setRegionEditMode(false); setSelectedRegionId(null); }} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 10px', color: '#606570', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Done</button></>}
      </div>

      {showAddFromProject && unplaced.length > 0 && <AddFromProjectPanel hosts={unplaced} accent={accent} onAdd={addFromProject} onClose={() => setShowAddFromProject(false)} />}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, position: 'relative', overflow: 'hidden', background: net?.background || '#07080b' }} onMouseMove={onMouseMove} onMouseUp={onMouseUp} onMouseLeave={onMouseUp} onContextMenu={e => e.preventDefault()}>
          <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
            <defs>
              <pattern id="sg" width={20 * zoom} height={20 * zoom} patternUnits="userSpaceOnUse" x={pan.x % (20 * zoom)} y={pan.y % (20 * zoom)}><path d={`M ${20 * zoom} 0 L 0 0 0 ${20 * zoom}`} fill="none" stroke="#ffffff05" strokeWidth="1" /></pattern>
              <pattern id="lg" width={100 * zoom} height={100 * zoom} patternUnits="userSpaceOnUse" x={pan.x % (100 * zoom)} y={pan.y % (100 * zoom)}><path d={`M ${100 * zoom} 0 L 0 0 0 ${100 * zoom}`} fill="none" stroke="#ffffff09" strokeWidth="1" /></pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#sg)" />
            <rect width="100%" height="100%" fill="url(#lg)" />
          </svg>
          <svg ref={svgRef} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }} onMouseDown={onSVGMouseDown} onWheel={onWheel}>
            <defs>{[['mgreen', '#39d353'], ['me', '#cc2233'], ['ml', '#e8cc42'], ['mt', '#5b8af5']].map(([id, c]) => <marker key={id} id={id} markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill={c} /></marker>)}</defs>
            <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
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
                  return <circle key={corner} cx={pos.x} cy={pos.y} r="5" fill={region.stroke || '#5b8af5'} stroke="#0e1016" strokeWidth="1.5" style={{ cursor: `${corner}-resize` }} onMouseDown={(e) => { e.stopPropagation(); setResizingRegion({ id: region.id, corner }); }} />;
                })}
              </g>)}
              {edges.map(edge => {
                const fn = nodes.find(n => n.id === edge.from); const tn = nodes.find(n => n.id === edge.to); if (!fn || !tn) return null;
                const ep = edgeStyle(edge.style); const mx = (fn.x + tn.x) / 2, my = (fn.y + tn.y) / 2;
                return <g key={edge.id}><line x1={fn.x} y1={fn.y} x2={tn.x} y2={tn.y} stroke={ep.stroke} strokeWidth={ep.sw} strokeDasharray={ep.dash === 'none' ? undefined : ep.dash} markerEnd={markerFor(edge.style)} opacity=".9" style={ep.anim ? { animation: 'dash 1.5s linear infinite' } : {}} />{!!edge.label && <><rect x={mx - edge.label.length * 3 - 4} y={my - 8} width={edge.label.length * 6 + 8} height={14} rx="3" fill="#0e1016" stroke={ep.stroke} strokeWidth=".5" opacity=".95" /><text x={mx} y={my + 3} textAnchor="middle" fontSize={9} fill={ep.stroke} fontFamily="JetBrains Mono">{edge.label}</text></>}<line x1={fn.x} y1={fn.y} x2={tn.x} y2={tn.y} stroke="transparent" strokeWidth={14} style={{ cursor: 'default' }} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setEdgeMenu({ x: e.clientX, y: e.clientY, edgeId: edge.id }); }} /></g>;
              })}
              {nodes.map(node => {
                const sc = NODE_STATUS[node.status]?.color || '#404550';
                const isSel = selectedNodeSet.has(node.id);
                const isHov = hoveredNodeId === node.id;
                const displayIps = node.ips && node.ips.length > 0 ? node.ips : (node.ip ? [node.ip] : []);
                return <g key={node.id} transform={`translate(${node.x - 20},${node.y - 20})`} onMouseDown={(e) => onNodeMouseDown(e, node.id)} onMouseEnter={() => setHoveredNodeId(node.id)} onMouseLeave={() => setHoveredNodeId(null)} style={{ cursor: 'pointer', userSelect: 'none' }}>
                  {isSel && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${accent}18`} stroke={accent} strokeWidth="1.5" />}
                  {isHov && !isSel && <rect x="-3" y="-3" width="46" height="46" rx="9" fill="#ffffff08" stroke={sc} strokeWidth="1" opacity=".5" />}
                  <NodeShape type={node.type} status={node.status} size={40} selected={isSel} accent={accent} />
                  <circle cx="36" cy="4" r="4" fill={sc} opacity=".9" style={{ filter: `drop-shadow(0 0 3px ${sc})` }} />
                  <text x="20" y="53" textAnchor="middle" fontSize="10" fill={isSel ? '#f0f2f6' : '#9098a8'} fontFamily="JetBrains Mono" fontWeight={isSel ? 600 : 400}>{node.label}</text>
                  {displayIps.map((ip, idx) => (
                    <text key={idx} x="20" y={64 + (idx * 9)} textAnchor="middle" fontSize="8" fill={sc} fontFamily="JetBrains Mono" opacity=".8">{ip}</text>
                  ))}
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

        {showAttackAnalyzer && (
        <AttackVectorAnalyzer
          projectId={projectId}
          hosts={hosts}
          creds={creds}
          nodes={nodes}
          existingEdges={edges}
          accent={accent}
          onApply={(newEdges) => emit({ edges: [...edges, ...newEdges] })}
          onClose={() => setShowAttackAnalyzer(false)}
        />
      )}
      {(selectedNode || selectedRegion) && <div style={{ width: 320, background: '#0c0e13', borderLeft: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
          <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}><span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>{selectedRegion ? 'Region / subnet' : 'Node'}</span><button onClick={() => { setSelectedNodeIds([]); setSelectedRegionId(null); }} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={12} color="#606570" /></button></div>
          <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
            {selectedRegion ? <>
              <FieldInput label="Subnet name" value={selectedRegion.label || ''} onChange={v => updateRegion(selectedRegion.id, { label: v })} placeholder="10.10.10.0/24" />
              <FieldInput label="Short note" value={selectedRegion.note || ''} onChange={v => updateRegion(selectedRegion.id, { note: v })} placeholder="VPN segment" textarea />
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
              <FieldInput label="Name" value={selectedNode.label || ''} onChange={v => updateNode(selectedNode.id, { label: v })} placeholder="HOST-01" />
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>IP / CIDR addresses</span>
                  <button onClick={() => {
                    let currentIps = (selectedNode.ips && selectedNode.ips.length > 0) ? selectedNode.ips : (selectedNode.ip ? [selectedNode.ip] : []);
                    updateNode(selectedNode.id, { ips: [...currentIps, ''] });
                  }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>+</button>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {(() => {
                    let displayIps = (selectedNode.ips && selectedNode.ips.length > 0) ? selectedNode.ips : (selectedNode.ip ? [selectedNode.ip] : ['']);
                    return displayIps.map((ip, i) => (
                      <div key={i} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        <input value={ip || ''} onChange={e => {
                          const currentIps = (selectedNode.ips && selectedNode.ips.length > 0) ? [...selectedNode.ips] : (selectedNode.ip ? [selectedNode.ip] : ['']);
                          const next = [...currentIps];
                          next[i] = e.target.value;
                          const filtered = next.filter(x => x && x.trim());
                          updateNode(selectedNode.id, { ips: filtered, ip: filtered[0] || '' });
                        }} placeholder="192.168.1.1 or 10.0.0.0/24" style={{ flex: 1, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }} />
                        {displayIps.length > 1 && (
                          <button onClick={() => {
                            const currentIps = (selectedNode.ips && selectedNode.ips.length > 0) ? [...selectedNode.ips] : (selectedNode.ip ? [selectedNode.ip] : []);
                            const next = currentIps.filter((_, idx) => idx !== i);
                            updateNode(selectedNode.id, { ips: next, ip: next[0] || '' });
                          }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 2, display: 'flex' }}>
                            <Icon name="trash" size={11} color="#404550" />
                          </button>
                        )}
                      </div>
                    ));
                  })()}
                </div>
              </div>
              <FieldInput label="Notes" value={selectedNode.notes || ''} onChange={v => updateNode(selectedNode.id, { notes: v })} placeholder="VPN jump host" textarea />
              <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Type</div><div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{Object.entries(NODE_TYPES).map(([k, v]) => <button key={k} onClick={() => updateNode(selectedNode.id, { type: k })} style={{ background: selectedNode.type === k ? `${accent}22` : '#0e1016', border: `1px solid ${selectedNode.type === k ? accent + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: selectedNode.type === k ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{v.label}</button>)}</div></div>
              <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Status</div><div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>{Object.entries(NODE_STATUS).map(([k, v]) => <button key={k} onClick={() => updateNode(selectedNode.id, { status: k })} style={{ background: selectedNode.status === k ? `${v.color}18` : 'transparent', border: `1px solid ${selectedNode.status === k ? v.color + '66' : '#2a2d35'}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: v.color }} /><span style={{ fontSize: 9, color: selectedNode.status === k ? v.color : '#606570', fontFamily: 'JetBrains Mono' }}>{v.label}</span></button>)}</div></div>
              <FieldInput label="Ports" value={(selectedNode.ports || []).join(', ')} onChange={v => updateNode(selectedNode.id, { ports: v.split(',').map(p => p.trim()).filter(Boolean) })} placeholder="22, 80, 443" />
              <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Edges</div>{edges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id).map(edge => <div key={edge.id} style={{ display: 'flex', flexDirection: 'column', gap: 5, padding: '6px 0', borderBottom: '1px solid #14161b' }}><div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span style={{ fontSize: 10, color: '#9098a8', flex: 1 }}>{(nodes.find(n => n.id === (edge.from === selectedNode.id ? edge.to : edge.from)) || {}).label || '?'}</span><select value={edge.style} onChange={e => updateEdge(edge.id, { style: e.target.value })} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 3, color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '1px 4px' }}>{['normal', 'exploit', 'lateral', 'tunnel'].map(s => <option key={s} value={s}>{s}</option>)}</select></div><input value={edge.label || ''} onChange={e => updateEdge(edge.id, { label: e.target.value })} placeholder="VPN / SMB / trust" style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 6px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }} /></div>)}</div>
              {hostObj?.domain && (
                <div style={{ background: '#c07af011', border: '1px solid #c07af033', borderRadius: 4, padding: '5px 9px', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontSize: 9, color: '#c07af0', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>AD</span>
                  <span style={{ fontSize: 10, color: '#c07af0', fontFamily: 'JetBrains Mono' }}>{hostObj.domain}</span>
                </div>
              )}
              <div>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Credentials</div>
                {nodeCreds.length === 0 && <div style={{ fontSize: 10, color: '#404550' }}>No linked credentials</div>}
                {hostObj ? nodeCreds.map(c => (
                  <CredPanel key={c.id} cred={c} host={hostObj} accent={accent} pid={projectId} linkType={c._linkType} />
                )) : nodeCreds.map(c => (
                  <div key={c.id} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, padding: '6px 8px', marginBottom: 6 }}>
                    <div style={{ fontSize: 10, color: '#e0e4ec', fontFamily: 'JetBrains Mono' }}>{c.username}</div>
                    <div style={{ fontSize: 9, color: '#606570' }}>{c.service || '—'} · {c.type}{c.cracked ? ' · cracked' : ''}</div>
                  </div>
                ))}
              </div>
            </>}
          </div>
        </div>}
      </div>
    </div>
  );
}

export default function NetworkView({ projectId, accent, accentGreen, networks, onCreateNetwork, onUpdateNetwork, onDeleteNetwork, onCreateHost, onSyncHostByIp, hosts, creds }) {
  const [activeNetId, setActiveNetId] = useState(null);
  const [editingName, setEditingName] = useState(null);
  const [nameVal, setNameVal] = useState('');

  useEffect(() => {
    if (networks.length > 0) {
      if (!activeNetId || !networks.find(n => n.id === activeNetId)) setActiveNetId(networks[0].id);
    } else {
      setActiveNetId(null);
    }
  }, [projectId, networks, activeNetId]);

  const activeNet = networks.find(n => n.id === activeNetId);
  const projectHosts = useMemo(() => hosts.filter(h => h.pid === projectId), [hosts, projectId]);

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
      </div>
      {activeNet ? <NetworkCanvas key={activeNet.id} projectId={projectId} net={activeNet} onUpdate={(data) => onUpdateNetwork(activeNet.id, data)} onCreateHost={onCreateHost} onSyncHostByIp={onSyncHostByIp} accent={accent} accentGreen={accentGreen} hosts={projectHosts} creds={creds} /> : <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 14, color: '#303540' }}><Icon name="network" size={40} color="#2a2d35" /><div style={{ fontSize: 13, color: '#404550' }}>No network maps</div><button onClick={() => onCreateNetwork({ pid: projectId, name: 'Main network', background: '#07080b' })} style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 20px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 7 }}><Icon name="plus" size={12} color="#fff" /> Create first map</button></div>}
    </div>
  );
}
