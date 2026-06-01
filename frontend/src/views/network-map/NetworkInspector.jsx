/**
 * Network inspector — details, activities, credentials, pivots, regions.
 *
 * Extracted verbatim from NetworkView.jsx to preserve all original logic.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../../components/Icon.jsx';
import { FieldInput, Badge } from '../../components/UI.jsx';
import { NODE_STATUS, NODE_TYPES, OS_ICONS } from '../../constants.js';
import { api } from '../../api.js';
import C2HostActionsPanel from '../../components/C2HostActionsPanel.jsx';
import { getCredBadges, getHostBadges, summarizeCreds, normalizeDomain, domainsMatch, HOST_ROLES } from '../../utils/hostMeta.js';
import CredPanel from './CredPanel.jsx';
import { ACTIVITY_TYPES, ACTIVITY_STATUS, EMPTY_ACTIVITY, INSPECTOR_TABS, ROLE_ICON } from './constants.js';
import { TRANSPORT_COLORS, updateIpAtIndex, removeIpAtIndex, CommitFieldInput } from './GraphAlgorithms.jsx';

function _noiseColor(level) {
  if (level === 'high') return '#e8574a';
  if (level === 'med') return '#f09a3a';
  return '#39d353';
}

function _getNodeDisplayIps(node) {
  if (node.ips && node.ips.length > 0) return node.ips;
  if (node.ip) return [node.ip];
  return [''];
}

function NodeIpsBlock({ selectedNode, updateNode }) {
  const displayIps = _getNodeDisplayIps(selectedNode);
  return (
    <div>
      <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>IP / CIDR addresses</span>
        <button onClick={() => { const cur = _getNodeDisplayIps(selectedNode); updateNode(selectedNode.id, { ips: [...cur, ''] }); }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>+</button>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {displayIps.map((ip, i) => (
          <div key={`ip-${ip || i}`} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
            <input value={ip || ''} onChange={e => updateIpAtIndex(selectedNode, i, e.target.value, updateNode)} placeholder="192.168.1.1 or 10.0.0.0/24" style={{ flex: 1, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }} />
            {displayIps.length > 1 && <button onClick={() => removeIpAtIndex(selectedNode, i, updateNode)} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 2, display: 'flex' }}><Icon name="trash" size={11} color="#404550" /></button>}
          </div>
        ))}
      </div>
    </div>
  );
}

NodeIpsBlock.propTypes = {
  selectedNode: PropTypes.object,
  updateNode: PropTypes.func,
};

function NodeRolesBlock({ selectedNode, hostObj, updateNode }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Role</div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
        {Object.entries(HOST_ROLES).map(([role, meta]) => {
          const active = (hostObj?.role || selectedNode.role) === role;
          return <button key={role} onClick={() => updateNode(selectedNode.id, { role, type: meta.nodeType, is_attacker: role === 'attacker' })} style={{ background: active ? `${meta.color}22` : '#0e1016', border: `1px solid ${active ? meta.color + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: active ? meta.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4 }}><Icon name={ROLE_ICON[role] || 'server'} size={10} color={active ? meta.color : '#505560'} />{meta.label}</button>;
        })}
      </div>
    </div>
  );
}

NodeRolesBlock.propTypes = {
  selectedNode: PropTypes.object,
  hostObj: PropTypes.object,
  updateNode: PropTypes.func,
};

function NodeTagsBlock({ selectedNode, hostObj, updateNode }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase' }}>Tags</div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 5 }}>
        {(hostObj.tags || []).map(tag => (
          <span key={tag} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 10, padding: '2px 7px', fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono' }}>
            {tag}<button onClick={() => updateNode(selectedNode.id, { tags: (hostObj.tags || []).filter(t => t !== tag) })} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: '#404550', display: 'flex', lineHeight: 1 }}>×</button>
          </span>
        ))}
      </div>
      <input placeholder="Add tag (Enter)" style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} onKeyDown={e => {
        if (e.key === 'Enter' && e.currentTarget.value.trim()) {
          updateNode(selectedNode.id, { tags: [...new Set([...(hostObj.tags || []), e.currentTarget.value.trim()])] });
          e.currentTarget.value = '';
        }
      }} />
    </div>
  );
}

NodeTagsBlock.propTypes = {
  selectedNode: PropTypes.object,
  hostObj: PropTypes.object,
  updateNode: PropTypes.func,
};

function EdgeDetailRow({ edge, peerLabel, selectedNode, updateEdge, deleteEdge }) {
  return (
    <div key={edge.id} style={{ display: 'flex', flexDirection: 'column', gap: 5, padding: '8px 0', borderBottom: '1px solid #14161b' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, color: '#9098a8', flex: 1 }}>{peerLabel || '?'}</span>
        <select value={edge.style} onChange={e => updateEdge(edge.id, { style: e.target.value })} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 3, color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '1px 4px' }}>{['normal', 'exploit', 'lateral', 'tunnel'].map(s => <option key={s} value={s}>{s}</option>)}</select>
        <button onClick={() => deleteEdge(edge.id)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, color: '#cc2233', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '2px 6px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4 }}><Icon name="trash" size={10} color="#cc2233" />Delete</button>
      </div>
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
        <select value={edge.type || 'link'} onChange={e => updateEdge(edge.id, { type: e.target.value })} style={{ background: '#0e1016', border: '1px solid #6fc8f044', borderRadius: 3, color: '#6fc8f0', fontSize: 9, fontFamily: 'JetBrains Mono', padding: '1px 4px' }}>
          {['ssh','winrm','smb_admin','local_admin','shell','c2_session','rdp','lateral','pivot','uplink','domain_admin','domain_member','auth_path','trust','same_subnet','lan','routed','exploit','tunnel','link'].map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        {edge.transport && (() => { const tc = TRANSPORT_COLORS[edge.transport] || '#808590'; return <span title={`Transport (P5): ${edge.transport}`} style={{ fontSize: 9, color: tc, background: tc + '18', border: `1px solid ${tc}33`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{edge.transport}</span>; })()}
        {edge.kind && edge.kind !== 'other' && <span title={`Kind (P5): ${edge.kind}`} style={{ fontSize: 9, color: '#6fc8f0', background: '#6fc8f018', border: '1px solid #6fc8f033', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{edge.kind}</span>}
        <span style={{ fontSize: 9, color: '#f09a3a', background: '#f09a3a18', border: '1px solid #f09a3a33', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{edge.state || (edge.is_manual ? 'manual' : 'inferred')}</span>
        <span style={{ fontSize: 9, color: edge.verified ? '#39d353' : '#808590', background: (edge.verified ? '#39d35318' : '#80859018'), border: `1px solid ${edge.verified ? '#39d35333' : '#80859033'}`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{edge.verified ? 'verified' : 'unverified'}</span>
        {edge.confidence != null && <span style={{ fontSize: 9, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{Math.round(Number(edge.confidence) * 100)}%</span>}
        {Array.isArray(edge.mitre_techniques) && edge.mitre_techniques.length > 0 && <span title="MITRE ATT&CK techniques" style={{ fontSize: 9, color: '#9a7af0', background: '#9a7af018', border: '1px solid #9a7af033', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{edge.mitre_techniques.join(', ')}</span>}
        {edge.noise_level && (() => { const nc = _noiseColor(edge.noise_level); return <span title="OPSEC noise level" style={{ fontSize: 9, color: nc, background: nc + '18', border: `1px solid ${nc}33`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>noise:{edge.noise_level}</span>; })()}
        {edge.kill_chain_stage && <span title="Kill-chain stage" style={{ fontSize: 9, color: '#6fc8f0', background: '#6fc8f018', border: '1px solid #6fc8f033', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{edge.kill_chain_stage.replace(/_/g, ' ')}</span>}
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
}

EdgeDetailRow.propTypes = {
  edge: PropTypes.object,
  peerLabel: PropTypes.string,
  selectedNode: PropTypes.object,
  updateEdge: PropTypes.func,
  deleteEdge: PropTypes.func,
};

function NodeLinksBlock({ selectedNode, selectedNodeEdges, updateEdge, deleteEdge, nodeById }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Links / Connections</div>
      {selectedNodeEdges.length === 0 && <div style={{ fontSize: 10, color: '#404550' }}>No connections for this host</div>}
      {selectedNodeEdges.map(edge => {
        const peerId = edge.from === selectedNode.id ? edge.to : edge.from;
        const peerNode = nodeById ? nodeById.get(peerId) : null;
        const peerLabel = peerNode?.label || '?';
        return <EdgeDetailRow key={edge.id} edge={edge} peerLabel={peerLabel} selectedNode={selectedNode} updateEdge={updateEdge} deleteEdge={deleteEdge} />;
      })}
    </div>
  );
}

NodeLinksBlock.propTypes = {
  selectedNode: PropTypes.object,
  selectedNodeEdges: PropTypes.array,
  updateEdge: PropTypes.func,
  deleteEdge: PropTypes.func,
  nodeById: PropTypes.object,
};

function PivotCard({ pivot, projectHosts, onUpdatePivot, onDeletePivot }) {
  const src = projectHosts.find(h => h.id === pivot.source_host_id);
  const tgt = projectHosts.find(h => h.id === pivot.target_host_id);
  const isActive = pivot.status === 'active';
  return (
    <div key={pivot.id} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px', marginBottom: 8 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 4, marginBottom: 4 }}>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', flex: 1 }}>
          <span style={{ fontSize: 8, color: '#e8cc42', background: '#e8cc4218', border: '1px solid #e8cc4233', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{pivot.tool || 'pivot'}</span>
          <span style={{ fontSize: 8, color: '#5b8af5', background: '#5b8af518', border: '1px solid #5b8af533', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{pivot.pivot_type}</span>
          <button onClick={() => onUpdatePivot?.(pivot.id, { status: isActive ? 'inactive' : 'active' })} title="Toggle active/inactive" style={{ fontSize: 8, color: isActive ? '#39d353' : '#808590', background: isActive ? '#39d35318' : '#80859018', border: `1px solid ${isActive ? '#39d35333' : '#80859033'}`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', cursor: 'pointer' }}>{pivot.status}</button>
        </div>
        <button onClick={() => onDeletePivot?.(pivot.id)} title="Remove pivot" style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 12, padding: '0 2px', lineHeight: 1, flexShrink: 0 }}>×</button>
      </div>
      <div style={{ fontSize: 10, color: '#c8cdd6', fontWeight: 600, marginBottom: 4 }}>{pivot.label || `${pivot.tool} ${pivot.pivot_type}`}</div>
      {pivot.route_cidr && <div style={{ fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono', marginBottom: 3 }}>route {pivot.route_cidr}</div>}
      {pivot.bind_address && <div style={{ fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono', marginBottom: 3 }}>bind {pivot.bind_address}</div>}
      {(src || tgt) && <div style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>{src ? `from ${src.hostname || src.ip}` : 'from ?'}{tgt ? ` → ${tgt.hostname || tgt.ip}` : ''}</div>}
      {pivot.notes && <div style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginTop: 4, fontStyle: 'italic' }}>{pivot.notes}</div>}
    </div>
  );
}

PivotCard.propTypes = {
  pivot: PropTypes.object,
  projectHosts: PropTypes.array,
  onUpdatePivot: PropTypes.func,
  onDeletePivot: PropTypes.func,
};

function NodePivotsBlock({ selectedNodePivots, projectHosts, hostObj, onUpdatePivot, onDeletePivot, onAddPivotForHost }) {
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 6 }}>
        <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', flex: 1 }}>Pivot Observations</div>
        {hostObj && onAddPivotForHost && (
          <button onClick={() => onAddPivotForHost(hostObj.id)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: '#808590', fontSize: 9, fontFamily: 'JetBrains Mono' }}>+ Add</button>
        )}
      </div>
      {selectedNodePivots.length === 0 && <div style={{ fontSize: 10, color: '#404550' }}>No pivot data for this host</div>}
      {selectedNodePivots.map(pivot => (
        <PivotCard key={pivot.id} pivot={pivot} projectHosts={projectHosts} onUpdatePivot={onUpdatePivot} onDeletePivot={onDeletePivot} />
      ))}
    </div>
  );
}

NodePivotsBlock.propTypes = {
  selectedNodePivots: PropTypes.array,
  projectHosts: PropTypes.array,
  hostObj: PropTypes.object,
  onUpdatePivot: PropTypes.func,
  onDeletePivot: PropTypes.func,
  onAddPivotForHost: PropTypes.func,
};

function NodeDetailsTab({ selectedNode, hostObj, accent, projectId, updateNode, updateEdge, deleteEdge, selectedNodeEdges, selectedNodePivots, projectHosts, nodeById, onUpdatePivot, onDeletePivot, onAddPivotForHost }) {
  return (
    <>
      <CommitFieldInput label="Name" value={selectedNode.label || ''} onCommit={(v) => updateNode(selectedNode.id, { label: v })} placeholder="HOST-01" />
      <NodeIpsBlock selectedNode={selectedNode} updateNode={updateNode} />
      <CommitFieldInput label="Notes" value={selectedNode.notes || ''} onCommit={(v) => updateNode(selectedNode.id, { notes: v })} placeholder="VPN jump host" textarea />
      <NodeRolesBlock selectedNode={selectedNode} hostObj={hostObj} updateNode={updateNode} />
      {hostObj && (
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>OS</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {['Linux', 'Windows', 'macOS', 'Various', 'Unknown'].map(os => (
              <button key={os} onClick={() => updateNode(selectedNode.id, { os })} style={{ background: hostObj.os === os ? `${accent}22` : '#0e1016', border: `1px solid ${hostObj.os === os ? accent + '77' : '#2a2d35'}`, borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: hostObj.os === os ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{OS_ICONS[os] || '?'} {os}</button>
            ))}
          </div>
        </div>
      )}
      {hostObj && <NodeTagsBlock selectedNode={selectedNode} hostObj={hostObj} updateNode={updateNode} />}
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
      <NodeLinksBlock selectedNode={selectedNode} selectedNodeEdges={selectedNodeEdges} updateEdge={updateEdge} deleteEdge={deleteEdge} nodeById={nodeById} />
      <NodePivotsBlock selectedNodePivots={selectedNodePivots} projectHosts={projectHosts} hostObj={hostObj} onUpdatePivot={onUpdatePivot} onDeletePivot={onDeletePivot} onAddPivotForHost={onAddPivotForHost} />
      <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, padding: '7px 9px' }}><div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 5 }}>Lazy data</div><div style={{ fontSize: 10, color: '#606570' }}>Credentials and activity stay out of the render path until their tab is opened.</div></div>
    </>
  );
}

NodeDetailsTab.propTypes = {
  selectedNode: PropTypes.object,
  hostObj: PropTypes.object,
  accent: PropTypes.string,
  projectId: PropTypes.any,
  updateNode: PropTypes.func,
  updateEdge: PropTypes.func,
  deleteEdge: PropTypes.func,
  selectedNodeEdges: PropTypes.array,
  selectedNodePivots: PropTypes.array,
  projectHosts: PropTypes.array,
  nodeById: PropTypes.object,
  onUpdatePivot: PropTypes.func,
  onDeletePivot: PropTypes.func,
  onAddPivotForHost: PropTypes.func,
};

const _TRUST_ZONES = [
  { id: null,       label: 'None',     fill: '#5b8af522', stroke: '#5b8af5' },
  { id: 'internal', label: 'Internal',  fill: '#39d35322', stroke: '#39d353' },
  { id: 'dmz',      label: 'DMZ',       fill: '#f09a3a22', stroke: '#f09a3a' },
  { id: 'external', label: 'External',  fill: '#cc223322', stroke: '#cc2233' },
  { id: 'custom',   label: 'Custom',    fill: '#a05cff22', stroke: '#a05cff' },
];

function RegionInspectorBody({ selectedRegion, updateRegion }) {
  return (
    <>
      <CommitFieldInput label="Subnet name" value={selectedRegion.label || ''} onCommit={(v) => updateRegion(selectedRegion.id, { label: v })} placeholder="x.x.x.x/24" />
      <CommitFieldInput label="Short note" value={selectedRegion.note || ''} onCommit={(v) => updateRegion(selectedRegion.id, { note: v })} placeholder="VPN segment" textarea />
      <div>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase' }}>Trust Zone</div>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {_TRUST_ZONES.map(z => {
            const active = (selectedRegion.zone_type || null) === z.id;
            return (
              <button key={z.id ?? 'none'} onClick={() => updateRegion(selectedRegion.id, { zone_type: z.id, fill: z.fill, stroke: z.stroke })} style={{ background: active ? z.stroke + '22' : 'transparent', border: `1px solid ${active ? z.stroke : '#2a2d35'}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: active ? z.stroke : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{z.label}</button>
            );
          })}
        </div>
      </div>
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
    </>
  );
}

RegionInspectorBody.propTypes = {
  selectedRegion: PropTypes.object,
  updateRegion: PropTypes.func,
};

async function _saveActivityHandler({ newActivity, editingActivityId, onUpdateActivity, onAddActivity, projectId, hostObj, setActivityCache, setNewActivity, setEditingActivityId, setShowActivityComposer, EMPTY_ACTIVITY }) {
  if (!newActivity.title.trim() && !newActivity.command.trim() && !newActivity.summary.trim() && !newActivity.output.trim()) return;
  const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
  if (editingActivityId) {
    const updated = await onUpdateActivity?.(editingActivityId, { ...newActivity, ts });
    if (updated) {
      setActivityCache(prev => ({
        ...prev,
        [hostObj.id]: (prev[hostObj.id] || []).map(item => item.id === editingActivityId ? updated : item),
      }));
    }
  } else {
    const created = await onAddActivity?.({ pid: projectId, host_id: hostObj.id, ...newActivity, ts });
    if (created) {
      setActivityCache(prev => ({
        ...prev,
        [hostObj.id]: prev[hostObj.id] ? [created, ...prev[hostObj.id]] : [created],
      }));
    }
  }
  setNewActivity(EMPTY_ACTIVITY);
  setEditingActivityId(null);
  setShowActivityComposer(false);
}

function ActivityCard({ act, accent, hostObj, setActivityCache, setEditingActivityId, setShowActivityComposer, setNewActivity, onDeleteActivity, EMPTY_ACTIVITY }) {
  const handleEditAct = () => {
    setEditingActivityId(act.id);
    setShowActivityComposer(true);
    setNewActivity({ title: act.title || '', activity_type: act.activity_type || 'recon', command: act.command || '', summary: act.summary || '', output: act.output || '', status: act.status || 'done' });
  };
  const handleDeleteAct = () => deleteActivityFromCache(act.id, hostObj.id, setActivityCache, onDeleteActivity);
  return (
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
        <button onClick={handleEditAct} style={{ background: 'none', border: 'none', cursor: 'pointer', color: accent, display: 'flex', padding: 2 }}><Icon name="edit" size={11} color="currentColor" /></button>
        <button onClick={handleDeleteAct} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', padding: 2 }}><Icon name="trash" size={11} color="currentColor" /></button>
      </div>
    </div>
  );
}

ActivityCard.propTypes = {
  act: PropTypes.object,
  accent: PropTypes.string,
  hostObj: PropTypes.object,
  setActivityCache: PropTypes.func,
  setEditingActivityId: PropTypes.func,
  setShowActivityComposer: PropTypes.func,
  setNewActivity: PropTypes.func,
  onDeleteActivity: PropTypes.func,
  EMPTY_ACTIVITY: PropTypes.object,
};

function ActivityTabPanel({ hostObj, accent, projectId, selNodeActivities, activitiesLoading, showActivityComposer, editingActivityId, activityTypeFilter, activityStatusFilter, newActivity, setShowActivityComposer, setEditingActivityId, setActivityTypeFilter, setActivityStatusFilter, setNewActivity, setActivityCache, onAddActivity, onUpdateActivity, onDeleteActivity }) {
  const handleToggleComposer = () => {
    setShowActivityComposer(v => !v);
    if (!showActivityComposer && !editingActivityId) setNewActivity(EMPTY_ACTIVITY);
  };
  const handleClearFilters = () => { setActivityTypeFilter(null); setActivityStatusFilter(null); };
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Host activity log</div>
        <button onClick={handleToggleComposer} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#808590', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{showActivityComposer || editingActivityId ? 'Hide form' : 'Add activity'}</button>
      </div>
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 6 }}>
        {Object.entries(ACTIVITY_TYPES).map(([key, meta]) => (
          <button key={key} onClick={() => setActivityTypeFilter(activityTypeFilter === key ? null : key)} style={{ background: activityTypeFilter === key ? `${meta.color}22` : 'transparent', border: `1px solid ${activityTypeFilter === key ? meta.color + '88' : '#2a2d35'}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: activityTypeFilter === key ? meta.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{meta.label}</button>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 8 }}>
        {Object.entries(ACTIVITY_STATUS).map(([key, meta]) => (
          <button key={key} onClick={() => setActivityStatusFilter(activityStatusFilter === key ? null : key)} style={{ background: activityStatusFilter === key ? `${meta.color}22` : 'transparent', border: `1px solid ${activityStatusFilter === key ? meta.color + '88' : '#2a2d35'}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: activityStatusFilter === key ? meta.color : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{meta.label}</button>
        ))}
        {(activityTypeFilter || activityStatusFilter) && (
          <button onClick={handleClearFilters} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>Clear</button>
        )}
      </div>
      {(showActivityComposer || editingActivityId) && (
        <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: 10, marginBottom: 10 }}>
          <input value={newActivity.title} onChange={e => setNewActivity(a => ({ ...a, title: e.target.value }))} placeholder="Title: SMB enum, nmap, exploit..." style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box', marginBottom: 6 }} />
          <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
            <select value={newActivity.activity_type} onChange={e => setNewActivity(a => ({ ...a, activity_type: e.target.value }))} style={{ flex: 1, minWidth: 0, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              {['recon','scan','exploit','privesc','lateral','postex','note'].map(v => <option key={v} value={v}>{v}</option>)}
            </select>
            <select value={newActivity.status} onChange={e => setNewActivity(a => ({ ...a, status: e.target.value }))} style={{ flex: 1, minWidth: 0, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono' }}>
              {['planned','running','done','failed'].map(v => <option key={v} value={v}>{v}</option>)}
            </select>
          </div>
          <textarea value={newActivity.command} onChange={e => setNewActivity(a => ({ ...a, command: e.target.value }))} placeholder="Command or technique used" rows={2} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} />
          <textarea value={newActivity.summary} onChange={e => setNewActivity(a => ({ ...a, summary: e.target.value }))} placeholder="Short summary of what was observed" rows={2} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} />
          <textarea value={newActivity.output} onChange={e => setNewActivity(a => ({ ...a, output: e.target.value }))} placeholder="Raw output / findings / IOC / next steps" rows={3} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} />
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, flexWrap: 'wrap' }}>
            <button onClick={() => { setEditingActivityId(null); setShowActivityComposer(false); setNewActivity(EMPTY_ACTIVITY); }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{editingActivityId ? 'Cancel edit' : 'Cancel'}</button>
            <button onClick={() => _saveActivityHandler({ newActivity, editingActivityId, onUpdateActivity, onAddActivity, projectId, hostObj, setActivityCache, setNewActivity, setEditingActivityId, setShowActivityComposer, EMPTY_ACTIVITY })} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>{editingActivityId ? 'Update activity' : 'Save activity'}</button>
          </div>
        </div>
      )}
      {activitiesLoading[hostObj.id] && <div style={{ fontSize: 10, color: '#404550' }}>Loading activity…</div>}
      {!activitiesLoading[hostObj.id] && selNodeActivities.length === 0 && !showActivityComposer && !editingActivityId && <div style={{ fontSize: 10, color: '#404550' }}>No recorded actions for this host</div>}
      {selNodeActivities.map(act => (
        <ActivityCard key={act.id} act={act} accent={accent} hostObj={hostObj} setActivityCache={setActivityCache} setEditingActivityId={setEditingActivityId} setShowActivityComposer={setShowActivityComposer} setNewActivity={setNewActivity} onDeleteActivity={onDeleteActivity} EMPTY_ACTIVITY={EMPTY_ACTIVITY} />
      ))}
    </div>
  );
}

ActivityTabPanel.propTypes = {
  hostObj: PropTypes.object,
  accent: PropTypes.string,
  projectId: PropTypes.any,
  selNodeActivities: PropTypes.array,
  activitiesLoading: PropTypes.object,
  showActivityComposer: PropTypes.bool,
  editingActivityId: PropTypes.string,
  activityTypeFilter: PropTypes.string,
  activityStatusFilter: PropTypes.string,
  newActivity: PropTypes.object,
  setShowActivityComposer: PropTypes.func,
  setEditingActivityId: PropTypes.func,
  setActivityTypeFilter: PropTypes.func,
  setActivityStatusFilter: PropTypes.func,
  setNewActivity: PropTypes.func,
  setActivityCache: PropTypes.func,
  onAddActivity: PropTypes.func,
  onUpdateActivity: PropTypes.func,
  onDeleteActivity: PropTypes.func,
};

function CredentialsTabPanel({ hostObj, accent, projectId, credsLoading, nodeCreds, nodeCredSummary }) {
  return (
    <div>
      {credsLoading && <div style={{ fontSize: 10, color: '#404550', marginBottom: 8 }}>Loading credentials…</div>}
      {!credsLoading && nodeCredSummary.total > 0 && (
        <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, padding: '7px 9px', marginBottom: 10 }}>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', marginBottom: 5 }}>Known credentials</div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            <Badge label={`${nodeCredSummary.total} linked`} color={accent} />
            {nodeCredSummary.withSecrets > 0 && <Badge label={`${nodeCredSummary.withSecrets} secrets`} color="#39d353" />}
            {nodeCredSummary.passwords > 0 && <Badge label={`${nodeCredSummary.passwords} passwords`} color="#5b8af5" />}
            {nodeCredSummary.hashes > 0 && <Badge label={`${nodeCredSummary.hashes} hashes`} color="#c07af0" />}
          </div>
        </div>
      )}
      {!credsLoading && nodeCreds.length === 0 && <div style={{ fontSize: 10, color: '#404550' }}>No linked credentials</div>}
      {nodeCreds.map(c => (
        <div key={c.id} style={{ marginBottom: 6 }}>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>{getCredBadges(c).slice(0, 5).map(b => <Badge key={`${c.id}-${b.label}`} label={b.label} color={b.color} />)}</div>
          <CredPanel cred={c} host={hostObj} accent={accent} pid={projectId} linkType={c._linkType} />
        </div>
      ))}
    </div>
  );
}

CredentialsTabPanel.propTypes = {
  hostObj: PropTypes.object,
  accent: PropTypes.string,
  projectId: PropTypes.any,
  credsLoading: PropTypes.bool,
  nodeCreds: PropTypes.array,
  nodeCredSummary: PropTypes.object,
};

function NodeInspectorContent({ activeTab, setActiveTab, accent, selectedNode, hostObj, projectId, updateNode, updateEdge, deleteEdge, selectedNodeEdges, selectedNodePivots, projectHosts, nodeById, onUpdatePivot, onDeletePivot, onAddPivotForHost, selNodeActivities, activitiesLoading, showActivityComposer, editingActivityId, activityTypeFilter, activityStatusFilter, newActivity, setShowActivityComposer, setEditingActivityId, setActivityTypeFilter, setActivityStatusFilter, setNewActivity, setActivityCache, onAddActivity, onUpdateActivity, onDeleteActivity, credsLoading, nodeCreds, nodeCredSummary }) {
  return (
    <>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {INSPECTOR_TABS.map(tab => {
          const active = activeTab === tab;
          return <button key={tab} onClick={() => setActiveTab(tab)} style={{ background: active ? `${accent}22` : 'transparent', border: `1px solid ${active ? accent + '66' : '#2a2d35'}`, borderRadius: 4, padding: '4px 9px', cursor: 'pointer', color: active ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{tab}</button>;
        })}
      </div>
      {activeTab === 'details' && (
        <NodeDetailsTab selectedNode={selectedNode} hostObj={hostObj} accent={accent} projectId={projectId} updateNode={updateNode} updateEdge={updateEdge} deleteEdge={deleteEdge} selectedNodeEdges={selectedNodeEdges} selectedNodePivots={selectedNodePivots} projectHosts={projectHosts} nodeById={nodeById} onUpdatePivot={onUpdatePivot} onDeletePivot={onDeletePivot} onAddPivotForHost={onAddPivotForHost} />
      )}
      {activeTab === 'activity' && hostObj && (
        <ActivityTabPanel hostObj={hostObj} accent={accent} projectId={projectId} selNodeActivities={selNodeActivities} activitiesLoading={activitiesLoading} showActivityComposer={showActivityComposer} editingActivityId={editingActivityId} activityTypeFilter={activityTypeFilter} activityStatusFilter={activityStatusFilter} newActivity={newActivity} setShowActivityComposer={setShowActivityComposer} setEditingActivityId={setEditingActivityId} setActivityTypeFilter={setActivityTypeFilter} setActivityStatusFilter={setActivityStatusFilter} setNewActivity={setNewActivity} setActivityCache={setActivityCache} onAddActivity={onAddActivity} onUpdateActivity={onUpdateActivity} onDeleteActivity={onDeleteActivity} />
      )}
      {activeTab === 'credentials' && hostObj && (
        <CredentialsTabPanel hostObj={hostObj} accent={accent} projectId={projectId} credsLoading={credsLoading} nodeCreds={nodeCreds} nodeCredSummary={nodeCredSummary} />
      )}
    </>
  );
}

NodeInspectorContent.propTypes = {
  activeTab: PropTypes.string,
  setActiveTab: PropTypes.func,
  accent: PropTypes.string,
  selectedNode: PropTypes.object,
  hostObj: PropTypes.object,
  projectId: PropTypes.any,
  updateNode: PropTypes.func,
  updateEdge: PropTypes.func,
  deleteEdge: PropTypes.func,
  selectedNodeEdges: PropTypes.array,
  selectedNodePivots: PropTypes.array,
  projectHosts: PropTypes.array,
  nodeById: PropTypes.object,
  onUpdatePivot: PropTypes.func,
  onDeletePivot: PropTypes.func,
  onAddPivotForHost: PropTypes.func,
  selNodeActivities: PropTypes.array,
  activitiesLoading: PropTypes.object,
  showActivityComposer: PropTypes.bool,
  editingActivityId: PropTypes.string,
  activityTypeFilter: PropTypes.string,
  activityStatusFilter: PropTypes.string,
  newActivity: PropTypes.object,
  setShowActivityComposer: PropTypes.func,
  setEditingActivityId: PropTypes.func,
  setActivityTypeFilter: PropTypes.func,
  setActivityStatusFilter: PropTypes.func,
  setNewActivity: PropTypes.func,
  setActivityCache: PropTypes.func,
  onAddActivity: PropTypes.func,
  onUpdateActivity: PropTypes.func,
  onDeleteActivity: PropTypes.func,
  credsLoading: PropTypes.bool,
  nodeCreds: PropTypes.array,
  nodeCredSummary: PropTypes.object,
};

export function NetworkInspector({ projectId, accent, selectedNode, selectedRegion, hostObj, edges, nodeById, updateNode, updateEdge, updateRegion, deleteEdge, onClose, onAddActivity, onUpdateActivity, onDeleteActivity, pivots = [], projectHosts = [], onDeletePivot, onUpdatePivot, onAddPivotForHost }) {
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

  const isDomainHost = !!hostObj?.domain?.trim();
  const nodeCreds = useMemo(() => {
    if (!selectedNode || !hostObj || !creds) return [];
    const nodeIps = new Set(_getNodeDisplayIps(selectedNode));
    const hostDomain = normalizeDomain(hostObj?.domain || '');
    return creds.filter(c => c.pid === projectId && (
      (c.host_ids || []).includes(hostObj.id) ||
      nodeIps.has(c.host) ||
      (hostObj.hostname && c.host === hostObj.hostname) ||
      (c.is_domain && hostDomain && domainsMatch(c.domain || '', hostDomain))
    )).map(c => {
      const linkedById = (c.host_ids || []).includes(hostObj.id);
      const linkedByIp = nodeIps.has(c.host) || (hostObj.hostname && c.host === hostObj.hostname);
      let linkType = 'domain?';
      if (linkedById) linkType = 'linked';
      else if (linkedByIp) linkType = 'ip';
      else if (isDomainHost) linkType = 'domain';
      return { ...c, _linkType: linkType };
    });
  }, [creds, hostObj, isDomainHost, projectId, selectedNode]);

  const nodeCredSummary = summarizeCreds(nodeCreds);
  const hostActivities = hostObj ? (activityCache[hostObj.id] || []) : [];
  const selNodeActivities = hostActivities
    .filter(a => !activityTypeFilter || a.activity_type === activityTypeFilter)
    .filter(a => !activityStatusFilter || a.status === activityStatusFilter)
    .sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));
  const selectedNodeEdges = selectedNode ? edges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id) : [];
  const selectedNodePivots = useMemo(() => {
    if (!selectedNode || !hostObj) return [];
    return pivots.filter(p => p.pivot_host_id === hostObj.id || p.source_host_id === hostObj.id || p.target_host_id === hostObj.id);
  }, [hostObj, pivots, selectedNode]);

  if (!selectedNode && !selectedRegion) return null;

  return (
    <div style={{ width: 320, background: '#0c0e13', borderLeft: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
      <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}><span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>{selectedRegion ? 'Region / subnet' : 'Node'}</span><button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={12} color="#606570" /></button></div>
      <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
        {selectedRegion ? (
          <RegionInspectorBody selectedRegion={selectedRegion} updateRegion={updateRegion} />
        ) : (
          <NodeInspectorContent activeTab={activeTab} setActiveTab={setActiveTab} accent={accent} selectedNode={selectedNode} hostObj={hostObj} projectId={projectId} updateNode={updateNode} updateEdge={updateEdge} deleteEdge={deleteEdge} selectedNodeEdges={selectedNodeEdges} selectedNodePivots={selectedNodePivots} projectHosts={projectHosts} nodeById={nodeById} onUpdatePivot={onUpdatePivot} onDeletePivot={onDeletePivot} onAddPivotForHost={onAddPivotForHost} selNodeActivities={selNodeActivities} activitiesLoading={activitiesLoading} showActivityComposer={showActivityComposer} editingActivityId={editingActivityId} activityTypeFilter={activityTypeFilter} activityStatusFilter={activityStatusFilter} newActivity={newActivity} setShowActivityComposer={setShowActivityComposer} setEditingActivityId={setEditingActivityId} setActivityTypeFilter={setActivityTypeFilter} setActivityStatusFilter={setActivityStatusFilter} setNewActivity={setNewActivity} setActivityCache={setActivityCache} onAddActivity={onAddActivity} onUpdateActivity={onUpdateActivity} onDeleteActivity={onDeleteActivity} credsLoading={credsLoading} nodeCreds={nodeCreds} nodeCredSummary={nodeCredSummary} />
        )}
      </div>
    </div>
  );
}

NetworkInspector.propTypes = {
  projectId: PropTypes.any,
  accent: PropTypes.string,
  selectedNode: PropTypes.object,
  selectedRegion: PropTypes.object,
  hostObj: PropTypes.object,
  edges: PropTypes.array,
  nodeById: PropTypes.object,
  updateNode: PropTypes.func,
  updateEdge: PropTypes.func,
  updateRegion: PropTypes.func,
  deleteEdge: PropTypes.func,
  onClose: PropTypes.func,
  onAddActivity: PropTypes.func,
  onUpdateActivity: PropTypes.func,
  onDeleteActivity: PropTypes.func,
  pivots: PropTypes.array,
  projectHosts: PropTypes.array,
  onDeletePivot: PropTypes.func,
  onUpdatePivot: PropTypes.func,
  onAddPivotForHost: PropTypes.func,
};
