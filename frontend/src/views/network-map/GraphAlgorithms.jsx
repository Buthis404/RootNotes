/**
 * Graph algorithms, edge styles, overlay computations for network topology.
 *
 * Pure functions extracted from NetworkView.jsx.
 */
import { memo, useCallback, useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import { isAttackerHost } from '../../utils/hostMeta.js';

// ── Transport colors (from edge_semantics) ────────────────────────────

export const TRANSPORT_COLORS = {
  ssh: '#39d353', winrm: '#5b8af5', smb: '#c07af0', rdp: '#f09a3a',
  c2: '#e8574a', ldap: '#8f7af5', http: '#6fc8f0', mssql: '#e8cc42',
};

// ── BFS / attack path ───────────────────────────────────────────────

export function buildAttackAdj(edges) {
  const adj = new Map();
  for (const e of edges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    if (!adj.has(e.to)) adj.set(e.to, []);
    adj.get(e.from).push({ node: e.to, eid: e.id });
    adj.get(e.to).push({ node: e.from, eid: e.id });
  }
  return adj;
}

function bfsReconstructPath(parent, targetId) {
  const pathNodes = new Set();
  const pathEdges = new Set();
  let n = targetId;
  while (n != null) {
    pathNodes.add(n);
    const p = parent.get(n);
    if (p) { pathEdges.add(p.eid); n = p.from; } else break;
  }
  return { pathNodes, pathEdges };
}

function bfsPath(adj, startSet, targetId) {
  if (startSet.has(targetId)) return { pathNodes: new Set([targetId]), pathEdges: new Set() };
  const parent = new Map();
  for (const id of startSet) parent.set(id, null);
  const queue = [...startSet];
  while (queue.length) {
    const cur = queue.shift();
    for (const { node, eid } of (adj.get(cur) || [])) {
      if (!parent.has(node)) {
        parent.set(node, { from: cur, eid });
        if (node === targetId) return bfsReconstructPath(parent, node);
        queue.push(node);
      }
    }
  }
  return null;
}

export function findAttackerNodeIds(nodes, hosts) {
  const result = new Set();
  for (const n of nodes) {
    const h = (hosts || []).find(x => x.id === n.host_id || (n.ip && x.ip === n.ip));
    if (h && isAttackerHost(h)) result.add(n.id);
  }
  return result;
}

function _collectNeighbours(adj, nodeId, pathNodes, pathEdges) {
  for (const { node, eid } of (adj.get(nodeId) || [])) { pathNodes.add(node); pathEdges.add(eid); }
}

function _applyBfsResultForTarget(adj, targetId, result, attackerNodeIds, pathNodes, pathEdges) {
  if (result) {
    for (const n of result.pathNodes) pathNodes.add(n);
    for (const e of result.pathEdges) pathEdges.add(e);
    for (const id of attackerNodeIds) pathNodes.add(id);
  } else {
    _collectNeighbours(adj, targetId, pathNodes, pathEdges);
  }
}

export function computeAttackPathSet(adj, selectedNodeIds, selectedNodeSet, attackerNodeIds) {
  const pathNodes = new Set(selectedNodeSet);
  const pathEdges = new Set();
  if (attackerNodeIds.size > 0) {
    for (const targetId of selectedNodeIds) {
      const result = bfsPath(adj, attackerNodeIds, targetId);
      _applyBfsResultForTarget(adj, targetId, result, attackerNodeIds, pathNodes, pathEdges);
    }
  } else {
    for (const id of selectedNodeSet) _collectNeighbours(adj, id, pathNodes, pathEdges);
  }
  return { nodes: pathNodes, edges: pathEdges };
}

// ── Edge style lookup ───────────────────────────────────────────────

const EDGE_STYLE_BY_TYPE = {
  internet_facing: { stroke: '#f06a3a', sw: 1.8, dash: '10 3', anim: true },
  lateral: { stroke: '#e8cc42', sw: 2, dash: '5 3', anim: true },
  pivot: { stroke: '#e8cc42', sw: 2, dash: '5 3', anim: true },
  domain_member: { stroke: '#8f7af5', sw: 1.5, dash: '8 4', anim: false },
  auth_path: { stroke: '#c07af0', sw: 1.5, dash: '6 3', anim: false },
  trust: { stroke: '#c07af0', sw: 1.5, dash: '6 3', anim: false },
  uplink: { stroke: '#f09a3a', sw: 2, dash: '7 3', anim: true },
  same_subnet: { stroke: '#3a4a5a', sw: 1, dash: '5 5', anim: false },
  lan: { stroke: '#3a4a5a', sw: 1, dash: '5 5', anim: false },
  service_dep: { stroke: '#6a7180', sw: 1, dash: '2 4', anim: false },
  routed: { stroke: '#2a3a50', sw: 1, dash: '3 7', anim: false },
};

const EDGE_STYLE_BY_STYLE = {
  exploit: { stroke: '#cc2233', sw: 2, dash: '6 3', anim: true },
  lateral: { stroke: '#e8cc42', sw: 2, dash: '4 4', anim: true },
  tunnel: { stroke: '#5b8af5', sw: 2, dash: '8 4', anim: true },
  normal: { stroke: '#39d353', sw: 1.5, dash: '4 6', anim: false },
};

const ACCESS_EDGE_TYPES = new Set(['ssh', 'winrm', 'smb_admin', 'local_admin', 'shell', 'c2_session']);

export function edgeStyle(edge) {
  const s = typeof edge === 'string' ? edge : (edge?.style || '');
  const t = typeof edge === 'string' ? '' : (edge?.type || '');
  const verified = typeof edge === 'object' ? edge?.verified : false;
  const state = typeof edge === 'object' ? (edge?.state || '') : '';
  if (state === 'stale') return { stroke: '#5a5a5a', sw: 1, dash: '2 6', anim: false };
  if (ACCESS_EDGE_TYPES.has(t)) {
    return verified ? { stroke: '#39d353', sw: 2.5, dash: 'none', anim: false } : { stroke: '#39d35399', sw: 1.5, dash: '6 3', anim: false };
  }
  if (t === 'domain_admin') {
    return verified ? { stroke: '#e8574a', sw: 2.5, dash: 'none', anim: false } : { stroke: '#e8574a88', sw: 1.5, dash: '6 3', anim: false };
  }
  return EDGE_STYLE_BY_TYPE[t] || EDGE_STYLE_BY_STYLE[s] || { stroke: '#39d353', sw: 1.5, dash: '4 6', anim: false };
}

// ── Overlay computations ────────────────────────────────────────────

function overlaySetHigherPriority(map, key, entry) {
  if (!key) return;
  const existing = map.get(key);
  if (!existing || entry.priority > existing.priority) map.set(key, entry);
}

function applyAttackStepsToOverlay(map, attackSteps, projectHosts) {
  for (const step of attackSteps) {
    if (!step.label) continue;
    for (const host of projectHosts) {
      if (step.label === host.ip || step.label === host.hostname || step.sublabel === host.ip) {
        overlaySetHigherPriority(map, host.id, { color: '#5b8af5', label: 'In attack path', priority: 3 }); break;
      }
    }
  }
}

function applyFindingsToOverlay(map, findings) {
  for (const f of findings) {
    if (!f.host_id) continue;
    if (f.severity === 'critical') overlaySetHigherPriority(map, f.host_id, { color: '#e8574a', label: 'Critical finding', priority: 5 });
    else if (f.severity === 'high') overlaySetHigherPriority(map, f.host_id, { color: '#f09a3a', label: 'High finding', priority: 4 });
    else if (f.severity === 'medium') overlaySetHigherPriority(map, f.host_id, { color: '#e8cc42', label: 'Medium finding', priority: 2 });
  }
}

export function computeOverlayThreats(map, creds, objectives, findings, attackSteps, projectHosts) {
  for (const cred of creds) { for (const hid of (cred.host_ids || [])) overlaySetHigherPriority(map, hid, { color: '#39d353', label: 'Has creds', priority: 1 }); }
  for (const obj of objectives) { if (obj.host_id && (obj.status === 'captured' || obj.status === 'submitted')) overlaySetHigherPriority(map, obj.host_id, { color: '#f09a3a', label: 'Objective captured', priority: 3 }); }
  applyFindingsToOverlay(map, findings);
  applyAttackStepsToOverlay(map, attackSteps, projectHosts);
}

export function computeOverlaySessions(map, allActivities) {
  for (const act of allActivities) {
    if (act.activity_type === 'c2') overlaySetHigherPriority(map, act.host_id, { color: '#39d353', label: 'C2 session', priority: 5 });
    else if (act.activity_type === 'shell' || act.activity_type === 'exec') overlaySetHigherPriority(map, act.host_id, { color: '#6fc8f0', label: 'Shell activity', priority: 3 });
  }
}

export function computeOverlayAccess(map, creds, projectHosts, networks, activeNetId) {
  for (const cred of creds) { for (const hid of (cred.host_ids || [])) overlaySetHigherPriority(map, hid, { color: '#39d353', label: 'Cred valid', priority: 2 }); }
  for (const host of projectHosts) {
    if (host.status === 'pwned') overlaySetHigherPriority(map, host.id, { color: '#e8574a', label: 'Pwned', priority: 5 });
    else if (host.status === 'access') overlaySetHigherPriority(map, host.id, { color: '#f09a3a', label: 'Access', priority: 4 });
  }
  const activeNetObj = networks.find(n => n.id === activeNetId);
  const netEdges = activeNetObj?.edges || activeNetObj?.edges_json || [];
  const netNodes = activeNetObj?.nodes || activeNetObj?.nodes_json || [];
  const nodeById = new Map(netNodes.map(n => [n.id, n]));
  for (const edge of netEdges) {
    if ((edge.type || '') === 'uplink') {
      const toNode = nodeById.get(String(edge.to || ''));
      if (toNode?.host_id) overlaySetHigherPriority(map, toNode.host_id, { color: '#f09a3a', label: 'Entry gateway', priority: 6 });
    }
  }
}

export function computeOverlayPivots(map, pivots) {
  for (const pivot of pivots) {
    if (pivot.source_host_id) overlaySetHigherPriority(map, pivot.source_host_id, { color: '#c07af0', label: 'Pivot source', priority: 3 });
    if (pivot.pivot_host_id) overlaySetHigherPriority(map, pivot.pivot_host_id, { color: '#e8cc42', label: pivot.route_cidr ? `Pivot ${pivot.route_cidr}` : 'Pivot node', priority: 5 });
    if (pivot.target_host_id) overlaySetHigherPriority(map, pivot.target_host_id, { color: '#5b8af5', label: 'Pivot target', priority: 2 });
  }
}

const ROLE_COLORS_MAP = {
  domain_controller: '#e8574a', server: '#f09a3a', file_server: '#f09a3a', database: '#c07af0',
  workstation: '#5b8af5', laptop: '#5b8af5', network: '#6fc8f0', printer: '#a0a8b8', other: '#606570',
};

export function computeOverlayRoles(map, projectHosts) {
  for (const host of projectHosts) {
    const color = ROLE_COLORS_MAP[host.role] || '#606570';
    overlaySetHigherPriority(map, host.id, { color, label: host.role || 'unknown', priority: 1 });
    if (host.ip) overlaySetHigherPriority(map, host.ip, { color, label: host.role || 'unknown', priority: 1 });
  }
}

export function renderRoleBadges(roleBadges, badgeY) {
  const bw = 20, gap = 2;
  const totalW = roleBadges.length * (bw + gap) - gap;
  const startX = 20 - totalW / 2;
  return roleBadges.map((r, i) => (
    <g key={r.id} transform={`translate(${startX + i * (bw + gap)},${badgeY})`}>
      <rect x="0" y="0" width={bw} height="10" rx="2.5" fill={r.color + '22'} stroke={r.color + '66'} strokeWidth=".8" />
      <text x={bw / 2} y="7.5" textAnchor="middle" fontSize="6" fill={r.color} fontFamily="JetBrains Mono" fontWeight="600">{r.short}</text>
    </g>
  ));
}

// ── IP array helpers ────────────────────────────────────────────────

function _resolveIps(node, emptyFallback) {
  if (node.ips && node.ips.length > 0) return [...node.ips];
  if (node.ip) return [node.ip];
  return emptyFallback ? [''] : [];
}

export function updateIpAtIndex(selectedNode, i, value, updateNode) {
  const currentIps = _resolveIps(selectedNode, true);
  const next = [...currentIps]; next[i] = value;
  const filtered = next.filter(x => x?.trim());
  updateNode(selectedNode.id, { ips: filtered, ip: filtered[0] || '' });
}

export function removeIpAtIndex(selectedNode, i, updateNode) {
  const currentIps = _resolveIps(selectedNode, false);
  const next = currentIps.filter((_, idx) => idx !== i);
  updateNode(selectedNode.id, { ips: next, ip: next[0] || '' });
}

// ── CommitFieldInput ────────────────────────────────────────────────

export const CommitFieldInput = memo(function CommitFieldInput({ label, value, onCommit, placeholder, mono = true, textarea = false }) {
  const [draft, setDraft] = useState(value || '');
  useEffect(() => { setDraft(value || ''); }, [value]);
  const commit = useCallback(() => { if ((value || '') !== draft) onCommit(draft); }, [draft, onCommit, value]);
  const commonProps = {
    value: draft, onChange: (e) => setDraft(e.target.value), onBlur: commit, placeholder,
    style: { width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: mono ? 'JetBrains Mono' : 'Space Grotesk', boxSizing: 'border-box' },
  };
  return (
    <div>
      <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
      {textarea ? <textarea {...commonProps} rows={3} style={{ ...commonProps.style, resize: 'vertical' }} /> : <input {...commonProps} onKeyDown={(e) => { if (e.key === 'Enter') e.currentTarget.blur(); }} />}
    </div>
  );
});

CommitFieldInput.propTypes = {
  label: PropTypes.string,
  value: PropTypes.string,
  onCommit: PropTypes.func,
  placeholder: PropTypes.string,
  mono: PropTypes.bool,
  textarea: PropTypes.bool,
};
