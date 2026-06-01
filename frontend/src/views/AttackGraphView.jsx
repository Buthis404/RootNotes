import PropTypes from 'prop-types';
import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';

function _renderChainNode(hid, si, chain, nodes, selectedNodeId) {
  const n = nodes.find(x => x.id === hid);
  const isSelf = hid === selectedNodeId;
  return (
    <React.Fragment key={si}>
      <span style={{ fontSize: 9, color: isSelf ? '#c07af0' : '#808590', fontFamily: 'JetBrains Mono', fontWeight: isSelf ? 700 : 400 }}>
        {n?.label || n?.ip || hid.slice(0, 10)}
      </span>
      {si < chain.length - 1 && <span style={{ fontSize: 9, color: '#c07af066' }}>→</span>}
    </React.Fragment>
  );
}
import { api } from '../api.js';

// ── Constants ────────────────────────────────────────────────────────────────
const STATUS_COLOR = {
  unknown: '#404550', up: '#5b8af5', alive: '#5b8af5', scanned: '#c07af0',
  access: '#f09a3a', pwned: '#cc2233', owned: '#39d353',
};

const CRED_COLOR = {
  plain: '#39d353', hash: '#c07af0', ntlm: '#c07af0',
  key: '#5b8af5', kerberos: '#f09a3a',
};

const ACCESS_COLOR = {
  verified: '#39d353',
  inferred: '#f09a3a',
  path: '#5b8af5',
  domain_admin: '#e8574a',
  pivot: '#c07af0',
  pivot_route: '#8060c0',
};

const SEV_COLOR = {
  critical: '#cc2233', high: '#e8574a', medium: '#f09a3a', low: '#e8cc42', info: '#5b8af5',
};

const NODE_W = 164;
const NODE_H = 68;

// ── Layout ───────────────────────────────────────────────────────────────────
function layoutNodes(raw, canvasH) {
  const nodes = raw.map(n => ({ ...n }));
  const attackerIdx = nodes.findIndex(n => n.type === 'attacker' || n.is_attacker);

  if (attackerIdx >= 0) {
    nodes[attackerIdx] = { ...nodes[attackerIdx], x: 100, y: canvasH / 2, type: 'attacker' };
  }

  let col = 0, rowIdx = 0;
  const ROW_H = 96, COL_W = 200, ROWS = 5;

  nodes.forEach((n, i) => {
    if (i === attackerIdx) return;
    col = Math.floor(rowIdx / ROWS);
    const row = rowIdx % ROWS;
    n.x = 260 + col * COL_W;
    n.y = (canvasH / 2) - ((Math.min(ROWS, nodes.length - (attackerIdx >= 0 ? 1 : 0)) - 1) / 2) * ROW_H + row * ROW_H;
    rowIdx++;
  });

  return nodes;
}

// ── localStorage helpers ─────────────────────────────────────────────────────
const POS_KEY = pid => `ag_pos_${pid}`;
const loadPos = pid => { try { return JSON.parse(localStorage.getItem(POS_KEY(pid)) || '{}'); } catch { return {}; } };
const savePos = (pid, pos) => { try { localStorage.setItem(POS_KEY(pid), JSON.stringify(pos)); } catch {} };

function _nodeOsShort(os) {
  if (!os) return '';
  if (os.includes('Windows')) return 'WIN';
  if (os.includes('Linux')) return 'LIN';
  return os.slice(0, 3).toUpperCase();
}

function _nodeReachBadge(reach) {
  if (reach.is_root) return null;
  if (reach.reachable_via_verified_path) return `v${reach.verified_distance}`;
  if (reach.reachable) return `r${reach.distance}`;
  return null;
}

function _nodeBorderColor(selected, isAttacker, onPath, isDA, sc) {
  if (selected) return '#ffffff';
  if (isAttacker) return '#cc2233';
  if (onPath && isDA) return '#e8574a';
  if (onPath) return '#e8cc42';
  return sc;
}

function _nodeBgFill(isAttacker, onPath, isDA) {
  if (isAttacker) return '#1a0a0a';
  if (onPath && isDA) return '#1a0a06';
  if (onPath) return '#141208';
  return '#0d0f14';
}

function NodeSecondaryLabel({ isAttacker, sublabel }) {
  if (isAttacker) {
    return <text x={NODE_W / 2} y={54} textAnchor="middle" fontSize={9} fill="#cc2233" fontFamily="JetBrains Mono" fontWeight={700}>◆ ATTACKER</text>;
  }
  if (sublabel) {
    return <text x={NODE_W / 2} y={54} textAnchor="middle" fontSize={9} fill="#505560" fontFamily="JetBrains Mono">{sublabel}</text>;
  }
  return null;
}
NodeSecondaryLabel.propTypes = {
  isAttacker: PropTypes.any,
  sublabel: PropTypes.any,
};

function NodeReachBadgeSvg({ reachBadge, reach }) {
  if (!reachBadge) return null;
  const color = reach.reachable_via_verified_path ? '#39d353' : '#5b8af5';
  return (
    <g>
      <rect x={4} y={NODE_H - 14} width={reachBadge.length * 6 + 6} height={11} rx={3} fill="#1a1c22" />
      <text x={7} y={NODE_H - 6} fontSize={8} fill={color} fontFamily="JetBrains Mono">{reachBadge}</text>
    </g>
  );
}
NodeReachBadgeSvg.propTypes = {
  reachBadge: PropTypes.any,
  reach: PropTypes.any,
};

function NodePortBadge({ isAttacker, node }) {
  if (isAttacker || !node.ports || node.ports.length === 0) return null;
  return (
    <g>
      <rect x={NODE_W - 30} y={NODE_H - 15} width={26} height={11} rx={3} fill="#1a1c22" />
      <text x={NODE_W - 17} y={NODE_H - 7} textAnchor="middle" fontSize={8} fill="#404550" fontFamily="JetBrains Mono">
        {node.ports.length}p
      </text>
    </g>
  );
}
NodePortBadge.propTypes = {
  isAttacker: PropTypes.any,
  node: PropTypes.any,
};

// ── Node component ───────────────────────────────────────────────────────────
function HostNode({ node, selected, privMode, onMouseDown, onClick }) {
  const isAttacker = node.type === 'attacker' || node.is_attacker;
  const sc = STATUS_COLOR[node.status] || STATUS_COLOR.unknown;
  const priv = node.privilege_info || {};
  const reach = node.reachability || {};

  const isDA = priv.is_da_capable;
  const isDC = priv.is_dc;
  const onPath = privMode && priv.on_da_path;

  const borderColor = _nodeBorderColor(selected, isAttacker, onPath, isDA, sc);
  const glowTint = isDA ? '#e8574a' : '#e8cc42';
  const glowColor = onPath ? glowTint : null;

  const label = node.label || node.hostname || node.ip || node.id || '';
  const sublabel = node.ip && label !== node.ip ? node.ip : '';
  const osShort = _nodeOsShort(node.os);
  const reachBadge = _nodeReachBadge(reach);
  const strokeW = selected || onPath ? 2 : 1.5;

  const x = node.x - NODE_W / 2;
  const y = node.y - NODE_H / 2;

  return (
    <g
      transform={`translate(${x},${y})`}
      onMouseDown={e => { e.stopPropagation(); onMouseDown(e, node); }}
      onClick={() => onClick(node)}
      style={{ cursor: 'pointer' }}
    >
      {glowColor && (
        <rect width={NODE_W} height={NODE_H} rx={10} ry={10}
          fill="none" stroke={glowColor} strokeWidth={6} strokeOpacity={0.18} />
      )}
      {selected && (
        <rect width={NODE_W} height={NODE_H} rx={9} ry={9}
          fill="none" stroke="#ffffff" strokeWidth={3} strokeOpacity={0.15} />
      )}
      <rect width={NODE_W} height={NODE_H} rx={8} ry={8}
        fill={_nodeBgFill(isAttacker, onPath, isDA)}
        stroke={borderColor}
        strokeWidth={strokeW}
        strokeOpacity={selected ? 1 : 0.8}
      />
      <rect width={NODE_W} height={3} rx={2} ry={0} fill={borderColor} opacity={0.5} />

      <circle cx={10} cy={14} r={3.5} fill={sc} />
      <text x={18} y={18} fontSize={8.5} fill={sc} fontFamily="JetBrains Mono">
        {(node.status || (isAttacker ? 'attacker' : 'unknown')).toUpperCase()}
      </text>

      {osShort && (
        <text x={NODE_W - 7} y={18} fontSize={8} fill="#404550" fontFamily="JetBrains Mono" textAnchor="end">
          {osShort}
        </text>
      )}

      <text x={NODE_W / 2} y={39} textAnchor="middle" fontSize={12} fontWeight={600} fill="#e4e8f0"
        fontFamily={label.match(/^\d/) ? 'JetBrains Mono' : 'Space Grotesk'}>
        {label.length > 18 ? label.slice(0, 17) + '…' : label}
      </text>

      <NodeSecondaryLabel isAttacker={isAttacker} sublabel={sublabel} />

      {isDA && (
        <g transform={`translate(${NODE_W - 16}, ${NODE_H - 16})`}>
          <circle r={7} fill="#e8574a" opacity={0.9} />
          <text textAnchor="middle" dominantBaseline="middle" fontSize={8} fill="#fff" fontFamily="JetBrains Mono" fontWeight={700}>
            {isDC ? 'DC' : 'DA'}
          </text>
        </g>
      )}

      <NodeReachBadgeSvg reachBadge={reachBadge} reach={reach} />
      <NodePortBadge isAttacker={isAttacker} node={node} />
    </g>
  );
}
HostNode.propTypes = {
  node: PropTypes.any,
  selected: PropTypes.any,
  privMode: PropTypes.any,
  onMouseDown: PropTypes.any,
  onClick: PropTypes.any,
};

function _edgeColor(edge, isPrivPath, isPivotRoute, isPivot, isAccess, isDomainAdmin, isPath) {
  if (isPrivPath) return '#e8574a';
  if (isPivotRoute) return ACCESS_COLOR.pivot_route;
  if (isPivot) return ACCESS_COLOR.pivot;
  if (isAccess) {
    if (edge.access_type === 'exploit') return '#cc2233';
    if (isDomainAdmin) return ACCESS_COLOR.domain_admin;
    if (edge.access_type === 'lateral' || edge.access_type === 'pivot') return '#e8cc42';
    if (edge.access_type === 'tunnel') return '#5b8af5';
    return edge.verified ? ACCESS_COLOR.verified : ACCESS_COLOR.inferred;
  }
  if (isPath) return ACCESS_COLOR.path;
  return CRED_COLOR[edge.cred_type] || CRED_COLOR.plain;
}

function _edgeStrokeDash(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess, isPath, verified) {
  if (isPrivPath) return '10 4';
  if (isPivotRoute) return '3 6';
  if (isPivot) return '5 3';
  if ((isDomainAdmin || isAccess) && !verified) return '6 4';
  if (isPath) return '3 5';
  return undefined;
}

function _edgeStrokeW(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess) {
  if (isPrivPath) return 3;
  if (isDomainAdmin) return 2.5;
  if (isAccess) return 2.2;
  if (isPivot || isPivotRoute) return 1.8;
  return 1.5;
}

function _edgeOpacity(dimmed, isPrivPath, isPivotRoute, isAccess, isDomainAdmin) {
  if (dimmed) return 0.12;
  if (isPrivPath) return 1;
  if (isPivotRoute) return 0.45;
  if (isAccess || isDomainAdmin) return 0.8;
  return 0.55;
}

// ── Edge component ───────────────────────────────────────────────────────────
function GraphEdge({ edge, nodes, privMode, highlightedPathIds, dimmed }) {
  const src = nodes.find(n => n.id === (edge.source || edge.from));
  const tgt = nodes.find(n => n.id === (edge.target || edge.to));
  if (!src || !tgt || src === tgt) return null;

  const isAccess = edge.kind === 'access';
  const isPath = edge.kind === 'path';
  const isPivot = edge.kind === 'pivot';
  const isPivotRoute = edge.kind === 'pivot_route';
  const isDomainAdmin = isAccess && edge.access_type === 'domain_admin';
  const isPrivPath = privMode && edge.on_priv_path;

  const color = _edgeColor(edge, isPrivPath, isPivotRoute, isPivot, isAccess, isDomainAdmin, isPath);

  const markerId = `arr-${color.replace('#', '')}`;

  const goRight = tgt.x >= src.x;
  const sx = src.x + (goRight ? NODE_W / 2 : -NODE_W / 2);
  const sy = src.y;
  const tx = tgt.x + (goRight ? -NODE_W / 2 : NODE_W / 2);
  const ty = tgt.y;
  const mx = (sx + tx) / 2;
  const my = (sy + ty) / 2 - Math.abs(tx - sx) * 0.18;
  const d = `M ${sx} ${sy} Q ${mx} ${my} ${tx} ${ty}`;

  const t = 0.5;
  const lx = (1 - t) ** 2 * sx + 2 * (1 - t) * t * mx + t ** 2 * tx;
  const ly = (1 - t) ** 2 * sy + 2 * (1 - t) * t * my + t ** 2 * ty - 6;

  const strokeDash = _edgeStrokeDash(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess, isPath, edge.verified);
  const strokeW = _edgeStrokeW(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess);
  const opacity = _edgeOpacity(dimmed, isPrivPath, isPivotRoute, isAccess, isDomainAdmin);

  return (
    <g>
      {/* Glow under priv path edges */}
      {isPrivPath && (
        <path d={d} fill="none" stroke="#e8574a" strokeWidth={8} strokeOpacity={0.12} strokeLinecap="round" />
      )}
      <path d={d} fill="none" stroke={color}
        strokeWidth={strokeW}
        strokeOpacity={opacity}
        strokeDasharray={strokeDash}
        markerEnd={`url(#${markerId})`}>
        {isPrivPath && (
          <animate attributeName="stroke-dashoffset" from="0" to="-28" dur="1.2s" repeatCount="indefinite" />
        )}
      </path>
      {edge.label && !isPivotRoute && (() => {
        const strippedCredLabel = edge.label.includes('\\') ? edge.label.split('\\').pop() : edge.label;
        const rawLabel = edge.kind === 'credential' ? strippedCredLabel : edge.label;
        const displayLabel = rawLabel.length > 14 ? rawLabel.slice(0, 13) + '…' : rawLabel;
        const boxW = Math.max(56, displayLabel.length * 5.2 + 12);
        return (
          <>
            <rect x={lx - boxW / 2} y={ly - 9} width={boxW} height={12} rx={3} fill="#07080b" opacity={0.9} />
            <text x={lx} y={ly} textAnchor="middle" fontSize={8} fill={color} fontFamily="JetBrains Mono" opacity={dimmed ? 0.2 : 0.9}>
              {displayLabel}
            </text>
          </>
        );
      })()}
    </g>
  );
}
GraphEdge.propTypes = {
  edge: PropTypes.any,
  nodes: PropTypes.any,
  privMode: PropTypes.any,
  highlightedPathIds: PropTypes.any,
  dimmed: PropTypes.any,
};

// ── Side panel pieces ────────────────────────────────────────────────────────
function PanelSection({ title, count, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
        {title}
        {count !== undefined && (
          <span style={{ fontSize: 9, color: '#2a2d35', background: '#1a1c22', borderRadius: 8, padding: '0 5px', fontFamily: 'JetBrains Mono' }}>{count}</span>
        )}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>{children}</div>
    </div>
  );
}
PanelSection.propTypes = {
  title: PropTypes.any,
  count: PropTypes.any,
  children: PropTypes.any,
};

function InfoRow({ label, value, color }) {
  if (!value) return null;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '72px 1fr', gap: 4, fontSize: 11 }}>
      <span style={{ color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.08em', paddingTop: 1 }}>{label}</span>
      <span style={{ color: color || '#c8cdd6', fontFamily: 'JetBrains Mono', wordBreak: 'break-all' }}>{value}</span>
    </div>
  );
}
InfoRow.propTypes = {
  label: PropTypes.any,
  value: PropTypes.any,
  color: PropTypes.any,
};

function NodeHostSection({ node, accent }) {
  const reach = node.reachability || {};
  return (
    <PanelSection title="Host">
      <InfoRow label="Role" value={node.role} />
      <InfoRow label="Zone" value={node.zone_type} />
      <InfoRow label="OS" value={node.os} />
      <InfoRow label="IP" value={node.ip} />
      {reach.is_root && <InfoRow label="Reach" value="attacker root" color="#cc2233" />}
      {!reach.is_root && reach.reachable && (
        <InfoRow label="Reach"
          color={reach.reachable_via_verified_path ? '#39d353' : '#5b8af5'}
          value={reach.reachable_via_verified_path
            ? `verified path · ${reach.verified_distance} hop`
            : `reachable · ${reach.distance} hop`} />
      )}
      {!reach.is_root && !reach.reachable && (
        <InfoRow label="Reach" value="unreachable" color="#404550" />
      )}
      {node.tags?.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 2 }}>
          {node.tags.map(t => (
            <span key={t} style={{ fontSize: 9, background: accent + '1a', border: `1px solid ${accent}33`, borderRadius: 3, padding: '1px 5px', color: accent, fontFamily: 'JetBrains Mono' }}>{t}</span>
          ))}
        </div>
      )}
      {node.ports?.length > 0 && (
        <div style={{ marginTop: 4 }}>
          <div style={{ fontSize: 9, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Ports</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
            {node.ports.slice(0, 20).map((p, i) => (
              <span key={`port-${i}-${typeof p === 'object' ? (p.port || p.number || p.portid) : p}`} style={{ fontSize: 9, background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 3, padding: '1px 5px', color: '#606570', fontFamily: 'JetBrains Mono' }}>
                {typeof p === 'object' ? (p.port || p.number || p.portid) : p}
              </span>
            ))}
            {node.ports.length > 20 && <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>+{node.ports.length - 20}</span>}
          </div>
        </div>
      )}
    </PanelSection>
  );
}
NodeHostSection.propTypes = {
  node: PropTypes.any,
  accent: PropTypes.any,
};

function NodePrivilegeSection({ node, privilegePaths, nodes }) {
  const priv = node.privilege_info || {};
  if (!priv.is_da_capable && !priv.on_da_path) return null;
  return (
    <PanelSection title="Privilege">
      {priv.is_dc && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', background: '#e8574a11', border: '1px solid #e8574a44', borderRadius: 5 }}>
          <span style={{ fontSize: 10, color: '#e8574a', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>◆ Domain Controller</span>
        </div>
      )}
      {priv.is_da_capable && !priv.is_dc && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', background: '#e8574a11', border: '1px solid #e8574a44', borderRadius: 5 }}>
          <span style={{ fontSize: 10, color: '#e8574a', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>◆ Domain Admin target</span>
        </div>
      )}
      {priv.on_da_path && !priv.is_da_capable && (
        <InfoRow label="DA Path" value={`step ${(priv.da_path_distance ?? 0) + 1} of privilege chain`} color="#e8cc42" />
      )}
      {privilegePaths.length > 0 && priv.is_da_capable && (
        <div style={{ marginTop: 4 }}>
          {privilegePaths.filter(p => p[p.length - 1] === node.id).map((path, i) => {
            const pathNodes = path.map(id => nodes.find(n => n.id === id));
            return (
              <div key={`privpath-${path.join('-')}`} style={{ fontSize: 9, color: '#808590', fontFamily: 'JetBrains Mono', marginBottom: 3 }}>
                {pathNodes.map(n => n?.label || n?.ip || '?').join(' → ')}
              </div>
            );
          })}
        </div>
      )}
    </PanelSection>
  );
}
NodePrivilegeSection.propTypes = {
  node: PropTypes.any,
  privilegePaths: PropTypes.any,
  nodes: PropTypes.any,
};

function NodeAccessSection({ edges, nodeId, nodes }) {
  return (
    <PanelSection title="Access" count={edges.length}>
      {edges.length === 0 ? (
        <div style={{ fontSize: 10, color: '#353840', fontFamily: 'JetBrains Mono' }}>No access edges for this host</div>
      ) : edges.slice(0, 8).map(edge => {
        const peerId = edge.from === nodeId ? edge.to : edge.from;
        const peer = nodes.find(n => n.id === peerId);
        const outgoing = edge.from === nodeId;
        const color = edge.verified ? ACCESS_COLOR.verified : ACCESS_COLOR.inferred;
        return (
          <div key={edge.id} style={{ background: '#0a0c10', border: `1px solid ${color}33`, borderRadius: 5, padding: '7px 9px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 9, color, fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{outgoing ? 'out' : 'in'}</span>
              <span style={{ fontSize: 10, color: '#c8cdd6', fontWeight: 600 }}>{peer?.label || peer?.ip || peerId}</span>
            </div>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: edge.reason ? 5 : 0 }}>
              <span style={{ fontSize: 8, color, background: color + '18', border: `1px solid ${color}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{edge.access_type || edge.label}</span>
              <span style={{ fontSize: 8, color: edge.verified ? '#39d353' : '#808590', background: edge.verified ? '#39d35318' : '#80859018', border: `1px solid ${edge.verified ? '#39d35333' : '#80859033'}`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{edge.verified ? 'verified' : 'inferred'}</span>
              {edge.confidence != null && <span style={{ fontSize: 8, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{Math.round(Number(edge.confidence) * 100)}%</span>}
            </div>
            {edge.reason && <div style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>{edge.reason}</div>}
          </div>
        );
      })}
      {edges.length > 8 && (
        <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>+{edges.length - 8} more</div>
      )}
    </PanelSection>
  );
}
NodeAccessSection.propTypes = {
  edges: PropTypes.any,
  nodeId: PropTypes.any,
  nodes: PropTypes.any,
};

function GraphHeader({ graphData, stats, privMode, setPrivMode, showPathsPanel, setShowPathsPanel, privilegePaths, showPivotRoutes, setShowPivotRoutes, resetLayout, load, loading, accent }) {
  return (
    <div style={{ padding: '10px 18px', borderBottom: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0, flexWrap: 'wrap' }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', flex: 1, minWidth: 100 }}>
        Attack Graph
      </div>
      {graphData && (
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          {[
            { label: 'hosts', val: stats.hosts, c: '#c8cdd6' },
            { label: 'access', val: stats.access_edges, c: ACCESS_COLOR.verified },
            { label: 'verified', val: stats.verified_access_edges, c: ACCESS_COLOR.inferred },
            { label: 'reachable', val: stats.reachable_hosts, c: '#5b8af5' },
            { label: 'priv paths', val: stats.privilege_paths, c: '#e8574a' },
            { label: 'DA hosts', val: stats.da_capable_hosts, c: '#e8574a' },
            { label: 'pivot routes', val: stats.pivot_route_edges, c: ACCESS_COLOR.pivot_route },
            { label: 'pivot chains', val: stats.pivot_chains, c: ACCESS_COLOR.pivot },
          ].map(({ label, val, c }) => val > 0 && (
            <span key={label} style={{ fontSize: 11, color: '#505560', fontFamily: 'JetBrains Mono' }}>
              <span style={{ color: c }}>{val}</span> {label}
            </span>
          ))}
        </div>
      )}
      <div style={{ display: 'flex', gap: 6 }}>
        <GraphBtn onClick={() => { setPrivMode(v => !v); if (!privMode) setShowPathsPanel(true); }} extra={{ borderColor: privMode ? '#e8574a88' : '#2a2d35', color: privMode ? '#e8574a' : '#606570', background: privMode ? '#e8574a11' : 'transparent' }}>{privMode ? '● Priv Paths' : '○ Priv Paths'}</GraphBtn>
        {privilegePaths.length > 0 && <GraphBtn onClick={() => setShowPathsPanel(v => !v)} extra={{ borderColor: showPathsPanel ? '#e8574a88' : '#2a2d35', color: showPathsPanel ? '#e8574a' : '#606570', background: showPathsPanel ? '#e8574a11' : 'transparent' }}>{showPathsPanel ? '● Paths' : '○ Paths'}</GraphBtn>}
        <GraphBtn onClick={() => setShowPivotRoutes(v => !v)} extra={{ borderColor: showPivotRoutes ? ACCESS_COLOR.pivot_route + '88' : '#2a2d35', color: showPivotRoutes ? ACCESS_COLOR.pivot_route : '#606570', background: showPivotRoutes ? ACCESS_COLOR.pivot_route + '11' : 'transparent' }}>{showPivotRoutes ? '● Pivots' : '○ Pivots'}</GraphBtn>
        <GraphBtn onClick={resetLayout}>Reset</GraphBtn>
        <GraphBtn onClick={load} extra={{ borderColor: accent + '44', color: accent }}>{loading ? 'Loading…' : 'Refresh'}</GraphBtn>
      </div>
    </div>
  );
}
GraphHeader.propTypes = {
  graphData: PropTypes.any,
  stats: PropTypes.any,
  privMode: PropTypes.any,
  setPrivMode: PropTypes.any,
  showPathsPanel: PropTypes.any,
  setShowPathsPanel: PropTypes.any,
  privilegePaths: PropTypes.any,
  showPivotRoutes: PropTypes.any,
  setShowPivotRoutes: PropTypes.any,
  resetLayout: PropTypes.any,
  load: PropTypes.any,
  loading: PropTypes.any,
  accent: PropTypes.any,
};


function _applyNodePos(rawNodes, nodePos) {
  return rawNodes.map(n => ({
    ...n,
    x: nodePos[n.id]?.x ?? n.x,
    y: nodePos[n.id]?.y ?? n.y,
  }));
}

function _filterEdges(allEdges, showPivotRoutes) {
  if (showPivotRoutes) return allEdges;
  return allEdges.filter(e => e.kind !== 'pivot_route' && e.kind !== 'pivot');
}

function _computeArrowColors(edges) {
  return [...new Set(edges.map(e => _edgeColor(
    e, false,
    e.kind === 'pivot_route', e.kind === 'pivot', e.kind === 'access',
    e.kind === 'access' && e.access_type === 'domain_admin',
    e.kind === 'path',
  )))];
}

function _getSelectedNodeEdges(allEdges, selectedNode) {
  if (!selectedNode) return [];
  return allEdges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id);
}

function _getLinkedCreds(allCreds, selectedNode) {
  if (!selectedNode) return [];
  return allCreds.filter(c => (c.host_ids || []).includes(selectedNode.id));
}

function _deriveGraphState(graphData, nodePos, canvasH, showPivotRoutes, selectedNode, allCreds) {
  const rawNodes = layoutNodes(graphData?.nodes || [], canvasH);
  const nodes = _applyNodePos(rawNodes, nodePos);
  const allEdges = graphData?.edges || [];
  const edges = _filterEdges(allEdges, showPivotRoutes);
  const arrowColors = _computeArrowColors(edges);

  const stats = graphData?.stats || {};
  const privilegePaths = graphData?.privilege_paths || [];
  const privilegePathDetails = graphData?.privilege_path_details || [];
  const pivotChains = graphData?.pivot_chains || [];

  const selectedNodeEdges = _getSelectedNodeEdges(allEdges, selectedNode);
  const linkedCreds = _getLinkedCreds(allCreds, selectedNode);

  return {
    nodes, allEdges, edges, arrowColors, stats,
    privilegePaths, privilegePathDetails, pivotChains,
    selectedNodeEdges, linkedCreds,
  };
}

function CanvasOverlay({ loading, error, nodes, load }) {
  if (loading) {
    return (
      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#404550', fontSize: 12, fontFamily: 'JetBrains Mono' }}>
        Loading graph…
      </div>
    );
  }
  if (error) {
    return (
      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: '#cc2233', fontSize: 12, fontFamily: 'JetBrains Mono' }}>
        <span>⚠ {error}</span>
        <GraphBtn onClick={load} extra={{ borderColor: '#cc233344', color: '#cc2233' }}>Retry</GraphBtn>
      </div>
    );
  }
  if (nodes.length === 0) {
    return (
      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 12 }}>
        <span style={{ fontSize: 30, opacity: 0.25 }}>◈</span>
        <span>No data — add hosts and access edges to build the graph</span>
      </div>
    );
  }
  return null;
}
CanvasOverlay.propTypes = {
  loading: PropTypes.any,
  error: PropTypes.any,
  nodes: PropTypes.any,
  load: PropTypes.any,
};

function _isPivotEdge(e) { return e.kind === 'pivot' || e.kind === 'pivot_route'; }

function _computeEdgeDimmed(e, selectedPathEdgePairs) {
  if (selectedPathEdgePairs === null) return false;
  const isOnSelected = selectedPathEdgePairs.has(`${e.from}:${e.to}`) || selectedPathEdgePairs.has(`${e.to}:${e.from}`);
  return !isOnSelected && e.kind !== 'credential';
}

function GraphSvg({ nodes, edges, arrowColors, pan, zoom, privMode, selectedNode, selectedPathEdgePairs, handleNodeMouseDown, handleNodeClick }) {
  return (
    <svg width="100%" height="100%" style={{ display: 'block' }}>
      <defs>
        {arrowColors.map(c => (
          <marker key={c} id={`arr-${c.replace('#', '')}`} markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
            <path d="M0,0 L0,7 L7,3.5 z" fill={c} opacity={0.75} />
          </marker>
        ))}
      </defs>
      <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
        {edges.map((e, i) => (
          <GraphEdge key={e.id || `edge-${i}`} edge={e} nodes={nodes} privMode={privMode} dimmed={_computeEdgeDimmed(e, selectedPathEdgePairs)} />
        ))}
        {nodes.map(n => (
          <HostNode
            key={n.id}
            node={n}
            selected={selectedNode?.id === n.id}
            privMode={privMode}
            onMouseDown={handleNodeMouseDown}
            onClick={handleNodeClick}
          />
        ))}
      </g>
    </svg>
  );
}
GraphSvg.propTypes = {
  nodes: PropTypes.any,
  edges: PropTypes.any,
  arrowColors: PropTypes.any,
  pan: PropTypes.any,
  zoom: PropTypes.any,
  privMode: PropTypes.any,
  selectedNode: PropTypes.any,
  selectedPathEdgePairs: PropTypes.any,
  handleNodeMouseDown: PropTypes.any,
  handleNodeClick: PropTypes.any,
};

function PathsPanel({ privilegePathDetails, pivotChains, nodes, selectedPathIdx, setSelectedPathIdx, setShowPathsPanel }) {
  return (
    <div style={{ width: 240, background: '#0d0f14', borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
      <div style={{ padding: '10px 12px', borderBottom: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, fontWeight: 700, color: '#e8574a', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.1em', flex: 1 }}>
          DA Paths · {privilegePathDetails.length}
        </span>
        <button onClick={() => { setSelectedPathIdx(null); setShowPathsPanel(false); }}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 13, padding: 0 }}>✕</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 0' }}>
        {privilegePathDetails.map((pathSteps, idx) => {
          const isSelected = selectedPathIdx === idx;
          return (
            <button type="button" key={`path-${pathSteps.map(s => s.label).join('-')}`} onClick={() => setSelectedPathIdx(isSelected ? null : idx)} onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                setSelectedPathIdx(isSelected ? null : idx);
              }
            }}
              style={{ margin: '3px 8px', padding: '8px 10px', borderRadius: 6, cursor: 'pointer', background: isSelected ? '#e8574a11' : 'transparent', border: `1px solid ${isSelected ? '#e8574a44' : '#1a1c22'}`, width: 'calc(100% - 16px)', textAlign: 'left', outline: 'none', color: 'inherit', font: 'inherit' }}>
              <div style={{ fontSize: 9, color: '#e8574a', fontFamily: 'JetBrains Mono', fontWeight: 700, marginBottom: 5, textTransform: 'uppercase' }}>
                Path {idx + 1} · {pathSteps.length} hops
              </div>
              {pathSteps.map((step, si) => (
                <div key={`pstep-${idx}-${si}`} style={{ display: 'flex', flexDirection: 'column', marginBottom: si < pathSteps.length - 1 ? 2 : 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    {(() => {
                      const midDotBg = si === pathSteps.length - 1 ? '#e8574a' : '#5b8af5';
                      const dotBg = si === 0 ? '#cc2233' : midDotBg;
                      return <div style={{ width: 6, height: 6, borderRadius: '50%', flexShrink: 0, background: dotBg }} />;
                    })()}
                    <span style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{step.label}</span>
                  </div>
                  {step.edge_to_next && (
                    <div style={{ marginLeft: 11, fontSize: 8, color: '#404550', fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 3, marginBottom: 2 }}>
                      <span style={{ color: '#2a2d35' }}>│</span>
                      <span style={{ color: '#e8574a', background: '#e8574a11', borderRadius: 2, padding: '0 3px' }}>{step.edge_to_next}</span>
                    </div>
                  )}
                </div>
              ))}
            </button>
          );
        })}
        {pivotChains.length > 0 && (
          <>
            <div style={{ margin: '8px 8px 4px', fontSize: 9, color: '#c07af0', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.1em' }}>
              Pivot Chains · {pivotChains.length}
            </div>
            {pivotChains.map((chain, ci) => (
              <div key={`pchain-${chain.join('-')}`} style={{ margin: '2px 8px', padding: '7px 10px', borderRadius: 6, background: '#c07af011', border: '1px solid #c07af033' }}>
                {chain.map((hid, si) => {
                  const n = nodes.find(x => x.id === hid);
                  return (
                    <div key={`pchain-${ci}-node-${si}`} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#c07af0', flexShrink: 0 }} />
                      <span style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>{n?.label || n?.ip || hid.slice(0, 10)}</span>
                      {si < chain.length - 1 && <span style={{ fontSize: 8, color: '#c07af0', marginLeft: 4 }}>→</span>}
                    </div>
                  );
                })}
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
PathsPanel.propTypes = {
  privilegePathDetails: PropTypes.any,
  pivotChains: PropTypes.any,
  nodes: PropTypes.any,
  selectedPathIdx: PropTypes.any,
  setSelectedPathIdx: PropTypes.any,
  setShowPathsPanel: PropTypes.any,
};

function ZoomControls({ zoom, setZoom, setPan }) {
  return (
    <div style={{ position: 'absolute', bottom: 14, left: 14, display: 'flex', flexDirection: 'column', gap: 3 }}>
      {[
        { lbl: '+', fn: () => setZoom(z => Math.min(4, z * 1.25)) },
        { lbl: '−', fn: () => setZoom(z => Math.max(0.15, z / 1.25)) },
        { lbl: '⟳', fn: () => { setZoom(1); setPan({ x: 0, y: 0 }); } },
      ].map(({ lbl, fn }) => (
        <button key={lbl} onClick={fn} style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 4, width: 26, height: 26, cursor: 'pointer', color: '#808590', fontSize: 13, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{lbl}</button>
      ))}
      <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono', textAlign: 'center', marginTop: 2 }}>
        {Math.round(zoom * 100)}%
      </span>
    </div>
  );
}
ZoomControls.propTypes = {
  zoom: PropTypes.any,
  setZoom: PropTypes.any,
  setPan: PropTypes.any,
};

function GraphLegend({ privMode, selectedNode }) {
  return (
    <div style={{ position: 'absolute', bottom: 14, right: selectedNode ? 298 : 14, display: 'flex', gap: 10, background: '#0d0f1499', backdropFilter: 'blur(4px)', border: '1px solid #1e2029', borderRadius: 6, padding: '5px 10px', flexWrap: 'wrap' }}>
      {[
        ['access', ACCESS_COLOR.verified],
        ['inferred', ACCESS_COLOR.inferred],
        ['domain admin', ACCESS_COLOR.domain_admin],
        ['pivot', ACCESS_COLOR.pivot],
        ['pivot route', ACCESS_COLOR.pivot_route],
        ['path', ACCESS_COLOR.path],
      ].map(([type, color]) => (
        <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <svg width={16} height={4}><rect width={16} height={2} y={1} rx={1} fill={color} /></svg>
          <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{type}</span>
        </div>
      ))}
      {privMode && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, paddingLeft: 6, borderLeft: '1px solid #2a2d35' }}>
          <svg width={12} height={12}><rect width={12} height={12} rx={3} fill="none" stroke="#e8574a" strokeWidth={2} /></svg>
          <span style={{ fontSize: 9, color: '#e8574a', fontFamily: 'JetBrains Mono' }}>DA PATH</span>
        </div>
      )}
    </div>
  );
}
GraphLegend.propTypes = {
  privMode: PropTypes.any,
  selectedNode: PropTypes.any,
};

function NodeSidePanel({ selectedNode, setSelectedNode, accent, privilegePaths, nodes, selectedNodeAccessEdges, selectedNodePivotEdges, linkedCreds, linkedFindings, pivotChains }) {
  const involvedChains = pivotChains.filter(chain => chain.includes(selectedNode.id));
  return (
    <div style={{ width: 280, margin: 10, background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
      <div style={{ padding: '12px 14px', borderBottom: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {selectedNode.label || selectedNode.hostname || selectedNode.ip || 'Node'}
          </div>
          {selectedNode.ip && (selectedNode.label || selectedNode.hostname) && (
            <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', marginTop: 1 }}>{selectedNode.ip}</div>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: STATUS_COLOR[selectedNode.status] || STATUS_COLOR.unknown }} />
          <span style={{ fontSize: 9, color: STATUS_COLOR[selectedNode.status] || STATUS_COLOR.unknown, fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{selectedNode.status || 'unknown'}</span>
        </div>
        <button onClick={() => setSelectedNode(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 14, padding: 0, marginLeft: 4 }}>✕</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '14px 14px 10px' }}>
        <NodeHostSection node={selectedNode} accent={accent} />
        <NodePrivilegeSection node={selectedNode} privilegePaths={privilegePaths} nodes={nodes} />
        <NodeAccessSection edges={selectedNodeAccessEdges} nodeId={selectedNode.id} nodes={nodes} />
        {involvedChains.length > 0 && (
          <PanelSection title="Pivot Chains" count={involvedChains.length}>
            {involvedChains.map((chain, ci) => (
              <div key={`ichain-${chain.join('-')}`} style={{ background: '#0a0c10', border: '1px solid #c07af033', borderRadius: 5, padding: '7px 9px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
                  {chain.map((hid, si) => _renderChainNode(hid, si, chain, nodes, selectedNode.id))}
                </div>
              </div>
            ))}
          </PanelSection>
        )}
        {selectedNodePivotEdges.length > 0 && (
          <PanelSection title="Pivot Routes" count={selectedNodePivotEdges.length}>
            {selectedNodePivotEdges.slice(0, 6).map(edge => {
              const isPR = edge.kind === 'pivot_route';
              const peerId = edge.from === selectedNode.id ? edge.to : edge.from;
              const peer = nodes.find(n => n.id === peerId);
              const color = ACCESS_COLOR.pivot_route;
              return (
                <div key={edge.id} style={{ background: '#0a0c10', border: `1px solid ${color}33`, borderRadius: 5, padding: '7px 9px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 8, color, background: color + '18', border: `1px solid ${color}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>
                      {isPR ? edge.route_cidr || 'route' : edge.pivot_tool || 'pivot'}
                    </span>
                    <span style={{ fontSize: 10, color: '#c8cdd6' }}>{peer?.label || peer?.ip || peerId}</span>
                  </div>
                </div>
              );
            })}
          </PanelSection>
        )}
        <PanelSection title="Credentials" count={linkedCreds.length}>
          {linkedCreds.length === 0 ? (
            <div style={{ fontSize: 10, color: '#353840', fontFamily: 'JetBrains Mono' }}>No credentials linked to this host</div>
          ) : linkedCreds.slice(0, 8).map(c => (
            <div key={c.id} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 5, padding: '7px 9px' }}>
              <div style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{c.username}</div>
              <div style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', marginTop: 2 }}>{[c.service, c.type, c.domain].filter(Boolean).join(' · ')}</div>
            </div>
          ))}
          {linkedCreds.length > 8 && <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>+{linkedCreds.length - 8} more</div>}
        </PanelSection>
        <PanelSection title="Findings" count={linkedFindings.length}>
          {linkedFindings.length === 0 ? (
            <div style={{ fontSize: 10, color: '#353840', fontFamily: 'JetBrains Mono' }}>No findings mention this host</div>
          ) : linkedFindings.slice(0, 5).map(f => (
            <div key={f.id} style={{ background: '#0a0c10', border: `1px solid ${SEV_COLOR[f.severity] || '#2a2d35'}33`, borderRadius: 5, padding: '7px 9px' }}>
              <div style={{ fontSize: 10, color: '#c8cdd6', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</div>
              <div style={{ fontSize: 8, color: SEV_COLOR[f.severity] || '#808590', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', marginTop: 2 }}>{f.severity}</div>
            </div>
          ))}
          {linkedFindings.length > 5 && <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>+{linkedFindings.length - 5} more</div>}
        </PanelSection>
      </div>
    </div>
  );
}
NodeSidePanel.propTypes = {
  selectedNode: PropTypes.any,
  setSelectedNode: PropTypes.any,
  accent: PropTypes.any,
  privilegePaths: PropTypes.any,
  nodes: PropTypes.any,
  selectedNodeAccessEdges: PropTypes.any,
  selectedNodePivotEdges: PropTypes.any,
  linkedCreds: PropTypes.any,
  linkedFindings: PropTypes.any,
  pivotChains: PropTypes.any,
};

function _startNodeDrag(e, node, nodePos, zoom, { draggingNode, dragMoved, setNodePos, selectedProject }) {
  e.stopPropagation();
  const nx = nodePos[node.id]?.x ?? node.x;
  const ny = nodePos[node.id]?.y ?? node.y;
  draggingNode.current = { nodeId: node.id, smx: e.clientX, smy: e.clientY, snx: nx, sny: ny };
  dragMoved.current = false;

  const onMove = ev => {
    const dn = draggingNode.current;
    if (!dn) return;
    const dx = (ev.clientX - dn.smx) / zoom;
    const dy = (ev.clientY - dn.smy) / zoom;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) dragMoved.current = true;
    const id = dn.nodeId;
    setNodePos(prev => ({ ...prev, [id]: { x: dn.snx + dx, y: dn.sny + dy } }));
  };
  const onUp = () => {
    if (draggingNode.current && dragMoved.current) savePos(selectedProject, { ...nodePos });
    draggingNode.current = null;
    globalThis.removeEventListener('mousemove', onMove);
    globalThis.removeEventListener('mouseup', onUp);
  };
  globalThis.addEventListener('mousemove', onMove);
  globalThis.addEventListener('mouseup', onUp);
}

function _startCanvasPan(e, pan, isPanning, panStart, setPan, draggingNode) {
  if (e.button !== 0 || draggingNode.current) return;
  isPanning.current = true;
  panStart.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };

  const onMove = ev => {
    if (!isPanning.current || !panStart.current) return;
    setPan({ x: panStart.current.px + (ev.clientX - panStart.current.x), y: panStart.current.py + (ev.clientY - panStart.current.y) });
  };
  const onUp = () => {
    isPanning.current = false;
    globalThis.removeEventListener('mousemove', onMove);
    globalThis.removeEventListener('mouseup', onUp);
  };
  globalThis.addEventListener('mousemove', onMove);
  globalThis.addEventListener('mouseup', onUp);
}

function _computeSelectedPathSets(selectedPathIdx, privilegePaths) {
  if (selectedPathIdx === null || !privilegePaths[selectedPathIdx]) return { nodeIds: null, edgePairs: null };
  const path = privilegePaths[selectedPathIdx];
  const nodeIds = new Set(path);
  const edgePairs = new Set();
  for (let i = 0; i < path.length - 1; i++) {
    edgePairs.add(`${path[i]}:${path[i + 1]}`);
    edgePairs.add(`${path[i + 1]}:${path[i]}`);
  }
  return { nodeIds, edgePairs };
}

function _loadCredsAndFindings(selectedProject, setAllCreds, setAllFindings) {
  api.getCreds(selectedProject).then(setAllCreds).catch(() => {});
  api.getFindings(selectedProject, {}).then(data => {
    setAllFindings(Array.isArray(data) ? data : data?.findings || []);
  }).catch(() => {});
}

function _computeLinkedFindings(selectedNode, allFindings) {
  if (!selectedNode) return [];
  const ip = (selectedNode.ip || '').toLowerCase();
  const hn = (selectedNode.label || selectedNode.hostname || '').toLowerCase();
  return allFindings.filter(f => {
    const t = `${f.title} ${f.description} ${f.proof}`.toLowerCase();
    return (ip && t.includes(ip)) || (hn && hn.length > 4 && t.includes(hn));
  });
}

function GraphBtn({ onClick, children, extra }) {
  return (
    <button onClick={onClick} style={{
      background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5,
      padding: '5px 10px', cursor: 'pointer', color: '#606570', fontSize: 11,
      fontFamily: 'JetBrains Mono', ...extra,
    }}>{children}</button>
  );
}
GraphBtn.propTypes = {
  onClick: PropTypes.any,
  children: PropTypes.any,
  extra: PropTypes.any,
};

// ── Main view ────────────────────────────────────────────────────────────────
export default function AttackGraphView({ selectedProject, accent }) {
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [nodePos, setNodePos] = useState({});
  const [allCreds, setAllCreds] = useState([]);
  const [allFindings, setAllFindings] = useState([]);
  const [privMode, setPrivMode] = useState(false);
  const [showPivotRoutes, setShowPivotRoutes] = useState(true);
  const [showPathsPanel, setShowPathsPanel] = useState(false);
  const [selectedPathIdx, setSelectedPathIdx] = useState(null);

  const isPanning = useRef(false);
  const panStart = useRef({ x: 0, y: 0, px: 0, py: 0 });
  const draggingNode = useRef(null);
  const dragMoved = useRef(false);

  const canvasH = 680;

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    setError('');
    try {
      const data = await api.getAttackGraph(selectedProject);
      setGraphData(data);
      setNodePos(loadPos(selectedProject));
    } catch (e) {
      setError(e.message || 'Failed to load attack graph');
    } finally {
      setLoading(false);
    }
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!selectedProject) return;
    _loadCredsAndFindings(selectedProject, setAllCreds, setAllFindings);
  }, [selectedProject]);

  const handleWheel = e => {
    e.preventDefault();
    setZoom(z => Math.max(0.15, Math.min(4, z * (e.deltaY > 0 ? 0.9 : 1.11))));
  };

  const handleNodeMouseDown = (e, node) => _startNodeDrag(e, node, nodePos, zoom, { draggingNode, dragMoved, setNodePos, selectedProject });

  const handleCanvasMouseDown = e => _startCanvasPan(e, pan, isPanning, panStart, setPan, draggingNode);

  const handleNodeClick = node => {
    if (dragMoved.current) return;
    setSelectedNode(prev => prev?.id === node.id ? null : node);
  };

  // ── Derived state ─────────────────────────────────────────────────────────
  const {
    nodes, edges, arrowColors, stats,
    privilegePaths, privilegePathDetails, pivotChains,
    selectedNodeEdges, linkedCreds,
  } = _deriveGraphState(graphData, nodePos, canvasH, showPivotRoutes, selectedNode, allCreds);

  const { edgePairs: selectedPathEdgePairs } = useMemo(
    () => _computeSelectedPathSets(selectedPathIdx, privilegePaths),
    [selectedPathIdx, privilegePaths],
  );

  const selectedNodeAccessEdges = selectedNodeEdges.filter(e => e.kind === 'access');
  const selectedNodePivotEdges = selectedNodeEdges.filter(_isPivotEdge);
  const linkedFindings = _computeLinkedFindings(selectedNode, allFindings);
  const canvasCursor = isPanning.current || draggingNode.current ? 'grabbing' : 'grab';

  const resetLayout = () => {
    setNodePos({});
    savePos(selectedProject, {});
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#090b0f' }}>

      {/* ── Header ── */}
      <GraphHeader
        graphData={graphData} stats={stats} privMode={privMode} setPrivMode={setPrivMode}
        showPathsPanel={showPathsPanel} setShowPathsPanel={setShowPathsPanel}
        privilegePaths={privilegePaths} showPivotRoutes={showPivotRoutes}
        setShowPivotRoutes={setShowPivotRoutes} resetLayout={resetLayout}
        load={load} loading={loading} accent={accent}
      />

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* ── Paths panel ── */}
        {showPathsPanel && privilegePathDetails.length > 0 && (
          <PathsPanel
            privilegePathDetails={privilegePathDetails}
            pivotChains={pivotChains}
            nodes={nodes}
            selectedPathIdx={selectedPathIdx}
            setSelectedPathIdx={setSelectedPathIdx}
            setShowPathsPanel={setShowPathsPanel}
          />
        )}

        {/* ── Canvas ── */}
        <button
          type="button"
          aria-label="Attack graph canvas"
          tabIndex={0}
          style={{
            flex: 1, overflow: 'hidden', position: 'relative',
            cursor: canvasCursor,
            userSelect: 'none',
            background: 'none', border: 'none', padding: 0,
            font: 'inherit', color: 'inherit', textAlign: 'left',
            display: 'flex', flexDirection: 'column', width: '100%',
          }}
          onWheel={handleWheel}
          onMouseDown={handleCanvasMouseDown}
          onKeyDown={e => { if (e.key === 'Tab') e.stopPropagation(); }}
          onKeyUp={() => {}}
        >
          <CanvasOverlay loading={loading} error={error} nodes={nodes} load={load} />
          {nodes.length > 0 && (
            <GraphSvg
              nodes={nodes} edges={edges} arrowColors={arrowColors}
              pan={pan} zoom={zoom} privMode={privMode} selectedNode={selectedNode}
              selectedPathEdgePairs={selectedPathEdgePairs}
              handleNodeMouseDown={handleNodeMouseDown}
              handleNodeClick={handleNodeClick}
            />
          )}
          <ZoomControls zoom={zoom} setZoom={setZoom} setPan={setPan} />
          {nodes.length > 0 && <GraphLegend privMode={privMode} selectedNode={selectedNode} />}
        </button>

        {/* ── Side panel ── */}
        {selectedNode && (
          <NodeSidePanel
            selectedNode={selectedNode}
            setSelectedNode={setSelectedNode}
            accent={accent}
            privilegePaths={privilegePaths}
            nodes={nodes}
            selectedNodeAccessEdges={selectedNodeAccessEdges}
            selectedNodePivotEdges={selectedNodePivotEdges}
            linkedCreds={linkedCreds}
            linkedFindings={linkedFindings}
            pivotChains={pivotChains}
          />
        )}
      </div>
    </div>
  );
}
AttackGraphView.propTypes = {
  selectedProject: PropTypes.any,
  accent: PropTypes.any,
};
