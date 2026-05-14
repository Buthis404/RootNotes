import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
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

// ── Node component ───────────────────────────────────────────────────────────
function HostNode({ node, selected, privMode, onMouseDown, onClick }) {
  const isAttacker = node.type === 'attacker' || node.is_attacker;
  const sc = STATUS_COLOR[node.status] || STATUS_COLOR.unknown;
  const priv = node.privilege_info || {};
  const reach = node.reachability || {};

  const isDA = priv.is_da_capable;
  const isDC = priv.is_dc;
  const onPath = privMode && priv.on_da_path;

  const borderColor = selected
    ? '#ffffff'
    : isAttacker ? '#cc2233'
    : onPath && isDA ? '#e8574a'
    : onPath ? '#e8cc42'
    : sc;

  const glowColor = onPath ? (isDA ? '#e8574a' : '#e8cc42') : null;

  const label = node.label || node.hostname || node.ip || node.id || '';
  const sublabel = node.ip && label !== node.ip ? node.ip : '';
  const osShort = node.os
    ? node.os.includes('Windows') ? 'WIN' : node.os.includes('Linux') ? 'LIN' : node.os.slice(0, 3).toUpperCase()
    : '';

  const reachBadge = reach.is_root ? null
    : reach.reachable_via_verified_path ? `v${reach.verified_distance}`
    : reach.reachable ? `r${reach.distance}`
    : null;

  const x = node.x - NODE_W / 2;
  const y = node.y - NODE_H / 2;

  return (
    <g
      transform={`translate(${x},${y})`}
      onMouseDown={e => { e.stopPropagation(); onMouseDown(e, node); }}
      onClick={() => onClick(node)}
      style={{ cursor: 'pointer' }}
    >
      {/* Privilege path glow */}
      {glowColor && (
        <rect width={NODE_W} height={NODE_H} rx={10} ry={10}
          fill="none" stroke={glowColor} strokeWidth={6} strokeOpacity={0.18} />
      )}
      {/* Selection glow */}
      {selected && (
        <rect width={NODE_W} height={NODE_H} rx={9} ry={9}
          fill="none" stroke="#ffffff" strokeWidth={3} strokeOpacity={0.15} />
      )}
      {/* Background */}
      <rect width={NODE_W} height={NODE_H} rx={8} ry={8}
        fill={isAttacker ? '#1a0a0a' : onPath && isDA ? '#1a0a06' : onPath ? '#141208' : '#0d0f14'}
        stroke={borderColor}
        strokeWidth={selected ? 2 : onPath ? 2 : 1.5}
        strokeOpacity={selected ? 1 : 0.8}
      />
      {/* Top accent strip */}
      <rect width={NODE_W} height={3} rx={2} ry={0}
        fill={borderColor} opacity={0.5} />

      {/* Status dot */}
      <circle cx={10} cy={14} r={3.5} fill={sc} />
      {/* Status label */}
      <text x={18} y={18} fontSize={8.5} fill={sc} fontFamily="JetBrains Mono" textTransform="uppercase">
        {(node.status || (isAttacker ? 'attacker' : 'unknown')).toUpperCase()}
      </text>

      {/* OS badge */}
      {osShort && (
        <text x={NODE_W - 7} y={18} fontSize={8} fill="#404550" fontFamily="JetBrains Mono" textAnchor="end">
          {osShort}
        </text>
      )}

      {/* Primary label */}
      <text x={NODE_W / 2} y={39} textAnchor="middle" fontSize={12} fontWeight={600} fill="#e4e8f0"
        fontFamily={label.match(/^\d/) ? 'JetBrains Mono' : 'Space Grotesk'}>
        {label.length > 18 ? label.slice(0, 17) + '…' : label}
      </text>

      {/* Secondary */}
      {isAttacker ? (
        <text x={NODE_W / 2} y={54} textAnchor="middle" fontSize={9} fill="#cc2233" fontFamily="JetBrains Mono" fontWeight={700}>
          ◆ ATTACKER
        </text>
      ) : sublabel ? (
        <text x={NODE_W / 2} y={54} textAnchor="middle" fontSize={9} fill="#505560" fontFamily="JetBrains Mono">
          {sublabel}
        </text>
      ) : null}

      {/* DA badge */}
      {isDA && (
        <g transform={`translate(${NODE_W - 16}, ${NODE_H - 16})`}>
          <circle r={7} fill="#e8574a" opacity={0.9} />
          <text textAnchor="middle" dominantBaseline="middle" fontSize={8} fill="#fff" fontFamily="JetBrains Mono" fontWeight={700}>
            {isDC ? 'DC' : 'DA'}
          </text>
        </g>
      )}

      {/* Reachability badge */}
      {reachBadge && (
        <g>
          <rect x={4} y={NODE_H - 14} width={reachBadge.length * 6 + 6} height={11} rx={3} fill="#1a1c22" />
          <text x={7} y={NODE_H - 6} fontSize={8} fill={reach.reachable_via_verified_path ? '#39d353' : '#5b8af5'} fontFamily="JetBrains Mono">
            {reachBadge}
          </text>
        </g>
      )}

      {/* Port count badge */}
      {!isAttacker && node.ports && node.ports.length > 0 && (
        <g>
          <rect x={NODE_W - 30} y={NODE_H - 15} width={26} height={11} rx={3} fill="#1a1c22" />
          <text x={NODE_W - 17} y={NODE_H - 7} textAnchor="middle" fontSize={8} fill="#404550" fontFamily="JetBrains Mono">
            {node.ports.length}p
          </text>
        </g>
      )}
    </g>
  );
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

  const color = isPrivPath ? '#e8574a'
    : isPivotRoute ? ACCESS_COLOR.pivot_route
    : isPivot ? ACCESS_COLOR.pivot
    : isAccess
      ? (edge.access_type === 'exploit' ? '#cc2233'
        : isDomainAdmin ? ACCESS_COLOR.domain_admin
        : (edge.access_type === 'lateral' || edge.access_type === 'pivot') ? '#e8cc42'
        : edge.access_type === 'tunnel' ? '#5b8af5'
        : edge.verified ? ACCESS_COLOR.verified : ACCESS_COLOR.inferred)
    : isPath
      ? ACCESS_COLOR.path
      : (CRED_COLOR[edge.cred_type] || CRED_COLOR.plain);

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

  const strokeDash = isPrivPath ? '10 4'
    : isPivotRoute ? '3 6'
    : isPivot ? '5 3'
    : isDomainAdmin && !edge.verified ? '6 4'
    : isAccess && !edge.verified ? '6 4'
    : isPath ? '3 5'
    : undefined;

  const strokeW = isPrivPath ? 3 : isDomainAdmin ? 2.5 : isAccess ? 2.2 : isPivot || isPivotRoute ? 1.8 : 1.5;
  const opacity = dimmed ? 0.12
    : isPrivPath ? 1
    : isPivotRoute ? 0.45
    : isAccess || isDomainAdmin ? 0.8 : 0.55;

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
      {edge.label && !isPivotRoute && (
        <>
          <rect x={lx - 28} y={ly - 9} width={56} height={12} rx={3} fill="#07080b" opacity={0.9} />
          <text x={lx} y={ly} textAnchor="middle" fontSize={8} fill={color} fontFamily="JetBrains Mono" opacity={dimmed ? 0.2 : 0.9}>
            {edge.label.slice(0, 16)}
          </text>
        </>
      )}
    </g>
  );
}

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

function InfoRow({ label, value, color }) {
  if (!value) return null;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '72px 1fr', gap: 4, fontSize: 11 }}>
      <span style={{ color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.08em', paddingTop: 1 }}>{label}</span>
      <span style={{ color: color || '#c8cdd6', fontFamily: 'JetBrains Mono', wordBreak: 'break-all' }}>{value}</span>
    </div>
  );
}

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
    api.getCreds(selectedProject).then(setAllCreds).catch(() => {});
    api.getFindings(selectedProject, {}).then(data => {
      setAllFindings(Array.isArray(data) ? data : data?.findings || []);
    }).catch(() => {});
  }, [selectedProject]);

  const handleWheel = e => {
    e.preventDefault();
    setZoom(z => Math.max(0.15, Math.min(4, z * (e.deltaY > 0 ? 0.9 : 1.11))));
  };

  const handleNodeMouseDown = (e, node) => {
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
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  const handleCanvasMouseDown = e => {
    if (e.button !== 0 || draggingNode.current) return;
    isPanning.current = true;
    panStart.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };

    const onMove = ev => {
      if (!isPanning.current || !panStart.current) return;
      setPan({ x: panStart.current.px + (ev.clientX - panStart.current.x), y: panStart.current.py + (ev.clientY - panStart.current.y) });
    };
    const onUp = () => {
      isPanning.current = false;
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  };

  const handleNodeClick = node => {
    if (dragMoved.current) return;
    setSelectedNode(prev => prev?.id === node.id ? null : node);
  };

  // ── Derived state ─────────────────────────────────────────────────────────
  const rawNodes = layoutNodes(graphData?.nodes || [], canvasH);
  const nodes = rawNodes.map(n => ({
    ...n,
    x: nodePos[n.id]?.x ?? n.x,
    y: nodePos[n.id]?.y ?? n.y,
  }));

  const allEdges = graphData?.edges || [];
  const edges = allEdges.filter(e =>
    showPivotRoutes || (e.kind !== 'pivot_route' && e.kind !== 'pivot')
  );

  const getEdgeColor = e => {
    if (e.kind === 'pivot_route') return ACCESS_COLOR.pivot_route;
    if (e.kind === 'pivot') return ACCESS_COLOR.pivot;
    if (e.kind === 'access') {
      if (e.access_type === 'exploit') return '#cc2233';
      if (e.access_type === 'domain_admin') return ACCESS_COLOR.domain_admin;
      if (e.access_type === 'lateral' || e.access_type === 'pivot') return '#e8cc42';
      if (e.access_type === 'tunnel') return '#5b8af5';
      return e.verified ? ACCESS_COLOR.verified : ACCESS_COLOR.inferred;
    }
    if (e.kind === 'path') return ACCESS_COLOR.path;
    return CRED_COLOR[e.cred_type] || CRED_COLOR.plain;
  };

  const arrowColors = [...new Set(edges.map(e => getEdgeColor(e)))];

  const stats = graphData?.stats || {};
  const privilegePaths = graphData?.privilege_paths || [];
  const privilegePathDetails = graphData?.privilege_path_details || [];
  const pivotChains = graphData?.pivot_chains || [];

  // When a specific path is selected, highlight only its nodes/edges
  const selectedPathNodeIds = useMemo(() => {
    if (selectedPathIdx === null || !privilegePaths[selectedPathIdx]) return null;
    return new Set(privilegePaths[selectedPathIdx]);
  }, [selectedPathIdx, privilegePaths]);

  const selectedPathEdgePairs = useMemo(() => {
    if (selectedPathIdx === null || !privilegePaths[selectedPathIdx]) return null;
    const path = privilegePaths[selectedPathIdx];
    const pairs = new Set();
    for (let i = 0; i < path.length - 1; i++) {
      pairs.add(`${path[i]}:${path[i + 1]}`);
      pairs.add(`${path[i + 1]}:${path[i]}`);
    }
    return pairs;
  }, [selectedPathIdx, privilegePaths]);

  const selectedNodeEdges = selectedNode
    ? allEdges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id)
    : [];
  const selectedNodeAccessEdges = selectedNodeEdges.filter(e => e.kind === 'access');
  const selectedNodePivotEdges = selectedNodeEdges.filter(e => e.kind === 'pivot' || e.kind === 'pivot_route');

  const linkedCreds = selectedNode
    ? allCreds.filter(c => (c.host_ids || []).includes(selectedNode.id))
    : [];

  const ip = (selectedNode?.ip || '').toLowerCase();
  const hn = (selectedNode?.label || selectedNode?.hostname || '').toLowerCase();
  const linkedFindings = selectedNode
    ? allFindings.filter(f => {
        const t = `${f.title} ${f.description} ${f.proof}`.toLowerCase();
        return (ip && t.includes(ip)) || (hn && hn.length > 4 && t.includes(hn));
      })
    : [];

  const resetLayout = () => {
    setNodePos({});
    savePos(selectedProject, {});
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  const btn = (onClick, children, extra = {}) => (
    <button onClick={onClick} style={{
      background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5,
      padding: '5px 10px', cursor: 'pointer', color: '#606570', fontSize: 11,
      fontFamily: 'JetBrains Mono', ...extra,
    }}>{children}</button>
  );

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#090b0f' }}>

      {/* ── Header ── */}
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
          {btn(() => { setPrivMode(v => !v); if (!privMode) setShowPathsPanel(true); }, privMode ? '● Priv Paths' : '○ Priv Paths', {
            borderColor: privMode ? '#e8574a88' : '#2a2d35',
            color: privMode ? '#e8574a' : '#606570',
            background: privMode ? '#e8574a11' : 'transparent',
          })}
          {privilegePaths.length > 0 && btn(() => setShowPathsPanel(v => !v), showPathsPanel ? '● Paths' : '○ Paths', {
            borderColor: showPathsPanel ? '#e8574a88' : '#2a2d35',
            color: showPathsPanel ? '#e8574a' : '#606570',
            background: showPathsPanel ? '#e8574a11' : 'transparent',
          })}
          {btn(() => setShowPivotRoutes(v => !v), showPivotRoutes ? '● Pivots' : '○ Pivots', {
            borderColor: showPivotRoutes ? ACCESS_COLOR.pivot_route + '88' : '#2a2d35',
            color: showPivotRoutes ? ACCESS_COLOR.pivot_route : '#606570',
            background: showPivotRoutes ? ACCESS_COLOR.pivot_route + '11' : 'transparent',
          })}
          {btn(resetLayout, 'Reset')}
          {btn(load, loading ? 'Loading…' : 'Refresh', { borderColor: accent + '44', color: accent })}
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* ── Paths panel ── */}
        {showPathsPanel && privilegePathDetails.length > 0 && (
          <div style={{
            width: 240, background: '#0d0f14', borderRight: '1px solid #1e2029',
            display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
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
                  <div key={idx}
                    onClick={() => setSelectedPathIdx(isSelected ? null : idx)}
                    style={{
                      margin: '3px 8px', padding: '8px 10px', borderRadius: 6, cursor: 'pointer',
                      background: isSelected ? '#e8574a11' : 'transparent',
                      border: `1px solid ${isSelected ? '#e8574a44' : '#1a1c22'}`,
                    }}>
                    <div style={{ fontSize: 9, color: '#e8574a', fontFamily: 'JetBrains Mono', fontWeight: 700, marginBottom: 5, textTransform: 'uppercase' }}>
                      Path {idx + 1} · {pathSteps.length} hops
                    </div>
                    {pathSteps.map((step, si) => (
                      <div key={si} style={{ display: 'flex', flexDirection: 'column', marginBottom: si < pathSteps.length - 1 ? 2 : 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                          <div style={{
                            width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                            background: si === 0 ? '#cc2233' : si === pathSteps.length - 1 ? '#e8574a' : '#5b8af5',
                          }} />
                          <span style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {step.label}
                          </span>
                        </div>
                        {step.edge_to_next && (
                          <div style={{ marginLeft: 11, fontSize: 8, color: '#404550', fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 3, marginBottom: 2 }}>
                            <span style={{ color: '#2a2d35' }}>│</span>
                            <span style={{ color: '#e8574a', background: '#e8574a11', borderRadius: 2, padding: '0 3px' }}>{step.edge_to_next}</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                );
              })}
              {pivotChains.length > 0 && (
                <>
                  <div style={{ margin: '8px 8px 4px', fontSize: 9, color: '#c07af0', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.1em' }}>
                    Pivot Chains · {pivotChains.length}
                  </div>
                  {pivotChains.map((chain, ci) => (
                    <div key={ci} style={{ margin: '2px 8px', padding: '7px 10px', borderRadius: 6, background: '#c07af011', border: '1px solid #c07af033' }}>
                      {chain.map((hid, si) => {
                        const n = nodes.find(x => x.id === hid);
                        return (
                          <div key={si} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                            <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#c07af0', flexShrink: 0 }} />
                            <span style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>
                              {n?.label || n?.ip || hid.slice(0, 10)}
                            </span>
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
        )}

        {/* ── Canvas ── */}
        <div
          style={{
            flex: 1, overflow: 'hidden', position: 'relative',
            cursor: isPanning.current ? 'grabbing' : draggingNode.current ? 'grabbing' : 'grab',
            userSelect: 'none',
          }}
          onWheel={handleWheel}
          onMouseDown={handleCanvasMouseDown}
        >
          {loading && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#404550', fontSize: 12, fontFamily: 'JetBrains Mono' }}>
              Loading graph…
            </div>
          )}
          {!loading && error && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: '#cc2233', fontSize: 12, fontFamily: 'JetBrains Mono' }}>
              <span>⚠ {error}</span>
              {btn(load, 'Retry', { borderColor: '#cc233344', color: '#cc2233' })}
            </div>
          )}
          {!loading && !error && nodes.length === 0 && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 12 }}>
              <span style={{ fontSize: 30, opacity: 0.25 }}>◈</span>
              <span>No data — add hosts and access edges to build the graph</span>
            </div>
          )}

          {nodes.length > 0 && (
            <svg width="100%" height="100%" style={{ display: 'block' }}>
              <defs>
                {arrowColors.map(c => (
                  <marker key={c} id={`arr-${c.replace('#', '')}`}
                    markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
                    <path d="M0,0 L0,7 L7,3.5 z" fill={c} opacity={0.75} />
                  </marker>
                ))}
              </defs>
              <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
                {edges.map((e, i) => {
                  const edgePairKey = `${e.from}:${e.to}`;
                  const edgePairKeyRev = `${e.to}:${e.from}`;
                  const isOnSelected = selectedPathEdgePairs
                    ? selectedPathEdgePairs.has(edgePairKey) || selectedPathEdgePairs.has(edgePairKeyRev)
                    : null;
                  const dimmed = selectedPathEdgePairs !== null && !isOnSelected && e.kind !== 'credential';
                  return <GraphEdge key={i} edge={e} nodes={nodes} privMode={privMode} dimmed={dimmed} />;
                })}
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
          )}

          {/* Zoom controls */}
          <div style={{ position: 'absolute', bottom: 14, left: 14, display: 'flex', flexDirection: 'column', gap: 3 }}>
            {[
              { lbl: '+', fn: () => setZoom(z => Math.min(4, z * 1.25)) },
              { lbl: '−', fn: () => setZoom(z => Math.max(0.15, z / 1.25)) },
              { lbl: '⟳', fn: () => { setZoom(1); setPan({ x: 0, y: 0 }); } },
            ].map(({ lbl, fn }) => (
              <button key={lbl} onClick={fn} style={{
                background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 4,
                width: 26, height: 26, cursor: 'pointer', color: '#808590', fontSize: 13,
                fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>{lbl}</button>
            ))}
            <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono', textAlign: 'center', marginTop: 2 }}>
              {Math.round(zoom * 100)}%
            </span>
          </div>

          {/* Legend */}
          {nodes.length > 0 && (
            <div style={{
              position: 'absolute', bottom: 14, right: selectedNode ? 298 : 14,
              display: 'flex', gap: 10, background: '#0d0f1499', backdropFilter: 'blur(4px)',
              border: '1px solid #1e2029', borderRadius: 6, padding: '5px 10px', flexWrap: 'wrap',
            }}>
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
          )}
        </div>

        {/* ── Side panel ── */}
        {selectedNode && (
          <div style={{
            width: 280, margin: 10, background: '#0d0f14', border: '1px solid #1e2029',
            borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
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
                <span style={{ fontSize: 9, color: STATUS_COLOR[selectedNode.status] || STATUS_COLOR.unknown, fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>
                  {selectedNode.status || 'unknown'}
                </span>
              </div>
              <button onClick={() => setSelectedNode(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#404550', fontSize: 14, padding: 0, marginLeft: 4 }}>✕</button>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: '14px 14px 10px' }}>

              <PanelSection title="Host">
                <InfoRow label="Role" value={selectedNode.role} />
                <InfoRow label="Zone" value={selectedNode.zone_type} />
                <InfoRow label="OS" value={selectedNode.os} />
                <InfoRow label="IP" value={selectedNode.ip} />
                {selectedNode.reachability?.is_root && <InfoRow label="Reach" value="attacker root" color="#cc2233" />}
                {!selectedNode.reachability?.is_root && selectedNode.reachability?.reachable && (
                  <InfoRow label="Reach"
                    color={selectedNode.reachability?.reachable_via_verified_path ? '#39d353' : '#5b8af5'}
                    value={selectedNode.reachability?.reachable_via_verified_path
                      ? `verified path · ${selectedNode.reachability?.verified_distance} hop`
                      : `reachable · ${selectedNode.reachability?.distance} hop`} />
                )}
                {!selectedNode.reachability?.is_root && !selectedNode.reachability?.reachable && (
                  <InfoRow label="Reach" value="unreachable" color="#404550" />
                )}
                {selectedNode.tags?.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 2 }}>
                    {selectedNode.tags.map(t => (
                      <span key={t} style={{ fontSize: 9, background: accent + '1a', border: `1px solid ${accent}33`, borderRadius: 3, padding: '1px 5px', color: accent, fontFamily: 'JetBrains Mono' }}>{t}</span>
                    ))}
                  </div>
                )}
                {selectedNode.ports?.length > 0 && (
                  <div style={{ marginTop: 4 }}>
                    <div style={{ fontSize: 9, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Ports</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                      {selectedNode.ports.slice(0, 20).map((p, i) => (
                        <span key={i} style={{ fontSize: 9, background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 3, padding: '1px 5px', color: '#606570', fontFamily: 'JetBrains Mono' }}>
                          {typeof p === 'object' ? (p.port || p.number || p.portid) : p}
                        </span>
                      ))}
                      {selectedNode.ports.length > 20 && <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>+{selectedNode.ports.length - 20}</span>}
                    </div>
                  </div>
                )}
              </PanelSection>

              {/* Privilege info */}
              {(selectedNode.privilege_info?.is_da_capable || selectedNode.privilege_info?.on_da_path) && (
                <PanelSection title="Privilege">
                  {selectedNode.privilege_info?.is_dc && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', background: '#e8574a11', border: '1px solid #e8574a44', borderRadius: 5 }}>
                      <span style={{ fontSize: 10, color: '#e8574a', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>◆ Domain Controller</span>
                    </div>
                  )}
                  {selectedNode.privilege_info?.is_da_capable && !selectedNode.privilege_info?.is_dc && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', background: '#e8574a11', border: '1px solid #e8574a44', borderRadius: 5 }}>
                      <span style={{ fontSize: 10, color: '#e8574a', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>◆ Domain Admin target</span>
                    </div>
                  )}
                  {selectedNode.privilege_info?.on_da_path && !selectedNode.privilege_info?.is_da_capable && (
                    <InfoRow label="DA Path" value={`step ${(selectedNode.privilege_info?.da_path_distance ?? 0) + 1} of privilege chain`} color="#e8cc42" />
                  )}
                  {privilegePaths.length > 0 && selectedNode.privilege_info?.is_da_capable && (
                    <div style={{ marginTop: 4 }}>
                      {privilegePaths.filter(p => p[p.length - 1] === selectedNode.id).map((path, i) => {
                        const pathNodes = path.map(id => nodes.find(n => n.id === id));
                        return (
                          <div key={i} style={{ fontSize: 9, color: '#808590', fontFamily: 'JetBrains Mono', marginBottom: 3 }}>
                            {pathNodes.map(n => n?.label || n?.ip || '?').join(' → ')}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </PanelSection>
              )}

              <PanelSection title="Access" count={selectedNodeAccessEdges.length}>
                {selectedNodeAccessEdges.length === 0 ? (
                  <div style={{ fontSize: 10, color: '#353840', fontFamily: 'JetBrains Mono' }}>No access edges for this host</div>
                ) : selectedNodeAccessEdges.slice(0, 8).map(edge => {
                  const peerId = edge.from === selectedNode.id ? edge.to : edge.from;
                  const peer = nodes.find(n => n.id === peerId);
                  const outgoing = edge.from === selectedNode.id;
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
                {selectedNodeAccessEdges.length > 8 && (
                  <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>+{selectedNodeAccessEdges.length - 8} more</div>
                )}
              </PanelSection>

              {/* Pivot chains involving this host */}
              {(() => {
                const involvedChains = pivotChains.filter(chain => chain.includes(selectedNode.id));
                if (involvedChains.length === 0) return null;
                return (
                  <PanelSection title="Pivot Chains" count={involvedChains.length}>
                    {involvedChains.map((chain, ci) => (
                      <div key={ci} style={{ background: '#0a0c10', border: '1px solid #c07af033', borderRadius: 5, padding: '7px 9px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
                          {chain.map((hid, si) => {
                            const n = nodes.find(x => x.id === hid);
                            const isSelf = hid === selectedNode.id;
                            return (
                              <React.Fragment key={si}>
                                <span style={{ fontSize: 9, color: isSelf ? '#c07af0' : '#808590', fontFamily: 'JetBrains Mono', fontWeight: isSelf ? 700 : 400 }}>
                                  {n?.label || n?.ip || hid.slice(0, 10)}
                                </span>
                                {si < chain.length - 1 && <span style={{ fontSize: 9, color: '#c07af066' }}>→</span>}
                              </React.Fragment>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </PanelSection>
                );
              })()}

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
                    <div style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', marginTop: 2 }}>
                      {[c.service, c.type, c.domain].filter(Boolean).join(' · ')}
                    </div>
                  </div>
                ))}
                {linkedCreds.length > 8 && (
                  <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>+{linkedCreds.length - 8} more</div>
                )}
              </PanelSection>

              <PanelSection title="Findings" count={linkedFindings.length}>
                {linkedFindings.length === 0 ? (
                  <div style={{ fontSize: 10, color: '#353840', fontFamily: 'JetBrains Mono' }}>No findings mention this host</div>
                ) : linkedFindings.slice(0, 5).map(f => (
                  <div key={f.id} style={{
                    background: '#0a0c10', border: `1px solid ${SEV_COLOR[f.severity] || '#2a2d35'}33`,
                    borderRadius: 5, padding: '7px 9px',
                  }}>
                    <div style={{ fontSize: 10, color: '#c8cdd6', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</div>
                    <div style={{ fontSize: 8, color: SEV_COLOR[f.severity] || '#808590', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', marginTop: 2 }}>{f.severity}</div>
                  </div>
                ))}
                {linkedFindings.length > 5 && (
                  <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>+{linkedFindings.length - 5} more</div>
                )}
              </PanelSection>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
