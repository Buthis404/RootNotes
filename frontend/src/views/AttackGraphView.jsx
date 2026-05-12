import React, { useState, useEffect, useCallback, useRef } from 'react';
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
function HostNode({ node, selected, onMouseDown, onClick }) {
  const isAttacker = node.type === 'attacker' || node.is_attacker;
  const sc = STATUS_COLOR[node.status] || STATUS_COLOR.unknown;
  const borderColor = selected ? '#ffffff' : isAttacker ? '#cc2233' : sc;
  const label = node.label || node.hostname || node.ip || node.id || '';
  const sublabel = node.ip && label !== node.ip ? node.ip : '';
  const osShort = node.os
    ? node.os.includes('Windows') ? 'WIN' : node.os.includes('Linux') ? 'LIN' : node.os.slice(0, 3).toUpperCase()
    : '';

  const x = node.x - NODE_W / 2;
  const y = node.y - NODE_H / 2;

  return (
    <g
      transform={`translate(${x},${y})`}
      onMouseDown={e => { e.stopPropagation(); onMouseDown(e, node); }}
      onClick={() => onClick(node)}
      style={{ cursor: 'pointer' }}
    >
      {/* Selection glow */}
      {selected && (
        <rect width={NODE_W} height={NODE_H} rx={9} ry={9}
          fill="none" stroke="#ffffff" strokeWidth={3} strokeOpacity={0.15} />
      )}
      {/* Background */}
      <rect width={NODE_W} height={NODE_H} rx={8} ry={8}
        fill={isAttacker ? '#1a0a0a' : '#0d0f14'}
        stroke={borderColor}
        strokeWidth={selected ? 2 : 1.5}
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

      {/* Secondary (IP or ATTACKER badge) */}
      {isAttacker ? (
        <text x={NODE_W / 2} y={54} textAnchor="middle" fontSize={9} fill="#cc2233" fontFamily="JetBrains Mono" fontWeight={700}>
          ◆ ATTACKER
        </text>
      ) : sublabel ? (
        <text x={NODE_W / 2} y={54} textAnchor="middle" fontSize={9} fill="#505560" fontFamily="JetBrains Mono">
          {sublabel}
        </text>
      ) : null}

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
function GraphEdge({ edge, nodes }) {
  const src = nodes.find(n => n.id === (edge.source || edge.from));
  const tgt = nodes.find(n => n.id === (edge.target || edge.to));
  if (!src || !tgt || src === tgt) return null;

  const isAccess = edge.kind === 'access';
  const isPath = edge.kind === 'path';
  const color = isAccess
    ? (edge.verified ? ACCESS_COLOR.verified : ACCESS_COLOR.inferred)
    : isPath
      ? ACCESS_COLOR.path
      : (CRED_COLOR[edge.cred_type] || CRED_COLOR.plain);
  const markerId = `arr-${color.replace('#', '')}`;

  // Connect right of src to left of tgt (or left-to-right, depending on position)
  const goRight = tgt.x >= src.x;
  const sx = src.x + (goRight ? NODE_W / 2 : -NODE_W / 2);
  const sy = src.y;
  const tx = tgt.x + (goRight ? -NODE_W / 2 : NODE_W / 2);
  const ty = tgt.y;

  // Bezier control point
  const mx = (sx + tx) / 2;
  const my = (sy + ty) / 2 - Math.abs(tx - sx) * 0.18;

  const d = `M ${sx} ${sy} Q ${mx} ${my} ${tx} ${ty}`;

  // Label midpoint (on bezier)
  const t = 0.5;
  const lx = (1 - t) ** 2 * sx + 2 * (1 - t) * t * mx + t ** 2 * tx;
  const ly = (1 - t) ** 2 * sy + 2 * (1 - t) * t * my + t ** 2 * ty - 6;

  return (
    <g>
      <path d={d} fill="none" stroke={color} strokeWidth={isAccess ? 2.2 : 1.5} strokeOpacity={isAccess ? 0.8 : 0.55}
        strokeDasharray={isAccess && !edge.verified ? '6 4' : isPath ? '3 5' : undefined}
        markerEnd={`url(#${markerId})`} />
      {edge.label && (
        <>
          <rect x={lx - 28} y={ly - 9} width={56} height={12} rx={3} fill="#07080b" opacity={0.9} />
          <text x={lx} y={ly} textAnchor="middle" fontSize={8} fill={color} fontFamily="JetBrains Mono" opacity={0.9}>
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

function InfoRow({ label, value }) {
  if (!value) return null;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '72px 1fr', gap: 4, fontSize: 11 }}>
      <span style={{ color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.08em', paddingTop: 1 }}>{label}</span>
      <span style={{ color: '#c8cdd6', fontFamily: 'JetBrains Mono', wordBreak: 'break-all' }}>{value}</span>
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

  const isPanning = useRef(false);
  const panStart = useRef({ x: 0, y: 0, px: 0, py: 0 });
  const draggingNode = useRef(null);  // { nodeId, startMouseX, startMouseY, startNodeX, startNodeY }
  const dragMoved = useRef(false);

  const canvasH = 680;

  // ── Data loading ──────────────────────────────────────────────────────────
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

  // ── Canvas interactions ───────────────────────────────────────────────────
  const handleWheel = e => {
    e.preventDefault();
    setZoom(z => Math.max(0.15, Math.min(4, z * (e.deltaY > 0 ? 0.9 : 1.11))));
  };

  const handleCanvasMouseDown = e => {
    if (e.button !== 0 || draggingNode.current) return;
    isPanning.current = true;
    panStart.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };
  };

  const handleNodeMouseDown = (e, node) => {
    e.stopPropagation();
    const nx = nodePos[node.id]?.x ?? node.x;
    const ny = nodePos[node.id]?.y ?? node.y;
    draggingNode.current = { nodeId: node.id, smx: e.clientX, smy: e.clientY, snx: nx, sny: ny };
    dragMoved.current = false;
  };

  const handleMouseMove = e => {
    if (draggingNode.current) {
      const dx = (e.clientX - draggingNode.current.smx) / zoom;
      const dy = (e.clientY - draggingNode.current.smy) / zoom;
      if (Math.abs(dx) > 3 || Math.abs(dy) > 3) dragMoved.current = true;
      setNodePos(prev => ({
        ...prev,
        [draggingNode.current.nodeId]: {
          x: draggingNode.current.snx + dx,
          y: draggingNode.current.sny + dy,
        },
      }));
    } else if (isPanning.current) {
      setPan({
        x: panStart.current.px + (e.clientX - panStart.current.x),
        y: panStart.current.py + (e.clientY - panStart.current.y),
      });
    }
  };

  const handleMouseUp = () => {
    if (draggingNode.current && dragMoved.current) {
      savePos(selectedProject, { ...nodePos });
    }
    draggingNode.current = null;
    isPanning.current = false;
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
  const edges = graphData?.edges || [];
  const arrowColors = [...new Set(edges.map(e => {
    if (e.kind === 'access') return e.verified ? ACCESS_COLOR.verified : ACCESS_COLOR.inferred;
    if (e.kind === 'path') return ACCESS_COLOR.path;
    return CRED_COLOR[e.cred_type] || CRED_COLOR.plain;
  }))];

  const stats = {
    hosts: nodes.length,
    edges: edges.length,
    compromised: nodes.filter(n => n.status === 'pwned' || n.status === 'owned').length,
    access: graphData?.stats?.access_edges || 0,
    verifiedAccess: graphData?.stats?.verified_access_edges || 0,
    creds: graphData?.stats?.credential_edges || 0,
  };

  const selectedNodeEdges = selectedNode
    ? edges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id)
    : [];
  const selectedNodeAccessEdges = selectedNodeEdges.filter(e => e.kind === 'access');

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

  // ── Reset layout ──────────────────────────────────────────────────────────
  const resetLayout = () => {
    setNodePos({});
    savePos(selectedProject, {});
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  // ── Render ────────────────────────────────────────────────────────────────
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
      <div style={{ padding: '10px 18px', borderBottom: '1px solid #1a1c22', display: 'flex', alignItems: 'center', gap: 18, flexShrink: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', flex: 1 }}>
          Attack Graph
        </div>
        {graphData && <>
          {[
            { label: 'hosts', val: stats.hosts, c: '#c8cdd6' },
            { label: 'connections', val: stats.edges, c: '#c8cdd6' },
            { label: 'access', val: stats.access, c: ACCESS_COLOR.verified },
            { label: 'verified', val: stats.verifiedAccess, c: ACCESS_COLOR.inferred },
            { label: 'cred links', val: stats.creds, c: '#c07af0' },
            { label: 'compromised', val: stats.compromised, c: '#f09a3a' },
          ].map(({ label, val, c }) => (
            <span key={label} style={{ fontSize: 11, color: '#505560', fontFamily: 'JetBrains Mono' }}>
              <span style={{ color: c }}>{val}</span> {label}
            </span>
          ))}
        </>}
        {btn(resetLayout, 'Reset layout')}
        {btn(load, loading ? 'Loading…' : 'Refresh', { borderColor: accent + '44', color: accent })}
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* ── Canvas ── */}
        <div
          style={{
            flex: 1, overflow: 'hidden', position: 'relative',
            cursor: isPanning.current ? 'grabbing' : draggingNode.current ? 'grabbing' : 'grab',
            userSelect: 'none',
          }}
          onWheel={handleWheel}
          onMouseDown={handleCanvasMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          {/* States */}
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

          {/* SVG canvas */}
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
                {/* Edges first */}
                {edges.map((e, i) => <GraphEdge key={i} edge={e} nodes={nodes} />)}
                {/* Nodes on top */}
                {nodes.map(n => (
                  <HostNode
                    key={n.id}
                    node={n}
                    selected={selectedNode?.id === n.id}
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

          {/* Graph legend */}
          {nodes.length > 0 && (
            <div style={{
              position: 'absolute', bottom: 14, right: selectedNode ? 298 : 14,
              display: 'flex', gap: 10, background: '#0d0f1499', backdropFilter: 'blur(4px)',
              border: '1px solid #1e2029', borderRadius: 6, padding: '5px 10px',
            }}>
              {[
                ['access', ACCESS_COLOR.verified],
                ['inferred', ACCESS_COLOR.inferred],
                ['path', ACCESS_COLOR.path],
                ['rN = reachable', '#5b8af5'],
                ['vN = verified path', '#39d353'],
              ].map(([type, color]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <svg width={16} height={4}><rect width={16} height={2} y={1} rx={1} fill={color} /></svg>
                  <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{type}</span>
                </div>
              ))}
              {Object.entries(CRED_COLOR).map(([type, color]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <svg width={16} height={4}><rect width={16} height={2} y={1} rx={1} fill={color} /></svg>
                  <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{type}</span>
                </div>
              ))}
              <span style={{ fontSize: 9, color: '#2a2d35', fontFamily: 'JetBrains Mono', marginLeft: 4 }}>drag nodes to reposition</span>
            </div>
          )}
        </div>

        {/* ── Side panel ── */}
        {selectedNode && (
          <div style={{
            width: 280, margin: 10, background: '#0d0f14', border: '1px solid #1e2029',
            borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
            {/* Panel header */}
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

            {/* Panel body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '14px 14px 10px' }}>

              {/* Host details */}
              <PanelSection title="Host">
                <InfoRow label="Role" value={selectedNode.role} />
                <InfoRow label="Zone" value={selectedNode.zone_type} />
                <InfoRow label="OS" value={selectedNode.os} />
                <InfoRow label="Hostname" value={selectedNode.label || selectedNode.hostname} />
                <InfoRow label="IP" value={selectedNode.ip} />
                {selectedNode.reachability?.is_root && <InfoRow label="Reach" value="attacker root" />}
                {!selectedNode.reachability?.is_root && selectedNode.reachability?.reachable && (
                  <InfoRow label="Reach" value={selectedNode.reachability?.reachable_via_verified_path
                    ? `verified path (${selectedNode.reachability?.verified_distance} hop)`
                    : `reachable (${selectedNode.reachability?.distance} hop)`} />
                )}
                {!selectedNode.reachability?.is_root && !selectedNode.reachability?.reachable && (
                  <InfoRow label="Reach" value="unreachable from attacker" />
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
                        {edge.state && <span style={{ fontSize: 8, color: '#5b8af5', background: '#5b8af518', border: '1px solid #5b8af533', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{edge.state}</span>}
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

              {/* Linked credentials */}
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

              {/* Linked findings */}
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
