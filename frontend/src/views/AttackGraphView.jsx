import React, { useState, useEffect, useCallback, useRef } from 'react';
import { api } from '../api.js';

const EDGE_COLORS = {
  plain: '#39d353',
  hash:  '#c07af0',
  ntlm:  '#c07af0',
  key:   '#5b8af5',
};

function getEdgeColor(credType) {
  return EDGE_COLORS[credType] || EDGE_COLORS.plain;
}

function NodeCircle({ node, selected, onClick }) {
  let fill, r;
  if (node.type === 'attacker') {
    fill = '#cc2233'; r = 22;
  } else if (node.status === 'pwned' || node.status === 'owned') {
    fill = '#f09a3a'; r = 18;
  } else {
    fill = '#5b8af5'; r = 14;
  }

  const statusColors = {
    unknown: '#404550', alive: '#5b8af5', scanned: '#c07af0',
    access: '#f09a3a', pwned: '#cc2233', owned: '#39d353',
  };
  const dotColor = statusColors[node.status] || '#404550';

  const label = node.hostname || node.ip || node.id || '';
  const maxLabel = label.length > 14 ? label.slice(0, 13) + '…' : label;

  return (
    <g
      transform={`translate(${node.x},${node.y})`}
      onClick={() => onClick(node)}
      style={{ cursor: 'pointer' }}
    >
      <circle r={r + 4} fill={selected ? '#ffffff10' : 'transparent'} />
      <circle
        r={r}
        fill={fill + '22'}
        stroke={selected ? '#fff' : fill}
        strokeWidth={selected ? 2 : 1.5}
      />
      {node.type === 'attacker' && (
        <text textAnchor="middle" dominantBaseline="middle" fontSize={11} fill="#fff" fontFamily="JetBrains Mono" fontWeight="bold">
          ATK
        </text>
      )}
      {/* Status dot */}
      <circle cx={r - 4} cy={-(r - 4)} r={4} fill={dotColor} />
      {/* Label */}
      <text
        y={r + 13}
        textAnchor="middle"
        fontSize={9}
        fill="#808590"
        fontFamily="JetBrains Mono"
      >
        {maxLabel}
      </text>
    </g>
  );
}

function EdgePath({ edge, nodes, color }) {
  const src = nodes.find(n => n.id === edge.source);
  const tgt = nodes.find(n => n.id === edge.target);
  if (!src || !tgt) return null;

  const dx = tgt.x - src.x;
  const dy = tgt.y - src.y;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;

  // Control point for curve
  const cx = (src.x + tgt.x) / 2 - dy * 0.2;
  const cy = (src.y + tgt.y) / 2 + dx * 0.2;

  const d = `M ${src.x} ${src.y} Q ${cx} ${cy} ${tgt.x} ${tgt.y}`;

  // Label midpoint approx
  const lx = (src.x + 2 * cx + tgt.x) / 4;
  const ly = (src.y + 2 * cy + tgt.y) / 4 - 6;

  return (
    <g>
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} strokeOpacity={0.7} markerEnd={`url(#arrow-${color.replace('#', '')})`} />
      {edge.label && (
        <text x={lx} y={ly} textAnchor="middle" fontSize={8} fill={color} fontFamily="JetBrains Mono" opacity={0.8}>
          {edge.label}
        </text>
      )}
    </g>
  );
}

function layoutNodes(raw = [], canvasH = 600) {
  const nodes = [...raw];
  const attackerIdx = nodes.findIndex(n => n.type === 'attacker' || n.is_attacker);
  if (attackerIdx >= 0) {
    nodes[attackerIdx] = { ...nodes[attackerIdx], x: 100, y: canvasH / 2, type: 'attacker' };
  }
  let idx = 0;
  nodes.forEach((n, i) => {
    if (i === attackerIdx) return;
    const col = Math.floor(idx / 3);
    const row = idx % 3;
    n.x = 280 + col * 160;
    n.y = 80 + row * 160;
    idx++;
  });
  return nodes;
}

export default function AttackGraphView({ selectedProject, accent }) {
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const svgRef = useRef(null);
  const dragging = useRef(false);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });

  const canvasW = 1400;
  const canvasH = 600;

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    setError('');
    try {
      const data = await api.getAttackGraph(selectedProject);
      setGraphData(data);
    } catch (e) {
      setError(e.message || 'Failed to load attack graph');
    } finally {
      setLoading(false);
    }
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  const handleWheel = (e) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(z => Math.max(0.2, Math.min(3, z * delta)));
  };

  const handleMouseDown = (e) => {
    if (e.button !== 0) return;
    dragging.current = true;
    dragStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y };
  };

  const handleMouseMove = (e) => {
    if (!dragging.current) return;
    setPan({
      x: dragStart.current.panX + (e.clientX - dragStart.current.x),
      y: dragStart.current.panY + (e.clientY - dragStart.current.y),
    });
  };

  const handleMouseUp = () => { dragging.current = false; };

  const nodes = layoutNodes(graphData?.nodes || graphData?.hosts || [], canvasH);
  const edges = graphData?.edges || graphData?.connections || [];

  const totalHosts = nodes.length;
  const compromised = nodes.filter(n => n.status === 'pwned' || n.status === 'owned').length;
  const totalEdges = edges.length;

  // Collect unique arrow colors
  const arrowColors = [...new Set(edges.map(e => getEdgeColor(e.cred_type || e.type)))];

  const card = { background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10 };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#090b0f' }}>
      {/* Stats bar */}
      <div style={{ padding: '10px 20px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 20, flexShrink: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', flex: 1 }}>Attack Graph</div>
        {graphData && (
          <>
            <span style={{ fontSize: 12, color: '#606570', fontFamily: 'JetBrains Mono' }}>
              <span style={{ color: '#c8cdd6' }}>{totalHosts}</span> hosts
            </span>
            <span style={{ fontSize: 12, color: '#606570', fontFamily: 'JetBrains Mono' }}>
              <span style={{ color: '#c8cdd6' }}>{totalEdges}</span> connections
            </span>
            <span style={{ fontSize: 12, color: '#606570', fontFamily: 'JetBrains Mono' }}>
              <span style={{ color: '#f09a3a' }}>{compromised}</span> compromised
            </span>
          </>
        )}
        <button
          onClick={load}
          disabled={loading}
          style={{ background: 'transparent', border: `1px solid ${accent}44`, borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: 'JetBrains Mono' }}
        >
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* SVG canvas */}
        <div
          style={{ flex: 1, overflow: 'hidden', cursor: dragging.current ? 'grabbing' : 'grab', position: 'relative' }}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          {loading && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#404550', fontSize: 13, fontFamily: 'JetBrains Mono' }}>
              Loading graph…
            </div>
          )}
          {error && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#cc2233', fontSize: 13, fontFamily: 'JetBrains Mono', flexDirection: 'column', gap: 8 }}>
              <span>⚠ {error}</span>
              <button onClick={load} style={{ background: 'transparent', border: '1px solid #cc233344', borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: '#cc2233', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Retry</button>
            </div>
          )}
          {!loading && !error && nodes.length === 0 && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 13 }}>
              <span style={{ fontSize: 32, opacity: 0.3 }}>◈</span>
              <span>No data — add hosts with credentials to build graph</span>
            </div>
          )}
          {nodes.length > 0 && (
            <svg
              ref={svgRef}
              width="100%"
              height="100%"
              style={{ display: 'block' }}
            >
              <defs>
                {arrowColors.map(c => (
                  <marker key={c} id={`arrow-${c.replace('#', '')}`} markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L8,3 z" fill={c} />
                  </marker>
                ))}
              </defs>
              <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
                {edges.map((e, i) => (
                  <EdgePath key={i} edge={e} nodes={nodes} color={getEdgeColor(e.cred_type || e.type)} />
                ))}
                {nodes.map(n => (
                  <NodeCircle
                    key={n.id}
                    node={n}
                    selected={selectedNode?.id === n.id}
                    onClick={setSelectedNode}
                  />
                ))}
              </g>
            </svg>
          )}
        </div>

        {/* Side panel */}
        {selectedNode && (
          <div style={{ ...card, width: 260, margin: 12, padding: '14px 16px', flexShrink: 0, overflowY: 'auto', fontSize: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Host details</div>
              <button
                onClick={() => setSelectedNode(null)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#606570', fontSize: 16 }}
              >✕</button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontFamily: 'JetBrains Mono' }}>
              {[
                ['IP', selectedNode.ip],
                ['Hostname', selectedNode.hostname],
                ['Status', selectedNode.status],
                ['OS', selectedNode.os],
              ].map(([k, v]) => v ? (
                <div key={k}>
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 2 }}>{k}</div>
                  <div style={{ color: '#c8cdd6', fontSize: 11 }}>{v}</div>
                </div>
              ) : null)}
              {selectedNode.tags && selectedNode.tags.length > 0 && (
                <div>
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Tags</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {selectedNode.tags.map(t => (
                      <span key={t} style={{ fontSize: 10, background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 3, padding: '2px 6px', color: accent }}>{t}</span>
                    ))}
                  </div>
                </div>
              )}
              {selectedNode.ports && selectedNode.ports.length > 0 && (
                <div>
                  <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Ports</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                    {selectedNode.ports.slice(0, 20).map((p, i) => (
                      <span key={i} style={{ fontSize: 9, background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 5px', color: '#808590', fontFamily: 'JetBrains Mono' }}>
                        {typeof p === 'object' ? p.port || p.number : p}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Zoom controls */}
      <div style={{ position: 'absolute', bottom: 16, left: 80, display: 'flex', gap: 4 }}>
        {[
          { label: '+', fn: () => setZoom(z => Math.min(3, z * 1.2)) },
          { label: '-', fn: () => setZoom(z => Math.max(0.2, z / 1.2)) },
          { label: '⟳', fn: () => { setZoom(1); setPan({ x: 0, y: 0 }); } },
        ].map(({ label, fn }) => (
          <button key={label} onClick={fn}
            style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 4, width: 28, height: 28, cursor: 'pointer', color: '#808590', fontSize: 14, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {label}
          </button>
        ))}
        <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', alignSelf: 'center', marginLeft: 4 }}>
          {Math.round(zoom * 100)}%
        </span>
      </div>
    </div>
  );
}
