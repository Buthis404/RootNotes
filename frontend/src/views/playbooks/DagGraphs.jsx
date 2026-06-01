/**
 * DAG graph visualizations for playbooks — static preview + live status.
 *
 * Extracted from PlaybooksView.jsx.
 */
import { useState } from 'react';
import PropTypes from 'prop-types';

function _failColor(failStop, failContinue) {
  if (failStop) return '#606570';
  if (failContinue) return '#f09a3a';
  return '#cc2233';
}

function _failBg(failStop, failContinue) {
  if (failStop) return '#60657012';
  if (failContinue) return '#f09a3a12';
  return '#cc223312';
}

function _failBorder(failStop, failContinue) {
  if (failStop) return '#60657030';
  if (failContinue) return '#f09a3a30';
  return '#cc223330';
}

// ── Layout engine ────────────────────────────────────────────────────

export function computeDagLayout(steps) {
  const n = steps.length;
  const deps = steps.map(s => (s.depends_on || []).map(Number).filter(d => d >= 1 && d <= n).map(d => d - 1));
  const hasAnyDep = deps.some(d => d.length > 0);
  const layer = new Array(n).fill(0);
  if (hasAnyDep) {
    for (let i = 0; i < n; i++) {
      if (deps[i].length === 0) {
        layer[i] = 0;
      } else {
        layer[i] = Math.max(...deps[i].map(d => layer[d])) + 1;
      }
    }
  } else {
    for (let i = 0; i < n; i++) layer[i] = i;
  }
  const byLayer = {};
  for (let i = 0; i < n; i++) {
    const layerIdx = layer[i];
    if (!byLayer[layerIdx]) byLayer[layerIdx] = [];
    byLayer[layerIdx].push(i);
  }
  return { layer, deps, byLayer, dagMode: hasAnyDep };
}

// ── Step flow diagram (vertical spine) ──────────────────────────────

export function StepFlowDiagram({ steps, accent }) {
  if (!steps || steps.length === 0) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {steps.map((step, idx) => {
        const failStop = step.on_failure === 'stop';
        const failContinue = step.on_failure === 'continue' || step.on_failure === 'next';
        const isLast = idx === steps.length - 1;
        return (
          <div key={`step-${step.id || idx}`} style={{ display: 'flex', gap: 0 }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 36, flexShrink: 0 }}>
              <div style={{ width: 28, height: 28, borderRadius: '50%', background: '#13161f', border: `1.5px solid ${accent}44`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: accent, fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 700, zIndex: 1 }}>{idx + 1}</div>
              {!isLast && <div style={{ width: 2, flex: 1, minHeight: 16, background: `${accent}22` }} />}
            </div>
            <div style={{ flex: 1, paddingBottom: isLast ? 0 : 8, paddingLeft: 10, minWidth: 0 }}>
              <div style={{ fontSize: 11, color: '#d9deea', fontWeight: 600, marginBottom: 2, paddingTop: 4 }}>{step.title || `${step.connector_key}:${step.operation}`}</div>
              <div style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginBottom: 4 }}>{step.connector_key}:{step.operation}</div>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 9, color: '#39d353', background: '#39d35312', border: '1px solid #39d35330', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>
                  ✓ {step.on_success || 'next'}{step.on_success === 'jump' ? ` → step ${step.on_success_step}` : ''}
                </span>
                <span style={{ fontSize: 9, color: _failColor(failStop, failContinue), background: _failBg(failStop, failContinue), border: `1px solid ${_failBorder(failStop, failContinue)}`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>
                  ✕ {step.on_failure || 'stop'}{step.on_failure === 'jump' ? ` → step ${step.on_failure_step}` : ''}
                </span>
                {(step.result_conditions || []).length > 0 && (
                  <span style={{ fontSize: 9, color: '#6fc8f0', background: '#6fc8f012', border: '1px solid #6fc8f030', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>
                    {step.result_conditions.length} condition{step.result_conditions.length > 1 ? 's' : ''}
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

StepFlowDiagram.propTypes = {
  steps: PropTypes.array,
  accent: PropTypes.string,
};

// ── DagPreview (static editor preview) ──────────────────────────────

export function DagPreview({ steps, accent }) {
  const [open, setOpen] = useState(true);
  if (!steps || steps.length === 0) return null;
  const { layer, deps, byLayer, dagMode } = computeDagLayout(steps);

  const COL_W = 170, ROW_H = 64, NODE_W = 150, NODE_H = 44, PAD_X = 16, PAD_Y = 16;

  const layers = Object.keys(byLayer).map(Number).sort((a, b) => a - b);
  const maxRow = Math.max(...layers.map(l => byLayer[l].length));
  const width = PAD_X * 2 + layers.length * COL_W;
  const height = PAD_Y * 2 + maxRow * ROW_H;

  const pos = {};
  for (const l of layers) {
    byLayer[l].forEach((idx, row) => {
      pos[idx] = {
        x: PAD_X + l * COL_W,
        y: PAD_Y + row * ROW_H + (maxRow - byLayer[l].length) * (ROW_H / 2),
      };
    });
  }

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 8, overflow: 'hidden' }}>
      <button onClick={() => setOpen(o => !o)} style={{ width: '100%', background: 'transparent', border: 'none', borderBottom: open ? '1px solid #1e2029' : 'none', padding: '10px 14px', cursor: 'pointer', color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ textTransform: 'uppercase', letterSpacing: '0.1em', fontSize: 9, color: '#404550' }}>
          {open ? '▾' : '▸'} Graph preview {dagMode ? <span style={{ color: '#5b8af5', marginLeft: 6 }}>(DAG)</span> : <span style={{ color: '#606570', marginLeft: 6 }}>(linear)</span>}
        </span>
        <span style={{ fontSize: 9, color: '#505560' }}>{steps.length} step{steps.length === 1 ? '' : 's'} · {layers.length} layer{layers.length === 1 ? '' : 's'}</span>
      </button>
      {open && (
        <div style={{ overflowX: 'auto', padding: 8 }}>
          <svg width={width} height={height} style={{ display: 'block', minWidth: '100%' }}>
            <defs>
              <marker id="dag-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" fill={accent} opacity="0.6" />
              </marker>
            </defs>
             {steps.map((_, idx) => {
              let edges;
              if (dagMode) { edges = deps[idx]; }
              else if (idx > 0) { edges = [idx - 1]; }
              else { edges = []; }
              return edges.map(d => {
                const a = pos[d], b = pos[idx];
                if (!a || !b) return null;
                const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2;
                const x2 = b.x, y2 = b.y + NODE_H / 2;
                const mx = (x1 + x2) / 2;
                return (
                  <path key={`${d}-${idx}`} d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
                    stroke={accent} strokeOpacity="0.5" strokeWidth="1.5" fill="none" markerEnd="url(#dag-arrow)" />
                );
              });
            })}
            {steps.map((step, idx) => {
              const p = pos[idx];
              if (!p) return null;
              const hasRetry = (Number(step.retry_count) || 0) > 0;
              const hasPrecond = !!step.precondition;
              const isParallel = dagMode && byLayer[layer[idx]].length > 1;
              return (
                <g key={`node-${step.connector_key}-${step.operation}-${p.x}`} transform={`translate(${p.x}, ${p.y})`}>
                  <rect width={NODE_W} height={NODE_H} rx="6" ry="6"
                    fill="#13161f" stroke={isParallel ? accent : '#1e2230'} strokeWidth={isParallel ? 1.5 : 1} />
                  <text x="8" y="16" fontSize="10" fontFamily="JetBrains Mono" fill="#606570">#{idx + 1}</text>
                  <text x="26" y="16" fontSize="10" fontFamily="JetBrains Mono" fill="#e0e4ec">
                    {(step.title || `${step.connector_key}:${step.operation}`).slice(0, 18)}
                  </text>
                  <text x="8" y="32" fontSize="9" fontFamily="JetBrains Mono" fill="#707580">
                    {step.connector_key}:{step.operation}
                  </text>
                  {(hasRetry || hasPrecond) && (
                    <text x={NODE_W - 8} y="32" fontSize="9" fontFamily="JetBrains Mono" fill="#5b8af5" textAnchor="end">
                      {hasRetry ? `↻${step.retry_count}` : ''}{hasRetry && hasPrecond ? ' ' : ''}{hasPrecond ? '⛬' : ''}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
      )}
    </div>
  );
}

DagPreview.propTypes = {
  steps: PropTypes.array,
  accent: PropTypes.string,
};

// ── LiveDagGraph (run-time status overlay) ──────────────────────────

const RUN_STATUS = {
  queued: { color: '#a0a8b8', label: 'Queued' },
  running: { color: '#f09a3a', label: 'Running' },
  done: { color: '#39d353', label: 'Done' },
  failed: { color: '#cc2233', label: 'Failed' },
  cancelled: { color: '#6a7080', label: 'Cancelled' },
  skipped: { color: '#5b8af5', label: 'Skipped' },
};

function _liveDagNodeBg(st, color) {
  const active = st === 'running' || st === 'done' || st === 'failed' || st === 'skipped';
  return active ? `${color}18` : '#13161f';
}

function _liveDagStatusColor(st) { return (RUN_STATUS[st] || RUN_STATUS.queued).color; }

function _liveDagGlyph(st, idx) {
  if (st === 'done') return '✓';
  if (st === 'running') return '●';
  if (st === 'failed') return '✗';
  if (st === 'skipped') return '↷';
  return idx + 1;
}

function _liveDagComputePos({ byLayer, layers, PAD_X, PAD_Y, COL_W, ROW_H, maxRow }) {
  const pos = {};
  for (const l of layers) {
    byLayer[l].forEach((idx, row) => {
      pos[idx] = {
        x: PAD_X + l * COL_W,
        y: PAD_Y + row * ROW_H + (maxRow - byLayer[l].length) * (ROW_H / 2),
      };
    });
  }
  return pos;
}

function DagEdgePaths({ playbookSteps, dagMode, deps, pos, statusByIdx, accent, NODE_W, NODE_H }) {
  return playbookSteps.map((_, idx) => {
    let edgeList;
    if (dagMode) { edgeList = deps[idx]; }
    else if (idx > 0) { edgeList = [idx - 1]; }
    else { edgeList = []; }
    return edgeList.map(d => {
      const a = pos[d], b = pos[idx];
      if (!a || !b) return null;
      const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2;
      const x2 = b.x, y2 = b.y + NODE_H / 2;
      const mx = (x1 + x2) / 2;
      const downstreamStatus = statusByIdx?.[idx] || 'queued';
      const liveEdge = downstreamStatus === 'running' || downstreamStatus === 'done';
      return (
        <path key={`${d}-${idx}`} d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
          stroke={liveEdge ? _liveDagStatusColor(downstreamStatus) : accent}
          strokeOpacity={liveEdge ? 0.7 : 0.35}
          strokeWidth={liveEdge ? 2 : 1.5}
          fill="none" markerEnd="url(#live-dag-arrow)" />
      );
    });
  });
}

DagEdgePaths.propTypes = {
  playbookSteps: PropTypes.array,
  dagMode: PropTypes.bool,
  deps: PropTypes.array,
  pos: PropTypes.object,
  statusByIdx: PropTypes.object,
  accent: PropTypes.string,
  NODE_W: PropTypes.number,
  NODE_H: PropTypes.number,
};

function DagNodeGroup({ step, idx, pos, statusByIdx, dagMode, byLayer, layer, NODE_W, NODE_H }) {
  const p = pos[idx];
  if (!p) return null;
  const st = statusByIdx?.[idx] || 'queued';
  const color = _liveDagStatusColor(st);
  const bg = _liveDagNodeBg(st, color);
  const attempts = statusByIdx?.[`${idx}__attempts`] || 1;
  const isParallel = dagMode && byLayer[layer[idx]].length > 1;
  let sw = 1;
  if (st === 'running') sw = 2;
  else if (isParallel) sw = 1.5;
  const glyph = _liveDagGlyph(st, idx);
  return (
    <g key={`node-${step.connector_key}-${step.operation}`} transform={`translate(${p.x}, ${p.y})`}>
      <rect width={NODE_W} height={NODE_H} rx="6" ry="6"
        fill={bg} stroke={color}
        strokeWidth={sw}
        strokeDasharray={st === 'queued' ? '3 3' : 'none'} />
      <circle cx="14" cy={NODE_H / 2} r="8" fill={`${color}22`} stroke={color} strokeWidth="1" />
      <text x="14" y={NODE_H / 2 + 3} fontSize="9" fontFamily="JetBrains Mono" fill={color} textAnchor="middle" fontWeight="700">
        {glyph}
      </text>
      <text x="28" y="16" fontSize="10" fontFamily="JetBrains Mono" fill="#e0e4ec">
        {(step.title || `${step.connector_key}:${step.operation}`).slice(0, 17)}
      </text>
      <text x="28" y="32" fontSize="9" fontFamily="JetBrains Mono" fill="#707580">
        {step.connector_key}:{step.operation}
      </text>
      {attempts > 1 && (
        <text x={NODE_W - 8} y="32" fontSize="9" fontFamily="JetBrains Mono" fill="#f09a3a" textAnchor="end">
          ↻{attempts}
        </text>
      )}
    </g>
  );
}

DagNodeGroup.propTypes = {
  step: PropTypes.object,
  idx: PropTypes.number,
  pos: PropTypes.object,
  statusByIdx: PropTypes.object,
  dagMode: PropTypes.bool,
  byLayer: PropTypes.object,
  layer: PropTypes.array,
  NODE_W: PropTypes.number,
  NODE_H: PropTypes.number,
};

export function LiveDagGraph({ playbookSteps, statusByIdx, accent }) {
  if (!playbookSteps || playbookSteps.length === 0) return null;
  const { layer, deps, byLayer, dagMode } = computeDagLayout(playbookSteps);

  const COL_W = 170, ROW_H = 64, NODE_W = 150, NODE_H = 44, PAD_X = 16, PAD_Y = 16;

  const layers = Object.keys(byLayer).map(Number).sort((a, b) => a - b);
  const maxRow = Math.max(...layers.map(l => byLayer[l].length));
  const width = PAD_X * 2 + layers.length * COL_W;
  const height = PAD_Y * 2 + maxRow * ROW_H;
  const pos = _liveDagComputePos({ byLayer, layers, PAD_X, PAD_Y, COL_W, ROW_H, maxRow });

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #14161b', fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>Live graph {dagMode ? <span style={{ color: '#5b8af5', marginLeft: 6 }}>(DAG)</span> : <span style={{ color: '#606570', marginLeft: 6 }}>(linear)</span>}</span>
        <span style={{ fontSize: 9, color: '#505560' }}>{playbookSteps.length} step{playbookSteps.length === 1 ? '' : 's'} · {layers.length} layer{layers.length === 1 ? '' : 's'}</span>
      </div>
      <div style={{ overflowX: 'auto', padding: 8 }}>
        <svg width={width} height={height} style={{ display: 'block', minWidth: '100%' }}>
          <defs>
            <marker id="live-dag-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill={accent} opacity="0.6" />
            </marker>
          </defs>
          <DagEdgePaths playbookSteps={playbookSteps} dagMode={dagMode} deps={deps} pos={pos} statusByIdx={statusByIdx} accent={accent} NODE_W={NODE_W} NODE_H={NODE_H} />
          {playbookSteps.map((step, idx) => (
            <DagNodeGroup key={`node-${step.connector_key}-${step.operation}`} step={step} idx={idx} pos={pos} statusByIdx={statusByIdx} dagMode={dagMode} byLayer={byLayer} layer={layer} NODE_W={NODE_W} NODE_H={NODE_H} />
          ))}
        </svg>
      </div>
    </div>
  );
}

LiveDagGraph.propTypes = {
  playbookSteps: PropTypes.array,
  statusByIdx: PropTypes.object,
  accent: PropTypes.string,
};
