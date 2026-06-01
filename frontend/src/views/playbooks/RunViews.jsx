/**
 * Run display components — rollup, step rows, expanded detail, run list.
 *
 * Extracted from PlaybooksView.jsx.
 */
import { LiveDagGraph } from './DagGraphs.jsx';
import PropTypes from 'prop-types';
import { toolbarBtn } from './utils.js';

// ── Run status config ───────────────────────────────────────────────

export const RUN_STATUS = {
  queued: { color: '#a0a8b8', label: 'Queued' },
  running: { color: '#f09a3a', label: 'Running' },
  done: { color: '#39d353', label: 'Done' },
  failed: { color: '#cc2233', label: 'Failed' },
  cancelled: { color: '#6a7080', label: 'Cancelled' },
  skipped: { color: '#5b8af5', label: 'Skipped' },
};

export function StatusBadge({ status }) {
  const meta = RUN_STATUS[status] || { color: '#808590', label: status || 'unknown' };
  return <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: meta.color, background: meta.color + '18', border: `1px solid ${meta.color}33`, borderRadius: 4, padding: '2px 8px' }}>{meta.label}</span>;
}

StatusBadge.propTypes = {
  status: PropTypes.string,
};

// ── Helpers ──────────────────────────────────────────────────────────

export function _runIsActive(run) { return run.status === 'queued' || run.status === 'running'; }
export function _runIsDone(run) { return run.status === 'done' || run.status === 'failed'; }
export function _runHasDagMode(run) { return !!run.result_json?.dag_mode || (run.jobs_json || []).some(s => s.step_idx !== undefined); }

export function _buildStatusByIdx(run, runJobsCache) {
  const statusByIdx = {};
  const stepStates = run.result_json?.step_states || {};
  const byIdx = new Map();
  for (const s of (run.jobs_json || [])) {
    const k = s.step_idx ?? -1;
    const cur = byIdx.get(k);
    if (!cur || (s.attempt ?? 1) > (cur.attempt ?? 1)) byIdx.set(k, s);
  }
  for (const [k, s] of byIdx.entries()) {
    if (k < 0) continue;
    const live = runJobsCache[run.id]?.find(j => j.id === s.id);
    statusByIdx[k] = (live || s).status || 'queued';
    statusByIdx[`${k}__attempts`] = s.attempt || 1;
  }
  for (const k of Object.keys(stepStates).map(Number)) {
    if (statusByIdx[k] === undefined) {
      statusByIdx[k] = stepStates[k].status || 'skipped';
      statusByIdx[`${k}__attempts`] = stepStates[k].attempts || 0;
    }
  }
  return statusByIdx;
}

export function _resolveRunSteps(run) {
  const rawSteps = run.jobs_json || [];
  const stepStates = run.result_json?.step_states || null;
  const dagMode = !!run.result_json?.dag_mode || rawSteps.some(s => s.step_idx !== undefined);
  if (!dagMode) return rawSteps;
  const byIdx = new Map();
  for (const s of rawSteps) {
    const k = s.step_idx ?? -1;
    const cur = byIdx.get(k);
    if (!cur || (s.attempt ?? 1) > (cur.attempt ?? 1)) byIdx.set(k, s);
  }
  let steps = [...byIdx.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v);
  if (stepStates) {
    for (const idx of Object.keys(stepStates).map(Number)) {
      if (!byIdx.has(idx)) {
        const st = stepStates[idx];
        steps.push({ id: `__skipped_${idx}`, step_idx: idx, status: st.status || 'skipped', title: `Step ${idx + 1}`, attempt: st.attempts || 0, __synthetic: true });
      }
    }
    steps.sort((a, b) => (a.step_idx ?? 0) - (b.step_idx ?? 0));
  }
  return steps;
}

export function _runDuration(run) {
  if (run.started_at && run.finished_at) {
    const s = new Date(run.started_at);
    const f = new Date(run.finished_at);
    const sec = Math.round((f - s) / 1000);
    return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
  }
  if (run.started_at && !run.finished_at) return 'running…';
  return null;
}

function _formatDuration(startedAt, finishedAt) {
  if (!startedAt) return null;
  const s = new Date(startedAt);
  const f = finishedAt ? new Date(finishedAt) : new Date();
  const sec = Math.round((f - s) / 1000);
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

// ── RunRollup ────────────────────────────────────────────────────────

const ROLLUP_META = {
  hosts_found:    { label: 'Hosts found',    color: '#5b8af5' },
  hosts_created:  { label: 'Hosts added',    color: '#5b8af5' },
  hosts_pwned:    { label: 'Compromised',    color: '#cc2233' },
  hosts_valid:    { label: 'Auth valid',     color: '#39d353' },
  findings_created: { label: 'Findings',     color: '#e8574a' },
  creds_created:  { label: 'Creds created',  color: '#c07af0' },
  paths_found:    { label: 'Paths found',    color: '#f09a3a' },
  urls_found:     { label: 'URLs found',     color: '#6fc8f0' },
};

export function RunRollup({ run, accent }) {
  const rollup = run.result_json?.rollup || {};
  const completedCount = (run.result_json?.completed_jobs || run.jobs_json || []).length;
  const failedCount = (run.result_json?.failed_jobs || []).length;
  const hasRollup = Object.keys(rollup).length > 0;

  const duration = run.started_at && run.finished_at
    ? (() => { const s = new Date(run.started_at), f = new Date(run.finished_at); const sec = Math.round((f - s) / 1000); return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`; })()
    : null;

  return (
    <div style={{ background: '#090b0f', border: '1px solid #1e2029', borderRadius: 8, padding: '10px 14px' }}>
      <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8, fontFamily: 'JetBrains Mono' }}>Run summary</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: hasRollup ? 10 : 0 }}>
        <div style={{ textAlign: 'center', background: '#39d35312', border: '1px solid #39d35330', borderRadius: 6, padding: '6px 12px', minWidth: 64 }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#39d353', fontFamily: 'JetBrains Mono' }}>{completedCount}</div>
          <div style={{ fontSize: 8, color: '#39d353', textTransform: 'uppercase', letterSpacing: '0.08em' }}>done</div>
        </div>
        {failedCount > 0 && (
          <div style={{ textAlign: 'center', background: '#cc223312', border: '1px solid #cc223330', borderRadius: 6, padding: '6px 12px', minWidth: 64 }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>{failedCount}</div>
            <div style={{ fontSize: 8, color: '#cc2233', textTransform: 'uppercase', letterSpacing: '0.08em' }}>failed</div>
          </div>
        )}
        {duration && (
          <div style={{ textAlign: 'center', background: '#ffffff06', border: '1px solid #2a2d35', borderRadius: 6, padding: '6px 12px', minWidth: 64 }}>
            <div style={{ fontSize: 18, fontWeight: 700, color: '#808590', fontFamily: 'JetBrains Mono' }}>{duration}</div>
            <div style={{ fontSize: 8, color: '#606570', textTransform: 'uppercase', letterSpacing: '0.08em' }}>duration</div>
          </div>
        )}
        {Object.entries(rollup).map(([k, v]) => {
          const meta = ROLLUP_META[k];
          if (!meta || !v) return null;
          return (
            <div key={k} style={{ textAlign: 'center', background: meta.color + '12', border: `1px solid ${meta.color}30`, borderRadius: 6, padding: '6px 12px', minWidth: 64 }}>
              <div style={{ fontSize: 18, fontWeight: 700, color: meta.color, fontFamily: 'JetBrains Mono' }}>{v}</div>
              <div style={{ fontSize: 8, color: meta.color, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{meta.label}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

RunRollup.propTypes = {
  run: PropTypes.object,
  accent: PropTypes.string,
};

// ── PlaybookCard ──────────────────────────────────────────────────────

export function PlaybookCard({ playbook, accent, selected, onSelect }) {
  const stepCount = (playbook.steps || []).length;
  return (
    <button onClick={() => onSelect(playbook.id)} style={{ width: '100%', minHeight: 104, textAlign: 'left', background: selected ? `${accent}14` : '#0d0f14', border: `1px solid ${selected ? accent + '55' : '#1e2029'}`, borderRadius: 10, padding: '12px 13px', cursor: 'pointer', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: 10, overflow: 'hidden', transition: 'border-color .15s, background .15s' }}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7 }}>
          <div style={{ fontSize: 13, color: selected ? '#f0f2f6' : '#e0e4ec', fontWeight: 700, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{playbook.title}</div>
          <span style={{ fontSize: 9, fontFamily: 'JetBrains Mono', color: playbook.source === 'custom' ? '#c07af0' : '#5b8af5', background: playbook.source === 'custom' ? '#c07af018' : '#5b8af518', border: `1px solid ${playbook.source === 'custom' ? '#c07af033' : '#5b8af533'}`, borderRadius: 999, padding: '2px 7px', flexShrink: 0, textTransform: 'uppercase' }}>{playbook.source}</span>
        </div>
        <div style={{ fontSize: 10, color: '#606570', lineHeight: 1.45, height: 30, overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>{playbook.description || 'No description'}</div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minHeight: 20 }}>
        <span style={{ fontSize: 10, color: selected ? accent : '#9098a8', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>{stepCount} step{stepCount === 1 ? '' : 's'}</span>
        <div style={{ width: 1, height: 12, background: '#262a35' }} />
        <div style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono' }}>
          {(playbook.steps || []).slice(0, 2).map(step => `${step.connector_key}:${step.operation}`).join(' · ')}
          {stepCount > 2 ? ` · +${stepCount - 2}` : ''}
        </div>
      </div>
    </button>
  );
}

PlaybookCard.propTypes = {
  playbook: PropTypes.object,
  accent: PropTypes.string,
  selected: PropTypes.bool,
  onSelect: PropTypes.func,
};

// ── Run step rows ───────────────────────────────────────────────────

function RunStepGlyph({ isRunning, effectiveStatus, isSkipped, stepIdx, idx }) {
  if (isRunning) return <span style={{ animation: 'pulse 1.2s infinite' }}>●</span>;
  if (effectiveStatus === 'done') return '✓';
  if (effectiveStatus === 'failed') return '✗';
  if (isSkipped) return '↷';
  return stepIdx === undefined ? idx + 1 : stepIdx + 1;
}

RunStepGlyph.propTypes = {
  isRunning: PropTypes.bool,
  effectiveStatus: PropTypes.string,
  isSkipped: PropTypes.bool,
  stepIdx: PropTypes.number,
  idx: PropTypes.number,
};

function _RunStepIconBg(effectiveStatus, isRunning, isSkipped, isFailed) {
  if (effectiveStatus === 'done') return '#39d35322';
  if (isRunning) return '#f09a3a22';
  if (isFailed) return '#cc223322';
  if (isSkipped) return '#5b8af522';
  return '#13161f';
}

function RunStepRow({ snapshot, idx, stepsCount, liveJob }) {
  const job = liveJob || snapshot;
  const isSkipped = snapshot.__synthetic || job.status === 'skipped';
  const effectiveStatus = isSkipped ? 'skipped' : job.status;
  const statusCfg = RUN_STATUS[effectiveStatus] || RUN_STATUS.queued;
  const isRunning = effectiveStatus === 'running';
  const isFailed = effectiveStatus === 'failed';
  const stepIdx = snapshot.step_idx;
  const attempts = snapshot.attempt || 1;
  const dur = liveJob?.started_at ? _formatDuration(liveJob.started_at, liveJob.finished_at) : null;
  const summary = liveJob?.result_json?.structured?.summary || '';
  const lastLines = liveJob?.output?.split('\n').filter(Boolean).slice(-3) || [];
  let rowBg = 'transparent';
  if (isRunning) rowBg = '#f09a3a06';
  else if (isFailed) rowBg = '#cc223306';
  return (
    <div key={job.id} style={{ borderBottom: idx < stepsCount - 1 ? '1px solid #12141a' : 'none', background: rowBg }}>
      <div style={{ padding: '8px 12px', display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ width: 20, height: 20, borderRadius: '50%', background: _RunStepIconBg(effectiveStatus, isRunning, isSkipped, isFailed), border: `1px solid ${statusCfg.color}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: statusCfg.color, fontSize: 9, fontFamily: 'JetBrains Mono', fontWeight: 700, flexShrink: 0 }}>
          <RunStepGlyph isRunning={isRunning} effectiveStatus={effectiveStatus} isSkipped={isSkipped} stepIdx={stepIdx} idx={idx} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 11, color: '#c8cdd6', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{job.title}</div>
          <div style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginTop: 2, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {liveJob?.connector_key && <span style={{ color: '#6fc8f0' }}>{liveJob.connector_key}</span>}
            {liveJob?.operation && <span>{liveJob.operation}</span>}
            {liveJob?.target && <span>→ {liveJob.target}</span>}
            {summary && <span style={{ color: '#808590' }}>{summary}</span>}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          {attempts > 1 && <span title={`${attempts} attempts (retry)`} style={{ fontSize: 9, color: '#f09a3a', background: '#f09a3a18', border: '1px solid #f09a3a33', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>↻{attempts}</span>}
          <StatusBadge status={effectiveStatus} />
          {dur && <span style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>⏱{dur}</span>}
        </div>
      </div>
      {(isRunning || isFailed) && lastLines.length > 0 && (
        <div style={{ padding: '0 12px 8px 42px' }}>
          <pre style={{ margin: 0, fontSize: 9, color: isFailed ? '#f87171' : '#606570', fontFamily: 'JetBrains Mono', lineHeight: 1.5, background: '#07080c', borderRadius: 4, padding: '4px 8px', overflow: 'hidden' }}>
            {lastLines.join('\n')}
          </pre>
        </div>
      )}
    </div>
  );
}

RunStepRow.propTypes = {
  snapshot: PropTypes.object,
  idx: PropTypes.number,
  stepsCount: PropTypes.number,
  liveJob: PropTypes.object,
};

function RunStepsBlock({ run, liveJobs }) {
  const steps = _resolveRunSteps(run);
  return (
    <div style={{ background: '#090b0f', border: '1px solid #1e2029', borderRadius: 8, overflow: 'hidden' }}>
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #14161b', fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: 8 }}>
        Steps
        {run.status === 'running' && <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f09a3a', animation: 'pulse 1.2s infinite', display: 'inline-block' }} />}
      </div>
      {steps.map((snapshot, idx) => (
        <RunStepRow key={snapshot.id || idx} snapshot={snapshot} idx={idx} stepsCount={steps.length} liveJob={liveJobs?.find(j => j.id === snapshot.id)} />
      ))}
    </div>
  );
}

RunStepsBlock.propTypes = {
  run: PropTypes.object,
  liveJobs: PropTypes.array,
};

function RunActionButtons({ run, accent, cancelRun, rerun, onNavigate }) {
  const isActive = _runIsActive(run);
  const hasJobs = !!(run.jobs_json || []).length;
  return (
    <div style={{ display: 'flex', gap: 8 }}>
      {isActive && <button onClick={() => cancelRun(run.id)} style={toolbarBtn('#f09a3a', false)}>Cancel run</button>}
      {!isActive && <button onClick={() => rerun(run.id)} style={toolbarBtn(accent, false)}>Rerun</button>}
      {hasJobs && <button onClick={() => onNavigate?.('jobs', { playbookRunId: run.id })} style={toolbarBtn('#5b8af5', false)}>Open Jobs</button>}
    </div>
  );
}

RunActionButtons.propTypes = {
  run: PropTypes.object,
  accent: PropTypes.string,
  cancelRun: PropTypes.func,
  rerun: PropTypes.func,
  onNavigate: PropTypes.func,
};

function RunExpandedDetail({ run, runJobsCache, playbooks, accent, cancelRun, rerun, onNavigate }) {
  const pb = playbooks.find(p => p.id === run.playbook_id);
  const pbSteps = pb?.steps || [];
  const dagMode = _runHasDagMode(run);
  const liveJobs = runJobsCache[run.id];
  return (
    <div style={{ padding: '0 16px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
      {dagMode && pbSteps.length > 0 && (
        <LiveDagGraph playbookSteps={pbSteps} statusByIdx={_buildStatusByIdx(run, runJobsCache)} accent={accent} />
      )}
      <RunStepsBlock run={run} liveJobs={liveJobs} />
      {_runIsDone(run) && <RunRollup run={run} accent={accent} />}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 10, fontFamily: 'JetBrains Mono', color: '#606570' }}>
        {run.started_at && <div><span style={{ color: '#404550' }}>started: </span>{run.started_at.slice(0, 16)}</div>}
        {run.finished_at && <div><span style={{ color: '#404550' }}>finished: </span>{run.finished_at.slice(0, 16)}</div>}
        <div><span style={{ color: '#404550' }}>run id: </span>{run.id}</div>
        <div><span style={{ color: '#404550' }}>playbook: </span>{run.playbook_id}</div>
      </div>
      {run.error_output && (
        <div style={{ background: '#130808', border: '1px solid #3a1010', borderRadius: 6, padding: '8px 12px', fontSize: 10, color: '#f87171', fontFamily: 'JetBrains Mono', lineHeight: 1.6 }}>{run.error_output}</div>
      )}
      <RunActionButtons run={run} accent={accent} cancelRun={cancelRun} rerun={rerun} onNavigate={onNavigate} />
    </div>
  );
}

RunExpandedDetail.propTypes = {
  run: PropTypes.object,
  runJobsCache: PropTypes.object,
  playbooks: PropTypes.array,
  accent: PropTypes.string,
  cancelRun: PropTypes.func,
  rerun: PropTypes.func,
  onNavigate: PropTypes.func,
};

// ── Run list item + full list ────────────────────────────────────────

function RunListItem({ run, i, runsLen, accent, expandedRunId, setExpandedRunId, runJobsCache, playbooks, cancelRun, rerun, onNavigate }) {
  const isExpanded = expandedRunId === run.id;
  const duration = _runDuration(run);
  return (
    <div key={run.id} style={{ borderBottom: i < runsLen - 1 ? '1px solid #14161b' : 'none' }}>
      <button
        type="button"
        onClick={() => setExpandedRunId(prev => prev === run.id ? null : run.id)}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setExpandedRunId(prev => prev === run.id ? null : run.id);
          }
        }}
        style={{ padding: '12px 16px', cursor: 'pointer', userSelect: 'none', width: '100%', textAlign: 'left', background: 'transparent', border: 'none' }}
        onMouseEnter={e => e.currentTarget.style.background = '#ffffff04'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 10, color: isExpanded ? accent : '#505560', fontFamily: 'JetBrains Mono', flexShrink: 0 }}>{isExpanded ? '▾' : '▸'}</span>
          <span style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 600 }}>{run.title}</span>
          <StatusBadge status={run.status} />
          {duration && <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>⏱ {duration}</span>}
          {run.request_json?.batch_id && <span style={{ fontSize: 9, color: '#f09a3a', background: '#f09a3a18', border: '1px solid #f09a3a33', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>batch</span>}
          {(run.result_json?.dag_mode || (run.jobs_json || []).some(s => s.step_idx !== undefined)) && <span title="DAG mode: parallel branches, retry, preconditions" style={{ fontSize: 9, color: '#5b8af5', background: '#5b8af518', border: '1px solid #5b8af533', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>DAG</span>}
        </div>
        <div style={{ fontSize: 10, color: '#606570', display: 'flex', gap: 12, flexWrap: 'wrap', fontFamily: 'JetBrains Mono', paddingLeft: 18 }}>
          {run.target && <span>target: {run.target}</span>}
          <span>{(run.jobs_json || []).length} step{(run.jobs_json || []).length === 1 ? '' : 's'}</span>
          <span>by: {run.created_by || '—'}</span>
          <span>{run.created_at?.slice(0, 16) || '—'}</span>
        </div>
      </button>
      {isExpanded && (
        <RunExpandedDetail run={run} runJobsCache={runJobsCache} playbooks={playbooks} accent={accent} cancelRun={cancelRun} rerun={rerun} onNavigate={onNavigate} />
      )}
    </div>
  );
}

RunListItem.propTypes = {
  run: PropTypes.object,
  i: PropTypes.number,
  runsLen: PropTypes.number,
  accent: PropTypes.string,
  expandedRunId: PropTypes.string,
  setExpandedRunId: PropTypes.func,
  runJobsCache: PropTypes.object,
  playbooks: PropTypes.array,
  cancelRun: PropTypes.func,
  rerun: PropTypes.func,
  onNavigate: PropTypes.func,
};

export function PlaybookRunsList({ runs, loading, accent, expandedRunId, setExpandedRunId, runJobsCache, playbooks, cancelRun, rerun, onNavigate }) {
  return (
    <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid #1e2029', background: '#090b0f', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 600 }}>Playbook Runs</div>
        <div style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{runs.length} total</div>
      </div>
      {(() => {
        if (loading) {
          return <div style={{ padding: 16, color: '#505560', fontSize: 12 }}>Loading...</div>;
        }
        if (runs.length === 0) {
          return <div style={{ padding: 16, color: '#505560', fontSize: 12 }}>No playbook runs yet.</div>;
        }
        return (
        <div>
          {runs.map((run, i) => (
            <RunListItem key={run.id} run={run} i={i} runsLen={runs.length} accent={accent} expandedRunId={expandedRunId} setExpandedRunId={setExpandedRunId} runJobsCache={runJobsCache} playbooks={playbooks} cancelRun={cancelRun} rerun={rerun} onNavigate={onNavigate} />
          ))}
        </div>
      ); })()}
    </div>
  );
}

PlaybookRunsList.propTypes = {
  runs: PropTypes.array,
  loading: PropTypes.bool,
  accent: PropTypes.string,
  expandedRunId: PropTypes.string,
  setExpandedRunId: PropTypes.func,
  runJobsCache: PropTypes.object,
  playbooks: PropTypes.array,
  cancelRun: PropTypes.func,
  rerun: PropTypes.func,
  onNavigate: PropTypes.func,
};
