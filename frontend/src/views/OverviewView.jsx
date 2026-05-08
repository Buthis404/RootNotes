import Icon from '../components/Icon.jsx';
import { isAttackerHost } from '../utils/hostMeta.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS = {
  critical: '#cc2233',
  high:     '#e8574a',
  medium:   '#f09a3a',
  low:      '#4a9eff',
  info:     '#606570',
};
const HOST_STATUS_COLORS = {
  unknown: '#404550',
  up:      '#39d353',
  down:    '#505560',
  alive:   '#5b8af5',
  scanned: '#c07af0',
  access:  '#f09a3a',
  pwned:   '#cc2233',
  owned:   '#39d353',
};
const HOST_STATUS_LABELS = {
  unknown: 'Unknown',
  up:      'Up',
  down:    'Down',
  alive:   'Discovered',
  scanned: 'Scanned',
  access:  'Access',
  pwned:   'Compromised',
  owned:   'Full Control',
};

function timeAgo(tsStr) {
  if (!tsStr) return '?';
  const ts = new Date(tsStr);
  if (isNaN(ts)) return tsStr;
  const diff = Math.floor((Date.now() - ts.getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const ENTITY_ICONS = {
  host: 'hosts', note: 'notes', cred: 'person', finding: 'bug',
  objective: 'flag', loot: 'loot', network: 'network',
};

const CHECKLIST_PHASES = ['recon', 'scan', 'exploit', 'post', 'report'];
const PHASE_LABELS = { recon: 'Recon', scan: 'Scan', exploit: 'Exploit', post: 'Post-Exploit', report: 'Report' };
const PHASE_COLORS = { recon: '#5b8af5', scan: '#c07af0', exploit: '#e8574a', post: '#f09a3a', report: '#6fc8f0' };

export default function OverviewView({
  selectedProject, projects, hosts, creds, findings,
  notes, objectives, timelineEvents = [], checklistItems = [],
  accent, onTabChange,
}) {
  const proj = projects.find(p => p.id === selectedProject);
  const pHosts = (hosts || []).filter(h => h.pid === selectedProject && !isAttackerHost(h));
  const pCreds = (creds || []).filter(c => c.pid === selectedProject);
  const pFindings = (findings || []).filter(f => f.pid === selectedProject);
  const pNotes = (notes || []).filter(n => n.pid === selectedProject);
  const pObjectives = (objectives || []).filter(o => o.pid === selectedProject);
  const pChecklist = (checklistItems || []).filter(i => i.pid === selectedProject);
  const pTimeline = (timelineEvents || []).filter(e => e.pid === selectedProject);

  const pwnedCount = pHosts.filter(h => h.status === 'pwned' || h.status === 'owned').length;
  const criticalCount = pFindings.filter(f => f.severity === 'critical').length;
  const highCount = pFindings.filter(f => f.severity === 'high').length;
  const crackedCount = pCreds.filter(c => c.cracked).length;
  const capturedCount = pObjectives.filter(o => o.status === 'captured' || o.status === 'submitted').length;

  // Findings breakdown
  const totalFindings = pFindings.length;

  // Hosts by status
  const allStatuses = [...new Set(pHosts.map(h => h.status || 'unknown'))];
  const hostStatusStats = allStatuses.map(s => ({
    status: s,
    count: pHosts.filter(h => (h.status || 'unknown') === s).length,
  })).sort((a, b) => b.count - a.count);

  // Timeline — последние 8
  const recentEvents = [...pTimeline]
    .sort((a, b) => String(b.ts || b.created_at || '').localeCompare(String(a.ts || a.created_at || '')))
    .slice(0, 8);

  // Checklist phases
  const checklistPhaseStats = CHECKLIST_PHASES.map(phase => {
    const items = pChecklist.filter(i => i.phase === phase || i.category === phase);
    const done = items.filter(i => i.done || i.checked || i.status === 'done').length;
    return { phase, done, total: items.length };
  });

  const cardStyle = {
    background: '#0d0f14',
    border: '1px solid #1e2029',
    borderRadius: 8,
    padding: '16px 18px',
    cursor: 'pointer',
    transition: 'border-color .15s',
  };

  const blockStyle = {
    background: '#0d0f14',
    border: '1px solid #1e2029',
    borderRadius: 8,
    padding: 18,
  };

  if (!proj) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#404550', fontSize: 13 }}>
        No project selected
      </div>
    );
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px', maxWidth: 1100 }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 9, color: '#404550', letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>
          Overview · {new Date().toLocaleDateString('en')}
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', margin: 0 }}>
          {proj.name}
        </h1>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12, marginBottom: 20 }}>
        {/* Hosts */}
        <div style={{ ...cardStyle, borderColor: pwnedCount > 0 ? '#cc223333' : '#1e2029' }}
          onClick={() => onTabChange && onTabChange('hosts')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = pwnedCount > 0 ? '#cc223333' : '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="hosts" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: '#606570', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Hosts</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#c07af0', fontFamily: 'Space Grotesk', marginBottom: 4 }}>{pHosts.length}</div>
          {pwnedCount > 0 && (
            <div style={{ fontSize: 10, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>{pwnedCount} pwned</div>
          )}
        </div>

        {/* Findings */}
        <div style={{ ...cardStyle, borderColor: totalFindings > 0 ? '#e8574a33' : '#1e2029' }}
          onClick={() => onTabChange && onTabChange('findings')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = totalFindings > 0 ? '#e8574a33' : '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="bug" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: '#606570', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Findings</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#e8574a', fontFamily: 'Space Grotesk', marginBottom: 4 }}>{totalFindings}</div>
          <div style={{ fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', gap: 8 }}>
            {criticalCount > 0 && <span style={{ color: '#cc2233' }}>{criticalCount} crit</span>}
            {highCount > 0 && <span style={{ color: '#e8574a' }}>{highCount} high</span>}
          </div>
        </div>

        {/* Creds */}
        <div style={cardStyle}
          onClick={() => onTabChange && onTabChange('creds')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="person" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: '#606570', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Creds</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#39d353', fontFamily: 'Space Grotesk', marginBottom: 4 }}>{pCreds.length}</div>
          {crackedCount > 0 && (
            <div style={{ fontSize: 10, color: '#39d353', fontFamily: 'JetBrains Mono' }}>{crackedCount} cracked</div>
          )}
        </div>

        {/* Objectives */}
        <div style={cardStyle}
          onClick={() => onTabChange && onTabChange('objectives')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="flag" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: '#606570', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Objectives</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#f09a3a', fontFamily: 'Space Grotesk', marginBottom: 4 }}>
            {capturedCount}/{pObjectives.length}
          </div>
          <div style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>captured</div>
        </div>

        {/* Notes */}
        <div style={cardStyle}
          onClick={() => onTabChange && onTabChange('notes')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="notes" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: '#606570', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Notes</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#6fc8f0', fontFamily: 'Space Grotesk', marginBottom: 4 }}>{pNotes.length}</div>
        </div>
      </div>

      {/* Middle row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        {/* Findings by severity */}
        <div style={blockStyle}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 14 }}>Findings by severity</div>
          {totalFindings === 0 ? (
            <div style={{ fontSize: 11, color: '#404550' }}>No findings</div>
          ) : SEV_ORDER.map(s => {
            const count = pFindings.filter(f => f.severity === s).length;
            const pct = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
            return (
              <div key={s} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                  <span style={{ fontSize: 10, color: SEV_COLORS[s], textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'JetBrains Mono', width: 70 }}>{s}</span>
                  <span style={{ fontSize: 11, color: count > 0 ? SEV_COLORS[s] : '#303540', fontFamily: 'JetBrains Mono', width: 30, textAlign: 'right' }}>{count}</span>
                  <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', width: 35, textAlign: 'right' }}>{pct}%</span>
                </div>
                <div style={{ height: 5, background: '#1a1c22', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: SEV_COLORS[s], borderRadius: 3, transition: 'width 0.5s' }} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Hosts by status */}
        <div style={blockStyle}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 14 }}>Hosts by status</div>
          {pHosts.length === 0 ? (
            <div style={{ fontSize: 11, color: '#404550' }}>No hosts</div>
          ) : hostStatusStats.map(({ status, count }) => {
            const pct = pHosts.length > 0 ? Math.round((count / pHosts.length) * 100) : 0;
            const color = HOST_STATUS_COLORS[status] || '#404550';
            const label = HOST_STATUS_LABELS[status] || status;
            return (
              <div key={status} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 0', borderBottom: '1px solid #14161b' }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: '#808590', flex: 1 }}>{label}</span>
                <span style={{ fontSize: 12, fontWeight: 600, color, fontFamily: 'JetBrains Mono', width: 30, textAlign: 'right' }}>{count}</span>
                <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', width: 36, textAlign: 'right' }}>{pct}%</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Recent activity */}
        <div style={blockStyle}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="clock" size={13} color="#404550" />Recent activity
          </div>
          {recentEvents.length === 0 ? (
            <div style={{ fontSize: 11, color: '#404550' }}>No recent events</div>
          ) : recentEvents.map((ev, i) => {
            const iconName = ENTITY_ICONS[ev.entity] || ENTITY_ICONS[ev.type] || 'notes';
            const ts = ev.ts || ev.created_at || ev.timestamp;
            return (
              <div key={ev.id || i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 0', borderBottom: '1px solid #14161b' }}>
                <div style={{ width: 24, height: 24, borderRadius: 6, background: '#1a1c22', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                  <Icon name={iconName} size={11} color="#606570" />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11, color: '#c8cdd6', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {ev.label || ev.title || ev.name || 'Event'}
                  </div>
                  {ev.description && (
                    <div style={{ fontSize: 10, color: '#606570', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>{ev.description}</div>
                  )}
                </div>
                <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono', flexShrink: 0, marginTop: 3 }}>{timeAgo(ts)}</span>
              </div>
            );
          })}
        </div>

        {/* Checklist progress */}
        <div style={blockStyle}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="list" size={13} color="#404550" />Checklist progress
          </div>
          {pChecklist.length === 0 ? (
            <div style={{ fontSize: 11, color: '#404550' }}>No checklist items</div>
          ) : checklistPhaseStats.filter(p => p.total > 0).length === 0 ? (
            <div style={{ fontSize: 11, color: '#404550' }}>No checklist items</div>
          ) : checklistPhaseStats.map(({ phase, done, total }) => {
            if (total === 0) return null;
            const pct = Math.round((done / total) * 100);
            const color = PHASE_COLORS[phase] || '#606570';
            return (
              <div key={phase} style={{ marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                  <span style={{ fontSize: 11, color: '#9098a8' }}>{PHASE_LABELS[phase] || phase}</span>
                  <span style={{ fontSize: 10, color: done === total ? '#39d353' : '#606570', fontFamily: 'JetBrains Mono' }}>
                    {done}/{total}
                  </span>
                </div>
                <div style={{ height: 4, background: '#1a1c22', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: done === total ? '#39d353' : color, borderRadius: 2, transition: 'width 0.5s' }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
