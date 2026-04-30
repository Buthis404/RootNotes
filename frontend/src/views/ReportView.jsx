import Icon from '../components/Icon.jsx';
import { StatusDot, PhaseTag, HostStatusBadge, CredTypeBadge } from '../components/UI.jsx';
import { PHASES, PHASE_COLORS, NODE_STATUS, SEVERITY, FINDING_STATUS } from '../constants.js';
import { isAttackerHost } from '../utils/hostMeta.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export default function ReportView({ projects, notes, hosts, creds, findings = [], hostActivities = [], selectedProject, accent }) {
  const proj = projects.find(p => p.id === selectedProject);
  const pNotes = notes.filter(n => n.pid === selectedProject);
  const pHosts = hosts.filter(h => h.pid === selectedProject && !isAttackerHost(h));
  const pCreds = creds.filter(c => c.pid === selectedProject);
  const pFindings = [...(findings.filter(f => f.pid === selectedProject))].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const pActivities = [...hostActivities.filter(a => a.pid === selectedProject && pHosts.some(h => h.id === a.host_id))].sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));

  const phaseStat = PHASES.map(ph => ({ ph, count: pNotes.filter(n => n.phase === ph).length })).filter(x => x.count > 0);
  const hostsBySt = Object.entries(NODE_STATUS).map(([k, v]) => ({ ...v, key: k, count: pHosts.filter(h => h.status === k).length })).filter(x => x.count > 0);
  const critHosts = pHosts.filter(h => h.status === 'pwned' || h.status === 'owned');
  const crackedCreds = pCreds.filter(c => c.cracked);

  const Row = ({ icon, label, value, color = '#9098a8' }) => (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #14161b' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Icon name={icon} size={12} color="#404550" /><span style={{ fontSize: 11, color: '#808590' }}>{label}</span></div>
      <span style={{ fontSize: 12, fontWeight: 600, color, fontFamily: 'JetBrains Mono' }}>{value}</span>
    </div>
  );

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px', maxWidth: 900 }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 9, color: '#404550', letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>Report · {new Date().toLocaleDateString('en')}</div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 4 }}>{proj?.name}</h1>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <StatusDot status={proj?.status} />
          <span style={{ fontSize: 11, color: '#606570' }}>{proj?.ip}</span>
          <span style={{ fontSize: 11, color: '#404550' }}>·</span>
          <span style={{ fontSize: 11, color: '#606570' }}>{proj?.os}</span>
          <span style={{ fontSize: 11, color: '#404550' }}>·</span>
          <span style={{ fontSize: 11, color: '#606570' }}>since {proj?.added}</span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 12, marginBottom: 24 }}>
        {[['notes', 'Notes', pNotes.length, '#6fc8f0'], ['hosts', 'Hosts', pHosts.length, '#c07af0'], ['person', 'Creds', pCreds.length, '#39d353'], ['target', 'Pwned', critHosts.length, '#cc2233'], ['bug', 'Findings', pFindings.length, '#e8574a']].map(([icon, l, v, c]) => (
          <div key={l} style={{ background: '#0d0f14', border: `1px solid ${v > 0 && (l === 'Pwned' || l === 'Findings') ? c + '44' : '#1e2029'}`, borderRadius: 8, padding: '14px 16px' }}>
            <div style={{ fontSize: 26, fontWeight: 700, color: v > 0 ? c : '#303540', fontFamily: 'Space Grotesk', marginBottom: 4 }}>{v}</div>
            <div style={{ fontSize: 10, color: '#606570', display: 'flex', alignItems: 'center', gap: 6 }}><Icon name={icon} size={11} color="#404550" />{l}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 14 }}>Activity by phase</div>
          {phaseStat.map(({ ph, count }) => {
            const c = PHASE_COLORS[ph], max = Math.max(...phaseStat.map(x => x.count));
            return (
              <div key={ph} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <PhaseTag phase={ph} small /><span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{count}</span>
                </div>
                <div style={{ height: 4, background: '#1a1c22', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${(count / max) * 100}%`, background: c, borderRadius: 2, transition: 'width 0.5s' }} />
                </div>
              </div>
            );
          })}
          {phaseStat.length === 0 && <div style={{ fontSize: 11, color: '#404550' }}>No notes</div>}
        </div>

        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 14 }}>Host status</div>
          {hostsBySt.map(({ key, color, label, count }) => (
            <Row key={key} icon="hosts" label={label} value={count} color={color} />
          ))}
          {hostsBySt.length === 0 && <div style={{ fontSize: 11, color: '#404550' }}>No hosts</div>}
        </div>
      </div>

      {critHosts.length > 0 && (
        <div style={{ background: '#0d0f14', border: `1px solid ${accent}33`, borderRadius: 8, padding: 18, marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: accent, fontFamily: 'Space Grotesk', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="warning" size={13} color={accent} />Compromised hosts
          </div>
          {critHosts.map(h => (
            <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 0', borderBottom: '1px solid #14161b' }}>
              <HostStatusBadge status={h.status} />
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#9098a8', width: 130 }}>{h.ip}</span>
              <span style={{ fontSize: 11, color: '#c8cdd6' }}>{h.hostname}</span>
              {h.notes && <span style={{ fontSize: 10, color: '#606570', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.notes}</span>}
            </div>
          ))}
        </div>
      )}

      {crackedCreds.length > 0 && (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18, marginBottom: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="person" size={13} color="#39d353" />Cracked credentials
          </div>
          {crackedCreds.map(c => (
            <div key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 0', borderBottom: '1px solid #14161b' }}>
              <CredTypeBadge type={c.type} />
              <span style={{ fontFamily: 'JetBrains Mono', fontSize: 11, color: '#c8cdd6', width: 130 }}>{c.username}</span>
              <span style={{ fontSize: 10, color: '#5b8af5', width: 110, fontFamily: 'JetBrains Mono' }}>{c.host}</span>
              <span style={{ fontSize: 10, color: '#606570' }}>{c.service}</span>
            </div>
          ))}
        </div>
      )}

      {pFindings.length > 0 && (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="bug" size={13} color="#e8574a" />Vulnerabilities
          </div>
          {/* Severity summary */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
            {SEV_ORDER.map(s => {
              const cnt = pFindings.filter(f => f.severity === s).length;
              if (!cnt) return null;
              const sv = SEVERITY[s];
              return (
                <div key={s} style={{ background: sv.color + '18', border: `1px solid ${sv.color}44`, borderRadius: 6, padding: '6px 12px', textAlign: 'center' }}>
                  <div style={{ fontSize: 18, fontWeight: 700, color: sv.color, fontFamily: 'Space Grotesk' }}>{cnt}</div>
                  <div style={{ fontSize: 9, color: sv.color + 'cc', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{sv.label}</div>
                </div>
              );
            })}
          </div>
          {pFindings.map(f => {
            const sv = SEVERITY[f.severity] || SEVERITY.info;
            const st = FINDING_STATUS[f.status] || FINDING_STATUS.open;
            const linkedHost = hosts.find(h => h.id === f.host_id);
            return (
              <div key={f.id} style={{ padding: '10px 0', borderBottom: '1px solid #14161b' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 9, fontWeight: 700, color: sv.color, background: sv.color + '22', border: `1px solid ${sv.color}55`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{sv.label}</span>
                  <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec', flex: 1 }}>{f.title}</span>
                  <span style={{ fontSize: 9, color: st.color, background: st.color + '18', border: `1px solid ${st.color}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{st.label}</span>
                </div>
                <div style={{ display: 'flex', gap: 12, marginBottom: 4 }}>
                  {f.cvss && <span style={{ fontSize: 10, color: '#808590', fontFamily: 'JetBrains Mono' }}>CVSS: {f.cvss}</span>}
                  {f.cve && <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: 'JetBrains Mono' }}>{f.cve}</span>}
                  {linkedHost && <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{linkedHost.ip}</span>}
                </div>
                {f.description && <div style={{ fontSize: 11, color: '#808590', lineHeight: 1.5 }}>{f.description.slice(0, 200)}{f.description.length > 200 ? '...' : ''}</div>}
              </div>
            );
          })}
        </div>
      )}

      {pActivities.length > 0 && (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: 18, marginTop: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="terminal" size={13} color={accent} />Host activity log
          </div>
          {pActivities.slice(0, 12).map(a => {
            const host = hosts.find(h => h.id === a.host_id);
            return (
              <div key={a.id} style={{ padding: '10px 0', borderBottom: '1px solid #14161b' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 8, color: accent, background: accent + '18', border: `1px solid ${accent}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{a.activity_type}</span>
                  <span style={{ fontSize: 8, color: '#808590', background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono', textTransform: 'uppercase' }}>{a.status}</span>
                  {host && <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: 'JetBrains Mono' }}>{host.ip}{host.hostname ? ` (${host.hostname})` : ''}</span>}
                  <span style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', marginLeft: 'auto' }}>{a.ts}</span>
                </div>
                <div style={{ fontSize: 11, color: '#e0e4ec', fontWeight: 600, marginBottom: 3 }}>{a.title || 'Untitled activity'}</div>
                {a.command && <div style={{ fontSize: 10, color: '#9098a8', fontFamily: 'JetBrains Mono', marginBottom: 3, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{a.command}</div>}
                {a.summary && <div style={{ fontSize: 10, color: '#808590', lineHeight: 1.5 }}>{a.summary}</div>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
