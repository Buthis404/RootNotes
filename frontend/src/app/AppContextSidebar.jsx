import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { TABS } from '../constants.js';
import { ProjectPicker } from './AppChrome.jsx';
import { isAttackerHost } from '../utils/hostMeta.js';

export default function AppContextSidebar({
  tab,
  projects, notes, hosts, creds,
  selectedProject, onSelectProject,
  accent,
  presence,
}) {
  const acc = accent;

  if (tab === 'projects' || tab === 'user-settings') return null;

  return (
    <div style={{ width: 200, background: '#0c0e13', borderRight: '1px solid #1a1c22', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
      <div style={{ padding: '14px 14px 10px', borderBottom: '1px solid #151720' }}>
        <div style={{ fontSize: 10, color: '#353840', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 7 }}>RootNotes</div>
        <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>
          {TABS.find(t => t.id === tab)?.label}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        <ProjectPicker
          projects={projects}
          hosts={hosts.filter(h => !isAttackerHost(h))}
          selected={selectedProject}
          onSelect={onSelectProject}
          accent={acc}
        />
      </div>

      <div style={{ borderTop: '1px solid #151720', padding: '12px 14px' }}>
        {[
          ['notes', notes.filter(n => n.pid === selectedProject).length, 'notes'],
          ['hosts', hosts.filter(h => h.pid === selectedProject && !isAttackerHost(h)).length, 'hosts'],
          ['creds', creds.filter(c => c.pid === selectedProject).length, 'creds'],
        ].map(([icon, val, label]) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              <Icon name={icon} size={11} color="#353840" />
              <span style={{ fontSize: 11, color: '#404550' }}>{label}</span>
            </div>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#606570', fontFamily: 'JetBrains Mono' }}>{val}</span>
          </div>
        ))}

        {presence.length > 0 && (
          <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #151720' }}>
            <div style={{ fontSize: 9, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 7 }}>In project now</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
              {presence.map(u => (
                <div key={u.name} title={u.note_id ? `${u.name} — editing a note` : u.name}
                  style={{ display: 'flex', alignItems: 'center', gap: 5, background: '#0e1016', border: `1px solid ${acc}33`, borderRadius: 12, padding: '3px 8px 3px 4px' }}>
                  <div style={{ width: 18, height: 18, borderRadius: '50%', background: `${acc}22`, border: `1px solid ${acc}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, fontWeight: 700, color: acc, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
                    {u.name.slice(0, 2).toUpperCase()}
                  </div>
                  <span style={{ fontSize: 10, color: '#808590', fontFamily: 'JetBrains Mono' }}>{u.name}</span>
                  {u.note_id && <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#f09a3a', flexShrink: 0 }} title="Editing a note" />}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

AppContextSidebar.propTypes = {
  tab: PropTypes.string,
  projects: PropTypes.array,
  notes: PropTypes.array,
  hosts: PropTypes.array,
  creds: PropTypes.array,
  selectedProject: PropTypes.any,
  onSelectProject: PropTypes.func,
  accent: PropTypes.string,
  presence: PropTypes.array,
};
