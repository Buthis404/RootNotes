import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { TABS, ADMIN_TAB } from '../constants.js';
import { NavTab } from './AppChrome.jsx';

function NavToggleBtn({ active, onClick, title, accent, expanded, iconName, label, shortcut }) {
  return (
    <button onClick={onClick} title={title}
      style={{ width: '100%', padding: expanded ? '14px 14px' : '14px 0', border: 'none', cursor: 'pointer', background: active ? `${accent}18` : 'transparent', borderLeft: active ? `2px solid ${accent}` : '2px solid transparent', display: 'flex', flexDirection: expanded ? 'row' : 'column', alignItems: 'center', justifyContent: expanded ? 'flex-start' : 'center', gap: 8, transition: 'all .15s' }}
      onMouseEnter={e => { if (!active) e.currentTarget.style.background = '#ffffff08'; }}
      onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}>
      <Icon name={iconName} size={expanded ? 20 : 18} color={active ? accent : '#404550'} />
      {expanded && <span style={{ fontSize: 9, color: active ? accent : '#606570', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 600, fontFamily: 'JetBrains Mono' }}>{label}</span>}
      {!expanded && shortcut && <span style={{ fontSize: 8, color: active ? accent : '#404550', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 600, fontFamily: 'JetBrains Mono' }}>{shortcut}</span>}
    </button>
  );
}

NavToggleBtn.propTypes = {
  active: PropTypes.bool,
  onClick: PropTypes.func,
  title: PropTypes.string,
  accent: PropTypes.string,
  expanded: PropTypes.bool,
  iconName: PropTypes.string,
  label: PropTypes.string,
  shortcut: PropTypes.string,
};

function NavUserSection({ currentUser, accent, navExpanded, setTab, onLogout }) {
  const initials = (currentUser?.display_name || currentUser?.username || '').slice(0, 2).toUpperCase();
  return (
    <div style={{ padding: navExpanded ? '10px 12px 6px' : '10px 0 6px', display: 'flex', flexDirection: navExpanded ? 'row' : 'column', alignItems: 'center', gap: 8 }}>
      <button onClick={() => setTab('user-settings')} title="User settings"
        style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, width: navExpanded ? '100%' : 'auto', padding: 0, textAlign: 'left' }}>
        <div style={{ width: 28, height: 28, borderRadius: '50%', background: `${accent}22`, border: `1px solid ${accent}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: accent, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
          {initials}
        </div>
        {navExpanded && (
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{currentUser?.display_name || currentUser?.username}</div>
            <div style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{currentUser?.username}</div>
          </div>
        )}
      </button>
      <button onClick={onLogout} title="Sign out"
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', fontSize: 9, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 3 }}
        onMouseEnter={e => { e.currentTarget.style.color = '#cc2233'; }}
        onMouseLeave={e => { e.currentTarget.style.color = '#303540'; }}>
        <Icon name="close" size={9} color="currentColor" /> {navExpanded ? 'logout' : ''}
      </button>
    </div>
  );
}

NavUserSection.propTypes = {
  currentUser: PropTypes.object,
  accent: PropTypes.string,
  navExpanded: PropTypes.bool,
  setTab: PropTypes.func,
  onLogout: PropTypes.func,
};

export default function AppNavBar({
  tab, setTab,
  accent,
  badges,
  navExpanded, setNavExpanded,
  showSearch, setShowSearch,
  showTweaks, setShowTweaks,
  currentUser,
  onLogout,
}) {
  const acc = accent;

  return (
    <div style={{ width: navExpanded ? 178 : 64, background: '#0a0b0f', borderRight: '1px solid #1a1c22', display: 'flex', flexDirection: 'column', flexShrink: 0, zIndex: 10, transition: 'width .18s' }}>
      {/* Logo */}
      <div style={{ padding: navExpanded ? '14px 12px 10px' : '14px 0 10px', display: 'flex', justifyContent: navExpanded ? 'flex-start' : 'center', alignItems: 'center', borderBottom: '1px solid #151720', gap: 8, position: 'relative' }}>
        <div style={{ width: 32, height: 32, background: `${acc}20`, border: `1px solid ${acc}55`, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <Icon name="shield" size={16} color={acc} />
        </div>
        {navExpanded && <span style={{ flex: 1, fontSize: 13, color: '#e0e4ec', fontFamily: 'Space Grotesk', fontWeight: 700 }}>RootNotes</span>}
      </div>

      {/* Tab list */}
      <div style={{ flex: 1, overflowY: 'auto', paddingTop: 4 }}>
        {TABS.map(t => (
          <NavTab key={t.id} tab={t} active={tab === t.id} onClick={() => setTab(t.id)}
            accent={acc} badge={badges[t.id]} expanded={navExpanded} />
        ))}
        {currentUser?.role === 'admin' && (
          <NavTab tab={ADMIN_TAB} active={tab === 'admin'} onClick={() => setTab('admin')}
            accent="#cc2233" expanded={navExpanded} />
        )}
      </div>

      {/* Bottom controls */}
      <div style={{ borderTop: '1px solid #151720', paddingBottom: 8 }}>
        <NavToggleBtn active={showSearch} onClick={() => setShowSearch(v => !v)} title="Search (Ctrl+K)"
          accent={acc} expanded={navExpanded} iconName="search" label="Search" shortcut="Ctrl+K" />
        <NavUserSection currentUser={currentUser} accent={acc} navExpanded={navExpanded} setTab={setTab} onLogout={onLogout} />
        <NavToggleBtn active={showTweaks} onClick={() => setShowTweaks(v => !v)} title="Tweaks"
          accent={acc} expanded={navExpanded} iconName="settings" label="Tweaks" />
        <button onClick={() => setNavExpanded(v => !v)} title={navExpanded ? 'Collapse sidebar' : 'Expand sidebar'}
          style={{ width: '100%', padding: navExpanded ? '14px 14px' : '14px 0', border: 'none', cursor: 'pointer', background: 'transparent', borderLeft: '2px solid transparent', display: 'flex', flexDirection: navExpanded ? 'row' : 'column', alignItems: 'center', justifyContent: navExpanded ? 'flex-start' : 'center', gap: 8, transition: 'all .15s', color: '#505560' }}
          onMouseEnter={e => { e.currentTarget.style.background = '#ffffff08'; e.currentTarget.style.color = '#9098a8'; }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#505560'; }}>
          <Icon name="chevron" size={20} color="currentColor" style={{ transform: navExpanded ? 'rotate(90deg)' : 'rotate(-90deg)' }} />
          {navExpanded && <span style={{ fontSize: 9, color: 'currentColor', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 600 }}>Collapse</span>}
        </button>
      </div>
    </div>
  );
}

AppNavBar.propTypes = {
  tab: PropTypes.string,
  setTab: PropTypes.func,
  accent: PropTypes.string,
  badges: PropTypes.object,
  navExpanded: PropTypes.bool,
  setNavExpanded: PropTypes.func,
  showSearch: PropTypes.bool,
  setShowSearch: PropTypes.func,
  showTweaks: PropTypes.bool,
  setShowTweaks: PropTypes.func,
  currentUser: PropTypes.object,
  onLogout: PropTypes.func,
};
