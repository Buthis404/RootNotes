import { useState } from 'react';
import Icon from '../components/Icon.jsx';
import { isAttackerHost } from '../utils/hostMeta.js';
import { ACCENT_PRESETS, TWEAK_DEFAULTS } from './uiConstants.js';

const statusColor = { active: '#39d353', paused: '#f09a3a', done: '#555' };

export function NavTab({ tab, active, onClick, accent, badge, expanded }) {
  const [hov, setHov] = useState(false);
  return (
    <button onClick={onClick} onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)} title={tab.label}
      style={{ width: '100%', padding: '12px 14px', border: 'none', cursor: 'pointer', background: active ? `${accent}18` : hov ? '#ffffff08' : 'transparent', borderLeft: active ? `2px solid ${accent}` : '2px solid transparent', display: 'flex', flexDirection: expanded ? 'row' : 'column', alignItems: 'center', justifyContent: expanded ? 'flex-start' : 'center', gap: 10, transition: 'all .15s', position: 'relative' }}>
      <Icon name={tab.icon} size={20} color={active ? accent : hov ? '#9098a8' : '#404550'} />
      {expanded && <span style={{ fontSize: 10, color: active ? accent : hov ? '#9098a8' : '#606570', letterSpacing: '0.04em', textTransform: 'uppercase', fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{tab.label}</span>}
      {badge > 0 && <span style={{ position: 'absolute', top: 10, right: 10, background: accent, color: '#fff', fontSize: 9, fontWeight: 700, borderRadius: '50%', width: 16, height: 16, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{badge > 9 ? '9+' : badge}</span>}
    </button>
  );
}

export function ProjectPicker({ projects, hosts, selected, onSelect, accent }) {
  return (
    <div style={{ padding: '10px 0' }}>
      <div style={{ padding: '6px 14px 10px', fontSize: 9, color: '#353840', letterSpacing: '0.14em', textTransform: 'uppercase' }}>Active target</div>
      {projects.map(p => {
        const act = p.id === selected;
        const sc = statusColor[p.status] || '#555';
        const pwned = hosts.filter(h => h.pid === p.id && !isAttackerHost(h) && (h.status === 'pwned' || h.status === 'owned')).length;
        return (
          <div key={p.id} onClick={() => onSelect(p.id)}
            style={{ padding: '10px 14px', cursor: 'pointer', background: act ? `${accent}18` : 'transparent', borderLeft: act ? `2px solid ${accent}` : '2px solid transparent', transition: 'all .12s' }}
            onMouseEnter={e => !act && (e.currentTarget.style.background = '#ffffff08')}
            onMouseLeave={e => !act && (e.currentTarget.style.background = 'transparent')}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: sc, boxShadow: `0 0 6px ${sc}`, flexShrink: 0 }} />
              <span style={{ fontSize: 13, color: act ? '#f0f2f6' : '#9098a8', fontWeight: act ? 600 : 400, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.name}</span>
            </div>
            <div style={{ display: 'flex', gap: 8, paddingLeft: 17, alignItems: 'center', minWidth: 0 }}>
              <span style={{ fontSize: 11, color: '#404550', fontFamily: 'JetBrains Mono', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.ip}</span>
              {pwned > 0 && <span style={{ fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono', fontWeight: 600, flexShrink: 0, whiteSpace: 'nowrap' }}>⚠ {pwned} pwned</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function TweaksPanel({ tweaks, updateTweak, onClose, left }) {
  const acc = tweaks.accent;
  const fs = tweaks.fontSize;
  return (
    <div style={{ position: 'fixed', bottom: 70, left, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 8, padding: 18, width: 280, zIndex: 300, boxShadow: '0 8px 40px #00000099' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', letterSpacing: '0.04em', textTransform: 'uppercase' }}>Interface settings</span>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={12} color="#606570" /></button>
      </div>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 9, color: '#505560', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Accent color</div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
          {ACCENT_PRESETS.map(c => (
            <button key={c} onClick={() => updateTweak('accent', c)} style={{ width: 22, height: 22, borderRadius: 4, background: c, border: `2px solid ${acc === c ? '#fff' : c}`, cursor: 'pointer', transition: 'transform .1s', transform: acc === c ? 'scale(1.2)' : 'scale(1)' }} />
          ))}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input type="color" value={acc} onChange={e => updateTweak('accent', e.target.value)} style={{ width: 36, height: 28, border: '1px solid #2a2d35', borderRadius: 4, cursor: 'pointer', padding: 2, background: '#1a1c22' }} />
          <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{acc}</span>
        </div>
      </div>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 9, color: '#505560', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Success color</div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input type="color" value={tweaks.accentGreen} onChange={e => updateTweak('accentGreen', e.target.value)} style={{ width: 36, height: 28, border: '1px solid #2a2d35', borderRadius: 4, cursor: 'pointer', padding: 2, background: '#1a1c22' }} />
          <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>{tweaks.accentGreen}</span>
        </div>
      </div>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 9, color: '#505560', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between' }}>
          <span>Font size</span>
          <span style={{ color: acc, fontFamily: 'JetBrains Mono' }}>{fs}px</span>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          {[12, 14, 16, 18, 20].map(s => (
            <button key={s} onClick={() => updateTweak('fontSize', s)} style={{ flex: 1, background: fs === s ? `${acc}22` : '#1a1c22', border: `1px solid ${fs === s ? acc + '66' : '#2a2d35'}`, borderRadius: 3, padding: '3px 0', cursor: 'pointer', color: fs === s ? acc : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
              {s}
            </button>
          ))}
        </div>
      </div>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 9, color: '#505560', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Network map animation</div>
        <button onClick={() => updateTweak('networkMapAnimations', !tweaks.networkMapAnimations)} style={{ width: '100%', background: tweaks.networkMapAnimations ? `${acc}22` : '#1a1c22', border: `1px solid ${tweaks.networkMapAnimations ? acc + '66' : '#2a2d35'}`, borderRadius: 4, padding: '7px 10px', cursor: 'pointer', color: tweaks.networkMapAnimations ? acc : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', textAlign: 'left' }}>
          {tweaks.networkMapAnimations ? 'Enabled: dashed and animated' : 'Disabled: solid lines'}
        </button>
      </div>
      <button onClick={() => { updateTweak('accent', TWEAK_DEFAULTS.accent); updateTweak('accentGreen', TWEAK_DEFAULTS.accentGreen); updateTweak('fontSize', TWEAK_DEFAULTS.fontSize); }} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 12px', cursor: 'pointer', color: '#505560', fontSize: 9, fontFamily: 'JetBrains Mono', width: '100%', marginTop: 4 }}>
        Reset to defaults
      </button>
    </div>
  );
}
