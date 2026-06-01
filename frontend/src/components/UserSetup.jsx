import { useState } from 'react';
import PropTypes from 'prop-types';
import Icon from './Icon.jsx';

export default function UserSetup({ accent, onSave }) {
  const [name, setName] = useState('');

  const submit = () => {
    const trimmed = name.trim();
    if (!trimmed) return;
    onSave(trimmed);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000cc', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: `1px solid ${accent}44`, borderRadius: 12, padding: '32px 36px', width: 380, boxShadow: `0 24px 64px #00000099, 0 0 0 1px ${accent}22` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
          <div style={{ width: 40, height: 40, borderRadius: '50%', background: `${accent}18`, border: `1px solid ${accent}44`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Icon name="shield" size={18} color={accent} />
          </div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Identify yourself</div>
            <div style={{ fontSize: 11, color: '#505560', marginTop: 2 }}>for multiplayer mode</div>
          </div>
        </div>

        <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Your callsign / name</div>
        <input
          autoFocus
          value={name}
          onChange={e => setName(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && submit()}
          placeholder="e.g. r00t, analyst_01..."
          maxLength={32}
          style={{ width: '100%', background: '#0a0c10', border: `1px solid ${accent}44`, borderRadius: 6, padding: '9px 12px', color: '#c8cdd6', fontSize: 13, outline: 'none', fontFamily: 'JetBrains Mono', marginBottom: 20, boxSizing: 'border-box' }}
        />

        <button
          onClick={submit}
          disabled={!name.trim()}
          style={{ width: '100%', background: name.trim() ? accent : '#1a1c22', border: 'none', borderRadius: 6, padding: '10px 0', cursor: name.trim() ? 'pointer' : 'not-allowed', color: name.trim() ? '#fff' : '#404550', fontSize: 12, fontWeight: 600, fontFamily: 'JetBrains Mono', transition: 'all .15s' }}
        >
          Join session
        </button>
      </div>
    </div>
  );
}

UserSetup.propTypes = {
  accent: PropTypes.string,
  onSave: PropTypes.func,
};
