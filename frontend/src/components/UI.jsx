import { useState } from 'react';
import Icon from './Icon.jsx';
import { NODE_STATUS, CRED_TYPES, PHASE_COLORS } from '../constants.js';

export const StatusDot = ({ status }) => {
  const c = { active: '#39d353', paused: '#f09a3a', done: '#555' }[status] || '#555';
  return <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: c, boxShadow: `0 0 6px ${c}`, flexShrink: 0 }} />;
};

export const PhaseTag = ({ phase, small }) => {
  const c = PHASE_COLORS[phase] || '#888';
  return (
    <span style={{ fontSize: small ? 9 : 10, fontFamily: 'JetBrains Mono', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', padding: small ? '1px 5px' : '2px 7px', borderRadius: 3, border: `1px solid ${c}55`, color: c, background: `${c}11`, whiteSpace: 'nowrap' }}>
      {phase}
    </span>
  );
};

export const Badge = ({ label, color = '#404550', bg }) => (
  <span style={{ fontSize: 9, fontFamily: 'JetBrains Mono', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', padding: '1px 6px', borderRadius: 3, border: `1px solid ${color}55`, color, background: bg || `${color}11`, whiteSpace: 'nowrap' }}>
    {label}
  </span>
);

export const HostStatusBadge = ({ status }) => {
  const { color, label } = NODE_STATUS[status] || { color: '#404550', label: '?' };
  return <Badge label={label} color={color} />;
};

export const CredTypeBadge = ({ type }) => {
  const { color, label } = CRED_TYPES[type] || { color: '#404550', label: type };
  return <Badge label={label} color={color} />;
};

export const Btn = ({ children, onClick, variant = 'ghost', icon, style = {} }) => {
  const [hov, setHov] = useState(false);
  const base = { border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, transition: 'all .12s', fontWeight: 600, ...style };
  const variants = {
    primary: { background: '#cc2233', color: '#fff', opacity: hov ? .85 : 1 },
    ghost:   { background: hov ? '#ffffff0e' : 'transparent', border: '1px solid ' + (hov ? '#404550' : '#2a2d35'), color: hov ? '#c0c5d0' : '#808590' },
    danger:  { background: hov ? '#cc223322' : 'transparent', border: '1px solid ' + (hov ? '#cc2233' : '#2a2d35'), color: hov ? '#cc2233' : '#606570' },
  };
  return (
    <button onClick={onClick} style={{ ...base, ...variants[variant] }} onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}>
      {icon && <Icon name={icon} size={11} color="currentColor" />}
      {children}
    </button>
  );
};

export const SearchBar = ({ value, onChange, placeholder = 'Search...' }) => (
  <div style={{ position: 'relative' }}>
    <Icon name="search" size={12} color="#404550" style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)' }} />
    <input
      value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      style={{ width: '100%', background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 5, padding: '6px 8px 6px 28px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}
      onFocus={e => e.target.style.borderColor = '#3a3d48'}
      onBlur={e => e.target.style.borderColor = '#2a2d35'}
    />
  </div>
);

export const FieldInput = ({ label, value, onChange, placeholder, mono = true, textarea = false }) => (
  <div>
    <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
    {textarea
      ? <textarea value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} rows={3}
          style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: mono ? 'JetBrains Mono' : 'Space Grotesk', resize: 'vertical' }} />
      : <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
          style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: mono ? 'JetBrains Mono' : 'Space Grotesk' }} />
    }
  </div>
);

export const TagEditor = ({ label, tags = [], onChange, placeholder = 'add tag' }) => {
  const [draft, setDraft] = useState('');
  const addTag = () => {
    const next = draft.trim();
    if (!next) return;
    onChange([...new Set([...(tags || []), next])]);
    setDraft('');
  };
  const removeTag = (tag) => onChange((tags || []).filter(t => t !== tag));

  return (
    <div>
      <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
        {(tags || []).map(tag => (
          <span key={tag} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 9, fontFamily: 'JetBrains Mono', padding: '2px 6px', borderRadius: 4, border: '1px solid #2a2d35', color: '#9098a8', background: '#0a0c10' }}>
            {tag}
            <button onClick={() => removeTag(tag)} style={{ background: 'none', border: 'none', color: '#606570', cursor: 'pointer', padding: 0, display: 'flex', alignItems: 'center' }}>
              <Icon name="close" size={9} color="currentColor" />
            </button>
          </span>
        ))}
        {(tags || []).length === 0 && <span style={{ fontSize: 10, color: '#404550', fontStyle: 'italic' }}>No tags</span>}
      </div>
      <div style={{ display: 'flex', gap: 6 }}>
        <input value={draft} onChange={e => setDraft(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag(); } }} placeholder={placeholder}
          style={{ flex: 1, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }} />
        <button onClick={addTag} style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Add</button>
      </div>
    </div>
  );
};
