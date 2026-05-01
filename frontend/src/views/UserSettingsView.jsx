import { useState } from 'react';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';

function Section({ title, children, action = null }) {
  return (
    <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, padding: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>{title}</div>
        {action}
      </div>
      {children}
    </div>
  );
}

export default function UserSettingsView({ accent, currentUser, onUserUpdated }) {
  const [displayName, setDisplayName] = useState(currentUser?.display_name || currentUser?.username || '');
  const [profileState, setProfileState] = useState({ saving: false, type: '', message: '' });
  const [passwords, setPasswords] = useState({ current: '', next: '', confirm: '' });
  const [passwordState, setPasswordState] = useState({ saving: false, type: '', message: '' });

  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '9px 12px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

  const saveProfile = async () => {
    if (!displayName.trim()) {
      setProfileState({ saving: false, type: 'error', message: 'Display name cannot be empty' });
      return;
    }
    setProfileState({ saving: true, type: '', message: '' });
    try {
      const updated = await api.authUpdateMe({ display_name: displayName.trim() });
      onUserUpdated(updated);
      setProfileState({ saving: false, type: 'success', message: 'Profile updated' });
    } catch (err) {
      setProfileState({ saving: false, type: 'error', message: err.message || 'Failed to update profile' });
    }
  };

  const savePassword = async () => {
    if (passwords.next.length < 4) {
      setPasswordState({ saving: false, type: 'error', message: 'Minimum 4 characters' });
      return;
    }
    if (passwords.next !== passwords.confirm) {
      setPasswordState({ saving: false, type: 'error', message: 'Passwords do not match' });
      return;
    }
    setPasswordState({ saving: true, type: '', message: '' });
    try {
      await api.authChangePassword({ current_password: passwords.current, new_password: passwords.next });
      setPasswords({ current: '', next: '', confirm: '' });
      setPasswordState({ saving: false, type: 'success', message: 'Password updated' });
    } catch (err) {
      setPasswordState({ saving: false, type: 'error', message: err.message || 'Failed to change password' });
    }
  };

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>
      <div style={{ maxWidth: 760, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 18 }}>
        <div>
          <div style={{ fontSize: 10, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.14em', marginBottom: 6 }}>Account</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 4 }}>User Settings</div>
          <div style={{ fontSize: 12, color: '#606570' }}>Manage your display name and password.</div>
        </div>

        <Section title="Profile" action={<div style={{ fontSize: 11, color: '#505560', fontFamily: 'JetBrains Mono' }}>@{currentUser?.username}</div>}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
            <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Display name</div>
              <input style={inp} value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="Your name" />
            </div>
            <div>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Login</div>
              <input style={{ ...inp, color: '#606570' }} value={currentUser?.username || ''} disabled />
            </div>
          </div>
          {profileState.message && <div style={{ marginBottom: 12, fontSize: 11, color: profileState.type === 'error' ? '#cc2233' : '#39d353' }}>{profileState.message}</div>}
          <button onClick={saveProfile} disabled={profileState.saving}
            style={{ background: accent, border: 'none', borderRadius: 6, padding: '9px 14px', cursor: profileState.saving ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
            {profileState.saving ? 'Saving...' : 'Save profile'}
          </button>
        </Section>

        <Section title="Password" action={<Icon name="key" size={14} color={accent} />}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 12, marginBottom: 14 }}>
            {[
              ['Current password', 'current', 'current-password'],
              ['New password', 'next', 'new-password'],
              ['Confirm new password', 'confirm', 'new-password'],
            ].map(([label, key, autoComplete]) => (
              <div key={key}>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
                <input style={inp} type="password" autoComplete={autoComplete} value={passwords[key]} onChange={e => setPasswords(prev => ({ ...prev, [key]: e.target.value }))} />
              </div>
            ))}
          </div>
          {passwordState.message && <div style={{ marginBottom: 12, fontSize: 11, color: passwordState.type === 'error' ? '#cc2233' : '#39d353' }}>{passwordState.message}</div>}
          <button onClick={savePassword} disabled={passwordState.saving || !passwords.current || !passwords.next || !passwords.confirm}
            style={{ background: accent, border: 'none', borderRadius: 6, padding: '9px 14px', cursor: passwordState.saving ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: passwordState.saving || !passwords.current || !passwords.next || !passwords.confirm ? 0.7 : 1 }}>
            {passwordState.saving ? 'Saving...' : 'Change password'}
          </button>
        </Section>
      </div>
    </div>
  );
}
