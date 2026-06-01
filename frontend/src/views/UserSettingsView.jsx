import PropTypes from 'prop-types';
import { useState, useEffect, useRef } from 'react';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';

function MfaSetupPanel({ mfaQr, mfaSecret, mfaCode, setMfaCode, mfaState, accent, qrCanvasRef, onConfirm, onCancel }) {
  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '9px 12px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ fontSize: 11, color: '#8090a0', lineHeight: 1.6 }}>
        Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.), then enter the 6-digit code below.
      </div>
      <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start' }}>
        <canvas ref={qrCanvasRef} style={{ borderRadius: 6, border: '1px solid #2a2d35' }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Manual entry key</div>
          <div style={{ background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 12px', fontFamily: 'JetBrains Mono', fontSize: 11, color: '#c8cdd6', wordBreak: 'break-all', letterSpacing: '0.08em' }}>{mfaSecret}</div>
        </div>
      </div>
      <div>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Verification code</div>
        <input style={{ ...inp, letterSpacing: '0.2em', fontSize: 16, textAlign: 'center', maxWidth: 160 }}
          value={mfaCode} onChange={e => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          placeholder="000000" autoFocus inputMode="numeric" maxLength={6} />
      </div>
      {mfaState.message && <div style={{ fontSize: 11, color: mfaState.type === 'error' ? '#cc2233' : '#39d353' }}>{mfaState.message}</div>}
      <div style={{ display: 'flex', gap: 10 }}>
        <button onClick={onConfirm} disabled={mfaState.saving || mfaCode.length !== 6}
          style={{ background: accent, border: 'none', borderRadius: 6, padding: '9px 14px', cursor: mfaState.saving ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: mfaCode.length === 6 ? 1 : 0.6 }}>
          {mfaState.saving ? 'Verifying...' : 'Enable MFA'}
        </button>
        <button onClick={onCancel}
          style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 6, padding: '9px 14px', cursor: 'pointer', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          Cancel
        </button>
      </div>
    </div>
  );
}

MfaSetupPanel.propTypes = {
  mfaQr: PropTypes.string,
  mfaSecret: PropTypes.string,
  mfaCode: PropTypes.string,
  setMfaCode: PropTypes.func,
  mfaState: PropTypes.object,
  accent: PropTypes.string,
  qrCanvasRef: PropTypes.object,
  onConfirm: PropTypes.func,
  onCancel: PropTypes.func,
};

function MfaDisablePanel({ mfaCode, setMfaCode, mfaState, onConfirm, onCancel }) {
  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '9px 12px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ fontSize: 11, color: '#8090a0', lineHeight: 1.6 }}>
        Enter your authenticator code to confirm disabling MFA.
      </div>
      <div>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Authenticator code</div>
        <input style={{ ...inp, letterSpacing: '0.2em', fontSize: 16, textAlign: 'center', maxWidth: 160 }}
          value={mfaCode} onChange={e => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          placeholder="000000" autoFocus inputMode="numeric" maxLength={6} />
      </div>
      {mfaState.message && <div style={{ fontSize: 11, color: mfaState.type === 'error' ? '#cc2233' : '#39d353' }}>{mfaState.message}</div>}
      <div style={{ display: 'flex', gap: 10 }}>
        <button onClick={onConfirm} disabled={mfaState.saving || mfaCode.length !== 6}
          style={{ background: '#cc2233', border: 'none', borderRadius: 6, padding: '9px 14px', cursor: mfaState.saving ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: mfaCode.length === 6 ? 1 : 0.6 }}>
          {mfaState.saving ? 'Disabling...' : 'Disable MFA'}
        </button>
        <button onClick={onCancel}
          style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 6, padding: '9px 14px', cursor: 'pointer', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          Cancel
        </button>
      </div>
    </div>
  );
}

MfaDisablePanel.propTypes = {
  mfaCode: PropTypes.string,
  setMfaCode: PropTypes.func,
  mfaState: PropTypes.object,
  onConfirm: PropTypes.func,
  onCancel: PropTypes.func,
};

function MfaIdlePanel({ mfaEnabled, mfaState, accent, onStartSetup, onStartDisable }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ fontSize: 11, color: '#8090a0', lineHeight: 1.6 }}>
        {mfaEnabled
          ? 'MFA is active. Each login requires a 6-digit code from your authenticator app.'
          : 'Add a second factor to your account. You will need an authenticator app (Google Authenticator, Authy, etc.).'}
      </div>
      {mfaState.message && <div style={{ fontSize: 11, color: mfaState.type === 'error' ? '#cc2233' : '#39d353' }}>{mfaState.message}</div>}
      {mfaEnabled ? (
        <button onClick={onStartDisable}
          style={{ background: '#1a1c22', border: '1px solid #cc233344', borderRadius: 6, padding: '9px 14px', cursor: 'pointer', color: '#cc4444', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', alignSelf: 'flex-start' }}>
          Disable MFA
        </button>
      ) : (
        <button onClick={onStartSetup} disabled={mfaState.saving}
          style={{ background: accent, border: 'none', borderRadius: 6, padding: '9px 14px', cursor: mfaState.saving ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', alignSelf: 'flex-start' }}>
          {mfaState.saving ? 'Loading...' : 'Set up MFA'}
        </button>
      )}
    </div>
  );
}

MfaIdlePanel.propTypes = {
  mfaEnabled: PropTypes.bool,
  mfaState: PropTypes.object,
  accent: PropTypes.string,
  onStartSetup: PropTypes.func,
  onStartDisable: PropTypes.func,
};

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

Section.propTypes = {
  title: PropTypes.string,
  children: PropTypes.node,
  action: PropTypes.node,
};

export default function UserSettingsView({ accent, currentUser, onUserUpdated }) {
  const [displayName, setDisplayName] = useState(currentUser?.display_name || currentUser?.username || '');
  const [profileState, setProfileState] = useState({ saving: false, type: '', message: '' });
  const [passwords, setPasswords] = useState({ current: '', next: '', confirm: '' });
  const [passwordState, setPasswordState] = useState({ saving: false, type: '', message: '' });

  // MFA state
  const [mfaEnabled, setMfaEnabled] = useState(currentUser?.mfa_enabled || false);
  const [mfaStep, setMfaStep] = useState(null); // null | 'setup' | 'disable'
  const [mfaQr, setMfaQr] = useState(null);     // DataURL for QR code
  const [mfaSecret, setMfaSecret] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaState, setMfaState] = useState({ saving: false, type: '', message: '' });
  const qrCanvasRef = useRef(null);

  useEffect(() => {
    if (!mfaQr || !qrCanvasRef.current) return;
    import('qrcode').then(QRCode => {
      QRCode.toCanvas(qrCanvasRef.current, mfaQr, { width: 200, margin: 1, color: { dark: '#f0f2f6', light: '#0d0f14' } });
    });
  }, [mfaQr]);

  const startMfaSetup = async () => {
    setMfaState({ saving: true, type: '', message: '' });
    try {
      const res = await api.authMfaSetup();
      setMfaQr(res.uri);
      setMfaSecret(res.secret);
      setMfaStep('setup');
      setMfaCode('');
      setMfaState({ saving: false, type: '', message: '' });
    } catch (err) {
      setMfaState({ saving: false, type: 'error', message: err.message || 'Failed to start MFA setup' });
    }
  };

  const confirmMfaEnable = async () => {
    if (mfaCode.length !== 6) return;
    setMfaState({ saving: true, type: '', message: '' });
    try {
      await api.authMfaEnable({ code: mfaCode });
      setMfaEnabled(true);
      setMfaStep(null);
      setMfaCode('');
      setMfaQr(null);
      setMfaSecret('');
      setMfaState({ saving: false, type: 'success', message: 'MFA enabled successfully' });
      if (onUserUpdated) onUserUpdated({ ...currentUser, mfa_enabled: true });
    } catch (err) {
      setMfaState({ saving: false, type: 'error', message: err.message || 'Invalid code' });
      setMfaCode('');
    }
  };

  const confirmMfaDisable = async () => {
    if (mfaCode.length !== 6) return;
    setMfaState({ saving: true, type: '', message: '' });
    try {
      await api.authMfaDisable({ code: mfaCode });
      setMfaEnabled(false);
      setMfaStep(null);
      setMfaCode('');
      setMfaState({ saving: false, type: 'success', message: 'MFA disabled' });
      if (onUserUpdated) onUserUpdated({ ...currentUser, mfa_enabled: false });
    } catch (err) {
      setMfaState({ saving: false, type: 'error', message: err.message || 'Invalid code' });
      setMfaCode('');
    }
  };

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

        <Section title="Two-Factor Authentication" action={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: mfaEnabled ? '#39d353' : '#505560' }} />
            <span style={{ fontSize: 11, color: mfaEnabled ? '#39d353' : '#505560', fontFamily: 'JetBrains Mono' }}>{mfaEnabled ? 'enabled' : 'disabled'}</span>
          </div>
        }>
          {mfaStep == 'setup' && (
            <MfaSetupPanel
              mfaQr={mfaQr}
              mfaSecret={mfaSecret}
              mfaCode={mfaCode}
              setMfaCode={setMfaCode}
              mfaState={mfaState}
              accent={accent}
              qrCanvasRef={qrCanvasRef}
              onConfirm={confirmMfaEnable}
              onCancel={() => { setMfaStep(null); setMfaCode(''); setMfaQr(null); setMfaSecret(''); setMfaState({ saving: false, type: '', message: '' }); }}
            />
          )}
          {mfaStep == 'disable' && (
            <MfaDisablePanel
              mfaCode={mfaCode}
              setMfaCode={setMfaCode}
              mfaState={mfaState}
              onConfirm={confirmMfaDisable}
              onCancel={() => { setMfaStep(null); setMfaCode(''); setMfaState({ saving: false, type: '', message: '' }); }}
            />
          )}
          {!mfaStep && (
            <MfaIdlePanel
              mfaEnabled={mfaEnabled}
              mfaState={mfaState}
              accent={accent}
              onStartSetup={startMfaSetup}
              onStartDisable={() => { setMfaStep('disable'); setMfaCode(''); setMfaState({ saving: false, type: '', message: '' }); }}
            />
          )}
        </Section>
      </div>
    </div>
  );
}

UserSettingsView.propTypes = {
  accent: PropTypes.string,
  currentUser: PropTypes.object,
  onUserUpdated: PropTypes.func,
};
