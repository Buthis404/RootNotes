import { useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';

function MfaForm({ accent, inp, loading, totpCode, setTotpCode, error, onSubmit, onBack }) {
  return (
    <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: `${accent}11`, border: `1px solid ${accent}33`, borderRadius: 6, padding: '10px 14px', fontSize: 11, color: accent, lineHeight: 1.6 }}>
        Open your authenticator app and enter the 6-digit code.
      </div>
      <div>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Authenticator code</div>
        <input
          style={{ ...inp, letterSpacing: '0.2em', fontSize: 18, textAlign: 'center' }}
          value={totpCode}
          onChange={e => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          placeholder="000000"
          autoFocus
          autoComplete="one-time-code"
          inputMode="numeric"
          maxLength={6}
        />
      </div>
      {error && (
        <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '8px 12px', fontSize: 11, color: '#cc2233' }}>{error}</div>
      )}
      <button type="submit" disabled={loading || totpCode.length !== 6}
        style={{ background: loading || totpCode.length !== 6 ? '#1a1c22' : accent, border: 'none', borderRadius: 6, padding: '11px 0', cursor: loading ? 'wait' : 'pointer', color: '#fff', fontSize: 12, fontWeight: 700, fontFamily: 'JetBrains Mono', marginTop: 4, transition: 'background .15s' }}>
        {loading ? 'Verifying...' : 'Verify'}
      </button>
      <button type="button" onClick={onBack}
        style={{ background: 'none', border: 'none', color: '#505560', fontSize: 11, cursor: 'pointer', fontFamily: 'JetBrains Mono' }}>
        ← Back to login
      </button>
    </form>
  );
}
MfaForm.propTypes = { accent: PropTypes.string, inp: PropTypes.object, loading: PropTypes.bool, totpCode: PropTypes.string, setTotpCode: PropTypes.func, error: PropTypes.string, onSubmit: PropTypes.func, onBack: PropTypes.func };

function CredForm({ accent, inp, isFirstRun, loading, username, setUsername, password, setPassword, error, onSubmit }) {
  return (
    <>
      {isFirstRun && (
        <div style={{ background: `${accent}11`, border: `1px solid ${accent}33`, borderRadius: 6, padding: '10px 14px', marginBottom: 22, fontSize: 11, color: accent, lineHeight: 1.6 }}>
          First launch — create an administrator account.
        </div>
      )}
      <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Login</div>
          <input style={inp} value={username} onChange={e => setUsername(e.target.value)} placeholder="username" autoFocus autoComplete="username" />
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Password</div>
          <input style={inp} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" autoComplete={isFirstRun ? 'new-password' : 'current-password'} />
        </div>
        {error && (
          <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '8px 12px', fontSize: 11, color: '#cc2233' }}>{error}</div>
        )}
        <button type="submit" disabled={loading || !username.trim() || !password}
          style={{ background: loading || !username.trim() || !password ? '#1a1c22' : accent, border: 'none', borderRadius: 6, padding: '11px 0', cursor: loading ? 'wait' : 'pointer', color: '#fff', fontSize: 12, fontWeight: 700, fontFamily: 'JetBrains Mono', marginTop: 4, transition: 'background .15s' }}>
          {(() => { if (loading) { return 'Please wait...'; } if (isFirstRun) { return 'Create administrator account'; } return 'Sign in'; })()}
        </button>
      </form>
    </>
  );
}
CredForm.propTypes = { accent: PropTypes.string, inp: PropTypes.object, isFirstRun: PropTypes.bool, loading: PropTypes.bool, username: PropTypes.string, setUsername: PropTypes.func, password: PropTypes.string, setPassword: PropTypes.func, error: PropTypes.string, onSubmit: PropTypes.func };

export default function LoginView({ accent, isFirstRun, onAuth, sessionExpired }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // MFA step state
  const [mfaToken, setMfaToken] = useState(null);
  const [totpCode, setTotpCode] = useState('');

  const submitCredentials = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      return;
    }
    setError(''); setLoading(true);
    try {
      const res = isFirstRun
        ? await api.authSetup({ username: username.trim(), password })
        : await api.authLogin({ username: username.trim(), password });
      if (res.mfa_required) {
        setMfaToken(res.mfa_token);
      } else {
        onAuth(res.user);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const submitMfa = async (e) => {
    e.preventDefault();
    if (!totpCode.trim()) {
      return;
    }
    setError(''); setLoading(true);
    try {
      const res = await api.authMfaVerify({ mfa_token: mfaToken, code: totpCode.trim() });
      onAuth(res.user);
    } catch (err) {
      setError(err.message);
      setTotpCode('');
    } finally {
      setLoading(false);
    }
  };

  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '10px 12px', color: '#c8cdd6', fontSize: 13, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#08090b', position: 'relative', overflow: 'hidden' }}>
      {/* Subtle grid bg */}
      <div style={{ position: 'absolute', inset: 0, backgroundImage: `linear-gradient(${accent}08 1px, transparent 1px), linear-gradient(90deg, ${accent}08 1px, transparent 1px)`, backgroundSize: '40px 40px', pointerEvents: 'none' }} />

      <div style={{ width: 400, position: 'relative', zIndex: 1 }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 36, justifyContent: 'center' }}>
          <div style={{ width: 48, height: 48, borderRadius: 12, background: `${accent}18`, border: `1px solid ${accent}44`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Icon name="shield" size={24} color={accent} />
          </div>
          <div>
            <div style={{ fontSize: 22, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>RootNotes</div>
            <div style={{ fontSize: 11, color: '#404550', fontFamily: 'JetBrains Mono' }}>
              {(() => { if (mfaToken) { return 'two-factor authentication'; } if (isFirstRun) { return 'initial setup'; } return 'sign in'; })()}
            </div>
          </div>
        </div>

        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 12, padding: '32px 36px', boxShadow: '0 24px 64px #00000088' }}>
          {sessionExpired && !mfaToken && (
            <div style={{ background: '#c8820011', border: '1px solid #c8820044', borderRadius: 6, padding: '8px 12px', marginBottom: 18, fontSize: 11, color: '#c88200', fontFamily: 'JetBrains Mono' }}>
              Session expired — please sign in again
            </div>
          )}
          {mfaToken ? (
            <MfaForm accent={accent} inp={inp} loading={loading} totpCode={totpCode} setTotpCode={setTotpCode}
              error={error} onSubmit={submitMfa}
              onBack={() => { setMfaToken(null); setError(''); setTotpCode(''); }} />
          ) : (
            <CredForm accent={accent} inp={inp} isFirstRun={isFirstRun} loading={loading}
              username={username} setUsername={setUsername} password={password} setPassword={setPassword}
              error={error} onSubmit={submitCredentials} />
          )}
        </div>

        <div style={{ textAlign: 'center', marginTop: 18, fontSize: 10, color: '#303540', fontFamily: 'JetBrains Mono' }}>
          RootNotes · secured access
        </div>
      </div>
    </div>
  );
}
LoginView.propTypes = { accent: PropTypes.string, isFirstRun: PropTypes.bool, onAuth: PropTypes.func, sessionExpired: PropTypes.bool };
