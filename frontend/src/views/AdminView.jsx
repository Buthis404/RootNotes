import { useEffect, useState } from 'react';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';

const ROLE_COLOR = { admin: '#cc2233', user: '#5b8af5' };

function ConfirmDialog({ text, onConfirm, onCancel, accent }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 400, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #cc233344', borderRadius: 10, padding: '28px 32px', width: 360, boxShadow: '0 20px 60px #00000099' }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 12 }}>Confirm</div>
        <div style={{ fontSize: 12, color: '#808590', lineHeight: 1.6, marginBottom: 24 }}>{text}</div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onCancel} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
          <button onClick={onConfirm} style={{ background: '#cc2233', border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>Delete</button>
        </div>
      </div>
    </div>
  );
}

function CreateUserModal({ accent, onClose, onCreated }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('user');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!username.trim() || !password) return;
    setError(''); setLoading(true);
    try {
      const user = await api.adminCreateUser({ username: username.trim(), password, role });
      onCreated(user);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 400, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: '#0e1016', border: `1px solid ${accent}44`, borderRadius: 10, padding: '28px 32px', width: 380, boxShadow: '0 20px 60px #00000099' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>New user</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={14} color="#606570" /></button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {[['Login', username, setUsername, 'text', 'username'], ['Password', password, setPassword, 'password', 'new-password']].map(([label, val, set, type, ac]) => (
            <div key={label}>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
              <input style={inp} type={type} value={val} onChange={e => set(e.target.value)} autoComplete={ac} />
            </div>
          ))}
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Role</div>
            <div style={{ display: 'flex', gap: 6 }}>
              {['user', 'admin'].map(r => (
                <button key={r} onClick={() => setRole(r)}
                  style={{ flex: 1, background: role === r ? `${ROLE_COLOR[r]}22` : 'transparent', border: `1px solid ${role === r ? ROLE_COLOR[r] + '88' : '#2a2d35'}`, borderRadius: 5, padding: '6px 0', cursor: 'pointer', color: role === r ? ROLE_COLOR[r] : '#606570', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', transition: 'all .1s' }}>
                  {r === 'admin' ? 'Administrator' : 'User'}
                </button>
              ))}
            </div>
          </div>

          {error && <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '7px 10px', fontSize: 11, color: '#cc2233' }}>{error}</div>}

          <button onClick={submit} disabled={loading || !username.trim() || !password}
            style={{ background: username.trim() && password ? accent : '#1a1c22', border: 'none', borderRadius: 5, padding: '9px 0', cursor: 'pointer', color: '#fff', fontSize: 12, fontWeight: 700, fontFamily: 'JetBrains Mono', marginTop: 4, transition: 'background .15s' }}>
            {loading ? 'Creating...' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  );
}

function ResetPasswordModal({ user, accent, onClose }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (password.length < 4) { setError('Minimum 4 characters'); return; }
    if (password !== confirm) { setError('Passwords do not match'); return; }
    setError(''); setLoading(true);
    try {
      await api.adminUpdateUser(user.id, { password });
      setDone(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 400, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: '#0e1016', border: `1px solid ${accent}44`, borderRadius: 10, padding: '28px 32px', width: 360, boxShadow: '0 20px 60px #00000099' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Reset password</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={14} color="#606570" /></button>
        </div>
        <div style={{ fontSize: 11, color: '#606570', marginBottom: 18 }}>User: <span style={{ color: accent, fontFamily: 'JetBrains Mono' }}>{user.username}</span></div>

        {done ? (
          <div style={{ background: '#39d35322', border: '1px solid #39d35344', borderRadius: 5, padding: '12px', fontSize: 12, color: '#39d353', textAlign: 'center' }}>
            Password changed successfully
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[['New password', password, setPassword], ['Confirm', confirm, setConfirm]].map(([label, val, set]) => (
              <div key={label}>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
                <input style={inp} type="password" value={val} onChange={e => set(e.target.value)} />
              </div>
            ))}
            {error && <div style={{ fontSize: 11, color: '#cc2233' }}>{error}</div>}
            <button onClick={submit} disabled={loading}
              style={{ background: accent, border: 'none', borderRadius: 5, padding: '9px 0', cursor: 'pointer', color: '#fff', fontSize: 12, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
              {loading ? 'Saving...' : 'Set password'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function AdminView({ currentUser, accent, onlineUsers = [] }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [resetUser, setResetUser] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    try { setUsers(await api.adminListUsers()); } catch (e) { setError(e.message); } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const toggleRole = async (u) => {
    const newRole = u.role === 'admin' ? 'user' : 'admin';
    try {
      const updated = await api.adminUpdateUser(u.id, { role: newRole });
      setUsers(prev => prev.map(x => x.id === u.id ? updated : x));
    } catch (e) { alert(e.message); }
  };

  const toggleActive = async (u) => {
    try {
      const updated = await api.adminUpdateUser(u.id, { active: !u.active });
      setUsers(prev => prev.map(x => x.id === u.id ? updated : x));
    } catch (e) { alert(e.message); }
  };

  const doDelete = async (uid) => {
    try {
      await api.adminDeleteUser(uid);
      setUsers(prev => prev.filter(x => x.id !== uid));
      setConfirmDelete(null);
    } catch (e) { alert(e.message); }
  };

  const isSelf = (u) => u.id === currentUser?.id;

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '28px 32px', maxWidth: 900 }}>
      {showCreate && <CreateUserModal accent={accent} onClose={() => setShowCreate(false)} onCreated={u => setUsers(prev => [...prev, u])} />}
      {resetUser && <ResetPasswordModal user={resetUser} accent={accent} onClose={() => setResetUser(null)} />}
      {confirmDelete && (
        <ConfirmDialog
          accent={accent}
          text={`Delete user «${users.find(u => u.id === confirmDelete)?.username}»? This action is irreversible.`}
          onConfirm={() => doDelete(confirmDelete)}
          onCancel={() => setConfirmDelete(null)}
        />
      )}

      <div style={{ marginBottom: 28 }}>
        <div style={{ fontSize: 9, color: '#404550', letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>Admin panel</div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>User management</h1>
          <button onClick={() => setShowCreate(true)}
            style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Icon name="plus" size={11} color="#fff" /> Add user
          </button>
        </div>
      </div>

      {error && <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: '#cc2233', marginBottom: 18 }}>{error}</div>}

      <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px 100px 100px 120px', gap: 0, padding: '10px 18px', borderBottom: '1px solid #1e2029', background: '#090b0f' }}>
          {['User', 'Role', 'Status', 'Created', 'Actions'].map(h => (
            <div key={h} style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{h}</div>
          ))}
        </div>
        {onlineUsers.length > 0 && (
          <div style={{ padding: '8px 18px', background: '#09090d', borderBottom: '1px solid #14161b', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#39d353', boxShadow: '0 0 6px #39d353', flexShrink: 0 }} />
            <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>Online now:</span>
            {onlineUsers.map(name => (
              <span key={name} style={{ fontSize: 10, color: '#39d353', fontFamily: 'JetBrains Mono', background: '#39d35318', border: '1px solid #39d35333', borderRadius: 4, padding: '1px 7px' }}>{name}</span>
            ))}
          </div>
        )}

        {loading && <div style={{ padding: 24, textAlign: 'center', color: '#404550', fontSize: 12 }}>Loading...</div>}

        {users.map((u, i) => (
          <div key={u.id} style={{ display: 'grid', gridTemplateColumns: '1fr 120px 100px 100px 120px', gap: 0, padding: '13px 18px', borderBottom: i < users.length - 1 ? '1px solid #14161b' : 'none', alignItems: 'center', background: isSelf(u) ? `${accent}08` : 'transparent' }}>
            {/* Username */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: `${ROLE_COLOR[u.role]}22`, border: `1px solid ${ROLE_COLOR[u.role]}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 700, color: ROLE_COLOR[u.role], fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
                {u.username.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <div style={{ fontSize: 13, color: '#e0e4ec', fontWeight: 600 }}>{u.username}</div>
                {isSelf(u) && <div style={{ fontSize: 9, color: accent, fontFamily: 'JetBrains Mono' }}>that's you</div>}
              </div>
            </div>

            {/* Role */}
            <div>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, color: ROLE_COLOR[u.role], background: `${ROLE_COLOR[u.role]}18`, border: `1px solid ${ROLE_COLOR[u.role]}44`, borderRadius: 4, padding: '2px 8px', textTransform: 'uppercase' }}>
                {u.role === 'admin' ? 'Admin' : 'User'}
              </span>
            </div>

            {/* Active */}
            <div>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: u.active ? '#39d353' : '#404550', background: u.active ? '#39d35318' : '#40455018', border: `1px solid ${u.active ? '#39d35344' : '#40455044'}`, borderRadius: 4, padding: '2px 8px' }}>
                {u.active ? 'Active' : 'Disabled'}
              </span>
            </div>

            {/* Created */}
            <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono' }}>{u.created_at}</div>

            {/* Actions */}
            <div style={{ display: 'flex', gap: 4 }}>
              {!isSelf(u) && (
                <>
                  <button onClick={() => toggleRole(u)} title={u.role === 'admin' ? 'Remove admin' : 'Promote to admin'}
                    style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 7px', cursor: 'pointer', color: '#404550', fontSize: 9, fontFamily: 'JetBrains Mono', transition: 'all .1s', whiteSpace: 'nowrap' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = ROLE_COLOR[u.role === 'admin' ? 'user' : 'admin']; e.currentTarget.style.color = ROLE_COLOR[u.role === 'admin' ? 'user' : 'admin']; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                    {u.role === 'admin' ? '→ User' : '→ Admin'}
                  </button>
                  <button onClick={() => toggleActive(u)} title={u.active ? 'Deactivate' : 'Activate'}
                    style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#404550', display: 'flex', transition: 'all .1s' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = u.active ? '#f09a3a' : '#39d353'; e.currentTarget.style.color = u.active ? '#f09a3a' : '#39d353'; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                    <Icon name={u.active ? 'close' : 'plus'} size={10} color="currentColor" />
                  </button>
                </>
              )}
              <button onClick={() => setResetUser(u)} title="Reset password"
                style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#404550', display: 'flex', transition: 'all .1s' }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = '#5b8af5'; e.currentTarget.style.color = '#5b8af5'; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                <Icon name="key" size={10} color="currentColor" />
              </button>
              {!isSelf(u) && (
                <button onClick={() => setConfirmDelete(u.id)} title="Delete"
                  style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#404550', display: 'flex', transition: 'all .1s' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = '#cc2233'; e.currentTarget.style.color = '#cc2233'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                  <Icon name="trash" size={10} color="currentColor" />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      <div style={{ marginTop: 12, fontSize: 10, color: '#303540', fontFamily: 'JetBrains Mono' }}>
        Total: {users.length} · Active: {users.filter(u => u.active).length} · Admins: {users.filter(u => u.role === 'admin').length}
      </div>
    </div>
  );
}
