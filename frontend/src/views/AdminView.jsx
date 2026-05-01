import { useEffect, useState } from 'react';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';

const GLOBAL_ROLE_COLOR = { admin: '#cc2233', user: '#5b8af5', viewer: '#808590' };

const PROJECT_ROLE_ORDER = ['owner', 'admin', 'editor', 'operator', 'viewer', 'auditor'];
const PROJECT_ROLE_COLOR = {
  owner: '#f09a3a', admin: '#cc2233', editor: '#5b8af5',
  operator: '#c07af0', viewer: '#39d353', auditor: '#6fc8f0',
};
const PROJECT_ROLE_LABEL = {
  owner: 'Owner', admin: 'Admin', editor: 'Editor',
  operator: 'Operator', viewer: 'Viewer', auditor: 'Auditor',
};

function ConfirmDialog({ text, onConfirm, onCancel }) {
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
              <input style={inp} type={type} value={val} onChange={e => set(e.target.value)} autoComplete={ac} onKeyDown={e => e.key === 'Enter' && submit()} />
            </div>
          ))}
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Role</div>
            <div style={{ display: 'flex', gap: 6 }}>
              {['viewer', 'user', 'admin'].map(r => (
                <button key={r} onClick={() => setRole(r)}
                  style={{ flex: 1, background: role === r ? `${GLOBAL_ROLE_COLOR[r]}22` : 'transparent', border: `1px solid ${role === r ? GLOBAL_ROLE_COLOR[r] + '88' : '#2a2d35'}`, borderRadius: 5, padding: '6px 0', cursor: 'pointer', color: role === r ? GLOBAL_ROLE_COLOR[r] : '#606570', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', transition: 'all .1s' }}>
                  {r === 'admin' ? 'Administrator' : r === 'viewer' ? 'Viewer' : 'User'}
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
    try { await api.adminUpdateUser(user.id, { password }); setDone(true); }
    catch (err) { setError(err.message); }
    finally { setLoading(false); }
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
          <div style={{ background: '#39d35322', border: '1px solid #39d35344', borderRadius: 5, padding: '12px', fontSize: 12, color: '#39d353', textAlign: 'center' }}>Password changed successfully</div>
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

// ── Project Access section ────────────────────────────────────────────
function ProjectAccessSection({ accent, allUsers }) {
  const [projects, setProjects] = useState([]);
  const [selectedPid, setSelectedPid] = useState('');
  const [members, setMembers] = useState([]);
  const [loadingMembers, setLoadingMembers] = useState(false);
  const [addUserId, setAddUserId] = useState('');
  const [addRole, setAddRole] = useState('viewer');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');
  const [transferTo, setTransferTo] = useState('');
  const [showTransfer, setShowTransfer] = useState(false);

  useEffect(() => {
    api.getProjects().then(setProjects).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedPid) { setMembers([]); return; }
    setLoadingMembers(true);
    setError('');
    api.getProjectMembers(selectedPid)
      .then(setMembers)
      .catch(e => setError(e.message))
      .finally(() => setLoadingMembers(false));
  }, [selectedPid]);

  const memberUserIds = new Set(members.map(m => m.user_id));
  const nonMembers = allUsers.filter(u => !memberUserIds.has(u.id));

  const handleAdd = async () => {
    if (!addUserId || !selectedPid) return;
    setAdding(true); setError('');
    try {
      const m = await api.addProjectMember(selectedPid, { user_id: addUserId, role: addRole });
      setMembers(prev => [...prev, m]);
      setAddUserId('');
    } catch (e) { setError(e.message); }
    finally { setAdding(false); }
  };

  const handleRoleChange = async (uid, newRole) => {
    try {
      const updated = await api.updateProjectMember(selectedPid, uid, { role: newRole });
      setMembers(prev => prev.map(m => m.user_id === uid ? { ...m, role: updated.role } : m));
    } catch (e) { setError(e.message); }
  };

  const handleRemove = async (uid) => {
    try {
      await api.removeProjectMember(selectedPid, uid);
      setMembers(prev => prev.filter(m => m.user_id !== uid));
    } catch (e) { setError(e.message); }
  };

  const handleTransfer = async () => {
    if (!transferTo) return;
    try {
      await api.transferOwnership(selectedPid, { user_id: transferTo });
      const refreshed = await api.getProjectMembers(selectedPid);
      setMembers(refreshed);
      setShowTransfer(false);
      setTransferTo('');
    } catch (e) { setError(e.message); }
  };

  const sel = { background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', cursor: 'pointer' };

  return (
    <div style={{ marginTop: 36 }}>
      {/* Section header */}
      <div style={{ marginBottom: 18 }}>
        <div style={{ fontSize: 9, color: '#404550', letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>Access control</div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Project members</h2>
          {projects.length > 0 && (
            <select value={selectedPid} onChange={e => { setSelectedPid(e.target.value); setShowTransfer(false); setError(''); }}
              style={{ ...sel, fontSize: 12, padding: '6px 10px', minWidth: 200 }}>
              <option value="">— select project —</option>
              {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          )}
        </div>
      </div>

      {!selectedPid && (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: '24px', textAlign: 'center', color: '#404550', fontSize: 12 }}>
          Select a project to manage its members
        </div>
      )}

      {selectedPid && (
        <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
          {/* Column header */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 160px 100px', gap: 0, padding: '9px 18px', borderBottom: '1px solid #1e2029', background: '#090b0f' }}>
            {['User', 'Project role', 'Actions'].map(h => (
              <div key={h} style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{h}</div>
            ))}
          </div>

          {loadingMembers && (
            <div style={{ padding: '18px', color: '#505560', fontSize: 12 }}>Loading...</div>
          )}

          {error && (
            <div style={{ margin: '10px 18px', background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '7px 10px', fontSize: 11, color: '#cc2233' }}>{error}</div>
          )}

          {!loadingMembers && members.map((m, i) => (
            <div key={m.user_id} style={{ display: 'grid', gridTemplateColumns: '1fr 160px 100px', gap: 0, padding: '11px 18px', borderBottom: i < members.length - 1 ? '1px solid #14161b' : 'none', alignItems: 'center' }}>
              {/* Username */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 28, height: 28, borderRadius: '50%', background: `${PROJECT_ROLE_COLOR[m.role] || accent}22`, border: `1px solid ${PROJECT_ROLE_COLOR[m.role] || accent}44`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: PROJECT_ROLE_COLOR[m.role] || accent, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
                  {m.username.slice(0, 2).toUpperCase()}
                </div>
                <span style={{ fontSize: 13, color: '#e0e4ec', fontWeight: 500 }}>{m.username}</span>
              </div>

              {/* Role selector */}
              {m.role === 'owner' ? (
                <span style={{ fontSize: 10, color: PROJECT_ROLE_COLOR.owner, background: PROJECT_ROLE_COLOR.owner + '18', border: `1px solid ${PROJECT_ROLE_COLOR.owner}44`, borderRadius: 4, padding: '2px 8px', fontFamily: 'JetBrains Mono', fontWeight: 600, display: 'inline-block' }}>
                  Owner
                </span>
              ) : (
                <select value={m.role} onChange={e => handleRoleChange(m.user_id, e.target.value)} style={sel}>
                  {PROJECT_ROLE_ORDER.filter(r => r !== 'owner').map(r => (
                    <option key={r} value={r}>{PROJECT_ROLE_LABEL[r]}</option>
                  ))}
                </select>
              )}

              {/* Remove */}
              <div>
                {m.role !== 'owner' && (
                  <button onClick={() => handleRemove(m.user_id)} title="Remove from project"
                    style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#404550', display: 'flex', transition: 'all .1s' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = '#cc2233'; e.currentTarget.style.color = '#cc2233'; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                    <Icon name="trash" size={10} color="currentColor" />
                  </button>
                )}
              </div>
            </div>
          ))}

          {/* Add member row */}
          {!loadingMembers && nonMembers.length > 0 && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '12px 18px', borderTop: members.length ? '1px solid #1e2029' : 'none', background: '#090b0f' }}>
              <Icon name="plus" size={11} color="#404550" />
              <select value={addUserId} onChange={e => setAddUserId(e.target.value)} style={{ ...sel, flex: 1 }}>
                <option value="">Add user to project...</option>
                {nonMembers.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
              </select>
              <select value={addRole} onChange={e => setAddRole(e.target.value)} style={sel}>
                {PROJECT_ROLE_ORDER.filter(r => r !== 'owner').map(r => (
                  <option key={r} value={r}>{PROJECT_ROLE_LABEL[r]}</option>
                ))}
              </select>
              <button onClick={handleAdd} disabled={!addUserId || adding}
                style={{ background: addUserId ? accent : '#1a1c22', border: 'none', borderRadius: 4, padding: '5px 14px', cursor: addUserId ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', transition: 'background .15s' }}>
                {adding ? '...' : 'Add'}
              </button>
            </div>
          )}

          {/* Transfer ownership */}
          {!loadingMembers && members.length > 0 && (
            <div style={{ padding: '12px 18px', borderTop: '1px solid #1e2029', background: '#07080b' }}>
              {!showTransfer ? (
                <button onClick={() => setShowTransfer(true)}
                  style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#505560', fontSize: 10, fontFamily: 'JetBrains Mono', transition: 'all .12s' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = '#f09a3a'; e.currentTarget.style.color = '#f09a3a'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#505560'; }}>
                  Transfer ownership…
                </button>
              ) : (
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>New owner:</span>
                  <select value={transferTo} onChange={e => setTransferTo(e.target.value)} style={{ ...sel, flex: 1 }}>
                    <option value="">Select user...</option>
                    {members.filter(m => m.role !== 'owner').map(m => (
                      <option key={m.user_id} value={m.user_id}>{m.username}</option>
                    ))}
                  </select>
                  <button onClick={handleTransfer} disabled={!transferTo}
                    style={{ background: transferTo ? '#f09a3a' : '#1a1c22', border: 'none', borderRadius: 4, padding: '5px 12px', cursor: transferTo ? 'pointer' : 'default', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
                    Transfer
                  </button>
                  <button onClick={() => { setShowTransfer(false); setTransferTo(''); }}
                    style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                    Cancel
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main AdminView ────────────────────────────────────────────────────
export default function AdminView({ currentUser, accent, onlineUsers = [] }) {
  const tableColumns = 'minmax(220px, 1fr) 120px 100px 110px 220px';
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

  const setRole = async (u, newRole) => {
    if (u.role === newRole) return;
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
    <div style={{ flex: 1, overflowY: 'auto', padding: '28px 32px', maxWidth: 960 }}>
      {showCreate && <CreateUserModal accent={accent} onClose={() => setShowCreate(false)} onCreated={u => setUsers(prev => [...prev, u])} />}
      {resetUser && <ResetPasswordModal user={resetUser} accent={accent} onClose={() => setResetUser(null)} />}
      {confirmDelete && (
        <ConfirmDialog
          text={`Delete user «${users.find(u => u.id === confirmDelete)?.username}»? This action is irreversible.`}
          onConfirm={() => doDelete(confirmDelete)}
          onCancel={() => setConfirmDelete(null)}
        />
      )}

      {/* ── Users section ── */}
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
        <div style={{ display: 'grid', gridTemplateColumns: tableColumns, gap: 0, padding: '10px 18px', borderBottom: '1px solid #1e2029', background: '#090b0f' }}>
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
          <div key={u.id} style={{ display: 'grid', gridTemplateColumns: tableColumns, gap: 0, padding: '13px 18px', borderBottom: i < users.length - 1 ? '1px solid #14161b' : 'none', alignItems: 'center', background: isSelf(u) ? `${accent}08` : 'transparent' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: `${GLOBAL_ROLE_COLOR[u.role]}22`, border: `1px solid ${GLOBAL_ROLE_COLOR[u.role]}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 700, color: GLOBAL_ROLE_COLOR[u.role], fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
                {u.username.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <div style={{ fontSize: 13, color: '#e0e4ec', fontWeight: 600 }}>{u.username}</div>
                {isSelf(u) && <div style={{ fontSize: 9, color: accent, fontFamily: 'JetBrains Mono' }}>that's you</div>}
              </div>
            </div>

            <div>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, color: GLOBAL_ROLE_COLOR[u.role], background: `${GLOBAL_ROLE_COLOR[u.role]}18`, border: `1px solid ${GLOBAL_ROLE_COLOR[u.role]}44`, borderRadius: 4, padding: '2px 8px', textTransform: 'uppercase' }}>
                {u.role === 'admin' ? 'Admin' : u.role === 'viewer' ? 'Viewer' : 'User'}
              </span>
            </div>

            <div>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: u.active ? '#39d353' : '#404550', background: u.active ? '#39d35318' : '#40455018', border: `1px solid ${u.active ? '#39d35344' : '#40455044'}`, borderRadius: 4, padding: '2px 8px' }}>
                {u.active ? 'Active' : 'Disabled'}
              </span>
            </div>

            <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono' }}>{u.created_at}</div>

            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
              {!isSelf(u) && (
                <>
                  <select value={u.role} onChange={e => setRole(u, e.target.value)}
                    style={{ background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 7px', cursor: 'pointer', color: GLOBAL_ROLE_COLOR[u.role] || '#808590', fontSize: 9, fontFamily: 'JetBrains Mono', minWidth: 92 }}>
                    <option value="viewer">Viewer</option>
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                  </select>
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
        Total: {users.length} · Active: {users.filter(u => u.active).length} · Admins: {users.filter(u => u.role === 'admin').length} · Viewers: {users.filter(u => u.role === 'viewer').length}
      </div>

      {/* ── Project Access section ── */}
      <ProjectAccessSection accent={accent} allUsers={users} />
    </div>
  );
}
