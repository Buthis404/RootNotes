import { useState, useEffect } from 'react';
import { api } from '../api.js';
import Icon from '../components/Icon.jsx';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';

const ROLE_ORDER = ['owner', 'admin', 'editor', 'operator', 'viewer', 'auditor'];
const ROLE_COLOR = {
  owner: '#f09a3a', admin: '#cc2233', editor: '#5b8af5',
  operator: '#c07af0', viewer: '#39d353', auditor: '#6fc8f0',
};
const ROLE_LABEL = {
  owner: 'Owner', admin: 'Admin', editor: 'Editor',
  operator: 'Operator', viewer: 'Viewer', auditor: 'Auditor',
};

export default function MembersPanel({ pid, accent, onClose }) {
  const [members, setMembers] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [addUserId, setAddUserId] = useState('');
  const [addRole, setAddRole] = useState('viewer');
  const [adding, setAdding] = useState(false);
  const [transferTo, setTransferTo] = useState('');
  const [showTransfer, setShowTransfer] = useState(false);
  const { can, isSuperAdmin } = useProjectPermissions();
  const canManage = can('project.manage_members');
  const canTransfer = can('project.transfer_ownership') || isSuperAdmin;

  const load = async () => {
    setLoading(true);
    try {
      const [m, u] = await Promise.all([api.getProjectMembers(pid), api.adminListUsers()]);
      setMembers(m);
      setUsers(u);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [pid]);

  const memberUserIds = new Set(members.map(m => m.user_id));
  const nonMembers = users.filter(u => !memberUserIds.has(u.id));

  const handleAdd = async () => {
    if (!addUserId) return;
    setAdding(true);
    try {
      await api.addProjectMember(pid, { user_id: addUserId, role: addRole });
      await load();
      setAddUserId('');
    } catch (e) { setError(e.message); }
    finally { setAdding(false); }
  };

  const handleRoleChange = async (uid, newRole) => {
    try {
      await api.updateProjectMember(pid, uid, { role: newRole });
      setMembers(ms => ms.map(m => m.user_id === uid ? { ...m, role: newRole } : m));
    } catch (e) { setError(e.message); }
  };

  const handleRemove = async (uid) => {
    try {
      await api.removeProjectMember(pid, uid);
      setMembers(ms => ms.filter(m => m.user_id !== uid));
    } catch (e) { setError(e.message); }
  };

  const handleTransfer = async () => {
    if (!transferTo) return;
    try {
      await api.transferOwnership(pid, { user_id: transferTo });
      await load();
      setShowTransfer(false);
    } catch (e) { setError(e.message); }
  };

  const inp = { background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' };
  const sel = { ...inp, cursor: 'pointer' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 500, backdropFilter: 'blur(4px)' }}
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{ background: '#0e1016', border: `1px solid ${accent}44`, borderRadius: 10, padding: 28, width: 520, maxHeight: '80vh', overflow: 'auto', boxShadow: '0 20px 60px #00000099' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <div style={{ fontSize: 15, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Project Members</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer' }}><Icon name="close" size={14} color="#606570" /></button>
        </div>

        {error && <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '7px 10px', fontSize: 11, color: '#cc2233', marginBottom: 12 }}>{error}</div>}

        {loading ? <div style={{ color: '#606570', fontSize: 12 }}>Loading...</div> : (
          <>
            <div style={{ marginBottom: 16 }}>
              {members.map(m => (
                <div key={m.user_id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid #1e2029' }}>
                  <div style={{ flex: 1, fontSize: 12, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>{m.username}</div>
                  {canManage && m.role !== 'owner' ? (
                    <select value={m.role} onChange={e => handleRoleChange(m.user_id, e.target.value)} style={sel}>
                      {ROLE_ORDER.filter(r => r !== 'owner').map(r => (
                        <option key={r} value={r}>{ROLE_LABEL[r]}</option>
                      ))}
                    </select>
                  ) : (
                    <span style={{ fontSize: 10, color: ROLE_COLOR[m.role] || '#808590', background: (ROLE_COLOR[m.role] || '#808590') + '18', border: `1px solid ${(ROLE_COLOR[m.role] || '#808590')}44`, borderRadius: 3, padding: '2px 8px', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                      {ROLE_LABEL[m.role] || m.role}
                    </span>
                  )}
                  {canManage && m.role !== 'owner' && (
                    <button onClick={() => handleRemove(m.user_id)}
                      style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#606570', display: 'flex', transition: 'all .12s' }}
                      onMouseEnter={e => { e.currentTarget.style.borderColor = '#cc2233'; e.currentTarget.style.color = '#cc2233'; }}
                      onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#606570'; }}>
                      <Icon name="trash" size={10} color="currentColor" />
                    </button>
                  )}
                </div>
              ))}
            </div>

            {canManage && nonMembers.length > 0 && (
              <div style={{ marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
                <select value={addUserId} onChange={e => setAddUserId(e.target.value)} style={{ ...sel, flex: 1 }}>
                  <option value="">Select user to add...</option>
                  {nonMembers.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
                </select>
                <select value={addRole} onChange={e => setAddRole(e.target.value)} style={sel}>
                  {ROLE_ORDER.filter(r => r !== 'owner').map(r => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                </select>
                <button onClick={handleAdd} disabled={!addUserId || adding}
                  style={{ background: addUserId ? accent : '#1a1c22', border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>
                  {adding ? '...' : 'Add'}
                </button>
              </div>
            )}

            {canTransfer && (
              <div style={{ borderTop: '1px solid #1e2029', paddingTop: 14, marginTop: 4 }}>
                {!showTransfer ? (
                  <button onClick={() => setShowTransfer(true)}
                    style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#808590', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
                    Transfer Ownership
                  </button>
                ) : (
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <select value={transferTo} onChange={e => setTransferTo(e.target.value)} style={{ ...sel, flex: 1 }}>
                      <option value="">Select new owner...</option>
                      {members.filter(m => m.role !== 'owner').map(m => <option key={m.user_id} value={m.user_id}>{m.username}</option>)}
                    </select>
                    <button onClick={handleTransfer} disabled={!transferTo}
                      style={{ background: transferTo ? '#f09a3a' : '#1a1c22', border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
                      Transfer
                    </button>
                    <button onClick={() => setShowTransfer(false)}
                      style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
