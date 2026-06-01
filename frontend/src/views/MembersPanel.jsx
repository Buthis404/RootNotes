import PropTypes from 'prop-types';
import { useState, useEffect, useRef } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { api } from '../api.js';
import Icon from '../components/Icon.jsx';

function _toggleId(prev, id, checked) {
  return checked ? [...prev, id] : prev.filter(x => x !== id);
}

function _filterUsers(users, search) {
  const q = search.trim().toLowerCase();
  if (!q) return users;
  return users.filter(u => u.username.toLowerCase().includes(q));
}

const ROLE_ORDER = ['owner', 'admin', 'editor', 'operator', 'viewer', 'auditor'];
const ROLE_COLOR = {
  owner: '#f09a3a', admin: '#cc2233', editor: '#5b8af5',
  operator: '#c07af0', viewer: '#39d353', auditor: '#6fc8f0',
};
const ROLE_LABEL = {
  owner: 'Owner', admin: 'Admin', editor: 'Editor',
  operator: 'Operator', viewer: 'Viewer', auditor: 'Auditor',
};

function MemberRow({ m, canManage, sel, handleRoleChange, handleRemove }) {
  const roleColor = ROLE_COLOR[m.role] || '#808590';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid #1e2029' }}>
      <div style={{ flex: 1, fontSize: 12, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>{m.username}</div>
      {canManage && m.role !== 'owner' ? (
        <select value={m.role} onChange={e => handleRoleChange(m.user_id, e.target.value)} style={sel}>
          {ROLE_ORDER.filter(r => r !== 'owner').map(r => (
            <option key={r} value={r}>{ROLE_LABEL[r]}</option>
          ))}
        </select>
      ) : (
        <span style={{ fontSize: 10, color: roleColor, background: roleColor + '18', border: `1px solid ${roleColor}44`, borderRadius: 3, padding: '2px 8px', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
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
  );
}
MemberRow.propTypes = {
  m: PropTypes.any,
  canManage: PropTypes.any,
  sel: PropTypes.any,
  handleRoleChange: PropTypes.any,
  handleRemove: PropTypes.any,
};

async function _loadMembersData(pid, setMembers, setUsers, setPermissionState, setError, setLoading) {
  setLoading(true);
  try {
    const [m, u, perms] = await Promise.all([
      api.getProjectMembers(pid),
      api.getProjectAvailableUsers(pid),
      api.getMyProjectPermissions(pid),
    ]);
    setMembers(m);
    setUsers(u);
    const isSA = !!perms.is_super_admin;
    const permsArr = perms.permissions || [];
    setPermissionState({
      canManage: isSA || permsArr.includes('project.manage_members'),
      canTransfer: isSA || permsArr.includes('project.transfer_ownership'),
    });
  } catch (e) { setError(e.message); }
  finally { setLoading(false); }
}

async function _handleMemberAdd(pid, addUserId, addRole, { load, setAddUserId, setSelectedUserIds, setAdding, setError }) {
  if (!addUserId) return;
  setAdding(true);
  try {
    await api.addProjectMember(pid, { user_id: addUserId, role: addRole });
    await load();
    setAddUserId('');
    setSelectedUserIds(ids => ids.filter(id => id !== addUserId));
  } catch (e) { setError(e.message); }
  finally { setAdding(false); }
}

async function _handleBulkAdd(pid, selectedUserIds, bulkRole, load, setSelectedUserIds, setBulkAdding, setError) {
  if (!selectedUserIds.length) return;
  setBulkAdding(true);
  try {
    await api.bulkAddProjectMembers(pid, { user_ids: selectedUserIds, role: bulkRole });
    setSelectedUserIds([]);
    await load();
  } catch (e) { setError(e.message); }
  finally { setBulkAdding(false); }
}

async function _handleRoleChange(pid, uid, newRole, setMembers, setError) {
  try {
    await api.updateProjectMember(pid, uid, { role: newRole });
    setMembers(ms => ms.map(m => m.user_id === uid ? { ...m, role: newRole } : m));
  } catch (e) { setError(e.message); }
}

async function _handleRemove(pid, uid, setMembers, setError) {
  try {
    await api.removeProjectMember(pid, uid);
    setMembers(ms => ms.filter(m => m.user_id !== uid));
  } catch (e) { setError(e.message); }
}

async function _handleTransfer(pid, transferTo, load, setShowTransfer, setError) {
  if (!transferTo) return;
  try {
    await api.transferOwnership(pid, { user_id: transferTo });
    await load();
    setShowTransfer(false);
  } catch (e) { setError(e.message); }
}

const _INP = { background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' };
const _SEL = { ..._INP, cursor: 'pointer' };

function AddUserRow({ canManage, nonMembers, addUserId, setAddUserId, addRole, setAddRole, adding, onAdd, accent }) {
  if (!canManage || nonMembers.length === 0) return null;
  return (
    <div style={{ marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
      <select value={addUserId} onChange={e => setAddUserId(e.target.value)} style={{ ..._SEL, flex: 1 }}>
        <option value="">Select user to add...</option>
        {nonMembers.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
      </select>
      <select value={addRole} onChange={e => setAddRole(e.target.value)} style={_SEL}>
        {ROLE_ORDER.filter(r => r !== 'owner').map(r => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
      </select>
      <button onClick={onAdd} disabled={!addUserId || adding}
        style={{ background: addUserId ? accent : '#1a1c22', border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>
        {adding ? '...' : 'Add'}
      </button>
    </div>
  );
}
AddUserRow.propTypes = {
  canManage: PropTypes.any,
  nonMembers: PropTypes.any,
  addUserId: PropTypes.any,
  setAddUserId: PropTypes.any,
  addRole: PropTypes.any,
  setAddRole: PropTypes.any,
  adding: PropTypes.any,
  onAdd: PropTypes.any,
  accent: PropTypes.any,
};

function useBulkInviteVirtualizer(filteredUsers) {
  const listRef = useRef(null);
  const virt = useVirtualizer({ count: filteredUsers.length, getScrollElement: () => listRef.current, estimateSize: () => 37, overscan: 5 });
  return { listRef, virt };
}

function BulkInviteSection({ canManage, nonMembers, search, setSearch, bulkRole, setBulkRole, filteredUsers, selectedUserIds, setSelectedUserIds, bulkAdding, onBulkAdd, accent }) {
  const { listRef, virt } = useBulkInviteVirtualizer(filteredUsers);
  if (!canManage || nonMembers.length <= 1) return null;
  return (
    <div style={{ borderTop: '1px solid #1e2029', paddingTop: 14, marginBottom: 16 }}>
      <div style={{ fontSize: 10, color: '#808590', fontFamily: 'Space Grotesk', fontWeight: 700, marginBottom: 10 }}>Bulk Invite</div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search users..." style={{ ..._INP, flex: 1 }} />
        <select value={bulkRole} onChange={e => setBulkRole(e.target.value)} style={_SEL}>
          {ROLE_ORDER.filter(r => r !== 'owner').map(r => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
        </select>
      </div>
      <div ref={listRef} style={{ maxHeight: 180, overflowY: 'auto', border: '1px solid #1e2029', borderRadius: 6, background: '#0a0c10', marginBottom: 10 }}>
        {filteredUsers.length === 0 ? (
          <div style={{ padding: '12px 10px', fontSize: 11, color: '#505560' }}>No matching users</div>
        ) : (
          <div style={{ height: `${virt.getTotalSize()}px`, position: 'relative' }}>
            {virt.getVirtualItems().map(vr => {
              const u = filteredUsers[vr.index];
              const checked = selectedUserIds.includes(u.id);
              return (
                <label key={u.id} style={{ position: 'absolute', top: 0, left: 0, width: '100%', transform: `translateY(${vr.start}px)`, display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', borderBottom: '1px solid #14161b', cursor: 'pointer', boxSizing: 'border-box' }}>
                  <input type="checkbox" checked={checked} onChange={e => setSelectedUserIds(prev => _toggleId(prev, u.id, e.target.checked))} />
                  <span style={{ flex: 1, fontSize: 12, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>{u.username}</span>
                  <span style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase' }}>{u.role}</span>
                </label>
              );
            })}
          </div>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <button onClick={() => setSelectedUserIds(filteredUsers.map(u => u.id))}
          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#808590', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          Select visible
        </button>
        <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono', flex: 1, textAlign: 'center' }}>{selectedUserIds.length} selected</div>
        <button onClick={onBulkAdd} disabled={!selectedUserIds.length || bulkAdding}
          style={{ background: selectedUserIds.length ? accent : '#1a1c22', border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
          {bulkAdding ? 'Inviting...' : 'Invite selected'}
        </button>
      </div>
    </div>
  );
}
BulkInviteSection.propTypes = {
  canManage: PropTypes.any,
  nonMembers: PropTypes.any,
  search: PropTypes.any,
  setSearch: PropTypes.any,
  bulkRole: PropTypes.any,
  setBulkRole: PropTypes.any,
  filteredUsers: PropTypes.any,
  selectedUserIds: PropTypes.any,
  setSelectedUserIds: PropTypes.any,
  bulkAdding: PropTypes.any,
  onBulkAdd: PropTypes.any,
  accent: PropTypes.any,
};

function TransferSection({ canTransfer, showTransfer, setShowTransfer, transferTo, setTransferTo, members, onTransfer }) {
  if (!canTransfer) return null;
  return (
    <div style={{ borderTop: '1px solid #1e2029', paddingTop: 14, marginTop: 4 }}>
      {showTransfer ? (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select value={transferTo} onChange={e => setTransferTo(e.target.value)} style={{ ..._SEL, flex: 1 }}>
            <option value="">Select new owner...</option>
            {members.filter(m => m.role !== 'owner').map(m => <option key={m.user_id} value={m.user_id}>{m.username}</option>)}
          </select>
          <button onClick={onTransfer} disabled={!transferTo}
            style={{ background: transferTo ? '#f09a3a' : '#1a1c22', border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
            Transfer
          </button>
          <button onClick={() => setShowTransfer(false)}
            style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
            Cancel
          </button>
        </div>
      ) : (
        <button onClick={() => setShowTransfer(true)}
          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#808590', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          Transfer Ownership
        </button>
      )}
    </div>
  );
}
TransferSection.propTypes = {
  canTransfer: PropTypes.any,
  showTransfer: PropTypes.any,
  setShowTransfer: PropTypes.any,
  transferTo: PropTypes.any,
  setTransferTo: PropTypes.any,
  members: PropTypes.any,
  onTransfer: PropTypes.any,
};

export default function MembersPanel({ pid, accent, onClose }) {
  const [members, setMembers] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [addUserId, setAddUserId] = useState('');
  const [addRole, setAddRole] = useState('viewer');
  const [adding, setAdding] = useState(false);
  const [bulkRole, setBulkRole] = useState('viewer');
  const [selectedUserIds, setSelectedUserIds] = useState([]);
  const [bulkAdding, setBulkAdding] = useState(false);
  const [transferTo, setTransferTo] = useState('');
  const [showTransfer, setShowTransfer] = useState(false);
  const [permissionState, setPermissionState] = useState({ canManage: false, canTransfer: false });

  const load = () => _loadMembersData(pid, setMembers, setUsers, setPermissionState, setError, setLoading);

  useEffect(() => {
    setSelectedUserIds([]);
    setSearch('');
    load();
  }, [pid]); // eslint-disable-line react-hooks/exhaustive-deps

  const nonMembers = users.filter(u => !new Set(members.map(m => m.user_id)).has(u.id));
  const filteredUsers = _filterUsers(nonMembers, search);

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 500, backdropFilter: 'blur(4px)' }}>
      <button type="button" aria-label="Close members modal" onClick={onClose} style={{ position: 'absolute', inset: 0, background: 'transparent', border: 'none', cursor: 'default' }} />
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
                <MemberRow key={m.user_id} m={m} canManage={permissionState.canManage} sel={_SEL}
                  handleRoleChange={(uid, r) => _handleRoleChange(pid, uid, r, setMembers, setError)}
                  handleRemove={(uid) => _handleRemove(pid, uid, setMembers, setError)} />
              ))}
            </div>
            <AddUserRow canManage={permissionState.canManage} nonMembers={nonMembers} addUserId={addUserId} setAddUserId={setAddUserId}
              addRole={addRole} setAddRole={setAddRole} adding={adding} accent={accent}
              onAdd={() => _handleMemberAdd(pid, addUserId, addRole, { load, setAddUserId, setSelectedUserIds, setAdding, setError })} />
            <BulkInviteSection canManage={permissionState.canManage} nonMembers={nonMembers} search={search} setSearch={setSearch}
              bulkRole={bulkRole} setBulkRole={setBulkRole} filteredUsers={filteredUsers} selectedUserIds={selectedUserIds}
              setSelectedUserIds={setSelectedUserIds} bulkAdding={bulkAdding} accent={accent}
              onBulkAdd={() => _handleBulkAdd(pid, selectedUserIds, bulkRole, load, setSelectedUserIds, setBulkAdding, setError)} />
            <TransferSection canTransfer={permissionState.canTransfer} showTransfer={showTransfer} setShowTransfer={setShowTransfer}
              transferTo={transferTo} setTransferTo={setTransferTo} members={members}
              onTransfer={() => _handleTransfer(pid, transferTo, load, setShowTransfer, setError)} />
          </>
        )}
      </div>
    </div>
  );
}
MembersPanel.propTypes = {
  pid: PropTypes.any,
  accent: PropTypes.any,
  onClose: PropTypes.any,
};
