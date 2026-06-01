import PropTypes from 'prop-types';
import { useState, useMemo } from 'react';
import Icon from '../components/Icon.jsx';

const SCOPE_TYPES = {
  cidr:     { label: 'CIDR',     color: '#5b8af5' },
  hostname: { label: 'Hostname', color: '#c07af0' },
  domain:   { label: 'Domain',   color: '#f09a3a' },
  url:      { label: 'URL',      color: '#6fc8f0' },
};

function isIpInCidr(ip, cidr) {
  try {
    const [base, bits] = cidr.split('/');
    if (!bits) return ip === cidr;
    const mask = ~((1 << (32 - Number.parseInt(bits))) - 1) >>> 0;
    const ipNum = ip.split('.').reduce((acc, o) => (acc << 8) + Number.parseInt(o), 0) >>> 0;
    const baseNum = base.split('.').reduce((acc, o) => (acc << 8) + Number.parseInt(o), 0) >>> 0;
    return (ipNum & mask) === (baseNum & mask);
  } catch { return false; }
}

function checkHostInScope(host, scopes) {
  const inScopes = scopes.filter(s => s.in_scope);
  const outScopes = scopes.filter(s => !s.in_scope);
  const matchIp = (ip, scope) => {
    if (scope.scope_type === 'cidr') return isIpInCidr(ip, scope.value);
    if (scope.scope_type === 'hostname') return ip === scope.value || host.hostname?.toLowerCase() === scope.value.toLowerCase();
    if (scope.scope_type === 'domain') return host.hostname?.toLowerCase().endsWith(scope.value.toLowerCase());
    return false;
  };
  const isOut = outScopes.some(s => matchIp(host.ip, s));
  if (isOut) return 'excluded';
  if (inScopes.length === 0) return 'unknown';
  const isIn = inScopes.some(s => matchIp(host.ip, s));
  return isIn ? 'in' : 'out';
}

const SCOPE_STATUS = {
  in:       { label: 'In Scope',    color: '#39d353' },
  out:      { label: 'Out of Scope', color: '#cc2233' },
  excluded: { label: 'Excluded',    color: '#f09a3a' },
  unknown:  { label: 'Unknown',     color: '#404550' },
};

const EMPTY = { value: '', scope_type: 'cidr', in_scope: true, description: '', gateway_ip: '', is_entry: false, via_host_id: '' };

const selectStyle = { background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

function ScopeAddForm({ newScope, setNewScope, projectHosts, accent, addScope, onCancel }) {
  return (
    <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0c0e13', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
      <div>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Type</div>
        <select value={newScope.scope_type} onChange={e => setNewScope(s => ({ ...s, scope_type: e.target.value }))}
          style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }}>
          {Object.entries(SCOPE_TYPES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
      </div>
      <div style={{ flex: 1, minWidth: 180 }}>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Value</div>
        <input value={newScope.value} onChange={e => setNewScope(s => ({ ...s, value: e.target.value }))} autoFocus
          placeholder="10.10.10.0/24 or domain.local"
          style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
      </div>
      <div style={{ width: 180 }}>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Description</div>
        <input value={newScope.description} onChange={e => setNewScope(s => ({ ...s, description: e.target.value }))}
          placeholder="Corp network, DMZ..."
          style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
      </div>
      {newScope.scope_type === 'cidr' && (
        <div style={{ width: 150 }}>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Gateway IP</div>
          <input value={newScope.gateway_ip} onChange={e => setNewScope(s => ({ ...s, gateway_ip: e.target.value }))}
            placeholder="x.x.x.x"
            style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
        </div>
      )}
      {newScope.scope_type === 'cidr' && (
        <div style={{ width: 180 }}>
          <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Reachable via host</div>
          <select value={newScope.via_host_id} onChange={e => setNewScope(s => ({ ...s, via_host_id: e.target.value }))}
            style={{ ...selectStyle, width: '100%' }}>
            <option value="">— direct access —</option>
            {projectHosts.map(h => <option key={h.id} value={h.id}>{h.hostname || h.ip}</option>)}
          </select>
        </div>
      )}
      {newScope.scope_type === 'cidr' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase' }}>Entry point</div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
            <input type="checkbox" checked={newScope.is_entry} onChange={e => setNewScope(s => ({ ...s, is_entry: e.target.checked }))} />{' '}
            Mark entry
          </label>
        </div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase' }}>Status</div>
        <div style={{ display: 'flex', gap: 4 }}>
          {[[true, 'In Scope', '#39d353'], [false, 'Exclude', '#cc2233']].map(([v, l, c]) => (
            <button key={String(v)} onClick={() => setNewScope(s => ({ ...s, in_scope: v }))}
              style={{ background: newScope.in_scope === v ? c + '22' : 'transparent', border: `1px solid ${newScope.in_scope === v ? c + '66' : '#2a2d35'}`, borderRadius: 4, padding: '4px 9px', cursor: 'pointer', color: newScope.in_scope === v ? c : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
              {l}
            </button>
          ))}
        </div>
      </div>
      <button onClick={addScope}
        style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>
        Save
      </button>
      <button onClick={onCancel}
        style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
        Cancel
      </button>
    </div>
  );
}

ScopeAddForm.propTypes = {
  newScope: PropTypes.object,
  setNewScope: PropTypes.func,
  projectHosts: PropTypes.array,
  accent: PropTypes.string,
  addScope: PropTypes.func,
  onCancel: PropTypes.func,
};

function _scopeViaLabel(projectHosts, via_host_id) {
  if (!via_host_id) return '';
  const h = projectHosts.find(h => h.id === via_host_id);
  return h ? ` · via ${h.hostname || h.ip}` : ` · via ${via_host_id}`;
}

function ScopeRowView({ scope, t, fs, projectHosts, onUpdate, startEdit, onDelete }) {
  const desc = scope.description || '—';
  const extra = (scope.gateway_ip ? ` · gw ${scope.gateway_ip}` : '')
    + (scope.is_entry ? ' · entry' : '')
    + _scopeViaLabel(projectHosts, scope.via_host_id);
  return (
    <>
      <span style={{ fontSize: 9, color: t.color, background: t.color + '18', border: `1px solid ${t.color}44`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', width: 60, textAlign: 'center', flexShrink: 0 }}>{t.label}</span>
      <span style={{ fontSize: Math.max(11, fs - 1), color: '#e0e4ec', fontFamily: 'JetBrains Mono', flex: 1, fontWeight: 500 }}>{scope.value}</span>
      <span style={{ fontSize: 10, color: '#808590', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{desc}{extra}</span>
      <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
        {[[true, '✓ In Scope', '#39d353'], [false, '✗ Exclude', '#cc2233']].map(([v, l, c]) => (
          <button key={String(v)} onClick={() => onUpdate(scope.id, { in_scope: v })}
            style={{ background: scope.in_scope === v ? c + '22' : 'transparent', border: `1px solid ${scope.in_scope === v ? c + '66' : '#2a2d35'}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: scope.in_scope === v ? c : '#505560', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
            {l}
          </button>
        ))}
        <button onClick={() => startEdit(scope)}
          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
          Edit
        </button>
        <button onClick={() => onDelete(scope.id)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', padding: 2 }}
          onMouseEnter={e => e.currentTarget.style.color = '#cc2233'}
          onMouseLeave={e => e.currentTarget.style.color = '#303540'}>
          <Icon name="trash" size={12} color="currentColor" />
        </button>
      </div>
    </>
  );
}

ScopeRowView.propTypes = {
  scope: PropTypes.object,
  t: PropTypes.object,
  fs: PropTypes.number,
  projectHosts: PropTypes.array,
  onUpdate: PropTypes.func,
  startEdit: PropTypes.func,
  onDelete: PropTypes.func,
};

function ScopeRowEdit({ scope, editScope, setEditScope, projectHosts, selectStyle, accent, saveEdit, cancelEdit }) {
  return (
    <>
      <select value={editScope.scope_type} onChange={e => setEditScope(s => ({ ...s, scope_type: e.target.value }))}
        style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', width: 90, flexShrink: 0 }}>
        {Object.entries(SCOPE_TYPES).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
      </select>
      <input value={editScope.value} onChange={e => setEditScope(s => ({ ...s, value: e.target.value }))}
        style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', flex: 1, minWidth: 120 }} />
      <input value={editScope.description} onChange={e => setEditScope(s => ({ ...s, description: e.target.value }))}
        placeholder="Description"
        style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', flex: 1, minWidth: 120 }} />
      {editScope.scope_type === 'cidr' && (
        <input value={editScope.gateway_ip} onChange={e => setEditScope(s => ({ ...s, gateway_ip: e.target.value }))}
          placeholder="Gateway IP"
          style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 7px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', width: 120, flexShrink: 0 }} />
      )}
      {editScope.scope_type === 'cidr' && (
        <select value={editScope.via_host_id} onChange={e => setEditScope(s => ({ ...s, via_host_id: e.target.value }))}
          style={{ ...selectStyle, fontSize: 10, width: 140, flexShrink: 0 }} title="Reachable via host">
          <option value="">— direct access —</option>
          {projectHosts.map(h => <option key={h.id} value={h.id}>{h.hostname || h.ip}</option>)}
        </select>
      )}
      {editScope.scope_type === 'cidr' && (
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
        <input type="checkbox" checked={editScope.is_entry} onChange={e => setEditScope(s => ({ ...s, is_entry: e.target.checked }))} />{' '}
        Entry
        </label>
      )}
      <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
        <button onClick={() => setEditScope(s => ({ ...s, in_scope: true }))}
          style={{ background: editScope.in_scope ? '#39d35322' : 'transparent', border: `1px solid ${editScope.in_scope ? '#39d35366' : '#2a2d35'}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: editScope.in_scope ? '#39d353' : '#505560', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
          ✓ In Scope
        </button>
        <button onClick={() => setEditScope(s => ({ ...s, in_scope: false }))}
          style={{ background: editScope.in_scope ? 'transparent' : '#cc223322', border: `1px solid ${editScope.in_scope ? '#2a2d35' : '#cc223366'}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: editScope.in_scope ? '#505560' : '#cc2233', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
          ✗ Exclude
        </button>
        <button onClick={() => saveEdit(scope.id)}
          style={{ background: accent, border: 'none', borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: '#fff', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
          Save
        </button>
        <button onClick={cancelEdit}
          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
          Cancel
        </button>
      </div>
    </>
  );
}

ScopeRowEdit.propTypes = {
  scope: PropTypes.object,
  editScope: PropTypes.object,
  setEditScope: PropTypes.func,
  projectHosts: PropTypes.array,
  selectStyle: PropTypes.object,
  accent: PropTypes.string,
  saveEdit: PropTypes.func,
  cancelEdit: PropTypes.func,
};

export default function ScopeView({ scopes, hosts, onAdd, onUpdate, onDelete, selectedProject, accent, fs = 14 }) {
  const [newScope, setNewScope] = useState(EMPTY);
  const [showAdd, setShowAdd] = useState(false);
  const [filterIn, setFilterIn] = useState(null);
  const [checkIp, setCheckIp] = useState('');
  const [editingId, setEditingId] = useState('');
  const [editScope, setEditScope] = useState(EMPTY);

  const projectScopes = scopes.filter(s => s.pid === selectedProject);
  const projectHosts = (hosts || []).filter(h => h.pid === selectedProject);

  const filtered = filterIn === null ? projectScopes
    : projectScopes.filter(s => s.in_scope === filterIn);

  const inCount  = projectScopes.filter(s => s.in_scope).length;
  const outCount = projectScopes.filter(s => !s.in_scope).length;

  const hostStatuses = useMemo(() => projectHosts.map(h => ({
    ...h,
    scopeStatus: checkHostInScope(h, projectScopes),
  })), [projectHosts, projectScopes]);

  const addScope = () => {
    if (!newScope.value.trim()) return;
    onAdd({ pid: selectedProject, ...newScope });
    setNewScope(EMPTY);
    setShowAdd(false);
  };

  const startEdit = (scope) => {
    setEditingId(scope.id);
    setEditScope({
      value: scope.value || '',
      scope_type: scope.scope_type || 'cidr',
      in_scope: !!scope.in_scope,
      description: scope.description || '',
      gateway_ip: scope.gateway_ip || '',
      is_entry: !!scope.is_entry,
      via_host_id: scope.via_host_id || '',
    });
  };

  const cancelEdit = () => {
    setEditingId('');
    setEditScope(EMPTY);
  };

  const saveEdit = (scopeId) => {
    if (!editScope.value.trim()) return;
    onUpdate(scopeId, {
      value: editScope.value,
      scope_type: editScope.scope_type,
      in_scope: editScope.in_scope,
      description: editScope.description,
      gateway_ip: editScope.gateway_ip,
      is_entry: editScope.is_entry,
      via_host_id: editScope.via_host_id,
    });
    cancelEdit();
  };

  const checkResult = useMemo(() => {
    if (!checkIp.trim() || !projectScopes.length) return null;
    const fakeHost = { ip: checkIp.trim(), hostname: checkIp.trim(), pid: selectedProject };
    return checkHostInScope(fakeHost, projectScopes);
  }, [checkIp, projectScopes]);

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {/* Left - scope list */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <div style={{ flex: 1 }}>
            <span style={{ fontSize: fs + 1, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>scope</span>
            <span style={{ fontSize: Math.max(10, fs - 2), color: '#404550', marginLeft: 10 }}>{inCount} in scope · {outCount} excluded</span>
          </div>
          <button onClick={() => setFilterIn(filterIn ? null : true)}
            style={{ background: filterIn ? '#39d35322' : 'transparent', border: `1px solid ${filterIn ? '#39d35388' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: filterIn ? '#39d353' : '#505560', fontFamily: 'JetBrains Mono' }}>
            ✓ In Scope {inCount}
          </button>
          <button onClick={() => setFilterIn(curr => Object.is(curr, false) ? null : false)}
            style={{ background: Object.is(filterIn, false) ? '#cc223322' : 'transparent', border: `1px solid ${Object.is(filterIn, false) ? '#cc223388' : '#2a2d35'}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: Object.is(filterIn, false) ? '#cc2233' : '#505560', fontFamily: 'JetBrains Mono' }}>
            ✗ Excluded {outCount}
          </button>
          <button onClick={() => setShowAdd(v => !v)}
            style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
            <Icon name="plus" size={10} color="#fff" /> Add
          </button>
        </div>

        {/* Add form */}
        {showAdd && (
          <ScopeAddForm newScope={newScope} setNewScope={setNewScope} projectHosts={projectHosts}
            accent={accent} addScope={addScope} onCancel={() => setShowAdd(false)} />
        )}

        {/* Check IP tool */}
        <div style={{ padding: '10px 18px', borderBottom: '1px solid #1a1c22', background: '#09090d', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <Icon name="scope" size={12} color="#404550" />
          <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>Check IP:</span>
          <input value={checkIp} onChange={e => setCheckIp(e.target.value)} placeholder="x.x.x.x"
            style={{ width: 160, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 7px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono' }} />
          {checkResult && (
            <span style={{ fontSize: 10, color: SCOPE_STATUS[checkResult].color, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
              → {SCOPE_STATUS[checkResult].label}
            </span>
          )}
        </div>

        {/* Scope list */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && (
            <div style={{ padding: 48, textAlign: 'center', color: '#303540' }}>
              <Icon name="scope" size={36} color="#2a2d35" />
              <div style={{ marginTop: 12, fontSize: 13, color: '#404550' }}>No entries. Add an IP range or domain.</div>
            </div>
          )}
          {filtered.map(scope => {
            const t = SCOPE_TYPES[scope.scope_type] || SCOPE_TYPES.cidr;
            const isEditing = editingId === scope.id;
            return (
              <div key={scope.id}
                style={{ display: 'flex', alignItems: 'center', minHeight: 44, padding: '8px 18px', borderBottom: '1px solid #14161b', gap: 12, borderLeft: `2px solid ${scope.in_scope ? '#39d35333' : '#cc223333'}` }}>
                {isEditing ? (
                  <ScopeRowEdit scope={scope} editScope={editScope} setEditScope={setEditScope} projectHosts={projectHosts} selectStyle={selectStyle} accent={accent} saveEdit={saveEdit} cancelEdit={cancelEdit} />
                ) : (
                  <ScopeRowView scope={scope} t={t} fs={fs} projectHosts={projectHosts} onUpdate={onUpdate} startEdit={startEdit} onDelete={onDelete} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Right - hosts coverage */}
      {projectHosts.length > 0 && (
        <div style={{ width: 280, background: '#0c0e13', borderLeft: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
          <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk' }}>Project hosts</span>
            <div style={{ fontSize: 9, color: '#404550', marginTop: 4 }}>
              {hostStatuses.filter(h => h.scopeStatus === 'in').length} in / {hostStatuses.filter(h => h.scopeStatus === 'out').length} out / {hostStatuses.filter(h => h.scopeStatus === 'excluded').length} excl.
            </div>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {hostStatuses.map(h => {
              const st = SCOPE_STATUS[h.scopeStatus];
              return (
                <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 14px', borderBottom: '1px solid #13151c' }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: st.color, flexShrink: 0 }} />
                  <span style={{ fontSize: 10, color: '#9098a8', fontFamily: 'JetBrains Mono', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {h.ip}{h.hostname ? ` (${h.hostname})` : ''}
                  </span>
                  <span style={{ fontSize: 8, color: st.color, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>{st.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

ScopeView.propTypes = {
  scopes: PropTypes.array,
  hosts: PropTypes.array,
  onAdd: PropTypes.func,
  onUpdate: PropTypes.func,
  onDelete: PropTypes.func,
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
  fs: PropTypes.number,
};
