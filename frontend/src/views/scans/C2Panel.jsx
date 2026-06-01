/**
 * C2 Integrations panel — CRUD, sessions, live agent inventory.
 *
 * Extracted from ScansView.jsx to reduce file size and isolate C2 concerns.
 */
import { useState, useEffect, useCallback, useMemo } from 'react';
import PropTypes from 'prop-types';
import Icon from '../../components/Icon.jsx';
import { api } from '../../api.js';
import { useProjectPermissions } from '../../context/ProjectPermissions.jsx';
import { isWsConnected } from '../../hooks/useSync.js';
import { FieldRow, Input } from './ScanFormFields.jsx';

// ── C2 type definitions ──────────────────────────────────────────────

export const C2_TYPES = [
  { id: 'adaptix', label: 'Adaptix',  color: '#c07af0', hint: 'REST API under /endpoint path. Username + password (or token). URL: https://host:port' },
  { id: 'mythic',  label: 'Mythic',   color: '#ffa726', hint: 'GraphQL API. Username + password OR apitoken (Settings → API Tokens). URL: https://host:7443' },
  { id: 'sliver',  label: 'Sliver',   color: '#5b8af5', hint: 'gRPC multiplayer. Paste the operator config JSON from sliver-server: `operator --name X --lhost ... --save .`' },
];

export const EMPTY_FORM = { name: '', type: 'adaptix', url: '', token: '', username: '', password: '', endpoint: '/endpoint', verify_ssl: false, project_ids: [], enabled: true, sync_interval_minutes: 0, has_token: false, has_password: false };

const SESSION_STATUS = {
  true:  { color: '#39d353', label: 'Active' },
  false: { color: '#6a7080', label: 'Dead'   },
};

// ── Helpers ───────────────────────────────────────────────────────────

function _sessionMatchesFilter(r, filter) {
  if (filter.aliveOnly && !r.alive) return false;
  if (filter.type && r.integration_type !== filter.type) return false;
  if (filter.tier && r.privilege_tier !== filter.tier) return false;
  if (filter.q) {
    const q = filter.q.toLowerCase();
    const blob = `${r.ip} ${r.hostname || ''} ${r.username || ''} ${r.domain || ''}`.toLowerCase();
    if (!blob.includes(q)) return false;
  }
  return true;
}

function _c2TokenLabel(type) {
  if (type === 'mythic') return 'API Token (preferred — set in Mythic UI → Settings)';
  if (type === 'sliver') return 'Operator Config (paste the entire JSON from sliver-server operator --save)';
  return 'API Token';
}

function _c2TokenPlaceholder(editing, has_token, type) {
  if (editing && has_token) return 'Stored - enter new to replace';
  if (editing) return '(leave blank to keep existing)';
  if (type === 'sliver') return '{"operator":"...","ca_certificate":"-----BEGIN CERTIFICATE-----..."}';
  return 'token...';
}

function _c2HasStoredSecrets(editing, form) {
  if (!editing) return false;
  if (form.type === 'adaptix' && form.has_password) return true;
  if (form.type === 'mythic' && (form.has_password || form.has_token)) return true;
  if (form.type !== 'adaptix' && form.type !== 'mythic' && form.has_token) return true;
  return false;
}

function _c2TypeInfo(type) { return C2_TYPES.find(t => t.id === type) || C2_TYPES[0]; }

function _c2SaveDisabled(saving, form) {
  if (saving || !form.name.trim()) return true;
  if (form.type !== 'sliver' && !form.url.trim()) return true;
  return false;
}

// ── Form sub-blocks ──────────────────────────────────────────────────

function C2FrameworkBlock({ form, editing, onSetF }) {
  return (
    <FieldRow label="C2 Framework">
      <div style={{ display: 'flex', gap: 6 }}>
        {C2_TYPES.map(t => (
          <button key={t.id} onClick={() => onSetF('type', t.id)} disabled={!!editing}
            style={{ flex: 1, background: form.type === t.id ? `${t.color}22` : '#1a1c22', border: `1px solid ${form.type === t.id ? t.color : '#2a2d35'}`, borderRadius: 5, padding: '8px 6px', cursor: editing ? 'not-allowed' : 'pointer', color: form.type === t.id ? t.color : '#505560', fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, textAlign: 'center' }}>
            {t.label}
          </button>
        ))}
      </div>
      <div style={{ fontSize: 10, color: '#404550', marginTop: 4 }}>{_c2TypeInfo(form.type).hint}</div>
    </FieldRow>
  );
}

C2FrameworkBlock.propTypes = {
  form: PropTypes.object,
  editing: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  onSetF: PropTypes.func,
};

function C2NameUrlBlock({ form, onSetF }) {
  if (form.type === 'sliver') {
    return (
      <FieldRow label="Name">
        <Input value={form.name} onChange={v => onSetF('name', v)} placeholder="My Sliver" />
      </FieldRow>
    );
  }
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      <FieldRow label="Name">
        <Input value={form.name} onChange={v => onSetF('name', v)} placeholder="My TeamServer" />
      </FieldRow>
      <FieldRow label="URL">
        <Input value={form.url} onChange={v => onSetF('url', v)} placeholder="https://1.2.3.4:50050" monospace />
      </FieldRow>
    </div>
  );
}

C2NameUrlBlock.propTypes = {
  form: PropTypes.object,
  onSetF: PropTypes.func,
};

function C2TypeFields({ form, editing, onSetF }) {
  if (form.type === 'adaptix') {
    return (
      <>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <FieldRow label="Username">
            <Input value={form.username} onChange={v => onSetF('username', v)} placeholder="operator1" />
          </FieldRow>
          <FieldRow label="Password">
            <Input value={form.password} onChange={v => onSetF('password', v)} placeholder={editing && form.has_password ? 'Stored - enter new to replace' : 'teamserver password'} />
          </FieldRow>
        </div>
        <FieldRow label="Endpoint path">
          <Input value={form.endpoint || '/endpoint'} onChange={v => onSetF('endpoint', v)} placeholder="/endpoint" monospace />
        </FieldRow>
      </>
    );
  }
  if (form.type === 'mythic') {
    return (
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <FieldRow label="Username (optional if API token set)">
          <Input value={form.username} onChange={v => onSetF('username', v)} placeholder="mythic_admin" />
        </FieldRow>
        <FieldRow label="Password">
          <Input value={form.password} onChange={v => onSetF('password', v)} placeholder={editing && form.has_password ? 'Stored - enter new to replace' : 'mythic password'} />
        </FieldRow>
      </div>
    );
  }
  return null;
}

C2TypeFields.propTypes = {
  form: PropTypes.object,
  editing: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  onSetF: PropTypes.func,
};

function C2ScopeBlock({ form, editing, accent, pid, isSuperAdmin, onSetF }) {
  const hasIds = form.project_ids?.length > 0;
  const isGlobal = form.project_ids?.length === 0;
  return (
    <FieldRow label="Project scope">
      <div style={{ display: 'flex', gap: 6 }}>
        <button onClick={() => onSetF('project_ids', pid ? [pid] : [])}
          style={{ flex: 1, background: hasIds ? `${accent}22` : '#1a1c22', border: `1px solid ${hasIds ? accent + '88' : '#2a2d35'}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: hasIds ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          This project only
        </button>
        <button onClick={() => isSuperAdmin && onSetF('project_ids', [])}
          disabled={!isSuperAdmin}
          title={isSuperAdmin ? '' : 'Only global admins can create unscoped integrations'}
          style={{ flex: 1, background: isGlobal ? `${accent}22` : '#1a1c22', border: `1px solid ${isGlobal ? accent + '88' : '#2a2d35'}`, borderRadius: 4, padding: '5px 10px', cursor: isSuperAdmin ? 'pointer' : 'not-allowed', color: isGlobal ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', opacity: isSuperAdmin ? 1 : 0.5 }}>
          All projects {!isSuperAdmin && '🔒'}
        </button>
      </div>
      {!isSuperAdmin && (
        <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', marginTop: 4 }}>
          As project owner you can register C2 integrations bound to this project.
          Unscoped (cross-project) integrations require a global admin.
        </div>
      )}
    </FieldRow>
  );
}

C2ScopeBlock.propTypes = {
  form: PropTypes.object,
  editing: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  accent: PropTypes.string,
  pid: PropTypes.string,
  isSuperAdmin: PropTypes.bool,
  onSetF: PropTypes.func,
};

// ── C2IntegrationForm ─────────────────────────────────────────────────

function C2IntegrationForm({ form, editing, saving, accent, pid, isSuperAdmin, errors, onSetF, onSave, onClose }) {
  return (
    <div style={{ background: '#0c0e13', border: `1px solid ${accent}44`, borderRadius: 8, padding: 18, marginTop: 8 }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec', marginBottom: 14 }}>
        {editing ? 'Edit Integration' : 'New C2 Integration'}
      </div>
      <C2FrameworkBlock form={form} editing={editing} onSetF={onSetF} />
      <C2NameUrlBlock form={form} onSetF={onSetF} />
      <C2TypeFields form={form} editing={editing} onSetF={onSetF} />
      <FieldRow label={_c2TokenLabel(form.type)}>
        <Input
          value={form.token}
          onChange={v => onSetF('token', v)}
          placeholder={_c2TokenPlaceholder(editing, form.has_token, form.type)}
          monospace
          multiline={form.type === 'sliver'}
          rows={form.type === 'sliver' ? 8 : 3}
        />
      </FieldRow>
      {_c2HasStoredSecrets(editing, form) && (
        <div style={{ fontSize: 10, color: '#606570', marginBottom: 10, fontFamily: 'JetBrains Mono' }}>
          Stored integration secrets are write-only. Leave blank to keep current values.
        </div>
      )}
      <FieldRow label="Auto-sync interval (minutes, 0 = manual only)">
        <Input value={String(form.sync_interval_minutes ?? 0)} onChange={v => onSetF('sync_interval_minutes', Number.parseInt(v) || 0)} placeholder="0" monospace />
      </FieldRow>
      <C2ScopeBlock form={form} editing={editing} accent={accent} pid={pid} isSuperAdmin={isSuperAdmin} onSetF={onSetF} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <button onClick={() => onSetF('verify_ssl', !form.verify_ssl)}
          style={{ background: form.verify_ssl ? '#1a3a1a' : '#1a1c22', border: `1px solid ${form.verify_ssl ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: form.verify_ssl ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {form.verify_ssl ? '✓ Verify SSL' : '✗ Ignore SSL (self-signed)'}
        </button>
        <button onClick={() => onSetF('enabled', !form.enabled)}
          style={{ background: form.enabled ? '#1a3a1a' : '#1a1c22', border: `1px solid ${form.enabled ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: form.enabled ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {form.enabled ? 'Enabled' : 'Disabled'}
        </button>
      </div>
      {errors.form && (
        <div style={{ color: '#cc2233', fontSize: 11, fontFamily: 'JetBrains Mono', marginBottom: 10 }}>{errors.form}</div>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={onSave} disabled={_c2SaveDisabled(saving, form)}
          style={{ background: saving ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: saving ? 'not-allowed' : 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          {(() => { if (saving) { return 'Saving...'; } if (editing) { return 'Save changes'; } return 'Add integration'; })()}
        </button>
        <button onClick={onClose}
          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          Cancel
        </button>
      </div>
    </div>
  );
}

C2IntegrationForm.propTypes = {
  form: PropTypes.object,
  editing: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  saving: PropTypes.bool,
  accent: PropTypes.string,
  pid: PropTypes.string,
  isSuperAdmin: PropTypes.bool,
  errors: PropTypes.object,
  onSetF: PropTypes.func,
  onSave: PropTypes.func,
  onClose: PropTypes.func,
};

// ── C2SessionsPanel (per-integration) ─────────────────────────────────

function C2SessionsPanel({ pid, accent, onNavigateToHost }) {
  const [sessions, setSessions] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [markingId, setMarkingId] = useState('');

  const load = useCallback(async () => {
    if (!pid) return;
    setLoading(true); setError('');
    try {
      const data = await api.getC2LiveSessions(pid);
      setSessions(data);
    } catch (e) {
      setError(e.message || 'Failed to fetch sessions');
    }
    setLoading(false);
  }, [pid]);

  useEffect(() => { load(); }, [load]);

  const markStatus = async (hostId, status) => {
    if (!hostId) return;
    setMarkingId(hostId);
    try {
      await api.updateHost(hostId, { status });
      setSessions(prev => prev ? prev.map(s => s.matched_host_id === hostId ? { ...s, matched_host_status: status } : s) : prev);
    } catch {}
    setMarkingId('');
  };

  const grouped = useMemo(() => {
    if (!sessions) return {};
    const map = {};
    for (const s of sessions) {
      const key = s.integration_name || s.integration_id;
      if (!map[key]) map[key] = { name: key, type: s.integration_type, sessions: [], error: null, deadCount: 0 };
      if (s.error) { map[key].error = s.error; continue; }
      if (s.alive === false) { map[key].deadCount++; continue; }
      map[key].sessions.push(s);
    }
    return map;
  }, [sessions]);

  const acc = accent || '#5b8af5';
  const typeColors = { adaptix: '#00bcd4', mythic: '#ffa726', sliver: '#8bc34a' };

  return (
    <div style={{ marginTop: 20, borderTop: '1px solid #1e2230', paddingTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec' }}>Live Sessions</span>
        <button onClick={load} disabled={loading}
          style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {loading ? 'Loading...' : 'Refresh'}
        </button>
        {sessions && <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>{sessions.filter(s => !s.error && s.alive !== false).length} live agent(s)</span>}
      </div>

      {error && <div style={{ fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono', marginBottom: 8 }}>{error}</div>}

      {sessions && Object.values(grouped).map(group => (
        <div key={group.name} style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
            <span style={{ fontSize: 10, color: typeColors[group.type] || '#808590', background: `${typeColors[group.type] || '#808590'}18`, border: `1px solid ${typeColors[group.type] || '#808590'}44`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>{group.type}</span>
            <span style={{ fontSize: 11, color: '#808590' }}>{group.name}</span>
            {group.deadCount > 0 && <span title={`${group.deadCount} dead agents hidden`} style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>({group.deadCount} dead hidden)</span>}
          </div>
          {group.error && (
            <div style={{ fontSize: 10, color: '#cc2233', fontFamily: 'JetBrains Mono', padding: '6px 8px', background: '#1a0508', border: '1px solid #cc223333', borderRadius: 4 }}>{group.error}</div>
          )}
          {group.sessions.length === 0 && !group.error && (
            <div style={{ fontSize: 10, color: '#404550', padding: '6px 0', fontFamily: 'JetBrains Mono' }}>No active agents</div>
          )}
          {group.sessions.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1e2230' }}>
                  {['', 'Host', 'IP', 'Privilege', 'User', 'OS', 'Process / Listener', 'Last seen', 'Action'].map((h, i) => (
                    <th key={`th-${h || 'idx'}`} style={{ padding: '4px 8px', color: '#404550', fontWeight: 500, fontSize: 10, textAlign: 'left', fontFamily: 'JetBrains Mono' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {group.sessions.map((s, idx) => {
                  const stCfg = SESSION_STATUS[String(s.alive)] || SESSION_STATUS.true;
                  const userStr = [s.username, s.domain].filter(Boolean).join('@') || '—';
                  const os = [s.os, s.arch].filter(Boolean).join(' ') || '—';
                  const procListener = [s.process, s.listener].filter(Boolean).join(' / ') || '—';
                  const tier = s.privilege_tier || 'user';
                  const privColors = { system: '#cc2233', admin: '#f09a3a', user: '#5b8af5' };
                  const privColor = privColors[tier] || '#808590';
                  const suggestedStatus = s.suggested_status || (tier === 'user' ? 'access' : 'pwned');
                  const actionLabel = suggestedStatus === 'pwned' ? '→ pwned' : '→ access';
                  const actionColor = suggestedStatus === 'pwned' ? '#cc2233' : '#f09a3a';
                  const alreadyMarked = s.matched_host_status === suggestedStatus || s.matched_host_status === 'pwned' || s.matched_host_status === 'owned';
                  return (
                    <tr key={`row-${s.ip || s.host || idx}`} style={{ borderBottom: '1px solid #14161b', opacity: s.alive ? 1 : 0.4 }}>
                      <td style={{ padding: '5px 8px' }}>
                        <span title={s.mark || stCfg.label} style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', background: stCfg.color }} />
                      </td>
                      <td style={{ padding: '5px 8px', color: '#c8cfe0', fontFamily: 'JetBrains Mono' }}>{s.hostname || '—'}</td>
                      <td style={{ padding: '5px 8px', color: '#808590', fontFamily: 'JetBrains Mono' }}>{s.ip || '—'}</td>
                      <td style={{ padding: '5px 8px' }}>
                        <span style={{ fontSize: 9, color: privColor, background: `${privColor}18`, border: `1px solid ${privColor}44`, borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
                          {s.privilege_label || tier}
                        </span>
                      </td>
                      <td style={{ padding: '5px 8px', color: '#c07af0', fontFamily: 'JetBrains Mono', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{userStr}</td>
                      <td style={{ padding: '5px 8px', color: '#606570', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis' }}>{os}</td>
                      <td style={{ padding: '5px 8px', color: '#404550', fontFamily: 'JetBrains Mono', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{procListener}</td>
                      <td style={{ padding: '5px 8px', color: '#404550', fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap', fontSize: 10 }}>{s.last_seen || '—'}</td>
                      <td style={{ padding: '5px 8px' }}>
                        {s.matched_host_id ? (
                          <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                            {s.alive && !alreadyMarked && (
                              <button onClick={() => markStatus(s.matched_host_id, suggestedStatus)} disabled={markingId === s.matched_host_id}
                                style={{ fontSize: 9, color: actionColor, background: `${actionColor}18`, border: `1px solid ${actionColor}44`, borderRadius: 3, padding: '1px 7px', cursor: 'pointer', fontFamily: 'JetBrains Mono', fontWeight: 600 }}>
                                {markingId === s.matched_host_id ? '...' : actionLabel}
                              </button>
                            )}
                            {alreadyMarked && (
                              <span style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono' }}>{s.matched_host_status}</span>
                            )}
                          </div>
                        ) : (
                          <span style={{ fontSize: 9, color: '#353840', fontFamily: 'JetBrains Mono' }}>no match</span>
                        )}
                      </td>
                      <td style={{ padding: '5px 8px' }}>
                        {s.matched_host_id && onNavigateToHost && (
                          <button onClick={() => onNavigateToHost(s.matched_host_id)}
                            style={{ fontSize: 9, color: acc, background: `${acc}18`, border: `1px solid ${acc}44`, borderRadius: 3, padding: '1px 6px', cursor: 'pointer', fontFamily: 'JetBrains Mono' }}>
                            → host
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      ))}
    </div>
  );
}

C2SessionsPanel.propTypes = {
  pid: PropTypes.string,
  accent: PropTypes.string,
  onNavigateToHost: PropTypes.func,
};

// ── SessionsPanel (cross-integration) ─────────────────────────────────

export function SessionsPanel({ pid, accent }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadedAt, setLoadedAt] = useState(null);
  const [filter, setFilter] = useState({ type: '', tier: '', q: '', aliveOnly: true });
  const [autoRefresh, setAutoRefresh] = useState(false);

  const load = useCallback(async () => {
    if (!pid) return;
    setLoading(true);
    try {
      const data = await api.getC2LiveSessions(pid);
      setRows(Array.isArray(data) ? data : []);
      setLoadedAt(new Date());
    } catch (e) {
      console.error('Live sessions fetch failed:', e);
    }
    setLoading(false);
  }, [pid]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!autoRefresh) return;
    let t;
    const schedule = () => {
      clearInterval(t);
      t = setInterval(load, isWsConnected() ? 60000 : 15000);
    };
    schedule();
    const onWs = () => schedule();
    globalThis.addEventListener('rt:ws-state', onWs);
    return () => { clearInterval(t); globalThis.removeEventListener('rt:ws-state', onWs); };
  }, [autoRefresh, load]);

  const errorRows = rows.filter(r => r.error);
  const sessionRows = rows.filter(r => !r.error);

  const perIntegration = {};
  for (const r of sessionRows) {
    const k = r.integration_id;
    if (!perIntegration[k]) {
      perIntegration[k] = { name: r.integration_name, type: r.integration_type, total: 0, alive: 0 };
    }
    perIntegration[k].total++;
    if (r.alive) perIntegration[k].alive++;
  }

  const filtered = sessionRows.filter(r => _sessionMatchesFilter(r, filter));

  const tierColor = { system: '#cc2233', admin: '#f09a3a', user: '#5b8af5' };
  const typeColor = { adaptix: '#c07af0', mythic: '#ffa726', sliver: '#5b8af5' };

  return (
    <div>
      {/* Per-integration health */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 14 }}>
        {Object.entries(perIntegration).map(([id, info]) => (
          <div key={id} style={{ background: '#0c0e13', border: `1px solid ${typeColor[info.type] || '#2a2d35'}55`, borderRadius: 6, padding: '6px 12px', fontSize: 11, fontFamily: 'JetBrains Mono', color: '#c8cdd6', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: typeColor[info.type] || '#808590', fontWeight: 600 }}>{info.name}</span>
            <span style={{ color: '#39d353', fontSize: 10 }}>● {info.alive} live</span>
            <span style={{ color: '#505560', fontSize: 10 }}>{info.total} total</span>
          </div>
        ))}
        {errorRows.map((r, i) => (
          <div key={`err-${r.ip || r.host || i}`} style={{ background: '#1a0508', border: '1px solid #cc223355', borderRadius: 6, padding: '6px 12px', fontSize: 11, fontFamily: 'JetBrains Mono', color: '#cc2233' }}>
            ⚠ {r.integration_name}: {r.error}
          </div>
        ))}
      </div>

      {/* Toolbar */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
        <input type="text" placeholder="Search ip / hostname / user…" value={filter.q}
          onChange={e => setFilter(f => ({ ...f, q: e.target.value }))}
          style={{ flex: 1, minWidth: 200, padding: '6px 10px', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none' }} />
        <select value={filter.type} onChange={e => setFilter(f => ({ ...f, type: e.target.value }))}
          style={{ padding: '6px 10px', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          <option value="">All C2 types</option>
          <option value="adaptix">Adaptix</option>
          <option value="mythic">Mythic</option>
          <option value="sliver">Sliver</option>
        </select>
        <select value={filter.tier} onChange={e => setFilter(f => ({ ...f, tier: e.target.value }))}
          style={{ padding: '6px 10px', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          <option value="">All privileges</option>
          <option value="system">SYSTEM</option>
          <option value="admin">Admin</option>
          <option value="user">User</option>
        </select>
        <button onClick={() => setFilter(f => ({ ...f, aliveOnly: !f.aliveOnly }))}
          style={{ background: filter.aliveOnly ? '#1a3a1a' : '#1a1c22', border: `1px solid ${filter.aliveOnly ? '#39d353' : '#2a2d35'}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: filter.aliveOnly ? '#39d353' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {filter.aliveOnly ? '✓ Alive only' : 'Alive only'}
        </button>
        <button onClick={() => setAutoRefresh(v => !v)}
          style={{ background: autoRefresh ? '#0e1a2a' : '#1a1c22', border: `1px solid ${autoRefresh ? '#5b8af5' : '#2a2d35'}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: autoRefresh ? '#5b8af5' : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          {autoRefresh ? '↻ Auto (15s)' : 'Auto refresh'}
        </button>
        <button onClick={load} disabled={loading}
          style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 12px', cursor: loading ? 'not-allowed' : 'pointer', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
          <Icon name="reset" size={11} color="#c8cdd6" /> {loading ? 'Loading…' : 'Refresh'}
        </button>
        {loadedAt && (
          <span style={{ fontSize: 9, color: '#404550', fontFamily: 'JetBrains Mono' }}>
            updated {loadedAt.toTimeString().slice(0, 8)}
          </span>
        )}
      </div>

      {/* Sessions table */}
      {sessionRows.length === 0 && !loading && (
        <div style={{ padding: '32px 0', textAlign: 'center', color: '#353840', fontSize: 12, fontFamily: 'JetBrains Mono' }}>
          No live sessions. Configure a C2 integration and run a sync first.
        </div>
      )}
      {filtered.length > 0 && (
        <div style={{ background: '#0c0e13', border: '1px solid #1a1c22', borderRadius: 6, overflow: 'hidden' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '120px 160px 1fr 140px 90px 90px 100px', gap: 0, fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '8px 12px', borderBottom: '1px solid #1a1c22', background: '#0a0c10' }}>
            <div>IP</div><div>Hostname</div><div>User / Domain</div><div>Integration</div><div>Priv</div><div>Status</div><div>Last seen</div>
          </div>
          {filtered.map((r, i) => (
            <div key={`${r.integration_id}-${r.ip}-${r.privilege_tier}-${i}`}
              style={{ display: 'grid', gridTemplateColumns: '120px 160px 1fr 140px 90px 90px 100px', gap: 0, fontSize: 11, color: '#b0b5c2', fontFamily: 'JetBrains Mono', padding: '8px 12px', borderBottom: '1px solid #0e1016', alignItems: 'center', opacity: r.alive ? 1 : 0.5 }}>
              <div style={{ color: '#e0e4ec' }}>{r.ip}</div>
              <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.hostname}>
                {r.hostname || <span style={{ color: '#353840' }}>—</span>}
              </div>
              <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <span style={{ color: '#c8cdd6' }}>{r.username || '—'}</span>
                {r.domain && <span style={{ color: '#606570' }}> @ {r.domain}</span>}
              </div>
              <div>
                <span style={{ fontSize: 9, color: typeColor[r.integration_type] || '#808590', background: `${typeColor[r.integration_type] || '#808590'}18`, border: `1px solid ${typeColor[r.integration_type] || '#808590'}44`, borderRadius: 3, padding: '1px 6px' }}>
                  {r.integration_name}
                </span>
              </div>
              <div>
                <span style={{ fontSize: 9, fontWeight: 700, color: tierColor[r.privilege_tier] || '#808590', background: `${tierColor[r.privilege_tier] || '#808590'}18`, border: `1px solid ${tierColor[r.privilege_tier] || '#808590'}44`, borderRadius: 3, padding: '1px 6px', textTransform: 'uppercase' }}>
                  {r.privilege_label || r.privilege_tier}
                </span>
              </div>
              <div>
                {r.alive
                  ? <span style={{ color: '#39d353', fontSize: 10 }}>● alive</span>
                  : <span style={{ color: '#606570', fontSize: 10 }}>○ dead</span>}
              </div>
              <div style={{ fontSize: 10, color: '#505560' }} title={r.last_seen || ''}>
                {(r.last_seen || '').slice(0, 16).replace('T', ' ') || '—'}
              </div>
            </div>
          ))}
        </div>
      )}
      {filtered.length === 0 && sessionRows.length > 0 && (
        <div style={{ padding: '24px 0', textAlign: 'center', color: '#404550', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          {sessionRows.length} session(s) total — none match the current filter.
        </div>
      )}
    </div>
  );
}

SessionsPanel.propTypes = {
  pid: PropTypes.string,
  accent: PropTypes.string,
};

// ── C2Panel (main — CRUD list + form) ─────────────────────────────────

export default function C2Panel({ pid, accent }) {
  const { role: projectRole, isSuperAdmin } = useProjectPermissions();
  const isProjectOwner = String(projectRole) === 'owner';
  const canManage = isSuperAdmin || isProjectOwner;
  const canManageIntegration = useCallback((cfg) => {
    if (isSuperAdmin) return true;
    if (!isProjectOwner) return false;
    const ids = cfg?.project_ids || [];
    return ids.length > 0 && pid && ids.includes(pid);
  }, [isSuperAdmin, isProjectOwner, pid]);

  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState('');
  const [syncing, setSyncing] = useState('');
  const [results, setResults] = useState({});
  const [errors, setErrors] = useState({});

  const load = useCallback(async () => {
    try {
      const r = pid ? await api.listC2ForProject(pid) : await api.listC2Integrations();
      setIntegrations(r);
    } catch (e) {
      if (e.message?.includes('403')) {
        setErrors({ global: 'You do not have permission to view C2 integrations in this project' });
      } else if (e.message) {
        setErrors({ global: e.message });
      }
    }
    setLoading(false);
  }, [pid]);

  useEffect(() => { load(); }, [load]);

  const setF = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const openNew = () => { setForm({ ...EMPTY_FORM, project_ids: pid ? [pid] : [] }); setEditing(null); setShowForm(true); };
  const openEdit = (cfg) => {
    setForm({ ...cfg, token: '', password: '' });
    setEditing(cfg.id);
    setShowForm(true);
  };
  const closeForm = () => { setShowForm(false); setEditing(null); };

  const save = async () => {
    if (!form.name.trim()) return;
    if (form.type !== 'sliver' && !form.url.trim()) return;
    if (!isSuperAdmin && (!form.project_ids || form.project_ids.length === 0)) {
      setErrors(prev => ({ ...prev, form: 'Project owners must scope the integration to a project. Switch to "This project only".' }));
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        const patch = { ...form };
        if (!patch.token) delete patch.token;
        if (!patch.password) delete patch.password;
        const r = await api.updateC2Integration(editing, patch);
        setIntegrations(prev => prev.map(i => i.id === editing ? r : i));
      } else {
        const r = await api.createC2Integration(form);
        setIntegrations(prev => [...prev, r]);
      }
      closeForm();
    } catch (e) {
      setErrors(prev => ({ ...prev, form: e.message }));
    }
    setSaving(false);
  };

  const remove = async (id) => {
    await api.deleteC2Integration(id);
    setIntegrations(prev => prev.filter(i => i.id !== id));
  };

  const test = async (id) => {
    setTesting(id);
    setResults(prev => ({ ...prev, [id]: null }));
    setErrors(prev => ({ ...prev, [id]: '' }));
    try {
      const r = await api.testC2Integration(id);
      setResults(prev => ({ ...prev, [id]: `✓ Connected — ${r.hosts_found} sessions, ${r.creds_found} creds` }));
    } catch (e) {
      setErrors(prev => ({ ...prev, [id]: e.message || 'Connection failed' }));
    }
    setTesting('');
  };

  const sync = async (id) => {
    setSyncing(id);
    setResults(prev => ({ ...prev, [id + '_sync']: null }));
    setErrors(prev => ({ ...prev, [id + '_sync']: '' }));
    try {
      const r = await api.syncC2ToProject(id, pid);
      setResults(prev => ({ ...prev, [id + '_sync']: `Synced: ${r.hosts_created} new hosts, ${r.hosts_updated} updated, ${r.creds_created} creds` }));
    } catch (e) {
      setErrors(prev => ({ ...prev, [id + '_sync']: e.message || 'Sync failed' }));
    }
    setSyncing('');
  };

  const typeInfo = (type) => C2_TYPES.find(t => t.id === type) || C2_TYPES[0];
  if (loading) return <div style={{ color: '#404550', fontSize: 12 }}>Loading...</div>;

  return (
    <div>
      {errors.global && (
        <div style={{ background: '#1a0508', border: '1px solid #cc223344', borderRadius: 6, padding: 12, marginBottom: 16, fontSize: 12, color: '#cc2233', fontFamily: 'JetBrains Mono' }}>
          {errors.global}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 16 }}>
        {integrations.length === 0 && !showForm && (
          <div style={{ padding: '32px 0', textAlign: 'center', color: '#353840', fontSize: 12 }}>
            No C2 integrations configured. Add one to start syncing sessions.
          </div>
        )}

        {integrations.map(cfg => {
          const ti = typeInfo(cfg.type);
          const isSyncing = syncing === cfg.id;
          const isTesting = testing === cfg.id;
          return (
            <div key={cfg.id} style={{ background: '#0c0e13', border: `1px solid ${cfg.enabled ? '#1a1c22' : '#141618'}`, borderRadius: 8, padding: 14, opacity: cfg.enabled ? 1 : 0.5 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: cfg.enabled ? ti.color : '#353840', flexShrink: 0 }} />
                <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', flex: 1 }}>{cfg.name}</span>
                <span style={{ fontSize: 10, color: ti.color, fontFamily: 'JetBrains Mono', background: `${ti.color}18`, border: `1px solid ${ti.color}44`, borderRadius: 10, padding: '2px 8px' }}>
                  {ti.label}
                </span>
                {cfg.last_sync && (
                  <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>
                    last sync: {cfg.last_sync}
                  </span>
                )}
              </div>

              <div style={{ fontSize: 11, color: '#505560', fontFamily: 'JetBrains Mono', marginBottom: 10 }}>
                {cfg.url}
              </div>

              {results[cfg.id] && (
                <div style={{ fontSize: 11, color: '#39d353', fontFamily: 'JetBrains Mono', marginBottom: 8, background: '#0a1208', border: '1px solid #39d35344', borderRadius: 4, padding: '6px 10px' }}>
                  {results[cfg.id]}
                </div>
              )}
              {errors[cfg.id] && (
                <div style={{ fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono', marginBottom: 8, background: '#1a0508', border: '1px solid #cc223344', borderRadius: 4, padding: '6px 10px' }}>
                  {errors[cfg.id]}
                </div>
              )}
              {results[cfg.id + '_sync'] && (
                <div style={{ fontSize: 11, color: '#39d353', fontFamily: 'JetBrains Mono', marginBottom: 8, background: '#0a1208', border: '1px solid #39d35344', borderRadius: 4, padding: '6px 10px' }}>
                  {results[cfg.id + '_sync']}
                </div>
              )}
              {errors[cfg.id + '_sync'] && (
                <div style={{ fontSize: 11, color: '#cc2233', fontFamily: 'JetBrains Mono', marginBottom: 8, background: '#1a0508', border: '1px solid #cc223344', borderRadius: 4, padding: '6px 10px' }}>
                  {errors[cfg.id + '_sync']}
                </div>
              )}

              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <button onClick={() => test(cfg.id)} disabled={isTesting || !cfg.enabled}
                  style={{ background: '#1a1c22', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 12px', cursor: isTesting || !cfg.enabled ? 'not-allowed' : 'pointer', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Icon name="check" size={10} color="#808590" />
                  {isTesting ? 'Testing...' : 'Test'}
                </button>
                <button onClick={() => sync(cfg.id)} disabled={isSyncing || !cfg.enabled}
                  style={{ background: isSyncing ? '#1a1c22' : `${ti.color}22`, border: `1px solid ${ti.color}55`, borderRadius: 4, padding: '5px 12px', cursor: isSyncing || !cfg.enabled ? 'not-allowed' : 'pointer', color: ti.color, fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Icon name="reset" size={10} color={ti.color} />
                  {isSyncing ? 'Syncing...' : 'Sync → project'}
                </button>
                {canManageIntegration(cfg) ? (
                  <>
                    <button onClick={() => openEdit(cfg)}
                      style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                      Edit
                    </button>
                    <button onClick={() => remove(cfg.id)}
                      style={{ background: 'transparent', border: '1px solid #cc233344', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#cc2233', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                      Delete
                    </button>
                  </>
                ) : (
                  <span style={{ fontSize: 10, color: '#353840', fontFamily: 'JetBrains Mono', padding: '5px 0' }}>Read-only</span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {canManage && !showForm && (
        <button onClick={openNew}
          style={{ background: accent || '#5b8af5', border: 'none', borderRadius: 5, padding: '8px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Icon name="plus" size={12} color="#fff" />
          Add integration
        </button>
      )}

      {showForm && (
        <C2IntegrationForm form={form} editing={editing} saving={saving} accent={accent} pid={pid}
          isSuperAdmin={isSuperAdmin} errors={errors} onSetF={setF} onSave={save} onClose={closeForm} />
      )}

      <C2SessionsPanel pid={pid} accent={accent} />
    </div>
  );
}

C2Panel.propTypes = {
  pid: PropTypes.string,
  accent: PropTypes.string,
};
