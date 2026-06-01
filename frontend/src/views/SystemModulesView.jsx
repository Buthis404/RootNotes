import { useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { moduleRegistry } from '../features/plugins/registry.js';

const INP_STYLE = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

const EMPTY_TARGET = { name: '', host: '', port: 22, username: '', password: '', private_key: '', known_hosts_policy: 'accept_new', proxy_type: 'none', proxy_host: '', proxy_port: 1080, proxy_username: '', proxy_password: '', proxy_private_key: '', exec_proxy_type: 'none', exec_proxy_host: '', exec_proxy_port: 1080, exec_proxy_username: '', exec_proxy_password: '', exec_jump_host: '', exec_jump_port: 22, exec_jump_username: '', project_ids: [], enabled: true, is_operator: true, runs_pivot: true, has_password: false, has_private_key: false, has_proxy_password: false, has_proxy_private_key: false, has_exec_proxy_password: false };

function FieldLabel({ children }) {
  return <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{children}</div>;
}
FieldLabel.propTypes = { children: PropTypes.any };

function ProxyCredFields({ form, setForm, isEditing, enabled }) {
  if (form.proxy_type !== 'jump' && form.proxy_type !== 'socks5') {
    return null;
  }
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
      <div>
        <FieldLabel>Proxy password</FieldLabel>
        <input style={INP_STYLE} type="password" value={form.proxy_password} onChange={e => setForm(prev => ({ ...prev, proxy_password: e.target.value }))} disabled={!enabled} placeholder={(() => { if (isEditing && form.has_proxy_password) { return 'Stored - enter new to replace'; } if (form.proxy_type === 'jump') { return 'Optional if using key'; } return 'Optional for SOCKS5 auth'; })()} />
      </div>
      <div>
        <FieldLabel>Proxy private key (PEM)</FieldLabel>
        <textarea style={{ ...INP_STYLE, resize: 'vertical', minHeight: 80, opacity: form.proxy_type === 'socks5' ? 0.55 : 1 }} value={form.proxy_private_key} onChange={e => setForm(prev => ({ ...prev, proxy_private_key: e.target.value }))} disabled={!enabled || form.proxy_type === 'socks5'} placeholder={isEditing && form.has_proxy_private_key ? 'Stored - paste new PEM to replace' : 'Optional - paste PEM key for jump host'} />
      </div>
    </div>
  );
}
ProxyCredFields.propTypes = { form: PropTypes.any, setForm: PropTypes.any, isEditing: PropTypes.any, enabled: PropTypes.any };

function ProxySection({ form, setForm, isEditing, enabled }) {
  const transportAdvancedEnabled = form.proxy_type !== 'none';

  const toggleTransportAdvanced = (checked) => {
    setForm(prev => checked
      ? { ...prev, proxy_type: prev.proxy_type === 'none' ? 'jump' : prev.proxy_type }
      : { ...prev, proxy_type: 'none', proxy_host: '', proxy_port: 1080, proxy_username: '', proxy_password: '', proxy_private_key: '' });
  };

  return (
    <div style={{ marginBottom: 14, background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px' }}>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: enabled ? 'pointer' : 'default' }}>
        <input type="checkbox" checked={transportAdvancedEnabled} disabled={!enabled} onChange={e => toggleTransportAdvanced(e.target.checked)} />
        <span style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>Use proxy / jump host to reach attacker</span>
      </label>
      {transportAdvancedEnabled && (
        <div style={{ marginTop: 10 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '140px 1.1fr 90px 1fr', gap: 10, marginBottom: 10 }}>
            <div>
              <FieldLabel>Mode</FieldLabel>
              <select style={INP_STYLE} value={form.proxy_type} onChange={e => setForm(prev => ({ ...prev, proxy_type: e.target.value }))} disabled={!enabled}>
                <option value="none">none</option>
                <option value="jump">jump host</option>
                <option value="socks5">socks5</option>
              </select>
            </div>
            <div>
              <FieldLabel>Proxy host</FieldLabel>
              <input style={INP_STYLE} value={form.proxy_host} disabled={!enabled || form.proxy_type === 'none'} onChange={e => setForm(prev => ({ ...prev, proxy_host: e.target.value }))} placeholder="bastion.local / 127.0.0.1" />
            </div>
            <div>
              <FieldLabel>Proxy port</FieldLabel>
              <input style={INP_STYLE} type="number" value={form.proxy_port} disabled={!enabled || form.proxy_type === 'none'} onChange={e => setForm(prev => ({ ...prev, proxy_port: Number(e.target.value) || (prev.proxy_type === 'jump' ? 22 : 1080) }))} />
            </div>
            <div>
              <FieldLabel>Proxy username</FieldLabel>
              <input style={INP_STYLE} value={form.proxy_username} disabled={!enabled || form.proxy_type === 'none'} onChange={e => setForm(prev => ({ ...prev, proxy_username: e.target.value }))} placeholder={(() => { if (form.proxy_type === 'jump') { return 'Required for jump host'; } if (form.proxy_type === 'socks5') { return 'Optional for SOCKS5 auth'; } return ''; })()} />
            </div>
          </div>
          <ProxyCredFields form={form} setForm={setForm} isEditing={isEditing} enabled={enabled} />
          {form.proxy_type === 'socks5' && (
            <div style={{ fontSize: 10, color: '#606570', marginTop: 8, fontFamily: 'JetBrains Mono' }}>
              SOCKS5 mode now supports optional username/password authentication.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
ProxySection.propTypes = { form: PropTypes.any, setForm: PropTypes.any, isEditing: PropTypes.any, enabled: PropTypes.any };

function RoleFlagsSection({ form, setForm, enabled }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <FieldLabel>Host role</FieldLabel>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        <label aria-label="Operator host" style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: enabled ? 'pointer' : 'default' }}>
          <input type="checkbox" checked={!!form.is_operator} disabled={!enabled}
            onChange={e => setForm(prev => ({ ...prev, is_operator: e.target.checked }))} />
          <div>
            <div style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>Operator host</div>
            <div style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>Run scans, bulk exec, playbook commands from this host</div>
          </div>
        </label>
        <label aria-label="Runs chisel or ligolo pivot" style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: enabled ? 'pointer' : 'default' }}>
          <input type="checkbox" checked={!!form.runs_pivot} disabled={!enabled}
            onChange={e => setForm(prev => ({ ...prev, runs_pivot: e.target.checked }))} />
          <div>
            <div style={{ fontSize: 11, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>Runs chisel / ligolo (pivot box)</div>
            <div style={{ fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>Pivot collector will SSH here to read ps / routes / ss state</div>
          </div>
        </label>
      </div>
      {!form.is_operator && !form.runs_pivot && (
        <div style={{ marginTop: 6, fontSize: 10, color: '#cc6633', fontFamily: 'JetBrains Mono' }}>
          Select at least one role — otherwise this host can't be used for anything.
        </div>
      )}
    </div>
  );
}
RoleFlagsSection.propTypes = { form: PropTypes.any, setForm: PropTypes.any, enabled: PropTypes.any };

function ProjectScopeSection({ form, setForm, projects, enabled, accent }) {
  const toggleProjectId = (pid) => {
    setForm(prev => {
      const ids = prev.project_ids || [];
      return { ...prev, project_ids: ids.includes(pid) ? ids.filter(x => x !== pid) : [...ids, pid] };
    });
  };

  return (
    <div style={{ marginBottom: 14 }}>
      <FieldLabel>Project scope</FieldLabel>
      <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
        <button onClick={() => setForm(prev => ({ ...prev, project_ids: [] }))} disabled={!enabled}
          style={{ background: (form.project_ids || []).length === 0 ? `${accent}22` : '#1a1c22', border: `1px solid ${(form.project_ids || []).length === 0 ? accent : '#2a2d35'}`, borderRadius: 4, padding: '4px 12px', cursor: 'pointer', color: (form.project_ids || []).length === 0 ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          Global (all projects)
        </button>
        <button onClick={() => { if ((form.project_ids || []).length === 0 && projects.length > 0) setForm(prev => ({ ...prev, project_ids: [projects[0].id] })); }} disabled={!enabled || projects.length === 0}
          style={{ background: (form.project_ids || []).length > 0 ? `${accent}22` : '#1a1c22', border: `1px solid ${(form.project_ids || []).length > 0 ? accent : '#2a2d35'}`, borderRadius: 4, padding: '4px 12px', cursor: 'pointer', color: (form.project_ids || []).length > 0 ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          Specific projects
        </button>
      </div>
      {(form.project_ids || []).length > 0 && projects.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {projects.map(p => {
            const sel = (form.project_ids || []).includes(p.id);
            return (
              <button key={p.id} onClick={() => toggleProjectId(p.id)} disabled={!enabled}
                style={{ background: sel ? `${accent}22` : '#13151a', border: `1px solid ${sel ? accent : '#2a2d35'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: sel ? accent : '#505560', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>
                {sel && <span style={{ fontSize: 9 }}>✓</span>}
                {p.name}
              </button>
            );
          })}
        </div>
      )}
      {(form.project_ids || []).length === 0 && (
        <div style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>
          This target will be available to all projects
        </div>
      )}
    </div>
  );
}
ProjectScopeSection.propTypes = { form: PropTypes.any, setForm: PropTypes.any, projects: PropTypes.any, enabled: PropTypes.any, accent: PropTypes.any };

function StoredSecretsNote({ isEditing, form }) {
  const showMain = isEditing && (form.has_password || form.has_private_key);
  const showProxy = isEditing && (form.has_proxy_password || form.has_proxy_private_key) && form.proxy_type === 'jump';
  if (!showMain && !showProxy) {
    return null;
  }
  return (
    <>
      {showMain && (
        <div style={{ fontSize: 10, color: '#606570', marginBottom: 10, fontFamily: 'JetBrains Mono' }}>
          Stored secrets are write-only. Leave fields blank to keep current values.
        </div>
      )}
      {showProxy && (
        <div style={{ fontSize: 10, color: '#606570', marginBottom: 10, fontFamily: 'JetBrains Mono' }}>
          Stored proxy credentials are also write-only. Leave fields blank to keep current jump-host secrets.
        </div>
      )}
    </>
  );
}
StoredSecretsNote.propTypes = { isEditing: PropTypes.any, form: PropTypes.any };

function TestResultBlock({ testState }) {
  if (!testState.result) {
    return null;
  }
  const extraLines = [testState.result.stdout, testState.result.stderr].filter(Boolean);
  return (
    <pre style={{ background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '10px 12px', color: testState.result.ok ? '#39d353' : '#f09a3a', fontSize: 11, fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', margin: 0 }}>
      {testState.result.ok ? 'Connection OK' : 'Connection failed'}{extraLines.length ? '\n\n' + extraLines.join('\n') : ''}
    </pre>
  );
}
TestResultBlock.propTypes = { testState: PropTypes.any };

async function _saveAttackerConfig(form, isEditing, selectedTargetId, setTargets, setSelectedTargetId, setIsEditing, setConfigState) {
  setConfigState({ loading: false, saving: true, message: '', error: '' });
  try {
    if (isEditing && selectedTargetId) {
      const saved = await api.adminUpdateAttackerTarget(selectedTargetId, form);
      setTargets(prev => prev.map(t => t.id === selectedTargetId ? saved : t));
    } else {
      const created = await api.adminCreateAttackerTarget(form);
      setTargets(prev => [...prev, created]);
      setSelectedTargetId(created.id);
      setIsEditing(true);
    }
    setConfigState({ loading: false, saving: false, message: 'Saved', error: '' });
  } catch (e) {
    setConfigState({ loading: false, saving: false, message: '', error: e.message || 'Failed to save' });
  }
}

async function _testAttackerConnection(form, isEditing, selectedTargetId, setTestState) {
  setTestState({ running: true, result: null, error: '' });
  try {
    const result = isEditing && selectedTargetId
      ? await api.adminTestAttackerTarget(selectedTargetId)
      : await api.adminTestAttackerSSH(form);
    setTestState({ running: false, result, error: '' });
  } catch (e) {
    setTestState({ running: false, result: null, error: e.message || 'SSH test failed' });
  }
}

async function _deleteAttackerTarget(selectedTargetId, targets, setTargets, setSelectedTargetId, setForm, setIsEditing, setConfigState) {
  if (!selectedTargetId) {
    return;
  }
  try {
    await api.adminDeleteAttackerTarget(selectedTargetId);
    const next = targets.filter(t => t.id !== selectedTargetId);
    setTargets(next);
    setSelectedTargetId(next[0]?.id || '');
    setForm(next[0] ? { ...next[0] } : EMPTY_TARGET);
    setIsEditing(!!next[0]);
  } catch (e) {
    setConfigState(s => ({ ...s, error: e.message || 'Failed to delete' }));
  }
}

async function _loadAttackerSSHData(setTargets, setProjects, setSelectedTargetId, setForm, setIsEditing, setConfigState) {
  try {
    const [cfg, projs] = await Promise.all([api.adminGetAttackerSSHConfig(), api.getProjects()]);
    const loadedTargets = cfg.targets || [];
    setTargets(loadedTargets);
    setProjects(projs || []);
    if (loadedTargets[0]) {
      setSelectedTargetId(loadedTargets[0].id);
      setForm({ ...loadedTargets[0], password: '', private_key: '' });
      setIsEditing(true);
    }
  } catch (e) {
    setConfigState(s => ({ ...s, error: e.message || 'Failed to load config' }));
  } finally {
    setConfigState(s => ({ ...s, loading: false }));
  }
}

function _updateAttackerFormOnSelect(selectedTargetId, targets, setForm, setIsEditing) {
  const selected = targets.find(t => t.id === selectedTargetId);
  if (selected) { setForm({ ...selected, password: '', private_key: '' }); setIsEditing(true); }
}

function TargetSelectorBar({ targets, selectedTargetId, setSelectedTargetId, setForm, setIsEditing, setConfigState, isEditing, enabled, accent, onDelete }) {
  return (
    <div style={{ display: 'flex', gap: 8, marginBottom: 14, alignItems: 'center' }}>
      <select style={{ ...INP_STYLE, maxWidth: 260 }} value={selectedTargetId} onChange={e => setSelectedTargetId(e.target.value)} disabled={!enabled || !targets.length}>
        <option value="">Select target...</option>
        {targets.map(t => {
          const scope = (t.project_ids || []).length === 0 ? 'global' : `${(t.project_ids || []).length} project(s)`;
          return <option key={t.id} value={t.id}>{t.name} ({t.host}) — {scope}</option>;
        })}
      </select>
      <button onClick={() => { setSelectedTargetId(''); setForm(EMPTY_TARGET); setIsEditing(false); setConfigState(s => ({ ...s, message: '', error: '' })); }} disabled={!enabled}
        style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 12px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: enabled ? 1 : 0.7 }}>
        New
      </button>
      {isEditing && selectedTargetId && (
        <button onClick={onDelete} disabled={!enabled}
          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 12px', cursor: 'pointer', color: '#cc2233', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
          Delete
        </button>
      )}
    </div>
  );
}
TargetSelectorBar.propTypes = { targets: PropTypes.any, selectedTargetId: PropTypes.any, setSelectedTargetId: PropTypes.any, setForm: PropTypes.any, setIsEditing: PropTypes.any, setConfigState: PropTypes.any, isEditing: PropTypes.any, enabled: PropTypes.any, accent: PropTypes.any, onDelete: PropTypes.any };

function TargetFieldsGrid({ form, setForm, enabled }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr 90px 1fr 1fr', gap: 10, marginBottom: 10 }}>
      {[['Name', 'name', 'text'], ['Host', 'host', 'text'], ['Port', 'port', 'number'], ['Username', 'username', 'text']].map(([label, key, type]) => (
        <div key={key}>
          <FieldLabel>{label}</FieldLabel>
          <input style={INP_STYLE} type={type} value={form[key]} disabled={!enabled}
            onChange={e => setForm(prev => ({ ...prev, [key]: type === 'number' ? (Number(e.target.value) || 22) : e.target.value }))} />
        </div>
      ))}
      <div>
        <FieldLabel>Host key policy</FieldLabel>
        <select style={INP_STYLE} value={form.known_hosts_policy} onChange={e => setForm(prev => ({ ...prev, known_hosts_policy: e.target.value }))} disabled={!enabled}>
          <option value="accept_new">accept_new</option>
          <option value="strict">strict</option>
        </select>
      </div>
    </div>
  );
}
TargetFieldsGrid.propTypes = { form: PropTypes.any, setForm: PropTypes.any, enabled: PropTypes.any };

function TargetCredentials({ form, setForm, isEditing, enabled }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 14 }}>
      <div>
        <FieldLabel>Password</FieldLabel>
        <input style={INP_STYLE} type="password" value={form.password} onChange={e => setForm(prev => ({ ...prev, password: e.target.value }))} disabled={!enabled}
          placeholder={isEditing && form.has_password ? 'Stored - enter new to replace' : 'Enter password'} />
      </div>
      <div>
        <FieldLabel>Private key (PEM)</FieldLabel>
        <textarea style={{ ...INP_STYLE, resize: 'vertical', minHeight: 80 }} value={form.private_key} onChange={e => setForm(prev => ({ ...prev, private_key: e.target.value }))} disabled={!enabled}
          placeholder={isEditing && form.has_private_key ? 'Stored - paste new PEM to replace' : 'Optional - paste PEM key instead of password'} />
      </div>
    </div>
  );
}
TargetCredentials.propTypes = { form: PropTypes.any, setForm: PropTypes.any, isEditing: PropTypes.any, enabled: PropTypes.any };

function TargetActionButtons({ accent, enabled, configState, testState, onSave, onTest }) {
  return (
    <>
      <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
        <button onClick={onSave} disabled={!enabled || configState.saving}
          style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: !enabled || configState.saving ? 0.7 : 1 }}>
          {configState.saving ? 'Saving...' : 'Save'}
        </button>
        <button onClick={onTest} disabled={!enabled || testState.running}
          style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#808590', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: !enabled || testState.running ? 0.7 : 1 }}>
          {testState.running ? 'Testing...' : 'Test connection'}
        </button>
      </div>
      {configState.message && <div style={{ fontSize: 11, color: '#39d353', marginBottom: 8 }}>{configState.message}</div>}
      {configState.error && <div style={{ fontSize: 11, color: '#cc2233', marginBottom: 8, whiteSpace: 'pre-wrap' }}>{configState.error}</div>}
      {testState.error && <div style={{ fontSize: 11, color: '#cc2233', marginBottom: 8, whiteSpace: 'pre-wrap', fontFamily: 'JetBrains Mono' }}>{testState.error}</div>}
      <TestResultBlock testState={testState} />
    </>
  );
}
TargetActionButtons.propTypes = { accent: PropTypes.any, enabled: PropTypes.any, configState: PropTypes.any, testState: PropTypes.any, onSave: PropTypes.any, onTest: PropTypes.any };

function AttackerSSHBody({ accent, enabled, form, setForm, targets, projects, selectedTargetId, setSelectedTargetId, isEditing, setIsEditing, setConfigState, configState, testState, onSave, onTest, onDelete }) {
  return (
    <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, padding: 18, marginTop: 18, opacity: enabled ? 1 : 0.6 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Attacker SSH</div>
          <div style={{ fontSize: 10, color: '#606570' }}>SSH connection to the attacker machine.</div>
        </div>
        {!enabled && <span style={{ fontSize: 10, color: '#f09a3a', fontFamily: 'JetBrains Mono' }}>Module disabled</span>}
      </div>
      {configState.loading ? <div style={{ color: '#505560', fontSize: 12 }}>Loading...</div> : (
        <>
          <TargetSelectorBar targets={targets} selectedTargetId={selectedTargetId} setSelectedTargetId={setSelectedTargetId}
            setForm={setForm} setIsEditing={setIsEditing} setConfigState={setConfigState} isEditing={isEditing} enabled={enabled} accent={accent} onDelete={onDelete} />
          <TargetFieldsGrid form={form} setForm={setForm} enabled={enabled} />
          <ProxySection form={form} setForm={setForm} isEditing={isEditing} enabled={enabled} />
          <TargetCredentials form={form} setForm={setForm} isEditing={isEditing} enabled={enabled} />
          <StoredSecretsNote isEditing={isEditing} form={form} />
          <RoleFlagsSection form={form} setForm={setForm} enabled={enabled} />
          <ProjectScopeSection form={form} setForm={setForm} projects={projects} enabled={enabled} accent={accent} />
          <TargetActionButtons accent={accent} enabled={enabled} configState={configState} testState={testState} onSave={onSave} onTest={onTest} />
        </>
      )}
    </div>
  );
}
AttackerSSHBody.propTypes = { accent: PropTypes.any, enabled: PropTypes.any, form: PropTypes.any, setForm: PropTypes.any, targets: PropTypes.any, projects: PropTypes.any, selectedTargetId: PropTypes.any, setSelectedTargetId: PropTypes.any, isEditing: PropTypes.any, setIsEditing: PropTypes.any, setConfigState: PropTypes.any, configState: PropTypes.any, testState: PropTypes.any, onSave: PropTypes.any, onTest: PropTypes.any, onDelete: PropTypes.any };

function AttackerSSHPanel({ accent, enabled }) {
  const [targets, setTargets] = useState([]);
  const [projects, setProjects] = useState([]);
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [form, setForm] = useState(EMPTY_TARGET);
  const [isEditing, setIsEditing] = useState(false);
  const [configState, setConfigState] = useState({ loading: true, saving: false, message: '', error: '' });
  const [testState, setTestState] = useState({ running: false, result: null, error: '' });

  useEffect(() => {
    _loadAttackerSSHData(setTargets, setProjects, setSelectedTargetId, setForm, setIsEditing, setConfigState);
  }, []);

  useEffect(() => {
    _updateAttackerFormOnSelect(selectedTargetId, targets, setForm, setIsEditing);
  }, [selectedTargetId, targets]);

  return <AttackerSSHBody
    accent={accent} enabled={enabled} form={form} setForm={setForm}
    targets={targets} projects={projects}
    selectedTargetId={selectedTargetId} setSelectedTargetId={setSelectedTargetId}
    isEditing={isEditing} setIsEditing={setIsEditing}
    configState={configState} setConfigState={setConfigState} testState={testState}
    onSave={() => _saveAttackerConfig(form, isEditing, selectedTargetId, setTargets, setSelectedTargetId, setIsEditing, setConfigState)}
    onTest={() => _testAttackerConnection(form, isEditing, selectedTargetId, setTestState)}
    onDelete={() => _deleteAttackerTarget(selectedTargetId, targets, setTargets, setSelectedTargetId, setForm, setIsEditing, setConfigState)}
  />;
}
AttackerSSHPanel.propTypes = { accent: PropTypes.any, enabled: PropTypes.any };

// ── Module-level helpers ───────────────────────────────────────────────
function _syncModuleRegistry(items) {
  for (const mod of items) {
    if (!moduleRegistry.get(mod.name)) {
      continue;
    }
    if (mod.enabled) {
      moduleRegistry.enable(mod.name);
    }
    else {
      moduleRegistry.disable(mod.name);
    }
  }
}

async function _loadModulesData(setModules, setConnectors, setError, setLoading) {
  setLoading(true);
  try {
    const [data, connectorData] = await Promise.all([
      api.adminListModules(),
      api.listConnectors().catch(() => ({ connectors: [] })),
    ]);
    const items = data.modules || [];
    setModules(items);
    setConnectors(connectorData.connectors || []);
    _syncModuleRegistry(items);
  } catch (e) {
    setError(e.message);
  } finally {
    setLoading(false);
  }
}

async function _toggleModuleEnabled(mod, setModules) {
  const updated = await api.adminUpdateModule(mod.name, { enabled: !mod.enabled });
  setModules(prev => prev.map(item => item.name === mod.name ? updated : item));
  if (moduleRegistry.get(mod.name)) {
    if (updated.enabled) {
      moduleRegistry.enable(mod.name);
    }
    else {
      moduleRegistry.disable(mod.name);
    }
  }
}

function EditModuleModal({ module, accent, onClose, onSave }) {
  const [form, setForm] = useState({ title: module.title || module.name, version: module.version || '1.0.0', description: module.description || '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    setSaving(true);
    setError('');
    try {
      await onSave(form);
      onClose();
    } catch (e) {
      setError(e.message || 'Failed to save module');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 500, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: '#0e1016', border: `1px solid ${accent}44`, borderRadius: 10, padding: '28px 32px', width: 440, boxShadow: '0 20px 60px #00000099' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Edit module</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={14} color="#606570" /></button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[['Title', 'title'], ['Version', 'version']].map(([label, key]) => (
            <div key={key}>
              <FieldLabel>{label}</FieldLabel>
              <input style={INP_STYLE} value={form[key]} onChange={e => setForm(prev => ({ ...prev, [key]: e.target.value }))} />
            </div>
          ))}
          <div>
            <FieldLabel>Description</FieldLabel>
            <textarea style={{ ...INP_STYLE, resize: 'vertical', minHeight: 100, lineHeight: 1.5 }} value={form.description} onChange={e => setForm(prev => ({ ...prev, description: e.target.value }))} />
          </div>
          {error && <div style={{ fontSize: 11, color: '#cc2233' }}>{error}</div>}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button onClick={onClose} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
            <button onClick={submit} disabled={saving} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>{saving ? 'Saving...' : 'Save'}</button>
          </div>
        </div>
      </div>
    </div>
  );
}
EditModuleModal.propTypes = { module: PropTypes.any, accent: PropTypes.any, onClose: PropTypes.any, onSave: PropTypes.any };

export default function SystemModulesView({ accent }) {
  const [modules, setModules] = useState([]);
  const [connectors, setConnectors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState(null);
  const [creating, setCreating] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [validation, setValidation] = useState(null);
  const [uploadError, setUploadError] = useState('');
  const [form, setForm] = useState({ name: '', title: '', version: '1.0.0', description: '' });

  const load = () => _loadModulesData(setModules, setConnectors, setError, setLoading);

  useEffect(() => { load(); }, []);

  const stats = useMemo(() => ({
    total: modules.length,
    enabled: modules.filter(m => m.enabled).length,
    custom: modules.filter(m => m.source === 'custom').length,
  }), [modules]);

  const connectorStats = useMemo(() => ({
    total: connectors.length,
    enabled: connectors.filter(c => c.enabled !== false).length,
    categories: new Set(connectors.map(c => c.category).filter(Boolean)).size,
  }), [connectors]);

  const toggleModule = (mod) => _toggleModuleEnabled(mod, setModules);

  const createModule = async () => {
    setCreating(true);
    setError('');
    try {
      const created = await api.adminCreateModule(form);
      setModules(prev => [...prev, created].sort((a, b) => a.title.localeCompare(b.title)));
      setForm({ name: '', title: '', version: '1.0.0', description: '' });
      setShowCreate(false);
    } catch (e) {
      setError(e.message);
    } finally {
      setCreating(false);
    }
  };

  const saveModule = async (mod, payload) => {
    const updated = await api.adminUpdateModule(mod.name, payload);
    setModules(prev => prev.map(item => item.name === mod.name ? updated : item));
  };

  const removeModule = async (mod) => {
    await api.adminDeleteModule(mod.name);
    setModules(prev => prev.filter(item => item.name !== mod.name));
  };

  const downloadTemplate = async () => {
    const blob = await api.adminDownloadModuleTemplate();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'module_template.py';
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadFrontendTemplate = async () => {
    const blob = await api.adminDownloadFrontendModuleTemplate();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'frontend_module_template.js';
    a.click();
    URL.revokeObjectURL(url);
  };

  const validateModule = async (file) => {
    const content = await file.text();
    return api.adminValidateModule({ filename: file.name, content });
  };

  const uploadModule = async (file) => {
    if (!file) {
      return;
    }
    setUploading(true);
    setError('');
    setUploadError('');
    setValidation(null);
    try {
      const validationResult = await validateModule(file);
      setValidation(validationResult);
      const created = await api.adminUploadModule(file);
      setModules(prev => [...prev, created].sort((a, b) => a.title.localeCompare(b.title)));
    } catch (e) {
      setUploadError(e.message || 'Failed to upload module');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {editing && <EditModuleModal module={editing} accent={accent} onClose={() => setEditing(null)} onSave={(payload) => saveModule(editing, payload)} />}

      <div>
        <div style={{ fontSize: 9, color: '#404550', letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>System control</div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Modules</h1>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <button onClick={downloadTemplate} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 14px', cursor: 'pointer', color: '#808590', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="export" size={11} color="currentColor" /> Get template
            </button>
            <button onClick={downloadFrontendTemplate} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 14px', cursor: 'pointer', color: '#808590', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="export" size={11} color="currentColor" /> Frontend template
            </button>
            <label style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 6, padding: '8px 14px', cursor: uploading ? 'wait' : 'pointer', color: '#808590', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, opacity: uploading ? 0.7 : 1 }}>
              <Icon name="plus" size={11} color="currentColor" /> {uploading ? 'Uploading...' : 'Upload module'}
              <input type="file" accept=".py,text/x-python" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && uploadModule(e.target.files[0])} disabled={uploading} />
            </label>
            <button onClick={() => setShowCreate(v => !v)} style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="plus" size={11} color="#fff" /> Add module
            </button>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {[[stats.total, 'Total', '#808590'], [stats.enabled, 'Enabled', '#39d353'], [stats.custom, 'Custom', accent]].map(([value, label, color]) => (
          <div key={label} style={{ minWidth: 110, background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: '10px 12px' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color, fontFamily: 'Space Grotesk' }}>{value}</div>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {[[connectorStats.total, 'Connectors', '#6fc8f0'], [connectorStats.enabled, 'Active connectors', '#39d353'], [connectorStats.categories, 'Categories', '#c07af0']].map(([value, label, color]) => (
          <div key={label} style={{ minWidth: 140, background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8, padding: '10px 12px' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color, fontFamily: 'Space Grotesk' }}>{value}</div>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
          </div>
        ))}
      </div>

      {showCreate && (
        <div style={{ background: '#0d0f14', border: `1px solid ${accent}44`, borderRadius: 10, padding: 18, display: 'grid', gridTemplateColumns: '1fr 1fr 120px', gap: 10 }}>
          <div>
            <FieldLabel>Module name</FieldLabel>
            <input style={INP_STYLE} value={form.name} onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))} placeholder="my_module" />
          </div>
          <div>
            <FieldLabel>Title</FieldLabel>
            <input style={INP_STYLE} value={form.title} onChange={e => setForm(prev => ({ ...prev, title: e.target.value }))} placeholder="My Module" />
          </div>
          <div>
            <FieldLabel>Version</FieldLabel>
            <input style={INP_STYLE} value={form.version} onChange={e => setForm(prev => ({ ...prev, version: e.target.value }))} />
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <FieldLabel>Description</FieldLabel>
            <textarea style={{ ...INP_STYLE, resize: 'vertical', minHeight: 70 }} value={form.description} onChange={e => setForm(prev => ({ ...prev, description: e.target.value }))} />
          </div>
          <div style={{ gridColumn: '1 / -1', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button onClick={() => setShowCreate(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
            <button onClick={createModule} disabled={creating || !form.name.trim() || !form.title.trim()} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: creating || !form.name.trim() || !form.title.trim() ? 0.7 : 1 }}>{creating ? 'Creating...' : 'Create module'}</button>
          </div>
        </div>
      )}

      {error && <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: '#cc2233' }}>{error}</div>}
      {validation && (
        <div style={{ background: '#39d35318', border: '1px solid #39d35333', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: '#39d353' }}>
          Validation passed for `{validation.module_name}`{validation.warnings?.length ? ` with ${validation.warnings.length} warning(s)` : ''}.
        </div>
      )}
      {validation?.warnings?.length > 0 && (
        <div style={{ background: '#f09a3a18', border: '1px solid #f09a3a33', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: '#f09a3a' }}>
          {validation?.warnings?.join(' | ')}
        </div>
      )}
      {uploadError && (
        <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: '#cc2233', whiteSpace: 'pre-wrap', fontFamily: 'JetBrains Mono' }}>{uploadError}</div>
      )}

      <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 1fr) 90px 90px 120px 180px', gap: 0, padding: '10px 18px', borderBottom: '1px solid #1e2029', background: '#090b0f' }}>
          {['Module', 'Version', 'Status', 'Source', 'Actions'].map(h => <div key={h} style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{h}</div>)}
        </div>
        {loading && <div style={{ padding: 24, textAlign: 'center', color: '#404550', fontSize: 12 }}>Loading...</div>}
        {!loading && modules.map((mod, i) => (
          <div key={mod.name} style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 1fr) 90px 90px 120px 180px', gap: 0, padding: '13px 18px', borderBottom: i < modules.length - 1 ? '1px solid #14161b' : 'none', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: 13, color: '#e0e4ec', fontWeight: 600 }}>{mod.title}</div>
              <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono' }}>{mod.name}</div>
              {mod.description && <div style={{ fontSize: 10, color: '#606570', marginTop: 4, lineHeight: 1.4 }}>{mod.description}</div>}
            </div>
            <div style={{ fontSize: 10, color: '#808590', fontFamily: 'JetBrains Mono' }}>{mod.version}</div>
            <div>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: mod.enabled ? '#39d353' : '#404550', background: mod.enabled ? '#39d35318' : '#40455018', border: `1px solid ${mod.enabled ? '#39d35344' : '#40455044'}`, borderRadius: 4, padding: '2px 8px' }}>{mod.enabled ? 'Enabled' : 'Disabled'}</span>
            </div>
            <div>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: mod.source === 'custom' ? accent : '#5b8af5', background: mod.source === 'custom' ? `${accent}18` : '#5b8af518', border: `1px solid ${mod.source === 'custom' ? accent + '44' : '#5b8af544'}`, borderRadius: 4, padding: '2px 8px', textTransform: 'uppercase' }}>{mod.source}</span>
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
              <button onClick={() => toggleModule(mod)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: mod.enabled ? '#f09a3a' : '#39d353', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{mod.enabled ? 'Disable' : 'Enable'}</button>
              {mod.editable && <button onClick={() => setEditing(mod)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#5b8af5', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Edit</button>}
              {mod.source === 'custom' && <button onClick={() => removeModule(mod)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#cc2233', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Delete</button>}
            </div>
          </div>
        ))}
      </div>

      <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ padding: '12px 18px', borderBottom: '1px solid #1e2029', background: '#090b0f', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 600, fontFamily: 'Space Grotesk' }}>Connector Inventory</div>
            <div style={{ fontSize: 10, color: '#505560' }}>Normalized orchestration contract aggregated from enabled backend modules</div>
          </div>
        </div>
        {connectors.length ? connectors.map((connector, i) => (
          <div key={`${connector.module}:${connector.key}`} style={{ padding: '12px 18px', borderBottom: i < connectors.length - 1 ? '1px solid #14161b' : 'none' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
              <span style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 600 }}>{connector.title}</span>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: '#6fc8f0', background: '#6fc8f018', border: '1px solid #6fc8f033', borderRadius: 4, padding: '1px 7px' }}>{connector.key}</span>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 4, padding: '1px 7px', textTransform: 'uppercase' }}>{connector.category}</span>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: '#808590' }}>module: {connector.module}</span>
            </div>
            {connector.description && <div style={{ fontSize: 10, color: '#606570', marginBottom: 6, lineHeight: 1.5 }}>{connector.description}</div>}
            <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', fontSize: 10, color: '#707580', fontFamily: 'JetBrains Mono' }}>
              <span>ops: {(connector.supported_operations || []).join(', ') || '—'}</span>
              <span>sources: {(connector.supported_sources || []).join(', ') || '—'}</span>
              <span>creates: {(connector.creates_entities || []).join(', ') || '—'}</span>
              <span>mode: {connector.execution_mode || 'sync'}</span>
            </div>
          </div>
        )) : (
          <div style={{ padding: 18, color: '#505560', fontSize: 11 }}>No connectors discovered.</div>
        )}
      </div>

      {(() => {
        const attackerModule = modules.find(mod => mod.name === 'attacker_ssh');
        return attackerModule ? <AttackerSSHPanel accent={accent} enabled={!!attackerModule.enabled} /> : null;
      })()}
    </div>
  );
}
SystemModulesView.propTypes = { accent: PropTypes.any };
