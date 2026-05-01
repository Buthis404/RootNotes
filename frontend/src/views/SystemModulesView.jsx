import { useEffect, useMemo, useState } from 'react';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { moduleRegistry } from '../features/plugins/registry.js';

function AttackerSSHPanel({ accent, enabled }) {
  const emptyTarget = { name: '', host: '', port: 22, username: '', password: '', private_key: '', known_hosts_policy: 'accept_new', project_ids: [], enabled: true };
  const [targets, setTargets] = useState([]);
  const [projects, setProjects] = useState([]);
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [form, setForm] = useState(emptyTarget);
  const [isEditing, setIsEditing] = useState(false);
  const [configState, setConfigState] = useState({ loading: true, saving: false, message: '', error: '' });
  const [testState, setTestState] = useState({ running: false, result: null, error: '' });
  const [snippets, setSnippets] = useState([]);
  const [selectedSnippetId, setSelectedSnippetId] = useState('');
  const [command, setCommand] = useState('');
  const [execState, setExecState] = useState({ running: false, result: null, error: '' });
  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.adminGetAttackerSSHConfig(), api.listSnippets(), api.getProjects()])
      .then(([cfg, list, prj]) => {
        if (cancelled) return;
        const loadedTargets = cfg.targets || [];
        setTargets(loadedTargets);
        setProjects(prj || []);
        setSnippets(list || []);
        if (loadedTargets[0]) {
          setSelectedTargetId(loadedTargets[0].id);
          setForm({ ...loadedTargets[0] });
          setIsEditing(true);
        }
      })
      .catch((e) => {
        if (!cancelled) setConfigState(s => ({ ...s, error: e.message || 'Failed to load attacker SSH config' }));
      })
      .finally(() => {
        if (!cancelled) setConfigState(s => ({ ...s, loading: false }));
      });
    return () => { cancelled = true; };
  }, []);

  const selectedSnippet = snippets.find(s => s.id === selectedSnippetId);

  useEffect(() => {
    if (selectedSnippet) setCommand(selectedSnippet.command || '');
  }, [selectedSnippetId]);

  useEffect(() => {
    const selected = targets.find(t => t.id === selectedTargetId);
    if (selected) {
      setForm({ ...selected });
      setIsEditing(true);
    }
  }, [selectedTargetId, targets]);

  const saveConfig = async () => {
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
      setConfigState({ loading: false, saving: false, message: 'Config saved', error: '' });
    } catch (e) {
      setConfigState({ loading: false, saving: false, message: '', error: e.message || 'Failed to save config' });
    }
  };

  const testConnection = async () => {
    setTestState({ running: true, result: null, error: '' });
    try {
      const result = isEditing && selectedTargetId ? await api.adminTestAttackerTarget(selectedTargetId) : await api.adminTestAttackerSSH(form);
      setTestState({ running: false, result, error: '' });
    } catch (e) {
      setTestState({ running: false, result: null, error: e.message || 'SSH test failed' });
    }
  };

  const executeCommand = async () => {
    setExecState({ running: true, result: null, error: '' });
    try {
      const result = await api.adminExecuteAttackerSSH({ command, timeout_seconds: 45 });
      setExecState({ running: false, result, error: '' });
    } catch (e) {
      setExecState({ running: false, result: null, error: e.message || 'Execution failed' });
    }
  };

  const deleteTarget = async () => {
    if (!selectedTargetId) return;
    try {
      await api.adminDeleteAttackerTarget(selectedTargetId);
      const next = targets.filter(t => t.id !== selectedTargetId);
      setTargets(next);
      setSelectedTargetId(next[0]?.id || '');
      setForm(next[0] ? { ...next[0] } : emptyTarget);
      setIsEditing(!!next[0]);
    } catch (e) {
      setConfigState(s => ({ ...s, error: e.message || 'Failed to delete target' }));
    }
  };

  const startNewTarget = () => {
    setSelectedTargetId('');
    setForm(emptyTarget);
    setIsEditing(false);
    setConfigState(s => ({ ...s, message: '', error: '' }));
  };

  const toggleProject = (pid) => {
    setForm(prev => ({
      ...prev,
      project_ids: prev.project_ids.includes(pid) ? prev.project_ids.filter(id => id !== pid) : [...prev.project_ids, pid],
    }));
  };

  return (
    <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, padding: 18, marginTop: 18, opacity: enabled ? 1 : 0.6 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Attacker SSH</div>
          <div style={{ fontSize: 10, color: '#606570' }}>Global SSH target for executing snippets from the attacker machine.</div>
        </div>
        {!enabled && <span style={{ fontSize: 10, color: '#f09a3a', fontFamily: 'JetBrains Mono' }}>Module disabled</span>}
      </div>

      {configState.loading ? <div style={{ color: '#505560', fontSize: 12 }}>Loading...</div> : (
        <>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12, alignItems: 'center' }}>
            <select style={{ ...inp, maxWidth: 260 }} value={selectedTargetId} onChange={e => setSelectedTargetId(e.target.value)} disabled={!enabled || !targets.length}>
              <option value="">Select attacker target...</option>
              {targets.map(t => <option key={t.id} value={t.id}>{t.name} ({t.host})</option>)}
            </select>
            <button onClick={startNewTarget} disabled={!enabled} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 12px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: !enabled ? 0.7 : 1 }}>New target</button>
            {isEditing && selectedTargetId && <button onClick={deleteTarget} disabled={!enabled} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 12px', cursor: 'pointer', color: '#cc2233', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: !enabled ? 0.7 : 1 }}>Delete</button>}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr 100px 1fr 1fr', gap: 10, marginBottom: 10 }}>
            <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Name</div><input style={inp} value={form.name} onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))} disabled={!enabled} /></div>
            <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Host</div><input style={inp} value={form.host} onChange={e => setForm(prev => ({ ...prev, host: e.target.value }))} disabled={!enabled} /></div>
            <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Port</div><input style={inp} type="number" value={form.port} onChange={e => setForm(prev => ({ ...prev, port: Number(e.target.value) || 22 }))} disabled={!enabled} /></div>
            <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Username</div><input style={inp} value={form.username} onChange={e => setForm(prev => ({ ...prev, username: e.target.value }))} disabled={!enabled} /></div>
            <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Host key policy</div><select style={inp} value={form.known_hosts_policy} onChange={e => setForm(prev => ({ ...prev, known_hosts_policy: e.target.value }))} disabled={!enabled}><option value="accept_new">accept_new</option><option value="strict">strict</option></select></div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Password</div><input style={inp} type="password" value={form.password} onChange={e => setForm(prev => ({ ...prev, password: e.target.value }))} disabled={!enabled} /></div>
            <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Private key</div><textarea style={{ ...inp, resize: 'vertical', minHeight: 84 }} value={form.private_key} onChange={e => setForm(prev => ({ ...prev, private_key: e.target.value }))} disabled={!enabled} placeholder="Optional PEM key instead of password" /></div>
          </div>

          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Assigned projects</div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {projects.map(project => {
                const active = form.project_ids.includes(project.id);
                return (
                  <button key={project.id} onClick={() => toggleProject(project.id)} disabled={!enabled}
                    style={{ background: active ? `${accent}22` : '#0a0c10', border: `1px solid ${active ? accent + '66' : '#2a2d35'}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: active ? accent : '#808590', fontSize: 10, fontFamily: 'JetBrains Mono', opacity: !enabled ? 0.7 : 1 }}>
                    {project.name}
                  </button>
                );
              })}
            </div>
            <div style={{ fontSize: 10, color: '#505560', marginTop: 6 }}>If no project is selected, the target is available globally.</div>
          </div>

          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <button onClick={saveConfig} disabled={!enabled || configState.saving} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: !enabled || configState.saving ? 0.7 : 1 }}>{configState.saving ? 'Saving...' : 'Save config'}</button>
            <button onClick={testConnection} disabled={!enabled || testState.running} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#808590', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: !enabled || testState.running ? 0.7 : 1 }}>{testState.running ? 'Testing...' : 'Test SSH'}</button>
          </div>

          {configState.message && <div style={{ marginBottom: 10, fontSize: 11, color: '#39d353' }}>{configState.message}</div>}
          {configState.error && <div style={{ marginBottom: 10, fontSize: 11, color: '#cc2233', whiteSpace: 'pre-wrap' }}>{configState.error}</div>}
          {testState.error && <div style={{ marginBottom: 10, fontSize: 11, color: '#cc2233', whiteSpace: 'pre-wrap', fontFamily: 'JetBrains Mono' }}>{testState.error}</div>}
          {testState.result && <pre style={{ background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '10px 12px', color: testState.result.ok ? '#39d353' : '#f09a3a', fontSize: 11, fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', margin: '0 0 12px 0' }}>{[testState.result.stdout, testState.result.stderr].filter(Boolean).join('\n')}</pre>}

          <div style={{ borderTop: '1px solid #1e2029', paddingTop: 12 }}>
            <div style={{ fontSize: 12, color: '#e0e4ec', fontWeight: 700, fontFamily: 'Space Grotesk', marginBottom: 10 }}>Run snippets</div>
            <div style={{ fontSize: 10, color: '#505560', marginBottom: 8 }}>Runs against the first enabled global attacker target. Project-aware execution is available from Cheatsheet.</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, marginBottom: 10 }}>
              <select style={inp} value={selectedSnippetId} onChange={e => setSelectedSnippetId(e.target.value)} disabled={!enabled}>
                <option value="">Pick a snippet...</option>
                {snippets.map(s => <option key={s.id} value={s.id}>{s.category} / {s.title}</option>)}
              </select>
              <button onClick={executeCommand} disabled={!enabled || execState.running || !command.trim()} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono', opacity: !enabled || execState.running || !command.trim() ? 0.7 : 1 }}>{execState.running ? 'Running...' : 'Execute'}</button>
            </div>
            <textarea style={{ ...inp, resize: 'vertical', minHeight: 140, marginBottom: 10 }} value={command} onChange={e => setCommand(e.target.value)} disabled={!enabled} placeholder="Snippet command to execute remotely via SSH" />
            {execState.error && <div style={{ marginBottom: 10, fontSize: 11, color: '#cc2233', whiteSpace: 'pre-wrap', fontFamily: 'JetBrains Mono' }}>{execState.error}</div>}
            {execState.result && <pre style={{ background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 6, padding: '10px 12px', color: execState.result.ok ? '#c8cdd6' : '#f09a3a', fontSize: 11, fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', margin: 0 }}>{`exit_code=${execState.result.exit_code}\n\nSTDOUT:\n${execState.result.stdout || ''}\n\nSTDERR:\n${execState.result.stderr || ''}`}</pre>}
          </div>
        </>
      )}
    </div>
  );
}

function EditModuleModal({ module, accent, onClose, onSave }) {
  const [form, setForm] = useState({ title: module.title || module.name, version: module.version || '1.0.0', description: module.description || '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

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
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
              <input style={inp} value={form[key]} onChange={e => setForm(prev => ({ ...prev, [key]: e.target.value }))} />
            </div>
          ))}
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Description</div>
            <textarea style={{ ...inp, resize: 'vertical', minHeight: 100, lineHeight: 1.5 }} value={form.description} onChange={e => setForm(prev => ({ ...prev, description: e.target.value }))} />
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

export default function SystemModulesView({ accent }) {
  const [modules, setModules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState(null);
  const [creating, setCreating] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [validation, setValidation] = useState(null);
  const [uploadError, setUploadError] = useState('');
  const [form, setForm] = useState({ name: '', title: '', version: '1.0.0', description: '' });

  const load = async () => {
    setLoading(true);
    try {
      const data = await api.adminListModules();
      const items = data.modules || [];
      setModules(items);
      for (const mod of items) {
        if (moduleRegistry.get(mod.name)) {
          if (mod.enabled) moduleRegistry.enable(mod.name);
          else moduleRegistry.disable(mod.name);
        }
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const stats = useMemo(() => ({
    total: modules.length,
    enabled: modules.filter(m => m.enabled).length,
    custom: modules.filter(m => m.source === 'custom').length,
  }), [modules]);

  const toggleModule = async (mod) => {
    const updated = await api.adminUpdateModule(mod.name, { enabled: !mod.enabled });
    setModules(prev => prev.map(item => item.name === mod.name ? updated : item));
    if (moduleRegistry.get(mod.name)) {
      if (updated.enabled) moduleRegistry.enable(mod.name);
      else moduleRegistry.disable(mod.name);
    }
  };

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
    if (!file) return;
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

  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

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

      {showCreate && (
        <div style={{ background: '#0d0f14', border: `1px solid ${accent}44`, borderRadius: 10, padding: 18, display: 'grid', gridTemplateColumns: '1fr 1fr 120px', gap: 10 }}>
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Module name</div>
            <input style={inp} value={form.name} onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))} placeholder="my_module" />
          </div>
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Title</div>
            <input style={inp} value={form.title} onChange={e => setForm(prev => ({ ...prev, title: e.target.value }))} placeholder="My Module" />
          </div>
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Version</div>
            <input style={inp} value={form.version} onChange={e => setForm(prev => ({ ...prev, version: e.target.value }))} />
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Description</div>
            <textarea style={{ ...inp, resize: 'vertical', minHeight: 70 }} value={form.description} onChange={e => setForm(prev => ({ ...prev, description: e.target.value }))} />
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
          {validation.warnings.join(' | ')}
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

      {(() => {
        const attackerModule = modules.find(mod => mod.name === 'attacker_ssh');
        return attackerModule ? <AttackerSSHPanel accent={accent} enabled={!!attackerModule.enabled} /> : null;
      })()}
    </div>
  );
}
