import { useEffect, useState, useMemo } from 'react';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';

function extractVars(cmd) {
  const matches = cmd.match(/\{\{([A-Z_]+)\}\}/g) || [];
  return [...new Set(matches.map(m => m.slice(2, -2)))];
}

function fillVars(cmd, vals) {
  return cmd.replace(/\{\{([A-Z_]+)\}\}/g, (_, k) => vals[k] || `{{${k}}}`);
}

const HOST_VAR_HINTS = ['IP', 'HOST', 'TARGET', 'RHOST', 'LHOST', 'DOMAIN', 'DC'];
const CRED_VAR_HINTS = ['USER', 'PASS', 'HASH', 'SECRET', 'CRED', 'PASSWORD', 'NT', 'LM', 'NTLM'];

function varHint(varName) {
  const up = varName.toUpperCase();
  if (HOST_VAR_HINTS.some(h => up.includes(h))) return 'host';
  if (CRED_VAR_HINTS.some(h => up.includes(h))) return 'cred';
  return null;
}

function applyHostToVars(host, vars, setVals) {
  const updates = {};
  for (const v of vars) {
    const up = v.toUpperCase();
    if (up === 'DOMAIN' || up === 'DC' || up === 'FQDN_DOMAIN') {
      updates[v] = host.domain || host.hostname || host.ip;
    } else if (up.includes('IP') || up === 'RHOST' || up === 'LHOST' || up.includes('TARGET')) {
      updates[v] = host.ip;
    } else if (up.includes('HOST') || up.includes('FQDN')) {
      updates[v] = host.hostname || host.ip;
    } else if (up.includes('DOMAIN') || up.includes('_DC')) {
      updates[v] = host.domain || host.hostname || host.ip;
    }
  }
  if (Object.keys(updates).length) setVals(prev => ({ ...prev, ...updates }));
}

function applyCredToVars(cred, vars, setVals) {
  const updates = {};
  for (const v of vars) {
    const up = v.toUpperCase();
    if (up.includes('USER')) updates[v] = cred.username;
    else if (up.includes('PASS') || up.includes('SECRET') || up.includes('CRED')) updates[v] = cred.secret;
    else if (up.includes('HASH') || up.includes('NT') || up.includes('LM')) updates[v] = cred.secret;
  }
  if (Object.keys(updates).length) setVals(prev => ({ ...prev, ...updates }));
}

function isWindowsHost(host) {
  return host?.os === 'Windows' || String(host?.os || '').toLowerCase().includes('windows');
}

function scoreHostForSnippet(host, snippet, vars) {
  let score = 0;
  const tags = (host.tags || []).map(t => String(t).toLowerCase());
  const domain = String(host.domain || '').trim();
  const hostText = `${host.ip || ''} ${host.hostname || ''} ${domain} ${(host.services || []).join(' ')} ${(host.tags || []).join(' ')}`.toLowerCase();
  const snippetText = `${snippet.title || ''} ${snippet.category || ''} ${(snippet.tags || []).join(' ')} ${snippet.command || ''}`.toLowerCase();

  if (vars.some(v => ['DOMAIN', 'DC', 'DC_IP', 'CA', 'CA_IP'].includes(v.toUpperCase()))) score += domain ? 15 : 0;
  if (snippetText.includes('ad') || snippetText.includes('kerberos') || snippetText.includes('certipy') || snippetText.includes('ldap')) score += domain ? 12 : 0;
  if (snippetText.includes('rdp')) score += tags.includes('workstation') || (host.ports || []).includes('3389') ? 8 : 0;
  if (snippetText.includes('ssh')) score += (host.ports || []).includes('22') ? 8 : 0;
  if (snippetText.includes('smb') || snippetText.includes('ntlm')) score += (host.ports || []).includes('445') ? 8 : 0;
  if (snippetText.includes('http') || snippetText.includes('web')) score += (host.ports || []).some(p => ['80', '443', '8080', '8443'].includes(String(p))) ? 8 : 0;
  if (tags.includes('domain-controller') || tags.includes('dc')) score += 10;
  if (isWindowsHost(host)) score += 2;
  if (hostText.includes('dc')) score += 2;
  return score;
}

function scoreCredForSnippet(cred, snippet, selectedHost, vars) {
  let score = 0;
  const snippetText = `${snippet.title || ''} ${snippet.category || ''} ${(snippet.tags || []).join(' ')} ${snippet.command || ''}`.toLowerCase();
  if (cred.secret) score += 8;
  if (cred.cracked) score += 4;
  if (cred.is_domain) score += 5;
  if (selectedHost && ((cred.host_ids || []).includes(selectedHost.id) || cred.host === selectedHost.ip || cred.host === selectedHost.hostname)) score += 10;
  if (selectedHost?.domain && cred.is_domain) score += 6;
  if (snippetText.includes('kerberos') || snippetText.includes('ldap') || snippetText.includes('certipy') || snippetText.includes('ad')) score += cred.is_domain ? 6 : 0;
  if (vars.some(v => ['HASH', 'NT', 'LM', 'NTLM'].some(k => v.toUpperCase().includes(k)))) score += ['hash', 'ntlm'].includes(cred.type) ? 8 : 0;
  if (vars.some(v => ['PASS', 'PASSWORD', 'SECRET'].some(k => v.toUpperCase().includes(k)))) score += !['hash', 'ntlm'].includes(cred.type) ? 5 : 0;
  return score;
}

function VarModal({ snippet, accent, onClose, hosts = [], creds = [], selectedProject }) {
  const vars = useMemo(() => extractVars(snippet.command), [snippet.command]);
  const [vals, setVals] = useState({});
  const [copied, setCopied] = useState(false);
  const [selectedHostId, setSelectedHostId] = useState('');
  const [selectedCredId, setSelectedCredId] = useState('');
  const [moduleEnabled, setModuleEnabled] = useState(false);
  const [availableTargets, setAvailableTargets] = useState({ project_hosts: [], global_targets: [] });
  const [execMode, setExecMode] = useState('auto');
  const [attackerHostId, setAttackerHostId] = useState('');
  const [attackerCredId, setAttackerCredId] = useState('');
  const [globalTargetId, setGlobalTargetId] = useState('');
  const [execState, setExecState] = useState({ running: false, error: '', result: null });
  const result = fillVars(snippet.command, vals);

  const hasHostVars = vars.some(v => varHint(v) === 'host');
  const hasCredVars = vars.some(v => varHint(v) === 'cred');

  const copy = () => {
    navigator.clipboard.writeText(result).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  const sel = { background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 4, padding: '5px 8px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none', width: '100%', cursor: 'pointer' };

  const attackerHosts = useMemo(
    () => hosts.filter(h => h.is_attacker || String(h.role || '').toLowerCase() === 'attacker'),
    [hosts],
  );

  const projectAttackerOptions = useMemo(
    () => availableTargets.project_hosts || [],
    [availableTargets],
  );

  const globalAttackerOptions = useMemo(
    () => availableTargets.global_targets || [],
    [availableTargets],
  );

  const attackerCreds = useMemo(() => {
    const selectedAttacker = attackerHosts.find(h => h.id === attackerHostId) || attackerHosts[0];
    if (!selectedAttacker) return [];
    return creds.filter(c => {
      const matchesHost = (c.host_ids || []).includes(selectedAttacker.id) || c.host === selectedAttacker.ip || c.host === selectedAttacker.hostname;
      const supportedType = ['plain', 'key'].includes(c.type);
      const looksSsh = !c.service || String(c.service).toLowerCase() === 'ssh' || c.type === 'key';
      return matchesHost && supportedType && looksSsh && !!c.secret;
    });
  }, [creds, attackerHosts, attackerHostId]);

  useEffect(() => {
    const bestHost = hosts.length ? [...hosts].sort((a, b) => scoreHostForSnippet(b, snippet, vars) - scoreHostForSnippet(a, snippet, vars))[0] : null;
    if (bestHost && scoreHostForSnippet(bestHost, snippet, vars) > 0) {
      setSelectedHostId(bestHost.id);
      applyHostToVars(bestHost, vars, setVals);
    }

    const bestCred = creds.length ? [...creds].sort((a, b) => scoreCredForSnippet(b, snippet, bestHost, vars) - scoreCredForSnippet(a, snippet, bestHost, vars))[0] : null;
    if (bestCred && scoreCredForSnippet(bestCred, snippet, bestHost, vars) > 0) {
      setSelectedCredId(bestCred.id);
      applyCredToVars(bestCred, vars, setVals);
    }
  }, [snippet, hosts, creds, vars]);

  useEffect(() => {
    api.listModules().then(({ modules }) => {
      const mod = (modules || []).find(m => m.name === 'attacker_ssh');
      setModuleEnabled(!!mod?.enabled);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedProject) return;
    api.listAttackerExecutionTargets(selectedProject).then(setAvailableTargets).catch(() => {});
  }, [selectedProject]);

  useEffect(() => {
    if (!attackerHostId && projectAttackerOptions[0]) setAttackerHostId(projectAttackerOptions[0].id);
  }, [projectAttackerOptions, attackerHostId]);

  useEffect(() => {
    if (!globalTargetId && globalAttackerOptions[0]) setGlobalTargetId(globalAttackerOptions[0].id);
  }, [globalAttackerOptions, globalTargetId]);

  useEffect(() => {
    if (!attackerCredId && attackerCreds[0]) setAttackerCredId(attackerCreds[0].id);
    if (attackerCredId && !attackerCreds.some(c => c.id === attackerCredId)) setAttackerCredId('');
  }, [attackerCreds, attackerCredId]);

  const execute = async () => {
    setExecState({ running: true, error: '', result: null });
    try {
      const data = await api.executeAttackerCommand(selectedProject, {
        command: result,
        snippet_title: snippet.title,
        host_id: attackerHostId || null,
        cred_id: attackerCredId || null,
        target_id: globalTargetId || null,
        execution_mode: execMode,
        timeout_seconds: 45,
        activity_type: 'postex',
      });
      setExecState({ running: false, error: '', result: data });
    } catch (e) {
      setExecState({ running: false, error: e.message || 'Execution failed', result: null });
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, padding: '28px 32px', width: 560, boxShadow: '0 24px 64px #00000099', maxHeight: '80vh', overflow: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>{snippet.title}</div>
            <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono', marginTop: 2 }}>{snippet.category}</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
            <Icon name="close" size={14} color="#606570" />
          </button>
        </div>

        {snippet.opsec && (
          <div style={{ padding: '8px 12px', background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 6, marginBottom: 16, display: 'flex', alignItems: 'flex-start', gap: 8 }}>
            <Icon name="opsec" size={13} color="#f09a3a" />
            <div>
              <div style={{ fontSize: 9, color: '#f09a3a', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 2 }}>OPSEC</div>
              <div style={{ fontSize: 11, color: '#c07a30', lineHeight: 1.5 }}>{snippet.opsec}</div>
            </div>
          </div>
        )}

        {(hasHostVars && hosts.length > 0) || (hasCredVars && creds.length > 0) ? (
          <div style={{ marginBottom: 16, padding: '10px 12px', background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 8 }}>Quick fill from project</div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {hasHostVars && hosts.length > 0 && (
                <div style={{ flex: 1, minWidth: 180 }}>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Target host</div>
                  <select style={sel} value={selectedHostId} onChange={e => {
                    setSelectedHostId(e.target.value);
                    const h = hosts.find(h => h.id === e.target.value);
                    if (h) applyHostToVars(h, vars, setVals);
                  }}>
                    <option value="">— pick a host —</option>
                    {hosts.map(h => <option key={h.id} value={h.id}>{h.ip}{h.hostname ? ` (${h.hostname})` : ''}</option>)}
                  </select>
                </div>
              )}
              {hasCredVars && creds.length > 0 && (
                <div style={{ flex: 1, minWidth: 180 }}>
                  <div style={{ fontSize: 9, color: '#404550', marginBottom: 4 }}>Credentials</div>
                  <select style={sel} value={selectedCredId} onChange={e => {
                    setSelectedCredId(e.target.value);
                    const c = creds.find(c => c.id === e.target.value);
                    if (c) applyCredToVars(c, vars, setVals);
                  }}>
                    <option value="">— pick a cred —</option>
                    {creds.map(c => <option key={c.id} value={c.id}>{c.username}{c.host ? `@${c.host}` : ''}{c.is_domain ? ' [AD]' : ''}</option>)}
                  </select>
                </div>
              )}
            </div>
          </div>
        ) : null}

        {vars.length > 0 && (
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 10 }}>Variables</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {vars.map(v => (
                <div key={v} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: accent, minWidth: 110, fontWeight: 600 }}>{'{{' + v + '}}'}</span>
                  <input value={vals[v] || ''} onChange={e => setVals(prev => ({ ...prev, [v]: e.target.value }))}
                    placeholder={v}
                    style={{ flex: 1, background: '#0d0f14', border: `1px solid ${vals[v] ? accent + '44' : '#2a2d35'}`, borderRadius: 4, padding: '5px 10px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none' }} />
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 8 }}>Command</div>
          <pre style={{ background: '#07080b', border: '1px solid #1e2029', borderRadius: 6, padding: '14px 16px', fontFamily: 'JetBrains Mono', fontSize: 12, color: '#c8cdd6', lineHeight: 1.7, whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
            {result.split(/(\{\{[A-Z_]+\}\})/g).map((part, i) =>
              part.match(/^\{\{[A-Z_]+\}\}$/)
                ? <span key={i} style={{ color: accent, background: accent + '22', borderRadius: 2, padding: '0 2px' }}>{part}</span>
                : <span key={i}>{part}</span>
            )}
          </pre>
        </div>

        {moduleEnabled && selectedProject && (
          <div style={{ marginBottom: 16, padding: '12px 14px', background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 8 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 10 }}>Exec via attacker</div>
            <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr 1fr', gap: 8, marginBottom: 8 }}>
              <select style={sel} value={execMode} onChange={e => setExecMode(e.target.value)}>
                <option value="auto">auto</option>
                <option value="project">project</option>
                <option value="global">global</option>
              </select>
              <select style={sel} value={attackerHostId} onChange={e => setAttackerHostId(e.target.value)} disabled={execMode === 'global'}>
                <option value="">Attacker host...</option>
                {projectAttackerOptions.map(h => <option key={h.id} value={h.id}>{h.name || h.host || h.id}</option>)}
              </select>
              {execMode === 'global'
                ? <select style={sel} value={globalTargetId} onChange={e => setGlobalTargetId(e.target.value)}>
                    <option value="">Global target...</option>
                    {globalAttackerOptions.map(t => <option key={t.id} value={t.id}>{t.name} ({t.host})</option>)}
                  </select>
                : <select style={sel} value={attackerCredId} onChange={e => setAttackerCredId(e.target.value)} disabled={execMode !== 'project'}>
                    <option value="">SSH credential...</option>
                    {attackerCreds.map(c => <option key={c.id} value={c.id}>{c.username} [{c.type}]</option>)}
                  </select>}
            </div>
            {!projectAttackerOptions.length && execMode !== 'global' && <div style={{ fontSize: 10, color: '#f09a3a', marginBottom: 8 }}>No attacker host is linked to this project. Global mode is still available.</div>}
            {!globalAttackerOptions.length && execMode === 'global' && <div style={{ fontSize: 10, color: '#f09a3a', marginBottom: 8 }}>No global attacker target is assigned to this project.</div>}
            {execState.error && <div style={{ fontSize: 10, color: '#cc2233', whiteSpace: 'pre-wrap', marginBottom: 8 }}>{execState.error}</div>}
            {execState.result && (
              <div style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 10, color: execState.result.ok ? '#39d353' : '#f09a3a', fontFamily: 'JetBrains Mono', marginBottom: 6 }}>
                  exit={execState.result.exit_code} · {execState.result.used_global_fallback ? 'global fallback' : 'project credential'}
                </div>
                <pre style={{ background: '#07080b', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px', fontFamily: 'JetBrains Mono', fontSize: 11, color: '#c8cdd6', lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0 }}>{`STDOUT:\n${execState.result.stdout || ''}\n\nSTDERR:\n${execState.result.stderr || ''}`}</pre>
              </div>
            )}
            <button onClick={execute} disabled={execState.running || (execMode !== 'global' && !attackerHostId) || (execMode === 'global' && !globalTargetId)}
              style={{ background: execState.running ? '#1a1c22' : accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: execState.running ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
              {execState.running ? 'Executing...' : 'Exec'}
            </button>
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Close</button>
          <button onClick={copy}
            style={{ background: copied ? '#39d353' : accent, border: 'none', borderRadius: 5, padding: '7px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, transition: 'background .2s' }}>
            <Icon name={copied ? 'check' : 'copy'} size={12} color="#fff" />
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
      </div>
    </div>
  );
}

function AddCustomModal({ accent, item = null, onAdd, onClose }) {
  const [form, setForm] = useState({ title: item?.title || '', category: item?.category || 'Misc', command: item?.command || '', tags: Array.isArray(item?.tags) ? item.tags.join(', ') : '', opsec: item?.opsec || '' });
  const [state, setState] = useState({ saving: false, type: '', message: '' });
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
  const inp = { background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 12, fontFamily: 'JetBrains Mono', outline: 'none', width: '100%' };

  const handleSave = async () => {
    if (!form.title || !form.command) {
      setState({ saving: false, type: 'error', message: 'Title and command are required' });
      return;
    }
    setState({ saving: true, type: '', message: '' });
    try {
      await onAdd({ ...form, tags: form.tags.split(',').map(t => t.trim()).filter(Boolean) });
      setState({ saving: false, type: 'success', message: item ? 'Snippet updated' : 'Snippet saved' });
      setTimeout(() => onClose(), 300);
    } catch (e) {
      setState({ saving: false, type: 'error', message: e.message || 'Failed to save snippet' });
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 12, padding: '28px 32px', width: 480, boxShadow: '0 24px 64px #00000099' }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 20 }}>{item ? 'Edit snippet' : 'Add snippet'}</div>
        {state.message && <div style={{ marginBottom: 14, fontSize: 10, color: state.type === 'error' ? '#cc2233' : '#39d353', fontFamily: 'JetBrains Mono' }}>{state.message}</div>}
        {[['Title', 'title', 'input'], ['Category', 'category', 'input'], ['Tags (comma)', 'tags', 'input'], ['OPSEC note', 'opsec', 'textarea'], ['Command', 'command', 'textarea']].map(([lbl, key, type]) => (
          <div key={key} style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>{lbl}</div>
            {type === 'textarea'
              ? <textarea style={{ ...inp, resize: 'vertical', minHeight: 100, lineHeight: 1.6 }} value={form[key]} onChange={e => set(key, e.target.value)} placeholder="Use {{VAR}} for variables" />
              : <input style={inp} value={form[key]} onChange={e => set(key, e.target.value)} />
            }
          </div>
        ))}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 4 }}>
          <button onClick={onClose} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
          <button onClick={handleSave}
            style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 18px', cursor: state.saving ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', opacity: state.saving ? 0.7 : 1 }}>
            {state.saving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function CheatsheetView({ accent, hosts = [], creds = [], selectedProject }) {
  const [search, setSearch] = useState('');
  const [selectedCat, setSelectedCat] = useState(null);
  const [modalSnippet, setModalSnippet] = useState(null);
  const [showAddCustom, setShowAddCustom] = useState(false);
  const [editingCustom, setEditingCustom] = useState(null);
  const [snippets, setSnippets] = useState([]);
  const [importing, setImporting] = useState(false);

  useEffect(() => {
    api.listSnippets().then(items => setSnippets(items.map(s => ({ ...s, isCustom: !!s.is_custom || !!s.isCustom })))).catch(() => {});
  }, []);

  const allSnippets = snippets;

  const categories = useMemo(() => {
    const cats = [...new Set(allSnippets.map(s => s.category))];
    return cats;
  }, [allSnippets]);

  const filtered = useMemo(() => {
    let list = selectedCat ? allSnippets.filter(s => s.category === selectedCat) : allSnippets;
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(s => s.title.toLowerCase().includes(q) || s.command.toLowerCase().includes(q) || s.tags?.some(t => t.includes(q)) || s.category.toLowerCase().includes(q));
    }
    return list;
  }, [search, selectedCat, allSnippets]);

  const grouped = useMemo(() => {
    const g = {};
    for (const s of filtered) (g[s.category] = g[s.category] || []).push(s);
    return g;
  }, [filtered]);

  const addCustom = async (item) => {
    const created = await api.createCustomSnippet(item);
    setSnippets(prev => [{ ...created, isCustom: true }, ...prev]);
  };

  const updateCustom = async (item) => {
    const updated = await api.updateCustomSnippet(editingCustom.id, item);
    setSnippets(prev => prev.map(s => s.id === editingCustom.id ? { ...updated, isCustom: true } : s));
    setEditingCustom(null);
  };

  const deleteCustom = async (id) => {
    await api.deleteCustomSnippet(id);
    setSnippets(prev => prev.filter(s => s.id !== id));
  };

  const exportSnippets = async () => {
    const blob = await api.exportSnippets();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'snippets.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const importSnippets = async (file) => {
    setImporting(true);
    try {
      await api.importSnippets(file);
      const items = await api.listSnippets();
      setSnippets(items.map(s => ({ ...s, isCustom: !!s.is_custom || !!s.isCustom })));
    } finally {
      setImporting(false);
    }
  };

  const quickCopy = (e, cmd) => {
    e.stopPropagation();
    navigator.clipboard.writeText(cmd);
  };

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {modalSnippet && <VarModal snippet={modalSnippet} accent={accent} onClose={() => setModalSnippet(null)}
        hosts={(hosts || []).filter(h => h.pid === selectedProject)}
        creds={(creds || []).filter(c => c.pid === selectedProject)}
        selectedProject={selectedProject} />}
      {showAddCustom && <AddCustomModal accent={accent} onAdd={addCustom} onClose={() => setShowAddCustom(false)} />}
      {editingCustom && <AddCustomModal accent={accent} item={editingCustom} onAdd={updateCustom} onClose={() => setEditingCustom(null)} />}

      {/* Category sidebar */}
      <div style={{ width: 160, background: '#0a0c10', borderRight: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
        <div style={{ padding: '12px 12px 6px', fontSize: 9, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.14em' }}>Categories</div>
        <button onClick={() => setSelectedCat(null)}
          style={{ width: '100%', padding: '8px 12px', background: !selectedCat ? `${accent}18` : 'transparent', borderLeft: !selectedCat ? `2px solid ${accent}` : '2px solid transparent', border: 'none', cursor: 'pointer', textAlign: 'left', color: !selectedCat ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
          All ({allSnippets.length})
        </button>
        {categories.map(cat => {
          const cnt = allSnippets.filter(s => s.category === cat).length;
          const act = selectedCat === cat;
          return (
            <button key={cat} onClick={() => setSelectedCat(act ? null : cat)}
              style={{ width: '100%', padding: '7px 12px', background: act ? `${accent}18` : 'transparent', borderLeft: act ? `2px solid ${accent}` : '2px solid transparent', border: 'none', cursor: 'pointer', textAlign: 'left', color: act ? accent : '#606570', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', justifyContent: 'space-between', alignItems: 'center', transition: 'all .12s' }}>
              <span>{cat}</span>
              <span style={{ fontSize: 9, color: act ? accent + 'aa' : '#303540' }}>{cnt}</span>
            </button>
          );
        })}
      </div>

      {/* Main area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Toolbar */}
        <div style={{ padding: '10px 20px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <Icon name="search" size={12} color="#404550" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search commands..."
              style={{ width: '100%', background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 6, padding: '7px 10px 7px 32px', color: '#c8cdd6', fontSize: 12, fontFamily: 'JetBrains Mono', outline: 'none' }} />
          </div>
          <label style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 14px', cursor: importing ? 'wait' : 'pointer', color: '#808590', fontSize: 11, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0, opacity: importing ? 0.7 : 1 }}>
            <Icon name="export" size={11} color="currentColor" /> {importing ? 'Importing...' : 'Import'}
            <input type="file" accept="application/json,.json" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && importSnippets(e.target.files[0])} disabled={importing} />
          </label>
          <button onClick={exportSnippets}
            style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#808590', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
            <Icon name="export" size={11} color="currentColor" /> Export
          </button>
          <button onClick={() => setShowAddCustom(true)}
            style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
            <Icon name="plus" size={11} color="#fff" /> Custom snippet
          </button>
        </div>

        {/* Snippets list */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 20px' }}>
          {Object.entries(grouped).map(([cat, snips]) => (
            <div key={cat} style={{ marginBottom: 24 }}>
              <div style={{ fontSize: 10, color: accent, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                {cat}
                <div style={{ flex: 1, height: 1, background: accent + '22' }} />
                <span style={{ fontSize: 9, color: accent + '88', fontWeight: 400 }}>{snips.length}</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 8 }}>
                {snips.map(s => {
                  const vars = extractVars(s.command);
                  return (
                    <div key={s.id} onClick={() => setModalSnippet(s)}
                      style={{ background: s.opsec ? '#1a0d0a' : '#0d0f14', border: `1px solid ${s.opsec ? '#cc223333' : '#1e2029'}`, borderRadius: 8, padding: '10px 14px', cursor: 'pointer', transition: 'border-color .12s', position: 'relative' }}
                      onMouseEnter={e => e.currentTarget.style.borderColor = s.opsec ? '#cc223366' : accent + '66'}
                      onMouseLeave={e => e.currentTarget.style.borderColor = s.opsec ? '#cc223333' : '#1e2029'}>
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 6, gap: 6 }}>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2, flexWrap: 'wrap' }}>
                            <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec', fontFamily: 'Space Grotesk', lineHeight: 1.3 }}>{s.title}</span>
                            {s.isCustom && (
                              <span style={{ fontSize: 8, color: '#39d353', background: '#39d35318', border: '1px solid #39d35333', borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>custom</span>
                            )}
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: 4, flexShrink: 0, alignItems: 'center' }}>
                          {s.opsec && (
                            <span title={`OPSEC: ${s.opsec}`} style={{ cursor: 'help', display: 'flex' }}>
                              <Icon name="opsec" size={12} color="#f09a3a" />
                            </span>
                          )}
                          {s.isCustom && (
                            <button onClick={e => { e.stopPropagation(); setEditingCustom(s); }}
                              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: accent, display: 'flex' }}>
                              <Icon name="edit" size={11} color="currentColor" />
                            </button>
                          )}
                          {s.isCustom && (
                            <button onClick={e => { e.stopPropagation(); deleteCustom(s.id); }}
                              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, color: '#cc2233', display: 'flex' }}>
                              <Icon name="trash" size={11} color="currentColor" />
                            </button>
                          )}
                          <button onClick={e => quickCopy(e, s.command)}
                            style={{ background: 'none', border: `1px solid #2a2d35`, borderRadius: 3, cursor: 'pointer', padding: '2px 6px', fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 3 }}>
                            <Icon name="copy" size={9} color="#505560" /> copy
                          </button>
                        </div>
                      </div>
                      <pre style={{ fontFamily: 'JetBrains Mono', fontSize: 10, color: '#808590', lineHeight: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, maxHeight: 60, overflow: 'hidden' }}>
                        {s.command}
                      </pre>
                      {vars.length > 0 && (
                        <div style={{ marginTop: 6, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {vars.map(v => (
                            <span key={v} style={{ fontSize: 8, color: accent, background: accent + '18', border: `1px solid ${accent}33`, borderRadius: 3, padding: '1px 5px', fontFamily: 'JetBrains Mono' }}>
                              {v}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
          {Object.keys(grouped).length === 0 && (
            <div style={{ padding: '60px 0', textAlign: 'center', color: '#303540' }}>
              <Icon name="terminal" size={40} color="#2a2d35" />
              <div style={{ fontSize: 13, marginTop: 12 }}>Nothing found</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
