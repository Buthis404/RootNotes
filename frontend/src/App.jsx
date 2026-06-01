import { useState, useEffect, useCallback, useRef, Suspense } from 'react';

function _syncNodeWithHosts(node, hosts, net) {
  const host = hosts.find(h => h.pid === net.pid && (node.host_id ? h.id === node.host_id : h.ip === node.ip));
  if (!host) return { node, changed: false };
  const next = { ...node };
  let changed = false;
  if (next.status !== host.status) { next.status = host.status; changed = true; }
  if (next.notes !== (host.notes || '')) { next.notes = host.notes || ''; changed = true; }
  const fallbackIps = host.ip ? [host.ip] : [];
  const hostIps = host.ips && host.ips.length > 0 ? host.ips : fallbackIps;
  if (JSON.stringify(next.ips || []) !== JSON.stringify(hostIps)) { next.ips = hostIps; changed = true; }
  if (JSON.stringify(next.ports || []) !== JSON.stringify(host.ports || [])) { next.ports = host.ports || []; changed = true; }
  if (next.host_id !== host.id) { next.host_id = host.id; changed = true; }
  if ((next.label === node.ip || next.label === host.ip || next.label === host.hostname || !next.label) && host.hostname) {
    if (next.label !== host.hostname) { next.label = host.hostname; changed = true; }
  }
  return { node: next, changed };
}
import ToastContainer from './components/Toast.jsx';
import Icon from './components/Icon.jsx';
import { api } from './api.js';
import { useProjectStore } from './store/useProjectStore.js';
import { useSync } from './hooks/useSync.js';
import { useEntityCRUD } from './hooks/useEntityCRUD.js';
import lazyWithReload from './utils/lazyWithReload.js';
import { useProjectPermissions } from './context/ProjectPermissions.jsx';
import { TweaksPanel } from './app/AppChrome.jsx';
import { TWEAK_DEFAULTS, TWEAKS_KEY } from './app/uiConstants.js';
import { applySyncEvent } from './app/applySyncEvent.js';
import AppNavBar from './app/AppNavBar.jsx';
import AppContextSidebar from './app/AppContextSidebar.jsx';
import AppTabRouter from './app/AppTabRouter.jsx';
import { isAttackerHost } from './utils/hostMeta.js';
import { moduleRegistry } from './features/plugins/registry.js';

// Eagerly loaded — needed on first render
import LoginView from './views/LoginView.jsx';

// Lazily loaded modals
const SearchModal = lazyWithReload(() => import('./components/SearchModal.jsx'));
import ImportModal from './components/ImportModal.jsx';
import AIChatPanel from './components/AIChatPanel.jsx';

// ── Main App ──────────────────────────────────────────────────────────
export default function App() {
  // ── Auth state ──────────────────────────────────────────────────────
  const [authReady, setAuthReady] = useState(false);
  const [isFirstRun, setIsFirstRun] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [sessionExpired, setSessionExpired] = useState(false);
  const { loadPermissions } = useProjectPermissions();

  useEffect(() => {
    const doCheck = async () => {
      const status = await api.authStatus();
      if (!status.initialized) { setIsFirstRun(true); setAuthReady(true); return; }
      try {
        const u = await api.authMe();
        setCurrentUser(u);
        moduleRegistry.syncFromBackend(api.listModules);
      } catch {}
      setAuthReady(true);
    };
    doCheck();
    const onLogout = () => { setCurrentUser(null); setIsFirstRun(false); setSessionExpired(false); loadPermissions(null); };
    const onAuthExpired = () => { setCurrentUser(null); setIsFirstRun(false); setSessionExpired(true); loadPermissions(null); };
    globalThis.addEventListener('rt:logout', onLogout);
    globalThis.addEventListener('rt:auth-expired', onAuthExpired);
    return () => {
      globalThis.removeEventListener('rt:logout', onLogout);
      globalThis.removeEventListener('rt:auth-expired', onAuthExpired);
    };
  }, [loadPermissions]);

  const handleAuth = (user) => {
    setError(null);
    setLoading(true);
    setCurrentUser(user);
    setIsFirstRun(false);
  };
  const handleLogout = async () => {
    try { await api.authLogout(); } catch {}
    setCurrentUser(null);
    setError(null);
    setLoading(true);
  };

  // ── UI state ─────────────────────────────────────────────────────────
  const [tweaks, setTweaks] = useState(() => {
    try { return { ...TWEAK_DEFAULTS, ...JSON.parse(localStorage.getItem(TWEAKS_KEY) || '{}') }; } catch { return TWEAK_DEFAULTS; }
  });
  const [showTweaks, setShowTweaks] = useState(false);
  const [navExpanded, setNavExpanded] = useState(() => {
    try { return JSON.parse(localStorage.getItem('rt_nav_expanded') || 'false'); } catch { return false; }
  });
  const [tab, setTab] = useState(() => localStorage.getItem('rt_tab') || 'projects');
  const [selectedProject, setSelectedProject] = useState(() => localStorage.getItem('rt_project') || '');
  const [jobsFilter, setJobsFilter] = useState(null);
  const [showSearch, setShowSearch] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [importProjectId, setImportProjectId] = useState(null);
  const [presence, setPresence] = useState([]);
  const [aiEnabled, setAiEnabled] = useState(true);

  // ── Project data (Zustand) ───────────────────────────────────────────
  const {
    projects, setProjects,
    notes, setNotes,
    hosts, setHosts,
    creds, setCreds,
    setNetworks,
    findings, setFindings,
    objectives, setObjectives,
    attackPaths, setAttackPaths,
    setAttackSteps,
    loots, setLoots,
    scopes, setScopes,
    setHostActivities,
  } = useProjectStore();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [jobs, setJobs] = useState([]);

  // ── CRUD actions ─────────────────────────────────────────────────────
  const crud = useEntityCRUD({ selectedProject, setSelectedProject });

  // ── Effects ───────────────────────────────────────────────────────────
  useEffect(() => {
    if (!currentUser) return;
    let cancelled = false;
    setError(null);
    setLoading(true);
    Promise.all([
      api.getProjects(), api.getNotes(), api.getHosts(), api.getCreds(),
      api.getNetworks(), api.getFindings(), api.getObjectives(),
      api.getAttackPaths(), api.getAttackSteps(), api.getLoots(),
      api.getScopes(), api.getHostActivities(),
    ])
      .then(([p, n, h, c, nets, f, obj, aps, ass, lts, scs, acts]) => {
        if (cancelled) return;
        setProjects(p); setNotes(n); setHosts(h); setCreds(c); setNetworks(nets);
        setFindings(f); setObjectives(obj); setAttackPaths(aps); setAttackSteps(ass);
        setLoots(lts); setScopes(scs); setHostActivities(acts);
        setSelectedProject(prev => prev || p[0]?.id || '');
        setLoading(false);
      })
      .catch(e => { if (!cancelled) { setError(e.message); setLoading(false); } });
    return () => { cancelled = true; };
  }, [currentUser]);

  useEffect(() => {
    if (!currentUser) return;
    let cancelled = false;
    const load = () => {
      api.getAIStatus()
        .then(s => { if (!cancelled) setAiEnabled(s?.enabled !== false); })
        .catch(() => { if (!cancelled) setAiEnabled(false); });
    };
    load();
    const handler = () => load();
    globalThis.addEventListener('rt:ai_status_changed', handler);
    return () => { cancelled = true; globalThis.removeEventListener('rt:ai_status_changed', handler); };
  }, [currentUser]);

  useEffect(() => {
    localStorage.setItem(TWEAKS_KEY, JSON.stringify(tweaks));
    const color = encodeURIComponent(tweaks.accent);
    const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%2308090b'/><path d='M16 4 L27 8 L27 17 C27 23 22 28 16 30 C10 28 5 23 5 17 L5 8 Z' fill='${color}' opacity='0.22'/><path d='M16 4 L27 8 L27 17 C27 23 22 28 16 30 C10 28 5 23 5 17 L5 8 Z' fill='none' stroke='${color}' stroke-width='1.5'/><path d='M11 16 L14.5 19.5 L21 13' stroke='${color}' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' fill='none'/></svg>`;
    const link = document.getElementById('favicon-link');
    if (link) { link.href = `data:image/svg+xml,${svg}`; }
  }, [tweaks]);

  useEffect(() => { localStorage.setItem('rt_tab', tab); }, [tab]);
  useEffect(() => { localStorage.setItem('rt_nav_expanded', JSON.stringify(navExpanded)); }, [navExpanded]);

  useEffect(() => {
    if (!currentUser) return;
    const fetchPresence = () => api.getPresence().then(r => setOnlineUsers(r.online || [])).catch(() => {});
    fetchPresence();
    const iv = setInterval(fetchPresence, 20000);
    return () => clearInterval(iv);
  }, [currentUser]);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); setShowSearch(v => !v); }
      if (e.key === 'Escape') { setShowSearch(false); }
    };
    globalThis.addEventListener('keydown', onKey);
    return () => globalThis.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => { if (selectedProject) localStorage.setItem('rt_project', selectedProject); }, [selectedProject]);
  useEffect(() => {
    if (!currentUser) return;
    loadPermissions(selectedProject || null);
  }, [selectedProject, loadPermissions, currentUser]);

  useEffect(() => {
    const onRefresh = () => {
      Promise.all([api.getHosts(), api.getCreds()]).then(([h, c]) => { setHosts(h); setCreds(c); }).catch(() => {});
    };
    globalThis.addEventListener('rt:refresh', onRefresh);
    return () => globalThis.removeEventListener('rt:refresh', onRefresh);
  }, []);

  useEffect(() => {
    return () => {
      Object.values(crud.netSaveTimers.current).forEach(clearTimeout);
      crud.netSaveTimers.current = {};
    };
  }, []);

  // ── WebSocket sync ────────────────────────────────────────────────────
  const localOps = useRef(new Set());
  const markLocalOp = useCallback((id) => { if (id) localOps.current.add(id); }, []);

  const updateOneNetwork = useCallback((networkId, updater) => {
    setNetworks(prev => prev.map(net => net.id === networkId ? updater(net) : net));
  }, [setNetworks]);

  const handleSyncEvent = useCallback((msg) => {
    applySyncEvent(msg, {
      localOps, setNotes, setHosts, setCreds, setNetworks, setFindings,
      setObjectives, setAttackPaths, setAttackSteps, setLoots, setScopes,
      setHostActivities, setJobs, setProjects, updateOneNetwork,
    });
  }, [setAttackPaths, setAttackSteps, setCreds, setFindings, setHostActivities, setHosts, setJobs, setLoots, setNetworks, setNotes, setObjectives, setProjects, setScopes, updateOneNetwork]);

  const { send: sendWs } = useSync(selectedProject, currentUser?.username, handleSyncEvent, setPresence);
  const sendFocus = useCallback((noteId) => sendWs(noteId ? { type: 'focus', note_id: noteId } : { type: 'blur' }), [sendWs]);

  // ── Sync hosts → network nodes ────────────────────────────────────────
  useEffect(() => {
    setNetworks(prev => prev.map(net => {
      let changed = false;
      const nodes = [];
      for (const node of (net.nodes || [])) {
        const { node: next, changed: c } = _syncNodeWithHosts(node, hosts, net);
        changed = changed || c;
        nodes.push(next);
      }
      return changed ? { ...net, nodes } : net;
    }));
  }, [hosts]);

  // ── Import modal refresh ──────────────────────────────────────────────
  const handleImported = async () => {
    const [n, h, c, nets, f, obj, aps, ass, lts, scs, acts] = await Promise.all([
      api.getNotes(), api.getHosts(), api.getCreds(), api.getNetworks(),
      api.getFindings(), api.getObjectives(), api.getAttackPaths(),
      api.getAttackSteps(), api.getLoots(), api.getScopes(), api.getHostActivities(),
    ]);
    setNotes(n); setHosts(h); setCreds(c); setNetworks(nets); setFindings(f);
    setObjectives(obj); setAttackPaths(aps); setAttackSteps(ass);
    setLoots(lts); setScopes(scs); setHostActivities(acts);
  };

  // ── Derived ───────────────────────────────────────────────────────────
  const acc = tweaks.accent;
  const green = tweaks.accentGreen;
  const fs = tweaks.fontSize;

  const badges = {
    notes:      notes.filter(n => n.pid === selectedProject && n.starred).length,
    hosts:      hosts.filter(h => h.pid === selectedProject && !isAttackerHost(h) && (h.status === 'pwned' || h.status === 'owned')).length,
    creds:      creds.filter(c => c.pid === selectedProject && c.cracked).length,
    findings:   findings.filter(f => f.pid === selectedProject && (f.severity === 'critical' || f.severity === 'high') && f.status === 'open').length,
    objectives: objectives.filter(o => o.pid === selectedProject && (o.status === 'captured' || o.status === 'in_progress')).length,
    attackpath: attackPaths.filter(p => p.pid === selectedProject).length,
    loot:       loots.filter(l => l.pid === selectedProject).length,
    scope:      scopes.filter(s => s.pid === selectedProject).length,
    jobs:       jobs.filter(j => j.pid === selectedProject && (j.status === 'running' || j.status === 'queued')).length,
    network: 0, attackgraph: 0, projects: 0, report: 0, checklist: 0, timeline: 0, cheatsheet: 0, scans: 0,
  };

  const refreshHosts = useCallback(() => api.getHosts().then(h => setHosts(h)), []);
  const refreshNetworks = useCallback(() => api.getNetworks().then(nets => setNetworks(nets)), []);
  const updateTweak = (key, val) => setTweaks(t => ({ ...t, [key]: val }));

  // ── Auth guards ───────────────────────────────────────────────────────
  if (!authReady) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%', color: '#404550', flexDirection: 'column', gap: 12 }}>
      <Icon name="shield" size={32} color={acc} />
      <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono' }}>Connecting...</div>
    </div>
  );

  if (!currentUser) return <LoginView accent={acc} isFirstRun={isFirstRun} onAuth={handleAuth} sessionExpired={sessionExpired} />;

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%', color: '#404550', flexDirection: 'column', gap: 12 }}>
      <Icon name="shield" size={32} color={acc} />
      <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono' }}>Loading...</div>
    </div>
  );

  if (error) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%', color: '#cc2233', flexDirection: 'column', gap: 12 }}>
      <Icon name="warning" size={32} color="#cc2233" />
      <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono' }}>Error: {error}</div>
    </div>
  );

  return (
    <div style={{ display: 'flex', width: '100%', height: '100%', fontSize: fs, background: '#08090b' }}>
      <AppNavBar
        tab={tab} setTab={setTab}
        accent={acc} badges={badges}
        navExpanded={navExpanded} setNavExpanded={setNavExpanded}
        showSearch={showSearch} setShowSearch={setShowSearch}
        showTweaks={showTweaks} setShowTweaks={setShowTweaks}
        currentUser={currentUser}
        onLogout={handleLogout}
      />

      <AppContextSidebar
        tab={tab}
        projects={projects} notes={notes} hosts={hosts} creds={creds}
        selectedProject={selectedProject} onSelectProject={setSelectedProject}
        accent={acc}
        presence={presence}
      />

      <AppTabRouter
        tab={tab} setTab={setTab}
        accent={acc} accentGreen={green} fontSize={fs}
        animateLinks={!!tweaks.networkMapAnimations}
        selectedProject={selectedProject} setSelectedProject={setSelectedProject}
        currentUser={currentUser} setCurrentUser={setCurrentUser}
        onlineUsers={onlineUsers}
        jobs={jobs} setJobs={setJobs}
        jobsFilter={jobsFilter} setJobsFilter={setJobsFilter}
        presence={presence}
        markLocalOp={markLocalOp}
        refreshHosts={refreshHosts}
        refreshNetworks={refreshNetworks}
        sendFocus={sendFocus}
        setImportProjectId={setImportProjectId}
        crud={crud}
      />

      {showTweaks && <TweaksPanel tweaks={tweaks} updateTweak={updateTweak} onClose={() => setShowTweaks(false)} left={72} />}

      {showSearch && (
        <Suspense fallback={null}>
          <SearchModal accent={acc} selectedProject={selectedProject} projects={projects}
            onNavigate={t => setTab(t)}
            onClose={() => setShowSearch(false)} />
        </Suspense>
      )}

      {importProjectId && (
        <ImportModal projectId={importProjectId} accent={acc}
          onClose={() => setImportProjectId(null)}
          onImported={handleImported} />
      )}

      {selectedProject && aiEnabled && <AIChatPanel selectedProject={selectedProject} accent={acc} />}

      <ToastContainer />
    </div>
  );
}
