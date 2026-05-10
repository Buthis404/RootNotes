import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import ToastContainer from './components/Toast.jsx';
import Icon from './components/Icon.jsx';
import { TABS, ADMIN_TAB } from './constants.js';
import { api } from './api.js';
import { useProjectStore } from './store/useProjectStore.js';
import { useSync } from './hooks/useSync.js';
import OverviewView from './views/OverviewView.jsx';
import ProjectsView from './views/ProjectsView.jsx';
import NotesView from './views/NotesView.jsx';
import HostsView from './views/HostsView.jsx';
import CredsView from './views/CredsView.jsx';
import NetworkView from './views/NetworkView.jsx';
import ReportView from './views/ReportView.jsx';
import AdminView from './views/AdminView.jsx';
import FindingsView from './views/FindingsView.jsx';
import ObjectivesView from './views/ObjectivesView.jsx';
import AttackPathView from './views/AttackPathView.jsx';
import AttackGraphView from './views/AttackGraphView.jsx';
import LootView from './views/LootView.jsx';
import ScopeView from './views/ScopeView.jsx';
import SearchModal from './components/SearchModal.jsx';
import ChecklistView from './views/ChecklistView.jsx';
import TimelineView from './views/TimelineView.jsx';
import CheatsheetView from './views/CheatsheetView.jsx';
import ScansView from './views/ScansView.jsx';
import JobsView from './views/JobsView.jsx';
import PlaybooksView from './views/PlaybooksView.jsx';
import DomainsView from './views/DomainsView.jsx';
import AIChatPanel from './components/AIChatPanel.jsx';
import KBView from './views/KBView.jsx';
import ImportModal from './components/ImportModal.jsx';
import LoginView from './views/LoginView.jsx';
import UserSettingsView from './views/UserSettingsView.jsx';
import { hasAutoRoleSignals, inferNodeType, isAttackerHost } from './utils/hostMeta.js';
import { useProjectPermissions } from './context/ProjectPermissions.jsx';
import { NavTab, ProjectPicker, TweaksPanel } from './app/AppChrome.jsx';
import { TWEAK_DEFAULTS, TWEAKS_KEY } from './app/uiConstants.js';
import { applySyncEvent } from './app/applySyncEvent.js';

// ── Main App ──────────────────────────────────────────────────────────
export default function App() {
  // ── Auth state ──────────────────────────────────────────────────────
  const [authReady, setAuthReady] = useState(false);
  const [isFirstRun, setIsFirstRun] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const { loadPermissions } = useProjectPermissions();

  useEffect(() => {
    const doCheck = async () => {
      const token = localStorage.getItem('rt_token');
      const status = await api.authStatus();
      if (!status.initialized) { setIsFirstRun(true); setAuthReady(true); return; }
      if (token) {
        try { const u = await api.authMe(); setCurrentUser(u); } catch { localStorage.removeItem('rt_token'); }
      }
      setAuthReady(true);
    };
    doCheck();
    const onLogout = () => { setCurrentUser(null); setIsFirstRun(false); loadPermissions(null); };
    window.addEventListener('rt:logout', onLogout);
    return () => window.removeEventListener('rt:logout', onLogout);
  }, [loadPermissions]);

  const handleAuth = (user) => {
    setError(null);
    setLoading(true);
    setCurrentUser(user);
    setIsFirstRun(false);
  };
  const handleLogout = () => {
    localStorage.removeItem('rt_token');
    setCurrentUser(null);
    setError(null);
    setLoading(true);
  };

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

  // ── Project data via Zustand ────────────────────────────────────────
  const {
    projects, setProjects,
    notes, setNotes,
    hosts, setHosts,
    creds, setCreds,
    networks, setNetworks,
    findings, setFindings,
    objectives, setObjectives,
    attackPaths, setAttackPaths,
    attackSteps, setAttackSteps,
    loots, setLoots,
    scopes, setScopes,
    hostActivities, setHostActivities,
  } = useProjectStore();

  // Keep loading/error as local state — they have UI-specific semantics
  // (loading starts true, drives the initial spinner before data arrives)
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [jobs, setJobs] = useState([]);

  const [showSearch, setShowSearch] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [importProjectId, setImportProjectId] = useState(null);
  const [presence, setPresence] = useState([]);

  // Track which request IDs originated locally — ignore own WS echoes
  const localOps = useRef(new Set());
  const markLocalOp = useCallback((id) => {
    if (id) localOps.current.add(id);
  }, []);

  // ── Initial load ────────────────────────────────────────────────────
  useEffect(() => {
    if (!currentUser) return;

    let cancelled = false;
    setError(null);
    setLoading(true);

    Promise.all([api.getProjects(), api.getNotes(), api.getHosts(), api.getCreds(), api.getNetworks(), api.getFindings(), api.getObjectives(), api.getAttackPaths(), api.getAttackSteps(), api.getLoots(), api.getScopes(), api.getHostActivities()])
      .then(([p, n, h, c, nets, f, obj, aps, ass, lts, scs, acts]) => {
        if (cancelled) return;
        setProjects(p);
        setNotes(n);
        setHosts(h);
        setCreds(c);
        setNetworks(nets);
        setFindings(f);
        setObjectives(obj);
        setAttackPaths(aps);
        setAttackSteps(ass);
        setLoots(lts);
        setScopes(scs);
        setHostActivities(acts);
        setSelectedProject(prev => prev || p[0]?.id || '');
        setLoading(false);
      })
      .catch(e => {
        if (cancelled) return;
        setError(e.message);
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [currentUser]);

  useEffect(() => {
    localStorage.setItem(TWEAKS_KEY, JSON.stringify(tweaks));
    // Update favicon color to match accent
    const color = encodeURIComponent(tweaks.accent);
    const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%2308090b'/><path d='M16 4 L27 8 L27 17 C27 23 22 28 16 30 C10 28 5 23 5 17 L5 8 Z' fill='${color}' opacity='0.22'/><path d='M16 4 L27 8 L27 17 C27 23 22 28 16 30 C10 28 5 23 5 17 L5 8 Z' fill='none' stroke='${color}' stroke-width='1.5'/><path d='M11 16 L14.5 19.5 L21 13' stroke='${color}' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' fill='none'/></svg>`;
    const link = document.getElementById('favicon-link');
    if (link) link.href = `data:image/svg+xml,${svg}`;
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
      if (e.key === 'Escape') setShowSearch(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  useEffect(() => { if (selectedProject) localStorage.setItem('rt_project', selectedProject); }, [selectedProject]);
  // Only fetch permissions when user is authenticated — prevents premature 401→rt:logout race
  useEffect(() => {
    if (!currentUser) return;
    loadPermissions(selectedProject || null);
  }, [selectedProject, loadPermissions, currentUser]);

  // BloodHound import full refresh
  useEffect(() => {
    const onRefresh = () => {
      Promise.all([api.getHosts(), api.getCreds()]).then(([h, c]) => {
        setHosts(h);
        setCreds(c);
      }).catch(() => {});
    };
    window.addEventListener('rt:refresh', onRefresh);
    return () => window.removeEventListener('rt:refresh', onRefresh);
  }, []);

  // ── WebSocket real-time sync ────────────────────────────────────────
  // We connect to the selected project's room.
  // When the backend broadcasts an event, we apply it to state.
  // Local mutations go through REST first, then WS echo arrives — we skip our own.
  const updateOneNetwork = useCallback((networkId, updater) => {
    setNetworks(prev => prev.map(net => net.id === networkId ? updater(net) : net));
  }, []);

  const handleSyncEvent = useCallback((msg) => {
    applySyncEvent(msg, {
      localOps,
      setNotes,
      setHosts,
      setCreds,
      setNetworks,
      setFindings,
      setObjectives,
      setAttackPaths,
      setAttackSteps,
      setLoots,
      setScopes,
      setHostActivities,
      setJobs,
      setProjects,
      updateOneNetwork,
    });
  }, [setAttackPaths, setAttackSteps, setCreds, setFindings, setHostActivities, setHosts, setJobs, setLoots, setNetworks, setNotes, setObjectives, setProjects, setScopes, updateOneNetwork]);

  const { send: sendWs } = useSync(selectedProject, currentUser?.username, handleSyncEvent, setPresence);
  const sendFocus = useCallback((noteId) => sendWs(noteId ? { type: 'focus', note_id: noteId } : { type: 'blur' }), [sendWs]);

  const updateTweak = (key, val) => setTweaks(t => ({ ...t, [key]: val }));
  const acc = tweaks.accent, green = tweaks.accentGreen, fs = tweaks.fontSize;

  // ── Projects CRUD ───────────────────────────────────────────────────
  const addProject = async (data) => {
    const p = await api.createProject(data);
    setProjects(prev => [...prev, p]);
    setSelectedProject(p.id);
    return p;
  };

  const deleteProject = async (id) => {
    await api.deleteProject(id);
    setProjects(prev => {
      const remaining = prev.filter(x => x.id !== id);
      if (selectedProject === id) setSelectedProject(remaining[0]?.id || '');
      return remaining;
    });
    setNotes(prev => prev.filter(x => x.pid !== id));
    setHosts(prev => prev.filter(x => x.pid !== id));
    setCreds(prev => prev.filter(x => x.pid !== id));
    setNetworks(prev => prev.filter(n => n.pid !== id));
    setHostActivities(prev => prev.filter(x => x.pid !== id));
    setJobs(prev => prev.filter(x => x.pid !== id));
  };

  // ── Loot CRUD ───────────────────────────────────────────────────────
  const addLoot = async (data) => {
    const l = await api.createLoot(data);
    setLoots(prev => prev.some(x => x.id === l.id) ? prev : [l, ...prev]);
    return l;
  };
  const updateLoot = async (id, patch) => {
    if (patch?.id && patch.id === id && patch.pid) {
      setLoots(prev => prev.map(x => x.id === id ? patch : x));
      return patch;
    }
    const l = await api.updateLoot(id, patch);
    setLoots(prev => prev.map(x => x.id === id ? l : x));
    return l;
  };
  const deleteLoot = async (id) => {
    await api.deleteLoot(id);
    setLoots(prev => prev.filter(x => x.id !== id));
  };

  // ── Scope CRUD ──────────────────────────────────────────────────────
  const addScope = async (data) => {
    const s = await api.createScope(data);
    setScopes(prev => prev.some(x => x.id === s.id) ? prev : [...prev, s]);
  };
  const updateScope = async (id, patch) => {
    const s = await api.updateScope(id, patch);
    setScopes(prev => prev.map(x => x.id === id ? s : x));
  };
  const deleteScope = async (id) => {
    await api.deleteScope(id);
    setScopes(prev => prev.filter(x => x.id !== id));
  };

  const addHostActivity = async (data) => {
    const item = await api.createHostActivity(data);
    setHostActivities(prev => prev.some(x => x.id === item.id) ? prev : [item, ...prev]);
    return item;
  };
  const updateHostActivity = async (id, patch) => {
    const item = await api.updateHostActivity(id, patch);
    setHostActivities(prev => prev.map(x => x.id === id ? item : x));
    return item;
  };
  const deleteHostActivity = async (id) => {
    await api.deleteHostActivity(id);
    setHostActivities(prev => prev.filter(x => x.id !== id));
  };

  // ── Attack Paths CRUD ───────────────────────────────────────────────
  const addAttackPath = async (data) => {
    const ap = await api.createAttackPath(data);
    setAttackPaths(prev => [...prev, ap]);
    return ap;
  };
  const updateAttackPath = async (id, patch) => {
    const ap = await api.updateAttackPath(id, patch);
    setAttackPaths(prev => prev.map(x => x.id === id ? ap : x));
    return ap;
  };
  const deleteAttackPath = async (id) => {
    await api.deleteAttackPath(id);
    setAttackPaths(prev => prev.filter(x => x.id !== id));
    setAttackSteps(prev => prev.filter(x => x.path_id !== id));
  };
  const addAttackStep = async (data) => {
    const s = await api.createAttackStep(data);
    setAttackSteps(prev => [...prev, s]);
    return s;
  };
  const updateAttackStep = async (id, patch) => {
    const s = await api.updateAttackStep(id, patch);
    setAttackSteps(prev => prev.map(x => x.id === id ? s : x));
    return s;
  };
  const deleteAttackStep = async (id) => {
    await api.deleteAttackStep(id);
    setAttackSteps(prev => prev.filter(x => x.id !== id));
  };

  // ── Objectives CRUD ─────────────────────────────────────────────────
  const addObjective = async (data) => {
    const obj = await api.createObjective(data);
    setObjectives(prev => [obj, ...prev]);
    return obj;
  };
  const updateObjective = async (id, patch) => {
    const obj = await api.updateObjective(id, patch);
    setObjectives(prev => prev.map(x => x.id === id ? obj : x));
    return obj;
  };
  const deleteObjective = async (id) => {
    await api.deleteObjective(id);
    setObjectives(prev => prev.filter(x => x.id !== id));
  };

  // ── Findings CRUD ───────────────────────────────────────────────────
  const addFinding = async (data) => {
    const f = await api.createFinding(data);
    setFindings(prev => [...prev, f]);
    return f;
  };
  const updateFinding = async (id, patch) => {
    const f = await api.updateFinding(id, patch);
    setFindings(prev => prev.map(x => x.id === id ? f : x));
  };
  const deleteFinding = async (id) => {
    const prevFindings = findings;
    setFindings(prev => prev.filter(x => x.id !== id)); // optimistic
    try {
      await api.deleteFinding(id);
    } catch (e) {
      setFindings(prevFindings); // rollback
    }
  };

  // ── Notes CRUD ──────────────────────────────────────────────────────
  const addNote = async (data) => {
    const n = await api.createNote(data);
    setNotes(prev => prev.some(x => x.id === n.id) ? prev : [n, ...prev]);
  };
  const updateNote = async (id, patch) => {
    const n = await api.updateNote(id, patch);
    setNotes(prev => prev.map(x => x.id === id ? n : x));
  };
  const deleteNote = async (id) => {
    await api.deleteNote(id);
    setNotes(prev => prev.filter(x => x.id !== id));
  };

  // ── Hosts CRUD ──────────────────────────────────────────────────────
  const addHost = async (data) => {
    const h = await api.createHost(data);
    setHosts(prev => prev.some(x => x.id === h.id) ? prev : [...prev, h]);
    return h;
  };
  const updateHost = async (id, patch) => {
    const current = hosts.find(x => x.id === id);
    const h = await api.updateHost(id, patch);
    setHosts(prev => prev.map(x => x.id === id ? h : x));
    setNetworks(prev => prev.map(net => {
      let changed = false;
      const nodes = (net.nodes || []).map(node => {
        const nodeIps = new Set((node.ips && node.ips.length > 0 ? node.ips : [node.ip]).filter(Boolean));
        const hostIps = new Set(([current?.ip, h.ip, ...(current?.ips || []), ...(h.ips || [])]).filter(Boolean));
        const match = node.host_id ? node.host_id === h.id : [...hostIps].some(ip => nodeIps.has(ip));
        if (!match) return node;
        const next = { ...node, host_id: h.id, ip: h.ip, ips: h.ips || [], status: h.status, ports: h.ports || [], notes: h.notes || '', role: h.role, is_attacker: h.is_attacker };
        if ((node.label === current?.hostname || node.label === current?.ip || node.label === h.ip) && h.hostname) next.label = h.hostname;
        if (hasAutoRoleSignals(h)) next.type = inferNodeType(h);
        changed = changed || next.ip !== node.ip || next.status !== node.status || next.label !== node.label || next.type !== node.type || next.notes !== node.notes;
        return next;
      });
      return changed ? { ...net, nodes } : net;
    }));
    return h;
  };
  const deleteHost = async (id) => {
    const current = hosts.find(x => x.id === id);
    const prevHosts = hosts;
    // Optimistic: remove immediately
    setHosts(prev => prev.filter(x => x.id !== id));
    if (current?.ip) {
      setNetworks(prev => prev.map(net => ({ ...net, nodes: (net.nodes || []).filter(n => n.ip !== current.ip), edges: (net.edges || []).filter(e => {
        const ids = new Set((net.nodes || []).filter(n => n.ip === current.ip).map(n => n.id));
        return !ids.has(e.from) && !ids.has(e.to);
      }) })));
    }
    try {
      await api.deleteHost(id);
    } catch (e) {
      setHosts(prevHosts); // rollback on error
    }
  };

  const syncHostByIp = async (ip, patch) => {
    const host = hosts.find(h => h.pid === selectedProject && h.ip === ip);
    if (!host) return null;
    const updated = await api.updateHost(host.id, patch);
    setHosts(prev => prev.map(h => h.id === host.id ? updated : h));
    return updated;
  };

  // ── Creds CRUD ──────────────────────────────────────────────────────
  const addCred = async (data) => {
    const c = await api.createCred(data);
    setCreds(prev => prev.some(x => x.id === c.id) ? prev : [...prev, c]);
  };
  const updateCred = async (id, patch) => {
    const c = await api.updateCred(id, patch);
    setCreds(prev => prev.map(x => x.id === id ? c : x));
  };
  const deleteCred = async (id) => {
    const prevCreds = creds;
    setCreds(prev => prev.filter(x => x.id !== id)); // optimistic
    try {
      await api.deleteCred(id);
    } catch (e) {
      setCreds(prevCreds); // rollback
    }
  };

  // ── Networks CRUD ───────────────────────────────────────────────────
  const createNetwork = async (data) => {
    const net = await api.createNetwork(data);
    setNetworks(prev => prev.some(x => x.id === net.id) ? prev : [...prev, net]);
  };

  // Debounced network save — no optimistic flag, just local state + server persist
  const netSaveTimers = useRef({});
  const updateNetwork = useCallback((id, patch) => {
    // Apply locally immediately for smooth dragging
    setNetworks(prev => prev.map(n => n.id === id ? { ...n, ...patch } : n));
    // Debounce server write
    if (netSaveTimers.current[id]) clearTimeout(netSaveTimers.current[id]);
    netSaveTimers.current[id] = setTimeout(async () => {
      try {
        await api.updateNetwork(id, patch);
      } catch (e) {
        console.error('Network save failed:', e);
      }
    }, 600);
  }, []);

  useEffect(() => {
    return () => {
      Object.values(netSaveTimers.current).forEach(clearTimeout);
      netSaveTimers.current = {};
    };
  }, []);

  const deleteNetwork = async (id) => {
    await api.deleteNetwork(id);
    setNetworks(prev => prev.filter(n => n.id !== id));
  };

  // ── After import: WS will push upserts, but also refresh immediately ─
  const handleImported = async () => {
    const [n, h, c, nets, f, obj, aps, ass, lts, scs, acts] = await Promise.all([
      api.getNotes(),
      api.getHosts(),
      api.getCreds(),
      api.getNetworks(),
      api.getFindings(),
      api.getObjectives(),
      api.getAttackPaths(),
      api.getAttackSteps(),
      api.getLoots(),
      api.getScopes(),
      api.getHostActivities(),
    ]);
    setNotes(n);
    setHosts(h);
    setCreds(c);
    setNetworks(nets);
    setFindings(f);
    setObjectives(obj);
    setAttackPaths(aps);
    setAttackSteps(ass);
    setLoots(lts);
    setScopes(scs);
    setHostActivities(acts);
  };

  useEffect(() => {
    setNetworks(prev => prev.map(net => {
      let changed = false;
      const nodes = (net.nodes || []).map(node => {
        const host = hosts.find(h => h.pid === net.pid && (node.host_id ? h.id === node.host_id : h.ip === node.ip));
        if (!host) return node;
        const next = { ...node };
        if (next.status !== host.status) { next.status = host.status; changed = true; }
        if (next.notes !== (host.notes || '')) { next.notes = host.notes || ''; changed = true; }
        const hostIps = host.ips && host.ips.length > 0 ? host.ips : (host.ip ? [host.ip] : []);
        if (JSON.stringify(next.ips || []) !== JSON.stringify(hostIps)) { next.ips = hostIps; changed = true; }
        if (JSON.stringify(next.ports || []) !== JSON.stringify(host.ports || [])) { next.ports = host.ports || []; changed = true; }
        if (next.host_id !== host.id) { next.host_id = host.id; changed = true; }
        if ((next.label === node.ip || next.label === host.ip || next.label === host.hostname || !next.label) && host.hostname) {
          if (next.label !== host.hostname) { next.label = host.hostname; changed = true; }
        }
        if (hasAutoRoleSignals(host)) {
          const derivedType = inferNodeType(host);
          if (next.type !== derivedType) { next.type = derivedType; changed = true; }
        }
        return next;
      });
      return changed ? { ...net, nodes } : net;
    }));
  }, [hosts]);

  const badges = {
    notes:      notes.filter(n => n.pid === selectedProject && n.starred).length,
    hosts:      hosts.filter(h => h.pid === selectedProject && !isAttackerHost(h) && (h.status === 'pwned' || h.status === 'owned')).length,
    creds:      creds.filter(c => c.pid === selectedProject && c.cracked).length,
    findings:   findings.filter(f => f.pid === selectedProject && (f.severity === 'critical' || f.severity === 'high') && f.status === 'open').length,
    objectives: objectives.filter(o => o.pid === selectedProject && (o.status === 'captured' || o.status === 'in_progress')).length,
    attackpath: attackPaths.filter(p => p.pid === selectedProject).length,
    loot:       loots.filter(l => l.pid === selectedProject).length,
    scope:      scopes.filter(s => s.pid === selectedProject).length,
    jobs:     jobs.filter(j => j.pid === selectedProject && (j.status === 'running' || j.status === 'queued')).length,
    network: 0, attackgraph: 0, projects: 0, report: 0, checklist: 0, timeline: 0, cheatsheet: 0, scans: 0,
  };

  const selectedProjectHosts = useMemo(
    () => hosts.filter(h => h.pid === selectedProject),
    [hosts, selectedProject],
  );
  const selectedProjectNetworks = useMemo(
    () => networks.filter(n => n.pid === selectedProject),
    [networks, selectedProject],
  );
  const refreshHosts = useCallback(() => api.getHosts().then(h => setHosts(h)), []);
  const refreshNetworks = useCallback(() => api.getNetworks().then(nets => setNetworks(nets)), []);

  if (!authReady) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%', color: '#404550', flexDirection: 'column', gap: 12 }}>
      <Icon name="shield" size={32} color={acc} />
      <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono' }}>Connecting...</div>
    </div>
  );

  if (!currentUser) return <LoginView accent={acc} isFirstRun={isFirstRun} onAuth={handleAuth} />;

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
      {/* Nav bar */}
      <div style={{ width: navExpanded ? 178 : 64, background: '#0a0b0f', borderRight: '1px solid #1a1c22', display: 'flex', flexDirection: 'column', flexShrink: 0, zIndex: 10, transition: 'width .18s' }}>
        <div style={{ padding: navExpanded ? '14px 12px 10px' : '14px 0 10px', display: 'flex', justifyContent: navExpanded ? 'flex-start' : 'center', alignItems: 'center', borderBottom: '1px solid #151720', gap: 8, position: 'relative' }}>
          <div style={{ width: 32, height: 32, background: `${acc}20`, border: `1px solid ${acc}55`, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <Icon name="shield" size={16} color={acc} />
          </div>
          {navExpanded && <span style={{ flex: 1, fontSize: 13, color: '#e0e4ec', fontFamily: 'Space Grotesk', fontWeight: 700 }}>RootNotes</span>}
        </div>
        <div style={{ flex: 1, overflowY: 'auto', paddingTop: 4 }}>
          {TABS.map(t => <NavTab key={t.id} tab={t} active={tab === t.id} onClick={() => setTab(t.id)} accent={acc} badge={badges[t.id]} expanded={navExpanded} />)}
          {currentUser?.role === 'admin' && (
            <NavTab tab={ADMIN_TAB} active={tab === 'admin'} onClick={() => setTab('admin')} accent="#cc2233" expanded={navExpanded} />
          )}
        </div>
        <div style={{ borderTop: '1px solid #151720', paddingBottom: 8 }}>
          {/* Search button */}
          <button onClick={() => setShowSearch(v => !v)} title="Search (Ctrl+K)"
            style={{ width: '100%', padding: navExpanded ? '10px 14px' : '10px 0', border: 'none', cursor: 'pointer', background: showSearch ? `${acc}18` : 'transparent', borderLeft: showSearch ? `2px solid ${acc}` : '2px solid transparent', display: 'flex', flexDirection: navExpanded ? 'row' : 'column', alignItems: 'center', justifyContent: navExpanded ? 'flex-start' : 'center', gap: 8, transition: 'all .15s' }}
            onMouseEnter={e => { if (!showSearch) e.currentTarget.style.background = '#ffffff08'; }}
            onMouseLeave={e => { if (!showSearch) e.currentTarget.style.background = 'transparent'; }}>
            <Icon name="search" size={18} color={showSearch ? acc : '#404550'} />
            {navExpanded && <span style={{ fontSize: 9, color: showSearch ? acc : '#606570', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 600, fontFamily: 'JetBrains Mono' }}>Search</span>}
            {!navExpanded && <span style={{ fontSize: 8, color: showSearch ? acc : '#404550', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 600, fontFamily: 'JetBrains Mono' }}>Ctrl+K</span>}
          </button>
          {/* Current user + logout */}
          <div style={{ padding: navExpanded ? '10px 12px 6px' : '10px 0 6px', display: 'flex', flexDirection: navExpanded ? 'row' : 'column', alignItems: 'center', gap: 8 }}>
            <button onClick={() => setTab('user-settings')} title="User settings"
              style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, width: navExpanded ? '100%' : 'auto', padding: 0, textAlign: 'left' }}>
              <div style={{ width: 28, height: 28, borderRadius: '50%', background: `${acc}22`, border: `1px solid ${acc}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: acc, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
                {(currentUser?.display_name || currentUser?.username || '').slice(0, 2).toUpperCase()}
              </div>
              {navExpanded && <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 10, color: '#c8cdd6', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{currentUser?.display_name || currentUser?.username}</div>
                <div style={{ fontSize: 9, color: '#606570', fontFamily: 'JetBrains Mono', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>@{currentUser?.username}</div>
              </div>}
            </button>
            <button onClick={handleLogout} title="Sign out"
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', fontSize: 9, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 3 }}
              onMouseEnter={e => e.currentTarget.style.color = '#cc2233'}
              onMouseLeave={e => e.currentTarget.style.color = '#303540'}>
              <Icon name="close" size={9} color="currentColor" /> {navExpanded ? 'logout' : ''}
            </button>
          </div>
          <button onClick={() => setShowTweaks(v => !v)} title="Tweaks"
            style={{ width: '100%', padding: navExpanded ? '14px 14px' : '14px 0', border: 'none', cursor: 'pointer', background: showTweaks ? `${acc}18` : 'transparent', borderLeft: showTweaks ? `2px solid ${acc}` : '2px solid transparent', display: 'flex', flexDirection: navExpanded ? 'row' : 'column', alignItems: 'center', justifyContent: navExpanded ? 'flex-start' : 'center', gap: 8, transition: 'all .15s' }}
            onMouseEnter={e => { if (!showTweaks) e.currentTarget.style.background = '#ffffff08'; }}
            onMouseLeave={e => { if (!showTweaks) e.currentTarget.style.background = 'transparent'; }}>
            <Icon name="settings" size={20} color={showTweaks ? acc : '#404550'} />
            {navExpanded && <span style={{ fontSize: 9, color: showTweaks ? acc : '#606570', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 600 }}>Tweaks</span>}
          </button>
          <button onClick={() => setNavExpanded(v => !v)} title={navExpanded ? 'Collapse sidebar' : 'Expand sidebar'}
            style={{ width: '100%', padding: navExpanded ? '14px 14px' : '14px 0', border: 'none', cursor: 'pointer', background: 'transparent', borderLeft: '2px solid transparent', display: 'flex', flexDirection: navExpanded ? 'row' : 'column', alignItems: 'center', justifyContent: navExpanded ? 'flex-start' : 'center', gap: 8, transition: 'all .15s', color: '#505560' }}
            onMouseEnter={e => { e.currentTarget.style.background = '#ffffff08'; e.currentTarget.style.color = '#9098a8'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#505560'; }}>
            <Icon name="chevron" size={20} color="currentColor" style={{ transform: navExpanded ? 'rotate(90deg)' : 'rotate(-90deg)' }} />
            {navExpanded && <span style={{ fontSize: 9, color: 'currentColor', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 600 }}>Collapse</span>}
          </button>
        </div>
      </div>

      {/* Context sidebar */}
      {tab !== 'projects' && tab !== 'user-settings' && (
        <div style={{ width: 200, background: '#0c0e13', borderRight: '1px solid #1a1c22', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
          <div style={{ padding: '14px 14px 10px', borderBottom: '1px solid #151720' }}>
            <div style={{ fontSize: 10, color: '#353840', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 7 }}>RootNotes</div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>{TABS.find(t => t.id === tab)?.label}</div>
          </div>
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <ProjectPicker projects={projects} hosts={hosts.filter(h => !isAttackerHost(h))} selected={selectedProject} onSelect={setSelectedProject} accent={acc} />
          </div>
          <div style={{ borderTop: '1px solid #151720', padding: '12px 14px' }}>
            {[['notes', notes.filter(n => n.pid === selectedProject).length, 'notes'],
              ['hosts', hosts.filter(h => h.pid === selectedProject && !isAttackerHost(h)).length, 'hosts'],
              ['creds', creds.filter(c => c.pid === selectedProject).length, 'creds']
            ].map(([icon, val, label]) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                  <Icon name={icon} size={11} color="#353840" />
                  <span style={{ fontSize: 11, color: '#404550' }}>{label}</span>
                </div>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#606570', fontFamily: 'JetBrains Mono' }}>{val}</span>
              </div>
            ))}
            {/* Online in this project */}
            {presence.length > 0 && (
              <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #151720' }}>
                <div style={{ fontSize: 9, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 7 }}>In project now</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {presence.map(u => (
                    <div key={u.name} title={u.note_id ? `${u.name} — editing a note` : u.name}
                      style={{ display: 'flex', alignItems: 'center', gap: 5, background: '#0e1016', border: `1px solid ${acc}33`, borderRadius: 12, padding: '3px 8px 3px 4px' }}>
                      <div style={{ width: 18, height: 18, borderRadius: '50%', background: `${acc}22`, border: `1px solid ${acc}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, fontWeight: 700, color: acc, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
                        {u.name.slice(0, 2).toUpperCase()}
                      </div>
                      <span style={{ fontSize: 10, color: '#808590', fontFamily: 'JetBrains Mono' }}>{u.name}</span>
                      {u.note_id && <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#f09a3a', flexShrink: 0 }} title="Editing a note" />}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Main content */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', minWidth: 0 }}>
        {tab === 'projects' && (
          <ProjectsView projects={projects} notes={notes} hosts={hosts} creds={creds}
            scopes={scopes}
            selectedProject={selectedProject}
            onSelect={p => { setSelectedProject(p); setTab('notes'); }}
            accent={acc} onAdd={addProject} onAddScope={addScope}
            onUpdate={async (id, patch) => { const p = await api.updateProject(id, patch); setProjects(prev => prev.map(x => x.id === id ? p : x)); }}
            onDelete={deleteProject}
            onImport={pid => setImportProjectId(pid)}
            onProjectImported={async (result) => {
              const [p, n, h, c, nets, f, obj, aps, ass, lts, scs, acts] = await Promise.all([
                api.getProjects(),
                api.getNotes(),
                api.getHosts(),
                api.getCreds(),
                api.getNetworks(),
                api.getFindings(),
                api.getObjectives(),
                api.getAttackPaths(),
                api.getAttackSteps(),
                api.getLoots(),
                api.getScopes(),
                api.getHostActivities(),
              ]);
              setProjects(p);
              setNotes(n);
              setHosts(h);
              setCreds(c);
              setNetworks(nets);
              setFindings(f);
              setObjectives(obj);
              setAttackPaths(aps);
              setAttackSteps(ass);
              setLoots(lts);
              setScopes(scs);
              setHostActivities(acts);
              setSelectedProject(result.project_id);
            }} />
        )}
        {tab === 'overview' && (
          <OverviewView
            selectedProject={selectedProject}
            projects={projects}
            hosts={hosts}
            creds={creds}
            findings={findings}
            notes={notes}
            objectives={objectives}
            timelineEvents={[]}
            checklistItems={[]}
            accent={acc}
            onTabChange={setTab}
          />
        )}
        {tab === 'user-settings' && (
          <UserSettingsView accent={acc} currentUser={currentUser} onUserUpdated={setCurrentUser} />
        )}
        {tab === 'notes' && (
          <NotesView notes={notes} onAdd={addNote} onUpdate={updateNote} onDelete={deleteNote}
            projects={projects} selectedProject={selectedProject} accent={acc} fs={fs}
            presence={presence} onFocus={sendFocus} username={currentUser?.username} />
        )}
        {tab === 'hosts' && (
          <HostsView hosts={hosts} creds={creds} hostActivities={hostActivities} onAdd={addHost} onUpdate={updateHost} onDelete={deleteHost}
            onAddActivity={addHostActivity} onUpdateActivity={updateHostActivity} onDeleteActivity={deleteHostActivity}
            projects={projects} selectedProject={selectedProject} accent={acc} fs={fs}
            onAddCred={addCred}
            onImport={() => setImportProjectId(selectedProject)} />
        )}
        {tab === 'creds' && (
          <CredsView creds={creds} onAdd={addCred} onUpdate={updateCred} onDelete={deleteCred}
            selectedProject={selectedProject} accent={acc} hosts={hosts} fs={fs} />
        )}
        {tab === 'network' && selectedProject && (
          <NetworkView
            key={selectedProject}
            projectId={selectedProject}
            accent={acc}
            accentGreen={green}
            animateLinks={!!tweaks.networkMapAnimations}
            networks={selectedProjectNetworks}
            onCreateNetwork={createNetwork}
            onUpdateNetwork={updateNetwork}
            onDeleteNetwork={deleteNetwork}
            onCreateHost={addHost}
            onUpdateHost={updateHost}
            onSyncHostByIp={syncHostByIp}
            hosts={selectedProjectHosts}
            onAddActivity={addHostActivity}
            onUpdateActivity={updateHostActivity}
            onDeleteActivity={deleteHostActivity}
            onRefreshHosts={refreshHosts}
            onRefreshNetworks={refreshNetworks}
            markLocalOp={markLocalOp}
            findings={findings.filter(f => f.pid === selectedProject)}
            objectives={objectives.filter(o => o.pid === selectedProject)}
            creds={creds.filter(c => c.pid === selectedProject)}
            attackSteps={attackSteps.filter(s => s.pid === selectedProject)}
          />
        )}
        {tab === 'findings' && (
          <FindingsView findings={findings} hosts={hosts} onAdd={addFinding} onUpdate={updateFinding} onDelete={deleteFinding}
            selectedProject={selectedProject} accent={acc} />
        )}
        {tab === 'objectives' && (
          <ObjectivesView objectives={objectives} hosts={hosts}
            onAdd={addObjective} onUpdate={updateObjective} onDelete={deleteObjective}
            selectedProject={selectedProject} accent={acc} currentUser={currentUser} />
        )}
        {tab === 'attackpath' && (
          <AttackPathView
            attackPaths={attackPaths}
            attackSteps={attackSteps}
            onCreatePath={addAttackPath}
            onUpdatePath={updateAttackPath}
            onDeletePath={deleteAttackPath}
            onCreateStep={addAttackStep}
            onUpdateStep={updateAttackStep}
            onDeleteStep={deleteAttackStep}
            selectedProject={selectedProject}
            accent={acc}
            hosts={hosts}
          />
        )}
        {tab === 'attackgraph' && selectedProject && (
          <AttackGraphView
            key={selectedProject}
            selectedProject={selectedProject}
            accent={acc}
          />
        )}
        {tab === 'loot' && (
          <LootView loots={loots} hosts={hosts} onAdd={addLoot} onUpdate={updateLoot} onDelete={deleteLoot}
            selectedProject={selectedProject} accent={acc} fs={fs} />
        )}
        {tab === 'scope' && (
          <ScopeView scopes={scopes} hosts={hosts} onAdd={addScope} onUpdate={updateScope} onDelete={deleteScope}
            selectedProject={selectedProject} accent={acc} fs={fs} />
        )}
        {tab === 'checklist' && (
          <ChecklistView selectedProject={selectedProject} accent={acc} />
        )}
        {tab === 'timeline' && (
          <TimelineView selectedProject={selectedProject} accent={acc} />
        )}
        {tab === 'cheatsheet' && (
          <CheatsheetView accent={acc} hosts={hosts} creds={creds} selectedProject={selectedProject} />
        )}
        {tab === 'scans' && (
          <ScansView selectedProject={selectedProject} accent={acc} />
        )}
        {tab === 'jobs' && (
          <JobsView
            selectedProject={selectedProject}
            accent={acc}
            jobs={jobs.filter(j => j.pid === selectedProject)}
            onJobUpdate={j => setJobs(prev => prev.map(x => x.id === j.id ? j : x))}
            onJobDelete={id => setJobs(prev => prev.filter(x => x.id !== id))}
            initialFilter={jobsFilter}
            onFilterConsumed={() => setJobsFilter(null)}
          />
        )}
        {tab === 'playbooks' && (
          <PlaybooksView selectedProject={selectedProject} accent={acc}
            onNavigate={(to, filter) => { setTab(to); if (filter) setJobsFilter(filter); }}
          />
        )}
        {tab === 'domains' && (
          <DomainsView selectedProject={selectedProject} accent={acc} />
        )}
        {tab === 'kb' && <KBView selectedProject={selectedProject} accent={acc} currentUser={currentUser} />}
        {tab === 'report' && (
          <ReportView projects={projects} notes={notes} hosts={hosts} creds={creds} findings={findings} hostActivities={hostActivities}
            selectedProject={selectedProject} accent={acc} />
        )}
        {tab === 'admin' && currentUser?.role === 'admin' && (
          <AdminView currentUser={currentUser} accent={acc} onlineUsers={onlineUsers} />
        )}
      </div>

      {showTweaks && <TweaksPanel tweaks={tweaks} updateTweak={updateTweak} onClose={() => setShowTweaks(false)} left={72} />}

      {showSearch && (
        <SearchModal accent={acc} selectedProject={selectedProject} projects={projects}
          onNavigate={(t) => setTab(t)}
          onClose={() => setShowSearch(false)} />
      )}

      {importProjectId && (
        <ImportModal projectId={importProjectId} accent={acc}
          onClose={() => setImportProjectId(null)}
          onImported={handleImported} />
      )}

      {selectedProject && <AIChatPanel selectedProject={selectedProject} accent={acc} />}

      <ToastContainer />

    </div>
  );
}
