/**
 * Centralised CRUD actions for all project entities.
 *
 * Reads/writes Zustand store directly so App.jsx doesn't have to thread
 * setter props through the component tree.
 *
 * Usage:
 *   const crud = useEntityCRUD({ selectedProject, setSelectedProject });
 *   await crud.addHost({ ... });
 */
import { useCallback, useRef } from 'react';
import { api } from '../api.js';
import { useProjectStore } from '../store/useProjectStore.js';
import { hasAutoRoleSignals, inferNodeType } from '../utils/hostMeta.js';

function _updateNodeForHost(node, h, current) {
  const nodeIps = new Set((node.ips && node.ips.length > 0 ? node.ips : [node.ip]).filter(Boolean));
  const hostIps = new Set(([current?.ip, h.ip, ...(current?.ips || []), ...(h.ips || [])]).filter(Boolean));
  const match = node.host_id ? node.host_id === h.id : [...hostIps].some(ip => nodeIps.has(ip));
  if (!match) return { node, changed: false };
  const next = { ...node, host_id: h.id, ip: h.ip, ips: h.ips || [], status: h.status, ports: h.ports || [], notes: h.notes || '', role: h.role, is_attacker: h.is_attacker };
  if ((node.label === current?.hostname || node.label === current?.ip || node.label === h.ip) && h.hostname) next.label = h.hostname;
  if (hasAutoRoleSignals(h)) next.type = inferNodeType(h);
  const changed = next.ip !== node.ip || next.status !== node.status || next.label !== node.label || next.type !== node.type || next.notes !== node.notes;
  return { node: next, changed };
}

function _removeHostFromNet(net, ip) {
  const removedIds = new Set((net.nodes || []).filter(n => n.ip === ip).map(n => n.id));
  return {
    ...net,
    nodes: (net.nodes || []).filter(n => n.ip !== ip),
    edges: (net.edges || []).filter(e => !removedIds.has(e.from) && !removedIds.has(e.to)),
  };
}

export function useEntityCRUD({ selectedProject, setSelectedProject } = {}) {
  const {
    setNotes, setHosts, setCreds, setNetworks,
    setFindings, setObjectives, setAttackPaths,
    setAttackSteps, setLoots, setScopes, setHostActivities,
    setProjects,
    hosts, creds, findings,
  } = useProjectStore();

  // ── Projects ──────────────────────────────────────────────────────────
  const addProject = useCallback(async (data) => {
    const p = await api.createProject(data);
    setProjects(prev => [...prev, p]);
    setSelectedProject?.(p.id);
    return p;
  }, [setProjects, setSelectedProject]);

  const deleteProject = useCallback(async (id) => {
    await api.deleteProject(id);
    setProjects(prev => {
      const remaining = prev.filter(x => x.id !== id);
      if (selectedProject === id) setSelectedProject?.(remaining[0]?.id || '');
      return remaining;
    });
    setNotes(prev => prev.filter(x => x.pid !== id));
    setHosts(prev => prev.filter(x => x.pid !== id));
    setCreds(prev => prev.filter(x => x.pid !== id));
    setNetworks(prev => prev.filter(n => n.pid !== id));
    setHostActivities(prev => prev.filter(x => x.pid !== id));
  }, [selectedProject, setSelectedProject, setProjects, setNotes, setHosts, setCreds, setNetworks, setHostActivities]);

  // ── Loot ──────────────────────────────────────────────────────────────
  const addLoot = useCallback(async (data) => {
    const l = await api.createLoot(data);
    setLoots(prev => prev.some(x => x.id === l.id) ? prev : [l, ...prev]);
    return l;
  }, [setLoots]);

  const updateLoot = useCallback(async (id, patch) => {
    if (patch?.id && patch.id === id && patch.pid) {
      setLoots(prev => prev.map(x => x.id === id ? patch : x));
      return patch;
    }
    const l = await api.updateLoot(id, patch);
    setLoots(prev => prev.map(x => x.id === id ? l : x));
    return l;
  }, [setLoots]);

  const deleteLoot = useCallback(async (id) => {
    await api.deleteLoot(id);
    setLoots(prev => prev.filter(x => x.id !== id));
  }, [setLoots]);

  // ── Scope ──────────────────────────────────────────────────────────────
  const addScope = useCallback(async (data) => {
    const s = await api.createScope(data);
    setScopes(prev => prev.some(x => x.id === s.id) ? prev : [...prev, s]);
  }, [setScopes]);

  const updateScope = useCallback(async (id, patch) => {
    const s = await api.updateScope(id, patch);
    setScopes(prev => prev.map(x => x.id === id ? s : x));
  }, [setScopes]);

  const deleteScope = useCallback(async (id) => {
    await api.deleteScope(id);
    setScopes(prev => prev.filter(x => x.id !== id));
  }, [setScopes]);

  // ── Host Activities ────────────────────────────────────────────────────
  const addHostActivity = useCallback(async (data) => {
    const item = await api.createHostActivity(data);
    setHostActivities(prev => prev.some(x => x.id === item.id) ? prev : [item, ...prev]);
    return item;
  }, [setHostActivities]);

  const updateHostActivity = useCallback(async (id, patch) => {
    const item = await api.updateHostActivity(id, patch);
    setHostActivities(prev => prev.map(x => x.id === id ? item : x));
    return item;
  }, [setHostActivities]);

  const deleteHostActivity = useCallback(async (id) => {
    await api.deleteHostActivity(id);
    setHostActivities(prev => prev.filter(x => x.id !== id));
  }, [setHostActivities]);

  // ── Attack Paths ───────────────────────────────────────────────────────
  const addAttackPath = useCallback(async (data) => {
    const ap = await api.createAttackPath(data);
    setAttackPaths(prev => [...prev, ap]);
    return ap;
  }, [setAttackPaths]);

  const updateAttackPath = useCallback(async (id, patch) => {
    const ap = await api.updateAttackPath(id, patch);
    setAttackPaths(prev => prev.map(x => x.id === id ? ap : x));
    return ap;
  }, [setAttackPaths]);

  const deleteAttackPath = useCallback(async (id) => {
    await api.deleteAttackPath(id);
    setAttackPaths(prev => prev.filter(x => x.id !== id));
    setAttackSteps(prev => prev.filter(x => x.path_id !== id));
  }, [setAttackPaths, setAttackSteps]);

  const addAttackStep = useCallback(async (data) => {
    const s = await api.createAttackStep(data);
    setAttackSteps(prev => [...prev, s]);
    return s;
  }, [setAttackSteps]);

  const updateAttackStep = useCallback(async (id, patch) => {
    const s = await api.updateAttackStep(id, patch);
    setAttackSteps(prev => prev.map(x => x.id === id ? s : x));
    return s;
  }, [setAttackSteps]);

  const deleteAttackStep = useCallback(async (id) => {
    await api.deleteAttackStep(id);
    setAttackSteps(prev => prev.filter(x => x.id !== id));
  }, [setAttackSteps]);

  // ── Objectives ─────────────────────────────────────────────────────────
  const addObjective = useCallback(async (data) => {
    const obj = await api.createObjective(data);
    setObjectives(prev => [obj, ...prev]);
    return obj;
  }, [setObjectives]);

  const updateObjective = useCallback(async (id, patch) => {
    const obj = await api.updateObjective(id, patch);
    setObjectives(prev => prev.map(x => x.id === id ? obj : x));
    return obj;
  }, [setObjectives]);

  const deleteObjective = useCallback(async (id) => {
    await api.deleteObjective(id);
    setObjectives(prev => prev.filter(x => x.id !== id));
  }, [setObjectives]);

  // ── Findings ───────────────────────────────────────────────────────────
  const addFinding = useCallback(async (data) => {
    const f = await api.createFinding(data);
    setFindings(prev => [...prev, f]);
    return f;
  }, [setFindings]);

  const updateFinding = useCallback(async (id, patch) => {
    const f = await api.updateFinding(id, patch);
    setFindings(prev => prev.map(x => x.id === id ? f : x));
  }, [setFindings]);

  const deleteFinding = useCallback(async (id) => {
    const snap = findings.slice();
    setFindings(prev => prev.filter(x => x.id !== id));
    try {
      await api.deleteFinding(id);
    } catch {
      setFindings(snap);
    }
  }, [findings, setFindings]);

  // ── Notes ──────────────────────────────────────────────────────────────
  const addNote = useCallback(async (data) => {
    const n = await api.createNote(data);
    setNotes(prev => prev.some(x => x.id === n.id) ? prev : [n, ...prev]);
  }, [setNotes]);

  const updateNote = useCallback(async (id, patch) => {
    const n = await api.updateNote(id, patch);
    setNotes(prev => prev.map(x => x.id === id ? n : x));
  }, [setNotes]);

  const deleteNote = useCallback(async (id) => {
    await api.deleteNote(id);
    setNotes(prev => prev.filter(x => x.id !== id));
  }, [setNotes]);

  // ── Hosts ──────────────────────────────────────────────────────────────
  const addHost = useCallback(async (data) => {
    const h = await api.createHost(data);
    setHosts(prev => prev.some(x => x.id === h.id) ? prev : [...prev, h]);
    return h;
  }, [setHosts]);

  const updateHost = useCallback(async (id, patch) => {
    const current = hosts.find(x => x.id === id);
    const h = await api.updateHost(id, patch);
    setHosts(prev => prev.map(x => x.id === id ? h : x));
    setNetworks(prev => prev.map(net => {
      let changed = false;
      const nodes = [];
      for (const node of (net.nodes || [])) {
        const { node: next, changed: c } = _updateNodeForHost(node, h, current);
        changed = changed || c;
        nodes.push(next);
      }
      return changed ? { ...net, nodes } : net;
    }));
    return h;
  }, [hosts, setHosts, setNetworks]);

  const deleteHost = useCallback(async (id) => {
    const current = hosts.find(x => x.id === id);
    const snap = hosts.slice();
    setHosts(prev => prev.filter(x => x.id !== id));
    if (current?.ip) {
      setNetworks(prev => prev.map(net => _removeHostFromNet(net, current.ip)));
    }
    try {
      await api.deleteHost(id);
    } catch {
      setHosts(snap);
    }
  }, [hosts, setHosts, setNetworks]);

  const syncHostByIp = useCallback(async (ip, patch) => {
    const host = hosts.find(h => h.pid === selectedProject && h.ip === ip);
    if (!host) return null;
    const updated = await api.updateHost(host.id, patch);
    setHosts(prev => prev.map(h => h.id === host.id ? updated : h));
    return updated;
  }, [hosts, selectedProject, setHosts]);

  // ── Credentials ────────────────────────────────────────────────────────
  const addCred = useCallback(async (data) => {
    const c = await api.createCred(data);
    setCreds(prev => prev.some(x => x.id === c.id) ? prev : [...prev, c]);
  }, [setCreds]);

  const updateCred = useCallback(async (id, patch) => {
    const c = await api.updateCred(id, patch);
    setCreds(prev => prev.map(x => x.id === id ? c : x));
  }, [setCreds]);

  const deleteCred = useCallback(async (id) => {
    const snap = creds.slice();
    setCreds(prev => prev.filter(x => x.id !== id));
    try {
      await api.deleteCred(id);
    } catch {
      setCreds(snap);
    }
  }, [creds, setCreds]);

  // ── Networks ───────────────────────────────────────────────────────────
  const createNetwork = useCallback(async (data) => {
    const net = await api.createNetwork(data);
    setNetworks(prev => prev.some(x => x.id === net.id) ? prev : [...prev, net]);
  }, [setNetworks]);

  const netSaveTimers = useRef({});
  const updateNetwork = useCallback((id, patch) => {
    setNetworks(prev => prev.map(n => n.id === id ? { ...n, ...patch } : n));
    if (netSaveTimers.current[id]) clearTimeout(netSaveTimers.current[id]);
    netSaveTimers.current[id] = setTimeout(async () => {
      try {
        await api.updateNetwork(id, patch);
      } catch (e) {
        console.error('Network save failed:', e);
      }
    }, 600);
  }, [setNetworks]);

  const deleteNetwork = useCallback(async (id) => {
    await api.deleteNetwork(id);
    setNetworks(prev => prev.filter(n => n.id !== id));
  }, [setNetworks]);

  return {
    addProject, deleteProject,
    addLoot, updateLoot, deleteLoot,
    addScope, updateScope, deleteScope,
    addHostActivity, updateHostActivity, deleteHostActivity,
    addAttackPath, updateAttackPath, deleteAttackPath,
    addAttackStep, updateAttackStep, deleteAttackStep,
    addObjective, updateObjective, deleteObjective,
    addFinding, updateFinding, deleteFinding,
    addNote, updateNote, deleteNote,
    addHost, updateHost, deleteHost, syncHostByIp,
    addCred, updateCred, deleteCred,
    createNetwork, updateNetwork, deleteNetwork,
    netSaveTimers,
  };
}
