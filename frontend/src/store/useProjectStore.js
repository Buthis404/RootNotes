import { create } from 'zustand';

const setter = (key) => (valOrFn) =>
  (set) => set((s) => ({ [key]: typeof valOrFn === 'function' ? valOrFn(s[key]) : valOrFn }));

export const useProjectStore = create((set, get) => {
  const mk = (key) => (valOrFn) =>
    set((s) => ({ [key]: typeof valOrFn === 'function' ? valOrFn(s[key]) : valOrFn }));

  return {
    projects: [],
    notes: [],
    hosts: [],
    creds: [],
    networks: [],
    findings: [],
    objectives: [],
    attackPaths: [],
    attackSteps: [],
    loots: [],
    scopes: [],
    hostActivities: [],

    setProjects:      mk('projects'),
    setNotes:         mk('notes'),
    setHosts:         mk('hosts'),
    setCreds:         mk('creds'),
    setNetworks:      mk('networks'),
    setFindings:      mk('findings'),
    setObjectives:    mk('objectives'),
    setAttackPaths:   mk('attackPaths'),
    setAttackSteps:   mk('attackSteps'),
    setLoots:         mk('loots'),
    setScopes:        mk('scopes'),
    setHostActivities: mk('hostActivities'),

    // ── Optimistic helpers ───────────────────────────────────────────────

    addHost: (host) => set((s) => ({ hosts: [...s.hosts, host] })),
    updateHost: (id, data) =>
      set((s) => ({ hosts: s.hosts.map((h) => (h.id === id ? { ...h, ...data } : h)) })),
    removeHost: (id) => set((s) => ({ hosts: s.hosts.filter((h) => h.id !== id) })),

    addCred: (cred) => set((s) => ({ creds: [...s.creds, cred] })),
    updateCred: (id, data) =>
      set((s) => ({ creds: s.creds.map((c) => (c.id === id ? { ...c, ...data } : c)) })),
    removeCred: (id) => set((s) => ({ creds: s.creds.filter((c) => c.id !== id) })),

    addNote: (note) => set((s) => ({ notes: [...s.notes, note] })),
    updateNote: (id, data) =>
      set((s) => ({ notes: s.notes.map((n) => (n.id === id ? { ...n, ...data } : n)) })),
    removeNote: (id) => set((s) => ({ notes: s.notes.filter((n) => n.id !== id) })),

    addFinding: (finding) => set((s) => ({ findings: [...s.findings, finding] })),
    updateFinding: (id, data) =>
      set((s) => ({ findings: s.findings.map((f) => (f.id === id ? { ...f, ...data } : f)) })),
    removeFinding: (id) => set((s) => ({ findings: s.findings.filter((f) => f.id !== id) })),

    addLoot: (loot) => set((s) => ({ loots: [...s.loots, loot] })),
    updateLoot: (id, data) =>
      set((s) => ({ loots: s.loots.map((l) => (l.id === id ? { ...l, ...data } : l)) })),
    removeLoot: (id) => set((s) => ({ loots: s.loots.filter((l) => l.id !== id) })),

    addScope: (scope) => set((s) => ({ scopes: [...s.scopes, scope] })),
    updateScope: (id, data) =>
      set((s) => ({ scopes: s.scopes.map((sc) => (sc.id === id ? { ...sc, ...data } : sc)) })),
    removeScope: (id) => set((s) => ({ scopes: s.scopes.filter((sc) => sc.id !== id) })),

    addHostActivity: (act) => set((s) => ({ hostActivities: [...s.hostActivities, act] })),
    updateHostActivity: (id, data) =>
      set((s) => ({ hostActivities: s.hostActivities.map((a) => (a.id === id ? { ...a, ...data } : a)) })),
    removeHostActivity: (id) =>
      set((s) => ({ hostActivities: s.hostActivities.filter((a) => a.id !== id) })),

    resetProjectData: () =>
      set({
        notes: [], hosts: [], creds: [], networks: [], findings: [],
        objectives: [], attackPaths: [], attackSteps: [], loots: [],
        scopes: [], hostActivities: [],
      }),
  };
});
