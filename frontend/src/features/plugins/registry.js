/**
 * Frontend Module Registry
 *
 * Usage:
 *   import { moduleRegistry } from './features/plugins/registry.js';
 *   moduleRegistry.register({ id: 'my-module', title: 'My Module', ... });
 *
 * Extension points are aggregated across all enabled modules.
 */

class ModuleRegistry {
  constructor() {
    this._modules = {};
  }

  register(module) {
    if (!module.id) throw new Error('Module must have an id');
    this._modules[module.id] = { ...module, enabled: module.enabled !== false };
    return this;
  }

  unregister(id) {
    delete this._modules[id];
    return this;
  }

  enable(id)  { if (this._modules[id]) this._modules[id].enabled = true; }
  disable(id) { if (this._modules[id]) this._modules[id].enabled = false; }

  getAll()     { return Object.values(this._modules); }
  getEnabled() { return this.getAll().filter(m => m.enabled); }
  get(id)      { return this._modules[id]; }

  // ── Aggregated extension points ───────────────────────────────────

  getRoutes()          { return this.getEnabled().flatMap(m => m.routes || []); }
  getMenuItems()       { return this.getEnabled().flatMap(m => m.menuItems || []); }
  getProjectTabs()     { return this.getEnabled().flatMap(m => m.projectTabs || []); }
  getHostTabs()        { return this.getEnabled().flatMap(m => m.hostTabs || []); }
  getNetworkTabs()     { return this.getEnabled().flatMap(m => m.networkTabs || []); }
  getReportSections()  { return this.getEnabled().flatMap(m => m.reportSections || []); }
  getImporters()       { return this.getEnabled().flatMap(m => m.importers || []); }
  getDashboardWidgets(){ return this.getEnabled().flatMap(m => m.dashboardWidgets || []); }

  getHostActions()        { return this.getEnabled().flatMap(m => m.actions?.hosts || []); }
  getFindingActions()     { return this.getEnabled().flatMap(m => m.actions?.findings || []); }
  getCredActions()        { return this.getEnabled().flatMap(m => m.actions?.creds || []); }
  getNetworkNodeActions() { return this.getEnabled().flatMap(m => m.actions?.networkNodes || []); }

  toJSON() {
    return this.getAll().map(({ id, title, version, description, enabled }) => ({
      id, title, version, description, enabled,
    }));
  }

  /**
   * Sync enabled/disabled state from the backend module list and auto-register
   * any uploaded modules that the backend knows about but the frontend doesn't.
   * Call once after authentication. Idempotent.
   *
   * @param {() => Promise<{modules: Array}>} fetchFn — e.g. () => api.listModules()
   */
  async syncFromBackend(fetchFn) {
    try {
      const { modules } = await fetchFn();
      for (const mod of modules) {
        const id = mod.name;
        if (this._modules[id]) {
          // Known module — just sync enabled state
          if (mod.enabled) this.enable(id);
          else this.disable(id);
        } else if (mod.source !== 'builtin') {
          // Uploaded plugin the frontend hasn't seen — auto-register with metadata only.
          // No UI extensions (routes/tabs/actions) — the plugin is backend-only until
          // the developer also ships a frontend companion file.
          this.register({
            id,
            title: mod.title || mod.name,
            version: mod.version || '0.0.0',
            description: mod.description || '',
            enabled: mod.enabled !== false,
            source: mod.source,
          });
        }
      }
    } catch {
      // Best-effort — never throw from a registry sync
    }
  }
}

export const moduleRegistry = new ModuleRegistry();

// ── Built-in modules registration ────────────────────────────────────

// Topology module — adds topology import UI to Network Map
moduleRegistry.register({
  id: 'topology',
  title: 'Topology Builder',
  version: '1.0.0',
  description: 'Automatic network topology from scan imports (Nmap XML)',
  enabled: true,
  // UI is embedded in NetworkView — no extra routes needed at this stage
  networkTabs: [],
  importers: [{
    id: 'topology-nmap',
    label: 'Build Topology (Nmap)',
    accept: '.xml',
    sourceType: 'nmap',
  }],
});

// Core modules (just metadata — functionality is in existing views)
const CORE_MODULES = [
  { id: 'hosts',       title: 'Hosts',        version: '1.0.0', description: 'Host inventory and management' },
  { id: 'credentials', title: 'Credentials',  version: '1.0.0', description: 'Credential management' },
  { id: 'findings',    title: 'Findings',     version: '1.0.0', description: 'Vulnerability findings' },
  { id: 'network-map', title: 'Network Map',  version: '1.0.0', description: 'Interactive network topology map' },
  { id: 'scan-import', title: 'Scan Import',  version: '1.0.0', description: 'Nmap/Nessus/BloodHound import' },
  { id: 'reports',     title: 'Reports',      version: '1.0.0', description: 'Report generation' },
];

CORE_MODULES.forEach(m => moduleRegistry.register({ ...m, enabled: true }));
