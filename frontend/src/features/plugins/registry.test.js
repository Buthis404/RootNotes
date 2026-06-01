import { describe, it, expect, afterEach, vi } from 'vitest';
import { moduleRegistry } from './registry.js';

// Helper: register a throwaway module and guarantee cleanup.
const TEMP = '__test_mod__';
afterEach(() => {
  moduleRegistry.unregister(TEMP);
  moduleRegistry.unregister('uploaded-x');
});

describe('moduleRegistry built-ins', () => {
  it('pre-registers the core modules and topology', () => {
    expect(moduleRegistry.get('topology')).toBeTruthy();
    expect(moduleRegistry.get('hosts')?.title).toBe('Hosts');
    expect(moduleRegistry.get('reports')).toBeTruthy();
  });

  it('exposes topology importer through getImporters', () => {
    const ids = moduleRegistry.getImporters().map(i => i.id);
    expect(ids).toContain('topology-nmap');
  });
});

describe('register / unregister / get', () => {
  it('register requires an id', () => {
    expect(() => moduleRegistry.register({})).toThrow(/must have an id/);
  });

  it('registers, defaults enabled=true, and unregisters', () => {
    moduleRegistry.register({ id: TEMP, title: 'Temp' });
    expect(moduleRegistry.get(TEMP)).toMatchObject({ id: TEMP, enabled: true });
    moduleRegistry.unregister(TEMP);
    expect(moduleRegistry.get(TEMP)).toBeUndefined();
  });

  it('respects explicit enabled=false', () => {
    moduleRegistry.register({ id: TEMP, enabled: false });
    expect(moduleRegistry.get(TEMP).enabled).toBe(false);
  });
});

describe('enable / disable / getEnabled', () => {
  it('toggles enabled state and filters via getEnabled', () => {
    moduleRegistry.register({ id: TEMP });
    moduleRegistry.disable(TEMP);
    expect(moduleRegistry.getEnabled().some(m => m.id === TEMP)).toBe(false);
    moduleRegistry.enable(TEMP);
    expect(moduleRegistry.getEnabled().some(m => m.id === TEMP)).toBe(true);
  });

  it('enable/disable on unknown id is a no-op', () => {
    expect(() => moduleRegistry.enable('nope')).not.toThrow();
    expect(() => moduleRegistry.disable('nope')).not.toThrow();
  });
});

describe('aggregated extension points', () => {
  it('flattens actions and tabs from enabled modules only', () => {
    moduleRegistry.register({
      id: TEMP,
      hostTabs: [{ id: 'ht1', label: 'HT' }],
      actions: { hosts: [{ id: 'ha1' }], creds: [{ id: 'ca1' }] },
    });
    expect(moduleRegistry.getHostTabs().some(t => t.id === 'ht1')).toBe(true);
    expect(moduleRegistry.getHostActions().some(a => a.id === 'ha1')).toBe(true);
    expect(moduleRegistry.getCredActions().some(a => a.id === 'ca1')).toBe(true);

    moduleRegistry.disable(TEMP);
    expect(moduleRegistry.getHostTabs().some(t => t.id === 'ht1')).toBe(false);
  });
});

describe('toJSON', () => {
  it('returns a serialisable summary shape', () => {
    const json = moduleRegistry.toJSON();
    expect(Array.isArray(json)).toBe(true);
    const topo = json.find(m => m.id === 'topology');
    expect(Object.keys(topo).sort()).toEqual(
      ['description', 'enabled', 'id', 'title', 'version'],
    );
  });
});

describe('syncFromBackend', () => {
  it('syncs enabled state of a known module', async () => {
    moduleRegistry.register({ id: TEMP, enabled: true });
    await moduleRegistry.syncFromBackend(async () => ({
      modules: [{ name: TEMP, enabled: false, source: 'builtin' }],
    }));
    expect(moduleRegistry.get(TEMP).enabled).toBe(false);
  });

  it('auto-registers an uploaded (non-builtin) module', async () => {
    await moduleRegistry.syncFromBackend(async () => ({
      modules: [{ name: 'uploaded-x', enabled: true, source: 'upload', version: '2.0.0' }],
    }));
    expect(moduleRegistry.get('uploaded-x')).toMatchObject({
      id: 'uploaded-x', version: '2.0.0', source: 'upload',
    });
  });

  it('does not auto-register unknown builtin modules', async () => {
    await moduleRegistry.syncFromBackend(async () => ({
      modules: [{ name: 'ghost', enabled: true, source: 'builtin' }],
    }));
    expect(moduleRegistry.get('ghost')).toBeUndefined();
  });

  it('never throws when the fetch fails', async () => {
    const failing = vi.fn().mockRejectedValue(new Error('boom'));
    await expect(moduleRegistry.syncFromBackend(failing)).resolves.toBeUndefined();
  });
});
