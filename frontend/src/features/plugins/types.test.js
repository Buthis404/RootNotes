import { describe, it, expect } from 'vitest';
import { MODULE_SCHEMA } from './types.js';

describe('MODULE_SCHEMA', () => {
  it('defines the documented extension-point keys', () => {
    expect(MODULE_SCHEMA).toHaveProperty('id');
    expect(MODULE_SCHEMA).toHaveProperty('version', '1.0.0');
    expect(MODULE_SCHEMA).toHaveProperty('enabled', true);
    for (const key of [
      'routes', 'menuItems', 'projectTabs', 'hostTabs',
      'networkTabs', 'reportSections', 'importers', 'dashboardWidgets',
    ]) {
      expect(Array.isArray(MODULE_SCHEMA[key])).toBe(true);
    }
  });

  it('declares the four action buckets', () => {
    expect(MODULE_SCHEMA.actions).toEqual({
      hosts: [], findings: [], creds: [], networkNodes: [],
    });
  });
});
