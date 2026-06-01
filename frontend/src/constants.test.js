import { describe, it, expect } from 'vitest';
import {
  PHASES, PHASE_COLORS, NODE_STATUS, NODE_TYPES, CRED_TYPES, OS_ICONS,
  SERVICE_COLORS, serviceColor, TABS, ADMIN_TAB, SEVERITY, FINDING_STATUS,
  FINDING_TEMPLATES, SNIPPETS, OBJECTIVE_CATEGORY, OBJECTIVE_STATUS,
  CHECKLIST_DEFAULTS, PORT_SERVICES,
} from './constants.js';

describe('constant tables', () => {
  it('PHASES lists the engagement phases and each has a colour', () => {
    expect(PHASES).toContain('recon');
    expect(PHASES).toContain('report');
    for (const p of PHASES) expect(PHASE_COLORS[p]).toMatch(/^#/);
  });

  it('lookup tables are non-empty objects', () => {
    for (const tbl of [NODE_STATUS, NODE_TYPES, CRED_TYPES, SERVICE_COLORS,
      SEVERITY, FINDING_STATUS, OBJECTIVE_CATEGORY, OBJECTIVE_STATUS, PORT_SERVICES]) {
      expect(Object.keys(tbl).length).toBeGreaterThan(0);
    }
  });

  it('OS_ICONS maps known operating systems', () => {
    expect(OS_ICONS.Windows).toBeTruthy();
    expect(OS_ICONS.Linux).toBeTruthy();
  });

  it('TABS and ADMIN_TAB have id/label/icon shape', () => {
    expect(TABS.length).toBeGreaterThan(5);
    for (const t of TABS) {
      expect(t).toHaveProperty('id');
      expect(t).toHaveProperty('label');
    }
    expect(ADMIN_TAB.id).toBe('admin');
  });

  it('templates/snippets/checklist defaults are present', () => {
    expect(Array.isArray(FINDING_TEMPLATES)).toBe(true);
    expect(Array.isArray(SNIPPETS)).toBe(true);
    expect(typeof CHECKLIST_DEFAULTS).toBe('object');
  });
});

describe('serviceColor', () => {
  it('returns the neutral colour for an empty name', () => {
    expect(serviceColor('')).toBe('#606570');
    expect(serviceColor(undefined)).toBe('#606570');
  });

  it('matches a known service colour case-insensitively', () => {
    const [key, color] = Object.entries(SERVICE_COLORS)[0];
    expect(serviceColor(key.toLowerCase())).toBe(color);
    expect(serviceColor('prefix-' + key + '-suffix')).toBe(color);
  });

  it('falls back to a deterministic hsl colour for unknown services', () => {
    const c1 = serviceColor('totally-unknown-svc-xyz');
    const c2 = serviceColor('totally-unknown-svc-xyz');
    expect(c1).toMatch(/^hsl\(\d+, 50%, 55%\)$/);
    expect(c1).toBe(c2); // deterministic
  });
});
