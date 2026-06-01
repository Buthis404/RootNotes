import { describe, it, expect } from 'vitest';
import {
  HOST_ROLES,
  normalizeDomain,
  domainShortLabel,
  domainsMatch,
  isAttackerHost,
  getCredTagMeta,
  inferHostRole,
  inferNodeType,
  hasAutoRoleSignals,
  getHostBadges,
  getCredBadges,
  summarizeCreds,
} from './hostMeta.js';

describe('normalizeDomain', () => {
  it('lowercases, trims and collapses empty labels', () => {
    expect(normalizeDomain('  CORP.Local  ')).toBe('corp.local');
    expect(normalizeDomain('corp..local.')).toBe('corp.local');
    expect(normalizeDomain('')).toBe('');
    expect(normalizeDomain(null)).toBe('');
    expect(normalizeDomain(undefined)).toBe('');
  });
});

describe('domainShortLabel', () => {
  it('returns the first label of a domain', () => {
    expect(domainShortLabel('corp.local')).toBe('corp');
    expect(domainShortLabel('EXAMPLE.com')).toBe('example');
    expect(domainShortLabel('')).toBe('');
  });
});

describe('domainsMatch', () => {
  it('matches identical normalized domains', () => {
    expect(domainsMatch('CORP.local', 'corp.local')).toBe(true);
  });
  it('matches a short name against a fqdn first label', () => {
    expect(domainsMatch('corp', 'corp.local')).toBe(true);
    expect(domainsMatch('corp.local', 'corp')).toBe(true);
  });
  it('returns false for empty or mismatched domains', () => {
    expect(domainsMatch('', 'corp.local')).toBe(false);
    expect(domainsMatch('foo.local', 'bar.local')).toBe(false);
    expect(domainsMatch('foo', 'bar.local')).toBe(false);
  });
});

describe('isAttackerHost', () => {
  it('detects attacker via various signals', () => {
    expect(isAttackerHost({ is_attacker: true })).toBe(true);
    expect(isAttackerHost({ role: 'attacker' })).toBe(true);
    expect(isAttackerHost({ status: 'attacker' })).toBe(true);
    expect(isAttackerHost({ tags: ['Attacker'] })).toBe(true);
  });
  it('returns false for regular hosts and nullish', () => {
    expect(isAttackerHost({ tags: ['web'] })).toBe(false);
    expect(isAttackerHost(null)).toBe(false);
    expect(isAttackerHost(undefined)).toBe(false);
  });
});

describe('getCredTagMeta', () => {
  it('returns known meta for known tags (case-insensitive)', () => {
    expect(getCredTagMeta('domain-admin')).toEqual({ label: 'DA', color: '#e8574a' });
    expect(getCredTagMeta('BLOODHOUND').label).toBe('BH');
  });
  it('falls back to a default for unknown tags', () => {
    expect(getCredTagMeta('whatever')).toEqual({ label: 'whatever', color: '#808590' });
  });
});

describe('inferHostRole', () => {
  it('prioritises attacker', () => {
    expect(inferHostRole({ role: 'attacker' }).id).toBe('attacker');
  });
  it('honours an explicit known role', () => {
    expect(inferHostRole({ role: 'database' })).toEqual({
      id: 'database', label: 'Database', color: '#f09a3a',
    });
  });
  it('infers a DC from kerberos service or port 88', () => {
    expect(inferHostRole({ services: ['kerberos'] }).id).toBe('dc');
    expect(inferHostRole({ ports: [88] }).id).toBe('dc');
    expect(inferHostRole({ tags: ['domain-controller'] }).id).toBe('dc');
  });
  it('infers a web server from web ports or http services', () => {
    expect(inferHostRole({ ports: ['443'] }).id).toBe('web');
    expect(inferHostRole({ services: ['http-proxy'] }).id).toBe('web');
  });
  it('infers a workstation from rdp port or desktop OS', () => {
    expect(inferHostRole({ ports: ['3389'] }).id).toBe('workstation');
    expect(inferHostRole({ os: 'Windows 10 Pro' }).id).toBe('workstation');
  });
  it('falls back to server / host', () => {
    expect(inferHostRole({ os: 'Windows Server 2019' }).id).toBe('server');
    expect(inferHostRole({}).label).toBe('Host');
  });
});

describe('inferNodeType', () => {
  it('maps explicit role to its nodeType', () => {
    expect(inferNodeType({ role: 'domain_controller' })).toBe('dc');
  });
  it('maps inferred role buckets to node type, defaulting to server', () => {
    expect(inferNodeType({ ports: ['3389'] })).toBe('workstation');
    expect(inferNodeType({})).toBe('server');
  });
});

describe('hasAutoRoleSignals', () => {
  it('is truthy when role/domain/known tags are present', () => {
    expect(hasAutoRoleSignals({ role: 'server' })).toBeTruthy();
    expect(hasAutoRoleSignals({ domain: 'corp.local' })).toBeTruthy();
    expect(hasAutoRoleSignals({ tags: ['bloodhound'] })).toBe(true);
  });
  it('is falsy with no signals', () => {
    expect(hasAutoRoleSignals({ tags: ['random'] })).toBe(false);
  });
});

describe('getHostBadges', () => {
  it('includes role, AD and tag-derived badges', () => {
    const badges = getHostBadges({
      role: 'database',
      domain: 'corp.local',
      tags: ['high-value', 'laps', 'spn'],
    });
    const labels = badges.map(b => b.label);
    expect(labels).toContain('Database');
    expect(labels).toContain('AD');
    expect(labels).toContain('HIGH');
    expect(labels).toContain('LAPS');
    expect(labels).toContain('SPN');
  });
  it('derives Disabled badge from notes', () => {
    const labels = getHostBadges({ notes: '[BH] disabled account' }).map(b => b.label);
    expect(labels).toContain('Disabled');
  });
  it('omits role badge for plain hosts', () => {
    const labels = getHostBadges({}).map(b => b.label);
    expect(labels).not.toContain('Host');
  });
});

describe('getCredBadges', () => {
  it('builds badges from flags, tags and notes', () => {
    const labels = getCredBadges({
      is_domain: true,
      cracked: true,
      secret: 'hunter2',
      type: 'ntlm',
      tags: ['kerberoastable'],
      notes: 'Domain Admin; admincount=1',
    }).map(b => b.label);
    expect(labels).toContain('AD');
    expect(labels).toContain('Cracked');
    expect(labels).toContain('Hash');
    expect(labels).toContain('Kerberoast');
    expect(labels).toContain('DA');
    expect(labels).toContain('AdminCount');
  });
  it('labels a plaintext secret as Secret', () => {
    const labels = getCredBadges({ secret: 'pw', type: 'plain' }).map(b => b.label);
    expect(labels).toContain('Secret');
  });
});

describe('summarizeCreds', () => {
  it('counts totals, secrets, hashes, passwords and keys', () => {
    const creds = [
      { secret: 'a', type: 'ntlm' },
      { secret: 'b', type: 'hash' },
      { secret: 'c', type: 'plain' },
      { secret: 'd', type: 'key' },
      { type: 'plain' },
    ];
    expect(summarizeCreds(creds)).toEqual({
      total: 5, withSecrets: 4, hashes: 2, passwords: 1, keys: 1,
    });
  });
  it('handles an empty list', () => {
    expect(summarizeCreds()).toEqual({
      total: 0, withSecrets: 0, hashes: 0, passwords: 0, keys: 0,
    });
  });
});

describe('HOST_ROLES table', () => {
  it('exposes a consistent shape for every role', () => {
    for (const role of Object.values(HOST_ROLES)) {
      expect(role).toHaveProperty('label');
      expect(role).toHaveProperty('color');
      expect(role).toHaveProperty('nodeType');
    }
  });
});
