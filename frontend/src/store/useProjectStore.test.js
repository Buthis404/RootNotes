import { describe, it, expect, beforeEach } from 'vitest';
import { useProjectStore } from './useProjectStore.js';

const get = () => useProjectStore.getState();

beforeEach(() => {
  get().resetProjectData();
  useProjectStore.setState({ projects: [] });
});

describe('useProjectStore setters', () => {
  it('setHosts accepts a value', () => {
    get().setHosts([{ id: 1 }]);
    expect(get().hosts).toEqual([{ id: 1 }]);
  });

  it('setHosts accepts an updater function', () => {
    get().setHosts([{ id: 1 }]);
    get().setHosts((prev) => [...prev, { id: 2 }]);
    expect(get().hosts.map(h => h.id)).toEqual([1, 2]);
  });

  it('setProjects / setCreds / setNotes store values', () => {
    get().setProjects([{ id: 'p1' }]);
    get().setCreds([{ id: 'c1' }]);
    get().setNotes([{ id: 'n1' }]);
    expect(get().projects).toHaveLength(1);
    expect(get().creds).toHaveLength(1);
    expect(get().notes).toHaveLength(1);
  });
});

describe('useProjectStore optimistic helpers', () => {
  it('addHost / updateHost / removeHost', () => {
    get().addHost({ id: 1, ip: '10.0.0.1' });
    get().addHost({ id: 2, ip: '10.0.0.2' });
    get().updateHost(1, { os: 'Linux' });
    expect(get().hosts.find(h => h.id === 1)).toEqual({ id: 1, ip: '10.0.0.1', os: 'Linux' });
    get().removeHost(2);
    expect(get().hosts.map(h => h.id)).toEqual([1]);
  });

  it('addCred / updateCred / removeCred', () => {
    get().addCred({ id: 'c1', secret: 'x' });
    get().updateCred('c1', { cracked: true });
    expect(get().creds[0].cracked).toBe(true);
    get().removeCred('c1');
    expect(get().creds).toHaveLength(0);
  });

  it('addFinding / addLoot / addScope / addHostActivity append', () => {
    get().addFinding({ id: 'f1' });
    get().addLoot({ id: 'l1' });
    get().addScope({ id: 's1' });
    get().addHostActivity({ id: 'a1' });
    expect(get().findings).toHaveLength(1);
    expect(get().loots).toHaveLength(1);
    expect(get().scopes).toHaveLength(1);
    expect(get().hostActivities).toHaveLength(1);
  });

  it('updateNote / removeNote operate by id', () => {
    get().addNote({ id: 'n1', text: 'a' });
    get().updateNote('n1', { text: 'b' });
    expect(get().notes[0].text).toBe('b');
    get().removeNote('n1');
    expect(get().notes).toHaveLength(0);
  });
});

describe('resetProjectData', () => {
  it('clears all per-project collections but keeps projects', () => {
    useProjectStore.setState({ projects: [{ id: 'p1' }] });
    get().addHost({ id: 1 });
    get().addCred({ id: 'c1' });
    get().resetProjectData();
    expect(get().hosts).toEqual([]);
    expect(get().creds).toEqual([]);
    expect(get().projects).toHaveLength(1);
  });
});
