import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';

// Mock the api re-export that useEntityCRUD imports.
vi.mock('../api.js', () => {
  return {
    api: {
      createProject: vi.fn(async (d) => ({ id: 'p1', ...d })),
      deleteProject: vi.fn(async () => null),
      createLoot: vi.fn(async (d) => ({ id: 'l1', ...d })),
      updateLoot: vi.fn(async (id, p) => ({ id, ...p })),
      deleteLoot: vi.fn(async () => null),
      createScope: vi.fn(async (d) => ({ id: 's1', ...d })),
      updateScope: vi.fn(async (id, p) => ({ id, ...p })),
      deleteScope: vi.fn(async () => null),
      createHostActivity: vi.fn(async (d) => ({ id: 'a1', ...d })),
      updateHostActivity: vi.fn(async (id, p) => ({ id, ...p })),
      deleteHostActivity: vi.fn(async () => null),
      createObjective: vi.fn(async (d) => ({ id: 'o1', ...d })),
      updateObjective: vi.fn(async (id, p) => ({ id, ...p })),
      deleteObjective: vi.fn(async () => null),
      createFinding: vi.fn(async (d) => ({ id: 'f1', ...d })),
      updateFinding: vi.fn(async (id, p) => ({ id, ...p })),
      deleteFinding: vi.fn(async () => null),
      createNote: vi.fn(async (d) => ({ id: 'n1', ...d })),
      updateNote: vi.fn(async (id, p) => ({ id, ...p })),
      deleteNote: vi.fn(async () => null),
      createHost: vi.fn(async (d) => ({ id: 'h1', ...d })),
      updateHost: vi.fn(async (id, p) => ({ id, ...p })),
      deleteHost: vi.fn(async () => null),
      createCred: vi.fn(async (d) => ({ id: 'c1', ...d })),
      updateCred: vi.fn(async (id, p) => ({ id, ...p })),
      deleteCred: vi.fn(async () => null),
      createNetwork: vi.fn(async (d) => ({ id: 'net1', ...d })),
      updateNetwork: vi.fn(async (id, p) => ({ id, ...p })),
      deleteNetwork: vi.fn(async () => null),
      createAttackPath: vi.fn(async (d) => ({ id: 'ap1', ...d })),
      updateAttackPath: vi.fn(async (id, p) => ({ id, ...p })),
      deleteAttackPath: vi.fn(async () => null),
      createAttackStep: vi.fn(async (d) => ({ id: 'as1', ...d })),
      updateAttackStep: vi.fn(async (id, p) => ({ id, ...p })),
      deleteAttackStep: vi.fn(async () => null),
    },
  };
});

import { api } from '../api.js';
import { useProjectStore } from '../store/useProjectStore.js';
import { useEntityCRUD } from './useEntityCRUD.js';

const store = () => useProjectStore.getState();

function setup(opts = {}) {
  return renderHook(() => useEntityCRUD(opts));
}

beforeEach(() => {
  vi.clearAllMocks();
  store().resetProjectData();
  useProjectStore.setState({ projects: [] });
});

describe('useEntityCRUD — projects', () => {
  it('addProject calls api and selects the new project', async () => {
    const setSelectedProject = vi.fn();
    const { result } = setup({ setSelectedProject });
    await act(async () => { await result.current.addProject({ name: 'P' }); });
    expect(api.createProject).toHaveBeenCalledWith({ name: 'P' });
    expect(store().projects).toHaveLength(1);
    expect(setSelectedProject).toHaveBeenCalledWith('p1');
  });

  it('deleteProject removes the project and its child entities', async () => {
    useProjectStore.setState({
      projects: [{ id: 'p1' }, { id: 'p2' }],
      hosts: [{ id: 'h', pid: 'p1' }, { id: 'h2', pid: 'p2' }],
      creds: [{ id: 'c', pid: 'p1' }],
    });
    const setSelectedProject = vi.fn();
    const { result } = setup({ selectedProject: 'p1', setSelectedProject });
    await act(async () => { await result.current.deleteProject('p1'); });
    expect(api.deleteProject).toHaveBeenCalledWith('p1');
    expect(store().projects.map(p => p.id)).toEqual(['p2']);
    expect(store().hosts.map(h => h.id)).toEqual(['h2']);
    expect(store().creds).toHaveLength(0);
    expect(setSelectedProject).toHaveBeenCalledWith('p2');
  });
});

describe('useEntityCRUD — generic entities', () => {
  it('addLoot prepends and dedupes', async () => {
    const { result } = setup();
    await act(async () => { await result.current.addLoot({ value: 'x' }); });
    expect(store().loots[0].id).toBe('l1');
    // adding the same id again is a no-op
    api.createLoot.mockResolvedValueOnce({ id: 'l1', value: 'dup' });
    await act(async () => { await result.current.addLoot({ value: 'dup' }); });
    expect(store().loots).toHaveLength(1);
  });

  it('addObjective / updateObjective / deleteObjective roundtrip', async () => {
    const { result } = setup();
    await act(async () => { await result.current.addObjective({ title: 'T' }); });
    expect(store().objectives[0]).toMatchObject({ id: 'o1', title: 'T' });
    await act(async () => { await result.current.updateObjective('o1', { status: 'done' }); });
    expect(store().objectives[0].status).toBe('done');
    await act(async () => { await result.current.deleteObjective('o1'); });
    expect(store().objectives).toHaveLength(0);
  });

  it('addScope dedupes by id', async () => {
    const { result } = setup();
    await act(async () => { await result.current.addScope({ cidr: '10/8' }); });
    api.createScope.mockResolvedValueOnce({ id: 's1' });
    await act(async () => { await result.current.addScope({ cidr: '10/8' }); });
    expect(store().scopes).toHaveLength(1);
  });
});

describe('useEntityCRUD — optimistic rollback', () => {
  it('deleteFinding rolls back when the api call fails', async () => {
    useProjectStore.setState({ findings: [{ id: 'f1' }, { id: 'f2' }] });
    api.deleteFinding.mockRejectedValueOnce(new Error('500'));
    const { result } = setup();
    await act(async () => { await result.current.deleteFinding('f1'); });
    // restored after failure
    expect(store().findings.map(f => f.id).sort()).toEqual(['f1', 'f2']);
  });

  it('deleteCred removes optimistically on success', async () => {
    useProjectStore.setState({ creds: [{ id: 'c1' }, { id: 'c2' }] });
    const { result } = setup();
    await act(async () => { await result.current.deleteCred('c1'); });
    expect(store().creds.map(c => c.id)).toEqual(['c2']);
  });
});

describe('useEntityCRUD — hosts & networks', () => {
  it('updateHost propagates host changes into matching network nodes', async () => {
    useProjectStore.setState({
      hosts: [{ id: 'h1', ip: '10.0.0.1', hostname: 'old' }],
      networks: [{ id: 'net1', nodes: [{ id: 'nd', ip: '10.0.0.1', label: '10.0.0.1' }], edges: [] }],
    });
    api.updateHost.mockResolvedValueOnce({
      id: 'h1', ip: '10.0.0.1', hostname: 'dc01', status: 'pwned', role: 'domain_controller',
    });
    const { result } = setup();
    await act(async () => { await result.current.updateHost('h1', { status: 'pwned' }); });
    const node = store().networks[0].nodes[0];
    expect(node.host_id).toBe('h1');
    expect(node.label).toBe('dc01');
    expect(node.status).toBe('pwned');
  });

  it('deleteHost removes the host and its network nodes/edges', async () => {
    useProjectStore.setState({
      hosts: [{ id: 'h1', ip: '10.0.0.1' }],
      networks: [{
        id: 'net1',
        nodes: [{ id: 'n1', ip: '10.0.0.1' }, { id: 'n2', ip: '10.0.0.2' }],
        edges: [{ from: 'n1', to: 'n2' }],
      }],
    });
    const { result } = setup();
    await act(async () => { await result.current.deleteHost('h1'); });
    expect(store().hosts).toHaveLength(0);
    expect(store().networks[0].nodes.map(n => n.id)).toEqual(['n2']);
    expect(store().networks[0].edges).toHaveLength(0);
  });

  it('syncHostByIp updates a host matched by project + ip', async () => {
    useProjectStore.setState({ hosts: [{ id: 'h1', pid: 'p1', ip: '10.0.0.9' }] });
    api.updateHost.mockResolvedValueOnce({ id: 'h1', pid: 'p1', ip: '10.0.0.9', os: 'Linux' });
    const { result } = setup({ selectedProject: 'p1' });
    let ret;
    await act(async () => { ret = await result.current.syncHostByIp('10.0.0.9', { os: 'Linux' }); });
    expect(ret.os).toBe('Linux');
    expect(store().hosts[0].os).toBe('Linux');
  });

  it('syncHostByIp returns null when no host matches', async () => {
    const { result } = setup({ selectedProject: 'p1' });
    let ret;
    await act(async () => { ret = await result.current.syncHostByIp('1.1.1.1', {}); });
    expect(ret).toBeNull();
    expect(api.updateHost).not.toHaveBeenCalled();
  });
});

describe('useEntityCRUD — debounced network save', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('updateNetwork updates the store immediately and persists after 600ms', async () => {
    useProjectStore.setState({ networks: [{ id: 'net1', name: 'old' }] });
    const { result } = setup();
    act(() => { result.current.updateNetwork('net1', { name: 'new' }); });
    expect(store().networks[0].name).toBe('new');
    expect(api.updateNetwork).not.toHaveBeenCalled();
    await act(async () => { await vi.advanceTimersByTimeAsync(600); });
    expect(api.updateNetwork).toHaveBeenCalledWith('net1', { name: 'new' });
  });
});
