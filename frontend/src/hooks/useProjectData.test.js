import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

vi.mock('../api/index.ts', () => ({
  api: {
    getHosts: vi.fn(async () => [{ id: 'h' }]),
    getCreds: vi.fn(async () => [{ id: 'c' }]),
    getFindings: vi.fn(async () => [{ id: 'f' }]),
    getNotes: vi.fn(async () => [{ id: 'n' }]),
    getNetworks: vi.fn(async () => [{ id: 'net' }]),
    listJobs: vi.fn(async () => [{ id: 'j' }]),
    getScopes: vi.fn(async () => [{ id: 's' }]),
    getHostActivities: vi.fn(async () => [{ id: 'a' }]),
    getObjectives: vi.fn(async () => [{ id: 'o' }]),
    getLoots: vi.fn(async () => [{ id: 'l' }]),
  },
}));

import { api } from '../api/index.ts';
import {
  useHosts, useCreds, useFindings, useNotes, useNetworks,
  useJobs, useScopes, useHostActivities, useObjectives, useLoots,
} from './useProjectData.js';

beforeEach(() => vi.clearAllMocks());

const cases = [
  ['useHosts', useHosts, 'getHosts', 'h'],
  ['useCreds', useCreds, 'getCreds', 'c'],
  ['useNotes', useNotes, 'getNotes', 'n'],
  ['useNetworks', useNetworks, 'getNetworks', 'net'],
  ['useScopes', useScopes, 'getScopes', 's'],
  ['useHostActivities', useHostActivities, 'getHostActivities', 'a'],
  ['useObjectives', useObjectives, 'getObjectives', 'o'],
  ['useLoots', useLoots, 'getLoots', 'l'],
];

describe('useProjectData simple hooks', () => {
  it.each(cases)('%s fetches via the right api method', async (_name, hook, method, id) => {
    const { result } = renderHook(() => hook('p1'));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(api[method]).toHaveBeenCalledWith('p1');
    expect(result.current.items).toEqual([{ id }]);
  });
});

describe('useProjectData parametrised hooks', () => {
  it('useFindings passes params through', async () => {
    const { result } = renderHook(() => useFindings('p1', { severity: 'high' }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(api.getFindings).toHaveBeenCalledWith('p1', { severity: 'high' });
    expect(result.current.items).toEqual([{ id: 'f' }]);
  });

  it('useJobs passes filters through', async () => {
    const { result } = renderHook(() => useJobs('p1', { state: 'running' }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(api.listJobs).toHaveBeenCalledWith('p1', { state: 'running' });
  });
});
