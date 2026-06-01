import { useEntityList } from './useEntityList.js';
import { api } from '../api/index.ts';

/**
 * Domain hooks for per-project entity data.
 *
 * Each hook wraps useEntityList with the correct fetcher so views can
 * fetch data independently without importing api directly.
 *
 * Usage:
 *   const { items: hosts, loading, reload } = useHosts(pid);
 */

export function useHosts(pid) {
  return useEntityList(() => api.getHosts(pid), [pid]);
}

export function useCreds(pid) {
  return useEntityList(() => api.getCreds(pid), [pid]);
}

export function useFindings(pid, params = {}) {
  const key = JSON.stringify(params);
  return useEntityList(() => api.getFindings(pid, params), [pid, key]);
}

export function useNotes(pid) {
  return useEntityList(() => api.getNotes(pid), [pid]);
}

export function useNetworks(pid) {
  return useEntityList(() => api.getNetworks(pid), [pid]);
}

export function useJobs(pid, filters = {}) {
  const key = JSON.stringify(filters);
  return useEntityList(() => api.listJobs(pid, filters), [pid, key]);
}

export function useScopes(pid) {
  return useEntityList(() => api.getScopes(pid), [pid]);
}

export function useHostActivities(pid) {
  return useEntityList(() => api.getHostActivities(pid), [pid]);
}

export function useObjectives(pid) {
  return useEntityList(() => api.getObjectives(pid), [pid]);
}

export function useLoots(pid) {
  return useEntityList(() => api.getLoots(pid), [pid]);
}
