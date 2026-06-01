import { describe, it, expect, beforeEach } from 'vitest';
import { useAuthStore } from './useAuthStore.js';

const initial = useAuthStore.getState();

beforeEach(() => {
  useAuthStore.setState({ currentUser: null, authReady: false, isFirstRun: false });
});

describe('useAuthStore', () => {
  it('has the expected initial state', () => {
    expect(initial.currentUser).toBeNull();
    expect(initial.authReady).toBe(false);
    expect(initial.isFirstRun).toBe(false);
  });

  it('setCurrentUser stores the user', () => {
    useAuthStore.getState().setCurrentUser({ id: 1, username: 'pentester' });
    expect(useAuthStore.getState().currentUser).toEqual({ id: 1, username: 'pentester' });
  });

  it('setAuthReady and setIsFirstRun toggle flags', () => {
    useAuthStore.getState().setAuthReady(true);
    useAuthStore.getState().setIsFirstRun(true);
    expect(useAuthStore.getState().authReady).toBe(true);
    expect(useAuthStore.getState().isFirstRun).toBe(true);
  });

  it('logout clears the current user', () => {
    useAuthStore.getState().setCurrentUser({ id: 7 });
    useAuthStore.getState().logout();
    expect(useAuthStore.getState().currentUser).toBeNull();
  });
});
