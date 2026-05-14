import { create } from 'zustand';

export const useAuthStore = create((set) => ({
  currentUser: null,
  authReady: false,
  isFirstRun: false,

  setCurrentUser: (user) => set({ currentUser: user }),
  setAuthReady: (ready) => set({ authReady: ready }),
  setIsFirstRun: (val) => set({ isFirstRun: val }),
  logout: () => {
    set({ currentUser: null });
  },
}));
