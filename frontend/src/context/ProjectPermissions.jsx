import { createContext, useContext, useState, useCallback, useMemo } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';

const Ctx = createContext({ permissions: [], role: null, isLoading: false, can: () => false, isSuperAdmin: false, loadPermissions: async () => {} });

export function ProjectPermissionsProvider({ children }) {
  const [state, setState] = useState({ permissions: [], role: null, isLoading: false, isSuperAdmin: false, projectId: null });

  const loadPermissions = useCallback(async (pid) => {
    if (!pid) {
      setState({ permissions: [], role: null, isLoading: false, isSuperAdmin: false, projectId: null });
      return;
    }
    setState(s => ({ ...s, isLoading: true }));
    try {
      const data = await api.getMyProjectPermissions(pid);
      setState({ permissions: data.permissions || [], role: data.role, isSuperAdmin: data.is_super_admin || false, isLoading: false, projectId: pid });
    } catch {
      setState({ permissions: [], role: null, isLoading: false, isSuperAdmin: false, projectId: pid });
    }
  }, []);

  const can = useCallback((permission) => {
    if (state.isSuperAdmin) return true;
    return state.permissions.includes(permission);
  }, [state.permissions, state.isSuperAdmin]);

  const ctxValue = useMemo(() => ({ ...state, can, loadPermissions }), [state, can, loadPermissions]);

  return (
    <Ctx.Provider value={ctxValue}>
      {children}
    </Ctx.Provider>
  );
}

ProjectPermissionsProvider.propTypes = {
  children: PropTypes.node,
};

export const useProjectPermissions = () => useContext(Ctx);
