import { useState, useEffect, useCallback } from 'react';

export function useEntityList(fetcher, deps = []) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    fetcher()
      .then(data => setItems(Array.isArray(data) ? data : []))
      .catch(e => setError(e.message || 'Load error'))
      .finally(() => setLoading(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => { load(); }, [load]);

  return { items, loading, error, setItems, reload: load };
}
