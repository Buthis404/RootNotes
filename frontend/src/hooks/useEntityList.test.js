import { describe, it, expect, vi } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { useEntityList } from './useEntityList.js';

describe('useEntityList', () => {
  it('loads items on mount', async () => {
    const fetcher = vi.fn().mockResolvedValue([{ id: 1 }, { id: 2 }]);
    const { result } = renderHook(() => useEntityList(fetcher));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.items).toHaveLength(2);
    expect(result.current.error).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('coerces a non-array result to an empty array', async () => {
    const { result } = renderHook(() => useEntityList(() => Promise.resolve(null)));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.items).toEqual([]);
  });

  it('captures the error message on failure', async () => {
    const { result } = renderHook(() =>
      useEntityList(() => Promise.reject(new Error('nope'))));
    await waitFor(() => expect(result.current.error).toBe('nope'));
    expect(result.current.items).toEqual([]);
  });

  it('reload re-invokes the fetcher', async () => {
    const fetcher = vi.fn().mockResolvedValue([{ id: 1 }]);
    const { result } = renderHook(() => useEntityList(fetcher));
    await waitFor(() => expect(result.current.loading).toBe(false));
    await act(async () => { result.current.reload(); });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('exposes setItems for optimistic updates', async () => {
    const { result } = renderHook(() => useEntityList(() => Promise.resolve([])));
    await waitFor(() => expect(result.current.loading).toBe(false));
    act(() => result.current.setItems([{ id: 9 }]));
    expect(result.current.items).toEqual([{ id: 9 }]);
  });
});
