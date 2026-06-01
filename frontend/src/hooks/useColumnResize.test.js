import { describe, it, expect } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useColumnResize } from './useColumnResize.js';

function mouseEvent(type, clientX) {
  return new MouseEvent(type, { clientX, bubbles: true });
}

describe('useColumnResize', () => {
  it('returns initial widths and column keys', () => {
    const { result } = renderHook(() => useColumnResize({ a: 100, b: 200 }));
    expect(result.current.widths).toEqual({ a: 100, b: 200 });
    expect(result.current.columns).toEqual(['a', 'b']);
  });

  it('updates width on drag move and clamps to a 60px minimum', () => {
    const { result } = renderHook(() => useColumnResize({ a: 100 }));

    act(() => {
      result.current.startResize('a', {
        preventDefault() {}, stopPropagation() {}, clientX: 500,
      });
    });
    act(() => { globalThis.dispatchEvent(mouseEvent('mousemove', 560)); });
    expect(result.current.widths.a).toBe(160); // 100 + (560-500)

    act(() => { globalThis.dispatchEvent(mouseEvent('mousemove', 100)); });
    expect(result.current.widths.a).toBe(60); // clamped, not 100 + (100-500)
  });

  it('stops updating after mouseup', () => {
    const { result } = renderHook(() => useColumnResize({ a: 100 }));
    act(() => {
      result.current.startResize('a', {
        preventDefault() {}, stopPropagation() {}, clientX: 0,
      });
    });
    act(() => { globalThis.dispatchEvent(mouseEvent('mousemove', 50)); });
    expect(result.current.widths.a).toBe(150);

    act(() => { globalThis.dispatchEvent(mouseEvent('mouseup', 50)); });
    act(() => { globalThis.dispatchEvent(mouseEvent('mousemove', 999)); });
    expect(result.current.widths.a).toBe(150); // unchanged after mouseup
  });
});
