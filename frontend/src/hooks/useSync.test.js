import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useSync, useWsConnected, isWsConnected } from './useSync.js';

let lastWs;
class FakeWebSocket {
  static OPEN = 1;
  constructor(url) {
    this.url = url;
    this.readyState = FakeWebSocket.OPEN;
    this.onopen = null; this.onmessage = null; this.onclose = null; this.onerror = null;
    this.send = vi.fn();
    this.close = vi.fn();
    lastWs = this;
  }
}

beforeEach(() => {
  vi.useFakeTimers();
  lastWs = undefined;
  globalThis.WebSocket = FakeWebSocket;
});
afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
});

describe('useSync', () => {
  it('does not open a socket without a project id', () => {
    renderHook(() => useSync(null, 'user', vi.fn()));
    expect(lastWs).toBeUndefined();
  });

  it('opens a ws to /ws/<pid> and flips connected state on open', () => {
    const { unmount } = renderHook(() => useSync('p1', 'user', vi.fn()));
    expect(lastWs.url).toMatch(/\/ws\/p1$/);
    act(() => { lastWs.onopen(); });
    expect(isWsConnected()).toBe(true);
    unmount();
  });

  it('routes presence and generic events to the right callbacks', () => {
    const onEvent = vi.fn();
    const onPresence = vi.fn();
    const { unmount } = renderHook(() => useSync('p1', 'user', onEvent, onPresence));
    act(() => { lastWs.onopen(); });

    act(() => { lastWs.onmessage({ data: JSON.stringify({ type: 'presence', users: ['a'] }) }); });
    expect(onPresence).toHaveBeenCalledWith(['a']);

    act(() => { lastWs.onmessage({ data: JSON.stringify({ type: 'host_update', id: 7 }) }); });
    expect(onEvent).toHaveBeenCalledWith({ type: 'host_update', id: 7 });

    // pong is swallowed (not delivered as an event)
    onEvent.mockClear();
    act(() => { lastWs.onmessage({ data: JSON.stringify({ type: 'pong' }) }); });
    expect(onEvent).not.toHaveBeenCalled();
    unmount();
  });

  it('ignores malformed message payloads', () => {
    const onEvent = vi.fn();
    const { unmount } = renderHook(() => useSync('p1', 'user', onEvent));
    act(() => { lastWs.onopen(); });
    act(() => { lastWs.onmessage({ data: 'not json{' }); });
    expect(onEvent).not.toHaveBeenCalled();
    unmount();
  });

  it('send() forwards a JSON message when the socket is open', () => {
    const { result, unmount } = renderHook(() => useSync('p1', 'user', vi.fn()));
    act(() => { lastWs.onopen(); });
    act(() => { result.current.send({ type: 'cursor', x: 1 }); });
    expect(lastWs.send).toHaveBeenCalledWith(JSON.stringify({ type: 'cursor', x: 1 }));
    unmount();
  });

  it('dispatches rt:auth-expired and does not reconnect on close code 4001', () => {
    const authExpired = vi.fn();
    globalThis.addEventListener('rt:auth-expired', authExpired);
    const { unmount } = renderHook(() => useSync('p1', 'user', vi.fn()));
    act(() => { lastWs.onopen(); });
    const firstWs = lastWs;
    act(() => { lastWs.onclose({ code: 4001 }); });
    expect(authExpired).toHaveBeenCalled();
    // no reconnect scheduled → still the same socket
    act(() => { vi.advanceTimersByTime(5000); });
    expect(lastWs).toBe(firstWs);
    globalThis.removeEventListener('rt:auth-expired', authExpired);
    unmount();
  });

  it('schedules a reconnect on an unexpected close', () => {
    const { unmount } = renderHook(() => useSync('p1', 'user', vi.fn()));
    act(() => { lastWs.onopen(); });
    const firstWs = lastWs;
    act(() => { lastWs.onclose({ code: 1006 }); });
    act(() => { vi.advanceTimersByTime(1000); });
    expect(lastWs).not.toBe(firstWs); // a new socket was created
    unmount();
  });
});

describe('useWsConnected', () => {
  it('reflects rt:ws-state events', () => {
    const { result } = renderHook(() => useWsConnected());
    act(() => {
      globalThis.dispatchEvent(new CustomEvent('rt:ws-state', { detail: true }));
    });
    expect(result.current).toBe(true);
    act(() => {
      globalThis.dispatchEvent(new CustomEvent('rt:ws-state', { detail: false }));
    });
    expect(result.current).toBe(false);
  });
});
