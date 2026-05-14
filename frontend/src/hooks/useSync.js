import { useEffect, useRef, useCallback } from 'react';

const PING_INTERVAL = 25_000;   // send ping every 25s
const PING_TIMEOUT  = 10_000;   // close if no pong within 10s

export function useSync(pid, username, onEvent, onPresence) {
  const wsRef        = useRef(null);
  const timerRef     = useRef(null);   // reconnect timer
  const pingRef      = useRef(null);   // ping interval
  const pongRef      = useRef(null);   // pong watchdog timeout
  const deadRef      = useRef(false);
  const delayRef     = useRef(1000);
  const onEventRef   = useRef(onEvent);
  const onPresenceRef = useRef(onPresence);
  onEventRef.current  = onEvent;
  onPresenceRef.current = onPresence;

  const stopHeartbeat = useCallback(() => {
    clearInterval(pingRef.current);
    clearTimeout(pongRef.current);
    pingRef.current = null;
    pongRef.current = null;
  }, []);

  const connect = useCallback(() => {
    if (deadRef.current || !pid) return;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const token = encodeURIComponent(localStorage.getItem('rt_token') || '');
    const url = `${proto}://${location.host}/ws/${pid}?token=${token}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      delayRef.current = 1000;
      // Start heartbeat
      stopHeartbeat();
      pingRef.current = setInterval(() => {
        if (ws.readyState !== WebSocket.OPEN) return;
        try { ws.send(JSON.stringify({ type: 'ping' })); } catch { ws.close(); return; }
        // Watchdog: close if pong doesn't arrive in time
        pongRef.current = setTimeout(() => { if (!deadRef.current) ws.close(); }, PING_TIMEOUT);
      }, PING_INTERVAL);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'pong') {
          clearTimeout(pongRef.current);   // pong received — connection alive
        } else if (msg.type === 'presence') {
          onPresenceRef.current?.(msg.users);
        } else {
          onEventRef.current(msg);
        }
      } catch { }
    };

    ws.onclose = () => {
      stopHeartbeat();
      if (deadRef.current) return;
      timerRef.current = setTimeout(() => {
        delayRef.current = Math.min(delayRef.current * 2, 30000);
        connect();
      }, delayRef.current);
    };

    ws.onerror = () => ws.close();
  }, [pid, username, stopHeartbeat]);

  const send = useCallback((msg) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    }
  }, []);

  useEffect(() => {
    if (!pid) return;
    deadRef.current = false;
    delayRef.current = 1000;
    connect();

    // Reconnect immediately when tab regains visibility after a flap
    const onVisible = () => {
      if (!deadRef.current && wsRef.current?.readyState !== WebSocket.OPEN) {
        clearTimeout(timerRef.current);
        delayRef.current = 1000;
        connect();
      }
    };
    document.addEventListener('visibilitychange', onVisible);

    return () => {
      deadRef.current = true;
      stopHeartbeat();
      clearTimeout(timerRef.current);
      document.removeEventListener('visibilitychange', onVisible);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [pid, username, connect, stopHeartbeat]);

  return { send };
}
