import { useEffect, useRef, useCallback } from 'react';

export function useSync(pid, username, onEvent, onPresence) {
  const wsRef = useRef(null);
  const timerRef = useRef(null);
  const deadRef = useRef(false);
  const delayRef = useRef(1000);
  const onEventRef = useRef(onEvent);
  const onPresenceRef = useRef(onPresence);
  onEventRef.current = onEvent;
  onPresenceRef.current = onPresence;

  const connect = useCallback(() => {
    if (deadRef.current || !pid) return;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const token = encodeURIComponent(localStorage.getItem('rt_token') || '');
    const url = `${proto}://${location.host}/ws/${pid}?token=${token}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => { delayRef.current = 1000; };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'presence') {
          onPresenceRef.current?.(msg.users);
        } else {
          onEventRef.current(msg);
        }
      } catch { }
    };

    ws.onclose = () => {
      if (deadRef.current) return;
      timerRef.current = setTimeout(() => {
        delayRef.current = Math.min(delayRef.current * 2, 30000);
        connect();
      }, delayRef.current);
    };

    ws.onerror = () => ws.close();
  }, [pid, username]);

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
    return () => {
      deadRef.current = true;
      clearTimeout(timerRef.current);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [pid, username, connect]);

  return { send };
}
