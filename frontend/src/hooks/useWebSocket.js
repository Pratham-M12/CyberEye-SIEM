import { useEffect, useRef, useState } from 'react';
import { io } from 'socket.io-client';

/**
 * Connects to the backend's socket.io server and calls onAlert for every
 * "new_alert" event pushed by the rule engine. Also exposes a live
 * connection status so the header can show a real/stale indicator.
 */
export function useWebSocket(onAlert) {
  const [connected, setConnected] = useState(false);
  const callbackRef = useRef(onAlert);
  callbackRef.current = onAlert;

  useEffect(() => {
    const socket = io('/', { path: '/socket.io' });

    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('new_alert', (alert) => callbackRef.current?.(alert));

    return () => {
      socket.disconnect();
    };
  }, []);

  return { connected };
}
