// frontend/src/hooks/useWebSocket.js
import { useEffect, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import { useAuth } from '../context/AuthContext.jsx';

/**
 * Connects to the backend socket.io server with JWT authentication
 * and calls onAlert for every "new_alert" event.
 */
export function useWebSocket(onAlert, tokenOverride) {
  let authContext = null;
  try {
    authContext = useAuth();
  } catch (err) {
    // If used outside AuthProvider in tests or edge cases
  }

  const token = tokenOverride || authContext?.token;
  const [connected, setConnected] = useState(false);
  const callbackRef = useRef(onAlert);
  callbackRef.current = onAlert;

  useEffect(() => {
    if (!token) {
      setConnected(false);
      return;
    }

    const socket = io('/', {
      path: '/socket.io',
      auth: { token },
    });

    socket.on('connect', () => setConnected(true));
    socket.on('disconnect', () => setConnected(false));
    socket.on('connect_error', (err) => {
      console.warn('[ws] connection error:', err.message);
      setConnected(false);
    });
    socket.on('new_alert', (alert) => callbackRef.current?.(alert));

    return () => {
      socket.disconnect();
    };
  }, [token]);

  return { connected };
}
