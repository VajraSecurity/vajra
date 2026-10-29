/**
 * WebSocket hook for node agent communication.
 * Uses cookie-based authentication (access_token cookie is sent automatically
 * by the browser for same-site WebSocket connections).
 *
 * StrictMode-safe: handles double mount/unmount cycles without leaking
 * connections or generating spurious error logs.
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { NODES_WS_BASE } from '../api/urls';
import { secureUUID } from '../lib/utils';

interface WebSocketMessage {
  type: 'agent' | 'osquery';
  params?: {
    agent?: 'port' | 'ip' | 'networkManager' | 'status' | 'driver' | 'powershell' | 'message' | 'removableDevice' | 'bluetooth' | 'wifi' | 'clamav';
    action?: 'allow' | 'block' | 'unblock' | 'terminate' | 'run' | 'message' | 'enable' | 'disable'
      // clamav agent actions (Linux)
      | 'ping' | 'scan' | 'contscan' | 'stats' | 'reload' | 'version';
    arg1?: string;
    arg2?: string;
    arg3?: string;
    /**
     * Human-entered reason, used for audit trail logging.
     * Backend also accepts this via `arg3`.
     */
    reason?: string;
    /** Powershell command key(s) — selects a predefined script on the agent (e.g. bluetooth enable/disable). */
    command_keys?: string[];
  };
  host_identifier: string;
  rid?: string;
  // Response fields
  status?: 'success' | 'error';
  message?: string;
  data?: unknown;
  response?: unknown;
}

interface UseNodeWebSocketReturn {
  connected: boolean;
  sendMessage: (
    message: Omit<WebSocketMessage, 'rid'>,
    options?: { timeoutMs?: number }
  ) => Promise<WebSocketMessage>;
  lastMessage: WebSocketMessage | null;
  disconnect: () => void;
  reconnect: () => void;
}

/**
 * Custom hook for WebSocket communication with node agents
 * @param hostIdentifier - The host identifier of the node
 * @param enabled - Whether to establish connection (default: true)
 */
export const useNodeWebSocket = (
  hostIdentifier: string,
  enabled: boolean = true
): UseNodeWebSocketReturn => {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const pendingRequests = useRef<Map<string, { resolve: (response: WebSocketMessage) => void; reject: (reason: Error) => void }>>(new Map());
  const reconnectTimeoutRef = useRef<number | null>(null);
  const [reconnectKey, setReconnectKey] = useState(0);
  /** Tracks whether the owning effect is still mounted. Prevents the async
   *  onclose/onerror handlers of a stale WebSocket (killed during React
   *  StrictMode unmount) from triggering reconnection or state updates. */
  const mountedRef = useRef(false);

  const rejectAllPending = useCallback((reason: string): void => {
    for (const [, { reject }] of pendingRequests.current) {
      reject(new Error(reason));
    }
    pendingRequests.current.clear();
  }, []);

  const sendMessage = useCallback((
    message: Omit<WebSocketMessage, 'rid'>,
    options?: { timeoutMs?: number }
  ): Promise<WebSocketMessage> => {
    return new Promise((resolve, reject) => {
      if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
        reject(new Error('WebSocket not connected'));
        return;
      }

      // secureUUID() (crypto.randomUUID(), falling back to crypto.getRandomValues()
      // on insecure-context/HTTP deployments — see lib/utils.ts): this rid is a live
      // routing key the backend stores (ws:rid:{rid} in Redis) to deliver the
      // response back to this socket — it should be as unguessable as the backend's
      // own generator for the same purpose (websocket/utils.ts's generateUniqueID,
      // crypto.randomBytes(8)) on every deployment, not just HTTPS ones.
      const rid = `${Date.now()}-${secureUUID()}`;
      const fullMessage = { ...message, rid };

      // Store resolver and rejecter for response
      pendingRequests.current.set(rid, { resolve, reject });

      try {
        wsRef.current.send(JSON.stringify(fullMessage));
      } catch (error) {
        pendingRequests.current.delete(rid);
        reject(error);
        return;
      }

      const timeoutMs = Math.max(1000, options?.timeoutMs ?? 15000);
      // Timeout guard (default 15 s; caller can override for slower agent jobs)
      setTimeout(() => {
        if (pendingRequests.current.has(rid)) {
          pendingRequests.current.delete(rid);
          reject(new Error(`Request timeout - no response from agent within ${timeoutMs}ms`));
        }
      }, timeoutMs);
    });
  }, []);

  // Single effect that owns the WebSocket lifecycle.
  //
  // Depends only on `hostIdentifier` and `enabled` (both primitives) so
  // it will not re-fire on every render unlike the previous version that
  // depended on `connect`/`disconnect` callbacks.
  useEffect(() => {
    // Nothing to do when disabled or host unknown
    if (!enabled || !hostIdentifier) return;

    mountedRef.current = true;

    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    /** Set to true once we call close() ourselves (cleanup or manual
     *  disconnect). Prevents the resulting onclose from re-triggering
     *  a reconnection attempt. */
    let intentionallyClosed = false;
    let reconnectAttempt = 0;
    const BASE_RECONNECT_DELAY = 3_000;  // start at 3 s
    const MAX_RECONNECT_DELAY  = 30_000; // cap at 30 s

    const openConnection = () => {
      // Guard: if the effect was already cleaned up, don't open
      if (!mountedRef.current) return;

      try {
        ws = new WebSocket(`${NODES_WS_BASE}/ui`);
        wsRef.current = ws;

        let connectionWasOpen = false;

        ws.onopen = () => {
          if (!mountedRef.current) { ws?.close(); return; }
          console.log(`[WebSocket] Connected for host: ${hostIdentifier}`);
          connectionWasOpen = true;
          reconnectAttempt = 0; // reset backoff on successful connect
          setConnected(true);

          // Clear any pending reconnection timer
          if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
        };

        ws.onmessage = (event) => {
          if (!mountedRef.current) return;
          try {
            const data = JSON.parse(event.data);
            setLastMessage(data);

            // Resolve/reject pending request by rid FIRST — even on error responses.
            // Backend sends { error: 'Agent not connected', rid } which must
            // immediately reject the in-flight promise, not leave it dangling.
            if (data.rid && pendingRequests.current.has(data.rid)) {
              const { resolve, reject } = pendingRequests.current.get(data.rid)!;
              pendingRequests.current.delete(data.rid);
              if (data.error) {
                reject(new Error(data.error));
              } else {
                resolve(data);
              }
              return;
            }

            // Non-rid errors (auth errors, etc.)
            if (data.error) {
              console.error('[WebSocket] Server error:', data.error);
              if (data.error.includes('Authentication') || data.error.includes('token')) {
                // Don't mark intentionallyClosed here: that flag makes onclose
                // bail out before setConnected(false)/wsRef cleanup/reconnect
                // scheduling run. Close normally so onclose treats this like
                // any other drop and self-heals with the usual backoff retry.
                ws?.close();
              }
            }
          } catch (error) {
            console.error('[WebSocket] Message parse error:', error);
          }
        };

        ws.onerror = () => {
          // Only log if this is the active (mounted) socket.
          // StrictMode cleanup closes the socket before it connects,
          // which fires onerror – suppress that noise.
          if (mountedRef.current) {
            console.warn('[WebSocket] Connection error');
          }
        };

        ws.onclose = (event) => {
          // If the component unmounted or we closed on purpose, do nothing.
          if (!mountedRef.current || intentionallyClosed) {
            return;
          }

          // Auth rejection: backend destroyed the socket during WS upgrade
          // (HTTP 401). Browser reports code=1006, wasClean=false, and the
          // connection was never opened. Stop reconnecting to avoid a loop.
          if (!connectionWasOpen && event.code === 1006 && !event.wasClean) {
            console.warn('[WebSocket] Auth rejected – stopping reconnect');
            intentionallyClosed = true;
            setConnected(false);
            wsRef.current = null;
            return;
          }

          console.log(`[WebSocket] Disconnected (code: ${event.code}, reason: ${event.reason})`);
          setConnected(false);
          wsRef.current = null;
          rejectAllPending('WebSocket disconnected');

          // Auto-reconnect with exponential backoff (3s, 6s, 12s … capped at 30s),
          // matching the useLiveWebSocket pattern.
          if (!reconnectTimer) {
            const delay = Math.min(BASE_RECONNECT_DELAY * Math.pow(2, reconnectAttempt), MAX_RECONNECT_DELAY);
            reconnectAttempt++;
            console.log(`[WebSocket] Reconnecting in ${delay / 1000}s (attempt ${reconnectAttempt})`);
            reconnectTimer = setTimeout(() => {
              reconnectTimer = null;
              openConnection();
            }, delay);
          }
        };
      } catch (error) {
        console.error('[WebSocket] Failed to create connection:', error);
        if (mountedRef.current) setConnected(false);
      }
    };

    openConnection();

    // Cleanup: runs on unmount or when deps change
    return () => {
      mountedRef.current = false;
      intentionallyClosed = true;
      rejectAllPending('WebSocket closed');

      if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
      if (reconnectTimeoutRef.current) { clearTimeout(reconnectTimeoutRef.current); reconnectTimeoutRef.current = null; }

      if (ws) {
        // Remove event handlers before closing to prevent noisy
        // "closed before connection established" errors from StrictMode.
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;

        // If the socket hasn't connected yet (CONNECTING state), wait for
        // it to open and then close it. Closing during CONNECTING triggers
        // the browser warning "WebSocket is closed before the connection
        // is established".
        if (ws.readyState === WebSocket.CONNECTING) {
          const staleWs = ws;
          staleWs.onopen = () => { staleWs.close(); };
        } else {
          ws.onopen = null;
          ws.close();
        }
        ws = null;
      }
      wsRef.current = null;
      setConnected(false);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostIdentifier, enabled, reconnectKey]);

  // Public imperative helpers
  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    rejectAllPending('Disconnected');
    if (wsRef.current) {
      wsRef.current.onclose = null; // prevent reconnect loop
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnected(false);
    mountedRef.current = false;
  }, [rejectAllPending]);

  /** Increment reconnectKey to force the effect to tear down and re-open a fresh connection. */
  const reconnect = useCallback(() => {
    setReconnectKey(k => k + 1);
  }, []);

  return { connected, sendMessage, lastMessage, disconnect, reconnect };
};
