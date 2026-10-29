/**
 * WebSocket hook for live dashboard – real-time node status & alert notifications.
 * Connects to /ws/live (cookie-based JWT auth, same as useNodeWebSocket).
 *
 * StrictMode-safe: handles double mount/unmount cycles without leaking
 * connections or generating spurious error logs.
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { NODES_WS_BASE } from '../api/urls';
/*  Types matching the backend LiveData shape                          */

export interface NodeStatus {
  online: number;
  offline: number;
  total: number;
  onlineNodeHostIdentifier: string[];
  agentOnline: string[];
}

export interface AlertStatus {
  new: number;
}

export interface LiveData {
  nodeStatus: NodeStatus;
  alertStatus: AlertStatus;
}

/** Accumulated ClamAV alert state per host, built from clamav_push messages. */
export interface ClamavAlertEntry {
  /** Total detections received since page load. */
  count: number;
  /** ISO-8601 timestamp of the most recent detection. */
  lastAlertAt: string;
}

/** Firewall push signal per host — reference change triggers a refetch in consumers. */
export interface FirewallStatusPushEntry {
  lastPushAt: string;
}

/** Patch Management (osupdate_result) push signal per host — same "reference
 * change = refetch trigger" contract as FirewallStatusPushEntry. */
export interface OsupdatePushEntry {
  lastPushAt: string;
}

/** Windows maintained-app install/uninstall job completion (patch_job_push)
 * push signal per host — unrelated to OsupdatePushEntry above (that's the
 * Linux osupdate feature); same "reference change = refetch trigger"
 * contract. */
export interface WindowsPatchPushEntry {
  lastPushAt: string;
}

/**
 * Payload of an `alerts_push` frame — the real-time new-alert signal.
 *
 * Emitted by liveWeb.ts when the Postgres `new_alert` NOTIFY fires (see
 * backend/src/migrations/add_alerts_notify_trigger.sql), already filtered to
 * hosts inside this client's node-group scope.
 *
 * This is a signal, never a data source. It says "new alerts landed"; the
 * alert list, the sidebar badge, the "new" row highlight and the assignment
 * toasts are all still derived exclusively from the scoped /alerts/list poll
 * in AlertsPollingContext, which the signal simply makes run sooner. Keeping
 * one writer for that state is what makes push and poll idempotent with each
 * other — no duplicate toasts, no double-counting, no ordering to reconcile.
 */
export interface AlertsPushDetail {
  /** New alerts in this flush that are visible to this client. Always >= 1. */
  count: number;
  /** Affected hosts, clipped to the server's per-frame cap. */
  hostIdentifiers: string[];
  /** True when `hostIdentifiers` was clipped — `count` is still exact. */
  truncated: boolean;
  /** Server-side ISO-8601 timestamp of the flush. */
  at: string;
}

/**
 * Window event carrying an AlertsPushDetail, dispatched by
 * LiveWebSocketContext and consumed by AlertsPollingContext.
 *
 * A DOM event rather than a context field on purpose. Adding `alertsPush` to
 * LiveWebSocketContext's value would invalidate its useMemo on every push and
 * re-render every `useLiveData()` subscriber app-wide — exactly the
 * whole-tree re-render the `reuseUnchanged` machinery below exists to prevent.
 * It also keeps AlertsPollingProvider independent of where it sits relative to
 * LiveWebSocketProvider. LiveWebSocketContext already bridges its auth failure
 * out the same way (`auth-change`), which AlertsPollingContext already listens
 * for, so this follows an established path in these two files.
 */
export const ALERTS_PUSH_EVENT = 'alerts-push';

/**
 * Raw payload received over the /ws/live socket. It's either a push
 * notification (error / clamav_push / clamav_status_push / firewall_status_push,
 * discriminated loosely by `rid`) or a full `LiveData` snapshot — hence the
 * `Partial<LiveData>` intersection for the latter case.
 */
interface LiveWsMessage extends Partial<LiveData> {
  error?: string;
  rid?: string;
  host_identifier?: string;
  response?: unknown;
  /** alerts_push only — see AlertsPushDetail. */
  count?: number;
  host_identifiers?: string[];
  truncated?: boolean;
  at?: string;
}

/** Single entry of a `clamav_push` message's `response` array. */
interface ClamavPushAlert {
  detected_at?: string;
}

/**
 * Structural reuse for snapshot frames.
 *
 * The server re-broadcasts a full {nodeStatus, alertStatus} snapshot for any
 * of three reasons (liveWeb.ts): the node totals changed, the group signature
 * changed, or a new alert landed. Usually only one of those sub-objects has
 * actually moved, but a plain `setData(parsed)` hands every consumer a
 * brand-new `data`, `data.nodeStatus` and `data.alertStatus` object each time.
 * LiveWebSocketContext's value useMemo keys on `data`, so one host flipping
 * online would re-render every `useLiveData()` subscriber in the app —
 * including the per-row usePatchPushFlow hooks on the patch tables — and
 * invalidate every downstream `useMemo([nodeStatus])`/`[liveData]` cache even
 * when the field they read was byte-identical.
 *
 * Returning the previous object when nothing changed (and reusing the
 * unchanged half otherwise) makes those caches actually hold. Any field this
 * comparison doesn't know about is carried over from the incoming frame, so
 * an unrecognised extra key can never be silently dropped or staled.
 */
function sameStringList(a: string[] | undefined, b: string[] | undefined): boolean {
  if (a === b) return true;
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function sameNodeStatus(a: NodeStatus | undefined, b: NodeStatus | undefined): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return (
    a.online === b.online &&
    a.offline === b.offline &&
    a.total === b.total &&
    sameStringList(a.onlineNodeHostIdentifier, b.onlineNodeHostIdentifier) &&
    sameStringList(a.agentOnline, b.agentOnline)
  );
}

function reuseUnchanged(prev: LiveData | null, next: LiveData): LiveData {
  if (!prev) return next;
  const nodeSame = sameNodeStatus(prev.nodeStatus, next.nodeStatus);
  const alertSame = prev.alertStatus === next.alertStatus || prev.alertStatus?.new === next.alertStatus?.new;
  if (nodeSame && alertSame) return prev;
  const merged = { ...next };
  if (nodeSame) merged.nodeStatus = prev.nodeStatus;
  if (alertSame) merged.alertStatus = prev.alertStatus;
  return merged;
}

export interface UseLiveWebSocketReturn {
  /** Whether the WebSocket is currently connected */
  connected: boolean;
  /** Latest live data from the server (null until first message) */
  data: LiveData | null;
  /**
   * Map of hostId → ClamAV alert entry, populated in real-time from
   * clamav_push messages forwarded through the live-dashboard channel.
   */
  clamavAlertsByHost: Map<string, ClamavAlertEntry>;
  /**
   * Map of hostId → last firewall_status_push timestamp.
   * Reference changes act as a refetch trigger in consumers.
   */
  firewallStatusPushByHost: Map<string, FirewallStatusPushEntry>;
  /**
   * Map of hostId → last osupdate_result (Patch Management) push timestamp.
   * Reference changes act as a refetch trigger in consumers.
   */
  osupdatePushByHost: Map<string, OsupdatePushEntry>;
  /**
   * Map of hostId → last patch_job_push (Windows maintained-app install/
   * uninstall) push timestamp. Reference changes act as a refetch trigger in
   * consumers.
   */
  windowsPatchPushByHost: Map<string, WindowsPatchPushEntry>;
  /** Imperatively close the connection */
  disconnect: () => void;
  /** Imperatively reconnect */
  reconnect: () => void;
}

/*  Hook                                                               */

/**
 * Connects to the live WebSocket endpoint and keeps the latest
 * nodeStatus / alertStatus in component state.
 *
 * @param enabled     – pass `false` to suppress the connection (e.g. before login).
 * @param onAuthFailed – called when the server rejects the connection with a 401.
 *                       Use this to clear stale auth state and redirect to login.
 * @param onAlertsPush – called on every `alerts_push` frame. Delivered as a
 *                       callback rather than React state so a burst of alerts
 *                       cannot re-render the entire `useLiveData()` subtree;
 *                       see ALERTS_PUSH_EVENT above.
 */
export const useLiveWebSocket = (
  enabled: boolean = true,
  onAuthFailed?: () => void,
  onAlertsPush?: (detail: AlertsPushDetail) => void
): UseLiveWebSocketReturn => {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const [data, setData] = useState<LiveData | null>(null);
  const [clamavAlertsByHost, setClamavAlertsByHost] = useState<Map<string, ClamavAlertEntry>>(new Map());
  const [firewallStatusPushByHost, setFirewallStatusPushByHost] = useState<Map<string, FirewallStatusPushEntry>>(new Map());
  const [osupdatePushByHost, setOsupdatePushByHost] = useState<Map<string, OsupdatePushEntry>>(new Map());
  const [windowsPatchPushByHost, setWindowsPatchPushByHost] = useState<Map<string, WindowsPatchPushEntry>>(new Map());
  const [reconnectKey, setReconnectKey] = useState(0);
  const mountedRef = useRef(false);

  // Keep onAuthFailed in a ref so the effect closure always calls the latest
  // version without needing it in the dependency array (avoids re-connecting
  // every time the parent re-renders with a new callback reference).
  const onAuthFailedRef = useRef(onAuthFailed);
  useEffect(() => { onAuthFailedRef.current = onAuthFailed; }, [onAuthFailed]);

  // Same ref indirection as onAuthFailed: keeps the socket out of the effect's
  // dependency array so a new callback identity never tears down the connection.
  const onAlertsPushRef = useRef(onAlertsPush);
  useEffect(() => { onAlertsPushRef.current = onAlertsPush; }, [onAlertsPush]);

  // `enabled` flips false on logout (LiveWebSocketContext ties it to
  // isAuthenticated) and true again on the next login, but LiveWebSocketProvider
  // itself is mounted once above <Routes> and never remounts across that
  // transition — so without this, the previous account's last-known
  // nodeStatus/alertStatus snapshot and the four push Maps (keyed by that
  // account's host_identifiers) would sit in this state and render briefly
  // (Maps: indefinitely, since they're purely additive) for whoever logs in
  // next on the same tab/browser. Only reacts to a genuine enabled
  // transition, not the reconnect()-driven reconnectKey bump, so a normal
  // reconnect never loses in-flight live data.
  const prevEnabledRef = useRef(enabled);
  useEffect(() => {
    if (prevEnabledRef.current && !enabled) {
      setData(null);
      setClamavAlertsByHost(new Map());
      setFirewallStatusPushByHost(new Map());
      setOsupdatePushByHost(new Map());
      setWindowsPatchPushByHost(new Map());
    }
    prevEnabledRef.current = enabled;
  }, [enabled]);

  /*  Core effect – owns the WebSocket lifecycle                       */
  useEffect(() => {
    if (!enabled) return;

    mountedRef.current = true;

    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let intentionallyClosed = false;
    let connectionWasOpen = false;
    let reconnectAttempt = 0;
    const MAX_RECONNECT_DELAY = 30_000; // cap at 30 seconds
    const BASE_RECONNECT_DELAY = 3_000; // start at 3 seconds

    const openConnection = () => {
      if (!mountedRef.current) return;

      try {
        ws = new WebSocket(`${NODES_WS_BASE}/live`);
        wsRef.current = ws;

        ws.onopen = () => {
          if (!mountedRef.current) {
            ws?.close();
            return;
          }
          console.log('[LiveWS] Connected');
          connectionWasOpen = true;
          setConnected(true);
          reconnectAttempt = 0; // reset backoff on successful connection

          if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
          }
        };

        ws.onmessage = (event) => {
          if (!mountedRef.current) return;
          try {
            const parsed = JSON.parse(event.data) as LiveWsMessage;

            // Detect server-side auth errors sent as JSON messages
            if (parsed.error) {
              console.error('[LiveWS] Server error:', parsed.error);
              intentionallyClosed = true;
              ws?.close();
              onAuthFailedRef.current?.();
              return;
            }

            // ClamAV pushes forwarded from node.ts via broadcastToLiveClients.
            //   clamav_push        — new detections landed in the alerts table
            //   clamav_status_push — daemon health / signature version changed
            // Either way the DB now holds fresher state than the page: bump the
            // Map (consumers use the reference change as a refetch trigger —
            // the Map is a signal, not the display source of truth).
            if ((parsed.rid === 'clamav_push' || parsed.rid === 'clamav_status_push') && parsed.host_identifier) {
              const hostId = String(parsed.host_identifier);
              try {
                let added = 0;
                let lastAt = new Date().toISOString();
                if (parsed.rid === 'clamav_push') {
                  const alerts: ClamavPushAlert[] = typeof parsed.response === 'string'
                    ? JSON.parse(parsed.response)
                    : (parsed.response ?? []);
                  if (Array.isArray(alerts) && alerts.length > 0) {
                    added = alerts.length;
                    lastAt = alerts[alerts.length - 1]?.detected_at ?? lastAt;
                  }
                }
                setClamavAlertsByHost((prev) => {
                  const next = new Map(prev);
                  const existing = next.get(hostId) ?? { count: 0, lastAlertAt: '' };
                  next.set(hostId, { count: existing.count + added, lastAlertAt: lastAt });
                  return next;
                });
              } catch { /* malformed ClamAV push — ignore */ }
              return;
            }

            // Firewall status push — bump the map so consumers can refetch.
            if (parsed.rid === 'firewall_status_push' && parsed.host_identifier) {
              const hostId = String(parsed.host_identifier);
              setFirewallStatusPushByHost((prev) => {
                const next = new Map(prev);
                next.set(hostId, { lastPushAt: new Date().toISOString() });
                return next;
              });
              return;
            }

            // Patch Management result push — bump the map so consumers (the
            // patch wizard's check/review steps, the job history view) can
            // refetch instead of polling.
            if (parsed.rid === 'osupdate_result' && parsed.host_identifier) {
              const hostId = String(parsed.host_identifier);
              setOsupdatePushByHost((prev) => {
                const next = new Map(prev);
                next.set(hostId, { lastPushAt: new Date().toISOString() });
                return next;
              });
              return;
            }

            // Windows maintained-app install/uninstall job completion push —
            // unrelated to osupdate_result above (that's the Linux osupdate
            // feature). Bump the map so the Windows tab's Jobs view can refetch.
            if (parsed.rid === 'patch_job_push' && parsed.host_identifier) {
              const hostId = String(parsed.host_identifier);
              setWindowsPatchPushByHost((prev) => {
                const next = new Map(prev);
                next.set(hostId, { lastPushAt: new Date().toISOString() });
                return next;
              });
              return;
            }

            // Real-time new-alert signal. Carries no alert data by design —
            // it only tells AlertsPollingContext to run its normal scoped
            // /alerts/list poll now instead of waiting for the next tick, so
            // there is exactly one writer of alert UI state and push/poll can
            // never disagree. Server-side this frame is already filtered to
            // hosts inside this client's node-group scope.
            if (parsed.rid === 'alerts_push') {
              const count = typeof parsed.count === 'number' && parsed.count > 0 ? parsed.count : 1;
              onAlertsPushRef.current?.({
                count,
                hostIdentifiers: Array.isArray(parsed.host_identifiers) ? parsed.host_identifiers : [],
                truncated: parsed.truncated === true,
                at: typeof parsed.at === 'string' ? parsed.at : new Date().toISOString(),
              });
              return;
            }

            // Snapshot frames are the only ones that carry nodeStatus/alertStatus,
            // and they never carry a `rid`. Every agent push forwarded by
            // broadcastToLiveClients() (backend/src/websocket/node.ts) does carry one.
            //
            // Anything with a `rid` that wasn't handled above is a push type this
            // client doesn't consume yet — it must be ignored, not passed to
            // setData(). Falling through would replace the whole snapshot with a
            // payload that has no nodeStatus, so `data?.nodeStatus ?? null` goes
            // null and every live counter (Total/Online/Offline Devices) reads 0 —
            // and stays 0, because status broadcasts are change-gated
            // (isNodeStatusEqual in liveWeb.ts) so a stable fleet never sends a
            // replacement snapshot. Hence a guard on the whole class rather than on
            // individual rids: the server forwards more rids than this file
            // handles, and that gap is easy to reintroduce.
            if (parsed.rid) return;

            setData((prev) => reuseUnchanged(prev, parsed as LiveData));
          } catch (err) {
            console.error('[LiveWS] Message parse error:', err);
          }
        };

        ws.onerror = () => {
          if (mountedRef.current) {
            console.warn('[LiveWS] Connection error');
          }
        };

        ws.onclose = (event) => {
          if (!mountedRef.current || intentionallyClosed) return;

          // Auth rejection: backend destroyed the socket during WS upgrade
          // (HTTP 401). Browser reports code=1006, wasClean=false, and the
          // connection was never opened. Stop reconnecting to avoid an
          // infinite retry loop and notify the caller to clear auth state.
          if (!connectionWasOpen && event.code === 1006 && !event.wasClean) {
            console.warn('[LiveWS] Auth rejected – stopping reconnect');
            intentionallyClosed = true;
            setConnected(false);
            wsRef.current = null;
            onAuthFailedRef.current?.();
            return;
          }

          console.log(
            `[LiveWS] Disconnected (code: ${event.code}, reason: ${event.reason})`
          );
          setConnected(false);
          wsRef.current = null;

          // Auto-reconnect with exponential backoff (3s, 6s, 12s, ... capped at 30s)
          if (!reconnectTimer) {
            const delay = Math.min(BASE_RECONNECT_DELAY * Math.pow(2, reconnectAttempt), MAX_RECONNECT_DELAY);
            reconnectAttempt++;
            console.log(`[LiveWS] Reconnecting in ${delay / 1000}s (attempt ${reconnectAttempt})`);
            reconnectTimer = setTimeout(() => {
              reconnectTimer = null;
              openConnection();
            }, delay);
          }
        };
      } catch (error) {
        console.error('[LiveWS] Failed to create connection:', error);
        if (mountedRef.current) setConnected(false);
      }
    };

    openConnection();

    return () => {
      mountedRef.current = false;
      intentionallyClosed = true;

      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }

      if (ws) {
        ws.onmessage = null;
        ws.onerror = null;
        ws.onclose = null;

        if (ws.readyState === WebSocket.CONNECTING) {
          const staleWs = ws;
          staleWs.onopen = () => {
            staleWs.close();
          };
        } else {
          ws.onopen = null;
          ws.close();
        }
        ws = null;
      }
      wsRef.current = null;
      setConnected(false);
    };
  // reconnectKey is intentionally included to force a clean reconnect cycle
  // when reconnect() is called imperatively.
  }, [enabled, reconnectKey]);

  /*  Imperative helpers                                               */

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnected(false);
    mountedRef.current = false;
  }, []);

  /** Tear down the current connection and open a fresh one. */
  const reconnect = useCallback(() => {
    setReconnectKey(k => k + 1);
  }, []);

  return { connected, data, clamavAlertsByHost, firewallStatusPushByHost, osupdatePushByHost, windowsPatchPushByHost, disconnect, reconnect };
};
