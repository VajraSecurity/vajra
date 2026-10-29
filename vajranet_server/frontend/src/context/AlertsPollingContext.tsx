import {
  useState,
  useCallback,
  useMemo,
  useEffect,
  useRef,
  type ReactNode,
} from 'react';
import { useNavigate } from 'react-router-dom';
import { ALERTS_URLS, getApiUrl } from '../api/urls';
import { ALERTS_PUSH_EVENT } from '../hooks/useLiveWebSocket';
import { useToast } from './useToast';
import { AlertsPollingContext } from './useAlertsPolling';
import type { AlertsPollingContextValue } from './useAlertsPolling';

/**
 * Reconciliation-fallback interval for the alert poll.
 *
 * Real-time delivery comes from the `alerts_push` signal on /ws/live (see
 * ALERTS_PUSH_EVENT below and backend/src/websocket/liveWeb.ts), so a new
 * alert normally surfaces in ~1 RTT. The poll cannot be dropped: that push is
 * INSERT-triggered, so alert assignment and close (both UPDATEs) emit nothing.
 * The /alerts/list/my assignment toasts are therefore poll-driven, and this
 * interval is their worst-case latency.
 */
const POLL_MS = 30000;
const POLL_ROWS = 50;
/**
 * Floor between two push-triggered polls (ms).
 *
 * The server already bounds alerts_push frames to one per ALERT_DEBOUNCE_MS
 * (5/s). This is the second, independent bound: however many frames arrive, a
 * browser issues at most one extra poll pair per 1.5 s, i.e. <= ~1.4 requests
 * per second per tab in a sustained storm, versus ~0.067/s at rest (one pair
 * per POLL_MS tick). A frame that arrives inside the window is not dropped —
 * it arms a trailing catch-up poll at the end of it, so the last alert of a
 * burst is always reflected.
 */
const PUSH_POLL_MIN_INTERVAL_MS = 1500;
/** My-alerts assignment toasts stay on screen longer than the default 4s. */
const MY_ALERT_ASSIGN_TOAST_MS = 7500;

type AlertListItem = {
  id: number | string;
  host_identifier?: string;
  hostname?: string;
  unixtime?: string | number;
  assigned_at?: string | number | null;
  event_code?: string;
  metadata?: Record<string, unknown> | null;
  is_open?: boolean;
  severity?: string;
  alert_type?: string;
  os_name?: string;
};

const ALERTS_MY_LIST_URL = ALERTS_URLS.ALERTS_LIST.replace('/alerts/list', '/alerts/list/my');
const ALERTS_ASSIGNEE_URL = getApiUrl(ALERTS_URLS.ASSIGNEE);

const normalizeId = (id: number | string): string => String(id);
const toBigIntId = (id: number | string): bigint | null => {
  if (typeof id === 'number') {
    if (!Number.isFinite(id) || !Number.isInteger(id) || id < 0) return null;
    return BigInt(id);
  }
  if (typeof id === 'string' && /^\d+$/.test(id)) {
    try {
      return BigInt(id);
    } catch {
      return null;
    }
  }
  return null;
};
const getMaxAlertId = (alerts: AlertListItem[]): bigint | null => {
  let maxId: bigint | null = null;
  alerts.forEach((alert) => {
    const n = toBigIntId(alert.id);
    if (n == null) return;
    if (maxId == null || n > maxId) maxId = n;
  });
  return maxId;
};
const toEpochMs = (value: string | number | null | undefined): number | null => {
  if (value == null) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const t = Date.parse(value);
  return Number.isFinite(t) ? t : null;
};
const getMaxAssignedAtMs = (alerts: AlertListItem[]): number | null => {
  let maxTs: number | null = null;
  alerts.forEach((alert) => {
    const ts = toEpochMs(alert.assigned_at);
    if (ts == null) return;
    if (maxTs == null || ts > maxTs) maxTs = ts;
  });
  return maxTs;
};

const buildOpenListUrl = () => {
  const params = new URLSearchParams({
    rows: String(POLL_ROWS),
    pageno: '1',
    is_open: 'true',
  });
  return `${ALERTS_URLS.ALERTS_LIST}?${params.toString()}`;
};

const buildMyListUrl = () => {
  const params = new URLSearchParams({
    rows: String(POLL_ROWS),
    pageno: '1',
  });
  return `${ALERTS_MY_LIST_URL}?${params.toString()}`;
};

const pollFetchOptions: RequestInit = {
  credentials: 'include',
  cache: 'no-store',
  headers: {
    'Cache-Control': 'no-cache',
    Pragma: 'no-cache',
  },
};

export function AlertsPollingProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const { showToast } = useToast();

  const [newAlertIds, setNewAlertIds] = useState<Set<string>>(new Set());
  const [newMyAlertIds, setNewMyAlertIds] = useState<Set<string>>(new Set());
  const [dismissedSidebarIds, setDismissedSidebarIds] = useState<Set<string>>(new Set());

  const bootstrappedRef = useRef(false);
  const myBootstrappedRef = useRef(false);
  const pollingRef = useRef(false);
  /**
   * Set when a poll is requested while one is already in flight, so it is
   * re-run once rather than dropped.
   *
   * Without this, an alerts_push arriving mid-poll would be swallowed by the
   * `pollingRef.current` guard even though the in-flight request may have been
   * issued before the alert was committed — the user would then wait for the
   * next POLL_MS tick, losing the real-time guarantee in exactly the busy
   * moments it matters. It cannot loop: the flag is cleared before the re-run,
   * so it can only be set again by a genuinely new request, and every entry
   * point that sets it is itself rate-limited.
   *
   * Only the alerts_push path may set it — see poll()'s `onBusy` parameter. If
   * every caller queued, foregrounding a tab would issue two full rounds
   * instead of one, because `visibilitychange` and `focus` both fire on a tab
   * switch: the first takes the pollingRef and the second queues a re-run
   * here. Foreground and interval polls therefore drop when busy, and lose
   * nothing — the in-flight poll they collided with is about to deliver the
   * same data. A push is different: it signals a row that may have been
   * committed after the in-flight query ran, so it must re-run.
   */
  const pollAgainRef = useRef(false);
  /** Timestamp of the last push-triggered poll, for the PUSH_POLL_MIN_INTERVAL_MS floor. */
  const lastPushPollAtRef = useRef(0);
  const pushPollTimerRef = useRef<number | null>(null);
  const knownOpenIdsRef = useRef<Set<string>>(new Set());
  const knownMyIdsRef = useRef<Set<string>>(new Set());
  const interactedIdsRef = useRef<Set<string>>(new Set());
  const maxSeenOpenIdRef = useRef<bigint | null>(null);
  const maxSeenMyIdRef = useRef<bigint | null>(null);
  const maxSeenMyAssignedAtMsRef = useRef<number | null>(null);

  const clearSidebarNewCount = useCallback(() => {
    setDismissedSidebarIds((prev) => {
      const next = new Set(prev);
      newAlertIds.forEach((id) => next.add(id));
      newMyAlertIds.forEach((id) => next.add(id));
      return next;
    });
  }, [newAlertIds, newMyAlertIds]);

  // dismissedSidebarIds only needs to remember ids that are still present in
  // newAlertIds/newMyAlertIds (those are already windowed to the latest poll
  // results each tick) — once an id drops out of both it can never affect
  // sidebarNewCount again, so drop it here to keep this Set from growing
  // unbounded over a long-lived session.
  useEffect(() => {
    setDismissedSidebarIds((prev) => {
      const next = new Set<string>();
      prev.forEach((id) => {
        if (newAlertIds.has(id) || newMyAlertIds.has(id)) next.add(id);
      });
      return next.size === prev.size ? prev : next;
    });
  }, [newAlertIds, newMyAlertIds]);

  const markAlertInteracted = useCallback((id: number | string) => {
    const key = normalizeId(id);
    interactedIdsRef.current.add(key);

    setNewAlertIds((prev) => {
      const next = new Set(prev);
      next.delete(key);
      return next;
    });
    setNewMyAlertIds((prev) => {
      const next = new Set(prev);
      next.delete(key);
      return next;
    });
    setDismissedSidebarIds((prev) => {
      const next = new Set(prev);
      next.add(key);
      return next;
    });
  }, []);

  const fetchAssignedByLabel = useCallback(async (alertId: number | string): Promise<string> => {
    try {
      const params = new URLSearchParams({ id: String(alertId) });
      const res = await fetch(`${ALERTS_ASSIGNEE_URL}?${params.toString()}`, { credentials: 'include' });
      if (!res.ok) return 'Someone';
      const data = await res.json();
      const assignedBy = data?.data?.assignedBy;
      if (!assignedBy) return 'Someone';
      const name = typeof assignedBy.name === 'string' ? assignedBy.name.trim() : '';
      const email = typeof assignedBy.email === 'string' ? assignedBy.email.trim() : '';
      if (name && email) return `${name} (${email})`;
      if (name) return name;
      if (email) return email;
      if (assignedBy.id != null) return `User #${String(assignedBy.id)}`;
      return 'Someone';
    } catch {
      return 'Someone';
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    // `onBusy` controls what happens when a poll is requested while one is
    // already in flight. 'drop' is the pre-existing behaviour and the default:
    // the collision is harmless because the in-flight poll is about to return
    // the same data. Only the alerts_push path passes 'queue' — see
    // pollAgainRef's docblock for why that one case genuinely must re-run.
    const poll = async (onBusy: 'drop' | 'queue' = 'drop') => {
      // Nothing this poll produces is observable while the tab is hidden — the
      // sidebar badge and assignment toasts are only ever seen on a visible
      // tab. This provider mounts in Layout, so without the guard every
      // authenticated page would keep firing two requests per POLL_MS tick
      // forever in background tabs, on locked screens and on forgotten
      // monitors. The visibilitychange listener below fires an immediate
      // catch-up poll on foreground — sooner than the browser's background-tab
      // timer clamp (1/min) would have delivered it — so what the user
      // actually sees is unchanged.
      if (document.hidden) return;
      if (pollingRef.current) {
        if (onBusy === 'queue') pollAgainRef.current = true;
        return;
      }
      pollingRef.current = true;
      try {
        const [openRes, myRes] = await Promise.allSettled([
          fetch(buildOpenListUrl(), pollFetchOptions),
          fetch(buildMyListUrl(), pollFetchOptions),
        ]);
        if (cancelled) return;

        // Populated below when each list fetch succeeds; used at the end of the tick
        // to prune interactedIdsRef once we know an id is gone from both lists.
        let currentOpenIds: Set<string> | null = null;
        let currentMyIds: Set<string> | null = null;

        // Process open alerts independently so /list/my issues don't block sidebar/new highlight.
        if (openRes.status === 'fulfilled' && openRes.value.ok) {
          const openData = await openRes.value.json();
          if (cancelled) return;
          const openAlerts: AlertListItem[] = Array.isArray(openData?.alerts) ? openData.alerts : [];
          currentOpenIds = new Set(openAlerts.map((a) => normalizeId(a.id)));
          const currentMaxOpenId = getMaxAlertId(openAlerts);
          // Local const alias so the updater closure below narrows to Set<string>
          // instead of the outer `let ... | null` (TS doesn't retain a `let`'s
          // narrowing across a closure boundary even though it's non-null here).
          const openIdsForPrune = currentOpenIds;

          // Keep only currently visible open-alert "new" IDs.
          setNewAlertIds((prev) => {
            const next = new Set<string>();
            prev.forEach((id) => {
              if (openIdsForPrune.has(id) && !interactedIdsRef.current.has(id)) next.add(id);
            });
            // `next` is built exclusively from `prev`'s members, so equal size
            // means equal contents — reuse `prev` and let React bail out.
            // Otherwise every tick hands out a fresh Set even when nothing
            // changed, invalidating this provider's `value` memo and
            // re-rendering every consumer (Sidebar, MobileNavbar, the Alerts
            // page). Same guard the dismissedSidebarIds effect above uses.
            return next.size === prev.size ? prev : next;
          });

          if (!bootstrappedRef.current) {
            knownOpenIdsRef.current = currentOpenIds;
            maxSeenOpenIdRef.current = currentMaxOpenId;
            bootstrappedRef.current = true;
          } else {
            const unseenOpenNew: string[] = [];
            currentOpenIds.forEach((id) => {
              if (interactedIdsRef.current.has(id)) return;
              const numericId = toBigIntId(id);
              if (numericId != null && maxSeenOpenIdRef.current != null) {
                if (numericId > maxSeenOpenIdRef.current) unseenOpenNew.push(id);
                return;
              }
              if (!knownOpenIdsRef.current.has(id)) unseenOpenNew.push(id);
            });
            if (unseenOpenNew.length > 0) {
              setNewAlertIds((prev) => {
                const next = new Set(prev);
                unseenOpenNew.forEach((id) => next.add(id));
                // `next` is a superset of `prev`, so equal size means every id
                // was already present and this add is a no-op.
                return next.size === prev.size ? prev : next;
              });
            }
            knownOpenIdsRef.current = currentOpenIds;
            if (currentMaxOpenId != null) {
              if (maxSeenOpenIdRef.current == null || currentMaxOpenId > maxSeenOpenIdRef.current) {
                maxSeenOpenIdRef.current = currentMaxOpenId;
              }
            }
          }
        }

        // Process my-alerts independently so assignment toast is reliable.
        if (myRes.status === 'fulfilled' && myRes.value.ok) {
          const myData = await myRes.value.json();
          if (cancelled) return;
          const myAlerts: AlertListItem[] = Array.isArray(myData?.alerts) ? myData.alerts : [];
          currentMyIds = new Set(myAlerts.map((a) => normalizeId(a.id)));
          const currentMaxMyId = getMaxAlertId(myAlerts);
          const currentMaxMyAssignedAtMs = getMaxAssignedAtMs(myAlerts);
          // See openIdsForPrune above -- same closure-narrowing workaround.
          const myIdsForPrune = currentMyIds;

          // Keep only currently visible my-alert "new" IDs.
          setNewMyAlertIds((prev) => {
            const next = new Set<string>();
            prev.forEach((id) => {
              if (myIdsForPrune.has(id) && !interactedIdsRef.current.has(id)) next.add(id);
            });
            // See the open-alerts prune above — same subset-of-prev argument.
            return next.size === prev.size ? prev : next;
          });

          if (!myBootstrappedRef.current) {
            knownMyIdsRef.current = currentMyIds;
            maxSeenMyIdRef.current = currentMaxMyId;
            maxSeenMyAssignedAtMsRef.current = currentMaxMyAssignedAtMs;
            myBootstrappedRef.current = true;
          } else {
            const unseenMyNewAlerts: AlertListItem[] = [];
            myAlerts.forEach((alert) => {
              const id = normalizeId(alert.id);
              if (interactedIdsRef.current.has(id)) return;
              if (knownMyIdsRef.current.has(id)) return;
              const assignedAtMs = toEpochMs(alert.assigned_at);
              if (assignedAtMs != null && maxSeenMyAssignedAtMsRef.current != null) {
                if (assignedAtMs > maxSeenMyAssignedAtMsRef.current) unseenMyNewAlerts.push(alert);
                return;
              }
              const numericId = toBigIntId(id);
              if (numericId != null && maxSeenMyIdRef.current != null) {
                if (numericId > maxSeenMyIdRef.current) unseenMyNewAlerts.push(alert);
                return;
              }
              unseenMyNewAlerts.push(alert);
            });

            if (unseenMyNewAlerts.length > 0) {
              setNewMyAlertIds((prev) => {
                const next = new Set(prev);
                unseenMyNewAlerts.forEach((a) => next.add(normalizeId(a.id)));
                // See the open-alerts add above — same superset-of-prev argument.
                return next.size === prev.size ? prev : next;
              });

              if (unseenMyNewAlerts.length === 1) {
                const alert = unseenMyNewAlerts[0];
                const assignedByLabel = await fetchAssignedByLabel(alert.id);
                if (!cancelled) {
                  showToast(
                    `${assignedByLabel} assigned alert #${String(alert.id)} to you`,
                    'info',
                    {
                      duration: MY_ALERT_ASSIGN_TOAST_MS,
                      actionLabel: 'View',
                      onAction: () => {
                        markAlertInteracted(alert.id);
                        navigate('/alerts/view', {
                          state: {
                            id: alert.id,
                            severity: alert.severity,
                            title: alert.alert_type || 'Unknown Alert',
                            description: alert.event_code || '—',
                            source: alert.hostname,
                            host_identifier: alert.host_identifier,
                            hostname: alert.hostname,
                            os_name: alert.os_name,
                            unixtime: alert.unixtime,
                            is_open: alert.is_open,
                            metadata: alert.metadata,
                          },
                        });
                      },
                    },
                  );
                }
              } else if (!cancelled) {
                // Collapse bulk-assignment bursts (e.g. from a bulk-assign action) into a
                // single toast instead of stacking one toast per alert.
                showToast(
                  `${unseenMyNewAlerts.length} alerts assigned to you`,
                  'info',
                  {
                    duration: MY_ALERT_ASSIGN_TOAST_MS,
                    actionLabel: 'View',
                    onAction: () => {
                      unseenMyNewAlerts.forEach((alert) => markAlertInteracted(alert.id));
                      navigate('/alerts', { state: { initialAlertsTab: 'my' } });
                    },
                  },
                );
              }
            }

            knownMyIdsRef.current = currentMyIds;
            if (currentMaxMyId != null) {
              if (maxSeenMyIdRef.current == null || currentMaxMyId > maxSeenMyIdRef.current) {
                maxSeenMyIdRef.current = currentMaxMyId;
              }
            }
            if (currentMaxMyAssignedAtMs != null) {
              if (
                maxSeenMyAssignedAtMsRef.current == null ||
                currentMaxMyAssignedAtMs > maxSeenMyAssignedAtMsRef.current
              ) {
                maxSeenMyAssignedAtMsRef.current = currentMaxMyAssignedAtMs;
              }
            }
          }
        }

        // Once an id is gone from both currently-polled lists it can never be
        // re-checked again (alert ids aren't reused), so it no longer needs to sit
        // in interactedIdsRef. Only prune when both lists were fetched successfully
        // this tick, so a transient failure on one side never causes it to be
        // dropped from the other side's still-relevant ids.
        if (currentOpenIds && currentMyIds) {
          const stillOpen = currentOpenIds;
          const stillMine = currentMyIds;
          interactedIdsRef.current.forEach((id) => {
            if (!stillOpen.has(id) && !stillMine.has(id)) {
              interactedIdsRef.current.delete(id);
            }
          });
        }
      } catch {
        // Polling failures should be silent and retried.
      } finally {
        pollingRef.current = false;
        if (pollAgainRef.current && !cancelled) {
          pollAgainRef.current = false;
          void poll();
        }
      }
    };

    void poll();
    const id = window.setInterval(() => {
      void poll();
    }, POLL_MS);

    const onFocus = () => {
      void poll();
    };
    const onAuthChange = () => {
      void poll();
    };
    // Catch-up poll on foreground, pairing with the document.hidden guard above.
    const onVisibility = () => {
      if (!document.hidden) void poll();
    };

    /**
     * Real-time path: a new alert landed in the DB and /ws/live pushed a
     * scoped signal (LiveWebSocketContext -> ALERTS_PUSH_EVENT).
     *
     * The push deliberately does not write any alert state itself — it only
     * runs the poll above, immediately. That keeps poll() the single writer of
     * newAlertIds / newMyAlertIds / knownOpenIdsRef / interactedIdsRef /
     * toasts, so push and poll are idempotent with each other by construction:
     * a pushed alert and a polled alert are literally the same code path, the
     * high-water marks (maxSeenOpenIdRef, maxSeenMyAssignedAtMsRef) make a
     * repeat poll a no-op, and no alert can be toasted or counted twice.
     *
     * The document.hidden guard is intentionally honoured here too: nothing
     * this produces is perceivable in a hidden tab, so running it would only
     * generate push-driven background traffic. document.hidden is false for a
     * merely unfocused window, so a side-by-side or second-monitor tab still
     * gets the full real-time path, and onVisibility above fires an immediate
     * catch-up poll on foreground.
     */
    const onAlertsPush = () => {
      if (document.hidden) return;
      if (pushPollTimerRef.current != null) return; // trailing catch-up already armed
      const sinceLast = Date.now() - lastPushPollAtRef.current;
      if (sinceLast >= PUSH_POLL_MIN_INTERVAL_MS) {
        lastPushPollAtRef.current = Date.now();
        void poll('queue');
        return;
      }
      pushPollTimerRef.current = window.setTimeout(() => {
        pushPollTimerRef.current = null;
        if (cancelled || document.hidden) return;
        lastPushPollAtRef.current = Date.now();
        void poll('queue');
      }, PUSH_POLL_MIN_INTERVAL_MS - sinceLast);
    };

    window.addEventListener('focus', onFocus);
    window.addEventListener('auth-change', onAuthChange);
    window.addEventListener(ALERTS_PUSH_EVENT, onAlertsPush);
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      cancelled = true;
      window.clearInterval(id);
      if (pushPollTimerRef.current != null) {
        window.clearTimeout(pushPollTimerRef.current);
        pushPollTimerRef.current = null;
      }
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('auth-change', onAuthChange);
      window.removeEventListener(ALERTS_PUSH_EVENT, onAlertsPush);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [fetchAssignedByLabel, markAlertInteracted, navigate, showToast]);

  const sidebarNewCount = useMemo(() => {
    const unique = new Set<string>();
    newAlertIds.forEach((id) => {
      if (!dismissedSidebarIds.has(id)) unique.add(id);
    });
    newMyAlertIds.forEach((id) => {
      if (!dismissedSidebarIds.has(id)) unique.add(id);
    });
    return unique.size;
  }, [dismissedSidebarIds, newAlertIds, newMyAlertIds]);

  const value = useMemo<AlertsPollingContextValue>(
    () => ({
      newAlertIds,
      newMyAlertIds,
      sidebarNewCount,
      clearSidebarNewCount,
      markAlertInteracted,
    }),
    [
      newAlertIds,
      newMyAlertIds,
      sidebarNewCount,
      clearSidebarNewCount,
      markAlertInteracted,
    ]
  );

  return (
    <AlertsPollingContext.Provider value={value}>
      {children}
    </AlertsPollingContext.Provider>
  );
}
