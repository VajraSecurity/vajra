/**
 * Live dashboard WebSocket: node status and alert notifications. Broadcasts a
 * LiveData payload ({ nodeStatus, alertStatus }) to connected UI clients on
 * change, scoped per client's node groups.
 *
 * Node status is event-driven: an agent connect/disconnect in node.ts writes
 * agent_online and emits on the nodeStatusEvents bus, which debounces into
 * getNodesStatus(). The LIVE_NODES_POLL_INTERVAL_MS safety-net poll exists for
 * the one case the event path cannot cover — a node killed without a clean WS
 * close leaves agent_online true, so no event fires and only last_seen drift
 * reveals it.
 *
 * Alerts arrive as pg NOTIFY on PG_ALERT_CHANNEL from
 * alerts_insert_notify_trigger (migrations/add_alerts_notify_trigger.sql), with
 * payload '<id>|<host_identifier>'. The frame pushed to browsers is a refetch
 * signal, not data: the client re-runs its own scoped /alerts/list poll, which
 * stays the single source of truth, so a push can never duplicate or reorder
 * anything. The poll is also the reconciliation fallback when the socket is
 * down or the tab is hidden.
 *
 * Nothing here shares resources with the agent path: /ws/ext
 * has its own WebSocketServer instance (see index.ts), and the LISTEN
 * connection is a dedicated raw pg Client rather than the TypeORM pool agent
 * ingest uses, so an alert storm cannot contend with agent queries.
 *
 * stopLiveWeb() cleans up all timers, listeners, and clients.
 */

import type { LiveData, NodeStatus, AlertStatus } from './types';
import { dbSourceConnection, dbRawSourceConnectionSecondary } from '../index';
import { isNodeStatusEqual } from './utils';
import { onNodeStatusChange, offNodeStatusChange, emitNodeStatusChange } from './nodeStatusEvents';
import { getRedisClient } from '../utils/redisClient';
import { getWsJwtPayload, type ReqLike } from '../utils/wsAuth';
import { getUserNodeScope, scopeGroupIds, type NodeScope } from '../utils/nodeScope';
import { getLogger } from '../utils/logger';
import {
  ALERT_DEBOUNCE_MS,
  NODE_ONLINE_SECONDS_LIMIT,
  NODE_STATUS_DEBOUNCE_MS,
  LIVE_SETUP_NOTIFICATIONS_DELAY_MS,
  LIVE_NODES_POLL_INTERVAL_MS,
  LIVE_ALERT_RESET_INTERVAL_MS,
  LIVE_SCOPE_REFRESH_INTERVAL_MS,
  LIVE_ALERT_BROADCAST_CAP,
  ALERT_WINDOW_HOST_CAP,
  ALERT_PUSH_HOSTS_PER_FRAME_CAP,
  ALERT_PUSH_RID,
  WS_REDIS_EXT_PREFIX,
  PG_ALERT_CHANNEL,
} from '../consts';

const logger = getLogger('websocket.liveWeb');

export type LiveWebWsLike = {
  send: (data: string) => void;
  on: (e: string, fn: (...args: unknown[]) => void) => void;
  /** ws library readyState: 0=CONNECTING 1=OPEN 2=CLOSING 3=CLOSED */
  readyState?: number;
};

// Shared state

/**
 * Per-client state for a connected UI socket.
 *
 * userId is retained so the scope can be re-resolved while the socket is open
 * (refreshClientScopes below); it is null only when the connection carried no
 * resolvable session, which already means an empty scope that cannot widen.
 */
type UiClientState = { userId: number | null; scope: NodeScope };

/**
 * Every connected UI client, with the node-group scope its payloads are built
 * from. Resolved at connect and refreshed on LIVE_SCOPE_REFRESH_INTERVAL_MS.
 */
const CLIENTS_UI = new Map<LiveWebWsLike, UiClientState>();

const UNRESTRICTED_SCOPE_KEY = '*';

/** Groups a client's scope into a cache key so identically-scoped clients share one computed payload per broadcast. */
function scopeKey(scope: NodeScope): string {
  return scope.unrestricted ? UNRESTRICTED_SCOPE_KEY : [...scopeGroupIds(scope)].sort().join(',');
}

const data: LiveData = {
  nodeStatus: {
    online: 0,
    offline: 0,
    total: 0,
    onlineNodeHostIdentifier: [],
    agentOnline: [],
  },
  alertStatus: {
    new: 0,
  },
};

/** Canonical (unscoped) per-node rows from the last poll — used to derive per-client scoped views. */
let canonicalNodeRows: NodeRow[] = [];
/**
 * host_identifier -> owner_group_id (or undefined if the host is unassigned).
 * A node has exactly one owning group, so this is a plain scalar map, kept in
 * sync with canonicalNodeRows on every poll — O(1) "is this host mine" lookups
 * with no per-check database round trip.
 */
let hostOwnerGroupIndex = new Map<string, string>();

/**
 * Exposes the same host->group index node.ts's nodeUi push-broadcast uses to
 * scope agent-initiated push messages (defender_push, usb_device_push, etc.)
 * to only the UI clients whose group scope includes the sending host — kept
 * here rather than duplicated, since this module already polls/maintains it.
 */
export function getHostOwnerGroupId(hostIdentifier: string): string | undefined {
  return hostOwnerGroupIndex.get(hostIdentifier);
}

/**
 * Start of the current "new alerts" counting window (epoch seconds), advanced
 * every LIVE_ALERT_RESET_INTERVAL_MS. data.alertStatus.new is the eager
 * fleet-wide count and is only correct for an unrestricted caller; a scoped
 * caller's count is queried on demand from this window boundary by
 * computeScopedAlertStatus, because a per-process counter cannot attribute a
 * NOTIFY to a group.
 */
let alertWindowStartEpoch = Math.floor(Date.now() / 1000);

/** Trailing-edge debounce handle for the full-snapshot alert broadcast (scheduleAlertBroadcast). */
let alertBroadcastTimeout: ReturnType<typeof setTimeout> | null = null;

/** Log-once latch for the fleet-wide counter hitting its display cap. Reset alongside alertWindowStartEpoch. */
let alertCapWarned = false;
/** Log-once latch for ALERT_WINDOW_HOST_CAP, so silently dropping hosts from scoped counts stays visible. */
let alertHostCapWarned = false;
/** Log-once latch for a NOTIFY with no host_identifier. Separate from alertHostCapWarned so neither warning suppresses the other. */
let alertUnknownHostWarned = false;

/**
 * host_identifier -> new alerts seen since the last LIVE_ALERT_RESET_INTERVAL_MS
 * reset. Source for each client's scoped alertStatus.new. Keyed by host so
 * computeScopedAlertStatus() can filter through hostOwnerGroupIndex the same
 * way computeScopedNodeStatus() does; a single global counter would leak
 * other groups' alert activity to a Group Admin.
 */
let alertWindowByHost = new Map<string, number>();
/** host_identifier -> new alerts since the last alerts_push flush (the delta a frame reports). Same keying, shorter lifetime. */
let alertPendingByHost = new Map<string, number>();
/**
 * Alerts in the current window / pending flush whose NOTIFY carried no
 * host_identifier and so cannot be attributed to a group.
 *
 * Fails closed: only unrestricted clients see these. A scoped client missing a
 * push is recoverable via the /alerts/list poll; broadcasting an unattributable
 * alert to every group would not be. Every known insert site supplies
 * host_identifier, so this should stay at 0 and the warn below fires if not.
 */
let alertWindowUnknownHost = 0;
let alertPendingUnknownHost = 0;

/** Monotonic wall-clock of the last alerts_push flush, for the leading-edge rate limiter. */
let alertLastFlushAt = 0;
let alertFlushTimeout: ReturnType<typeof setTimeout> | null = null;

let notificationRetryTimeout: ReturnType<typeof setTimeout> | null = null;
let nodeStatusDebounceTimeout: ReturnType<typeof setTimeout> | null = null;

/**
 * Set to true by stopLiveWeb(). Prevents any new retries from being scheduled
 * after the process has begun shutting down.
 */
let liveWebStopped = false;

// Broadcast

/** Computes the NodeStatus a given scope should see, from the canonical (unscoped) rows. */
function computeScopedNodeStatus(scope: NodeScope): NodeStatus {
  if (scope.unrestricted) return data.nodeStatus;

  const groupIds = new Set(scopeGroupIds(scope));
  const next: NodeStatus = { online: 0, offline: 0, total: 0, onlineNodeHostIdentifier: [], agentOnline: [] };
  const currentTime = Math.floor(Date.now() / 1000);

  for (const row of canonicalNodeRows) {
    const ownerGroupId = hostOwnerGroupIndex.get(row.host_identifier);
    // Unassigned nodes are hidden from scoped users — same fail-safe default as the REST endpoints.
    if (!ownerGroupId || !groupIds.has(ownerGroupId)) continue;

    next.total++;
    if (currentTime - Number(row.last_seen) < NODE_ONLINE_SECONDS_LIMIT) {
      next.online++;
      next.onlineNodeHostIdentifier.push(row.host_identifier);
    } else {
      next.offline++;
    }
    if (row.agent_online) next.agentOnline.push(row.host_identifier);
  }

  return next;
}

/**
 * Computes the AlertStatus a given scope should see: unrestricted callers get
 * the eager fleet-wide counter, scoped callers a live count of alerts in their
 * own groups since the current window started. Fails closed to 0 on a missing
 * DB connection or query error rather than falling back to the fleet-wide count.
 *
 * Scoping must stay in sync with alert_list.ts: the LEFT JOIN covers the usual
 * host_identifier -> owner_group_id ownership, OR'd with the alert's own
 * group_id for alert types that have no `nodes` row (the Scan Scheduler's
 * consolidated unmanaged-hosts alert). An inner join alone would undercount,
 * showing a badge lower than the alert list the user can actually open.
 * scopeGroupIds (view-level) is right here because this is a read, not a write.
 */
async function computeScopedAlertStatus(scope: NodeScope): Promise<AlertStatus> {
  if (scope.unrestricted) return data.alertStatus;

  const groupIds = [...scopeGroupIds(scope)];
  if (groupIds.length === 0) return { new: 0 };

  const ds = dbSourceConnection();
  if (!ds || ds.length < 2) return { new: 0 };

  try {
    const rows = await ds[1].query(
      `SELECT count(*)::int AS c
           FROM alerts a
           LEFT JOIN nodes n
             ON n.host_identifier = a.host_identifier
          WHERE a.unixtime >= $1
            AND (n.owner_group_id = ANY($2::text[]) OR a.group_id = ANY($2::text[]))`,
      [alertWindowStartEpoch, groupIds],
    );
    return { new: Number(rows?.[0]?.c ?? 0) };
  } catch (err) {
    logger.warn({ err }, 'Failed to compute scoped alert status, failing closed to 0');
    return { new: 0 };
  }
}

/**
 * Push the current data snapshot to every connected UI client, scoped to each
 * client's node-group access. Dead sockets that throw on send are silently
 * pruned from the map. Clients sharing a scope share one computed+serialized
 * payload per broadcast rather than recomputing per client.
 */
async function broadcastAll(): Promise<void> {
  if (CLIENTS_UI.size === 0) return;
  const dead: LiveWebWsLike[] = [];
  const payloadByScopeKey = new Map<string, Promise<string>>();
  let staleReadyState = 0;

  for (const [client, { scope }] of CLIENTS_UI) {
    // Skip sockets that are CLOSING (2) or CLOSED (3) — send() on these either
    // throws or silently drops the message, leaving the client stuck on stale data.
    if (client.readyState !== undefined && client.readyState !== 1 /* OPEN */) {
      dead.push(client);
      staleReadyState++;
      continue;
    }
    const key = scopeKey(scope);
    let payloadPromise = payloadByScopeKey.get(key);
    if (payloadPromise === undefined) {
      payloadPromise = computeScopedAlertStatus(scope).then((alertStatus) =>
        JSON.stringify({ nodeStatus: computeScopedNodeStatus(scope), alertStatus }));
      payloadByScopeKey.set(key, payloadPromise);
    }
    try {
      client.send(await payloadPromise);
    } catch (err) {
      // scopeKey is the only client identity available at this layer.
      logger.debug({ err, scopeKey: key }, 'Broadcast send error, pruning dead client');
      dead.push(client);
    }
  }
  for (const d of dead) CLIENTS_UI.delete(d);
  if (staleReadyState > 0) {
    logger.warn({ staleReadyState, remaining: CLIENTS_UI.size }, 'Pruned clients with stale readyState during broadcast');
  }
}

// Alert push

/**
 * Build the alerts_push frame a given scope should receive for this flush, or
 * null when nothing in the flush is visible to that scope (in which case the
 * client is sent nothing at all — an out-of-group alert must not even reveal
 * that *something* happened).
 *
 * Cost: O(pending hosts), bounded by ALERT_WINDOW_HOST_CAP, once per distinct
 * scope per flush.
 */
function buildAlertPushFrame(
  scope: NodeScope,
  pendingByHost: Map<string, number>,
  pendingUnknown: number,
): string | null {
  let count = 0;
  let distinctHosts = 0;
  const hosts: string[] = [];

  const take = (host: string, n: number): void => {
    count += n;
    distinctHosts++;
    if (hosts.length < ALERT_PUSH_HOSTS_PER_FRAME_CAP) hosts.push(host);
  };

  if (scope.unrestricted) {
    count = pendingUnknown;
    for (const [host, n] of pendingByHost) take(host, n);
  } else {
    const groupIds = new Set(scopeGroupIds(scope));
    for (const [host, n] of pendingByHost) {
      const ownerGroupId = hostOwnerGroupIndex.get(host);
      // Unassigned hosts are invisible to scoped users — same fail-safe
      // default as computeScopedNodeStatus() and the REST endpoints.
      if (!ownerGroupId || !groupIds.has(ownerGroupId)) continue;
      take(host, n);
    }
  }

  if (count === 0) return null;

  // Shape follows the existing rid-tagged push convention on this channel.
  // The frame is a SIGNAL, not data: the browser re-runs its own scoped
  // /alerts/list fetch on receipt, so the fields here only need to say "new
  // alerts exist, and roughly where" — never the alert contents.
  return JSON.stringify({
    rid: ALERT_PUSH_RID,
    count,
    host_identifiers: hosts,
    truncated: distinctHosts > hosts.length,
    at: new Date().toISOString(),
  });
}

/**
 * Send one alerts_push frame per distinct in-scope client cohort and clear the
 * pending delta.
 *
 * Deliberately does not call broadcastAll(): a new alert must not force a
 * full-snapshot re-send to every connected client, and must not touch
 * broadcastToLiveClients() (which node.ts calls from the agent path).
 */
function flushAlertPush(): void {
  alertLastFlushAt = Date.now();

  // Swap out the pending delta first so a NOTIFY arriving mid-flush accumulates
  // into the next bucket instead of being counted twice or lost.
  const pendingByHost = alertPendingByHost;
  const pendingUnknown = alertPendingUnknownHost;
  alertPendingByHost = new Map();
  alertPendingUnknownHost = 0;

  if (pendingByHost.size === 0 && pendingUnknown === 0) return;
  if (CLIENTS_UI.size === 0) return;

  // null is a real memoised value here ("this cohort gets nothing"), so the
  // cache is probed with .has() rather than an undefined check.
  const frameByScopeKey = new Map<string, string | null>();
  const dead: LiveWebWsLike[] = [];
  let staleReadyState = 0;

  for (const [client, { scope }] of CLIENTS_UI) {
    if (client.readyState !== undefined && client.readyState !== 1 /* OPEN */) {
      dead.push(client);
      staleReadyState++;
      continue;
    }
    const key = scopeKey(scope);
    let frame: string | null;
    if (frameByScopeKey.has(key)) {
      frame = frameByScopeKey.get(key) ?? null;
    } else {
      frame = buildAlertPushFrame(scope, pendingByHost, pendingUnknown);
      frameByScopeKey.set(key, frame);
    }
    if (frame === null) continue;
    try {
      client.send(frame);
    } catch (err) {
      logger.debug({ err, scopeKey: key }, 'Alert push send error, pruning dead client');
      dead.push(client);
    }
  }

  for (const d of dead) CLIENTS_UI.delete(d);
  if (staleReadyState > 0) {
    logger.warn({ staleReadyState, remaining: CLIENTS_UI.size }, 'Pruned clients with stale readyState during alert push');
  }
}

/**
 * Rate-limit alert pushes to at most one flush per ALERT_DEBOUNCE_MS, with a
 * LEADING edge.
 *
 * The leading edge is what makes an isolated alert feel real-time: it flushes
 * in the same tick the NOTIFY arrives instead of paying the full debounce a
 * pure trailing implementation would always add. Bursts fall back to the
 * trailing edge and coalesce into one frame.
 *
 * This is the storm bound. However many NOTIFYs arrive, at most one flush
 * happens per ALERT_DEBOUNCE_MS, each doing O(scopes x pending hosts) work plus
 * one send per in-scope client — synchronous, but bounded, so it cannot stall
 * the event loop the agent sockets share.
 */
function scheduleAlertPush(): void {
  if (liveWebStopped) return;
  if (alertFlushTimeout != null) return; // a trailing flush is already armed

  const sinceLast = Date.now() - alertLastFlushAt;
  if (sinceLast >= ALERT_DEBOUNCE_MS) {
    flushAlertPush();
    return;
  }
  alertFlushTimeout = setTimeout(() => {
    alertFlushTimeout = null;
    flushAlertPush();
  }, ALERT_DEBOUNCE_MS - sinceLast);
}

/**
 * Record one NOTIFY from the alerts_insert_notify_trigger.
 *
 * Payload is '<alerts.id>|<alerts.host_identifier>' (see
 * migrations/add_alerts_notify_trigger.sql). Parsed with indexOf/slice rather
 * than split() or JSON.parse() so a storm allocates as little as possible on
 * the shared event loop.
 */
function recordAlertNotification(payload: string | undefined): void {
  let id = '';
  let host = '';
  if (payload) {
    const sep = payload.indexOf('|');
    if (sep < 0) {
      id = payload;
    } else {
      id = payload.slice(0, sep);
      host = payload.slice(sep + 1);
    }
  }

  if (host) {
    // Only admit a NEW key while under the cap; existing keys always increment,
    // so the map size is hard-bounded but no host already being tracked ever
    // silently stops counting mid-window.
    if (alertWindowByHost.has(host) || alertWindowByHost.size < ALERT_WINDOW_HOST_CAP) {
      alertWindowByHost.set(host, (alertWindowByHost.get(host) ?? 0) + 1);
    } else if (!alertHostCapWarned) {
      alertHostCapWarned = true;
      logger.warn(
        { cap: ALERT_WINDOW_HOST_CAP, alertId: id },
        'Alert window host cap reached, further unseen hosts this window are excluded from scoped alert counts',
      );
    }
    if (alertPendingByHost.has(host) || alertPendingByHost.size < ALERT_WINDOW_HOST_CAP) {
      alertPendingByHost.set(host, (alertPendingByHost.get(host) ?? 0) + 1);
    }
  } else {
    alertWindowUnknownHost++;
    alertPendingUnknownHost++;
    if (!alertUnknownHostWarned) {
      alertUnknownHostWarned = true;
      logger.warn(
        { alertId: id || undefined, payload },
        'new_alert notification carried no host_identifier; it can only be pushed to unrestricted clients (scoped clients rely on the /alerts/list poll for it)',
      );
    }
  }

  // Bounded at LIVE_ALERT_BROADCAST_CAP so the snapshot value stays
  // min(count, CAP). computeScopedAlertStatus() hands unrestricted clients this
  // object directly, so the bound has to hold at write time.
  if (data.alertStatus.new < LIVE_ALERT_BROADCAST_CAP) {
    data.alertStatus.new++;
  }
  if (data.alertStatus.new >= LIVE_ALERT_BROADCAST_CAP && !alertCapWarned) {
    alertCapWarned = true;
    logger.warn(
      { cap: LIVE_ALERT_BROADCAST_CAP, current: data.alertStatus.new },
      'Alert window cap reached, snapshot alertStatus.new is clamped for the remainder of this window (real-time pushes continue unthrottled beyond the debounce rate limit)',
    );
  }

  scheduleAlertPush();
}

function scheduleAlertBroadcast(): void {
  // Same shutdown guard as scheduleAlertPush and notifyNodeStatusChange: a
  // NOTIFY arriving during shutdown must not re-arm a cleared timer.
  if (liveWebStopped) return;
  if (alertBroadcastTimeout != null) return;
  alertBroadcastTimeout = setTimeout(() => {
    alertBroadcastTimeout = null;
    broadcastAll().catch((err) => logger.error({ err }, 'Alert broadcast failed'));
  }, ALERT_DEBOUNCE_MS);
}

// Event-driven node status

/**
 * Called via the nodeStatusEvents bus after every UpdateAgentStatus() DB write
 * (agent connect / disconnect in node.ts).
 *
 * Uses a trailing-edge debounce so a rapid burst of connect/disconnect events
 * (e.g. fleet restart) collapses into a single DB query + broadcast cycle.
 * Registered with onNodeStatusChange() inside startLiveWeb().
 */
function notifyNodeStatusChange(): void {
  if (liveWebStopped) return;
  if (nodeStatusDebounceTimeout != null) {
    clearTimeout(nodeStatusDebounceTimeout);
  }
  nodeStatusDebounceTimeout = setTimeout(() => {
    nodeStatusDebounceTimeout = null;
    getNodesStatus();
  }, NODE_STATUS_DEBOUNCE_MS);
}

// Node status polling

type NodeRow = { host_identifier: string; last_seen: number; agent_online: boolean; owner_group_id: string | null };

/** One-time first-poll diagnostic flag — logs the raw query result once so
 *  startup issues are visible in the server log without flooding output. */
let _firstPollLogged = false;

/** Detects group-assignment changes between polls (see broadcast guard below). */
let lastGroupSignature = '';

/**
 * Query the fleet DB for node status and broadcast only when the result differs
 * from the cached state, to avoid redundant WebSocket traffic.
 *
 * Nodes live in the fleet (secondary) data source, ds[1] — the same one the
 * LISTEN setup uses. TypeORM's query() resolves with the rows array itself for
 * pg, not a { rows } wrapper.
 */
function getNodesStatus(): void {
  const ds = dbSourceConnection();
  if (!ds || ds.length < 2) {
    if (!_firstPollLogged) {
      _firstPollLogged = true;
      logger.warn(
        { dbSourceCount: ds ? ds.length : null },
        'getNodesStatus: dbSourceConnection() returned fewer than 2 data sources',
      );
    }
    return;
  }
  const db = ds[1]; // fleet / secondary DB

  db.query('SELECT host_identifier, last_seen, agent_online, owner_group_id FROM nodes ORDER BY host_identifier')
    .then((rows: unknown) => {
      // One-time diagnostic: log the raw result on the very first poll.
      if (!_firstPollLogged) {
        _firstPollLogged = true;
        logger.debug(
          {
            resultType: typeof rows,
            isArray: Array.isArray(rows),
            length: Array.isArray(rows) ? (rows as unknown[]).length : 'N/A',
            sample: JSON.stringify(Array.isArray(rows) ? (rows as unknown[]).slice(0, 2) : rows).slice(0, 300),
          },
          'First nodes poll result',
        );
      }

      // TypeORM returns the rows array directly for pg. Guard against any
      // unexpected shape so a driver change doesn't cause a silent regression.
      if (!Array.isArray(rows)) {
        logger.warn({ resultType: typeof rows }, 'Unexpected result shape from nodes query, expected array');
        return;
      }

      const typedRows = rows as NodeRow[];
      canonicalNodeRows = typedRows;
      hostOwnerGroupIndex = new Map(
        typedRows
          .filter((row): row is NodeRow & { owner_group_id: string } => !!row.owner_group_id)
          .map((row) => [row.host_identifier, row.owner_group_id]),
      );
      const currentTime = Math.floor(Date.now() / 1000);

      const next: NodeStatus = {
        online: 0,
        offline: 0,
        total: typedRows.length,
        onlineNodeHostIdentifier: [],
        agentOnline: [],
      };

      for (let i = 0; i < typedRows.length; i++) {
        const row = typedRows[i];
        if (currentTime - Number(row.last_seen) < NODE_ONLINE_SECONDS_LIMIT) {
          next.online++;
          next.onlineNodeHostIdentifier.push(row.host_identifier);
        } else {
          next.offline++;
        }
        if (row.agent_online) {
          next.agentOnline.push(row.host_identifier);
        }
      }

      // Stale agent_online cleanup. A node whose extension process died without
      // sending a WS close frame never runs nodeExt.on('close'), so
      // UpdateAgentStatus(false) is never called and agent_online stays true.
      //
      // Redis presence, not last_seen, is the authority for clearing it: the
      // ws:ext:{hostId} key exists exactly while the extension is connected, so
      // a live extension with a slow osquery schedule is left alone while an
      // uncleanly disconnected one is cleared even if osquery is still fresh.
      const redis = getRedisClient();
      if (redis) {
        const staleCandidates = typedRows.filter((row) => row.agent_online);
        if (staleCandidates.length > 0) {
          // One MGET rather than a GET per candidate: this runs against every
          // agent_online node on every safety-net poll. MGET preserves key
          // order, so the null-vs-present decision per host is unchanged.
          //
          // Cleared hosts are aggregated into one summary line because a Redis
          // flush or restart can turn the whole fleet stale at once. Per-host
          // failures still log individually — each needs its own follow-up.
          let clearedCount = 0;
          let clearFailedCount = 0;
          let lookupFailedCount = 0;
          const extKeys = staleCandidates.map((row) => `${WS_REDIS_EXT_PREFIX}${row.host_identifier}`);
          redis.mGet(extKeys)
            .then((values) => staleCandidates.filter((_row, i) => values[i] === null))
            .catch((err: unknown) => {
              // MGET fails as a unit, so attribute the failure to every
              // candidate it covered.
              lookupFailedCount = staleCandidates.length;
              for (const row of staleCandidates) {
                logger.warn({ err, hostIdentifier: row.host_identifier }, 'Redis lookup failed during stale agent_online cleanup check');
              }
              return [] as NodeRow[];
            })
            .then((toClear) => {
              // No live extension slot in Redis means the DB flag is stale.
              const clearPromises = toClear.map((row) =>
                db.query(
                  'UPDATE nodes SET agent_online = false WHERE host_identifier = $1',
                  [row.host_identifier],
                )
                  .then(() => {
                    clearedCount++;
                    emitNodeStatusChange();
                  })
                  .catch((err: unknown) => {
                    clearFailedCount++;
                    logger.error({ err, hostIdentifier: row.host_identifier }, 'Failed to clear stale agent_online flag');
                  }),
              );
              return Promise.allSettled(clearPromises);
            })
            .then(() => {
              if (clearedCount > 0 || clearFailedCount > 0) {
                logger.info(
                  { checked: staleCandidates.length, cleared: clearedCount, clearFailed: clearFailedCount, lookupFailed: lookupFailedCount },
                  'Stale agent_online cleanup pass complete',
                );
              }
            });
        }
      }

      // Reverse pass: enrollment race. The extension's WS connect runs
      // UPDATE nodes SET agent_online = true before osquery has enrolled and
      // created the row, so the UPDATE matches nothing and the new row keeps
      // agent_online = false while the connection (and its ws:ext key) stays up.
      // A node flagged offline whose routing key exists is actually connected.
      if (redis) {
        const missedCandidates = typedRows.filter((row) => !row.agent_online);
        if (missedCandidates.length > 0) {
          const missedKeys = missedCandidates.map((row) => `${WS_REDIS_EXT_PREFIX}${row.host_identifier}`);
          redis.mGet(missedKeys)
            .then((values) => missedCandidates.filter((_row, i) => values[i] !== null))
            .then((toSet) => Promise.allSettled(toSet.map((row) =>
              db.query(
                'UPDATE nodes SET agent_online = true WHERE host_identifier = $1 AND agent_online IS DISTINCT FROM true',
                [row.host_identifier],
              )
                .then(() => {
                  logger.info({ hostIdentifier: row.host_identifier }, 'Restored agent_online for node that enrolled after its extension connected');
                  emitNodeStatusChange();
                }),
            )))
            .catch((err: unknown) => logger.warn({ err }, 'Enrollment-race agent_online repair failed'));
        }
      }

      // Broadcast when the unscoped totals changed, OR when group assignment
      // changed (group reassignment doesn't move the unscoped totals but does
      // change what a scoped client should see).
      const groupSignature = typedRows
        .map((row) => `${row.host_identifier}:${row.owner_group_id ?? ''}`)
        .join('|');
      const groupSignatureChanged = groupSignature !== lastGroupSignature;
      lastGroupSignature = groupSignature;

      if (!isNodeStatusEqual(next, data.nodeStatus) || groupSignatureChanged) {
        Object.assign(data.nodeStatus, next);
        broadcastAll().catch((err) => logger.error({ err }, 'Node status broadcast failed'));
      }
    })
    .catch((err: unknown) => {
      if (!_firstPollLogged) {
        _firstPollLogged = true;
        logger.error(
          { err },
          'First nodes poll failed, query could not execute; check that secondary DB env vars (PG_HOST1, POSTGRES_DB1, etc.) point to the fleet database containing the "nodes" table',
        );
      }
      logger.error({ err }, 'Failed to query nodes');
    });
}

// LISTEN / NOTIFY with reconnection

/**
 * Establish a LISTEN subscription on the fleet (secondary) raw pg client.
 * Retries indefinitely every LIVE_SETUP_NOTIFICATIONS_DELAY_MS, both on initial
 * failure and after a drop, so alerts survive DB restarts.
 *
 * Both 'error' and 'end' must tear down every listener on the dead client
 * before rescheduling: rawPgClient.ts nullifies its cache on error, so the next
 * attempt gets a fresh client, and a stale handle left listening would silently
 * lose LISTEN forever. liveWebStopped keeps retries from outliving stopLiveWeb().
 */
async function setupNotifications(): Promise<void> {
  if (liveWebStopped) return;

  const scheduleRetry = (reason: string, err?: unknown): void => {
    if (err !== undefined) {
      logger.warn({ err, reason, retryDelayMs: LIVE_SETUP_NOTIFICATIONS_DELAY_MS }, 'Notification client unavailable, scheduling retry');
    } else {
      logger.warn({ reason, retryDelayMs: LIVE_SETUP_NOTIFICATIONS_DELAY_MS }, 'Notification client unavailable, scheduling retry');
    }
    if (!liveWebStopped) {
      notificationRetryTimeout = setTimeout(() => {
        notificationRetryTimeout = null;
        setupNotifications();
      }, LIVE_SETUP_NOTIFICATIONS_DELAY_MS);
    }
  };

  try {
    const client = await dbRawSourceConnectionSecondary();
    await client.query(`LISTEN ${PG_ALERT_CHANNEL}`);
    logger.info(`LISTEN ${PG_ALERT_CHANNEL} established`);

    // pg emits { channel, payload, processId }. The payload is produced by
    // alerts_insert_notify_trigger; a notification with none (e.g. a manual
    // `NOTIFY new_alert` from psql) is still counted, just unattributable.
    const onNotification = (msg: { channel?: string; payload?: string }): void => {
      if (liveWebStopped) return;
      recordAlertNotification(msg?.payload);
      // recordAlertNotification drives the low-latency scoped push; this
      // additionally refreshes the full snapshot, on its own debounce.
      scheduleAlertBroadcast();
    };

    /**
     * Cleans up all three listeners from this specific client instance so they
     * cannot fire a second time (e.g. 'end' after 'error'), then triggers a
     * fresh connection attempt.
     */
    const reconnect = (reason: string, err?: unknown): void => {
      client.removeListener('notification', onNotification);
      client.removeListener('error', onError);
      client.removeListener('end', onEnd);
      scheduleRetry(reason, err);
    };

    // Named so removeListener can target them precisely.
    const onError = (err: Error): void => reconnect('error', err);
    const onEnd = (): void => reconnect('connection ended');

    client.on('notification', onNotification);
    client.on('error', onError);
    client.on('end', onEnd);
  } catch (err) {
    scheduleRetry('setup failed', err);
  }
}

/**
 * Re-resolve the node-group scope of every connected client.
 *
 * A dashboard socket outlives the request that opened it, so the scope stored
 * at connect would otherwise be authoritative for the life of the tab: a user
 * removed from a group, or demoted from Super Administrator, would keep
 * receiving that group's node counts and host-identifier lists until they
 * disconnected. Nothing closes these sockets on a role change or a session
 * invalidation, so the refresh has to come from this side.
 *
 * Only the live counts are affected. Every path that returns records or acts on
 * a node re-checks scope on its own — the REST endpoints per request,
 * terminal.ts per shell_start, node.ts per message — so this closes a
 * staleness window, not an authorisation hole.
 *
 * Sequential on purpose: this runs on a timer for every connected dashboard at
 * once, and issuing them in parallel would put a burst on the same pool the
 * request path uses for no gain at these client counts. getUserNodeScope
 * handles its own errors and returns a fail-closed scope rather than throwing,
 * so one bad lookup narrows that client's view instead of aborting the sweep.
 */
async function refreshClientScopes(): Promise<void> {
  if (CLIENTS_UI.size === 0) return;

  for (const state of CLIENTS_UI.values()) {
    // A client with no resolvable session already has an empty scope. There is
    // nothing to re-read, and no lookup that could widen it.
    if (state.userId === null) continue;
    state.scope = await getUserNodeScope(state.userId);
  }
}

// Timer handles (started lazily by startLiveWeb)

let nodesPollingInterval: ReturnType<typeof setInterval> | null = null;
let alertResetInterval: ReturnType<typeof setInterval> | null = null;
let scopeRefreshInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Start the live-web system: registers the event-driven node status handler,
 * runs a first poll, arms the safety-net poll and window reset, and sets up the
 * alert LISTEN subscription.
 *
 * Must be called after the database is initialised, or the first poll and the
 * LISTEN setup both start from their retry paths.
 */
export function startLiveWeb(): void {
  if (liveWebStopped) return;

  // Wire the event-driven path: emitNodeStatusChange() (node.ts) →
  // notifyNodeStatusChange() (here) → debounce → getNodesStatus().
  onNodeStatusChange(notifyNodeStatusChange);

  // Immediate poll so the first browser client gets real data, not zeros.
  getNodesStatus();

  notificationRetryTimeout = setTimeout(() => {
    notificationRetryTimeout = null;
    setupNotifications();
  }, LIVE_SETUP_NOTIFICATIONS_DELAY_MS);

  // Safety net for nodes killed without a clean WS disconnect, not the primary
  // status path.
  nodesPollingInterval = setInterval(getNodesStatus, LIVE_NODES_POLL_INTERVAL_MS);

  // Rolls the cumulative window that feeds the scoped alertStatus.new. The
  // pending delta is not touched here: it belongs to the push path and is
  // cleared by flushAlertPush() within one ALERT_DEBOUNCE_MS of being filled,
  // so a reset landing between a NOTIFY and its flush can never swallow a push.
  alertResetInterval = setInterval(() => {
    data.alertStatus.new = 0;
    alertWindowByHost = new Map();
    alertWindowUnknownHost = 0;
    alertCapWarned = false;
    alertHostCapWarned = false;
    alertUnknownHostWarned = false;
    alertWindowStartEpoch = Math.floor(Date.now() / 1000);
  }, LIVE_ALERT_RESET_INTERVAL_MS);

  // Bounds how long a demoted or reassigned user keeps their old scope on an
  // already-open dashboard socket. Errors are contained inside
  // refreshClientScopes; the catch is here only so a rejected sweep cannot
  // surface as an unhandled rejection and take the process down.
  scopeRefreshInterval = setInterval(() => {
    refreshClientScopes().catch((err) => {
      logger.warn({ err }, 'Failed to refresh live dashboard client scopes');
    });
  }, LIVE_SCOPE_REFRESH_INTERVAL_MS);

  logger.info('Event-driven updates, 30s safety-net, and alert listeners started');
}

// Public API

/**
 * Register a new UI WebSocket client for live dashboard updates. The connection
 * was already JWT-authenticated at upgrade; this resolves the user's node-group
 * scope before the first snapshot so a scoped user never sees fleet-wide totals.
 * Rethrows if session or scope resolution fails, leaving the client unregistered.
 */
export async function liveWeb(ws: LiveWebWsLike, req?: ReqLike): Promise<void> {
  let jwtPayload: Awaited<ReturnType<typeof getWsJwtPayload>>;
  let scope: NodeScope;
  try {
    jwtPayload = req ? await getWsJwtPayload(req) : null;
    scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false, groups: [] };
  } catch (err) {
    // Neither getWsJwtPayload nor getUserNodeScope logs its own failure.
    logger.error({ err }, 'Failed to resolve session/scope for live dashboard client');
    throw err;
  }

  CLIENTS_UI.set(ws, { userId: jwtPayload?.id ?? null, scope });
  logger.debug(
    { unrestricted: scope.unrestricted, groupCount: scope.unrestricted ? undefined : [...scopeGroupIds(scope)].length },
    'Live dashboard client connected',
  );

  ws.on('close', (...args: unknown[]) => {
    CLIENTS_UI.delete(ws);
    const reason = typeof args[1] === 'string' ? args[1] : '';
    logger.debug({ reason: reason || undefined }, 'Live dashboard client disconnected');
  });

  // On send failure, prune immediately rather than leaving a dead socket in
  // the set to be discovered on the next broadcast cycle.
  try {
    const alertStatus = await computeScopedAlertStatus(scope);
    ws.send(JSON.stringify({ nodeStatus: computeScopedNodeStatus(scope), alertStatus }));
  } catch (err) {
    logger.error({ err }, 'Initial send error, pruning client');
    CLIENTS_UI.delete(ws);
  }
}

/**
 * Broadcast an arbitrary JSON string to every connected live-dashboard client
 * whose scope includes the event's host. Used by node.ts to forward
 * agent-initiated push messages (e.g. clamav_push) so pages like MyDevices
 * update without per-node WebSocket connections.
 *
 * The payload must carry a `host_identifier`; its owning group is matched
 * against each client's membership. A payload that will not parse, or whose
 * host is unassigned, fails closed to unrestricted clients only.
 */
export function broadcastToLiveClients(payload: string): void {
  if (CLIENTS_UI.size === 0) return;

  let hostIdentifier: string | undefined;
  try {
    hostIdentifier = JSON.parse(payload)?.host_identifier;
  } catch (err) {
    // Unparseable payload — fail closed below (only unrestricted clients get it).
    logger.warn({ err }, 'broadcastToLiveClients payload was not valid JSON, failing closed to unrestricted clients only');
  }
  const ownerGroupId = hostIdentifier ? hostOwnerGroupIndex.get(hostIdentifier) : undefined;

  const dead: LiveWebWsLike[] = [];
  let staleReadyState = 0;
  for (const [client, { scope }] of CLIENTS_UI) {
    if (client.readyState !== undefined && client.readyState !== 1 /* OPEN */) {
      dead.push(client);
      staleReadyState++;
      continue;
    }
    // Membership is tested directly rather than via scopeGroupIds(scope), which
    // would allocate a fresh array per client on every push.
    const inScope = scope.unrestricted || (!!ownerGroupId && scope.groups.some((g) => g.id === ownerGroupId));
    if (!inScope) continue;
    try {
      client.send(payload);
    } catch (err) {
      logger.debug({ err, hostIdentifier }, 'Live client push send error, pruning dead client');
      dead.push(client);
    }
  }
  for (const d of dead) CLIENTS_UI.delete(d);
  if (staleReadyState > 0) {
    logger.warn({ staleReadyState, remaining: CLIENTS_UI.size }, 'Pruned clients with stale readyState during live push');
  }
}

/**
 * Stop all live-web timers and disconnect all clients.
 * Wire this into the graceful shutdown handler in index.ts.
 */
export function stopLiveWeb(): void {
  liveWebStopped = true;

  if (nodesPollingInterval != null) {
    clearInterval(nodesPollingInterval);
    nodesPollingInterval = null;
  }
  if (alertResetInterval != null) {
    clearInterval(alertResetInterval);
    alertResetInterval = null;
  }
  if (scopeRefreshInterval != null) {
    clearInterval(scopeRefreshInterval);
    scopeRefreshInterval = null;
  }
  if (notificationRetryTimeout != null) {
    clearTimeout(notificationRetryTimeout);
    notificationRetryTimeout = null;
  }
  if (alertFlushTimeout != null) {
    clearTimeout(alertFlushTimeout);
    alertFlushTimeout = null;
  }
  // Must be cleared alongside alertFlushTimeout: a pending broadcast would
  // otherwise fire after shutdown, running broadcastAll()'s query against a
  // closing datasource and holding the event loop open.
  if (alertBroadcastTimeout != null) {
    clearTimeout(alertBroadcastTimeout);
    alertBroadcastTimeout = null;
  }
  if (nodeStatusDebounceTimeout != null) {
    clearTimeout(nodeStatusDebounceTimeout);
    nodeStatusDebounceTimeout = null;
  }

  // Deregister the event-driven handler so any post-shutdown
  // emitNodeStatusChange() calls are silent no-ops.
  offNodeStatusChange();

  CLIENTS_UI.clear();
  logger.info('Live dashboard stopped');
}
