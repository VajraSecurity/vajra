/**
 * Node WebSocket handlers: UI client (nodeUi) and Agent extension (nodeExt).
 *
 * Redis is the primary routing store; the in-memory Maps are a fallback
 * consulted only when Redis is unavailable, so routing degrades rather than
 * fails. Both stores are written on every routing change and must stay in sync.
 *
 *   ws:ext:{hostId} -> extSlot  (TTL CONN_EXPIRY_SECONDS, long-lived per agent)
 *   ws:rid:{rid}    -> uiSlot   (TTL RID_EXPIRY_SECONDS, one-time-use per request)
 *
 * UI -> extension: the server assigns or preserves a rid, records rid -> uiSlot,
 * resolves extSlot from host_identifier and forwards the whole payload; if no
 * extension is registered the UI gets { error, rid } immediately.
 *
 * Extension -> UI: the rid resolves back to a uiSlot, the payload is delivered
 * and the rid mapping is deleted from both stores. A response whose UI is gone
 * is discarded.
 */

import { ValidateMessage, ValidateExtResponse, generateUniqueID } from './utils';
import type { Job, WebSocRevMessage } from './types';
import { dbSourceConnection } from '../index';
import { emitNodeStatusChange } from './nodeStatusEvents';
import { broadcastToLiveClients } from './liveWeb';
import { dispatchPendingPatchCommands, dispatchNextPendingPatchCommand } from './patchDispatch';
import { createPatchJob, findHostsInFlight } from '../controllers/nodes/patch_management';
import { reapplyEnabledPoliciesForHost } from '../services/policyEnforcement';
import { getRedisClient } from '../utils/redisClient';
import { getWsJwtPayload, resolveNodeUiWsSession } from '../utils/wsAuth';
import { ALERT_TYPE_CLAMAV_SCAN, ALERT_TYPE_CLAMAV_ALERT, ALERT_TYPE_USB_DEVICE } from '../consts/alerts';
import { assertHostInScope, assertCanActOnHost, scopeGroupIds, type NodeScope } from '../utils/nodeScope';
import { logAuditTrail } from '../utils/auditTrailLogger';
import type { AuditTrailAction } from '../orm/entities/audit/AuditTrail';
import { AUDIT_ACTION_COMPLIANCE } from '../orm/entities/audit/AuditTrail';
import { DEFAULT_USER_ROLE } from '../orm/entities/users/Users';
import { getLogger } from '../utils/logger';
import { PATCH_REASON_MAX_LENGTH } from '../consts/pagination';
import { MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL } from '../utils/maintainedAppKnownAliases';
import { returningRows } from '../utils/returningRows';
import {
  WS_POOL_SIZE,
  JOB_DRAIN_PER_TICK,
  JOB_DRAIN_INTERVAL_MS,
  RID_EXPIRY_SECONDS,
  RID_CLEANUP_INTERVAL_MS,
  CONN_EXPIRY_SECONDS,
  EXT_ROUTING_REFRESH_MIN_MS,
  WS_REDIS_EXT_PREFIX,
  WS_REDIS_RID_PREFIX,
  RID_PREFIX_OSUPDATE_ACK,
  RID_PREFIX_PATCH_JOB_ACK,
  RID_PREFIX_PATCH_CHECK,
  COMPLIANCE_KEY_RANGE,
  BLUETOOTH_DISABLE_KEY,
  BLUETOOTH_ENABLE_KEY,
  BLUETOOTH_STATUS_KEY,
} from '../consts';

// node-postgres' own scalar-parameter serialiser, used to normalise
// agent-supplied values before they enter the packages_snapshot unnest()
// arrays — see the block comment at that INSERT for why it is load-bearing.
// Taken from pg's internals deliberately: reimplementing it would mean
// tracking node-postgres' serialisation rules by hand, and any drift between
// the two is exactly the bug this prevents.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { prepareValue: pgPrepareValue } = require('pg/lib/utils') as {
  prepareValue: (v: unknown) => string | null;
};

export type WsLike = {
  on: (e: string, fn: (...args: unknown[]) => void) => void;
  send: (data: string) => void;
  /** Close the connection with optional code and reason (mirrors ws.WebSocket.close). */
  close: (code?: number, reason?: string) => void;
  /**
   * Bytes queued by send() but not yet flushed (ws.WebSocket.bufferedAmount).
   * Optional because test fakes and the `as unknown as WsLike` casts in index.ts
   * do not all provide it; every real `ws` socket does. Its only consumer is the
   * backpressure guard in the push broadcast below.
   */
  bufferedAmount?: number;
};
export type ReqLike = { headers: { [key: string]: string | undefined } };

const logger = getLogger('websocket.node');

// Redis key builders, namespaced to avoid collisions with auth/captcha/blacklist keys.

const extKey = (hostId: string): string => `${WS_REDIS_EXT_PREFIX}${hostId}`;
const ridKey  = (rid:    string): string => `${WS_REDIS_RID_PREFIX}${rid}`;

// Connection pools

const CLIENTS:    (WsLike | null)[] = Array(WS_POOL_SIZE).fill(null);
const wsToClientIndex               = new Map<WsLike, number>();
const clientFreeList: number[]      = [];

// UI client node-group scoping (agent-push broadcast RBAC).
//
// The agent-push broadcast below must filter by the pushing host's owning group
// exactly the way liveWeb.ts's broadcastToLiveClients does; unfiltered it would
// hand a Group Admin or Viewer Defender detections, USB serials, ClamAV paths
// and package inventories for hosts outside their groups. Keep the two rules
// identical rather than inventing a second one.
//
// The decision needs two pieces of state, neither of which may cost I/O on the
// push path:
//
//  1. CLIENT_SCOPES — the user's NodeScope, resolved once per socket at connect
//     and thereafter refreshed from the session resolveNodeUiWsSession already
//     computes for each inbound message.
//  2. hostOwnerGroupIndex — host_identifier -> owner_group_id, a local copy of
//     what liveWeb.ts maintains (its copy is module-private). Refreshed lazily,
//     and only while a scoped client is connected, so a Super-Admin-only
//     deployment issues no extra queries at all.

/**
 * A UI slot's resolved scope plus its precomputed cohort key.
 *
 * The key is computed when the scope is stored so the broadcast loop never
 * allocates: identically-scoped clients share a key, so the in/out-of-scope
 * decision is computed once per cohort per push. Same key derivation as
 * liveWeb.ts's scopeKey(), just hoisted off the push path.
 */
type ClientScopeEntry = { scope: NodeScope; cohortKey: string };

const CLIENT_SCOPES: (ClientScopeEntry | null)[] = Array(WS_POOL_SIZE).fill(null);

/** Cohort key for Super Admins. Matches liveWeb.ts's UNRESTRICTED_SCOPE_KEY. */
const UNRESTRICTED_COHORT_KEY = '*';

/**
 * Number of occupied UI slots whose resolved scope is restricted. Gates the
 * host->group index refresh: with only unrestricted clients connected there is
 * nothing to filter, so the index is never built and never polled.
 */
let scopedClientCount = 0;

function cohortKeyFor(scope: NodeScope): string {
  // scopeGroupIds() already returns a fresh array, so sorting it in place is safe.
  return scope.unrestricted ? UNRESTRICTED_COHORT_KEY : scopeGroupIds(scope).sort().join(',');
}

/** Record (or update) the resolved scope for a UI slot, keeping scopedClientCount in sync. */
function setClientScope(slot: number, scope: NodeScope): void {
  const previous = CLIENT_SCOPES[slot];
  if (previous && !previous.scope.unrestricted) scopedClientCount--;
  if (!scope.unrestricted) scopedClientCount++;
  CLIENT_SCOPES[slot] = { scope, cohortKey: cohortKeyFor(scope) };

  // Warm the host->group index as soon as a scoped client appears; otherwise
  // the first push after they connect is evaluated against a cold index and
  // fails closed. Throttled by HOST_GROUP_INDEX_TTL_MS.
  if (!scope.unrestricted) refreshHostOwnerGroupIndexIfStale();
}

/** Forget a UI slot's scope. Always paired with freeing the slot itself. */
function clearClientScope(slot: number): void {
  const previous = CLIENT_SCOPES[slot];
  if (previous && !previous.scope.unrestricted) scopedClientCount--;
  CLIENT_SCOPES[slot] = null;
}

/**
 * host_identifier -> owner_group_id, for hosts that have an owning group.
 * A host absent from this map counts as unassigned and is invisible to scoped
 * users, matching liveWeb.ts and the REST endpoints. Failing this way round
 * means a stale or cold index can only withhold a push from a scoped user
 * (recoverable via their own REST polls), never leak one.
 */
let hostOwnerGroupIndex = new Map<string, string>();

/**
 * Wall clock of the last refresh ATTEMPT (not the last success), so a failing
 * query backs off by the TTL instead of being retried on every single push.
 */
let hostOwnerGroupIndexAttemptedAt = 0;
let hostOwnerGroupRefreshInFlight = false;

/**
 * How long a host->group snapshot is reused before another refresh is attempted.
 * This is also the maximum time a node reassigned between groups can keep being
 * pushed to its former group — the same bounded staleness liveWeb.ts's poll
 * accepts for the same decision.
 */
const HOST_GROUP_INDEX_TTL_MS = 10_000;

/**
 * Fire-and-forget refresh of hostOwnerGroupIndex. Must never be awaited: the
 * push broadcast reads whatever snapshot is resident and returns, so this
 * cannot add latency to the nodeExt handler the agent channel runs on.
 */
function refreshHostOwnerGroupIndexIfStale(): void {
  if (hostOwnerGroupRefreshInFlight) return;
  const now = Date.now();
  if (now - hostOwnerGroupIndexAttemptedAt < HOST_GROUP_INDEX_TTL_MS) return;

  const ds = dbSourceConnection();
  const fleetDb = ds?.[1];
  if (!fleetDb || !fleetDb.isInitialized) return; // keep the old snapshot; retry next push

  hostOwnerGroupIndexAttemptedAt = now;
  hostOwnerGroupRefreshInFlight = true;
  fleetDb
    .query(`SELECT host_identifier, owner_group_id FROM nodes WHERE owner_group_id IS NOT NULL`)
    .then((rows: unknown) => {
      if (!Array.isArray(rows)) {
        logger.warn({ resultType: typeof rows }, 'Unexpected result shape refreshing host→group index for push scoping');
        return;
      }
      const next = new Map<string, string>();
      for (const row of rows as { host_identifier: string; owner_group_id: string }[]) {
        if (row?.host_identifier && row?.owner_group_id) next.set(row.host_identifier, row.owner_group_id);
      }
      // Swapped wholesale rather than mutated in place so a concurrent
      // broadcast always reads one consistent snapshot.
      hostOwnerGroupIndex = next;
    })
    .catch((err: unknown) => {
      // Keep the previous snapshot on failure: clearing it would blank out
      // pushes for every scoped user for the duration of a transient DB blip.
      logger.warn({ err }, 'Failed to refresh host→group index for push scoping, reusing previous snapshot');
    })
    .finally(() => { hostOwnerGroupRefreshInFlight = false; });
}

/**
 * Free a UI slot and everything that references it. Every UI slot free must go
 * through here — the CLIENTS-side equivalent of releaseExtSlot() — because a
 * partial free is a cross-user data leak:
 *
 *  - Deleting `ws` from wsToClientIndex stops a later 'close' on the same socket
 *    from pushing the slot onto clientFreeList a second time, which would hand
 *    one slot to two browser clients and misroute rid responses between them.
 *  - Evicting in-flight rids that point at this slot (and their Redis keys)
 *    stops a surviving rid from resolving to whichever client gets the slot next.
 *  - Clearing CLIENT_SCOPES keeps the push-broadcast RBAC decision from being
 *    made against a departed user's group membership.
 */
function releaseClientSlot(slot: number, ws?: WsLike | null): void {
  CLIENTS[slot] = null;
  clearClientScope(slot);
  if (ws) wsToClientIndex.delete(ws);
  clientFreeList.push(slot);

  const redisForCleanup = getRedisClient();
  for (const [rid, entry] of ridToUiSlot) {
    if (entry.slot === slot) {
      ridToUiSlot.delete(rid);
      if (redisForCleanup) redisForCleanup.del(ridKey(rid)).catch(() => {});
    }
  }
}

const EXTENSIONS: (WsLike | null)[] = Array(WS_POOL_SIZE).fill(null);
const wsToExtIndex                  = new Map<WsLike, number>();
const extFreeList: number[]         = [];

/**
 * extSlot -> host_identifier of the agent currently occupying that slot.
 *
 * Routing safety net. ws:ext:{hostId} keys have a long TTL, so a stale one can
 * outlive its connection and point at a slot since re-allocated to a different
 * host (failed DEL on close, crash, multi-day uptime). Every forward must
 * verify the resolved slot still belongs to the requested host before sending:
 * for an EDR this is the difference between isolating the intended machine and
 * isolating a bystander.
 */
const extSlotToHost: (string | null)[] = Array(WS_POOL_SIZE).fill(null);

/**
 * Return an extension slot to the pool, clearing every structure that
 * references it. Every slot free must go through here — a partial free causes
 * double-free slot reuse and cross-host misrouting.
 *
 * `ws` (when available) is removed from wsToExtIndex so a later 'close' on the
 * same socket finds no index and cannot free the slot a second time.
 */
function releaseExtSlot(slot: number, ws?: WsLike): void {
  EXTENSIONS[slot] = null;
  extSlotToHost[slot] = null;
  if (ws) wsToExtIndex.delete(ws);
  extFreeList.push(slot);
}

// In-memory routing tables (fallback store)

/** host_identifier → extension slot index. Updated on agent connect/disconnect. */
const hostToExtSlot = new Map<string, number>();

/**
 * True if this host has a live extension connection on this process. Reflects
 * only this process's hostToExtSlot, not Redis — the same scope dispatchToAgent
 * resolves against, since a policy push can only reach agents connected to the
 * instance handling it. See the known-limitation note in
 * services/policyEnforcement.ts.
 */
export function isHostConnected(hostIdentifier: string): boolean {
  return hostToExtSlot.has(hostIdentifier);
}

/** Every host_identifier with a live extension connection on this process. */
export function getConnectedHostIdentifiers(): string[] {
  return Array.from(hostToExtSlot.keys());
}

/**
 * rid → { slot: UI slot index, expiresAt: epoch ms }
 *
 * One-time-use: deleted the moment the matching extension response is delivered.
 * Also swept periodically to evict entries for requests that never got a response
 * (e.g. extension timed out or crashed mid-request).
 */
const ridToUiSlot = new Map<string, { slot: number; expiresAt: number }>();
const RID_EXPIRY_MS = RID_EXPIRY_SECONDS * 1000;

export const ridCleanupInterval = setInterval(() => {
  const now = Date.now();
  let expired = 0;
  for (const [rid, entry] of ridToUiSlot) {
    if (entry.expiresAt < now) {
      ridToUiSlot.delete(rid);
      expired++;
    }
  }
  // Each expired entry is a UI request the extension never answered within
  // RID_EXPIRY_SECONDS; otherwise the timeout is only visible client-side.
  if (expired > 0) {
    logger.warn({ expired, remaining: ridToUiSlot.size }, 'Swept expired rid routing entries, requests went unanswered');
  }
}, RID_CLEANUP_INTERVAL_MS);

// Slot allocators

function allocClientSlot(ws: WsLike): number {
  const idx = clientFreeList.pop();
  if (idx !== undefined) { CLIENTS[idx] = ws; return idx; }
  for (let i = 0; i < CLIENTS.length; i++) {
    if (CLIENTS[i] === null) { CLIENTS[i] = ws; return i; }
  }
  return -1;
}

function allocExtSlot(ws: WsLike): number {
  const idx = extFreeList.pop();
  if (idx !== undefined) { EXTENSIONS[idx] = ws; return idx; }
  for (let i = 0; i < EXTENSIONS.length; i++) {
    if (EXTENSIONS[i] === null) { EXTENSIONS[i] = ws; return i; }
  }
  return -1;
}

// Send helper

/**
 * Safe JSON send.  Returns true on success, false on error.
 * Does not mutate slots; callers decide what to do with a dead socket.
 */
function safeSend(ws: WsLike, payload: string, label: string, quiet = false): boolean {
  try {
    ws.send(payload);
    return true;
  } catch (err) {
    // Debug level only: callers emit an aggregate summary for a batch of these,
    // so a broadcast to many dead sockets does not produce one error line each.
    logger[quiet ? 'debug' : 'error']({ err, label }, 'WebSocket send error');
    return false;
  }
}

function isViewerRole(role: unknown): boolean {
  return typeof role === 'string' && role.trim().toLowerCase() === DEFAULT_USER_ROLE.toLowerCase();
}

function isViewerReadOnlyAgentCommand(data: WebSocRevMessage): boolean {
  if (data.type !== 'agent') return false;
  const p = data.params;
  if (!p?.agent) return false;

  // Read-only status endpoints used by the dashboard.
  if (p.agent === 'status') return true; // port/ip status lists
  if (p.agent === 'wifi' && String(p.action) === 'status') return true;
  if (p.agent === 'bluetooth' && String(p.action) === 'status') return true;
  if (p.agent === 'removableDevice' && String(p.action) === 'status') return true;
  if (p.agent === 'packages') return true;

  // Powershell read-only keys (compliance + status/telemetry snapshots).
  if (p.agent === 'powershell' && Array.isArray(p.command_keys) && p.command_keys.length > 0) {
    const readOnlyKeys = new Set([
      // Compliance checklist
      ...COMPLIANCE_KEY_RANGE,
      // Status-only keys used by controls
      '22', // Defender status
      '54', // USB status
      '55', // Bluetooth status
      '64', // Defender signature telemetry
      '65', // Defender last scan status
      '69', // Firewall profile status
    ]);
    return p.command_keys.every((k) => readOnlyKeys.has(String(k)));
  }

  return false;
}

// UI push backpressure thresholds. Local to this module because only the
// /ws/ui agent-push broadcast reads them. Sized against WS_MAX_PAYLOAD_BYTES:
// the drop threshold is below one maximum frame, so a client that cannot drain
// even a single worst-case push stops accumulating; the close threshold is
// roughly three such frames, i.e. a client that is gone rather than slow.

/** Withhold further push frames from a client once its unflushed send buffer reaches this (bytes). */
const UI_PUSH_BUFFER_DROP_BYTES  = 4 * 1024 * 1024;
/** Close a client outright once its unflushed send buffer reaches this (bytes). */
const UI_PUSH_BUFFER_CLOSE_BYTES = 16 * 1024 * 1024;

// Bounded-concurrency ingest

/**
 * Maximum simultaneous DB statements issued by one agent push batch.
 *
 * A store-and-forward flush from an agent that has been offline can carry
 * thousands of statements. Unbounded, they occupy every connection in the pool
 * while they queue, and every HTTP request and every other agent handler that
 * needs the fleet DB waits behind them. Keeping this at half the pool leaves
 * the other half available however large the flush is. The batch simply takes
 * longer, which is free: the persist step is fire-and-forget and nothing waits
 * on it.
 */
const PUSH_INSERT_CONCURRENCY = 5;

/**
 * Run `tasks` with at most `limit` in flight, resolving when all have settled.
 * Never rejects.
 *
 * Preserves per-row failure isolation — each task is one statement with its own
 * .catch(), so a bad row fails alone where a bulk statement would abort the
 * whole batch. This is why the callers use this rather than a bulk `unnest`
 * INSERT.
 *
 * Only execution order and overlap differ from starting every task at once. The
 * statements this is used on are order-independent, except that two rows in one
 * batch conflicting with each other are now de-duplicated by ON CONFLICT rather
 * than both slipping through — which is what that clause is for.
 */
function runBounded(tasks: (() => Promise<unknown>)[], limit: number): Promise<void> {
  if (tasks.length === 0) return Promise.resolve();
  const width = Math.max(1, Math.min(limit, tasks.length));
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= tasks.length) return;
      // Callers' tasks attach their own .catch(); this guard is for an
      // unexpected rejection (e.g. a synchronous throw building the query),
      // which would otherwise kill a worker and strand the rest of the batch.
      try {
        await tasks[i]();
      } catch (err) {
        logger.error({ err }, 'Bounded ingest task rejected unexpectedly');
      }
    }
  };
  const workers: Promise<void>[] = [];
  for (let w = 0; w < width; w++) workers.push(worker());
  return Promise.all(workers).then(() => undefined);
}

/**
 * Per-host tail of the ClamAV persist chain. Present only while a batch for
 * that host is queued or running; deleted as soon as its chain drains, so this
 * cannot grow with fleet size or uptime.
 */
const clamavPersistChains = new Map<string, Promise<void>>();

/**
 * Serialise a host's ClamAV upsert batch, and serialise consecutive batches for
 * that host against each other.
 *
 * Serial, not merely bounded: the clamav_push upsert is a bump-or-insert CTE
 * whose whole point is to find an already-open alert for the same
 * (host, signature, path) and bump it. Run concurrently, two identical
 * detections in one batch both see no committed open alert and both INSERT.
 * Statements run in autocommit, so executing them one at a time means statement
 * k observes statements 1..k-1 and matches the bump instead. Chaining per host
 * extends that across back-to-back batches, which can otherwise overlap because
 * the handler does not await the persist step.
 *
 * Agent comms are unaffected: the chain is keyed by host so two agents never
 * contend, the nodeExt handler never awaits it, and one batch now holds a single
 * pool connection instead of N.
 */
function runClamavBatchSerialised(hostId: string, tasks: (() => Promise<unknown>)[]): Promise<void> {
  const previous = clamavPersistChains.get(hostId) ?? Promise.resolve();
  const run = previous.then(() => runBounded(tasks, 1));
  clamavPersistChains.set(hostId, run);
  // Only the current tail clears the entry: a batch queued behind this one has
  // already replaced the tail and must keep it.
  void run.then(() => {
    if (clamavPersistChains.get(hostId) === run) clamavPersistChains.delete(hostId);
  });
  return run;
}

// Push-message DB helpers

/** Normalize Windows Defender severity string to lowercase alert severity. */
function normalizeDefenderSeverity(sev: unknown): string {
  const s = String(sev ?? '').toLowerCase();
  if (s === 'critical' || s === 'severe') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'low' || s === 'informational') return 'low';
  if (s === 'medium' || s === 'moderate') return 'medium';
  if (s === '5' || s === '4') return 'critical';
  if (s === '3') return 'high';
  if (s === '2') return 'medium';
  if (s === '1' || s === '0') return 'low';
  return 'medium';
}

/** Parse a date string or unix timestamp into unix seconds. Returns null on failure. */
function parseUnixTime(val: unknown): number | null {
  if (val == null || val === '') return null;
  const n = Number(val);
  if (!isNaN(n) && isFinite(n)) return n > 1e10 ? Math.floor(n / 1000) : Math.floor(n);
  const d = new Date(String(val));
  if (!isNaN(d.getTime())) return Math.floor(d.getTime() / 1000);
  return null;
}

// Database helpers

function IsolateMachine(data: WebSocRevMessage): void {
  // The current caller guards this at the WS message-parse site, but that guard
  // is not visible from here; stay safe on our own for any future caller.
  if (!data) return;
  if (data.type === 'agent' && data?.params?.agent === 'networkManager') {
    const action = data?.params?.action;
    if (action !== 'block' && action !== 'allow') return;

    const ds = dbSourceConnection();
    // nodes table lives in the fleet (secondary) DB — ds[1]
    if (!ds || ds.length < 2) {
      logger.warn(
        { hostIdentifier: data.host_identifier, action },
        'Isolate/allow command dispatched to agent but not persisted, fleet DB unavailable',
      );
      return;
    }
    const db = ds[1];
    if (action === 'block') {
      db.query(`UPDATE nodes SET isolated = $1 WHERE host_identifier = $2`, [true, data.host_identifier])
        .then(() => logger.info({ hostIdentifier: data.host_identifier }, 'Node isolation persisted, isolated=true'))
        .catch((err: unknown) => logger.error({ err, hostIdentifier: data.host_identifier }, 'Failed to set node isolated=true'));
    } else {
      db.query(`UPDATE nodes SET isolated = $1 WHERE host_identifier = $2`, [false, data.host_identifier])
        .then(() => logger.info({ hostIdentifier: data.host_identifier }, 'Node isolation persisted, isolated=false'))
        .catch((err: unknown) => logger.error({ err, hostIdentifier: data.host_identifier }, 'Failed to set node isolated=false'));
    }
  }
}

// Compliance DB helper

/**
 * Persist a compliance check result to the compliance_results table.
 * Called from nodeExt when the agent sends back a powershell compliance response.
 * Fire-and-forget — errors are logged but never bubble up to the WS handler.
 *
 * Caller must ensure rows are machine-compliance only (command_key 1–18); see
 * isMachineCompliancePayload in the nodeExt handler.
 */
async function saveComplianceResult(hostId: string, complianceData: unknown[]): Promise<void> {
  const ds = dbSourceConnection();
  if (!ds || ds.length < 2) {
    // This function does not throw, so without logging here the caller's
    // .catch() never fires and the compliance result is lost without trace.
    logger.warn({ hostId }, 'Fleet DB unavailable, compliance result not persisted');
    return;
  }
  const db = ds[1];
  const unixtime = Math.floor(Date.now() / 1000);
  await db.query(
    `INSERT INTO compliance_results (host_identifier, unixtime, compliance_data)
     VALUES ($1, $2, $3)`,
    [hostId, unixtime, JSON.stringify(complianceData)],
  );
}

/** Machine compliance checklist uses PowerShell keys 1–18 only. Keys 19+ are Defender/USB/Bluetooth/etc. */
const COMPLIANCE_KEY_MIN = 1;
const COMPLIANCE_KEY_MAX = 18;

function isMachineCompliancePayload(respArr: unknown[]): boolean {
  for (const item of respArr) {
    const key = (item as Record<string, unknown>)?.command_key;
    if (typeof key !== 'string') return false;
    const n = parseInt(key, 10);
    if (!Number.isFinite(n) || n < COMPLIANCE_KEY_MIN || n > COMPLIANCE_KEY_MAX) {
      return false;
    }
  }
  return true;
}

// Audit trail for WebSocket actions (port block, ip block, compliance, wifi, bluetooth, defender, usb)

function getWsAuditAction(data: WebSocRevMessage): { action: AuditTrailAction; details: Record<string, unknown> } | null {
  if (data.type !== 'agent' || !data.params) return null;
  const p = data.params;
  const host = data.host_identifier;
  const details: Record<string, unknown> = {
    host_identifier: host,
    ws_agent: p.agent,
    ws_action: p.action,
    arg1: p.arg1,
    arg2: p.arg2,
    // UI may include a human-entered reason; agents may ignore it.
    // We store it both in JSON details and in the dedicated column.
    reason: (p as any)?.reason ?? (p as any)?.arg3 ?? null,
  };
  if (p.agent === 'networkManager') {
    if (p.action === 'block') {
      return { action: 'ISOLATE_NODE', details: { ...details, sub_action: 'block' } };
    }
    if (p.action === 'allow') {
      return { action: 'REENROLL_NODE', details: { ...details, sub_action: 'allow' } };
    }
  }
  if (p.agent === 'port') {
    return {
      action: 'PORT_BLOCK',
      details: {
        ...details,
        sub_action: p.action,
        port: p.arg1 ?? null,
        protocol: p.arg2 ?? null,
      },
    };
  }
  if (p.agent === 'ip') {
    return {
      action: 'IP_BLOCK',
      details: {
        ...details,
        sub_action: p.action,
        ip: p.arg1 ?? null,
        port: p.arg2 ?? null,
      },
    };
  }
  if (p.agent === 'wifi') {
    return { action: 'WIFI', details };
  }
  if (p.agent === 'bluetooth') {
    return { action: 'BLUETOOTH', details: { ...details, sub_action: p.action } };
  }
  if (p.agent === 'removableDevice') {
    return { action: 'USB', details: { ...details, sub_action: p.action } };
  }
  if (p.agent === 'clamav') {
    // arg1 is the scan path for scan/contscan actions.
    return { action: 'CLAMAV', details: { ...details, sub_action: p.action, path: p.arg1 ?? null } };
  }
  if (p.agent === 'powershell' && p.command_keys?.length) {
    const keys = p.command_keys;
    const bluetoothKeys = [String(BLUETOOTH_DISABLE_KEY), String(BLUETOOTH_ENABLE_KEY), String(BLUETOOTH_STATUS_KEY)];
    const hasBluetooth = keys.some((k) => bluetoothKeys.includes(String(k)));
    const hasUsb = keys.some((k) => String(k) === '54');
    const hasCompliance = keys.some((k) => {
      const n = parseInt(String(k), 10);
      return n >= 1 && n <= 18;
    });
    const hasDefender = keys.some((k) => {
      const n = parseInt(String(k), 10);
      return n >= 19 && n <= 43;
    });
    if (hasBluetooth && !hasCompliance && !hasDefender) {
      return { action: 'BLUETOOTH', details: { ...details, command_keys: keys } };
    }
    if (hasUsb && !hasBluetooth && !hasCompliance && !hasDefender) {
      return { action: 'USB', details: { ...details, command_keys: keys } };
    }
    if (hasDefender) {
      return { action: 'DEFENDER', details: { ...details, command_keys: keys } };
    }
    if (hasCompliance) {
      return { action: AUDIT_ACTION_COMPLIANCE, details: { ...details, command_keys: keys } };
    }
    return { action: 'DEFENDER', details: { ...details, command_keys: keys } };
  }
  if (p.agent === 'patchManagement') {
    // Dispatch-time only: "we told the agent to do this", not "it worked". The
    // verified outcome is audited by the patch_job_push handler with its own
    // SUCCESS/FAILURE actions. Covers the direct (non-AI) WS dispatch path only
    // — the AI /api/ai/confirm/:id path audits its own dispatch via
    // ACTION_TO_AUDIT.
    return {
      action: 'WINDOWS_PATCH_INSTALL_DISPATCHED',
      details: { ...details, sub_action: p.action, job_id: p.arg1 ?? null },
    };
  }
  return null;
}

async function logWsAuditIfNeeded(
  req: ReqLike,
  data: WebSocRevMessage,
  status: 'success' | 'failure' = 'success',
  reason?: string,
  // Callers in this file already resolved this payload via
  // resolveNodeUiWsSession; passing it through avoids a second cookie-parse,
  // jwt.verify and blacklist check per auditable action. Falls back to
  // re-deriving for a caller that does not have it to hand.
  knownPayload?: Awaited<ReturnType<typeof getWsJwtPayload>>,
): Promise<void> {
  const mapped = getWsAuditAction(data);
  if (!mapped) return;
  const payload = knownPayload ?? await getWsJwtPayload(req);
  if (!payload) {
    logger.warn(
      { hostIdentifier: data.host_identifier, action: mapped.action },
      'WS audit trail skipped, no JWT payload resolved for an auditable action',
    );
    return;
  }

  // Enrich with hostname from nodes table (fleet DB, ds[1]).
  try {
    const ds = dbSourceConnection();
    const fleetDb = ds?.[1];
    if (fleetDb?.isInitialized) {
      const rows = await fleetDb.query(
        'SELECT hostname FROM nodes WHERE host_identifier = $1 LIMIT 1',
        [data.host_identifier],
      );
      const hostname = rows?.[0]?.hostname != null ? String(rows[0].hostname) : null;
      if (hostname) mapped.details.hostname = hostname;
    }
  } catch (err) {
    logger.warn({ err, hostIdentifier: data.host_identifier }, 'Hostname lookup for audit enrichment failed');
  }

  if (reason) mapped.details.failure_reason = reason;

  await logAuditTrail({
    action: mapped.action,
    status: status,
    userId: payload.id,
    email: payload.email,
    details: mapped.details,
  });
}

// nodeUi

export function nodeUi(ws: WsLike, req: ReqLike): void {
  const ptCli = allocClientSlot(ws);
  if (ptCli < 0) {
    logger.error({ poolSize: WS_POOL_SIZE }, 'nodeUi connection rejected, client slot pool exhausted');
    ws.close(1013, 'Server at capacity');
    return;
  }
  wsToClientIndex.set(ws, ptCli);
  logger.debug({ slot: ptCli }, 'UI client connected');

  // Resolve this client's node-group scope once, at connect. The push broadcast
  // reads CLIENT_SCOPES[slot] and cannot do I/O, so the scope must already be
  // resident when a push arrives; the message handler below then keeps it
  // current from the session it already resolves.
  //
  // Detached rather than awaited because nodeUi is synchronous (index.ts does
  // not await it). Until it lands the slot's scope is null, which the broadcast
  // treats as unknown and fails closed, so a just-connected client can miss one
  // push. That is accepted: the window is a single indexed lookup on a socket
  // that has not rendered yet, and every push type is re-derivable from the
  // scoped REST endpoints. Failing open would reopen the leak this closes.
  void (async () => {
    try {
      const session = await resolveNodeUiWsSession(req);
      // The socket may have closed, or its slot been recycled, while the lookup
      // was in flight; writing the scope then would attach this user's group
      // membership to whoever now holds the slot.
      if (wsToClientIndex.get(ws) !== ptCli) return;
      if (!session) {
        // Same condition the message handler treats as fatal. Leave the scope
        // unresolved so the client receives no pushes; its first message closes
        // the socket with 1008.
        logger.warn({ slot: ptCli }, 'UI client scope unresolved, session invalid — client will receive no agent pushes');
        return;
      }
      setClientScope(ptCli, session.scope);
    } catch (err) {
      logger.error({ err, slot: ptCli }, 'Failed to resolve node scope for UI client, client will receive no agent pushes');
    }
  })();

  ws.on('message', async (...args: unknown[]) => {
    // Top-level try/catch so no unhandled rejection can crash the process.
    // hostIdForLog is set as soon as the message parses, so the catch below can
    // attribute an unhandled error to a host.
    let hostIdForLog: string | undefined;
    try {
      const raw = args[0];
      const message = typeof raw === 'string' ? raw : (raw as { toString?(): string })?.toString?.() ?? '';
      const data = ValidateMessage(message);
      if (!data) {
        logger.warn({ messageLength: message.length }, 'nodeUi message rejected, not valid JSON or missing host_identifier');
        safeSend(ws, 'Please send a valid JSON', 'nodeUi');
        return;
      }
      hostIdForLog = data.host_identifier;

      const uiSession = await resolveNodeUiWsSession(req);
      if (!uiSession) {
        logger.warn({ hostIdentifier: data.host_identifier }, 'nodeUi message rejected, session invalid or account suspended');
        ws.close(1008, 'Account suspended or session invalid');
        return;
      }

      const { effectiveRole, scope } = uiSession;

      // Keep the push-broadcast scope current for free: resolveNodeUiWsSession
      // just re-read role and group membership for this message's own checks, so
      // a user demoted or moved between groups mid-session stops receiving
      // out-of-scope pushes from their next message onward.
      //
      // Slot-guarded like the connect path. `ptCli` was captured in this
      // closure, but resolveNodeUiWsSession awaited on the way here; if the
      // socket closed during that await the close handler has already returned
      // the slot to clientFreeList, which is LIFO, so the next connection holds
      // the same index. Writing the departed user's scope then would stamp it
      // onto whoever now owns the slot.
      //
      // Guards only the scope write, not the whole handler: bailing out would
      // also drop a command for a user who disconnected mid-flight.
      if (wsToClientIndex.get(ws) === ptCli) {
        setClientScope(ptCli, scope);
      }

      if (data.type === 'agent' && isViewerRole(effectiveRole) && !isViewerReadOnlyAgentCommand(data)) {
        const rid = data.rid ?? generateUniqueID();
        logger.warn(
          { hostIdentifier: data.host_identifier, agent: data.params?.agent, action: data.params?.action },
          'nodeUi request rejected, viewer role attempted a non-read-only agent command',
        );
        safeSend(
          ws,
          JSON.stringify({ error: 'Viewer role can only run read-only websocket requests', rid }),
          'nodeUi',
        );
        return;
      }

      // Windows patch install/uninstall/check must never go through this raw
      // forwarding path. The dedicated REST route
      // (routes/api/windowsPatchManagement.ts) requires Super Administrator plus
      // fresh MFA and sources install_script only from the reviewed
      // maintained_app_versions catalog. This handler enforces just group-level
      // "act" permission, which would let such a user forward an arbitrary
      // install_script to run as SYSTEM. mcp/executor.ts rejects the same
      // actions on the AI path.
      if (data.type === 'agent' && data.params?.agent === 'patchManagement') {
        const rid = data.rid ?? generateUniqueID();
        logger.warn(
          { hostIdentifier: data.host_identifier, action: data.params?.action },
          'nodeUi request rejected, patchManagement agent commands must go through the Windows Patch Management UI',
        );
        safeSend(
          ws,
          JSON.stringify({ error: 'Windows patch install/uninstall/check must go through the Patch Management UI', rid }),
          'nodeUi',
        );
        return;
      }

      // Group-scoped users may only act on hosts in their assigned groups. Every
      // action (isolate/block/allow, compliance check, USB/firewall/defender
      // toggles) shares this one handler, so the check lives here.
      //
      // A mutating command additionally requires "act" permission on the owning
      // group: a per-group Viewer membership is read-only within that group,
      // like the isViewerRole() check above but scoped to one group.
      if (data.host_identifier) {
        const isMutatingAgentCommand = data.type === 'agent' && !isViewerReadOnlyAgentCommand(data);
        const allowed = isMutatingAgentCommand
          ? await assertCanActOnHost(scope, data.host_identifier)
          : await assertHostInScope(scope, data.host_identifier);
        if (!allowed) {
          const rid = data.rid ?? generateUniqueID();
          logger.warn(
            { hostIdentifier: data.host_identifier, isMutatingAgentCommand },
            'nodeUi request rejected, host outside caller node scope',
          );
          safeSend(
            ws,
            JSON.stringify({ error: 'You do not have access to this node', rid }),
            'nodeUi',
          );
          return;
        }
      }



      // Preserve the frontend rid if present; generate one if not.
      const rid = data.rid ?? generateUniqueID();
      data.rid  = rid;

      // Store rid -> UI slot. Redis is primary, in-memory ridToUiSlot the
      // fallback; both are written on every request so routing survives a Redis
      // outage.
      //
      // Slot-guarded like the setClientScope write above: several awaits have
      // happened since `ptCli` was captured, and if the socket closed during one
      // the slot is already back on the LIFO free list and held by the next
      // connection. Registering the rid then routes this user's agent response
      // to that user.
      //
      // When the slot is no longer ours the rid is left unregistered on purpose:
      // the response finds no route and is dropped, which is correct because the
      // client that asked for it is gone. releaseClientSlot's rid eviction
      // cannot cover this, because the free happens before this registration.
      const redis = getRedisClient();
      if (wsToClientIndex.get(ws) === ptCli) {
        if (redis) {
          redis.set(ridKey(rid), String(ptCli), { EX: RID_EXPIRY_SECONDS })
            .catch((err: unknown) => logger.error({ err, rid }, 'Redis rid routing key set failed'));
        }
        ridToUiSlot.set(rid, { slot: ptCli, expiresAt: Date.now() + RID_EXPIRY_MS });
      } else {
        logger.warn({ rid, slot: ptCli }, 'nodeUi rid not registered, socket closed and slot reassigned before routing was recorded');
      }

      // Resolve the extension slot: Redis is authoritative, in-memory
      // hostToExtSlot is consulted only when Redis is unavailable.
      //
      // A slot index from either store can be stale — the entry survives a
      // failed DEL, a crash or a Redis flush while the slot is re-allocated to a
      // different agent. Forwarding without checking extSlotToHost would deliver
      // this command, possibly an isolate/block, to the wrong machine. Stale
      // entries are deleted so they cannot misroute again.
      let extIndex = -1;
      if (redis) {
        const val = await redis.get(extKey(data.host_identifier)).catch((err: unknown) => {
          // Without this a Redis outage during the lookup is absorbed into "no
          // extension found" and falls through to the in-memory fallback with no
          // trace of why Redis was skipped.
          logger.warn({ err, hostIdentifier: data.host_identifier }, 'Redis extension routing lookup failed, falling back to in-memory table');
          return null;
        });
        if (val != null) {
          const parsed = parseInt(val, 10);
          if (Number.isFinite(parsed)) extIndex = parsed;
        }
        if (extIndex >= 0
            && (extIndex >= WS_POOL_SIZE || extSlotToHost[extIndex] !== data.host_identifier)) {
          logger.warn(
            {
              hostIdentifier: data.host_identifier,
              slot: extIndex,
              slotOwner: extIndex < WS_POOL_SIZE ? (extSlotToHost[extIndex] ?? 'nobody') : 'out-of-range',
            },
            'Stale Redis routing entry, discarding key',
          );
          redis.del(extKey(data.host_identifier)).catch(() => {});
          extIndex = -1;
        }
      }
      if (extIndex < 0) {
        extIndex = hostToExtSlot.get(data.host_identifier) ?? -1;
        if (extIndex >= 0 && extSlotToHost[extIndex] !== data.host_identifier) {
          logger.warn({ hostIdentifier: data.host_identifier, slot: extIndex }, 'Stale in-memory routing entry, discarding');
          hostToExtSlot.delete(data.host_identifier);
          extIndex = -1;
        }
      }

      if (extIndex < 0 || extIndex >= WS_POOL_SIZE || EXTENSIONS[extIndex] === null) {
        // Extension not connected — fail fast instead of leaving the UI hanging.
        logger.info({ hostIdentifier: data.host_identifier, rid }, 'No extension connected for host, rejecting request');
        ridToUiSlot.delete(rid);
        if (redis) redis.del(ridKey(rid)).catch(() => {});
        safeSend(ws, JSON.stringify({ error: 'Agent not connected', rid }), 'nodeUi');
        logWsAuditIfNeeded(req, data, 'failure', 'Agent not connected', uiSession.jwt).catch((err) => logger.error({ err, hostIdentifier: data.host_identifier }, 'Failed to log WS audit entry'));
        return;
      }

      // Forward to extension
      const sent = safeSend(EXTENSIONS[extIndex]!, JSON.stringify(data), 'nodeUi→ext');
      if (sent) {
        IsolateMachine(data);
        // Log successful forwards of mutating agent commands (block/allow,
        // wifi/bluetooth/USB toggles, clamav scans, agent binary updates).
        // Read-only status commands are excluded so routine dashboard polling
        // does not flood the log.
        if (data.type === 'agent' && !isViewerReadOnlyAgentCommand(data)) {
          logger.info(
            { hostIdentifier: data.host_identifier, agent: data.params?.agent, action: data.params?.action, rid },
            'Mutating agent command forwarded to agent',
          );
        } else if (data.type !== 'agent') {
          // Non-'agent' message types (currently only 'osquery') take this same
          // forward path, but getWsAuditAction() maps only 'agent' messages, so
          // logWsAuditIfNeeded is a no-op for them and this is their only trace.
          logger.info(
            { hostIdentifier: data.host_identifier, type: data.type, rid },
            'Non-agent message type forwarded to agent',
          );
        }
        logWsAuditIfNeeded(req, data, 'success', undefined, uiSession.jwt).catch((err) => logger.error({ err, hostIdentifier: data.host_identifier }, 'Failed to log WS audit entry'));
      } else {
        // Extension socket is a zombie (TCP half-open, not yet caught by the
        // heartbeat). Evict the stale slot and drive a clean offline update, or
        // agent_online stays true in the DB until the next server restart.
        const deadSlot = extIndex;
        const deadHostId = extSlotToHost[deadSlot];
        const deadWs = EXTENSIONS[deadSlot];
        if (deadHostId && hostToExtSlot.get(deadHostId) === deadSlot) {
          hostToExtSlot.delete(deadHostId);
        }

        // releaseExtSlot also removes the socket from wsToExtIndex, so the
        // eventual nodeExt.on('close') finds no index and cannot push the slot
        // onto extFreeList a second time.
        releaseExtSlot(deadSlot, deadWs ?? undefined);

        // Mark the agent offline and clear its Redis routing key here, because
        // hostToExtSlot has already been cleared: nodeExt.on('close') would
        // resolve isOwner=false and skip UpdateAgentStatus.
        if (deadHostId) {
          UpdateAgentStatus(deadHostId, false);
          if (redis) redis.del(extKey(deadHostId)).catch(() => {});
        }

        ridToUiSlot.delete(rid);
        if (redis) redis.del(ridKey(rid)).catch(() => {});
        safeSend(ws, JSON.stringify({ error: 'Agent connection error', rid }), 'nodeUi');
        logger.warn({ hostIdentifier: deadHostId, slot: deadSlot, rid }, 'Evicted dead extension slot after failed forward, marked host offline');
        logWsAuditIfNeeded(req, data, 'failure', 'Agent connection error (send failed)', uiSession.jwt).catch((err) => logger.error({ err, hostIdentifier: deadHostId }, 'Failed to log WS audit entry'));
      }
    } catch (err) {
      logger.error({ err, hostIdentifier: hostIdForLog }, 'Unhandled nodeUi message handler error');
    }
  });

  ws.on('close', (...args: unknown[]) => {
    const reason = typeof args[1] === 'string' ? args[1] : '';

    const idx = wsToClientIndex.get(ws);
    if (idx !== undefined) {
      // releaseClientSlot() nulls the slot, unindexes the socket, returns the
      // index to the free list and evicts every in-flight rid (and its Redis
      // key) still pointing at it. That last part matters: once the slot is back
      // on the free list a new browser client can be handed it, and a surviving
      // rid would route the old request's agent response to them.
      releaseClientSlot(idx, ws);
    }

    logger.debug({ reason: reason || undefined }, 'UI client disconnected');
  });
}

// Agent status job queue

const jobQueue: Job[] = [];

function UpdateAgentStatus(hostIdentifier: string, online: boolean): boolean {
  const pgClient = dbSourceConnection();
  // nodes table lives in the fleet (secondary) DB — pgClient[1]
  if (!pgClient || pgClient.length < 2) {
    logger.warn({ hostIdentifier, online, queueLength: jobQueue.length + 1 }, 'Fleet DB unavailable, agent status update queued for later drain');
    jobQueue.push({ hostIdentifier, online });
    return false;
  }
  const db = pgClient[1];
  db.query('UPDATE nodes SET agent_online = $1 WHERE host_identifier = $2', [online, hostIdentifier])
    .then(() => {
      // Notify the live dashboard only after the write commits: getNodesStatus()
      // runs NODE_STATUS_DEBOUNCE_MS later, so its SELECT reads this value.
      emitNodeStatusChange();
    })
    .catch((err: unknown) => logger.error({ err, hostIdentifier, online }, 'Failed to update agent status'));
  return true;
}

export const jobDrainInterval = setInterval(() => {
  let drained = 0;
  for (let i = 0; i < JOB_DRAIN_PER_TICK && jobQueue.length > 0; i++) {
    const job = jobQueue.shift()!;
    if (!UpdateAgentStatus(job.hostIdentifier, job.online)) {
      jobQueue.unshift(job);
      break;
    }
    drained++;
  }
  if (drained > 0) {
    logger.info({ drained, remaining: jobQueue.length }, 'Drained queued agent status jobs');
  }
}, JOB_DRAIN_INTERVAL_MS);

// nodeExt

export function nodeExt(ws: WsLike, req: ReqLike): void {
  const agentExtInfoHeader = req.headers['agent-info'];
  if (!agentExtInfoHeader) {
    logger.warn('Agent connection rejected, missing agent-info header');
    ws.close(1008, 'Missing agent-info header');
    return;
  }

  const ptExt = allocExtSlot(ws);
  if (ptExt < 0) {
    logger.error({ poolSize: WS_POOL_SIZE }, 'Agent connection rejected, extension slot pool exhausted');
    ws.close(1013, 'Server at capacity');
    return;
  }
  wsToExtIndex.set(ws, ptExt);

  let agentInfo: { host_identifier?: string };
  try {
    agentInfo = JSON.parse(agentExtInfoHeader);
  } catch (err) {
    logger.warn({ err }, 'Agent connection rejected, invalid agent-info JSON');
    releaseExtSlot(ptExt, ws);
    ws.close(1008, 'Invalid agent-info JSON');
    return;
  }

  const hostId = agentInfo.host_identifier;
  if (!hostId || typeof hostId !== 'string') {
    logger.warn('Agent connection rejected, missing host_identifier in agent-info');
    releaseExtSlot(ptExt, ws);
    ws.close(1008, 'Missing host_identifier in agent-info');
    return;
  }

  // Register in the routing tables. Redis is primary, in-memory hostToExtSlot
  // the fallback, and both are written on every connect. Always overwrite: a
  // reconnecting agent must point at the new slot immediately.
  const redis = getRedisClient();
  if (redis) {
    redis.set(extKey(hostId), String(ptExt), { EX: CONN_EXPIRY_SECONDS })
      .catch((err: unknown) => logger.error({ err, hostId }, 'Redis routing key set failed'));
  }
  hostToExtSlot.set(hostId, ptExt);
  extSlotToHost[ptExt] = hostId;

  UpdateAgentStatus(hostId, true);
  logger.info({ hostId, slot: ptExt }, 'Agent connected');

  // Replay Patch Management commands queued while this host was offline.
  // dispatchToAgent is a hoisted function declaration further down this file.
  void dispatchPendingPatchCommands(hostId, dispatchToAgent);

  // Re-apply every enabled policy targeting this host; same hoisting note as
  // above. See services/policyEnforcement.ts.
  void reapplyEnabledPoliciesForHost(hostId, dispatchToAgent);

  // Routing-key keep-alive. ws:ext:{hostId} carries a 24 h TTL but agent
  // connections routinely outlive it. An expired key under a healthy connection
  // makes liveWeb's cleanup loop see agent_online=true with no Redis key and
  // flip the node offline permanently, since nothing on an established
  // connection ever sets agent_online back to true.
  //
  // Refreshed on every heartbeat pong and on every inbound agent message (so
  // this survives a future decision to stop pinging /ws/ext), throttled to one
  // EXPIRE per EXT_ROUTING_REFRESH_MIN_MS. If EXPIRE reports the key missing,
  // re-create it and restore agent_online, which the cleanup loop may already
  // have cleared.
  let lastRoutingRefreshMs = Date.now();
  const refreshExtRouting = (): void => {
    // Ownership guard: if a newer connection for this host has taken over the
    // routing tables, this older socket must not resurrect its entry.
    if (hostToExtSlot.get(hostId) !== ptExt) return;
    const now = Date.now();
    if (now - lastRoutingRefreshMs < EXT_ROUTING_REFRESH_MIN_MS) return;
    lastRoutingRefreshMs = now;

    const freshRedis = getRedisClient();
    if (!freshRedis) return;
    freshRedis.expire(extKey(hostId), CONN_EXPIRY_SECONDS)
      .then((refreshed: boolean | number) => {
        if (!refreshed) {
          // NX so a fresh key written by a reconnecting agent between the
          // EXPIRE and this SET is never overwritten with this older slot index.
          freshRedis.set(extKey(hostId), String(ptExt), { EX: CONN_EXPIRY_SECONDS, NX: true })
            .catch((err: unknown) => logger.error({ err, hostId }, 'Routing self-heal SET failed'));
          UpdateAgentStatus(hostId, true);
          logger.warn({ hostId, slot: ptExt }, 'Restored missing routing key');
        }
      })
      .catch((err: unknown) => logger.error({ err, hostId, slot: ptExt }, 'Routing key EXPIRE refresh failed'));
  };
  ws.on('pong', refreshExtRouting);

  ws.on('message', async (...args: unknown[]) => {
    try {
      refreshExtRouting();
      const raw = args[0];
      const message = typeof raw === 'string' ? raw : (raw as { toString?(): string })?.toString?.() ?? '';
      // Extension responses need a valid rid for routing; host_identifier is
      // not required, and agents do not reliably echo it.
      const data = ValidateExtResponse(message);
      if (!data) {
        logger.warn({ hostId, messageLength: message.length }, 'nodeExt message rejected, not valid JSON or missing rid');
        safeSend(ws, 'Please send a valid JSON', 'nodeExt');
        return;
      }

      // Immediate ack for a server-initiated Patch Management dispatch.
      // createPatchJob and dispatchNextPendingPatchCommand mint a synthetic rid
      // "osupdate_ack:<patch_job_node id>" when dispatching an osupdate command.
      // These dispatches do not originate from a UI socket, so there is no
      // CLIENTS[] slot to route the ack to and it is intercepted by rid prefix
      // here rather than falling through to rid resolution and being dropped.
      // The agent echoes back whatever rid it was sent.
      if (typeof data.rid === 'string' && data.rid.startsWith(RID_PREFIX_OSUPDATE_ACK)) {
        try {
          const nodeId = Number(data.rid.slice(RID_PREFIX_OSUPDATE_ACK.length));
          const db = dbSourceConnection();
          if (Number.isInteger(nodeId) && nodeId > 0 && db && db.length >= 2 && db[1].isInitialized) {
            const fleetDb = db[1];
            const ackRaw = typeof data.response === 'string' ? JSON.parse(data.response as string) : data.response;
            const ack = (ackRaw && typeof ackRaw === 'object') ? ackRaw as Record<string, unknown> : null;
            const taskId = ack && typeof ack.task_id === 'string' ? ack.task_id : null;
            if (taskId) {
              // Agent accepted and started the job. task_id is the key
              // osupdate_result correlates on.
              await fleetDb.query(
                `UPDATE patch_job_nodes SET task_id = $1, status = 'acked', updated_at = NOW()
                   WHERE id = $2 AND LOWER(host_identifier) = LOWER($3) AND status = 'dispatched'`,
                [taskId, nodeId, hostId],
              );
              logger.info({ hostId, nodeId, taskId }, 'Osupdate command acked by agent');
            } else {
              // errorJSON shape: the agent refused to start (its single-flight
              // guard was held, no supported package manager, unsupported
              // action). Fail the row now rather than waiting for the stale-job
              // sweep to relabel it timed_out.
              const errMsg = ack && typeof ack.error === 'string' ? ack.error : 'osupdate did not start';
              await fleetDb.query(
                `UPDATE patch_job_nodes SET status = 'failed', failure_reason = $1, completed_at = NOW(), updated_at = NOW()
                   WHERE id = $2 AND LOWER(host_identifier) = LOWER($3) AND status = 'dispatched'`,
                [String(errMsg).slice(0, PATCH_REASON_MAX_LENGTH), nodeId, hostId],
              );
              logger.warn({ hostId, nodeId, reason: errMsg }, 'Osupdate command refused by agent');
            }
            // A refusal frees this host for its next queued command. After a
            // genuine ack the row is 'acked' and still busy, so
            // dispatchNextPendingPatchCommand's own check no-ops.
            void dispatchNextPendingPatchCommand(hostId, dispatchToAgent);
          } else {
            // The rid did not parse to a positive integer, or the fleet DB is
            // not ready. The row stays 'dispatched' until the stale-job sweep
            // relabels it timed_out.
            logger.warn(
              { rid: data.rid, hostId, nodeId, dbReady: !!(db && db.length >= 2 && db[1].isInitialized) },
              'Osupdate ack could not be applied, row left dispatched until stale-job sweep',
            );
          }
        } catch (err) {
          logger.error({ err, rid: data.rid, hostId }, 'Osupdate ack parse/DB error');
        }
        return;
      }

      // Immediate ack for a Windows maintained-app install/uninstall. Mirrors
      // the osupdate_ack: branch above, for the unrelated Windows
      // software-install feature. guardrails.ts's buildWsPayload sets
      // rid = "patch_job_ack:<job_id>" and the agent echoes it on its
      // synchronous accept/reject reply, distinct from the later async
      // patch_job_push completion. job_id is the UUID PK of windows_patch_jobs,
      // so no numeric-id lookup is needed.
      if (typeof data.rid === 'string' && data.rid.startsWith(RID_PREFIX_PATCH_JOB_ACK)) {
        const jobId = data.rid.slice(RID_PREFIX_PATCH_JOB_ACK.length);
        try {
          const db = dbSourceConnection();
          if (db && db.length >= 2 && db[1].isInitialized) {
            const fleetDb = db[1];
            const ackRaw = typeof data.response === 'string' ? JSON.parse(data.response as string) : data.response;
            const ack = (ackRaw && typeof ackRaw === 'object') ? ackRaw as Record<string, unknown> : null;
            if (ack && typeof ack.status === 'string' && ack.status === 'acknowledged') {
              await fleetDb.query(
                `UPDATE windows_patch_jobs SET status = 'acknowledged', acknowledged_at = NOW()
                   WHERE id = $1 AND LOWER(host_identifier) = LOWER($2) AND status = 'pending'`,
                [jobId, hostId],
              );
              logger.info({ hostId, jobId, note: ack.note ?? null }, 'Windows patch job acked by agent');
            } else {
              const errMsg = ack && typeof ack.error === 'string' ? ack.error : 'agent rejected the job';
              await fleetDb.query(
                `UPDATE windows_patch_jobs SET status = 'rejected', outcome_reason = $1, completed_at = NOW()
                   WHERE id = $2 AND LOWER(host_identifier) = LOWER($3) AND status = 'pending'`,
                [String(errMsg).slice(0, 1000), jobId, hostId],
              );
              logger.warn({ hostId, jobId, reason: errMsg }, 'Windows patch job rejected by agent');
            }
          } else {
            logger.warn({ rid: data.rid, hostId, jobId }, 'Windows patch job ack could not be applied, fleet DB unavailable');
          }
        } catch (err) {
          logger.error({ err, rid: data.rid, hostId, jobId }, 'Windows patch job ack parse/DB error');
        }
        return;
      }

      // Synchronous reply for an on-demand Windows maintained-app check.
      // guardrails.ts's buildWsPayload sets rid = "patch_check:<uuid>" purely so
      // the agent has a non-empty rid to echo (ValidateExtResponse requires
      // one). There is no delivery path back to the proposer: the AI confirm
      // flow has no live UI socket holding this HTTP-scoped rid, which is why
      // patch_check is not in guardrails.ts's ALLOWED_ACTION_TYPES. This branch
      // drains any reply that is still in flight and logs the outcome instead of
      // letting it be rejected as an unrecognised rid.
      if (typeof data.rid === 'string' && data.rid.startsWith(RID_PREFIX_PATCH_CHECK)) {
        try {
          const result = typeof data.response === 'string' ? JSON.parse(data.response as string) : data.response;
          logger.debug(
            { hostId, rid: data.rid, resultCount: Array.isArray(result) ? result.length : undefined },
            'Windows patch check result received',
          );
        } catch (err) {
          logger.error({ err, rid: data.rid, hostId }, 'Windows patch check reply parse error');
        }
        return;
      }

      // Agent-initiated push messages. Agents use the rid field as a
      // message-type sentinel rather than a request-correlation id, so these
      // bypass the normal rid routing path: they are broadcast to in-scope UI
      // clients and persisted.
      // clamav_push:        Linux ClamAV malware detections (store-and-forward).
      // clamav_status_push: clamd daemon health and signature DB version.
      // clamav_scan_push:   completion summary of an async scan, which is ack'd
      //                     immediately because rid routing expires after 60 s.
      // osupdate_result:    completion of a Patch Management op, correlated to
      //                     patch_job_nodes by task_id.
      // patch_job_push:     completion of a Windows maintained-app install or
      //                     uninstall (third-party software, not Windows Update,
      //                     and unrelated to osupdate_result), correlated to
      //                     windows_patch_jobs by job_id.
      if (data.rid === 'defender_push' || data.rid === 'usb_device_push' || data.rid === 'wifi_push'
          || data.rid === 'clamav_push' || data.rid === 'clamav_status_push' || data.rid === 'clamav_scan_push'
          || data.rid === 'firewall_status_push' || data.rid === 'packages_push' || data.rid === 'osupdate_result'
          || data.rid === 'patch_job_push') {
        const pushType = data.rid;
        // Attach host_identifier so the UI knows which node sent this push.
        const enriched = { ...data, host_identifier: hostId };
        const payload = JSON.stringify(enriched);

        // Broadcast to every in-scope connected UI client, using the same rule
        // as liveWeb.ts's broadcastToLiveClients(): in scope iff the client is
        // unrestricted, or the pushing host has an owning group that is in the
        // client's membership. A host with no owning group in the index is
        // invisible to scoped clients, matching computeScopedNodeStatus() and
        // the REST endpoints. Keep the two rules identical.
        //
        // This is a hot path, so the group-membership test runs at most once per
        // distinct scope cohort per push (cached under the precomputed cohort
        // key), never once per client.

        // Only pay for the host->group snapshot when a scoped client is
        // connected; with unrestricted clients only, no query is ever issued.
        if (scopedClientCount > 0) refreshHostOwnerGroupIndexIfStale();
        const pushOwnerGroupId = hostOwnerGroupIndex.get(hostId);
        const cohortDecisions = new Map<string, boolean>();

        let pushPruned = 0;
        let pushOutOfScope = 0;
        let pushScopeUnresolved = 0;
        let pushBackpressureDropped = 0;
        let pushBackpressureClosed = 0;
        for (let i = 0; i < WS_POOL_SIZE; i++) {
          const client = CLIENTS[i];
          if (client === null) continue;

          const entry = CLIENT_SCOPES[i];
          if (entry === null) {
            // Scope not resolved yet, or resolution failed. Fail closed; see
            // the note in nodeUi.
            pushScopeUnresolved++;
            continue;
          }
          let allowed = cohortDecisions.get(entry.cohortKey);
          if (allowed === undefined) {
            allowed = entry.scope.unrestricted
              || (!!pushOwnerGroupId && entry.scope.groups.some((g) => g.id === pushOwnerGroupId));
            cohortDecisions.set(entry.cohortKey, allowed);
          }
          if (!allowed) {
            pushOutOfScope++;
            continue;
          }

          // Backpressure guard. safeSend() only catches throws; `ws` will queue
          // an unbounded send buffer for a browser that has stopped reading
          // (suspended tab, dead Wi-Fi not yet TCP-timed-out). The UI and agent
          // channels share one process, so an unbounded UI buffer is an
          // agent-comms outage waiting to happen. Drop frames for a backed-up
          // client, close one that is hopeless. bufferedAmount is undefined on
          // sockets that do not expose it, reading as 0 and disabling the guard
          // rather than misfiring.
          const buffered = client.bufferedAmount ?? 0;
          if (buffered >= UI_PUSH_BUFFER_CLOSE_BYTES) {
            pushBackpressureClosed++;
            // Do not free the slot here: the 'close' handler does the full
            // teardown, and freeing twice is the double-free releaseClientSlot()
            // exists to prevent.
            try { client.close(1013, 'Client too slow'); } catch { /* already closing */ }
            continue;
          }
          if (buffered >= UI_PUSH_BUFFER_DROP_BYTES) {
            pushBackpressureDropped++;
            continue;
          }

          // safeSend threw, so the socket is dead: free the slot now instead of
          // hitting it on every future broadcast, and close it so the browser
          // notices. Freeing alone leaves the tab believing it is still
          // connected while receiving nothing — every later request then burns
          // its full timeout instead of onclose triggering the frontend's
          // reconnect/backoff. close() makes the later 'close' handler run its
          // own teardown too; releaseClientSlot() is idempotent for exactly this
          // free-then-close ordering (see nodeSlotPool.selftest.ts's double-free
          // case), so the slot cannot be handed to two clients.
          if (!safeSend(client, payload, `nodeExt[${pushType}]→ui`, true)) {
            releaseClientSlot(i, client);
            try { client.close(1011, 'Push delivery failed'); } catch { /* already closing */ }
            pushPruned++;
          }
        }
        // safeSend() logs each individual failure; this adds the batch outcome
        // so a run of dropped UI updates is visible as a trend.
        if (pushPruned > 0) {
          logger.warn({ hostId, pushType, pruned: pushPruned }, 'Pruned dead UI clients during push broadcast');
        }
        if (pushBackpressureDropped > 0 || pushBackpressureClosed > 0) {
          logger.warn(
            { hostId, pushType, dropped: pushBackpressureDropped, closed: pushBackpressureClosed },
            'UI push frames withheld from backed-up clients (send buffer over threshold)',
          );
        }
        if (pushScopeUnresolved > 0) {
          // Expected only between connect and the scope lookup landing. A
          // sustained non-zero count means scope resolution is failing and
          // scoped users are silently receiving no pushes.
          logger.debug({ hostId, pushType, unresolved: pushScopeUnresolved }, 'UI push skipped for clients with unresolved scope');
        }
        if (pushOutOfScope > 0) {
          logger.debug({ hostId, pushType, outOfScope: pushOutOfScope }, 'UI push withheld from out-of-group clients');
        }

        // Persist to DB (best-effort; errors caught so a missing table doesn't crash the handler).
        try {
          const db = dbSourceConnection();
          if (db && db.length >= 2 && db[1].isInitialized) {
            const entityManager = db[1];

            if (pushType === 'defender_push' || pushType === 'usb_device_push') {
              // Both of these send a JSON array as the response payload.
              const rows: unknown[] = JSON.parse(String(data.response ?? '[]'));
              if (Array.isArray(rows)) {
                // The inserts below are fire-and-forget, so without this the
                // batch size is invisible and "no alerts appeared" looks the same
                // as "nothing was sent".
                logger.info({ hostId, pushType, count: rows.length }, 'Processing push batch');
                if (pushType === 'defender_push') {
                  // Settles once every insert in the batch has resolved and
                  // reports the total, so the batch outcome does not have to be
                  // reconstructed from scattered per-row error lines.
                  let insertFailures = 0;
                  // Thunks, not started promises, so runBounded() can cap how
                  // many are in flight (see PUSH_INSERT_CONCURRENCY). Per-row
                  // values are still computed here in the loop.
                  const insertTasks: (() => Promise<unknown>)[] = [];
                  for (const row of rows as any[]) {
                    insertTasks.push(() => entityManager.query(
                      `INSERT INTO defender_alerts
                         (host_identifier, source, threat_id, threat_name, severity,
                          action_success, initial_detection_time, last_threat_status_change,
                          resources, process_name, event_id, message, level, record_id)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                       ON CONFLICT DO NOTHING`,
                      [hostId, row.source, row.threat_id, row.threat_name, row.severity,
                       row.action_success, row.initial_detection_time, row.last_threat_status_change,
                       row.resources, row.process_name, row.event_id, row.message, row.level, row.record_id]
                    ).catch((err: unknown) => { insertFailures++; logger.error({ err, hostId, threatId: row.threat_id, eventId: row.event_id }, 'defender_push: defender_alerts insert failed'); }));

                    const rawEventId = String(row.event_id ?? '');
                    const defSeverity  = rawEventId === '5001' ? 'critical' : rawEventId === '5007' ? 'low' : normalizeDefenderSeverity(row.severity);
                    const defEventCode = String(row.event_code || row.threat_name || row.threat_id || 'DEFENDER_ALERT');
                    const defUnixTime  = parseUnixTime(row.initial_detection_time) ?? Math.floor(Date.now() / 1000);
                    const defEventId   = row.event_id != null ? (Number(row.event_id) || null) : null;
                    insertTasks.push(() => entityManager.query(
                      `INSERT INTO alerts
                         (host_identifier, unixTime, event_code, metadata,
                          is_alert, is_open, severity, alert_type, event_id, detection_time)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
                      [hostId, defUnixTime, defEventCode, JSON.stringify(row),
                       true, true, defSeverity, 'Defender Alert', defEventId, defUnixTime]
                    ).catch((err: unknown) => { insertFailures++; logger.error({ err, hostId, threatId: row.threat_id, eventId: defEventId }, 'defender_push: alerts insert failed'); }));
                  }
                  runBounded(insertTasks, PUSH_INSERT_CONCURRENCY).then(() => {
                    if (insertFailures > 0) {
                      logger.warn({ hostId, pushType, count: rows.length, insertFailures }, 'defender_push batch completed with failures');
                    }
                  });
                } else {
                  // usb_device_push — handles both Windows and Linux field layouts.
                  // Windows fields: caption, pnp_device_id, serial_number, size_gb, event_type, detected_at
                  // Linux fields:   vendor, product, serial, dev_name,     size_gb, event_type, detected_at
                  // Same fire-and-forget-with-tally pattern as defender_push.
                  let insertFailures = 0;
                  // Same thunk-plus-runBounded treatment as defender_push.
                  const insertTasks: (() => Promise<unknown>)[] = [];
                  for (const row of rows as any[]) {
                    // Normalise to a common shape so a single insert covers both platforms.
                    const usbCaption  = row.caption  ?? [row.vendor, row.product].filter(Boolean).join(' ') ?? null;
                    const usbDevId    = row.pnp_device_id ?? row.dev_name ?? null;
                    const usbSerial   = row.serial_number ?? row.serial   ?? null;

                    insertTasks.push(() => entityManager.query(
                      `INSERT INTO usb_events
                         (host_identifier, caption, pnp_device_id, serial_number, size_gb, event_type, detected_at)
                       VALUES ($1,$2,$3,$4,$5,$6,$7)
                       ON CONFLICT DO NOTHING`,
                      [hostId, usbCaption, usbDevId, usbSerial, row.size_gb, row.event_type, row.detected_at]
                    ).catch((err: unknown) => { insertFailures++; logger.error({ err, hostId, serial: usbSerial, devId: usbDevId }, 'usb_device_push: usb_events insert failed'); }));

                    // Build a human-readable event_code that works for both platforms:
                    //   Windows: "SanDisk Cruzer Blade — SERIAL"
                    //   Linux:   "Kingston DataTraveler 3.0 — SERIAL"
                    const usbEventCode = [usbCaption, usbSerial].filter(Boolean).join(' — ')
                      || String(row.event_type ?? 'USB_DEVICE');
                    const usbUnixTime  = parseUnixTime(row.detected_at) ?? Math.floor(Date.now() / 1000);
                    insertTasks.push(() => entityManager.query(
                      `INSERT INTO alerts
                         (host_identifier, unixTime, event_code, metadata,
                          is_alert, is_open, severity, alert_type)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                      [hostId, usbUnixTime, usbEventCode, JSON.stringify(row),
                       true, true, 'medium', ALERT_TYPE_USB_DEVICE]
                    ).catch((err: unknown) => { insertFailures++; logger.error({ err, hostId, serial: usbSerial, devId: usbDevId }, 'usb_device_push: alerts insert failed'); }));
                  }
                  runBounded(insertTasks, PUSH_INSERT_CONCURRENCY).then(() => {
                    if (insertFailures > 0) {
                      logger.warn({ hostId, pushType, count: rows.length, insertFailures }, 'usb_device_push batch completed with failures');
                    }
                  });
                }
              } else {
                logger.warn({ hostId, pushType, resultType: typeof rows }, 'Push response was not an array, skipping persist');
              }
            } else if (pushType === 'wifi_push') {
              // wifi_push sends a single JSON object (WifiEvent), not an array.
              // Must be handled outside the Array.isArray guard above.
              const wifiEvent = typeof data.response === 'string'
                ? JSON.parse(data.response as string)
                : data.response;
              if (wifiEvent && typeof wifiEvent === 'object') {
                const c            = (wifiEvent as any).connected    ?? null;
                const savedProfiles = (wifiEvent as any).saved_profiles ?? [];
                const wifiTs       = (wifiEvent as any).timestamp
                  ? new Date((wifiEvent as any).timestamp)
                  : null;
                entityManager.query(
                  `INSERT INTO wifi_events
                     (host_identifier, event_type,
                      connected_ssid, connected_bssid, connected_interface, connected_signal,
                      connected_frequency, connected_channel, connected_bitrate,
                      connected_security, connected_ip, is_connected,
                      saved_profiles, wifi_timestamp)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
                  [
                    hostId,
                    String((wifiEvent as any).event_type ?? 'initial'),
                    c?.ssid        ?? null,
                    c?.bssid       ?? null,
                    c?.interface   ?? null,
                    c?.signal      ?? null,
                    c?.frequency   ?? null,
                    c?.channel     ?? null,
                    c?.bitrate     ?? null,
                    c?.security    ?? null,
                    c?.ip_address  ?? null,
                    c !== null,
                    JSON.stringify(savedProfiles),
                    wifiTs,
                  ]
                )
                  .then(() => logger.debug({ hostId, eventType: (wifiEvent as any).event_type }, 'wifi_push: event persisted'))
                  .catch((err: unknown) => logger.error({ err, hostId }, 'wifi_push: insert failed'));
              } else {
                logger.warn({ hostId, pushType, resultType: typeof wifiEvent }, 'wifi_push payload was not a valid object, skipping persist');
              }
            } else if (pushType === 'clamav_push') {
              // clamav_push sends a JSON array of ClamAV malware detections.
              // Alert fields: source, scan_type, path, signature, status, detected_at
              //
              // Idempotent ingest: the agent's store-and-forward buffer clears
              // only after a successful WS write, so a crash in that window can
              // redeliver the same batch on reconnect. A redelivered row is
              // byte-identical (same metadata JSON + timestamp), so skip exact
              // duplicates instead of double-alerting.
              const rows: unknown[] = JSON.parse(String(data.response ?? '[]'));
              if (Array.isArray(rows)) {
                // Same rationale as defender_push/usb_device_push: these upserts
                // are fire-and-forget, so the batch size is otherwise invisible.
                logger.info({ hostId, pushType, count: rows.length }, 'Processing push batch');
                let upsertFailures = 0;
                // Thunks so runClamavBatchSerialised() can execute them one at a
                // time: the bump-or-insert CTE below only de-duplicates if each
                // statement observes the ones before it.
                const upsertTasks: (() => Promise<unknown>)[] = [];
                for (const row of rows as any[]) {
                  const clamUnixTime = parseUnixTime(row.detected_at) ?? Math.floor(Date.now() / 1000);
                  const eventCode    = String(row.signature ?? 'MALWARE_DETECTED');
                  const metadataJson = JSON.stringify(row);
                  const alertPath    = String(row.path ?? '');
                  // EDR-style aggregation, one atomic statement:
                  //   1. If an OPEN alert for the same host+signature+path
                  //      exists, bump it (last-seen unixtime, occurrences
                  //      counter, last_detected_at in metadata) — repeated
                  //      access to the same infected file must not flood the
                  //      dashboard with duplicate rows. A CLOSED alert is not
                  //      bumped: the file reappearing after triage warrants a
                  //      fresh alert.
                  //   2. Otherwise insert, unless this exact row already
                  //      exists (store-and-forward redelivery guard).
                  // Explicit casts on every parameter — Postgres deduces
                  // parameter types independently per context and fails with
                  // "inconsistent types deduced" without them.
                  upsertTasks.push(() => entityManager.query(
                    `WITH bump AS (
                       UPDATE alerts
                       SET unixtime = GREATEST(unixtime, $2::bigint),
                           metadata = jsonb_set(
                             jsonb_set(
                               metadata::jsonb,
                               '{occurrences}',
                               to_jsonb(COALESCE((metadata::jsonb->>'occurrences')::int, 1) + 1)
                             ),
                             '{last_detected_at}',
                             to_jsonb($9::text)
                           )::text
                       WHERE host_identifier = $1::varchar
                         AND alert_type = $8::text
                         AND is_open = true
                         AND event_code = $3::text
                         -- COALESCE(..., '') rather than a bare comparison:
                         -- metadata holds the raw agent row, so a detection
                         -- carrying no path key (or an explicit JSON null)
                         -- extracts as SQL NULL here, while $10 is
                         -- String(row.path ?? '') and is therefore the empty
                         -- string. NULL = '' evaluates to NULL, never true, so
                         -- the bump could not fire and EVERY pathless detection
                         -- inserted a fresh open alert instead of incrementing
                         -- occurrences. Normalising the stored side to the
                         -- empty string makes it match the parameter's own
                         -- normalisation. Path-bearing rows are unaffected:
                         -- COALESCE over a non-NULL value is that value, and
                         -- the planner produces an identical plan (verified on
                         -- prod -- neither form is indexable, both are heap
                         -- filters at the same cost).
                         AND COALESCE(metadata::jsonb->>'path', '') = $10::text
                       RETURNING 1
                     )
                     INSERT INTO alerts
                       (host_identifier, unixTime, event_code, metadata,
                        is_alert, is_open, severity, alert_type)
                     SELECT $1::varchar,$2::bigint,$3::text,$4::text,$5::boolean,$6::boolean,$7::text,$8::text
                     WHERE NOT EXISTS (SELECT 1 FROM bump)
                       AND NOT EXISTS (
                         SELECT 1 FROM alerts
                         WHERE host_identifier = $1::varchar
                           AND unixTime = $2::bigint
                           AND event_code = $3::text
                           AND metadata = $4::text
                           AND alert_type = $8::text
                       )`,
                    [hostId, clamUnixTime, eventCode, metadataJson,
                     true, true, 'high', ALERT_TYPE_CLAMAV_ALERT,
                     String(row.detected_at ?? ''), alertPath]
                  ).catch((err: unknown) => { upsertFailures++; logger.error({ err, hostId, signature: eventCode, path: alertPath }, 'clamav_push: alerts upsert failed'); }));
                }
                runClamavBatchSerialised(hostId, upsertTasks).then(() => {
                  if (upsertFailures > 0) {
                    logger.warn({ hostId, pushType, count: rows.length, upsertFailures }, 'clamav_push batch completed with failures');
                  }
                });
              } else {
                // clamav_push has its own Array.isArray check rather than sharing
                // defender_push/usb_device_push's outer if/else, so a non-array
                // response from a malformed agent build needs its own trace here.
                logger.warn({ hostId, pushType, resultType: typeof rows }, 'clamav_push payload was not an array, skipping persist');
              }
            } else if (pushType === 'clamav_status_push') {
              // Single JSON object: { source, daemon_running, engine_version,
              // db_version, db_date, version_raw, freshclam_result, error, timestamp }.
              // Upserted so the DB always holds the latest known daemon state per
              // host — the MyDevices pill reads this via /alerts/clamav-summary
              // instead of assuming "agent online ⇒ ClamAV running".
              const st = typeof data.response === 'string'
                ? JSON.parse(data.response as string)
                : data.response;
              if (st && typeof st === 'object') {
                entityManager.query(
                  `INSERT INTO clamav_status
                     (host_identifier, daemon_running, engine_version, db_version,
                      db_date, version_raw, last_error, freshclam_result, updated_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
                   ON CONFLICT (host_identifier) DO UPDATE SET
                     daemon_running   = EXCLUDED.daemon_running,
                     engine_version   = EXCLUDED.engine_version,
                     db_version       = EXCLUDED.db_version,
                     db_date          = EXCLUDED.db_date,
                     version_raw      = EXCLUDED.version_raw,
                     last_error       = EXCLUDED.last_error,
                     freshclam_result = COALESCE(NULLIF(EXCLUDED.freshclam_result, ''), clamav_status.freshclam_result),
                     updated_at       = NOW()`,
                  [hostId, !!(st as any).daemon_running, (st as any).engine_version ?? null,
                   (st as any).db_version ?? null, (st as any).db_date ?? null,
                   (st as any).version_raw ?? null, (st as any).error ?? null,
                   (st as any).freshclam_result ?? null]
                )
                  .then(() => logger.debug({ hostId, daemonRunning: !!(st as any).daemon_running }, 'clamav_status_push: status persisted'))
                  .catch((err: unknown) => logger.error({ err, hostId }, 'clamav_status_push: upsert failed'));
              } else {
                logger.warn({ hostId, pushType, resultType: typeof st }, 'clamav_status_push payload was not a valid object, skipping persist');
              }
            } else if (pushType === 'clamav_scan_push') {
              // Single CommandResponse JSON: one completed remote scan.
              // Persisted as one alerts row whose metadata carries the whole
              // scan document — command, target, per-file results (capped
              // agent-side), counts, raw output — same pattern as Defender
              // event rows. Individual FOUND detections still land as separate
              // 'ClamAV Alert' rows via the store-and-forward clamav_push path
              // (and drive the MyDevices count); this row is the scan's audit
              // record. Clean scans are stored closed (is_open=false) so they
              // are searchable history, not pending alerts.
              const scan = typeof data.response === 'string'
                ? JSON.parse(data.response as string)
                : data.response;
              if (scan && typeof scan === 'object') {
                const s = scan as any;
                const infected = Number(s.infected) || 0;
                const errCount = Number(s.errors) || 0;
                const verdict = infected > 0
                  ? `${infected} infected`
                  : errCount > 0 ? `clean, ${errCount} error(s)` : 'clean';
                const eventCode = `ClamAV ${String(s.command ?? 'scan').toUpperCase()} ${String(s.target ?? '')} — ${verdict}`;
                const scanUnixTime = parseUnixTime(s.timestamp) ?? Math.floor(Date.now() / 1000);
                entityManager.query(
                  `INSERT INTO alerts
                     (host_identifier, unixTime, event_code, metadata,
                      is_alert, is_open, severity, alert_type)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                  [hostId, scanUnixTime, eventCode, JSON.stringify(s),
                   infected > 0, infected > 0, infected > 0 ? 'high' : 'low', ALERT_TYPE_CLAMAV_SCAN]
                )
                  .then(() => logger.info({ hostId, infected, errCount }, 'clamav_scan_push: scan result persisted'))
                  .catch((err: unknown) => logger.error({ err, hostId }, 'clamav_scan_push: alerts insert failed'));
              } else {
                logger.warn({ hostId, pushType, resultType: typeof scan }, 'clamav_scan_push payload was not a valid object, skipping persist');
              }
            } else if (pushType === 'patch_job_push') {
              // Single JSON object: completion of a Windows maintained-app
              // install/uninstall job. Unlike clamav_scan_push this is not a
              // fresh alerts row but the terminal state of a windows_patch_jobs
              // row created at dispatch time by
              // controllers/nodes/windows_patch_management.ts, so it is an
              // UPDATE keyed on job_id.
              //
              // This push carries the only verified outcome: dispatch-time
              // logging proves nothing beyond "we sent it", and the installer's
              // exit code is not trusted even by the agent, which verifies
              // against the registry. WINDOWS_PATCH_INSTALL_SUCCESS/_FAILURE are
              // therefore written only here.
              const job = typeof data.response === 'string'
                ? JSON.parse(data.response as string)
                : data.response;
              if (job && typeof job === 'object') {
                const j = job as any;
                const status: 'success' | 'failure' = j.status === 'success' ? 'success' : 'failure';
                const completedAt = (() => {
                  const d = j.completed_at ? new Date(j.completed_at) : null;
                  return d && !Number.isNaN(d.getTime()) ? d : new Date();
                })();
                entityManager.query(
                  // Must exclude every terminal state, not just success and
                  // failure: without 'rejected' and 'timed_out' a redelivered
                  // patch_job_push for such a job would still match, overwrite
                  // it, and re-run the alerts insert, programs.version sync and
                  // audit write for a job that never executed. osupdate_result's
                  // guard below excludes its own terminal states for the same
                  // reason.
                  `UPDATE windows_patch_jobs SET
                     status = $2, exit_code = $3, outcome_reason = $4, installed_version = $5,
                     completed_at = $6, duration_ms = $7
                   WHERE id = $1 AND LOWER(host_identifier) = LOWER($8)
                     AND status NOT IN ('success', 'failure', 'rejected', 'timed_out')
                   RETURNING id, maintained_app_id, action`,
                  [j.job_id, status, j.exit_code ?? null, j.reason ?? null, j.installed_version ?? null,
                   completedAt, j.duration_ms ?? null, hostId],
                )
                  .then((raw: unknown) => {
                    // TypeORM's Postgres driver returns UPDATE ... RETURNING as
                    // the tuple [rows, rowCount], so `raw.length` is always 2
                    // ([[], 0] on zero matches) and `raw[0]` holds the rows.
                    // returningRows() is what makes the redelivery guard below
                    // able to fire at all.
                    const rows = returningRows<{ id: string; maintained_app_id: number | string; action: string }>(raw);
                    if (rows.length === 0) {
                      // A redelivered push for an already-terminal job, or a
                      // host mismatch. Either way skip the alerts and audit side
                      // effects so a redelivery cannot duplicate them.
                      logger.warn({ hostId, jobId: j.job_id, status }, 'patch_job_push: no in-scope pending windows_patch_jobs row matched, skipping side effects');
                      return;
                    }
                    logger.info({ hostId, jobId: j.job_id, status }, 'patch_job_push: windows_patch_jobs updated');
                    // maintained_app_id is BIGINT, which node-postgres returns
                    // as a string to avoid precision loss above 2^53.
                    const jobRow = rows[0];

                    // Only failures become alerts; successes are already visible
                    // in the Jobs tab history.
                    if (status === 'failure') {
                      entityManager.query(
                        `INSERT INTO alerts (host_identifier, unixTime, event_code, metadata, is_alert, is_open, severity, alert_type)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
                        [hostId, Math.floor(Date.now() / 1000), `Windows app install failed: ${j.app_slug ?? j.job_id}`,
                         JSON.stringify(j), true, true, 'medium', 'Patch Management'],
                      ).catch((err: unknown) => logger.error({ err, hostId, jobId: j.job_id }, 'patch_job_push: alerts insert failed'));
                    }

                    // After a successful install/update the host's `programs`
                    // inventory is stale for this app until the next full sync,
                    // and getAvailability reads `programs` directly, so it would
                    // keep reporting the pre-update version. Match on the job's
                    // own maintained_app_id (validated at dispatch time), not the
                    // agent-echoed j.app_slug, and update only the host's latest
                    // row for that app, mirroring getAvailability's DISTINCT ON
                    // (name) latest-row idiom.
                    //
                    // Install/update only: whether an uninstall should delete the
                    // row (and whether that would resurrect older history for the
                    // same name) depends on the inventory ingestion contract in
                    // node_programs.ts, so uninstalls stay on the periodic sync.
                    if (status === 'success' && jobRow.action !== 'uninstall' && j.installed_version) {
                      entityManager.query(
                        // Deliberately not reusing getAvailability's
                        // `id > MAX(id) - 1000000` window: that bounds a table
                        // scan for a frequently-polled read, but this write runs
                        // once per completed job, and the window is global rather
                        // than per-host, so it would silently no-op for any quiet
                        // host whose rows fell outside it.
                        `WITH latest_programs AS (
                           SELECT DISTINCT ON (name) id, name
                             FROM programs
                            WHERE host_identifier = $1
                              AND name IS NOT NULL AND name <> ''
                            ORDER BY name, unixtime DESC
                         ), matched AS (
                           SELECT lp.id
                             FROM latest_programs lp
                             -- Word-boundary fuzzy match plus known Store/OEM
                             -- aliases (see utils/maintainedAppKnownAliases.ts's
                             -- MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL for the
                             -- full rationale — shared with getAvailability in
                             -- windows_patch_management.ts) — matters even
                             -- more here since this is the UPDATE path: a
                             -- false-positive match would overwrite an
                             -- unrelated installed program's version.
                             JOIN maintained_apps ma ON ma.id = $2 AND (
                               ${MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL}
                             )
                            ORDER BY (LOWER(lp.name) = LOWER(ma.display_name_match)) DESC, lp.name
                            LIMIT 1
                         )
                         UPDATE programs SET version = $3, unixtime = $4
                          WHERE id = (SELECT id FROM matched)
                          RETURNING id, name`,
                        [hostId, jobRow.maintained_app_id, j.installed_version, Math.floor(completedAt.getTime() / 1000)],
                      )
                        .then((raw: unknown) => {
                          // The top-level statement is `UPDATE programs` (the
                          // SELECTs are CTEs), so this returns the [rows,
                          // rowCount] tuple; see the note on the enclosing
                          // .then(). Without returningRows() the "no matching
                          // programs row" warn below is unreachable.
                          const programRows = returningRows<{ id: number; name: string }>(raw);
                          if (programRows.length === 0) {
                            logger.warn(
                              { hostId, jobId: j.job_id, maintainedAppId: jobRow.maintained_app_id },
                              'patch_job_push: no matching programs row found to sync installed_version, will remain stale until next inventory sync',
                            );
                            return;
                          }
                          logger.info(
                            { hostId, jobId: j.job_id, installedVersion: j.installed_version, program: programRows[0] },
                            'patch_job_push: programs.version synced after successful install',
                          );
                        })
                        .catch((err: unknown) => logger.error({ err, hostId, jobId: j.job_id }, 'patch_job_push: programs version sync failed'));
                    }

                    logAuditTrail({
                      action: status === 'success' ? 'WINDOWS_PATCH_INSTALL_SUCCESS' : 'WINDOWS_PATCH_INSTALL_FAILURE',
                      status,
                      details: {
                        host_identifier: hostId, job_id: j.job_id, app_slug: j.app_slug ?? null,
                        action: j.action ?? null, exit_code: j.exit_code ?? null, reason: j.reason ?? null,
                        installed_version: j.installed_version ?? null,
                      },
                    }).catch((err: unknown) => logger.error({ err, hostId, jobId: j.job_id }, 'patch_job_push: audit trail write failed'));
                  })
                  .catch((err: unknown) => logger.error({ err, hostId, jobId: j.job_id }, 'patch_job_push: windows_patch_jobs update failed'));
              } else {
                logger.warn({ hostId, pushType, resultType: typeof job }, 'patch_job_push payload was not a valid object, skipping persist');
              }
            } else if (pushType === 'firewall_status_push') {
              // Single JSON object matching statusPayload from the Linux agent:
              // { manager, active, enabled_on_boot, default_policy_in,
              //   default_policy_out, zone_or_profile, installed, distro,
              //   init_system, details, timestamp }
              // Upserted so the DB always holds the latest known firewall state per host.
              const fw = typeof data.response === 'string'
                ? JSON.parse(data.response as string)
                : data.response;
              if (fw && typeof fw === 'object') {
                entityManager.query(
                  `INSERT INTO firewall_status
                     (host_identifier, manager, active, enabled_on_boot,
                      default_policy_in, default_policy_out, zone_or_profile,
                      installed, distro, init_system, details, updated_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
                   ON CONFLICT (host_identifier) DO UPDATE SET
                     manager           = EXCLUDED.manager,
                     active            = EXCLUDED.active,
                     enabled_on_boot   = EXCLUDED.enabled_on_boot,
                     default_policy_in  = EXCLUDED.default_policy_in,
                     default_policy_out = EXCLUDED.default_policy_out,
                     zone_or_profile   = EXCLUDED.zone_or_profile,
                     installed         = EXCLUDED.installed,
                     distro            = EXCLUDED.distro,
                     init_system       = EXCLUDED.init_system,
                     details           = EXCLUDED.details,
                     updated_at        = NOW()`,
                  [
                    hostId,
                    String((fw as any).manager ?? 'none'),
                    Boolean((fw as any).active),
                    Boolean((fw as any).enabled_on_boot),
                    String((fw as any).default_policy_in  ?? 'unknown'),
                    String((fw as any).default_policy_out ?? 'unknown'),
                    (fw as any).zone_or_profile ?? null,
                    JSON.stringify((fw as any).installed ?? []),
                    (fw as any).distro ?? null,
                    (fw as any).init_system ?? null,
                    (fw as any).details ?? null,
                  ]
                )
                  .then(() => logger.debug({ hostId, active: Boolean((fw as any).active) }, 'firewall_status_push: status persisted'))
                  .catch((err: unknown) => logger.error({ err, hostId }, 'firewall_status_push: upsert failed'));
              } else {
                logger.warn({ hostId, pushType, resultType: typeof fw }, 'firewall_status_push payload was not a valid object, skipping persist');
              }
            } else if (pushType === 'packages_push') {
              // packages_push sends { snap: [...], pacman: [...], flatpak: [...], timestamp }.
              // Per-source snapshot replacement: for each source present in the payload,
              // delete old rows for that source and insert the fresh list — all inside a
              // single transaction so a reconnect-race or crash never leaves partial data.
              // Sources not present in the payload are left untouched, so a temporary
              // collector failure (e.g. snapd down) doesn't wipe previously-good data
              // from other sources.
              const pkg = typeof data.response === 'string'
                ? JSON.parse(data.response as string)
                : data.response;
              if (pkg && typeof pkg === 'object' && !(pkg as any).error) {
                const runner = entityManager.createQueryRunner();
                const sourceCounts: Record<string, number> = {};
                try {
                  await runner.connect();
                  await runner.startTransaction();
                  for (const src of ['snap', 'pacman', 'flatpak'] as const) {
                    const arr = (pkg as any)[src];
                    if (!Array.isArray(arr)) continue;
                    sourceCounts[src] = arr.length;
                    await runner.query(
                      `DELETE FROM packages_snapshot WHERE host_identifier = $1 AND source = $2`,
                      [hostId, src]
                    );
                    // One multi-row INSERT via parallel unnest() rather than a
                    // round-trip per package, the same technique as the
                    // patch_available_updates bulk insert in osupdate_result.
                    // This runs inside the transaction opened above, and the
                    // payload size is agent-supplied and unbounded, so a
                    // per-package loop would hold one of the few pooled
                    // connections "idle in transaction" for N sequential awaits.
                    // unnest() preserves array subscript order, and NOW() is
                    // transaction-scoped, so the rows land exactly as a loop
                    // would have written them.
                    //
                    // Every value must go through pgPrepareValue (node-postgres'
                    // own scalar serialiser) before entering the arrays. The
                    // field values come straight off agent-supplied JSON with no
                    // type validation beyond Array.isArray() on the outer list,
                    // and multi-argument unnest() pads shorter arrays with NULL
                    // up to the longest: a field value that was itself a JS array
                    // would bind as a nested array, run longer than its siblings
                    // and emit junk rows with every other column NULL. All the
                    // columns are text, so nothing would raise a type error and
                    // packages_snapshot would be corrupted silently.
                    //
                    // pgPrepareValue is also what a per-row INSERT would apply to
                    // each scalar parameter, so using it keeps the stored text
                    // identical. String() would not: String([1,2]) is '1,2' where
                    // pg stores '{"1","2"}', String({a:1}) is '[object Object]'
                    // where pg stores '{"a":1}', and Date differs too.
                    const names         = (arr as any[]).map((row) => pgPrepareValue(row.name ?? null));
                    const versions      = (arr as any[]).map((row) => pgPrepareValue(row.version ?? null));
                    const revisions     = (arr as any[]).map((row) => pgPrepareValue(row.revision ?? null));
                    const channels      = (arr as any[]).map((row) => pgPrepareValue(row.channel ?? null));
                    const publishers    = (arr as any[]).map((row) => pgPrepareValue(row.publisher ?? null));
                    const confinements  = (arr as any[]).map((row) => pgPrepareValue(row.confinement ?? null));
                    const snapTypes     = (arr as any[]).map((row) => pgPrepareValue(row.snap_type ?? null));
                    const appIds        = (arr as any[]).map((row) => pgPrepareValue(row.app_id ?? null));
                    const branches      = (arr as any[]).map((row) => pgPrepareValue(row.branch ?? null));
                    const origins       = (arr as any[]).map((row) => pgPrepareValue(row.origin ?? null));
                    const arches        = (arr as any[]).map((row) => pgPrepareValue(row.arch ?? null));
                    const installDirs   = (arr as any[]).map((row) => pgPrepareValue(row.install_dir ?? null));
                    const sizes         = (arr as any[]).map((row) => pgPrepareValue(row.size ?? null));
                    // Explicit ::text[] casts: Postgres cannot deduce the element
                    // type of a bare parameter inside unnest().
                    await runner.query(
                      `INSERT INTO packages_snapshot
                         (host_identifier, source, name, version, revision, channel,
                          publisher, confinement, snap_type, app_id, branch, origin,
                          arch, install_dir, size, updated_at)
                       SELECT $1, $2, u.name, u.version, u.revision, u.channel,
                              u.publisher, u.confinement, u.snap_type, u.app_id, u.branch, u.origin,
                              u.arch, u.install_dir, u.size, NOW()
                         FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[],
                                     $8::text[], $9::text[], $10::text[], $11::text[], $12::text[],
                                     $13::text[], $14::text[], $15::text[])
                           AS u(name, version, revision, channel, publisher, confinement,
                                snap_type, app_id, branch, origin, arch, install_dir, size)`,
                      [hostId, src, names, versions, revisions, channels, publishers,
                       confinements, snapTypes, appIds, branches, origins, arches,
                       installDirs, sizes]
                    );
                  }
                  await runner.commitTransaction();
                  // Without a success trace, a snapshot that silently stopped
                  // updating for one source looks like one that never ran.
                  logger.info({ hostId, sourceCounts }, 'packages_snapshot updated');
                } catch (txErr) {
                  await runner.rollbackTransaction().catch(() => {});
                  logger.error({ err: txErr, hostId }, 'packages_snapshot transaction failed');
                } finally {
                  await runner.release().catch(() => {});
                }
              } else if (pkg && typeof pkg === 'object' && (pkg as any).error) {
                logger.warn({ hostId, error: (pkg as any).error }, 'packages_push: agent reported collector error, snapshot not updated');
              } else {
                logger.warn({ hostId, pushType, resultType: typeof pkg }, 'packages_push payload was not a valid object, skipping persist');
              }
            } else if (pushType === 'osupdate_result') {
              // osupdate_result reports the completion, or Start() refusal, of a
              // Patch Management op.
              //
              // Correlation prefers task_id: the result carries the same task_id
              // that arrived on this row's earlier osupdate_ack: response, so the
              // match is unambiguous even if the host has several rows in a
              // non-terminal state. Only a result with no task_id (an agent build
              // predating ack task_id support, or a lost ack) falls back to "the
              // newest dispatched/acked/running row for this host", a heuristic
              // whose correctness rests on osupdate's single-flight guarantee.
              const result = typeof data.response === 'string' ? JSON.parse(data.response as string) : data.response;
              if (result && typeof result === 'object') {
                const success = Boolean((result as any).success);
                const resultTaskId = typeof (result as any).task_id === 'string' && (result as any).task_id
                  ? (result as any).task_id
                  : null;
                const rebootRequired = typeof (result as any).reboot_required === 'boolean'
                  ? (result as any).reboot_required
                  : null;
                // Only meaningful on failure. Trust whatever string arrives
                // rather than validating against a closed enum server-side.
                const failureReason = !success && typeof (result as any).failure_reason === 'string'
                  ? (result as any).failure_reason
                  : null;

                const nodeRowsRaw = resultTaskId
                  ? await entityManager.query(
                      // status NOT IN (...) stops a redelivered osupdate_result
                      // for an already-terminal task_id (the agent's
                      // store-and-forward buffer resending after a crash) from
                      // re-matching this row and re-running everything below,
                      // including the auto-recheck dispatch further down.
                      `UPDATE patch_job_nodes
                          SET status = $1, manager = $2, result = $3, reboot_required = $4,
                              failure_reason = $5, completed_at = NOW(), updated_at = NOW()
                        WHERE task_id = $6 AND LOWER(host_identifier) = LOWER($7)
                          AND status NOT IN ('success', 'failed', 'timed_out')
                        RETURNING id`,
                      [success ? 'success' : 'failed', (result as any).manager ?? null, JSON.stringify(result),
                       rebootRequired, failureReason, resultTaskId, hostId],
                    )
                  : await entityManager.query(
                      `UPDATE patch_job_nodes
                          SET status = $1, manager = $2, result = $3, reboot_required = $4,
                              failure_reason = $5, completed_at = NOW(), updated_at = NOW()
                        WHERE id = (
                          SELECT id FROM patch_job_nodes
                           WHERE LOWER(host_identifier) = LOWER($6) AND status IN ('dispatched','acked','running')
                           ORDER BY dispatched_at DESC LIMIT 1
                        )
                        RETURNING id`,
                      [success ? 'success' : 'failed', (result as any).manager ?? null, JSON.stringify(result),
                       rebootRequired, failureReason, hostId],
                    );
                // Both branches above are UPDATE ... RETURNING, which TypeORM
                // hands back as the [rows, rowCount] tuple, so `.length` is
                // always 2 and the rows must be unwrapped before use.
                const nodeRows = returningRows<{ id: string }>(nodeRowsRaw);

                const availablePackages = (result as any).available_packages;
                if (success && (result as any).operation === 'check' && Array.isArray(availablePackages) && availablePackages.length > 0) {
                  const manager = String((result as any).manager ?? '');
                  const runner = entityManager.createQueryRunner();
                  try {
                    await runner.connect();
                    await runner.startTransaction();
                    await runner.query(
                      `DELETE FROM patch_available_updates WHERE LOWER(host_identifier) = LOWER($1) AND manager = $2`,
                      [hostId, manager],
                    );
                    // One multi-row INSERT via parallel unnest(): a round-trip
                    // per package would hold this query runner, and this
                    // connection's message processing, for as many awaits as the
                    // host has upgradable packages.
                    const names = (availablePackages as any[]).map((row) => row.name ?? null);
                    const installedVersions = (availablePackages as any[]).map((row) => row.installed_version ?? null);
                    const availableVersions = (availablePackages as any[]).map((row) => row.available_version ?? null);
                    await runner.query(
                      `INSERT INTO patch_available_updates
                         (host_identifier, manager, name, installed_version, available_version, updated_at)
                       SELECT $1, $2, u.name, u.installed_version, u.available_version, NOW()
                         FROM unnest($3::text[], $4::text[], $5::text[]) AS u(name, installed_version, available_version)
                       ON CONFLICT (host_identifier, manager, name) DO UPDATE
                         SET installed_version = EXCLUDED.installed_version,
                             available_version = EXCLUDED.available_version,
                             updated_at = NOW()`,
                      [hostId, manager, names, installedVersions, availableVersions],
                    );
                    await runner.commitTransaction();
                    // Without a success trace this silently succeeding looks
                    // identical to the branch never having been entered (e.g.
                    // availablePackages empty or absent).
                    logger.info({ hostId, manager, count: names.length }, 'patch_available_updates updated');
                  } catch (txErr) {
                    await runner.rollbackTransaction().catch(() => {});
                    logger.error({ err: txErr, hostId }, 'patch_available_updates transaction failed');
                  } finally {
                    await runner.release().catch(() => {});
                  }
                }

                if (nodeRows.length === 0) {
                  logger.warn({ hostId }, 'osupdate_result matched no in-flight patch_job_nodes row (late/duplicate/unsolicited push?)');
                } else {
                  // The only log line carrying the patch operation's outcome;
                  // otherwise it is visible only by querying patch_job_nodes.
                  logger.info(
                    {
                      hostId,
                      nodeId: nodeRows[0]?.id,
                      operation: (result as any).operation,
                      success,
                      manager: (result as any).manager ?? null,
                      taskId: resultTaskId,
                      rebootRequired,
                      failureReason,
                    },
                    'Osupdate result processed',
                  );

                  // This host's in-flight row just reached a terminal state, so
                  // advance its pending_patch_commands queue by one. Awaited so
                  // the auto-recheck below observes whatever this dispatched,
                  // instead of both racing to claim the host in the same tick.
                  await dispatchNextPendingPatchCommand(hostId, dispatchToAgent);

                  // Only a 'check' completion refreshes patch_available_updates
                  // (see the availablePackages block above), so without
                  // auto-dispatching one here a package the operator just applied
                  // would stay listed forever. Consistent with this feature's
                  // trust model: never infer state from a job outcome, re-verify
                  // against the device. Fires on failure too, since a failed
                  // install can still change the available-package list.
                  if ((result as any).operation === 'upgrade_packages') {
                    const inFlight = await findHostsInFlight(entityManager, [hostId]);
                    if (inFlight.has(hostId.toLowerCase())) {
                      // dispatchNextPendingPatchCommand just claimed this host
                      // for a different queued command. Skip the auto-recheck
                      // rather than stacking a second in-flight row on top; the
                      // next check will catch up.
                      logger.warn({ hostId }, 'Skipping auto re-check, host is already in-flight');
                    } else {
                      try {
                        const autoCheck = await createPatchJob(
                          entityManager, 'check', [hostId], null, 'auto re-check after per-package upgrade', null, null,
                          dispatchToAgent,
                        );
                        logAuditTrail({
                          action: 'PATCH_CHECK',
                          status: 'success',
                          userId: null,
                          email: null,
                          // ipAddress is a Postgres `inet` column: 'system' is
                          // not a valid inet literal and would fail the insert
                          // silently, since logAuditTrail swallows its errors.
                          // details.trigger below already records this.
                          ipAddress: null,
                          details: { patch_job_id: autoCheck.patch_job_id, host_count: 1, trigger: 'auto_recheck_after_upgrade_packages' },
                        }).catch(() => {});
                      } catch (err: unknown) {
                        logger.error({ err, hostId }, 'Auto re-check dispatch failed');
                      }
                    }
                  }
                }
              } else {
                logger.warn({ hostId, pushType, resultType: typeof result }, 'osupdate_result payload was not a valid object, skipping persist');
              }
            }
          } else {
            // Fleet DB unavailable, so the whole persist step is skipped and
            // this agent push is dropped with no DB row and no other log line.
            logger.warn({ hostId, pushType }, 'Fleet DB unavailable, push message not persisted');
          }
        } catch (err) {
          logger.error({ err, pushType, hostId }, 'Push message response parse/DB error');
        }

        // Forward ClamAV detections and daemon-status changes to the
        // live-dashboard channel so pages like MyDevices can refresh their
        // ClamAV tags without per-node WebSocket connections. Scan summaries are
        // not forwarded: they only matter to the per-node control panel.
        if (pushType === 'clamav_push' || pushType === 'clamav_status_push'
            || pushType === 'firewall_status_push' || pushType === 'packages_push'
            || pushType === 'osupdate_result' || pushType === 'patch_job_push') {
          broadcastToLiveClients(payload);
        }

        return; // Push handled — skip rid routing below.
      }

      // Resolve rid -> UI slot. Redis is authoritative; in-memory ridToUiSlot is
      // consulted only if Redis is unavailable. ValidateExtResponse has already
      // guaranteed data.rid is non-empty.
      const freshRedis = getRedisClient();
      let uiSlot = -1;
      if (freshRedis) {
        const val = await freshRedis.get(ridKey(data.rid)).catch((err: unknown) => {
          // Without this a Redis outage during rid resolution is
          // indistinguishable from the rid genuinely not being in Redis.
          logger.warn({ err, rid: data.rid, hostId }, 'Redis rid routing lookup failed, falling back to in-memory table');
          return null;
        });
        if (val != null) {
          const parsed = parseInt(val, 10);
          if (Number.isFinite(parsed)) uiSlot = parsed;
        }
        // One-time-use: delete from Redis immediately after reading.
        freshRedis.del(ridKey(data.rid)).catch(() => {});
      }
      if (uiSlot < 0) {
        const memEntry = ridToUiSlot.get(data.rid);
        uiSlot = memEntry?.slot ?? -1;
      }
      // One-time-use: always clean up the memory entry too.
      ridToUiSlot.delete(data.rid);

      if (uiSlot < 0 || uiSlot >= WS_POOL_SIZE) {
        logger.debug({ rid: data.rid }, 'rid not found, UI may have disconnected or request timed out');
        return;
      }
      if (CLIENTS[uiSlot] === null) {
        logger.debug({ rid: data.rid, uiSlot }, 'UI client already disconnected');
        return;
      }

      // Deliver to UI
      const uiWs = CLIENTS[uiSlot]!;
      const sent = safeSend(uiWs, JSON.stringify(data), 'nodeExt→ui');
      if (!sent) {
        // UI socket is dead, so evict the stale slot. safeSend logged the raw
        // send error; this logs the eviction itself, as every other slot
        // eviction path in this file does.
        //
        // Must go through releaseClientSlot() like every other free path, or the
        // socket stays in wsToClientIndex and its eventual 'close' frees the same
        // slot twice.
        releaseClientSlot(uiSlot, uiWs);
        logger.warn({ hostId, uiSlot, rid: data.rid }, 'Evicted dead UI slot after failed delivery from agent');
      }

      // Persist the compliance result if applicable. Only keys 1-18 are the
      // security-guidelines checklist; Defender (19-43), USB (54), Bluetooth
      // (47/48/55) and others share the same [{ command_key, output }] shape.
      // Writing those to compliance_results would overwrite "latest" and show as
      // bogus guidelines scoring 0%, since their JSON outputs are not True/False.
      try {
        const respRaw = data.response;
        const respArr = Array.isArray(respRaw)
          ? respRaw
          : (typeof respRaw === 'string' ? JSON.parse(respRaw as string) : null);
        if (
          Array.isArray(respArr) &&
          respArr.length > 0 &&
          typeof (respArr[0] as Record<string, unknown>)?.command_key === 'string' &&
          isMachineCompliancePayload(respArr)
        ) {
          saveComplianceResult(hostId, respArr)
            .then(() => logger.debug({ hostId, checks: respArr.length }, 'Compliance result saved'))
            .catch(
              (err: unknown) => logger.error({ err, hostId }, 'Failed to save compliance result'),
            );
        }
      } catch {
        // Not a compliance response — ignore
      }
    } catch (err) {
      logger.error({ err, hostId }, 'Unhandled nodeExt message handler error');
    }
  });

  ws.on('close', (...args: unknown[]) => {
    const reason = typeof args[1] === 'string' ? args[1] : '';

    // Free this connection's pool slot. Guard on wsToExtIndex: if another path
    // already evicted this socket (dead-socket eviction in nodeUi or
    // dispatchToAgent) the lookup misses, and the slot must not be freed twice.
    const idx = wsToExtIndex.get(ws);
    if (idx !== undefined) {
      releaseExtSlot(idx, ws);
    }

    // Ownership check. A reconnecting agent for the same hostId overwrites
    // hostToExtSlot with its new slot before this close fires. Still owning the
    // mapping means this was the last connection for the host, so mark it
    // offline. No longer owning it means the new connection is live and has
    // already called UpdateAgentStatus(hostId, true), which must not be
    // clobbered with false.
    const isOwner = hostToExtSlot.get(hostId) === ptExt;
    if (isOwner) {
      UpdateAgentStatus(hostId, false);
      hostToExtSlot.delete(hostId);
    }

    // Conditional Redis DEL: read the current value and delete only if it is
    // still our slot. An unconditional DEL would destroy a reconnecting agent's
    // routing entry milliseconds after it was written.
    const freshRedis = getRedisClient();
    if (freshRedis) {
      freshRedis.get(extKey(hostId))
        .then((val: string | null) => {
          if (val === String(ptExt)) {
            freshRedis.del(extKey(hostId)).catch(() => {});
          }
        })
        .catch(() => {});
    }

    logger.info({ hostId, slot: ptExt, reason: reason || undefined }, 'Agent disconnected');
  });
}

// Server-side dispatch (shared transport for AI HITL and Patch Management)

/**
 * Dispatch a WS payload directly to the agent extension for a given node.
 * Returns {dispatched:true} on success, {dispatched:false, error} otherwise.
 * Fire-and-forget: it does not wait for an agent response.
 *
 * Shared by AI HITL confirmed actions (guardrails.ts) and Patch Management
 * (controllers/nodes/patch_management.ts, patch_bundles.ts, patchDispatch.ts),
 * so the log messages must stay caller-agnostic — "AI-driven" wording here would
 * misattribute ordinary patch dispatch failures during incident forensics.
 */
export function dispatchToAgent(
  host_identifier: string,
  payload: Record<string, unknown>,
): { dispatched: boolean; error?: string } {
  const payloadKeys = Object.keys(payload);
  const extSlot = hostToExtSlot.get(host_identifier);
  if (extSlot === undefined || extSlot < 0 || extSlot >= WS_POOL_SIZE) {
    logger.warn({ hostIdentifier: host_identifier, payloadKeys }, 'Server-initiated agent dispatch failed, no slot for host');
    return { dispatched: false, error: 'Agent not connected (no slot)' };
  }
  // Ownership validation, the same invariant as the nodeUi forward path: never
  // send to a slot unless it is currently registered to this exact host.
  if (extSlotToHost[extSlot] !== host_identifier) {
    hostToExtSlot.delete(host_identifier);
    logger.warn({ hostIdentifier: host_identifier, slot: extSlot, payloadKeys }, 'Server-initiated agent dispatch failed, stale slot');
    return { dispatched: false, error: 'Agent not connected (stale slot)' };
  }
  const ext = EXTENSIONS[extSlot];
  if (!ext) {
    hostToExtSlot.delete(host_identifier);
    logger.warn({ hostIdentifier: host_identifier, slot: extSlot, payloadKeys }, 'Server-initiated agent dispatch failed, slot empty');
    return { dispatched: false, error: 'Agent not connected (slot empty)' };
  }
  const sent = safeSend(ext, JSON.stringify(payload), 'server→ext');
  if (!sent) {
    // releaseExtSlot also removes the dead socket from wsToExtIndex so the
    // eventual 'close' cannot double-free the slot.
    releaseExtSlot(extSlot, ext);
    hostToExtSlot.delete(host_identifier);
    UpdateAgentStatus(host_identifier, false);
    const redis = getRedisClient();
    if (redis) redis.del(extKey(host_identifier)).catch(() => {});
    logger.warn({ hostIdentifier: host_identifier, slot: extSlot, payloadKeys }, 'Server-initiated agent dispatch failed, send failed');
    return { dispatched: false, error: 'Send failed — agent disconnected' };
  }
  logger.info({ hostIdentifier: host_identifier, slot: extSlot, payloadKeys }, 'Server-initiated command dispatched to agent');
  return { dispatched: true };
}
