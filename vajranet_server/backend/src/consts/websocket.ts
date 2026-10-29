/** WebSocket and live dashboard literal constants (no env). */

import { NODE_STATUS_ONLINE_THRESHOLD_SECONDS } from './database';

export const WS_POOL_SIZE = 1024;
export const JOB_DRAIN_PER_TICK = 20;
export const JOB_DRAIN_INTERVAL_MS = 2000;

export const ALERT_DEBOUNCE_MS = 200;
// Raised from 10s: Fleet server debounces last_seen writes to ~30s (fleet_main.cpp update_last_seen), so a threshold at or below that flaps nodes online/offline every debounce cycle.
// Shared with consts/database.ts's NODE_STATUS_ONLINE_THRESHOLD_SECONDS so the SQL-based and websocket status paths never drift apart.
export const NODE_ONLINE_SECONDS_LIMIT = NODE_STATUS_ONLINE_THRESHOLD_SECONDS;
export const LIVE_SETUP_NOTIFICATIONS_DELAY_MS = 1000;
/**
 * Safety-net poll interval for node status (ms).
 *
 * Primary updates are EVENT-DRIVEN: node.ts calls emitNodeStatusChange()
 * after every UpdateAgentStatus() DB write (agent connect / disconnect).
 * That path runs getNodesStatus() within NODE_STATUS_DEBOUNCE_MS and
 * broadcasts immediately if the state changed.
 *
 * This 5 s interval serves as the fast fallback for two scenarios:
 *  1. last_seen drift — osquery heartbeat stops but WS extension did not
 *     send a clean close (power loss, kernel OOM kill); agent_online stays
 *     true in DB so no event fires, but last_seen drift is caught here.
 *  2. Any event-driven miss — dirty disconnect (service kill, SIGKILL)
 *     where the OS drops the TCP connection without a close frame, so
 *     the server only learns of it at the next heartbeat (~25 s). The
 *     5 s poll catches the resulting last_seen drift quickly.
 *
 * Matches the proven 5 s poll cadence of the reference Vajra-UI implementation.
 */
export const LIVE_NODES_POLL_INTERVAL_MS = 5_000;

/**
 * Trailing-edge debounce for event-driven node status checks (ms).
 *
 * Multiple agents can connect / disconnect within milliseconds of each
 * other (fleet restart). The debounce collapses all events in this
 * window into a single DB query + single broadcast cycle.
 *
 * 200 ms: fast enough to feel instant to the UI, long enough to coalesce
 * burst reconnects and to let the preceding DB write commit.
 */
export const NODE_STATUS_DEBOUNCE_MS = 200;

/**
 * How often each connected live-dashboard client's node-group scope is
 * re-resolved from the database.
 *
 * REST endpoints resolve scope per request, so a demotion or group removal
 * takes effect on the caller's next call. A dashboard socket has no such
 * boundary — it is opened once and can stay open for as long as the tab does,
 * and nothing closes it on role change or session invalidation. Without this
 * the connect-time scope would be the one used forever.
 *
 * Sets the ceiling on how long a removed user keeps receiving their old
 * group's counts. Costs one indexed read per connected dashboard per interval,
 * so it trades a small steady query load for a bounded revocation window.
 */
export const LIVE_SCOPE_REFRESH_INTERVAL_MS = 60_000;

export const LIVE_ALERT_RESET_INTERVAL_MS = 360000;
/**
 * Clamp on the cumulative scoped `alertStatus.new` reported in a live-dashboard
 * snapshot, per LIVE_ALERT_RESET_INTERVAL_MS window.
 *
 * This clamps the displayed number only, so a storm reads as "100" instead of
 * growing without bound and churning every client's snapshot diff. It must not
 * become a silencing cap that stops scheduling broadcasts once the counter is
 * crossed: with the NOTIFY trigger in add_alerts_notify_trigger.sql live, that
 * would black out the real-time path for the whole 6-minute window during
 * exactly the alert storm the operator most needs to see. The broadcast *rate*
 * is bounded separately, by the leading- and trailing-edge limiter in liveWeb.ts
 * (see ALERT_DEBOUNCE_MS), which caps alert frames at one per debounce interval
 * however many NOTIFYs arrive.
 */
export const LIVE_ALERT_BROADCAST_CAP = 100;

/**
 * Max distinct host_identifiers tracked per alert window / pending flush.
 *
 * Bounds two things at once: the memory held between resets, and the per-scope
 * scan cost in liveWeb.ts's computeScopedAlertStatus / buildAlertPushFrame,
 * which are O(tracked hosts) per distinct client scope per flush. Set well
 * above any realistic fleet size so it is a runaway guard, not a normal
 * operating limit -- a host beyond the cap still counts
 * toward nothing rather than growing the map without bound.
 */
export const ALERT_WINDOW_HOST_CAP = 500;

/**
 * Max host_identifiers enumerated in a single alerts_push frame.
 *
 * Keeps the frame small during a storm. The frame is a refetch *signal*, not
 * the data, so the client behaves identically whether it receives 5 host ids
 * or 500; `truncated: true` records that the list was clipped.
 */
export const ALERT_PUSH_HOSTS_PER_FRAME_CAP = 50;

/**
 * `rid` discriminator for the real-time new-alert push frame on /ws/live.
 *
 * Follows the existing rid-tagged push convention on this channel
 * (clamav_push, firewall_status_push, osupdate_result, patch_job_push): the
 * frontend ignores any frame carrying an unrecognised `rid`, so shipping this
 * server-side ahead of a frontend deploy is inert rather than breaking.
 */
export const ALERT_PUSH_RID = 'alerts_push';

/** Max WebSocket message payload in bytes (5 MB) */
export const WS_MAX_PAYLOAD_BYTES = 5 * 1024 * 1024;

/**
 * Redis key prefixes — namespaced to prevent collisions with auth/captcha keys.
 * ws:ext:{hostId}  → extension slot index (long-lived, per agent connection)
 * ws:rid:{rid}     → UI slot index        (short-lived, per request)
 */
export const WS_REDIS_EXT_PREFIX = 'ws:ext:';
export const WS_REDIS_RID_PREFIX = 'ws:rid:';

/** Redis TTL for rid → UI slot mapping (seconds). 60 s is generous vs. a typical frontend request timeout. */
export const RID_EXPIRY_SECONDS = 60;

/**
 * Redis TTL safety-net for ws:ext:{hostId} keys (seconds, 24 h).
 * Keys are deleted on clean close; this prevents stale entries surviving a server crash.
 *
 * IMPORTANT: agent connections routinely outlive this TTL. The key MUST be
 * refreshed while the connection is alive (see refreshExtRouting in
 * websocket/node.ts) — otherwise the liveWeb cleanup loop sees
 * agent_online=true with no Redis key and flips the node offline even though
 * the agent is still connected.
 */
export const CONN_EXPIRY_SECONDS = 86400;

/**
 * Minimum interval between ws:ext:{hostId} TTL refreshes per connection (ms).
 *
 * Refresh triggers are heartbeat pongs (~25 s apart) and inbound agent
 * messages; this throttle coalesces them so each live agent costs at most
 * one Redis EXPIRE per minute regardless of traffic. Must be far below
 * CONN_EXPIRY_SECONDS (60 s vs 24 h gives ~1440 refresh opportunities per
 * TTL window).
 */
export const EXT_ROUTING_REFRESH_MIN_MS = 60_000;

/**
 * How often the in-memory ridToUiSlot Map is swept for expired entries (ms).
 * Matches RID_EXPIRY_SECONDS so no entry survives more than 2× its TTL.
 */
export const RID_CLEANUP_INTERVAL_MS = RID_EXPIRY_SECONDS * 1000;

// ─── Terminal WebSocket constants ─────────────────────────────────────────────

/**
 * Redis key prefix for terminal agent routing: ws:term:ext:{hostId} → agent slot.
 * Namespaced separately from ws:ext:* to prevent any collision with control channel keys.
 */
export const WS_REDIS_TERM_EXT_PREFIX = 'ws:term:ext:';

/** Maximum total concurrent terminal sessions across all nodes and users. */
export const TERMINAL_MAX_SESSIONS_TOTAL = 50;

/** Maximum concurrent terminal sessions per UI WebSocket connection. */
export const TERMINAL_MAX_SESSIONS_PER_UI = 5;

/**
 * Server-side terminal session inactivity timeout (ms, 35 minutes).
 * Slightly above the 30-minute agent-side inactivity timeout so the agent always
 * cleans up first (shell_exit fires) before the server closes the session.
 */
export const TERMINAL_SESSION_INACTIVITY_MS = 35 * 60 * 1000;

/** How often the server sweeps for idle terminal sessions (ms). */
export const TERMINAL_INACTIVITY_SWEEP_MS = 60_000;

// ─── WS heartbeat ──────────────────────────────────────────────────────────

/**
 * WebSocket ping/pong heartbeat interval (ms), shared by /ws/live, /ws/ext
 * and terminal WS servers (see index.ts's startHeartbeat). 25 s keeps every
 * connection alive through even the most aggressive NAT/firewall idle-drop
 * timeout (typically 60-120 s) and lets us terminate truly dead sockets fast.
 */
export const WS_HEARTBEAT_INTERVAL_MS = 25_000;

// ─── Sentinel rid prefixes ──────────────────────────────────────────────────
// Used to correlate an agent's immediate WS reply back to a server-initiated
// dispatch that has no nodeUi CLIENTS[] slot to route through (the dispatch
// didn't originate from a UI websocket request). See websocket/node.ts's
// rid-prefix branches and mcp/guardrails.ts's buildWsPayload.

/** rid = `${RID_PREFIX_OSUPDATE_ACK}<patch_job_node id>` for osupdate check/upgrade dispatches. */
export const RID_PREFIX_OSUPDATE_ACK = 'osupdate_ack:';

/** rid = `${RID_PREFIX_PATCH_JOB_ACK}<windows_patch_jobs id>` for patch_install/patch_uninstall dispatches. */
export const RID_PREFIX_PATCH_JOB_ACK = 'patch_job_ack:';

/** rid = `${RID_PREFIX_PATCH_CHECK}<uuid>` for on-demand Windows maintained-app patch_check dispatches. */
export const RID_PREFIX_PATCH_CHECK = 'patch_check:';

// ─── Powershell command_keys ────────────────────────────────────────────────

/** The 18 powershell command_keys that make up the compliance checklist (see mcp/schema/definitions.ts's COMPLIANCE_KEYS). */
export const COMPLIANCE_KEY_RANGE: readonly string[] = [
  '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '10', '11', '12', '13', '14', '15', '16', '17', '18',
];

/** Powershell command_key that disables Bluetooth. */
export const BLUETOOTH_DISABLE_KEY = 47;
/** Powershell command_key that enables Bluetooth. */
export const BLUETOOTH_ENABLE_KEY = 48;
/** Powershell command_key that reports Bluetooth status. */
export const BLUETOOTH_STATUS_KEY = 55;

// ─── Postgres LISTEN/NOTIFY ─────────────────────────────────────────────────

/** Postgres NOTIFY channel for new-alert notifications (see websocket/liveWeb.ts's setupNotifications). */
export const PG_ALERT_CHANNEL = 'new_alert';
