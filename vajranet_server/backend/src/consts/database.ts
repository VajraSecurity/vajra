/** Database and ORM literal constants (no env). */

export const PG_DEFAULT_PORT = 5432;
export const POOL_SIZE = 10;

/**
 * Max simultaneously in-flight hosts when createPatchJob (patchJobCore.ts)
 * dispatches a bulk patch job — that per-host work (status UPDATE, optional
 * bundle-selection SELECTs, the WS dispatch) all runs against the fleet DB's
 * POOL_SIZE=10-connection pool, shared with every other concurrent request
 * this process is serving. Kept below POOL_SIZE (not equal to it) so one big
 * bulk push (up to MAX_HOSTS hosts) can't fully monopolize that shared pool
 * and starve unrelated requests for its whole duration, while still running
 * well ahead of a fully-sequential one-host-at-a-time baseline.
 *
 * Lowered 8 -> 4. "Below POOL_SIZE" was doing much less work than the comment
 * above implied: at 8 of 10 a single bulk push holds 80% of the fleet pool for
 * its whole duration, leaving 2 connections for ALL other traffic — every
 * dashboard read, every scope check, every WebSocket agent handler and every
 * cron sweep in this single-process backend. That is not "can't monopolize",
 * it is monopolization with two spare slots, and with
 * DB_POOL_CONNECTION_TIMEOUT_MS=5000 the overflow surfaces to users as pool-
 * acquire timeouts rather than as a slow patch job. 4 leaves a 6-connection
 * majority for everything else while still being 4x a sequential baseline; the
 * dispatch loop is batch-synchronous, so the cost is roughly a 2x longer
 * wall-clock push (a few extra seconds even at MAX_HOSTS=2500, since per host
 * this is a couple of indexed queries plus a WS frame, not real work).
 */
export const PATCH_JOB_DISPATCH_CONCURRENCY = 4;

/**
 * Pool size for the group-scoped historical-hunting connection (vajra_hunt).
 * Kept small and separate from POOL_SIZE: this connection is only used by
 * non-global callers running free-form SQL, a low-frequency path compared to
 * ingest/dashboard traffic on the main fleet pool.
 */
export const HUNT_POOL_SIZE = 5;

/** Seconds threshold for considering a node 'Online' in SQL status queries. */
export const NODE_STATUS_ONLINE_THRESHOLD_SECONDS = 60; // consts/websocket.ts's NODE_ONLINE_SECONDS_LIMIT re-exports this value, keeping the SQL and websocket status paths in sync

/** Maximum number of rows returned by the alert export endpoint. */
export const ALERT_EXPORT_MAX_ROWS = 10000;

/** Default row cap for a threat-hunting SQL query when no `limit` is given in the request body. */
export const THREAT_HUNTING_DEFAULT_ROW_LIMIT = 10000;

/** Hard ceiling a threat-hunting SQL query's row cap is clamped to, regardless of the requested `limit`. */
export const THREAT_HUNTING_MAX_ROW_LIMIT = 50000;

/**
 * Width (in `id` values) of the "recent rows" window used by latest-snapshot
 * queries of the form `id > (SELECT COALESCE(MAX(id), 0) - N FROM table)`.
 * Cheaper than a full `MAX(unixtime)`/window-function scan on large,
 * append-only per-host tables: it narrows to a recent slice of rows by id
 * before filtering by host_identifier and taking the latest one.
 */
/**
 * Connection-level safety timeouts applied to every pg pool.
 *
 * Deliberately set ABOVE the Express-level REQUEST_TIMEOUT_MS (30s) watchdog
 * rather than at or below it. The watchdog already returns 504 to the client
 * at 30s, but it does not cancel the Postgres query — the backend stays busy
 * and keeps occupying one of the POOL_SIZE slots, potentially for as long as
 * the query runs. Putting the DB timeout below 30s would change what clients
 * see (a 500 from a cancelled statement instead of today's 504); putting it
 * above means the watchdog always wins the race, the response is byte-identical
 * to today, and the abandoned query is reaped shortly after instead of never.
 */
export const DB_STATEMENT_TIMEOUT_MS = 45000;

/** Client-side backstop for the above, in case the server never answers. */
export const DB_QUERY_TIMEOUT_MS_POOL = 50000;

/**
 * Caps a transaction left open across awaits. Comfortably above any legitimate
 * transaction in this codebase; exists so a future regression surfaces as a
 * reaped connection rather than a pool slot lost until restart.
 */
export const DB_IDLE_IN_TRANSACTION_TIMEOUT_MS = 60000;

/** Reap pooled connections idle this long, instead of holding them for months. */
export const DB_POOL_IDLE_TIMEOUT_MS = 30000;

/**
 * Cap on waiting for a pool slot.
 *
 * This needs care: pg-pool arms this timer on QUEUED WAITERS, not just on the
 * TCP connect, so it is not the harmless "fail fast if the database is
 * unreachable" knob it reads as. Left unset it is an unbounded queue wait, and a
 * saturated pool becomes slow requests that the Express REQUEST_TIMEOUT_MS
 * watchdog turns into a 504. Set too low — a few seconds — a queued request
 * instead errors outright where it would have succeeded a moment later once a
 * slot freed.
 *
 * That is a live risk, not a theoretical one: POOL_SIZE is 10 and shared by all
 * HTTP traffic, every WebSocket agent handler and the cron sweeps, and
 * PATCH_JOB_DISPATCH_CONCURRENCY's own comment cites bulk patch pushes as a real
 * source of contention.
 *
 * Set above REQUEST_TIMEOUT_MS (30s) so the watchdog still wins for HTTP and
 * the client-visible response stays the 504 it is today, while a genuinely
 * wedged pool is still eventually bounded rather than waiting forever.
 */
export const DB_POOL_CONNECTION_TIMEOUT_MS = 40000;

export const RECENT_ROWS_ID_WINDOW = 1000000;

/** Wider variant of RECENT_ROWS_ID_WINDOW for higher-write-volume Windows telemetry tables. */
export const RECENT_ROWS_ID_WINDOW_WIDE = 2000000;

/** Max length (chars) a node critical/uncritical `reason` string is validated to. */
export const NODE_CRITICAL_REASON_MAX_LENGTH = 500;

/** Number of most-recent snapshots returned for compliance-history sparklines/tables. */
export const COMPLIANCE_HISTORY_SNAPSHOT_LIMIT = 10;

/** Default `source` value for a compliance snapshot (certin/irdai/sebi/org) when the caller doesn't supply one — a live (as-of-now) computation rather than a replayed/backfilled one. */
export const COMPLIANCE_SNAPSHOT_DEFAULT_SOURCE = 'live';

/** Selector value for the primary (non-fleet) database in data-retention policy `databaseName`/db-selector fields. */
export const DB_SOURCE_PRIMARY = 'primary';

/** Selector value for the fleet database in data-retention policy `databaseName`/db-selector fields. */
export const DB_SOURCE_FLEET = 'fleet';

/** Column length (chars) for the hex-encoded AES-GCM IV and auth-tag columns paired with an encrypted secret. */
export const ENCRYPTED_FIELD_HEX_LENGTH = 64;

/** Postgres session variable (via set_config/current_setting) carrying the caller's group scope for RLS policies on the vajra_hunt role. */
export const RLS_GROUP_SESSION_VAR = 'vajra.groups';

/** Lifecycle states shared by one-time bearer token entities (AgentCertProvisioningToken). */
export const TOKEN_STATUS_ACTIVE = 'active';
export const TOKEN_STATUS_USED = 'used';
export const TOKEN_STATUS_REVOKED = 'revoked';
export type TokenStatus = typeof TOKEN_STATUS_ACTIVE | typeof TOKEN_STATUS_USED | typeof TOKEN_STATUS_REVOKED;
