import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { RECENT_ROWS_ID_WINDOW } from '../../consts/database';
import { ERROR_DATABASE_CONNECTION, ERROR_NODE_NOT_FOUND } from '../../consts/http';

const logger = getLogger('nodes.nodeNetworkPosture');

/**
 * Known osquery `protocol` values for listening_ports (IANA protocol
 * numbers). Purely a display label alongside the raw numeric column, not a
 * derived verdict — anything else stays unlabeled rather than guessed.
 */
const PROTOCOL_NAMES: Record<string, string> = { '6': 'tcp', '17': 'udp' };

function parseNumber(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const n = typeof value === 'number' ? value : parseInt(String(value).trim(), 10);
  return Number.isFinite(n) ? n : null;
}

/** Default/max rows per page for the listening-ports endpoint. */
const LISTENING_PORTS_DEFAULT_PAGE_SIZE = 200;
const LISTENING_PORTS_MAX_PAGE_SIZE = 500;

/**
 * GET /api/nodes/network/listening-ports/:host_identifier?limit=&offset=
 *
 * `listening_ports` is NOT a flat snapshot — verified live against the fleet
 * DB before writing this query: every row's `action` column is exactly
 * 'added' or 'removed' (289,908 / 252,058 rows respectively, no other
 * values), which is osquery's standard differential-log format for this
 * table. There is no ingestion code for it in this repo (the table is
 * populated directly by the fleet/osquery pipeline, outside this codebase,
 * the same way `programs` is — see node_programs.ts's comment on that), so
 * the semantics were established from the data itself rather than from
 * source: walking a single (host, port) pair's full row history in id order
 * shows osquery diffs the FULL row, including `pid` — so a process that
 * restarts and rebinds the same port produces a paired
 * remove-old-pid / add-new-pid event even though nothing about the socket
 * meaningfully changed. Concretely, host 2C402E17-B2FE-6C4A-00AB-E89C256BC3CF
 * port 22/tcp/0.0.0.0 shows ten *different* pids each with their own
 * 'added' row across the observed history, each superseded by the next
 * pid's pair, not by an explicit 'removed' row for that same pid.
 *
 * Consequence: grouping "currently listening" by a key that includes `pid`
 * (tried first, against live data) surfaces every historical pid that was
 * ever added on a given port and never itself explicitly removed under that
 * exact key — e.g. 1,946 "currently listening" rows for that host, most of
 * them stale service-restart ghosts. Dropping `pid` from the grouping key —
 * grouping instead by the socket's own identity, (port, protocol, family,
 * address, path, net_namespace) — collapses those restarts into one key per
 * socket and cut the same host down to 1,204 rows whose latest state
 * resolves cleanly (port 22/tcp/0.0.0.0 now correctly yields a single
 * "currently added" row, at whichever pid last rebound it).
 *
 * The query below takes, per that key, the row with the highest `id` (the
 * primary key, so a true total order — `unixtime` is not: many exact ties
 * were observed for the same key, e.g. duplicate 'added' rows logged back to
 * back at identical unixtime) and keeps the key only if that latest row's
 * action is 'added'. `pid` is still returned as an attribute of the winning
 * row — the last pid observed on that socket — just not as part of what
 * identifies the socket.
 *
 * Residual, stated plainly rather than hidden: a key can still show
 * 'added' as stale fact rather than current truth if its own `address`
 * value went stale without ever being explicitly removed — observed live on
 * the same host, whose DHCP-server bindings (port 67/udp) sit on a dozen
 * distinct virtual-adapter addresses (172.21.80.1, 172.22.176.1, ...), most
 * long superseded but each carrying its own never-removed 'added' row
 * because the *address* rotated rather than the port closing. This is a
 * property of the source data (no 'removed' row was ever logged for those
 * addresses), not something a query can correct. That is exactly why every
 * row below carries `observed_at` (the unixtime of that latest row) — so the
 * caller can judge freshness instead of the API silently asserting
 * "currently listening" as an unqualified fact.
 *
 * `id > MAX(id) - RECENT_ROWS_ID_WINDOW` is the same recent-rows guard used
 * by node_storage.ts; at today's live row count (541,889, under the
 * 1,000,000-row window) it excludes nothing yet, but stays in place so a
 * host whose data ages out of the window degrades to empty rather than a
 * full scan of expired rows.
 *
 * There is no index on `host_identifier` on this table (only the `id`
 * primary key) — confirmed via EXPLAIN ANALYZE against the live DB, the
 * query below runs as an index-range scan on the id window followed by a
 * host_identifier filter, ~390ms on the fleet's busiest host (72,898 rows).
 * Acceptable for a per-node detail endpoint; no schema change is available
 * (none permitted) to improve on it.
 */
export async function node_listening_ports(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.params;
    if (!host_identifier) {
      return res.status(400).json({ success: false, message: 'Host identifier is required' });
    }

    const rawLimit = parseNumber(req.query.limit);
    const limit = rawLimit && rawLimit > 0 ? Math.min(rawLimit, LISTENING_PORTS_MAX_PAGE_SIZE) : LISTENING_PORTS_DEFAULT_PAGE_SIZE;
    const rawOffset = parseNumber(req.query.offset);
    const offset = rawOffset && rawOffset > 0 ? rawOffset : 0;

    const dataSources = dbSourceConnection();
    if (!dataSources || dataSources.length < 2) {
      logger.error({ host_identifier }, 'Database connection not initialized');
      return res.status(500).json({ success: false, message: ERROR_DATABASE_CONNECTION });
    }

    const db = dataSources[1];

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.debug({ host_identifier, reason: 'host_out_of_scope' }, 'Listening ports request rejected');
      return res.status(404).json({ success: false, message: ERROR_NODE_NOT_FOUND });
    }

    const rows = await db.query(
      `WITH latest AS (
         SELECT DISTINCT ON (port, protocol, family, address, path, net_namespace)
           pid, port, protocol, family, address, path, net_namespace, unixtime, action
         FROM listening_ports
         WHERE host_identifier = $1
           AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM listening_ports)
         ORDER BY port, protocol, family, address, path, net_namespace, id DESC
       )
       SELECT port, protocol, family, address, pid, path, net_namespace, unixtime
       FROM latest
       WHERE action = 'added'
       ORDER BY port ASC, protocol ASC, address ASC
       LIMIT $2 OFFSET $3`,
      [host_identifier, limit, offset],
    );

    const list = Array.isArray(rows) ? (rows as Array<Record<string, unknown>>) : [];
    const ports = list.map((row) => {
      const protocol = parseNumber(row.protocol);
      return {
        port: parseNumber(row.port),
        protocol,
        protocol_name: protocol !== null ? (PROTOCOL_NAMES[String(protocol)] ?? null) : null,
        family: parseNumber(row.family),
        address: row.address ?? null,
        pid: parseNumber(row.pid),
        path: row.path || null,
        net_namespace: row.net_namespace || null,
        observed_at: parseNumber(row.unixtime),
      };
    });

    logger.debug({ host_identifier, count: ports.length, limit, offset }, 'Listening ports retrieved');
    return res.status(200).json({
      success: true,
      data: {
        ports,
        limit,
        offset,
        has_more: ports.length === limit,
      },
    });
  } catch (err) {
    logger.error({ err, host_identifier: req.params?.host_identifier }, 'Failed to fetch listening ports');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}

/**
 * GET /api/nodes/network/uptime/:host_identifier
 *
 * `win_socket_events` carries `uptime` (seconds since boot) alongside
 * `unixtime` on every row. Last boot = unixtime - uptime, computed from the
 * single most recent row for the host (`idx_win_socket_events_host_time` on
 * (host_identifier, unixtime DESC) makes this an index-only lookup, not a
 * scan).
 *
 * Verified live before trusting this derivation: sampling widely-spaced rows
 * across a host's full history (about a month, ~800,000-second steps) gives
 * a DIFFERENT derived boot time at each sample — expected, since a real host
 * reboots repeatedly over a month and `uptime` resets each time. The
 * meaningful stability check is within one boot session: the ten most recent
 * consecutive rows for two different Windows hosts
 * (2C402E17-B2FE-6C4A-00AB-E89C256BC3CF and
 * 03560230-040F-0533-4D06-C10700080009) each resolve to the exact same
 * derived boot_unixtime to the second, and both land on plausible calendar
 * dates in the recent past (2026-08-27 and 2026-08-20 respectively, against
 * observation times of 2026-08-27 and 2026-09-03) — not epoch-zero, not in
 * the future, not wildly precise/unstable jitter. That stability is what
 * makes the derivation defensible; it is not asserted from the column
 * documentation alone.
 *
 * Both `boot_unixtime` (derived) and `observed_at` (the row's own unixtime)
 * are returned so the caller can judge how stale the reading is — a node
 * that stopped reporting days ago (observed live: one Windows host's newest
 * win_socket_events row is a week old) should not be read as "rebooted
 * recently" just because the derived boot time itself looks recent.
 *
 * This is a tracking control only (SEBI display 30 / key 32: "system uptime
 * and last reboot time are tracked") — no uptime-duration threshold is
 * applied or implied here; see the doctrine in the task for why inventing
 * one would be out of scope.
 *
 * A row with a non-finite `uptime`/`unixtime`, or one where the derived
 * boot_unixtime would be negative or later than the observation itself
 * (uptime negative or corrupt), is not defensible and is not returned —
 * `data` comes back null in that case, same as "no rows found".
 */
export async function node_network_uptime(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.params;
    if (!host_identifier) {
      return res.status(400).json({ success: false, message: 'Host identifier is required' });
    }

    const dataSources = dbSourceConnection();
    if (!dataSources || dataSources.length < 2) {
      logger.error({ host_identifier }, 'Database connection not initialized');
      return res.status(500).json({ success: false, message: ERROR_DATABASE_CONNECTION });
    }

    const db = dataSources[1];

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.debug({ host_identifier, reason: 'host_out_of_scope' }, 'Node uptime request rejected');
      return res.status(404).json({ success: false, message: ERROR_NODE_NOT_FOUND });
    }

    const rows = await db.query(
      `SELECT unixtime, uptime
       FROM win_socket_events
       WHERE host_identifier = $1
       ORDER BY unixtime DESC
       LIMIT 1`,
      [host_identifier],
    );

    const row = Array.isArray(rows) && rows.length ? (rows[0] as Record<string, unknown>) : null;
    const observedAt = row ? parseNumber(row.unixtime) : null;
    const uptimeSeconds = row ? parseNumber(row.uptime) : null;

    let bootUnixtime: number | null = null;
    if (observedAt !== null && uptimeSeconds !== null && uptimeSeconds >= 0) {
      const candidate = observedAt - uptimeSeconds;
      if (candidate > 0 && candidate <= observedAt) {
        bootUnixtime = candidate;
      }
    }

    if (!row || bootUnixtime === null) {
      logger.debug({ host_identifier, found: !!row, defensible: bootUnixtime !== null }, 'Node uptime retrieved');
      return res.status(200).json({ success: true, data: null });
    }

    logger.debug({ host_identifier, observedAt, uptimeSeconds, bootUnixtime }, 'Node uptime retrieved');
    return res.status(200).json({
      success: true,
      data: {
        boot_unixtime: bootUnixtime,
        uptime_seconds: uptimeSeconds,
        observed_at: observedAt,
      },
    });
  } catch (err) {
    logger.error({ err, host_identifier: req.params?.host_identifier }, 'Failed to fetch node uptime');
    return res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
}
