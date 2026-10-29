import { dbSourceConnection } from '../../index';
import { Request, Response, NextFunction } from 'express';
import {
  isWindowsPlatform,
  WINDOWS_MEMORY_RAW_LIKELY_KILOBYTES_BELOW_BYTES,
} from '../../utils/windowsMemory';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { RECENT_ROWS_ID_WINDOW_WIDE } from '../../consts/database';
import { isPgUndefinedTableError } from '../../utils/dbErrors';

const logger = getLogger('windows.memoryInfo');

interface MemoryRow {
  unixtime: number;
  memory_total: number;
  memory_available: number;
  os_platform: string | null;
}

export async function nodes_memory_health(
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const host_identifier = req.body.host_identifier || req.query.host_identifier;

  if (typeof host_identifier !== 'string' || !host_identifier.trim()) {
    return res.status(400).json({
      status: 'Error',
      message: 'Missing required parameter: host_identifier',
    });
  }

  const dataSources = dbSourceConnection();

  if (!dataSources?.[1]) {
    logger.error({ host_identifier }, 'Database connection error');
    return res.status(500).json({
      status: 'Error',
      message: 'Database connection error',
    });
  }

  const entityManager = dataSources[1];

  const jwtPayload = (req as any).jwtPayload;
  const scope = jwtPayload?.id
    ? await getUserNodeScope(jwtPayload.id)
    : { unrestricted: false as const, groups: [] };
  if (!(await assertHostInScope(scope, host_identifier))) {
    logger.warn({ host_identifier, userId: jwtPayload?.id }, 'Memory health lookup denied, host out of caller scope');
    return res.status(404).json({ status: 'Error', message: 'Node not found' });
  }

  const INTERVAL_SECONDS = 30;   // 30s buckets
  const TOTAL_SECONDS = 300;     // 5 minutes

  const endTime = Math.floor(Date.now() / 1000);
  const startTime = endTime - TOTAL_SECONDS;

  try {
    // The host and the id window are pinned into single-row MATERIALIZED CTEs and
    // joined in, rather than written as plain `WHERE m.host_identifier = $1 AND
    // m.id > (SELECT ...)` predicates. This is an access-path change only: `h` and
    // `lo` each yield exactly one row, so the joins are no-op multipliers and the
    // surviving rows, groups and ordering are unchanged.
    //
    // memory_info carries idx_memory_info_host_id (host_identifier, id DESC), which
    // satisfies both predicates, but the flat form never reaches it: with `id >`
    // written as an ordinary comparison against an InitPlan scalar the planner
    // treats it as the cheapest available index bound, drives the scan off
    // memory_info_pkey across the whole id window and applies host_identifier as a
    // post-filter. Materialising the host makes it a runtime value the planner
    // cannot fold into that pkey bound, so it reaches for the host index instead.
    // A residual cost remains: unixtime is in no index, so the host's whole
    // id-window slice is still scanned to find the few recent rows. Closing that
    // needs an index on (host_identifier, unixtime), which is a migration, not a
    // query change.
    //
    // The `id > MAX(id) - RECENT_ROWS_ID_WINDOW_WIDE` guard is load-bearing for the
    // result set, not dead weight; it is only relocated to the join condition.
    const result: MemoryRow[] = await entityManager.query(
      `
      WITH lo AS MATERIALIZED (
        SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} AS min_id FROM memory_info
      ),
      h AS MATERIALIZED (
        SELECT $1::varchar AS hid
      )
      SELECT
        MIN(m.unixtime) as unixtime,
        AVG(m.memory_total)::bigint as memory_total,
        AVG(m.memory_available)::bigint as memory_available,
        MAX(n.os_platform) as os_platform
      FROM h
      CROSS JOIN lo
      JOIN memory_info m
        ON m.host_identifier = h.hid
       AND m.id > lo.min_id
      LEFT JOIN nodes n ON n.host_identifier = m.host_identifier
      WHERE m.unixtime BETWEEN $2 AND $3
      GROUP BY FLOOR(m.unixtime / $4)
      ORDER BY unixtime ASC
      `,
      [host_identifier, startTime, endTime, INTERVAL_SECONDS]
    );

    logger.debug({ host_identifier, count: result.length }, 'Memory health retrieved');

    if (!result.length) {
      return res.status(200).json({
        status: 'Success',
        message: 'No memory data found for this host in the last 5 minutes.',
        data: [],
      });
    }

    const memory_health = result.map((row) => {
      const win = isWindowsPlatform(row.os_platform);
      const totalRaw = Number(row.memory_total);
      const availRaw = Number(row.memory_available);
      // Decide KB-vs-bytes once from memory_total (the only field for which the
      // low-value heuristic is valid) and apply that same decision to
      // memory_available, instead of re-guessing per field.
      const isKB =
        win &&
        Number.isFinite(totalRaw) &&
        totalRaw > 0 &&
        totalRaw < WINDOWS_MEMORY_RAW_LIKELY_KILOBYTES_BELOW_BYTES;
      const totalBytes = isKB ? Math.round(totalRaw * 1024) : totalRaw;
      const availBytes = isKB ? Math.round(availRaw * 1024) : availRaw;
      const memoryUsed = totalBytes - availBytes;

      return {
        memory_total: +(totalBytes / (1024 * 1024)).toFixed(2),
        memory_usage: +(memoryUsed / (1024 * 1024)).toFixed(2),
        time: row.unixtime,
      };
    });

    return res.status(200).json({
      status: 'Success',
      message: 'Memory health fetched successfully.',
      data: memory_health,
    });

  } catch (error) {
    if (isPgUndefinedTableError(error)) {
      logger.debug({ err: error, host_identifier }, 'Memory info table not provisioned, returning unavailable status');
      return res.status(200).json({
        status: 'Unavailable',
        message:
          'Live memory metrics are unavailable (memory_info table is not provisioned on the server).',
        data: [],
      });
    }

    logger.error({ err: error, host_identifier }, 'Failed to fetch memory health');
    return res.status(500).json({
      status: 'Error',
      message: error instanceof Error
        ? error.message
        : 'Unknown database error',
    });
  }
}