import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { NODE_STATUS_ONLINE_THRESHOLD_SECONDS, RECENT_ROWS_ID_WINDOW } from '../../consts';
import {
  isWindowsPlatform,
  normalizeWindowsMemoryMetricToBytes,
  WINDOWS_MEMORY_RAW_LIKELY_KILOBYTES_BELOW_BYTES,
} from '../../utils/windowsMemory';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { isPgUndefinedTableError } from '../../utils/dbErrors';

const logger = getLogger('nodes.details');

/** True when nodes.hardware_physical_memory is missing or not a usable byte count (e.g. NaN from osquery on Windows). */
function isValidPhysicalMemoryBytes(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  const s = String(value).trim();
  if (!s) return false;
  const lower = s.toLowerCase();
  if (lower === 'nan' || lower === 'null' || lower === 'undefined') return false;
  const n = typeof value === 'number' ? value : parseInt(s, 10);
  return Number.isFinite(n) && n >= 0;
}

function windowsHardwareRamLikelyKilobytes(bytesOrKb: unknown): boolean {
  if (!isValidPhysicalMemoryBytes(bytesOrKb)) return false;
  const n = typeof bytesOrKb === 'number' ? bytesOrKb : parseInt(String(bytesOrKb).trim(), 10);
  return n > 0 && n < WINDOWS_MEMORY_RAW_LIKELY_KILOBYTES_BELOW_BYTES;
}

export async function node_detail(req: Request, res: Response, _next: NextFunction) {
  try {
    const { host_identifier } = req.params;

    if (!host_identifier) {
      return res.status(400).json({
        success: false,
        message: 'Host identifier is required'
      });
    }

    const dataSources = dbSourceConnection();

    if (!dataSources || dataSources.length < 2) {
      logger.error({ host_identifier }, 'Database connection not initialized while fetching node details');
      return res.status(500).json({
        success: false,
        message: 'Database connection not initialized'
      });
    }

    const entityManager = dataSources[1];

    const jwtPayload = (req as any).jwtPayload;
    const scope = jwtPayload?.id
      ? await getUserNodeScope(jwtPayload.id)
      : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, host_identifier))) {
      logger.warn({ host_identifier }, 'Node details request rejected: host not in caller scope');
      return res.status(404).json({
        success: false,
        message: 'Node not found'
      });
    }

    const query = `
      SELECT
        host_identifier,
        hostname,
        device_group,

        isolated,

        os_name,
        os_platform,
        os_arch,
        os_build,
        os_major,
        os_minor,
        osquery_version,

        hardware_vendor,
        hardware_model,
        hardware_cpu_type,
        hardware_cpu_logical_core,
        hardware_physical_memory,

        enrolled_on,
        last_seen,

        CASE
          WHEN (EXTRACT(EPOCH FROM NOW()) - CAST(last_seen AS INTEGER)) < $2
          THEN 'Online'
          ELSE 'Offline'
        END AS status

      FROM nodes
      WHERE host_identifier = $1
      LIMIT 1
    `;

    const result = await entityManager.query(query, [
      host_identifier,
      NODE_STATUS_ONLINE_THRESHOLD_SECONDS
    ]);

    if (!result?.length) {
      // Anomalous: assertHostInScope above confirmed this host is in the
      // caller's scope, yet the row is missing here — stale scope cache or
      // the node was deleted in between.
      logger.warn({ host_identifier }, 'Node not found in nodes table while fetching details, despite passing scope check');
      return res.status(404).json({
        success: false,
        message: 'Node not found'
      });
    }

    const row = result[0] as Record<string, unknown>;

    if (isWindowsPlatform(row.os_platform as string | undefined)) {
      let memRows: { memory_total: string | number | null }[] = [];
      try {
        // Do not "optimise" this query without re-measuring across every host. Four
        // obvious-looking rewrites — hoisting the LIMIT 1 above the guard, adding
        // `ORDER BY host_identifier, id DESC`, a MATERIALIZED CTE joined to the table,
        // and `host_identifier = ANY(ARRAY[$1])` — were all measured and all slower,
        // some catastrophically.
        //
        // There are two candidate plans:
        //   (a) Index Scan Backward on idx_memory_info_host_id (host_identifier, id DESC)
        //       — a handful of buffers, always fast.
        //   (b) Index Scan Backward on memory_info_pkey (id) with host_identifier as a
        //       Filter.
        // The planner picks (b) for a minority of hosts because it assumes a host's rows
        // are spread uniformly over the id range. That assumption is false for a host
        // that has STOPPED reporting: all of its rows sit at the low end, so plan (b)
        // walks backwards through the whole window.
        //
        // The `id >` guard is therefore load-bearing, not decorative — it is what caps
        // that walk at RECENT_ROWS_ID_WINDOW entries. Hoisting the LIMIT 1 above it
        // removes the cap and the same host scans millions of rows instead.
        //
        // `ORDER BY host_identifier, id DESC` looks like it should force plan (a), since
        // only the composite index supplies that order. It does not: `host_identifier =
        // $1` puts the column in a constant equivalence class, so Postgres canonicalises
        // the pathkey away. Forcing (a) would need an index hint (unavailable) or making
        // host_identifier non-constant via a join, and the join then costs the nested
        // loop its ordering and forces a full sort of the host's rows.
        memRows = await entityManager.query(
          `
        SELECT memory_total
        FROM memory_info
        WHERE host_identifier = $1
          AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM memory_info)
        ORDER BY id DESC
        LIMIT 1
        `,
          [host_identifier]
        );
      } catch (memErr: unknown) {
        if (isPgUndefinedTableError(memErr)) {
          logger.debug({ host_identifier }, 'memory_info relation missing, skipping Windows RAM enrichment');
          row.memory_metrics_unavailable_reason =
            'Live memory metrics are unavailable (memory_info table is not provisioned on the server).';
        } else {
          // Distinct from the outer catch's generic failure log — without this,
          // a memory_info query failure here is indistinguishable in the logs
          // from the main `nodes` query above failing.
          logger.error({ err: memErr, host_identifier }, 'memory_info query failed during Windows RAM enrichment');
          throw memErr;
        }
      }
      const total = memRows?.[0]?.memory_total;
      if (total !== null && total !== undefined && String(total).trim() !== '') {
        const raw = typeof total === 'number' ? total : parseInt(String(total).trim(), 10);
        row.hardware_physical_memory = String(normalizeWindowsMemoryMetricToBytes(raw));
      } else if (windowsHardwareRamLikelyKilobytes(row.hardware_physical_memory)) {
        const kb =
          typeof row.hardware_physical_memory === 'number'
            ? row.hardware_physical_memory
            : parseInt(String(row.hardware_physical_memory).trim(), 10);
        row.hardware_physical_memory = String(normalizeWindowsMemoryMetricToBytes(kb));
      } else if (!isValidPhysicalMemoryBytes(row.hardware_physical_memory)) {
        // keep invalid; frontend shows N/A
        logger.debug({ host_identifier }, 'No usable Windows RAM value from memory_info or nodes.hardware_physical_memory, leaving as-is');
      }
    }

    logger.debug({ host_identifier }, 'Node details retrieved');

    return res.status(200).json({
      success: true,
      data: row
    });

  } catch (error) {
    logger.error({ err: error, host_identifier: req.params.host_identifier }, 'Failed to fetch node details');

    return res.status(500).json({
      success: false,
      message: 'Internal Server Error'
    });
  }
}