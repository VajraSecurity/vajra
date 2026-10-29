import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { RECENT_ROWS_ID_WINDOW_WIDE } from '../../consts/database';
import {
  ERROR_MISSING_HOST_IDENTIFIER,
  ERROR_DATABASE_CONNECTION,
  ERROR_NODE_NOT_FOUND,
  ERROR_DATABASE_FETCH_FAILED,
} from '../../consts/http';
import { getLogger } from '../../utils/logger';

const logger = getLogger('windows.firewallRules');

export async function firewall_rules_fetch(
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const { host_identifier, unixtime } = req.body;

  if (!host_identifier || typeof host_identifier !== 'string') {
    return res.status(400).json({
      status: "Error",
      message: ERROR_MISSING_HOST_IDENTIFIER
    });
  }

  const dataSources = dbSourceConnection();
  if (!dataSources?.[1]) {
    logger.error({ host_identifier }, 'Database connection error');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_CONNECTION
    });
  }

  const entityManager = dataSources[1];

  const scope = (req as any).jwtPayload?.id
    ? await getUserNodeScope((req as any).jwtPayload.id)
    : { unrestricted: false as const, groups: [] };
  if (!(await assertHostInScope(scope, host_identifier))) {
    logger.warn({ host_identifier, userId: (req as any).jwtPayload?.id }, 'Firewall rules lookup denied, host out of caller scope');
    return res.status(404).json({ status: "Error", message: ERROR_NODE_NOT_FOUND });
  }

  try {
    let snapshotTime: string | null = null;
    let queryStr = "";
    let params: any[] = [];

    if (unixtime) {
      const parsedUnixTime = Number(unixtime);
      if (!Number.isFinite(parsedUnixTime)) {
        return res.status(400).json({
          status: "Error",
          message: "Invalid unixtime value"
        });
      }
      snapshotTime = String(parsedUnixTime);
    } else {
      // Fetch latest snapshot timestamp first (avoids deduping across older snapshots).
      const latestSnapshotRows: Array<{ unixtime: string }> = await entityManager.query(
        `
          SELECT unixtime
          FROM windows_firewall_rules
          WHERE host_identifier = $1
            AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} FROM windows_firewall_rules)
          ORDER BY unixtime::bigint DESC
          LIMIT 1
        `,
        [host_identifier]
      );
      snapshotTime = latestSnapshotRows[0]?.unixtime || null;
    }

    if (!snapshotTime) {
      logger.debug({ host_identifier, requestedUnixtime: unixtime ?? null }, 'No firewall rule snapshot found for host');
      return res.status(404).json({
        status: "Error",
        message: "No firewall rules found for this host"
      });
    }

    // Dedupe within a single snapshot only, then pick latest row by id for each rule key.
    queryStr = `
      WITH snapshot_rules AS (
        SELECT *
        FROM windows_firewall_rules
        WHERE host_identifier = $1
          AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} FROM windows_firewall_rules)
          AND unixtime = $2
      ),
      ranked_rules AS (
        SELECT
          *,
          ROW_NUMBER() OVER (
            PARTITION BY name, direction, protocol
            ORDER BY id DESC
          ) AS rn
        FROM snapshot_rules
      )
      SELECT *
      FROM ranked_rules
      WHERE rn = 1
      ORDER BY name, direction, protocol
    `;
    params = [host_identifier, snapshotTime];

    const result = await entityManager.query(queryStr, params);

    if (!result?.length) {
      logger.debug({ host_identifier, snapshotTime }, 'Firewall rule snapshot found but contained no rules for host');
      return res.status(404).json({
        status: "Error",
        message: "No firewall rules found for this host"
      });
    }

    logger.debug({ host_identifier, count: result.length, snapshotTime, requestedUnixtime: unixtime ?? null }, 'Firewall rules retrieved');
    return res.status(200).json({
      status: "Success",
      message: "Firewall rules fetched successfully.",
      data: result
    });

  } catch (error) {
    logger.error({ err: error, host_identifier }, 'Failed to fetch firewall rules');
    return res.status(500).json({
      status: "Error",
      message: ERROR_DATABASE_FETCH_FAILED
    });
  }
}