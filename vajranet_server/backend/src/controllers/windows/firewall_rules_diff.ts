import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { RECENT_ROWS_ID_WINDOW_WIDE } from '../../consts/database';
import { ERROR_DATABASE_CONNECTION, ERROR_NODE_NOT_FOUND } from '../../consts/http';
import { getLogger } from '../../utils/logger';

const logger = getLogger('windows.firewallRulesDiff');

type FirewallRuleRow = {
  id: string;
  host_identifier: string;
  unixtime: string;
  name: string;
  app_name: string;
  action: string;
  enabled: number;
  grouping: string;
  direction: string;
  protocol: string;
  local_addresses: string;
  remote_addresses: string;
  local_ports: string;
  remote_ports: string;
  icmp_types_codes: string;
  profile_domain: number;
  profile_private: number;
  profile_public: number;
  service_name: string;
};

type ModifiedChange = {
  rule_identifier: string;
  name: string;
  from_unixtime: string;
  to_unixtime: string;
  changes: { old_state: FirewallRuleRow; new_state: FirewallRuleRow };
};

const fieldsToCompare: Array<keyof FirewallRuleRow> = [
  'action',
  'enabled',
  'local_addresses',
  'remote_addresses',
  'local_ports',
  'remote_ports',
  'icmp_types_codes',
  'profile_domain',
  'profile_private',
  'profile_public',
  'app_name',
  'service_name',
  'grouping'
];

const makeRuleKey = (rule: FirewallRuleRow) =>
  `${rule.name}|${rule.direction}|${rule.protocol}`;

const normalizeValue = (value: unknown) =>
  value === null || value === undefined ? '' : String(value);

const isRuleModified = (oldRule: FirewallRuleRow, newRule: FirewallRuleRow) => {
  for (const field of fieldsToCompare) {
    if (normalizeValue(oldRule[field]) !== normalizeValue(newRule[field])) {
      return true;
    }
  }
  return false;
};

const buildSnapshotMap = (rules: FirewallRuleRow[]) => {
  const map = new Map<string, FirewallRuleRow>();
  for (const rule of rules) {
    const key = makeRuleKey(rule);
    if (!map.has(key)) {
      map.set(key, rule);
    }
  }
  return map;
};

export async function firewall_rules_diff(
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const { host_identifier, start_time, end_time } = req.body;

  const missingStart =
    start_time === undefined || start_time === null || start_time === '';
  const missingEnd =
    end_time === undefined || end_time === null || end_time === '';

  // Guard against missing required fields without rejecting valid numeric values like `0`.
  if (!host_identifier || missingStart || missingEnd) {
    return res.status(400).json({
      status: "Error",
      message: "Missing required fields: host_identifier, start_time, or end_time"
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
    logger.warn({ host_identifier, userId: (req as any).jwtPayload?.id }, 'Firewall rules diff denied, host out of caller scope');
    return res.status(404).json({ status: "Error", message: ERROR_NODE_NOT_FOUND });
  }

  try {
    const parsedStart = Number(start_time);
    const parsedEnd = Number(end_time);

    if (!Number.isFinite(parsedStart) || !Number.isFinite(parsedEnd)) {
      return res.status(400).json({
        status: 'Error',
        message: 'start_time and end_time must be valid unix timestamps'
      });
    }

    if (parsedStart > parsedEnd) {
      return res.status(400).json({
        status: 'Error',
        message: 'start_time cannot be greater than end_time'
      });
    }

    const startSnapshotRows: Array<{ unixtime: string }> = await entityManager.query(
      `
        SELECT DISTINCT unixtime
        FROM windows_firewall_rules
        WHERE host_identifier = $1
          AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} FROM windows_firewall_rules)
          AND unixtime::bigint >= $2::bigint
        ORDER BY unixtime::bigint ASC
        LIMIT 1
      `,
      [host_identifier, String(parsedStart)]
    );

    const endSnapshotRows: Array<{ unixtime: string }> = await entityManager.query(
      `
        SELECT DISTINCT unixtime
        FROM windows_firewall_rules
        WHERE host_identifier = $1
          AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} FROM windows_firewall_rules)
          AND unixtime::bigint <= $2::bigint
        ORDER BY unixtime::bigint DESC
        LIMIT 1
      `,
      [host_identifier, String(parsedEnd)]
    );

    const actualStart = startSnapshotRows[0]?.unixtime || null;
    const actualEnd = endSnapshotRows[0]?.unixtime || null;

    if (!actualStart || !actualEnd) {
      logger.info({ host_identifier, start_time, end_time }, 'No firewall snapshots found in requested time range');
      return res.status(404).json({
        status: 'Error',
        message: 'No firewall snapshots found in the requested time range'
      });
    }

    if (Number(actualStart) > Number(actualEnd)) {
      logger.info({ host_identifier, start_time, end_time, actualStart, actualEnd }, 'No overlapping firewall snapshots found between start_time and end_time');
      return res.status(404).json({
        status: 'Error',
        message: 'No overlapping snapshots found between start_time and end_time'
      });
    }

    // snapshotTimes pins the host and the id window into single-row MATERIALIZED
    // CTEs and joins them in, rather than writing them as plain
    // `WHERE host_identifier = $1 AND id > (SELECT ...)` predicates. This is an
    // access-path change only: `h` and `lo` each yield exactly one row, so the
    // joins are no-op multipliers and the surviving rows and ordering are
    // unchanged. (Same treatment, and same reason, as windows/memory_info.ts.)
    //
    // The flat form makes the planner see two independently indexed predicates and
    // combine them with a BitmapAnd — one bitmap over
    // idx_windows_firewall_rules_host_unixtime, the useful one, plus one over
    // windows_firewall_rules_pkey for the id window. That second bitmap is pure
    // overhead: the id window is a slice wide enough that every row the host/time
    // index already found is inside it, so it removes approximately nothing.
    // Materialising the host makes it a runtime value the planner cannot fold into
    // a pkey bound, so the pkey bitmap disappears and `id > min_id` becomes a cheap
    // join filter on rows already located by the host/time index.
    //
    // The `id > MAX(id) - RECENT_ROWS_ID_WINDOW_WIDE` guard is only relocated to
    // the join condition. It excludes nothing for recent ranges, but it is
    // load-bearing in general: a host whose rows have aged out of the window must
    // keep disappearing from the diff.
    //
    // Two sibling queries are deliberately left in the flat form. The two LIMIT 1
    // snapshot-boundary queries above already stop after one row. The allRules
    // query below does get cheaper in buffers under the same treatment, but
    // materialising the host also costs it its parallel plan, and buffers are not
    // its bottleneck — sorting and returning ~109k wide rows is, and that work is
    // identical either way — so the trade is parallelism for no measured gain.
    const snapshotTimes: Array<{ unixtime: string }> = await entityManager.query(
      `
        WITH lo AS MATERIALIZED (
          SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} AS min_id
          FROM windows_firewall_rules
        ),
        h AS MATERIALIZED ( SELECT $1::varchar AS hid )
        SELECT DISTINCT w.unixtime
        FROM h
        CROSS JOIN lo
        JOIN windows_firewall_rules w
          ON w.host_identifier = h.hid
         AND w.id > lo.min_id
        WHERE w.unixtime::bigint BETWEEN $2::bigint AND $3::bigint
        ORDER BY w.unixtime::bigint ASC
      `,
      [host_identifier, actualStart, actualEnd]
    );

    const allRules: FirewallRuleRow[] = await entityManager.query(
      `
        SELECT *
        FROM windows_firewall_rules
        WHERE host_identifier = $1
          AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW_WIDE} FROM windows_firewall_rules)
          AND unixtime::bigint BETWEEN $2::bigint AND $3::bigint
        ORDER BY unixtime::bigint ASC, name, direction, protocol, id DESC
      `,
      [host_identifier, actualStart, actualEnd]
    );

    const rulesByTime = new Map<string, FirewallRuleRow[]>();
    for (const rule of allRules) {
      const bucket = rulesByTime.get(rule.unixtime);
      if (bucket) {
        bucket.push(rule);
      } else {
        rulesByTime.set(rule.unixtime, [rule]);
      }
    }

    const added: Array<FirewallRuleRow & { at_unixtime: string }> = [];
    const deleted: Array<FirewallRuleRow & { at_unixtime: string }> = [];
    const modified: ModifiedChange[] = [];

    for (let index = 1; index < snapshotTimes.length; index++) {
      const previousTime = snapshotTimes[index - 1].unixtime;
      const currentTime = snapshotTimes[index].unixtime;

      const previousMap = buildSnapshotMap(rulesByTime.get(previousTime) || []);
      const currentMap = buildSnapshotMap(rulesByTime.get(currentTime) || []);

      for (const [key, currentRule] of currentMap.entries()) {
        if (!previousMap.has(key)) {
          added.push({ ...currentRule, at_unixtime: currentTime });
          continue;
        }

        const previousRule = previousMap.get(key)!;
        if (isRuleModified(previousRule, currentRule)) {
          modified.push({
            rule_identifier: key,
            name: currentRule.name,
            from_unixtime: previousTime,
            to_unixtime: currentTime,
            changes: { old_state: previousRule, new_state: currentRule }
          });
        }
      }

      for (const [key, previousRule] of previousMap.entries()) {
        if (!currentMap.has(key)) {
          deleted.push({ ...previousRule, at_unixtime: currentTime });
        }
      }
    }

    const uniqueChangedRuleIds = new Set<string>();
    for (const item of added) {
      uniqueChangedRuleIds.add(makeRuleKey(item));
    }
    for (const item of deleted) {
      uniqueChangedRuleIds.add(makeRuleKey(item));
    }
    for (const item of modified) {
      uniqueChangedRuleIds.add(item.rule_identifier);
    }

    const firstMap = buildSnapshotMap(rulesByTime.get(actualStart) || []);
    const totalUniqueRules = firstMap.size;
    const uniqueUnchangedRules = totalUniqueRules - uniqueChangedRuleIds.size;

    const totalCountEvents = added.length + deleted.length + modified.length;
    const totalCount = uniqueChangedRuleIds.size;

    logger.info(
      {
        host_identifier,
        addedCount: added.length,
        deletedCount: deleted.length,
        modifiedCount: modified.length,
        snapshotsCompared: snapshotTimes.length,
        requestedStart: String(parsedStart),
        requestedEnd: String(parsedEnd),
        actualStart,
        actualEnd,
      },
      'Firewall rules diff generated',
    );
    return res.status(200).json({
      status: "Success",
      message: "Firewall rules diff generated successfully.",
      data: {
        meta: {
          host_identifier,
          requested_start: String(parsedStart),
          actual_start: actualStart,
          requested_end: String(parsedEnd),
          actual_end: actualEnd,
          snapshots_compared: snapshotTimes.length
        },
        summary: {
          added_count: added.length,
          deleted_count: deleted.length,
          modified_count: modified.length,
          unmodified_count: uniqueUnchangedRules,
          unchanged_count: uniqueUnchangedRules,
          total_count_events: totalCountEvents,
          total_count: totalCount,
          unmodified: uniqueUnchangedRules,
          unchanged: uniqueUnchangedRules,
          total_events: totalCountEvents,
          total: totalCount
        },
        added,
        deleted,
        modified
      }
    });

  } catch (error) {
    logger.error({ err: error, host_identifier }, 'Failed to generate firewall rules diff');
    return res.status(500).json({
      status: "Error",
      message: "Failed to generate firewall rules diff."
    });
  }
}