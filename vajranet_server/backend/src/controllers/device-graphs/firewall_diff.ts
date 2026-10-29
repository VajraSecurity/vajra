import { Request, Response, NextFunction } from "express";
import { dbSourceConnection } from "../../index";
import { getUserNodeScope, assertHostInScope } from "../../utils/nodeScope";
import { getLogger } from "../../utils/logger";

const logger = getLogger("controllers.deviceGraphs.firewallDiff");

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
  "action",
  "enabled",
  "local_addresses",
  "remote_addresses",
  "local_ports",
  "remote_ports",
  "icmp_types_codes",
  "profile_domain",
  "profile_private",
  "profile_public",
  "app_name",
  "service_name",
  "grouping"
];

const makeRuleKey = (rule: FirewallRuleRow) =>
  `${rule.name}|${rule.direction}|${rule.protocol}`;

const normalizeValue = (value: unknown) =>
  value === null || value === undefined ? "" : String(value);

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

/**
 * How many snapshots are pulled from Postgres per round trip.
 *
 * The diff walks snapshots pairwise, so only two adjacent snapshots are ever needed at
 * once. Reading the host's whole history instead makes the predicate unselective enough
 * that the planner abandons idx_windows_firewall_rules_host_unixtime for a full scan and
 * a large external sort, and Node then holds every row of that history resident. A
 * bounded window keeps both the plan and peak memory proportional to this constant
 * rather than to how long the host has been reporting.
 *
 * 256 is measured, not guessed, and smaller is not safer: below ~256 rows per batch the
 * estimate falls under the parallel threshold, so each batch runs single-threaded and
 * the many serial sorts cost more in total than one large scan. Past ~384 the gain
 * flattens while memory keeps doubling.
 */
const SNAPSHOT_BATCH_SIZE = 256;

export async function firewall_type(
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const { host_identifier } = req.body;

  if (!host_identifier) {
    return res.status(400).json({
      status: "Error",
      message: "host_identifier is required"
    });
  }

  const dataSources = dbSourceConnection();
  const entityManager = dataSources?.[1];

  if (!entityManager) {
    logger.warn({ host_identifier }, "Firewall rule summary aborted: database connection not initialized");
    return res.status(500).json({
      status: "Error",
      message: "Database connection not initialized"
    });
  }

  const jwtPayload = (req as any).jwtPayload;
  const scope = jwtPayload?.id
    ? await getUserNodeScope(jwtPayload.id)
    : { unrestricted: false as const, groups: [] };
  if (!(await assertHostInScope(scope, host_identifier))) {
    logger.warn({ host_identifier, userId: jwtPayload?.id ?? null }, "Firewall rule summary denied: host outside caller's node scope");
    return res.status(404).json({ status: "Error", message: "Node not found" });
  }

  try {
    const snapshotTimes: Array<{ unixtime: string }> = await entityManager.query(
      `
        SELECT DISTINCT unixtime
        FROM windows_firewall_rules
        WHERE host_identifier = $1
        ORDER BY unixtime::bigint ASC
      `,
      [host_identifier]
    );

    if (!snapshotTimes.length) {
      logger.info({ host_identifier }, "Firewall rule summary retrieved: no snapshots found for this host");
      return res.status(404).json({
        status: "Error",
        message: "No firewall rule snapshots found for this host"
      });
    }

    // Sliding window over the snapshot list: `batchStart` is the index into
    // snapshotTimes that `batchBuckets` covers, and the window only ever moves forward,
    // so each snapshot is fetched exactly once.
    //
    // The batch query's sort key (unixtime, name, direction, protocol, id) must stay a
    // unique total order — `id` is the non-null bigint primary key. Duplicates within a
    // (host, unixtime, name, direction, protocol) group are common, so the `id DESC`
    // tiebreaker is what decides which row buildSnapshotMap() keeps for a rule key.
    // Drop it and two different plans can return different rules.
    let batchStart = -1;
    let batchBuckets = new Map<string, FirewallRuleRow[]>();

    const loadBatchFor = async (index: number) => {
      const start = Math.floor(index / SNAPSHOT_BATCH_SIZE) * SNAPSHOT_BATCH_SIZE;
      if (start === batchStart) {
        return;
      }

      const batchTimes = snapshotTimes
        .slice(start, start + SNAPSHOT_BATCH_SIZE)
        .map((snapshot) => snapshot.unixtime);

      // `unixtime` is nullable, so `SELECT DISTINCT unixtime` above can yield NULL as a
      // legitimate snapshot. `unixtime = ANY(...)` is never true for such a row, so
      // without the explicit IS NULL branch that snapshot would load empty and the
      // preceding snapshot's entire rule set would be reported as `deleted`. Latent
      // today, but the table is written by an external ingest outside this repo, so the
      // column staying non-NULL is not ours to assume.
      const hasNullSnapshot = batchTimes.some((t) => t === null || t === undefined);
      const times = batchTimes.filter((t) => t !== null && t !== undefined);

      /**
       * `SELECT *` cannot be narrowed: `added`, `deleted` and `modified` echo whole
       * rows back to the caller, so every column is part of the response.
       *
       * Pushing buildSnapshotMap()'s de-duplication into SQL as
       * `SELECT DISTINCT ON (unixtime, name, direction, protocol)` is output-equivalent
       * but not faster on a multi-host table: the Unique node sits on the sort that has
       * to happen anyway, so what it saves in client-side row parsing it gives back in
       * server-side filtering. It was measured and deliberately not adopted.
       */
      const rules: FirewallRuleRow[] = await entityManager.query(
        `
        SELECT *
        FROM windows_firewall_rules
        WHERE host_identifier = $1
          AND (unixtime = ANY($2::bigint[]) OR ($3::boolean AND unixtime IS NULL))
        ORDER BY unixtime::bigint ASC, name, direction, protocol, id DESC
      `,
        [host_identifier, times, hasNullSnapshot]
      );

      // A NULL-unixtime snapshot keys under `null`, which Map handles natively.
      const buckets = new Map<string, FirewallRuleRow[]>();
      for (const rule of rules) {
        const bucket = buckets.get(rule.unixtime);
        if (bucket) {
          bucket.push(rule);
        } else {
          buckets.set(rule.unixtime, [rule]);
        }
      }

      // Dropping the previous window here is the whole point: this is what keeps resident
      // memory proportional to SNAPSHOT_BATCH_SIZE instead of to the host's entire history.
      batchStart = start;
      batchBuckets = buckets;
    };

    const snapshotMapAt = async (index: number) => {
      await loadBatchFor(index);
      return buildSnapshotMap(batchBuckets.get(snapshotTimes[index].unixtime) || []);
    };

    // Snapshot 0's rule count must be captured here: the sliding window may have moved
    // past it by the time the total is needed. This is also the only reason snapshot 0
    // is loaded at all when there is a single snapshot and the diff loop never runs.
    let previousMap = await snapshotMapAt(0);
    const totalUniqueRules = previousMap.size;

    const added: Array<FirewallRuleRow & { at_unixtime: string }> = [];
    const deleted: Array<FirewallRuleRow & { at_unixtime: string }> = [];
    const modified: ModifiedChange[] = [];

    for (let index = 1; index < snapshotTimes.length; index++) {
      const previousTime = snapshotTimes[index - 1].unixtime;
      const currentTime = snapshotTimes[index].unixtime;

      // Carried over from the previous iteration so each snapshot is turned into a
      // Map once and never re-fetched after the window moves past it.
      const currentMap = await snapshotMapAt(index);

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
            changes: {
              old_state: previousRule,
              new_state: currentRule
            }
          });
        }
      }

      for (const [key, previousRule] of previousMap.entries()) {
        if (!currentMap.has(key)) {
          deleted.push({ ...previousRule, at_unixtime: currentTime });
        }
      }

      previousMap = currentMap;
    }

    // Rule keys touched anywhere in the history. Feeds the subtraction below, which
    // is a known defect — read the block above that line before touching this.
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

    /**
     * Known defect, intentionally not fixed: this subtracts two counts drawn from
     * different populations, so it is not the number of unchanged rules.
     *
     *   - `totalUniqueRules` is snapshot 0's rule count alone;
     *   - `uniqueChangedRuleIds` accumulates rule keys across the entire history.
     *
     * A rule first seen at a later snapshot inflates the subtrahend without
     * contributing to the minuend, so the result undercounts by the number of rules
     * the host grew after it first reported, and can go negative behind an HTTP 200.
     *
     * The corrected minuend is the union of rule keys across all snapshots rather
     * than snapshot 0's alone. It is not applied because it changes a value this
     * endpoint returns for almost every host, not just the pathological ones, and a
     * changed API response is out of scope here. Clamping with Math.max(0, ...) was
     * also rejected: it hides the only visible symptom while still returning a wrong
     * number.
     */
    const uniqueUnchangedRules = totalUniqueRules - uniqueChangedRuleIds.size;

    /**
     * Unbounded response, deliberately not capped. `added`, `deleted` and `modified`
     * accumulate over the host's entire history and each entry carries whole rows
     * (`modified` carries two), so the body grows with history rather than with
     * SNAPSHOT_BATCH_SIZE — the worst production host replays to a ~12MB body. A
     * limit or pagination parameter would change the response, so it is not added.
     *
     * Before optimising: the wall clock is dominated by fetching and materialising
     * rows, not by serialising them, so capping the payload would not shrink latency.
     * The real lever is skipping snapshots identical to their predecessor, which is a
     * rewrite rather than a tweak.
     */
    const totalEvents = added.length + deleted.length + modified.length;
    const total = uniqueChangedRuleIds.size;

    logger.info(
      { host_identifier, added: added.length, deleted: deleted.length, modified: modified.length },
      "Firewall rule summary generated"
    );
    return res.status(200).json({
      status: "Success",
      message: "Firewall rule summary generated",
      data: {
        host_identifier,
        meta: {
          first_snapshot: snapshotTimes[0].unixtime,
          last_snapshot: snapshotTimes[snapshotTimes.length - 1].unixtime,
          snapshots_compared: snapshotTimes.length
        },
        summary: {
          added: added.length,
          deleted: deleted.length,
          modified: modified.length,
          // `unmodified` and `unchanged` are the same value under two names, kept for
          // back-compat with any caller reading either. Dropping one would change the
          // response body.
          unmodified: uniqueUnchangedRules,
          unchanged: uniqueUnchangedRules,
          total_events: totalEvents,
          total
        },
        added,
        deleted,
        modified
      }
    });

  } catch (error) {
    logger.error({ err: error, host_identifier }, "Failed to generate firewall rule summary");

    return res.status(500).json({
      status: "Error",
      message: "Failed to fetch firewall summary"
    });
  }
}