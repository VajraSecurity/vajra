import { DataSource } from 'typeorm';
import * as cron from 'node-cron';
import { NodeAssignmentRule, NODE_ASSIGNMENT_CONDITION_TYPE_IP_CIDR } from '../orm/entities/fleet/NodeAssignmentRule';
import { NODE_AUTO_ASSIGN_CRON_EXPRESSION } from '../consts';
import { getLogger } from '../utils/logger';
import { IPV4_OCTET_PATTERN } from '../controllers/node-assignment-rules/validateCondition';
import { returningRowCount } from '../utils/returningRows';

const logger = getLogger('services.nodeAutoAssign');

// Only accept a plain dotted-quad IPv4 address before it's cast to ::inet in SQL,
// so a garbage/IPv6 value reported by an agent can't blow up the query. Each octet
// is range-checked (0-255), not just digit-counted, so a malformed value like
// '999.1.2.3' is filtered out here instead of reaching (and failing) the ::inet cast.
const IPV4_ADDRESS_SQL_PATTERN = `^${IPV4_OCTET_PATTERN}\\.${IPV4_OCTET_PATTERN}\\.${IPV4_OCTET_PATTERN}\\.${IPV4_OCTET_PATTERN}$`;

export class NodeAutoAssignService {
  private fleetDb: DataSource;
  private task: cron.ScheduledTask | null = null;
  private running = false;

  constructor(fleetDb: DataSource) {
    this.fleetDb = fleetDb;
  }

  public start() {
    if (this.task) {
      this.task.stop();
    }
    this.task = cron.schedule(NODE_AUTO_ASSIGN_CRON_EXPRESSION, () => {
      // runAssignment() only rejects via the rules-load failure below, which logs
      // its own message before rethrowing. This catch is a safety net for the
      // unforeseen, so it stays quiet for an already-logged rejection.
      this.runAssignment().catch((err) => {
        if (!(err && typeof err === 'object' && (err as any).__loggedByRunAssignment)) {
          logger.error({ err }, 'Scheduled node auto-assign run failed');
        }
      });
    });
    logger.info({ cronExpression: NODE_AUTO_ASSIGN_CRON_EXPRESSION }, 'Node auto-assign scheduler started');
  }

  public stop() {
    const wasRunning = !!this.task;
    this.task?.stop();
    this.task = null;
    if (wasRunning) {
      logger.info('Node auto-assign scheduler stopped');
    }
  }

  /**
   * Evaluates enabled rules (by priority, ascending) against nodes that have no group yet.
   * A node is claimed by the first rule whose CIDR contains its address; once claimed it's
   * no longer eligible, so lower-priority rules can't re-match it in the same run.
   * Nodes matching no rule are left untouched and are retried on the next run.
   *
   * owner_group_id is the authoritative column every access-scoping decision
   * reads (REST scoping, RLS policies, the live host->group map); a node belongs
   * to at most one group. group_ids is written alongside it only so the
   * group-management UI, which still reads it for chips and labels, shows
   * auto-assigned nodes; no enforcement path reads it. "Already assigned" is
   * judged by owner_group_id too, so a node assigned manually via
   * assign_nodes.ts is skipped here.
   */
  public async runAssignment(): Promise<{ rulesEvaluated: number; totalAssigned: number }> {
    if (this.running) {
      logger.info('Node auto-assign run still in progress from a previous tick — skipping');
      return { rulesEvaluated: 0, totalAssigned: 0 };
    }
    this.running = true;

    let totalAssigned = 0;
    let rulesEvaluated = 0;

    try {
      const ruleRepo = this.fleetDb.getRepository(NodeAssignmentRule);
      let rules: NodeAssignmentRule[];
      try {
        rules = await ruleRepo.find({ where: { enabled: true }, order: { priority: 'ASC', id: 'ASC' } });
      } catch (err) {
        logger.error({ err }, 'Node auto-assign run failed: could not load enabled assignment rules');
        if (err && typeof err === 'object') (err as any).__loggedByRunAssignment = true;
        throw err;
      }

      for (const rule of rules) {
        if (rule.conditionType !== NODE_ASSIGNMENT_CONDITION_TYPE_IP_CIDR) {
          logger.warn({ ruleId: rule.id, ruleName: rule.name, conditionType: rule.conditionType }, 'Node auto-assign rule has an unsupported condition type; skipping');
          continue;
        }
        rulesEvaluated++;

        let matchedCount = 0;
        try {
          // returningRowCount, not `.length`: TypeORM hands back [rows, rowCount]
          // for an UPDATE, so `.length` is always 2 and would be persisted as a
          // constant 2 in rule.lastMatchedCount below.
          const matched = await this.fleetDb.query(
            `
              UPDATE nodes
              SET owner_group_id = $1, group_ids = jsonb_build_array($1::text)
              WHERE owner_group_id IS NULL
                AND address IS NOT NULL
                AND address ~ '${IPV4_ADDRESS_SQL_PATTERN}'
                AND address::inet <<= $2::cidr
              RETURNING host_identifier
            `,
            [rule.groupId, rule.conditionValue]
          );

          matchedCount = returningRowCount(matched);
          totalAssigned += matchedCount;
        } catch (err) {
          logger.error({ err, ruleId: rule.id, ruleName: rule.name }, 'Node auto-assign rule failed to match/assign nodes');
          continue;
        }

        try {
          await ruleRepo.update(rule.id, {
            lastRunAt: new Date(),
            lastMatchedCount: matchedCount,
          });
        } catch (err) {
          // The node assignment above already committed; only this rule's own
          // bookkeeping failed to save. Kept separate from the match/assign
          // failure log above, which means no nodes were touched at all.
          logger.error({ err, ruleId: rule.id, ruleName: rule.name, matchedCount }, 'Node auto-assign rule matched and assigned nodes but failed to record last-run metadata on the rule');
        }
      }

      logger.info({ totalAssigned, rulesEvaluated, totalRules: rules.length }, 'Node auto-assign run finished');
    } finally {
      this.running = false;
    }

    return { rulesEvaluated, totalAssigned };
  }
}

let instance: NodeAutoAssignService | null = null;

export function setNodeAutoAssignServiceInstance(service: NodeAutoAssignService) {
  instance = service;
}

export function getNodeAutoAssignServiceInstance(): NodeAutoAssignService | null {
  return instance;
}
