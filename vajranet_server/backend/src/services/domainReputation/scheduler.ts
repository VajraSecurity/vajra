import { DataSource } from 'typeorm';
import * as cron from 'node-cron';
import { DomainReputationTarget } from '../../orm/entities/fleet/DomainReputationTarget';
import { DomainReputationCheckResult } from '../../orm/entities/fleet/DomainReputationCheckResult';
import { checkVirusTotal } from './providers/virustotal';
import { checkAbuseIPDB } from './providers/abuseipdb';
import type { NormalizedReputationResult, ReputationChecker } from './providers/types';
import { getLogger } from '../../utils/logger';
import { sanitizeAxiosError } from '../../utils/sanitizeAxiosError';

const logger = getLogger('services.domainReputation.scheduler');

const PROVIDER_CHECKERS: Record<string, ReputationChecker> = {
  virustotal: checkVirusTotal,
  abuseipdb: checkAbuseIPDB,
};

// Ranks verdicts so a multi-provider run reports the worst one on the target.
const VERDICT_RANK: Record<string, number> = { clean: 0, unknown: 1, error: 1, suspicious: 2, malicious: 3 };

/**
 * Runs the Threat Intel watchlist on node-cron, one job per target — same
 * shape as DataRetentionService. The manual server has no scheduling (Manual Check tab
 * only), so it never appears here.
 */
export class DomainReputationSchedulerService {
  private fleetDb: DataSource;
  private activeJobs: Map<string, cron.ScheduledTask> = new Map();
  // Overlap guard, matching runningFlags/runningPolicyIds/`running` in the other
  // cron services. Every provider call queues behind the shared in-process
  // throttle in ./rateLimiter.ts, and VirusTotal's lane is a handful of requests
  // per minute globally, across all targets and both trigger paths, so a
  // watchlist on a tight schedule cannot finish a tick within a tick. Without
  // this, each tick stacks another run onto a queue that is still draining and
  // the backlog of pending timers and open sockets grows without bound.
  //
  // Membership is maintained for both trigger paths but only the scheduled path
  // skips: the manual "Check Now" endpoint returns this method's results array
  // straight to its caller, so short-circuiting it to [] would change that
  // response. A tick landing during a manual run is still skipped. Being a Set
  // rather than a refcount, two overlapping manual runs on one target un-mark it
  // when the first finishes; only the scheduled pile-up is guarded.
  //
  // Keyed through Number(): DomainReputationTarget.id is a bigint column and
  // node-postgres returns bigints as strings despite the entity's `number`
  // annotation, so without the coercion the cron closure holds "7" while
  // targetsController's parseIdParam produces 7 and the two never see each other.
  private runningTargetIds: Set<number> = new Set();

  constructor(fleetDb: DataSource) {
    this.fleetDb = fleetDb;
  }

  public async initializeJobs(): Promise<void> {
    const repo = this.fleetDb.getRepository(DomainReputationTarget);
    let targets: DomainReputationTarget[];
    try {
      targets = await repo.find({ where: { isActive: true } });
    } catch (err) {
      // Without this a DB hiccup at startup surfaces only in index.ts's generic
      // top-level catch, with nothing naming the scheduler as what failed.
      logger.error({ err }, 'Failed to initialize domain reputation scheduler jobs: could not load targets from the database');
      throw err;
    }
    for (const target of targets) {
      this.scheduleJob(target);
    }
    logger.info({ total: targets.length }, 'Initialized domain reputation scheduler jobs');
  }

  public scheduleJob(target: DomainReputationTarget): void {
    const key = target.id.toString();
    this.activeJobs.get(key)?.stop();
    this.activeJobs.delete(key);

    if (!target.isActive) {
      logger.info({ targetId: target.id, value: target.value }, 'Domain reputation target is inactive; not scheduling');
      return;
    }
    if (!cron.validate(target.cronExpression)) {
      logger.warn({ targetId: target.id, value: target.value, cronExpression: target.cronExpression }, 'Domain reputation target has an invalid cron expression; not scheduling');
      return;
    }

    const task = cron.schedule(target.cronExpression, () => {
      if (this.runningTargetIds.has(Number(target.id))) {
        logger.warn(
          { targetId: target.id, value: target.value, cronExpression: target.cronExpression },
          'Domain reputation check skipped: previous run for this target is still in progress',
        );
        return;
      }
      // Safety net for anything runCheck does not log locally. Its target lookup
      // and persist steps log their own failure before rethrowing (tagged below),
      // so this only prints for something unforeseen.
      this.runCheck(target.id).catch((err) => {
        if (!(err && typeof err === 'object' && (err as any).__loggedByRunCheck)) {
          logger.error({ err, targetId: target.id }, 'Scheduled domain reputation run failed');
        }
      });
    });

    this.activeJobs.set(key, task);
    logger.debug(
      { targetId: target.id, value: target.value, providers: target.providers, cronExpression: target.cronExpression },
      'Scheduled domain reputation check',
    );
  }

  public unscheduleJob(targetId: number): void {
    const key = targetId.toString();
    const existed = this.activeJobs.has(key);
    this.activeJobs.get(key)?.stop();
    this.activeJobs.delete(key);
    if (existed) {
      logger.info({ targetId }, 'Unscheduled domain reputation check');
    }
  }

  public async runCheck(targetId: number, triggeredBy: 'manual' | 'schedule' = 'schedule'): Promise<NormalizedReputationResult[]> {
    // Must stay the first statement, before any await: an async body runs
    // synchronously to its first await, which is what stops a scheduled tick
    // interleaving between scheduleJob's `has` and this `add`.
    const runKey = Number(targetId);
    this.runningTargetIds.add(runKey);
    try {
      return await this.runCheckUnguarded(targetId, triggeredBy);
    } finally {
      this.runningTargetIds.delete(runKey);
    }
  }

  private async runCheckUnguarded(targetId: number, triggeredBy: 'manual' | 'schedule'): Promise<NormalizedReputationResult[]> {
    const targetRepo = this.fleetDb.getRepository(DomainReputationTarget);
    let target: DomainReputationTarget | null;
    try {
      target = await targetRepo.findOne({ where: { id: targetId } });
    } catch (err) {
      logger.error({ err, targetId }, 'Domain reputation check run failed: could not load target from the database');
      if (err && typeof err === 'object') (err as any).__loggedByRunCheck = true;
      throw err;
    }
    if (!target) {
      logger.warn({ targetId }, 'Domain reputation check run requested for unknown target id');
      return [];
    }

    // Captured before this run touches anything: the alert gate below compares
    // the outcome against the verdict the target had going in, not against itself.
    const previousVerdict = target.lastVerdict;

    const resultRepo = this.fleetDb.getRepository(DomainReputationCheckResult);
    const results: NormalizedReputationResult[] = [];
    let worstVerdict = 'clean';
    let skippedProviders = 0;

    for (const provider of target.providers) {
      const checker = PROVIDER_CHECKERS[provider];
      if (!checker) {
        logger.warn({ targetId: target.id, provider }, 'Domain reputation target references an unsupported provider; skipping');
        skippedProviders++;
        continue;
      }

      let result: NormalizedReputationResult;
      try {
        result = await checker(target.value, target.type, target.groupId);
      } catch (err: any) {
        // Providers rethrow the raw AxiosError after logging their own sanitized
        // line, so logging { err } here would leak the API keys
        // utils/sanitizeAxiosError.ts exists to strip.
        logger.error({ err: sanitizeAxiosError(err), targetId: target.id, value: target.value, provider }, 'Domain reputation check failed');
        result = {
          provider: provider as NormalizedReputationResult['provider'],
          verdict: 'error',
          score: null,
          summary: err.message || 'Check failed',
          raw: null,
        };
      }

      results.push(result);
      try {
        await resultRepo.save(resultRepo.create({
          target_id: target.id,
          group_id: target.groupId,
          value: target.value,
          type: target.type,
          provider: result.provider,
          verdict: result.verdict,
          score: result.score,
          summary: result.summary,
          raw_response: result.raw,
          triggered_by: triggeredBy,
          checked_by_user_id: null,
          checked_by_name: null,
        }));
      } catch (err) {
        logger.error({ err, targetId: target.id, provider: result.provider }, 'Failed to persist domain reputation check result');
        if (err && typeof err === 'object') (err as any).__loggedByRunCheck = true;
        throw err;
      }

      if (VERDICT_RANK[result.verdict] > VERDICT_RANK[worstVerdict]) {
        worstVerdict = result.verdict;
      }
    }

    // Alert only on a change from the target's previous state: on every run, a
    // persistently malicious target on a tight schedule would insert identical
    // alerts forever and drown out new findings.
    if ((worstVerdict === 'malicious' || worstVerdict === 'suspicious') && worstVerdict !== previousVerdict) {
      const worstResult = results.find((r) => r.verdict === worstVerdict) ?? results[0];
      if (worstResult) await this.raiseAlert(target, worstResult);
    }

    try {
      await targetRepo.update(target.id, { lastCheckedAt: new Date(), lastVerdict: worstVerdict });
    } catch (err) {
      logger.error({ err, targetId: target.id, worstVerdict }, 'Failed to update domain reputation target after check');
      if (err && typeof err === 'object') (err as any).__loggedByRunCheck = true;
      throw err;
    }

    // providers/results/skippedProviders show whether every configured provider
    // actually ran; a target silently missing one would otherwise look identical
    // to a clean run.
    logger.info(
      { targetId: target.id, value: target.value, triggeredBy, providers: target.providers, results: results.length, skippedProviders, worstVerdict, previousVerdict },
      'Domain reputation check completed',
    );
    return results;
  }

  private async raiseAlert(target: DomainReputationTarget, result: NormalizedReputationResult): Promise<void> {
    try {
      await this.fleetDb.query(
        `INSERT INTO alerts (host_identifier, hostname, unixTime, event_code, metadata, is_alert, is_open, severity, alert_type)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          'system:domain-reputation',
          target.value,
          Math.floor(Date.now() / 1000),
          `DOMAIN_REPUTATION_${result.verdict.toUpperCase()}`,
          JSON.stringify({ value: target.value, type: target.type, provider: result.provider, score: result.score, summary: result.summary }),
          true,
          true,
          result.verdict === 'malicious' ? 'critical' : 'medium',
          'Domain Reputation Alert',
        ],
      );
      logger.info({ targetId: target.id, value: target.value, verdict: result.verdict, provider: result.provider }, 'Raised domain reputation alert');
    } catch (err) {
      logger.error({ err, targetId: target.id, verdict: result.verdict }, 'Failed to raise domain reputation alert');
    }
  }
}

let instance: DomainReputationSchedulerService | null = null;
export function setDomainReputationSchedulerInstance(svc: DomainReputationSchedulerService): void { instance = svc; }
export function getDomainReputationSchedulerInstance(): DomainReputationSchedulerService | null { return instance; }
