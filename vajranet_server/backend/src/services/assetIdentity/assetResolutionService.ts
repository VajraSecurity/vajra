import { DataSource } from 'typeorm';
import * as cron from 'node-cron';

import { ASSET_RESOLUTION_CRON_EXPRESSION, OBSERVATION_SOURCES } from '../../consts/assets';
import type { ObservationSource } from '../../types/assetIdentity';
import { getLogger } from '../../utils/logger';
import { runOpenvasFeeder } from './openvasFeeder';

// agentFeeder.ts, arpFeeder.ts, nmapFeeder.ts and nucleiFeeder.ts are
// DELIBERATELY NOT imported here — see DISABLED_SOURCES below.

const logger = getLogger('services.assetIdentity.resolution');

/** What one feeder reports back about its own run. */
export interface FeederResult {
  rows: number;
  observations: number;
  created: number;
  attached: number;
  /**
   * Highest source-table id ingested, to persist as the next watermark. Null
   * from feeders with no monotonic source id (agent, arp, openvas), which are
   * full re-reads or event-driven and leave asset_feed_state.last_source_id
   * alone.
   */
  maxSourceId: string | null;
}

/** Per-source outcome in a tick summary; `error` is set only when it threw. */
export interface FeedRunSourceSummary extends FeederResult {
  source: ObservationSource;
  durationMs: number;
  error?: string;
}

export interface FeedRunSummary {
  startedAt: Date;
  durationMs: number;
  sources: FeedRunSourceSummary[];
  totalObservations: number;
  totalCreated: number;
  totalAttached: number;
  failedSources: ObservationSource[];
}

/**
 * SCOPE NARROWED TO OPENVAS-ONLY (SPEC.md Addendum 3, ordered directly by the
 * user, 2026-09-07): "Only OpenVAS should feed the asset system at all." The
 * agent/arp/nmap/nuclei feeders below are left fully intact on disk and are
 * NOT called from this tick — they are not deleted because the decision may
 * be revisited once OpenVAS-only coverage has been evaluated in production.
 *
 * To re-enable one: import its `run<X>Feeder` above and replace its entry in
 * `disabledFeeder(...)` below with the real call, e.g.
 * `agent: (db) => runAgentFeeder(db)`. The original run-order rationale
 * (agent -> arp -> nmap -> openvas -> nuclei, so high-confidence agent assets
 * exist before weak agentless observations try to attach) still applies if
 * any of the disabled sources come back.
 */
async function disabledFeeder(source: ObservationSource): Promise<FeederResult> {
  logger.debug(
    { source },
    'Asset identity feeder disabled — scope narrowed to OpenVAS-only per user decision (SPEC.md Addendum 3, 2026-09-07)',
  );
  return { rows: 0, observations: 0, created: 0, attached: 0, maxSourceId: null };
}

const FEEDERS: Record<ObservationSource, (db: DataSource, sinceId: string | null) => Promise<FeederResult>> = {
  agent: () => disabledFeeder('agent'),
  arp: () => disabledFeeder('arp'),
  nmap: () => disabledFeeder('nmap'),
  openvas: (db) => runOpenvasFeeder(db),
  nuclei: () => disabledFeeder('nuclei'),
};

/**
 * Owns the asset identity resolution cron tick.
 *
 * One task, one re-entrancy flag — the same shape as NodeAutoAssignService.
 * Deliberately NOT the DataRetentionService shape: that reads a per-row cron
 * expression out of the database and keeps a Map of tasks, which is machinery
 * this feature has no use for. There is exactly one schedule here and it is a
 * literal constant.
 *
 * A tick is cheap because the nmap and nuclei feeders are incremental: their
 * watermarks live in asset_feed_state.last_source_id, so a tick reads only the
 * scans a previous tick has not already ingested. The agent feeder is a
 * deliberate full re-read of all 57 `nodes` rows; that is how a new NIC or a
 * changed IP gets picked up, and the observation insert is a no-op on
 * ON CONFLICT (source, source_ref).
 */
export class AssetResolutionService {
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
    this.task = cron.schedule(ASSET_RESOLUTION_CRON_EXPRESSION, () => {
      // cron.schedule does not await the callback, so an unhandled rejection
      // here would be fatal on Node >= 15. runFeeds() already swallows and logs
      // every per-feeder failure, so anything reaching this catch is unforeseen.
      this.runFeeds().catch((err) => {
        logger.error({ err }, 'Scheduled asset identity resolution run failed');
      });
    });
    logger.info({ cronExpression: ASSET_RESOLUTION_CRON_EXPRESSION }, 'Asset identity resolution scheduler started');
  }

  public stop() {
    const wasRunning = !!this.task;
    this.task?.stop();
    this.task = null;
    if (wasRunning) {
      logger.info('Asset identity resolution scheduler stopped');
    }
  }

  /**
   * Run the feeders once, on demand. `sources` restricts the run to a subset
   * (still in OBSERVATION_SOURCES order); omitting it runs all of them.
   */
  public async runNow(sources?: ObservationSource[]): Promise<FeedRunSummary> {
    return this.runFeeds(sources);
  }

  private async runFeeds(sources?: ObservationSource[]): Promise<FeedRunSummary> {
    const startedAt = new Date();
    const startedMs = Date.now();
    const summary: FeedRunSummary = {
      startedAt,
      durationMs: 0,
      sources: [],
      totalObservations: 0,
      totalCreated: 0,
      totalAttached: 0,
      failedSources: [],
    };

    if (this.running) {
      logger.info('Asset identity resolution still in progress from a previous tick — skipping');
      summary.durationMs = Date.now() - startedMs;
      return summary;
    }
    this.running = true;

    try {
      // Filter OBSERVATION_SOURCES rather than iterating the caller's array:
      // the run order is a correctness property, not a caller preference.
      const requested = sources ? new Set<ObservationSource>(sources) : null;
      const toRun = OBSERVATION_SOURCES.filter((s) => requested === null || requested.has(s));

      for (const source of toRun) {
        const sourceStartedMs = Date.now();
        let state: { lastSourceId: string | null };
        try {
          state = await this.readFeedState(source);
        } catch (err) {
          // Reading the watermark failed, so the feeder cannot be run safely:
          // running it with a null cursor would re-ingest everything. Skip and
          // retry next tick.
          logger.error({ err, source }, 'Could not read asset feed watermark — skipping this feeder for this tick');
          summary.sources.push({
            source, rows: 0, observations: 0, created: 0, attached: 0, maxSourceId: null,
            durationMs: Date.now() - sourceStartedMs, error: errorMessage(err),
          });
          summary.failedSources.push(source);
          continue;
        }

        try {
          const result = await FEEDERS[source](this.fleetDb, state.lastSourceId);
          summary.sources.push({ source, ...result, durationMs: Date.now() - sourceStartedMs });
          summary.totalObservations += result.observations;
          summary.totalCreated += result.created;
          summary.totalAttached += result.attached;
          await this.writeFeedState(source, result.maxSourceId, null);
        } catch (err) {
          // One feeder's source table can be missing or malformed without
          // costing the others their tick — the whole point of running agent
          // first is lost if an nmap parse failure aborts the run before it.
          logger.error({ err, source }, 'Asset identity feeder failed');
          summary.sources.push({
            source, rows: 0, observations: 0, created: 0, attached: 0, maxSourceId: null,
            durationMs: Date.now() - sourceStartedMs, error: errorMessage(err),
          });
          summary.failedSources.push(source);
          // Persist the failure so a feeder that has been silently broken for
          // days is visible in asset_feed_state, not only in the log buffer.
          // The watermark itself is NOT advanced.
          await this.writeFeedState(source, null, errorMessage(err)).catch((stateErr) => {
            logger.warn({ err: stateErr, source }, 'Could not record asset feed failure in asset_feed_state');
          });
        }
      }

      summary.durationMs = Date.now() - startedMs;
      logger.info(
        {
          durationMs: summary.durationMs,
          totalObservations: summary.totalObservations,
          totalCreated: summary.totalCreated,
          totalAttached: summary.totalAttached,
          failedSources: summary.failedSources,
        },
        'Asset identity resolution run finished',
      );
    } finally {
      this.running = false;
    }

    return summary;
  }

  /**
   * The watermark for one feeder. Absent row = never run = null cursor = full
   * ingest, which is exactly what a fresh install wants.
   *
   * last_source_id is read as `string | null`: node-postgres hands back bigint
   * as a string, and it is passed straight back into the feeder's `$1::bigint`
   * without ever becoming a JS number, so a value past Number.MAX_SAFE_INTEGER
   * cannot be silently rounded.
   */
  private async readFeedState(source: ObservationSource): Promise<{ lastSourceId: string | null }> {
    const rows: { last_source_id: string | null }[] = await this.fleetDb.query(
      'SELECT last_source_id FROM asset_feed_state WHERE source = $1',
      [source],
    );
    const raw = rows && rows.length > 0 ? rows[0].last_source_id : null;
    return { lastSourceId: raw === null || raw === undefined ? null : String(raw) };
  }

  /**
   * `GREATEST` on the stored value, so a feeder that reports a lower id than
   * the one already recorded (a manual replay, a rolled-back source row) cannot
   * drag the cursor backwards and re-ingest a backlog on every tick from then
   * on. A null maxSourceId leaves the existing cursor untouched.
   */
  private async writeFeedState(
    source: ObservationSource,
    maxSourceId: string | null,
    lastError: string | null,
  ): Promise<void> {
    await this.fleetDb.query(
      `
        INSERT INTO asset_feed_state (source, last_source_id, last_run_at, last_error)
        VALUES ($1, $2::bigint, NOW(), $3)
        ON CONFLICT (source) DO UPDATE SET
          last_source_id = GREATEST(
            asset_feed_state.last_source_id,
            COALESCE(EXCLUDED.last_source_id, asset_feed_state.last_source_id)
          ),
          last_run_at = EXCLUDED.last_run_at,
          last_error = EXCLUDED.last_error
      `,
      [source, maxSourceId, lastError],
    );
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

let instance: AssetResolutionService | null = null;

export function setAssetResolutionServiceInstance(service: AssetResolutionService) {
  instance = service;
}

export function getAssetResolutionServiceInstance(): AssetResolutionService | null {
  return instance;
}
