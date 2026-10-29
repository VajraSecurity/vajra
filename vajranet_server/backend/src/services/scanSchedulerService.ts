import { DataSource } from 'typeorm';
import * as cron from 'node-cron';
import { ScanSchedule } from '../orm/entities/fleet/ScanSchedule';
import {
  launchNmapScan,
  awaitScanCompletion,
  getUnmanagedIps,
} from '../controllers/network/nmapController';
import { getLogger } from '../utils/logger';
import { CRON_DAILY_AT_MIDNIGHT } from '../orm/entities/fleet/DataRetentionPolicy';

const logger = getLogger('services.scanScheduler');

// How many not-yet-alerted unmanaged IPs one tick will advanced-scan. The
// remainder is picked up next tick — still "not yet alerted", so nothing is
// lost; this only bounds work per run.
const MAX_ADVANCED_SCANS_PER_RUN = 25;
const ADVANCED_SCAN_CONCURRENCY = 3;

// Every flagged host from a single scheduler tick is rolled into one alert of
// this type (rather than one alert per IP), so a busy subnet's first run
// doesn't flood the Alerts page with hundreds of near-identical rows.
const CONSOLIDATED_ALERT_TYPE = 'Unmanaged Hosts Detected';

interface RunCandidate {
  ip: string;
  kind: 'new' | 'reuse';
}

interface RunHost extends RunCandidate {
  advancedScanId: number;
  openPorts: string[];
  osGuess: string | null;
  // Only populated for kind === 'reuse': the device this IP used to belong
  // to, per the nodes/interface_addresses row that made it match staleManagedIps.
  registeredHostIdentifier: string | null;
  registeredHostname: string | null;
  registeredLastSeen: number | null;
}

const FREQUENCY_CRON_MAP: Record<string, string> = {
  '5min': '*/5 * * * *',
  '1h': '0 * * * *',
  '1d': CRON_DAILY_AT_MIDNIGHT,
};

export function resolveCronExpression(frequencyPreset: string, customCronExpression?: string | null): string {
  if (frequencyPreset === 'custom') {
    if (!customCronExpression || !cron.validate(customCronExpression)) {
      throw new Error('A valid custom cron expression is required when frequency is "custom".');
    }
    return customCronExpression;
  }
  const resolved = FREQUENCY_CRON_MAP[frequencyPreset];
  if (!resolved) {
    throw new Error(`Unknown frequency preset: ${frequencyPreset}`);
  }
  return resolved;
}

function extractOpenPorts(output: string): string[] {
  const ports: string[] = [];
  for (const line of output.split('\n')) {
    const match = line.match(/^(\d+\/tcp)\s+open\s+(\S+)/);
    if (match) ports.push(`${match[1]} ${match[2]}`);
  }
  return ports;
}

function extractOsGuess(output: string): string | null {
  for (const line of output.split('\n')) {
    const runningMatch = line.match(/^Running:\s*(.+)$/);
    if (runningMatch) return runningMatch[1].trim();
    const osDetailsMatch = line.match(/^OS details:\s*(.+)$/);
    if (osDetailsMatch) return osDetailsMatch[1].trim();
  }
  return null;
}

async function chunkedConcurrent<T>(items: T[], concurrency: number, worker: (item: T) => Promise<void>): Promise<void> {
  let cursor = 0;
  const runWorker = async () => {
    while (cursor < items.length) {
      const item = items[cursor++];
      await worker(item);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, runWorker));
}

export class ScanSchedulerService {
  private fleetDb: DataSource;
  private activeJobs: Map<number, cron.ScheduledTask> = new Map();
  private runningFlags: Map<number, boolean> = new Map();
  // Schedules deleted while a run is in flight — runSchedule checks this at
  // each step boundary so a deleted schedule doesn't keep launching new child
  // scans/alerts after it's gone (the one nmap process already spawned at the
  // moment of deletion still runs to completion; only further work stops).
  private deletedScheduleIds: Set<number> = new Set();

  constructor(fleetDb: DataSource) {
    this.fleetDb = fleetDb;
  }

  public async initializeJobs(): Promise<void> {
    const repo = this.fleetDb.getRepository(ScanSchedule);

    let schedules: ScanSchedule[];
    try {
      // At startup a "running" schedule can only be a leftover from a process
      // that no longer exists. Reconcile before scheduling new ticks, or a crash
      // mid-run leaves it stuck showing "Running" forever.
      const reconciled = await repo.update({ lastRunStatus: 'running' }, { lastRunStatus: 'failed' });
      if (reconciled.affected) {
        logger.warn({ count: reconciled.affected }, 'Reconciled scan schedules stuck in "running" status after restart; marked as failed');
      }

      schedules = await repo.find({ where: { enabled: true } });
    } catch (err) {
      // Without this a DB hiccup at startup surfaces only in index.ts's generic
      // top-level catch, with no indication that scan-schedule initialization is
      // what failed.
      logger.error({ err }, 'Failed to initialize scan schedules: could not load schedules from the database');
      throw err;
    }

    let scheduled = 0;
    for (const schedule of schedules) {
      try {
        this.scheduleJob(schedule);
        scheduled++;
      } catch (err) {
        logger.error({ err, scheduleId: schedule.id, scheduleName: schedule.name }, 'Failed to schedule scan — skipping, other schedules unaffected');
      }
    }
    logger.info({ scheduled, total: schedules.length }, 'Initialized scan schedules');
  }

  public scheduleJob(schedule: ScanSchedule): void {
    this.cancelJob(schedule.id);

    if (!schedule.enabled) {
      logger.info({ scheduleId: schedule.id, scheduleName: schedule.name }, 'Scan schedule is disabled; not scheduling');
      return;
    }

    const scheduleId = schedule.id;
    const task = cron.schedule(schedule.cronExpression, () => {
      this.runSchedule(scheduleId).catch((err) => logger.error({ err, scheduleId }, 'Scan schedule run failed'));
    });
    this.activeJobs.set(schedule.id, task);
    // Debug, not info: scheduleJob() is called once per schedule from
    // initializeJobs()'s startup loop (already summarized by the 'Initialized
    // scan schedules' log) as well as from the create/update API paths, and the
    // two cannot be told apart cheaply here.
    logger.debug(
      { scheduleId: schedule.id, scheduleName: schedule.name, cronExpression: schedule.cronExpression, target: schedule.target },
      'Scheduled scan',
    );
  }

  public cancelJob(scheduleId: number): void {
    const existing = this.activeJobs.get(scheduleId);
    if (existing) {
      existing.stop();
      this.activeJobs.delete(scheduleId);
      // A schedule disabled via the update endpoint reaches cancelJob() directly
      // rather than scheduleJob()'s own "not scheduling" log, so this is the only
      // record that the cron job stopped.
      logger.info({ scheduleId }, 'Cancelled scan schedule cron job');
    }
  }

  /** Called when a schedule is deleted — stops future ticks and signals any in-flight run to stop doing further work. */
  public markDeleted(scheduleId: number): void {
    this.cancelJob(scheduleId);
    this.deletedScheduleIds.add(scheduleId);
    logger.info({ scheduleId }, 'Scan schedule marked deleted; future ticks cancelled and in-flight run will stop at next step boundary');
  }

  public async runNow(scheduleId: number): Promise<void> {
    await this.runSchedule(scheduleId);
  }

  public async runSchedule(scheduleId: number): Promise<void> {
    if (this.runningFlags.get(scheduleId)) {
      logger.info({ scheduleId }, 'Scan schedule still running from a previous tick — skipping');
      return;
    }
    this.runningFlags.set(scheduleId, true);

    const repo = this.fleetDb.getRepository(ScanSchedule);

    // Tracks which step of the run was in flight when the catch below fires;
    // otherwise a DB error loading the schedule, an nmap launch failure, a
    // stalled discovery scan and a failed alert insert are indistinguishable.
    let step = 'load_schedule';

    try {
      const schedule = await repo.findOne({ where: { id: scheduleId } });
      if (!schedule) {
        logger.warn({ scheduleId }, 'Scan schedule run requested for unknown schedule id — skipping');
        return;
      }
      if (!schedule.enabled) {
        logger.info({ scheduleId, scheduleName: schedule.name }, 'Scan schedule run skipped: schedule is disabled');
        return;
      }
      if (this.deletedScheduleIds.has(scheduleId)) {
        // Consumed here: this id's only purpose was to reach this check, and the
        // other removal point below fires only when a scan was in flight, so
        // leaving it in the Set would leak an entry per such deletion.
        this.deletedScheduleIds.delete(scheduleId);
        logger.info({ scheduleId, scheduleName: schedule.name }, 'Scan schedule run skipped: schedule was deleted');
        return;
      }

      step = 'mark_running';
      await repo.update(scheduleId, { lastRunStatus: 'running' });

      step = 'launch_discovery_scan';
      const { historyId } = await launchNmapScan({
        target: schedule.target,
        scanType: 'discovery',
        reason: schedule.reason || `Scheduled scan (${schedule.name})`,
        scheduleId: schedule.id,
        // Attribute the scan to the schedule's owner. A NULL created_by_user_id
        // is visible through grafana_scan_visible only to a Super Administrator,
        // which would hide scheduled scans from group-scoped "unknown devices"
        // panels even though they are the main way unmanaged hosts get found.
        createdByUserId: schedule.createdByUserId,
        createdByName: schedule.createdByName,
      });

      step = 'await_discovery_completion';
      const discoveryScan = await awaitScanCompletion(historyId);

      if (this.deletedScheduleIds.has(scheduleId)) {
        logger.info({ scheduleId, historyId }, 'Scan schedule run abandoned after discovery scan: schedule was deleted mid-run');
        this.deletedScheduleIds.delete(scheduleId);
        return;
      }

      if (discoveryScan.status !== 'COMPLETED') {
        logger.warn({ scheduleId, historyId, discoveryScanStatus: discoveryScan.status }, 'Scan schedule run failed: discovery scan did not complete');
        await repo.update(scheduleId, {
          lastRunAt: new Date(),
          lastRunStatus: 'failed',
          lastRunHistoryId: historyId,
        });
        return;
      }

      step = 'analyze_unmanaged_hosts';
      const { unknownIps, staleManagedIps } = await getUnmanagedIps(discoveryScan.output, this.fleetDb);
      const knownIpsSet = new Set<string>(schedule.knownIps || []);

      // Unnest each prior consolidated alert's `hosts` array so an IP already
      // surfaced (in any past run, new or reuse) isn't alerted on again.
      step = 'query_already_notified_ips';
      const alreadyNotified = await this.fleetDb.query(
        `SELECT DISTINCT h->>'ip' AS ip
         FROM alerts, jsonb_array_elements(metadata::jsonb->'hosts') AS h
         WHERE alert_type = $1 AND metadata::jsonb->>'schedule_id' = $2`,
        [CONSOLIDATED_ALERT_TYPE, String(scheduleId)],
      );
      const notifiedSet = new Set<string>(alreadyNotified.map((r: any) => r.ip));

      const eligible: RunCandidate[] = [
        ...unknownIps.map((ip): RunCandidate => ({ ip, kind: 'new' })),
        ...staleManagedIps.map((ip): RunCandidate => ({ ip, kind: 'reuse' })),
      ].filter((c) => !notifiedSet.has(c.ip) && !knownIpsSet.has(c.ip));

      const candidates = eligible.slice(0, MAX_ADVANCED_SCANS_PER_RUN);
      // Eligible IPs deferred past the per-tick cap, surfaced rather than
      // silently dropped; they are picked up next tick.
      const pendingCount = Math.max(eligible.length - candidates.length, 0);

      step = 'run_advanced_scans';
      const hosts = await this.runAdvancedScans({
        candidates,
        schedule,
        discoveryScanId: historyId,
        scheduleId,
      });

      if (this.deletedScheduleIds.has(scheduleId)) {
        // candidates/completed distinguish abandoning before any advanced scan
        // finished from abandoning after most of the batch completed.
        logger.info({ scheduleId, historyId, candidates: candidates.length, completed: hosts.length }, 'Scan schedule run abandoned after advanced scans: schedule was deleted mid-run');
        this.deletedScheduleIds.delete(scheduleId);
        return;
      }

      if (hosts.length > 0) {
        step = 'create_run_alert';
        await this.createRunAlert({ schedule, discoveryScanId: historyId, hosts });
      }

      const newCount = hosts.filter((h) => h.kind === 'new').length;
      const reuseCount = hosts.filter((h) => h.kind === 'reuse').length;

      step = 'record_run_success';
      await repo.update(scheduleId, {
        lastRunAt: new Date(),
        lastRunStatus: 'success',
        lastRunHistoryId: historyId,
        lastNewIpCount: newCount,
        lastPendingIpCount: pendingCount,
        lastReusedIpCount: reuseCount,
      });

      logger.info(
        { scheduleId, alerted: hosts.length, candidates: candidates.length, failedAdvancedScans: candidates.length - hosts.length, newCount, reuseCount, pendingCount },
        'Scan schedule run completed',
      );
    } catch (err) {
      if (!(err && typeof err === 'object' && (err as any).__loggedByCreateRunAlert)) {
        logger.error({ err, scheduleId, step }, 'Scan schedule run threw');
      }
      await repo.update(scheduleId, {
        lastRunAt: new Date(),
        lastRunStatus: 'failed',
      }).catch((updateErr) => logger.error({ err: updateErr, scheduleId }, 'Failed to record scan schedule failure'));
    } finally {
      this.runningFlags.set(scheduleId, false);
    }
  }

  /**
   * Runs an advanced nmap scan against each candidate IP and collects the
   * result (open ports, OS guess, and — for 'reuse' candidates — the
   * previously-registered device's identity) without alerting yet. All
   * results from one run are rolled into a single alert by createRunAlert.
   */
  private async runAdvancedScans(opts: {
    candidates: RunCandidate[];
    schedule: ScanSchedule;
    discoveryScanId: number;
    scheduleId: number;
  }): Promise<RunHost[]> {
    const { candidates, schedule, discoveryScanId, scheduleId } = opts;
    const hosts: RunHost[] = [];
    await chunkedConcurrent(candidates, ADVANCED_SCAN_CONCURRENCY, async ({ ip, kind }) => {
      if (this.deletedScheduleIds.has(scheduleId)) return;
      // Tracks which of launch, await or owner-lookup was in flight when the
      // catch below fires; all three would otherwise collapse into the same
      // "Advanced scan failed" line.
      let step = 'launch_advanced_scan';
      try {
        const { historyId: advHistoryId } = await launchNmapScan({
          target: ip,
          scanType: 'advanced',
          reason: kind === 'new'
            ? `Auto-triggered: new unmanaged host detected by schedule "${schedule.name}"`
            : `Auto-triggered: possible IP reuse (registered device currently offline) detected by schedule "${schedule.name}"`,
          parentId: discoveryScanId,
          scheduleId: schedule.id,
          // Same attribution as the parent discovery scan; see the comment there.
          createdByUserId: schedule.createdByUserId,
          createdByName: schedule.createdByName,
        });
        step = 'await_advanced_scan_completion';
        const advScan = await awaitScanCompletion(advHistoryId);

        const openPorts = advScan.status === 'COMPLETED' ? extractOpenPorts(advScan.output) : [];
        const osGuess = advScan.status === 'COMPLETED' ? extractOsGuess(advScan.output) : null;

        let owner: { host_identifier: string; hostname: string; last_seen: number | null } | null = null;
        if (kind === 'reuse') {
          step = 'query_registered_owner';
          // The ORDER BY is load-bearing, not cosmetic. This picks one owner for
          // a scanned IP, but an address is not unique — loopback and common
          // gateway addresses are each held by many hosts. Without an explicit
          // order a UNION ALL + LIMIT 1 returns whichever branch the planner
          // happens to lead with, and a Parallel Append reorders subplans, so the
          // reported owner can change under a plan flip.
          //
          //   pref       - a host whose own nodes.address matches beats one that
          //                merely carries the address on some interface.
          //   last_seen  - for a shared address the live host is the useful owner,
          //                not an arbitrary stale one.
          //   host_id    - total tie-break, so the answer is fully deterministic.
          const ownerRows = await this.fleetDb.query(
            `SELECT host_identifier, hostname, last_seen FROM (
               SELECT host_identifier, hostname, last_seen, 0 AS pref
               FROM nodes WHERE address = $1
               UNION ALL
               SELECT n.host_identifier, n.hostname, n.last_seen, 1 AS pref
               FROM interface_addresses ia JOIN nodes n ON n.host_identifier = ia.host_identifier
               WHERE ia.address = $1
             ) owners
             ORDER BY pref, last_seen DESC NULLS LAST, host_identifier
             LIMIT 1`,
            [ip],
          );
          owner = ownerRows[0] || null;
        }

        hosts.push({
          ip,
          kind,
          advancedScanId: advHistoryId,
          openPorts,
          osGuess,
          registeredHostIdentifier: owner?.host_identifier ?? null,
          registeredHostname: owner?.hostname ?? null,
          registeredLastSeen: owner?.last_seen ?? null,
        });
      } catch (err) {
        logger.error({ err, ip, scheduleId, step }, 'Advanced scan failed');
      }
    });
    return hosts;
  }

  /** One alert per scheduler run, covering every flagged host from that run. */
  private async createRunAlert(opts: {
    schedule: ScanSchedule;
    discoveryScanId: number;
    hosts: RunHost[];
  }): Promise<void> {
    const { schedule, discoveryScanId, hosts } = opts;
    const unixTime = Math.floor(Date.now() / 1000);
    const newCount = hosts.filter((h) => h.kind === 'new').length;
    const reuseCount = hosts.filter((h) => h.kind === 'reuse').length;

    const metadata = JSON.stringify({
      schedule_id: schedule.id,
      schedule_name: schedule.name,
      subnet: schedule.target,
      discovery_scan_id: discoveryScanId,
      reason: schedule.reason,
      new_host_count: newCount,
      possible_reuse_count: reuseCount,
      hosts: hosts.map((h) => ({
        ip: h.ip,
        kind: h.kind,
        advanced_scan_id: h.advancedScanId,
        open_ports: h.openPorts,
        os_guess: h.osGuess,
        registered_host_identifier: h.registeredHostIdentifier,
        registered_hostname: h.registeredHostname,
        registered_last_seen: h.registeredLastSeen,
      })),
    });

    // Not a real IP or hostname: this alert spans many hosts, so it is keyed by
    // the run. event_code is left null so the Alerts list falls back to
    // displaying alert_type as the title rather than a meaningless id.
    const runIdentifier = `schedule-${schedule.id}-run-${discoveryScanId}`;

    try {
      await this.fleetDb.query(
        `INSERT INTO alerts
           (host_identifier, unixTime, event_code, metadata, is_alert, is_open, severity, alert_type, hostname, group_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [runIdentifier, unixTime, null, metadata, true, true, 'medium', CONSOLIDATED_ALERT_TYPE, schedule.name, schedule.groupId],
      );
    } catch (err) {
      logger.error({ err, scheduleId: schedule.id, discoveryScanId, hostCount: hosts.length }, 'Failed to create consolidated alert for scan schedule run');
      // Tagged so runSchedule's outer catch does not log this DB error a second
      // time under the generic "Scan schedule run threw" line; this line already
      // carries the fuller context.
      if (err && typeof err === 'object') (err as any).__loggedByCreateRunAlert = true;
      throw err;
    }
  }
}

let instance: ScanSchedulerService | null = null;

export function setScanSchedulerServiceInstance(service: ScanSchedulerService) {
  instance = service;
}

export function getScanSchedulerServiceInstance(): ScanSchedulerService | null {
  return instance;
}
