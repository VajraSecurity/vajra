/**
 * Patch Management — Linux OS-package patching across the fleet.
 *
 * Wraps the agent's `osupdate` engine (check / upgrade) in a job-tracking
 * layer: every check/apply creates a `patch_jobs` row plus one
 * `patch_job_nodes` row per targeted host, dispatches (or queues, for offline
 * hosts) the underlying WS command via the existing `dispatchToAgent`, and
 * later correlates the agent's async `osupdate_result` push back onto the
 * right row — primarily by `task_id` (recorded from the agent's immediate
 * ack), falling back to a host_identifier heuristic only when task_id is
 * absent (see websocket/node.ts's "osupdate_ack:" and `osupdate_result`
 * handling).
 *
 * A "native" job (source='native', the default) targets the host's own
 * package manager directly. A "bundle" job (source='bundle') is created by
 * `POST /api/patch/apply/fallback` (auto-selects a bundle for the host) or
 * `POST /api/patch/bundles/:id/apply` (pins an exact bundle row) and
 * dispatches the agent's `apply_bundle` action with the bundle's original
 * signed-manifest wire bytes as arg1 — see createPatchJob's header comment.
 *
 * host_identifier comparisons throughout this file are wrapped in LOWER() at
 * query time (matching the convention in
 * src/migrations/create_grafana_views.sql) — stored casing is never rewritten.
 *
 * Every route is Super-Admin-only (see routes/api/patch.ts). Applying an
 * upgrade, and the bundle fallback, additionally require MFA (see requireMfa below) — check/list are read-mostly and don't
 * carry that extra gate.
 */

import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { JwtPayload } from '../../types/JwtPayload';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { verifyTotpCode } from '../../utils/totp';
import { dispatchToAgent } from '../../websocket/node';
import { dispatchNextPendingPatchCommand } from '../../websocket/patchDispatch';
import { MAX_PACKAGES_PER_HOST, PACKAGE_CAPABLE_MANAGERS, validatePackagesByHost } from '../../utils/patchPackageValidation';
import { createPatchJob, dispatchOrQueuePatchJobNode, PerHostResult, PatchJobSource, PatchJobOperation } from './patchJobCore';
import { getLogger } from '../../utils/logger';
import { claimTotpCodeOnce } from '../../utils/redisClient';
import { PATCH_LIST_DEFAULT_ROWS, PATCH_REASON_MAX_LENGTH, PATCH_FLEETWIDE_ROW_LIMIT } from '../../consts/pagination';
import { returningRows } from '../../utils/returningRows';

const logger = getLogger('nodes.patchManagement');

export const MAX_HOSTS = 2500; // matches the frontend's MAX_BULK_OPERATIONS
export { MAX_PACKAGES_PER_HOST, PACKAGE_CAPABLE_MANAGERS, validatePackagesByHost };
export type { PerHostResult, PatchJobSource, PatchJobOperation };

function getFleetDb() {
  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length < 2) return null;
  return dbSources[1];
}

/**
 * Verifies the caller's MFA TOTP for a high-privilege patch-apply operation.
 * Same shape and library as other MFA-gated controllers,
 * deliberately not shared (matches this codebase's existing convention of
 * per-controller duplication over a shared auth-helper module).
 */
export async function requireMfa(req: Request, res: Response, usersDb: any): Promise<VajraUser | null> {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  if (!jwtPayload?.id) {
    res.status(401).json({ status: 'Fail', message: 'Unauthorized' });
    return null;
  }
  const { totp_code } = req.body ?? {};
  if (!totp_code) {
    res.status(400).json({ status: 'Fail', message: 'Missing totp_code' });
    return null;
  }
  const user = await usersDb.getRepository(VajraUser).findOne({ where: { id: jwtPayload.id } });
  if (!user || !user.mfa_enabled || !user.mfa_secret) {
    logger.warn({ user_id: jwtPayload.id }, 'Patch-apply operation denied: MFA not enabled for user');
    res.status(403).json({ status: 'Fail', message: 'MFA must be enabled for patch-apply operations' });
    return null;
  }
  const verified = verifyTotpCode(user.mfa_secret, totp_code);
  if (!verified) {
    logger.warn({ user_id: jwtPayload.id }, 'Patch-apply operation denied: invalid TOTP code');
    res.status(401).json({ status: 'Fail', message: 'Invalid TOTP code' });
    return null;
  }
  if (!(await claimTotpCodeOnce(jwtPayload.id, totp_code))) {
    logger.warn({ user_id: jwtPayload.id }, 'Patch-apply operation denied: TOTP code already used');
    res.status(401).json({ status: 'Fail', message: 'Invalid TOTP code' });
    return null;
  }
  return user;
}

export function validateHostIdentifiers(input: unknown): string[] | null {
  if (!Array.isArray(input) || input.length === 0 || input.length > MAX_HOSTS) return null;
  const hosts = input.map((h) => (typeof h === 'string' ? h.trim() : ''));
  if (hosts.some((h) => !h)) return null;
  return [...new Set(hosts)];
}

/**
 * Hosts that already have a patch_job_nodes row in an in-flight state.
 *
 * 'queued' counts as in-flight: a job merely queued for an offline host has not been
 * dispatched yet, and stacking a second job on top of it must not be allowed. So does
 * 'acked', the ack-confirmed state between 'dispatched' and 'running'.
 *
 * host_identifier comparisons are case-insensitive throughout this file (matching the
 * LOWER() convention in src/migrations/create_grafana_views.sql): both the query's
 * column and the caller's `hosts` array are lowered, and the returned Set's keys are
 * lowercased — callers must `.toLowerCase()` before calling `.has()`.
 */
export async function findHostsInFlight(fleetDb: any, hosts: string[]): Promise<Set<string>> {
  if (hosts.length === 0) return new Set();
  const lowerHosts = hosts.map((h) => h.toLowerCase());
  const rows = await fleetDb.query(
    `SELECT DISTINCT LOWER(host_identifier) AS host_identifier FROM patch_job_nodes
      WHERE LOWER(host_identifier) = ANY($1) AND status IN ('queued','dispatched','acked','running')`,
    [lowerHosts],
  );
  return new Set(rows.map((r: any) => r.host_identifier as string));
}

/**
 * Most recently *successful* check's reported manager, per host. Returned map
 * is keyed by lowercased host_identifier — callers must `.toLowerCase()`
 * before calling `.get()`.
 */
async function getLastCheckedManagers(fleetDb: any, hosts: string[]): Promise<Map<string, string>> {
  if (hosts.length === 0) return new Map();
  const lowerHosts = hosts.map((h) => h.toLowerCase());
  const rows = await fleetDb.query(
    `SELECT DISTINCT ON (LOWER(pjn.host_identifier)) LOWER(pjn.host_identifier) AS host_identifier, pjn.manager
       FROM patch_job_nodes pjn
       JOIN patch_jobs pj ON pj.id = pjn.patch_job_id
      WHERE LOWER(pjn.host_identifier) = ANY($1) AND pj.operation = 'check' AND pjn.status = 'success'
      ORDER BY LOWER(pjn.host_identifier), pjn.completed_at DESC`,
    [lowerHosts],
  );
  const map = new Map<string, string>();
  for (const r of rows) map.set(r.host_identifier, r.manager);
  return map;
}

// createPatchJob/dispatchOrQueuePatchJobNode and the PatchJobSource/PatchJobOperation
// types live in patchJobCore.ts and are re-exported here so existing
// `from './patch_management'` imports keep working. They are defined there so
// websocket/node.ts can call createPatchJob without importing this file, which already
// imports dispatchToAgent from node.ts — see patchJobCore.ts's header comment.
export { createPatchJob, dispatchOrQueuePatchJobNode };

/**
 * POST /api/patch/check
 * Body: { host_identifiers: string[], reason?: string }
 * Admin-gated only (no MFA) — this refreshes metadata and lists available
 * updates, it never installs anything.
 */
export const triggerPatchCheck = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const hosts = validateHostIdentifiers(req.body?.host_identifiers);
    if (!hosts) {
      return res.status(400).json({ status: 'Fail', message: `host_identifiers must be a non-empty array (max ${MAX_HOSTS})` });
    }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.slice(0, PATCH_REASON_MAX_LENGTH) : null;
    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;

    const inFlight = await findHostsInFlight(fleetDb, hosts);
    const eligible = hosts.filter((h) => !inFlight.has(h.toLowerCase()));
    const rejected: PerHostResult[] = hosts
      .filter((h) => inFlight.has(h.toLowerCase()))
      .map((h) => ({ host_identifier: h, status: 'rejected_in_progress', message: 'a patch job is already in progress for this host' }));

    if (eligible.length === 0) {
      logger.info({ host_count: hosts.length, rejected_count: rejected.length }, 'Patch check rejected: all targeted hosts already have a job in progress');
      return res.status(409).json({ status: 'Fail', message: 'All targeted hosts already have a patch job in progress', per_host: rejected });
    }

    const { patch_job_id, per_host } = await createPatchJob(
      fleetDb, 'check', eligible, null, reason, jwtPayload?.id ?? null, jwtPayload?.email ?? null, dispatchToAgent,
    );

    logAuditTrail({
      action: 'PATCH_CHECK',
      status: 'success',
      userId: jwtPayload?.id ?? null,
      email: jwtPayload?.email ?? null,
      details: { patch_job_id, host_count: eligible.length, reason },
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
    }).catch((auditErr) => {
      logger.warn({ err: auditErr, patch_job_id }, 'Failed to write audit trail for patch check');
    });

    logger.debug({ patch_job_id, host_count: eligible.length, rejected_count: rejected.length }, 'Patch check triggered');

    return res.status(201).json({ status: 'Success', patch_job_id, per_host: [...per_host, ...rejected] });
  } catch (error) {
    logger.error({ err: error, host_identifiers: req.body?.host_identifiers }, 'Failed to trigger patch check');
    return next(new CustomError(500, 'Raw', 'Failed to trigger patch check', null, error));
  }
};

/**
 * POST /api/patch/apply
 * Body: { host_identifiers, mode: 'full'|'packages', packages?: Record<host,string[]>, totp_code, reason? }
 * Requires MFA. Enforces server-side that every targeted host has a completed
 * successful "check" on record — the check-first wizard order is a real
 * security gate here, not just UI sequencing, since it's the only place the
 * backend learns which manager a host actually has.
 *
 * mode:'packages' dispatches operation='upgrade_packages' (agent action
 * "upgrade_packages", see the Linux agent's osupdate/upgrade_packages.go)
 * instead of a full upgrade. Every requested package name is checked twice:
 * validatePackagesByHost's shape/charset check here, THEN a subset check
 * against that host's own patch_available_updates rows (populated from its
 * last successful "check") immediately below — a host being targeted doesn't
 * prove the agent ever actually offered the requested packages, so this is
 * real defense-in-depth, not just UI-trust. Only apt/dnf/yum
 * (PACKAGE_CAPABLE_MANAGERS) support this — every other manager's native op
 * is whole-system only, so packages mode rejects those hosts individually
 * rather than failing the whole request.
 *
 * `scheduled_at` (optional, RFC3339): when it parses to a future moment the job/node
 * rows are created exactly as normal — including the check-first eligibility gate,
 * evaluated now, since a scheduled job still needs a known manager to build its dispatch
 * payload later — but dispatch is deferred to sweepScheduledPatchJobs. A value that is
 * missing, unparseable, or not in the future means "apply immediately", matching the
 * wizard's "leave blank to apply now" copy. This is a single-shot scheduler, not a
 * recurring maintenance-window policy.
 */
export const applyPatchUpgrade = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length < 2) return next(new CustomError(500, 'Database', 'DB connection missing', []));
    const fleetDb = dbSources[1];

    const user = await requireMfa(req, res, dbSources[0]);
    if (!user) return;

    const hosts = validateHostIdentifiers(req.body?.host_identifiers);
    if (!hosts) {
      return res.status(400).json({ status: 'Fail', message: `host_identifiers must be a non-empty array (max ${MAX_HOSTS})` });
    }
    const mode = req.body?.mode;
    if (mode !== 'full' && mode !== 'packages') {
      return res.status(400).json({ status: 'Fail', message: `mode must be "full" or "packages"` });
    }
    let requestedPackagesByHost: Record<string, string[]> | null = null;
    if (mode === 'packages') {
      requestedPackagesByHost = validatePackagesByHost(hosts, req.body?.packages);
      if (!requestedPackagesByHost) {
        return res.status(400).json({
          status: 'Fail',
          message: `packages must supply a non-empty package list (max ${MAX_PACKAGES_PER_HOST}) for every host in host_identifiers`,
        });
      }
    }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.slice(0, PATCH_REASON_MAX_LENGTH) : null;

    let scheduledAt: Date | null = null;
    const scheduledAtRaw = req.body?.scheduled_at;
    if (typeof scheduledAtRaw === 'string' && scheduledAtRaw.trim()) {
      const parsed = new Date(scheduledAtRaw);
      if (Number.isNaN(parsed.getTime())) {
        return res.status(400).json({ status: 'Fail', message: 'scheduled_at must be a valid RFC3339 timestamp' });
      }
      if (parsed.getTime() > Date.now()) scheduledAt = parsed;
    }

    const inFlight = await findHostsInFlight(fleetDb, hosts);
    const rejected: PerHostResult[] = hosts
      .filter((h) => inFlight.has(h.toLowerCase()))
      .map((h) => ({ host_identifier: h, status: 'rejected_in_progress', message: 'a patch job is already in progress for this host' }));
    const notInFlight = hosts.filter((h) => !inFlight.has(h.toLowerCase()));

    const managers = await getLastCheckedManagers(fleetDb, notInFlight);
    const eligible: string[] = [];
    for (const host of notInFlight) {
      const manager = managers.get(host.toLowerCase());
      if (!manager) {
        rejected.push({ host_identifier: host, status: 'rejected_no_check', message: 'run a check for this host before applying an upgrade' });
        continue;
      }
      eligible.push(host);
    }

    // Packages mode: narrow `eligible` further — capable manager, then every
    // requested name actually present in that host's last-reported available
    // updates. Two separate rejection reasons so the UI can distinguish
    // "wrong package manager" from "stale/tampered package list" instead of
    // one generic failure.
    let finalEligible = eligible;
    let finalPackagesByHost: Record<string, string[]> | null = null;
    if (mode === 'packages' && requestedPackagesByHost) {
      const capable = eligible.filter((host) => {
        const manager = managers.get(host.toLowerCase());
        if (manager && PACKAGE_CAPABLE_MANAGERS.has(manager)) return true;
        rejected.push({
          host_identifier: host,
          status: 'rejected_manager_not_capable',
          message: `manager "${manager ?? 'unknown'}" does not support per-package upgrade`,
        });
        return false;
      });

      const availableRows = capable.length
        ? await fleetDb.query(
            `SELECT LOWER(host_identifier) AS host_identifier, name FROM patch_available_updates WHERE LOWER(host_identifier) = ANY($1)`,
            [capable.map((h) => h.toLowerCase())],
          )
        : [];
      const availableByHost = new Map<string, Set<string>>();
      for (const row of availableRows) {
        const set = availableByHost.get(row.host_identifier) ?? new Set<string>();
        set.add(row.name);
        availableByHost.set(row.host_identifier, set);
      }

      const packagesEligible: string[] = [];
      const packagesFinal: Record<string, string[]> = {};
      for (const host of capable) {
        const requested = requestedPackagesByHost[host] ?? [];
        const available = availableByHost.get(host.toLowerCase()) ?? new Set<string>();
        const notAvailable = requested.filter((p) => !available.has(p));
        if (notAvailable.length > 0) {
          rejected.push({
            host_identifier: host,
            status: 'rejected_package_not_available',
            message: `not currently reported as available on this host: ${notAvailable.slice(0, 5).join(', ')}${notAvailable.length > 5 ? ', …' : ''}`,
          });
          continue;
        }
        packagesEligible.push(host);
        packagesFinal[host] = requested;
      }
      finalEligible = packagesEligible;
      finalPackagesByHost = packagesFinal;
    }

    // Broken out by `status` (rejected_in_progress / rejected_no_check /
    // rejected_manager_not_capable / rejected_package_not_available) — a bare
    // rejected_count here would make "most hosts never had a check run" and
    // "most hosts don't support per-package upgrade" indistinguishable from
    // logs alone, unlike createPatchJob's failureReasonCounts breakdown for
    // the analogous per-host-failure summary.
    const rejectedReasonCounts: Record<string, number> = {};
    for (const r of rejected) rejectedReasonCounts[r.status] = (rejectedReasonCounts[r.status] ?? 0) + 1;

    if (finalEligible.length === 0) {
      logger.info({ host_count: hosts.length, rejected_count: rejected.length, rejected_reasons: rejectedReasonCounts, mode }, 'Patch apply rejected: no targeted host is eligible for this upgrade');
      return res.status(409).json({ status: 'Fail', message: 'No targeted host is eligible for this upgrade', per_host: rejected });
    }

    const operation: PatchJobOperation = mode === 'packages' ? 'upgrade_packages' : 'upgrade';
    const { patch_job_id, per_host, scheduled_at } = await createPatchJob(
      fleetDb, operation, finalEligible, mode === 'packages' ? finalPackagesByHost : null, reason, user.id, user.email,
      dispatchToAgent, { scheduledAt },
    );

    logAuditTrail({
      action: 'PATCH_APPLY',
      status: 'success',
      userId: user.id,
      email: user.email,
      details: { patch_job_id, operation, host_count: eligible.length, reason, scheduled_at },
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
    }).catch((auditErr) => {
      logger.warn({ err: auditErr, patch_job_id }, 'Failed to write audit trail for patch apply');
    });

    logger.debug({ patch_job_id, operation, host_count: finalEligible.length, rejected_count: rejected.length, rejected_reasons: rejectedReasonCounts, scheduled: scheduled_at !== null }, 'Patch upgrade applied');

    return res.status(201).json({ status: 'Success', patch_job_id, operation, scheduled_at, per_host: [...per_host, ...rejected] });
  } catch (error) {
    logger.error(
      { err: error, host_identifiers: req.body?.host_identifiers, mode: req.body?.mode },
      'Failed to apply patch upgrade',
    );
    return next(new CustomError(500, 'Raw', 'Failed to apply patch upgrade', null, error));
  }
};

/**
 * POST /api/patch/apply/fallback
 * Body: { patch_job_id: number, totp_code: string }
 * Requires MFA (same requireMfa gate/pattern as applyPatchUpgrade, same
 * audit-trail logging convention). Looks up the given job's patch_job_nodes
 * rows currently in 'failed' status and creates a NEW patch_jobs row
 * (source='bundle', fallback_of_job_id=<original job id>) with one
 * patch_job_node per originally-failed host, using the same `operation` as
 * the original job, then dispatches the agent's `apply_bundle` action for
 * each (see createPatchJob's header comment for bundle auto-selection).
 *
 * Rejects fallback for an original job whose `operation` a signed package
 * bundle cannot possibly satisfy ('reboot', or 'apply_bundle' itself) — a
 * bundle installs packages, it cannot reboot a host, and falling back a
 * failed bundle job with another bundle job of the same nonsensical
 * "operation" is never meaningful. Enforced server-side rather than relying
 * solely on the frontend hiding the fallback button for these cases.
 */
export const applyPatchFallback = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length < 2) return next(new CustomError(500, 'Database', 'DB connection missing', []));
    const fleetDb = dbSources[1];

    const user = await requireMfa(req, res, dbSources[0]);
    if (!user) return;

    const patchJobId = Number(req.body?.patch_job_id);
    if (!Number.isInteger(patchJobId) || patchJobId <= 0) {
      return res.status(400).json({ status: 'Fail', message: 'patch_job_id must be a positive integer' });
    }

    const jobRows = await fleetDb.query(`SELECT * FROM patch_jobs WHERE id = $1`, [patchJobId]);
    if (jobRows.length === 0) {
      return res.status(404).json({ status: 'Fail', message: 'Patch job not found' });
    }
    const originalJob = jobRows[0];

    if (originalJob.operation === 'reboot' || originalJob.operation === 'apply_bundle') {
      return res.status(400).json({ status: 'Fail', message: `a signed patch bundle cannot fall back a "${originalJob.operation}" job` });
    }
    // Guards fallback-of-a-fallback: a 'bundle'-source job can never dispatch anything
    // as its own fallback target.
    if (originalJob.source === 'bundle') {
      return res.status(409).json({ status: 'Fail', message: 'this job is already a bundle-source fallback; cannot fall back again' });
    }

    const failedRows = await fleetDb.query(
      `SELECT DISTINCT host_identifier FROM patch_job_nodes WHERE patch_job_id = $1 AND status = 'failed'`,
      [patchJobId],
    );
    const failedHosts: string[] = failedRows.map((r: any) => r.host_identifier as string);
    if (failedHosts.length === 0) {
      return res.status(409).json({ status: 'Fail', message: 'This job has no failed hosts to fall back for' });
    }

    // Same in-flight guard as a normal check/apply — a host that's since
    // picked up a brand-new job of any source must not also get a fallback
    // job stacked on top of it.
    const inFlight = await findHostsInFlight(fleetDb, failedHosts);
    const rejected: PerHostResult[] = failedHosts
      .filter((h) => inFlight.has(h.toLowerCase()))
      .map((h) => ({ host_identifier: h, status: 'rejected_in_progress', message: 'a patch job is already in progress for this host' }));
    const eligible = failedHosts.filter((h) => !inFlight.has(h.toLowerCase()));

    if (eligible.length === 0) {
      logger.info({ patch_job_id: patchJobId, failed_host_count: failedHosts.length, rejected_count: rejected.length }, 'Patch apply fallback rejected: all originally-failed hosts already have a job in progress');
      return res.status(409).json({ status: 'Fail', message: 'All originally-failed hosts already have a patch job in progress', per_host: rejected });
    }

    const { patch_job_id: newJobId, per_host } = await createPatchJob(
      fleetDb, originalJob.operation, eligible, null, originalJob.reason ?? null, user.id, user.email,
      dispatchToAgent, { source: 'bundle', fallbackOfJobId: patchJobId },
    );

    logAuditTrail({
      action: 'PATCH_APPLY_FALLBACK',
      status: 'success',
      userId: user.id,
      email: user.email,
      details: { patch_job_id: newJobId, fallback_of_job_id: patchJobId, operation: originalJob.operation, host_count: eligible.length },
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
    }).catch((auditErr) => {
      logger.warn({ err: auditErr, patch_job_id: newJobId, fallback_of_job_id: patchJobId }, 'Failed to write audit trail for patch apply fallback');
    });

    logger.debug({ patch_job_id: newJobId, fallback_of_job_id: patchJobId, host_count: eligible.length, rejected_count: rejected.length }, 'Patch apply fallback dispatched');

    return res.status(201).json({ status: 'Success', patch_job_id: newJobId, operation: originalJob.operation, per_host: [...per_host, ...rejected] });
  } catch (error) {
    logger.error({ err: error, patch_job_id: req.body?.patch_job_id }, 'Failed to apply patch fallback');
    return next(new CustomError(500, 'Raw', 'Failed to apply patch fallback', null, error));
  }
};

/** GET /api/patch/jobs — fleet-wide job history, most recent first. */
export const listPatchJobs = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));
    const jobs = await fleetDb.query(`
      SELECT pj.id, pj.operation, pj.created_by_email, pj.reason, pj.created_at,
             pj.scheduled_at, pj.bundle_id,
             COUNT(*) FILTER (WHERE pjn.status = 'queued')     AS queued_count,
             COUNT(*) FILTER (WHERE pjn.status = 'dispatched') AS dispatched_count,
             COUNT(*) FILTER (WHERE pjn.status = 'running')    AS running_count,
             COUNT(*) FILTER (WHERE pjn.status = 'success')    AS success_count,
             COUNT(*) FILTER (WHERE pjn.status = 'failed')     AS failed_count,
             COUNT(*) FILTER (WHERE pjn.status = 'timed_out')  AS timed_out_count,
             COUNT(*)                                          AS total_count
        FROM patch_jobs pj
        LEFT JOIN patch_job_nodes pjn ON pjn.patch_job_id = pj.id
       GROUP BY pj.id
       ORDER BY pj.created_at DESC
       LIMIT ${PATCH_LIST_DEFAULT_ROWS}
    `);
    logger.debug({ count: jobs.length }, 'Patch jobs listed');
    return res.status(200).json({ status: 'Success', jobs });
  } catch (error) {
    logger.error({ err: error }, 'Failed to list patch jobs');
    return next(new CustomError(500, 'Raw', 'Failed to list patch jobs', null, error));
  }
};

/** GET /api/patch/jobs/:id — full per-node breakdown for one job. */
export const getPatchJobDetail = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ status: 'Fail', message: 'Invalid job id' });
    }
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const jobRows = await fleetDb.query(`SELECT * FROM patch_jobs WHERE id = $1`, [id]);
    if (jobRows.length === 0) {
      return res.status(404).json({ status: 'Fail', message: 'Patch job not found' });
    }
    const nodeRows = await fleetDb.query(
      `SELECT * FROM patch_job_nodes WHERE patch_job_id = $1 ORDER BY id`,
      [id],
    );
    logger.debug({ patch_job_id: id, node_count: nodeRows.length }, 'Patch job detail retrieved');
    return res.status(200).json({ status: 'Success', job: jobRows[0], nodes: nodeRows });
  } catch (error) {
    logger.error({ err: error, patch_job_id: req.params?.id }, 'Failed to get patch job detail');
    return next(new CustomError(500, 'Raw', 'Failed to get patch job', null, error));
  }
};

// Fleet-wide (no host_identifier filter) responses are capped as a
// defense-in-depth safety valve, same rationale/value as patch_gap.ts's
// FLEETWIDE_ROW_LIMIT — a single-host query is naturally bounded by that
// host's own available-update count and is never capped.
const AVAILABLE_UPDATES_FLEETWIDE_ROW_LIMIT = PATCH_FLEETWIDE_ROW_LIMIT;

/**
 * GET /api/patch/available?host_identifier=...
 * With a host filter: that host's reviewable available-updates list, backing the
 * wizard's review step. Without one: every host+package row fleet-wide rather than an
 * aggregate, because AvailableUpdatesPage.tsx aggregates by package name client-side and
 * needs the per-host identifiers to survive for the per-package "Apply" action to target.
 */
export const listAvailableUpdates = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const host = typeof req.query.host_identifier === 'string' ? req.query.host_identifier.trim() : '';
    if (host) {
      const rows = await fleetDb.query(
        `SELECT manager, name, installed_version, available_version, updated_at
           FROM patch_available_updates WHERE LOWER(host_identifier) = LOWER($1) ORDER BY manager, name`,
        [host],
      );
      logger.debug({ host_identifier: host, count: rows.length }, 'Available updates retrieved');
      return res.status(200).json({ status: 'Success', host_identifier: host, updates: rows });
    }

    // Fetch one row past the cap to detect truncation without a separate
    // COUNT(*) query (same trick as patch_gap.ts's limitClause).
    const rowsRaw = await fleetDb.query(`
      SELECT host_identifier, manager, name, installed_version, available_version, updated_at
        FROM patch_available_updates
       ORDER BY name, manager, host_identifier
       LIMIT ${AVAILABLE_UPDATES_FLEETWIDE_ROW_LIMIT + 1}
    `);
    const truncated = rowsRaw.length > AVAILABLE_UPDATES_FLEETWIDE_ROW_LIMIT;
    const rows = truncated ? rowsRaw.slice(0, AVAILABLE_UPDATES_FLEETWIDE_ROW_LIMIT) : rowsRaw;
    logger.debug({ count: rows.length, truncated }, 'Available updates retrieved');
    return res.status(200).json({ status: 'Success', host_identifier: null, updates: rows, truncated });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.query?.host_identifier }, 'Failed to list available updates');
    return next(new CustomError(500, 'Raw', 'Failed to list available updates', null, error));
  }
};

/**
 * POST /api/patch/reboot
 * Body: { host_identifiers: string[], totp_code: string, reason?: string }
 * Requires MFA (same requireMfa gate as applyPatchUpgrade). Creates a native-source
 * patch_jobs row with operation='reboot', dispatched over the same osupdate WS
 * channel/ack/result-correlation machinery as check/upgrade.
 *
 * Deliberately does NOT require a prior successful 'check': that gate exists to learn
 * the host's package manager, which a reboot does not depend on.
 *
 * Plumbing only today. The Go agent's osupdate switch implements only OpCheck/OpUpgrade
 * and OpApplyBundle; anything else falls through to `default: unknown osupdate action`,
 * an immediate refusal with no task_id. websocket/node.ts treats a no-task_id ack as a
 * prompt 'failed' outcome, so a reboot job shows up in Job History as failed with that
 * reason per host — visible and auditable, but it will not reboot anything until the
 * agent gains a real 'reboot' handler. agent/terminal is not reused for this: it is an
 * interactive shell-session capability, far wider than "run one fixed command".
 */
export const triggerPatchReboot = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length < 2) return next(new CustomError(500, 'Database', 'DB connection missing', []));
    const fleetDb = dbSources[1];

    const user = await requireMfa(req, res, dbSources[0]);
    if (!user) return;

    const hosts = validateHostIdentifiers(req.body?.host_identifiers);
    if (!hosts) {
      return res.status(400).json({ status: 'Fail', message: `host_identifiers must be a non-empty array (max ${MAX_HOSTS})` });
    }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason.slice(0, PATCH_REASON_MAX_LENGTH) : null;

    const inFlight = await findHostsInFlight(fleetDb, hosts);
    const rejected: PerHostResult[] = hosts
      .filter((h) => inFlight.has(h.toLowerCase()))
      .map((h) => ({ host_identifier: h, status: 'rejected_in_progress', message: 'a patch job is already in progress for this host' }));
    const eligible = hosts.filter((h) => !inFlight.has(h.toLowerCase()));

    if (eligible.length === 0) {
      logger.info({ host_count: hosts.length, rejected_count: rejected.length }, 'Patch reboot rejected: all targeted hosts already have a job in progress');
      return res.status(409).json({ status: 'Fail', message: 'All targeted hosts already have a patch job in progress', per_host: rejected });
    }

    const { patch_job_id, per_host } = await createPatchJob(
      fleetDb, 'reboot', eligible, null, reason, user.id, user.email, dispatchToAgent,
    );

    logAuditTrail({
      action: 'PATCH_REBOOT',
      status: 'success',
      userId: user.id,
      email: user.email,
      details: { patch_job_id, host_count: eligible.length, reason },
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
    }).catch((auditErr) => {
      logger.warn({ err: auditErr, patch_job_id }, 'Failed to write audit trail for patch reboot');
    });

    logger.debug({ patch_job_id, host_count: eligible.length, rejected_count: rejected.length }, 'Patch reboot triggered');

    return res.status(201).json({ status: 'Success', patch_job_id, operation: 'reboot', per_host: [...per_host, ...rejected] });
  } catch (error) {
    logger.error({ err: error, host_identifiers: req.body?.host_identifiers }, 'Failed to trigger patch reboot');
    return next(new CustomError(500, 'Raw', 'Failed to trigger reboot', null, error));
  }
};

/**
 * GET /api/patch/reboot-required
 * Fleet-wide list of hosts whose most recent patch_job_nodes row that reported a
 * `reboot_required` signal at all (from any operation) says true. A later row saying
 * false, or reporting no signal at all (reboot_required stays NULL, e.g. any row from a
 * failed job), supersedes an earlier true.
 *
 * Known limitation: the agent has no real 'reboot' action yet (see triggerPatchReboot),
 * so a dispatched reboot job fails before running anything and never sets
 * reboot_required. A host therefore only leaves this list once a later check/upgrade
 * reports reboot_required=false, or once agent-side reboot support lands.
 */
export const listHostsNeedingReboot = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));
    const rows = await fleetDb.query(`
      SELECT host_identifier, patch_job_id, operation, completed_at FROM (
        SELECT DISTINCT ON (LOWER(pjn.host_identifier))
               LOWER(pjn.host_identifier) AS host_identifier, pjn.patch_job_id, pj.operation,
               pjn.reboot_required, pjn.completed_at
          FROM patch_job_nodes pjn
          JOIN patch_jobs pj ON pj.id = pjn.patch_job_id
         WHERE pjn.reboot_required IS NOT NULL
         ORDER BY LOWER(pjn.host_identifier), pjn.completed_at DESC NULLS LAST, pjn.id DESC
      ) latest
      WHERE reboot_required = true
      ORDER BY completed_at DESC NULLS LAST
      LIMIT 500
    `);
    logger.debug({ count: rows.length }, 'Hosts needing reboot listed');
    return res.status(200).json({ status: 'Success', hosts: rows });
  } catch (error) {
    logger.error({ err: error }, 'Failed to list hosts needing reboot');
    return next(new CustomError(500, 'Raw', 'Failed to list hosts needing reboot', null, error));
  }
};

// Stale-job reaper. Deliberately simple: no auto-retry, it only relabels so the
// dashboard stops showing a job as "running" forever when the agent crashed mid-upgrade
// or the completion push was lost. STUCK_JOB_GRACE_MINUTES exceeds osupdate's own
// 45-minute upgrade timeout so a slow-but-healthy run is never mislabeled. 'acked' is
// reaped alongside 'dispatched'/'running' — a job stuck there is just as stale.
const STUCK_JOB_GRACE_MINUTES = 50;
const SWEEP_INTERVAL_MS = 5 * 60 * 1000;

async function sweepStalePatchJobs(): Promise<void> {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb || !fleetDb.isInitialized) return;
    // returningRows is required: TypeORM's Postgres driver returns UPDATE ... RETURNING
    // as [rows, rowCount], not as a row array.
    const rows = returningRows<{ host_identifier: string }>(await fleetDb.query(
      `UPDATE patch_job_nodes
          SET status = 'timed_out', updated_at = NOW()
        WHERE status IN ('dispatched', 'acked', 'running')
          AND dispatched_at < NOW() - ($1 * INTERVAL '1 minute')
        RETURNING host_identifier`,
      [STUCK_JOB_GRACE_MINUTES],
    ));
    // Each relabeled row frees its host up for the next queued command —
    // same single-in-flight-per-host gate as every other terminal transition
    // (see websocket/patchDispatch.ts).
    for (const row of rows) {
      void dispatchNextPendingPatchCommand(row.host_identifier, dispatchToAgent);
    }

    // A patch_job_nodes row sitting 'queued' past the grace period with NO
    // pending_patch_commands entry was never even attempted — a legitimately offline
    // host always gets a pending_patch_commands row via dispatchOrQueuePatchJobNode —
    // and is not part of a still-future scheduled job. Reaped because findHostsInFlight
    // treats a 'queued' row as busy, so leaving one behind locks the host out of every
    // future patch action permanently.
    const stuckQueued = returningRows<{ host_identifier: string }>(await fleetDb.query(
      `UPDATE patch_job_nodes pjn
          SET status = 'failed', failure_reason = 'job was never dispatched (stuck queued with no delivery attempt)', completed_at = NOW(), updated_at = NOW()
        FROM patch_jobs pj
        WHERE pjn.patch_job_id = pj.id
          AND pjn.status = 'queued'
          AND pj.scheduled_at IS NULL
          AND pjn.updated_at < NOW() - ($1 * INTERVAL '1 minute')
          AND NOT EXISTS (SELECT 1 FROM pending_patch_commands ppc WHERE ppc.patch_job_node_id = pjn.id)
        RETURNING pjn.host_identifier`,
      [STUCK_JOB_GRACE_MINUTES],
    ));
    for (const row of stuckQueued) {
      void dispatchNextPendingPatchCommand(row.host_identifier, dispatchToAgent);
    }

    if (rows.length > 0 || stuckQueued.length > 0) {
      logger.warn(
        { timed_out_count: rows.length, stuck_queued_count: stuckQueued.length },
        'Stale patch job sweep relabeled stuck jobs',
      );
    }
  } catch (err) {
    logger.error({ err }, 'Stale patch job sweep failed');
  }
}

setInterval(() => {
  void sweepStalePatchJobs();
}, SWEEP_INTERVAL_MS).unref();

// Scheduled-job dispatcher
// Single-shot scheduling for POST /api/patch/apply's `scheduled_at` field. A periodic
// sweep, not a job queue — same setInterval idiom as sweepStalePatchJobs.
//
// Runs every minute; schedules are minute-granularity from the wizard's
// datetime-local input, so anything tighter buys nothing. The claiming UPDATE is
// atomic and RETURNING-based so a job is claimed exactly once even if two ticks
// overlapped, and scheduled_at is cleared as part of the claim rather than after
// dispatch so a mid-loop crash cannot cause a double dispatch on the next tick.
const SCHEDULE_SWEEP_INTERVAL_MS = 60 * 1000;

async function sweepScheduledPatchJobs(): Promise<void> {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb || !fleetDb.isInitialized) return;

    // 'bundle'-source jobs are excluded — they never dispatch regardless of
    // scheduling (see createPatchJob), so there's nothing to fire for them;
    // excluding them here just avoids pointlessly claiming (and thereby
    // losing the scheduled_at audit value from) a job that would no-op anyway.
    // returningRows is required: TypeORM returns [rows, rowCount] for an UPDATE, so
    // the raw result's length is always 2 and the loop below would iterate the tuple
    // instead of the claimed jobs.
    const due = returningRows<{ id: number; operation: PatchJobOperation }>(await fleetDb.query(
      `UPDATE patch_jobs SET scheduled_at = NULL
        WHERE scheduled_at IS NOT NULL AND scheduled_at <= NOW() AND source = 'native'
        RETURNING id, operation`,
    ));
    if (due.length === 0) return;

    for (const job of due) {
      const nodeRows = await fleetDb.query(
        `SELECT id, host_identifier, package_names FROM patch_job_nodes
          WHERE patch_job_id = $1 AND status = 'queued'`,
        [job.id],
      );
      if (nodeRows.length === 0) {
        // Should not happen in normal operation (createPatchJob always creates
        // one 'queued' patch_job_nodes row per targeted host) — logged so a
        // due job that silently dispatches nothing leaves a trace rather than
        // vanishing from the logs entirely.
        logger.warn({ patch_job_id: job.id, operation: job.operation }, 'Scheduled patch job sweep found a due job with no queued nodes to dispatch');
        continue;
      }

      // Defense-in-depth busy re-check immediately before dispatch, the same pattern
      // dispatchNextPendingPatchCommand uses on its own dispatch surface. Today no
      // other endpoint can slip a job in ahead of this one — findHostsInFlight already
      // treats this row's own 'queued' status as busy — but that is incidental, not
      // enforced here. This job's own rows are excluded from the check, since they
      // would otherwise always self-match as busy.
      const hostIdentifiers: string[] = nodeRows.map((n: any) => n.host_identifier as string);
      const busyRows = await fleetDb.query(
        `SELECT DISTINCT LOWER(host_identifier) AS host_identifier FROM patch_job_nodes
          WHERE LOWER(host_identifier) = ANY($1) AND status IN ('dispatched','acked','running')
            AND patch_job_id <> $2`,
        [hostIdentifiers.map((h: string) => h.toLowerCase()), job.id],
      );
      const busy = new Set(busyRows.map((r: any) => r.host_identifier as string));
      let skippedBusyCount = 0;
      for (const node of nodeRows) {
        if (busy.has((node.host_identifier as string).toLowerCase())) {
          // Left 'queued' rather than dispatched: a newer job took the host between
          // this sweep claiming job.id and this node's turn. Counted rather than
          // warned per node (the sweep runs every minute and would spam), but counted
          // so the skip is not a silent no-op.
          skippedBusyCount++;
          continue;
        }
        const pkgs: string[] | null = node.package_names
          ? (typeof node.package_names === 'string' ? JSON.parse(node.package_names) : node.package_names)
          : null;
        const extraParams = pkgs && pkgs.length > 0 ? { command_keys: pkgs } : null;
        await dispatchOrQueuePatchJobNode(fleetDb, node.id, node.host_identifier, job.operation, extraParams, dispatchToAgent);
      }
      if (skippedBusyCount > 0) {
        logger.warn(
          { patch_job_id: job.id, operation: job.operation, skipped_busy_count: skippedBusyCount, node_count: nodeRows.length },
          'Scheduled patch job sweep skipped some hosts that became busy before dispatch',
        );
      }
    }

    logger.info({ due_job_count: due.length }, 'Scheduled patch job sweep dispatched due jobs');
  } catch (err) {
    logger.error({ err }, 'Scheduled patch job sweep failed');
  }
}

setInterval(() => {
  void sweepScheduledPatchJobs();
}, SCHEDULE_SWEEP_INTERVAL_MS).unref();
