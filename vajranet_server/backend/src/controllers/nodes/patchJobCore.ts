/**
 * Patch-job creation core — deliberately free of any dependency on
 * websocket/node.ts and controllers/nodes/patch_management.ts.
 *
 * It lives here rather than in patch_management.ts so websocket/node.ts's
 * osupdate_result handler can create a follow-up 'check' job without importing from
 * patch_management.ts, which already imports dispatchToAgent from node.ts — that
 * combination would be a circular import. Importing dispatchToAgent here would recreate
 * the same cycle one file over, so the WS-send function is injected as the `dispatch`
 * parameter instead: node.ts passes its own local dispatchToAgent, and
 * patch_management.ts passes the one it already imports from node.ts. The result is
 * node.ts -> patchJobCore.ts and patch_management.ts -> patchJobCore.ts with no edge
 * back, a DAG rather than a cycle. Keep it that way.
 */

import { DispatchFn } from '../../websocket/patchDispatch';
import { detectHostPackageFamily, selectBundleForHostFamily, SelectedPatchBundle } from '../../utils/patchBundleSelect';
import { getLogger } from '../../utils/logger';
import { PATCH_REASON_MAX_LENGTH } from '../../consts/pagination';
import { RID_PREFIX_OSUPDATE_ACK } from '../../consts/websocket';
import { PATCH_JOB_DISPATCH_CONCURRENCY } from '../../consts/database';

const logger = getLogger('nodes.patchJobCore');

export type PerHostResult = { host_identifier: string; status: string; message?: string };

/** Where the job's payload came from — matches patch_jobs.source. */
export type PatchJobSource = 'native' | 'bundle';

export type PatchJobOperation = 'check' | 'upgrade' | 'upgrade_packages' | 'reboot' | 'apply_bundle';

/**
 * Dispatches one osupdate command to `host` (or queues it in
 * pending_patch_commands if the host isn't currently connected), tagging the
 * payload with a synthetic `rid` of "osupdate_ack:<patch_job_node id>" so the
 * agent's immediate response can be correlated back to this exact row (see
 * websocket/node.ts's osupdate_ack handling).
 */
async function dispatchOrQueuePatchJobNode(
  fleetDb: any,
  nodeId: number,
  host: string,
  action: string,
  extraParams: Record<string, unknown> | null,
  dispatch: DispatchFn,
): Promise<PerHostResult> {
  const params: Record<string, unknown> = { agent: 'osupdate', action };
  if (extraParams) Object.assign(params, extraParams);
  const payload = { type: 'agent', params, host_identifier: host, rid: `${RID_PREFIX_OSUPDATE_ACK}${nodeId}` };

  // Marked 'dispatched' BEFORE the send, not after: otherwise the agent's ack can arrive
  // and be processed before the DB write lands.
  await fleetDb.query(
    `UPDATE patch_job_nodes SET status='dispatched', dispatched_at=NOW(), updated_at=NOW() WHERE id=$1`,
    [nodeId],
  );
  const result = dispatch(host, payload);
  if (result.dispatched) {
    return { host_identifier: host, status: 'dispatched' };
  }
  await fleetDb.query(
    `UPDATE patch_job_nodes SET status='queued', dispatched_at=NULL, updated_at=NOW() WHERE id=$1`,
    [nodeId],
  );
  await fleetDb.query(
    `INSERT INTO pending_patch_commands (patch_job_node_id, host_identifier, payload) VALUES ($1,$2,$3)`,
    [nodeId, host, JSON.stringify(payload)],
  );
  return { host_identifier: host, status: 'queued', message: result.error };
}

/**
 * Creates one patch_jobs row plus one patch_job_nodes row per host.
 *
 * For a 'native' job (the default — every check/upgrade/reboot goes through
 * this path) with no future `scheduledAt`: dispatches the underlying WS
 * command to each online host immediately via dispatchOrQueuePatchJobNode.
 *
 * For a 'native' job with a future `scheduledAt`: every row is left 'queued' with no
 * dispatch attempt; patch_management.ts's sweepScheduledPatchJobs fires it once
 * `scheduled_at` has passed.
 *
 * For a 'bundle' job: dispatches the agent's `apply_bundle` action with arg1
 * set to the chosen patch_bundles row's original signed `{payload,signature}`
 * wire bytes. If `bundleId` is set, that exact row is used (looked up once,
 * not once per host — the row never changes across hosts in the loop below).
 * Otherwise a bundle is auto-selected via selectBundleForHostFamily for
 * whichever family the host's own package inventory indicates. If no usable
 * bundle exists, the row is failed immediately with an honest reason rather
 * than left 'queued' forever.
 */
export async function createPatchJob(
  fleetDb: any,
  operation: PatchJobOperation,
  hosts: string[],
  packagesByHost: Record<string, string[]> | null,
  reason: string | null,
  createdById: number | null,
  createdByEmail: string | null,
  dispatch: DispatchFn,
  options?: {
    source?: PatchJobSource;
    fallbackOfJobId?: number | null;
    bundleId?: number | null;
    /** Future timestamp: defer dispatch to sweepScheduledPatchJobs. Past/now/omitted: dispatch immediately. */
    scheduledAt?: Date | null;
  },
): Promise<{ patch_job_id: number; per_host: PerHostResult[]; scheduled_at: string | null }> {
  const source = options?.source ?? 'native';
  const fallbackOfJobId = options?.fallbackOfJobId ?? null;
  const bundleId = options?.bundleId ?? null;
  const scheduledAt = options?.scheduledAt && options.scheduledAt.getTime() > Date.now() ? options.scheduledAt : null;

  const jobRows = await fleetDb.query(
    `INSERT INTO patch_jobs (operation, created_by_id, created_by_email, reason, source, fallback_of_job_id, bundle_id, scheduled_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
    [operation, createdById, createdByEmail, reason ?? null, source, fallbackOfJobId, bundleId, scheduledAt],
  );
  const patchJobId = jobRows[0].id as number;

  // A pinned bundleId names one specific, unchanging row, so it is fetched once before
  // the per-host loop rather than lazily on first use. Lazy loading was safe while the
  // loop was sequential; with hosts processed in concurrent batches several would
  // observe "not loaded yet" at the same time and each fire an identical SELECT.
  let pinnedBundle: SelectedPatchBundle | null = null;
  if (source === 'bundle' && bundleId) {
    const rows = await fleetDb.query(
      `SELECT id, bundle_id, family, payload, signature FROM patch_bundles WHERE id = $1`,
      [bundleId],
    );
    pinnedBundle = rows[0] ?? null;
  }

  // Indexed writes (not .push()) below so each host's result lands at its
  // own position regardless of completion order within a concurrent batch.
  const perHost: PerHostResult[] = new Array(hosts.length);
  // Distinct immediate-failure reasons seen in this batch (bundle-source jobs
  // only — see the 'failed' push below) so the summary warn below can report
  // which specific reason(s) occurred instead of a hardcoded, sometimes-wrong
  // guess: "no signed patch bundle available" and "bundle predates raw-
  // signature storage" are different, actionable situations for an operator.
  const failureReasonCounts = new Map<string, number>();

  // Every host's patch_job_nodes row is created in one multi-row INSERT rather than one
  // round trip per host, since a single job can target up to MAX_HOSTS hosts. Everything
  // after row creation stays per-host: bundle selection, signature checks and the WS
  // dispatch are genuine per-host decisions with side effects.
  //
  // A multi-row VALUES INSERT returns its rows in the order the VALUES were listed, so
  // nodeIds[i] corresponds to hosts[i] positionally. Deliberately not keyed by
  // host_identifier: `hosts` may contain a duplicate, and a host->id map would collapse
  // it to one row instead of one row per loop iteration. The empty guard matters too —
  // an empty VALUES list is a SQL syntax error, not a graceful no-op.
  const nodeRowsAll: { id: number }[] = hosts.length === 0 ? [] : await fleetDb.query(
    `INSERT INTO patch_job_nodes (patch_job_id, host_identifier, package_names, status, updated_at)
     VALUES ${hosts.map((_h, i) => `($1, $${i * 2 + 2}, $${i * 2 + 3}, 'queued', NOW())`).join(', ')}
     RETURNING id`,
    [patchJobId, ...hosts.flatMap((host) => {
      const pkgs = packagesByHost ? packagesByHost[host] ?? [] : null;
      return [host, pkgs ? JSON.stringify(pkgs) : null];
    })],
  );
  const nodeIds = nodeRowsAll.map((r) => r.id);

  // Each host's work here (bundle selection, the status UPDATE, the WS dispatch) is
  // independent of every other host's: its own patch_job_nodes row and its own agent
  // socket (websocket/node.ts's EXTENSIONS pool is one connection per agent, never
  // shared). Processed in PATCH_JOB_DISPATCH_CONCURRENCY-sized batches rather than
  // sequentially (up to MAX_HOSTS round trips awaited one at a time) or as one
  // Promise.all over every host, which would demand far more connections than the fleet
  // DB's fixed-size pool has.
  async function processHost(hostIndex: number): Promise<void> {
    const host = hosts[hostIndex];
    const nodeId = nodeIds[hostIndex];
    const pkgs = packagesByHost ? packagesByHost[host] ?? [] : null;

    if (source === 'bundle') {
      const bundle = bundleId
        ? pinnedBundle
        : await (async () => {
            const family = await detectHostPackageFamily(fleetDb, host);
            return family ? await selectBundleForHostFamily(fleetDb, family, host) : null;
          })();

      if (!bundle || !bundle.payload || !bundle.signature) {
        const failReason = !bundle
          ? 'no signed patch bundle available for this host'
          : 'selected bundle predates raw-signature storage and cannot be forwarded to the agent (re-upload it)';
        await fleetDb.query(
          `UPDATE patch_job_nodes SET status='failed', failure_reason=$1, completed_at=NOW(), updated_at=NOW() WHERE id=$2`,
          [failReason.slice(0, PATCH_REASON_MAX_LENGTH), nodeId],
        );
        perHost[hostIndex] = { host_identifier: host, status: 'failed', message: failReason };
        failureReasonCounts.set(failReason, (failureReasonCounts.get(failReason) ?? 0) + 1);
        return;
      }

      const arg1 = JSON.stringify({ payload: bundle.payload, signature: bundle.signature });
      perHost[hostIndex] = await dispatchOrQueuePatchJobNode(fleetDb, nodeId, host, 'apply_bundle', { arg1 }, dispatch);
      return;
    }
    if (scheduledAt) {
      perHost[hostIndex] = { host_identifier: host, status: 'queued', message: `scheduled for ${scheduledAt.toISOString()}` };
      return;
    }

    const extraParams = pkgs && pkgs.length > 0 ? { command_keys: pkgs } : null;
    perHost[hostIndex] = await dispatchOrQueuePatchJobNode(fleetDb, nodeId, host, operation, extraParams, dispatch);
  }

  for (let batchStart = 0; batchStart < hosts.length; batchStart += PATCH_JOB_DISPATCH_CONCURRENCY) {
    const batchEnd = Math.min(batchStart + PATCH_JOB_DISPATCH_CONCURRENCY, hosts.length);
    const batch: Promise<void>[] = [];
    for (let hostIndex = batchStart; hostIndex < batchEnd; hostIndex++) batch.push(processHost(hostIndex));
    await Promise.all(batch);
  }

  const failedCount = perHost.filter((r) => r.status === 'failed').length;
  const dispatchedCount = perHost.filter((r) => r.status === 'dispatched').length;
  const queuedCount = perHost.filter((r) => r.status === 'queued').length;
  if (failedCount > 0) {
    // Reasons broken out explicitly — the two possible causes ("no bundle
    // uploaded for this family" vs. "a bundle exists but predates raw-
    // signature storage and needs re-upload") call for different operator
    // action, and a single hardcoded message here would misdiagnose whichever
    // one didn't actually happen.
    logger.warn(
      {
        patch_job_id: patchJobId, operation, source, failed_count: failedCount, host_count: hosts.length,
        failure_reasons: Object.fromEntries(failureReasonCounts),
      },
      'Patch job created with one or more hosts failed immediately',
    );
  }
  logger.info(
    {
      patch_job_id: patchJobId, operation, source, host_count: hosts.length,
      dispatched_count: dispatchedCount, queued_count: queuedCount, failed_count: failedCount,
      scheduled: scheduledAt !== null,
    },
    'Patch job created',
  );

  return { patch_job_id: patchJobId, per_host: perHost, scheduled_at: scheduledAt ? scheduledAt.toISOString() : null };
}

/** Exposed for sweepScheduledPatchJobs, which dispatches already-created rows directly rather than via createPatchJob. */
export { dispatchOrQueuePatchJobNode };
