/**
 * Redelivery of Patch Management commands that controllers/nodes/patch_management.ts
 * queued in pending_patch_commands while a node was offline.
 *
 * The agent's osupdate engine is single-flight, so this module never sends more
 * than one outstanding command to a host: every entry point advances the queue
 * by exactly one and re-checks "is this host busy" immediately before
 * dispatching. Both functions are therefore safe to call opportunistically —
 * calling one while the host is still busy is a no-op.
 */

import { dbSourceConnection } from '../index';
import { getLogger } from '../utils/logger';

const logger = getLogger('websocket.patchDispatch');

export type DispatchFn = (hostIdentifier: string, payload: Record<string, unknown>) => { dispatched: boolean; error?: string };

// Statuses meaning the host already has a patch_job_nodes row in flight; never
// send a second command on top. Intentionally excludes 'queued', unlike
// findHostsInFlight in controllers/nodes/patch_management.ts: 'queued' is the
// state of the very command this module is about to dispatch, so counting it as
// busy would make redelivery impossible.
const BUSY_STATUSES = ['dispatched', 'acked', 'running'];

async function isHostBusy(fleetDb: any, hostIdentifier: string): Promise<boolean> {
  const rows = await fleetDb.query(
    `SELECT 1 FROM patch_job_nodes
      WHERE LOWER(host_identifier) = LOWER($1) AND status = ANY($2)
      LIMIT 1`,
    [hostIdentifier, BUSY_STATUSES],
  );
  return rows.length > 0;
}

/**
 * Dispatches the single oldest command queued in pending_patch_commands for
 * `hostIdentifier`, provided it has no in-flight (dispatched/acked/running)
 * patch_job_nodes row. No-op if the host is busy or has nothing pending; all
 * errors are logged and swallowed.
 *
 * Dispatch-then-delete, not delete-then-dispatch: a crash mid-call leaves the
 * row queued for the next trigger instead of silently losing the command.
 */
export async function dispatchNextPendingPatchCommand(hostIdentifier: string, dispatch: DispatchFn): Promise<void> {
  try {
    const dbSources = dbSourceConnection();
    if (!dbSources || dbSources.length < 2 || !dbSources[1].isInitialized) {
      logger.warn({ hostIdentifier }, 'Fleet DB unavailable, cannot dispatch pending patch command');
      return;
    }
    const fleetDb = dbSources[1];

    // Several independent triggers call this concurrently with a "check busy,
    // then act" pattern. Without serialization two of them can both observe
    // "not busy" and both dispatch, and the agent's refusal of the loser can
    // land first and permanently mark a job 'failed' that actually succeeded.
    // The advisory lock makes busy-check + dispatch atomic per host.
    await fleetDb.transaction(async (manager: any) => {
      await manager.query('SELECT pg_advisory_xact_lock(hashtext($1))', [hostIdentifier]);

      if (await isHostBusy(manager, hostIdentifier)) return;

      const pending = await manager.query(
        `SELECT id, patch_job_node_id, payload FROM pending_patch_commands
          WHERE LOWER(host_identifier) = LOWER($1)
          ORDER BY created_at ASC LIMIT 1`,
        [hostIdentifier],
      );
      if (pending.length === 0) return;

      const row = pending[0];
      const payload = typeof row.payload === 'string' ? JSON.parse(row.payload) : row.payload;

      // Mark dispatched before sending, matching dispatchOrQueuePatchJobNode in
      // patch_management.ts: otherwise the agent's ack can arrive before this
      // write lands and be applied to a stale row.
      await manager.query(
        `UPDATE patch_job_nodes SET status = 'dispatched', dispatched_at = NOW(), updated_at = NOW() WHERE id = $1`,
        [row.patch_job_node_id],
      );

      const result = dispatch(hostIdentifier, payload);
      if (result.dispatched) {
        await manager.query(`DELETE FROM pending_patch_commands WHERE id = $1`, [row.id]);
        logger.info(
          { hostIdentifier, pendingId: row.id, patchJobNodeId: row.patch_job_node_id },
          'Pending patch command dispatched, advanced queue',
        );
      } else {
        // Send failed right after connect (e.g. a flapping link). Revert to
        // queued and leave the pending_patch_commands row for the next trigger.
        await manager.query(
          `UPDATE patch_job_nodes SET status = 'queued', dispatched_at = NULL, updated_at = NOW() WHERE id = $1`,
          [row.patch_job_node_id],
        );
        logger.debug(
          { hostIdentifier, pendingId: row.id, dispatchError: result.error },
          'Pending patch command dispatch failed, reverted to queued',
        );
      }
    });
  } catch (err) {
    logger.error({ err, hostIdentifier }, 'Failed to dispatch next pending patch command');
  }
}

/**
 * Called on agent (re)connect. Deliberately tries only the single oldest
 * pending command rather than draining the queue: osupdate processes one job at
 * a time, so a burst would strand all but the first in 'dispatched' until the
 * stale-job sweep relabels them 'timed_out'.
 */
export async function dispatchPendingPatchCommands(hostIdentifier: string, dispatch: DispatchFn): Promise<void> {
  await dispatchNextPendingPatchCommand(hostIdentifier, dispatch);
}
