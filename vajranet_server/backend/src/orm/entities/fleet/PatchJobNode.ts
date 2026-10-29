import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  Index,
} from 'typeorm';

/**
 * Status machine: queued -> dispatched -> acked -> running -> success|failed|timed_out
 *   queued:     row created, not yet sent (host offline at dispatch time, or
 *               awaiting a scheduled_at firing — see PatchJob). 'bundle'-
 *               source jobs dispatch the same as any other job once created.
 *   dispatched: WS send to the agent succeeded; no confirmation yet.
 *   acked:      the agent's immediate response to "osupdate" carried a
 *               task_id — see websocket/node.ts's "osupdate_ack:" rid
 *               handling — confirming it actually started.
 *   running:    reserved for a future explicit in-progress signal.
 *   success/failed/timed_out: terminal.
 */
export type PatchJobNodeStatus =
  | 'queued'
  | 'dispatched'
  | 'acked'
  | 'running'
  | 'success'
  | 'failed'
  | 'timed_out';

/**
 * Per-host outcome of a patch_jobs row. Correlated to the agent's async
 * osupdate_result push primarily by `task_id` (set once the row moves
 * dispatched -> acked); falls back to "the newest dispatched/acked/running
 * row for this host" only when task_id is absent (older agent build, or a
 * lost ack) — see websocket/node.ts.
 *
 * All host_identifier comparisons against this table are wrapped in LOWER()
 * at query time; the column itself is left case-as-stored.
 */
@Entity('patch_job_nodes')
@Index(['patchJobId'])
@Index(['hostIdentifier', 'status'])
@Index(['taskId'])
export class PatchJobNode {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'bigint', name: 'patch_job_id' })
  patchJobId!: number;

  @Column({ type: 'text', name: 'host_identifier' })
  hostIdentifier!: string;

  @Column({ type: 'jsonb', nullable: true, name: 'package_names' })
  packageNames!: string[] | null;

  @Column({ type: 'text', default: 'queued' })
  status!: PatchJobNodeStatus;

  @Column({ type: 'text', nullable: true })
  manager!: string | null;

  @Column({ type: 'jsonb', nullable: true })
  result!: Record<string, unknown> | null;

  /** Set from the agent's immediate ack; the osupdate_result correlation key. */
  @Column({ type: 'text', nullable: true, name: 'task_id' })
  taskId!: string | null;

  @Column({ type: 'boolean', nullable: true, name: 'reboot_required' })
  rebootRequired!: boolean | null;

  /**
   * Populated when the agent reports success:false with a failure_reason
   * string (network_unreachable, dns_failure, repo_unreachable, lock_timeout,
   * gpg_verify_failed, disk_full, other). Not validated against an enum
   * server-side — the Go agent owns that vocabulary.
   */
  @Column({ type: 'text', nullable: true, name: 'failure_reason' })
  failureReason!: string | null;

  @Column({ type: 'timestamptz', nullable: true, name: 'dispatched_at' })
  dispatchedAt!: Date | null;

  @Column({ type: 'timestamptz', nullable: true, name: 'completed_at' })
  completedAt!: Date | null;

  @Column({ type: 'timestamptz', name: 'updated_at' })
  updatedAt!: Date;
}
