import {
  Entity,
  PrimaryColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';

export type WindowsPatchJobAction = 'install' | 'uninstall';
export type WindowsPatchJobStatus = 'pending' | 'acknowledged' | 'success' | 'failure' | 'rejected' | 'timed_out';

/**
 * Per-host job tracking for a Windows maintained-app install/uninstall
 * dispatch. id IS the job_id sent to the agent as arg1 (a UUID already
 * satisfies the agent's ^[A-Za-z0-9_-]{1,64}$ charset).
 *
 * Deliberately NOT named patch_jobs — that table already exists for the
 * pre-existing, unrelated Linux osupdate feature (see PatchJob.ts).
 *
 * Schema-tracked by migration backend/migrations/011_add_windows_maintained_apps.sql
 * — see MaintainedApp.ts's header comment; this entity exists for schema
 * drift-detection only, controllers use raw fleetDb.query(...) (see
 * controllers/nodes/windows_patch_management.ts and the patch_job_ack:/
 * patch_job_push handling in websocket/node.ts).
 */
@Entity('windows_patch_jobs')
@Index('idx_wpj_host', ['hostIdentifier'])
@Index('idx_wpj_status', ['status'])
@Index('idx_wpj_requested_at', ['requestedAt'])
@Index('idx_wpj_maintained_app_id', ['maintainedAppId'])
@Index('idx_wpj_maintained_app_version_id', ['maintainedAppVersionId'])
export class WindowsPatchJob {
  // Explicit gen_random_uuid() default (not @PrimaryGeneratedColumn('uuid'),
  // which — absent uuidExtension:'pgcrypto' in this codebase's Postgres
  // DataSource options — synchronize would instead default to
  // uuid_generate_v4() via the uuid-ossp extension, drifting from migration
  // 011's actual `DEFAULT gen_random_uuid()`. The DB-level default is never
  // actually exercised in practice — every INSERT (see
  // controllers/nodes/windows_patch_management.ts's requestInstall) supplies
  // id explicitly via crypto.randomUUID() — but keeping it consistent avoids
  // a hard synchronize failure on a non-production DB user lacking rights to
  // CREATE EXTENSION "uuid-ossp".
  @PrimaryColumn({ type: 'uuid', default: () => 'gen_random_uuid()' })
  id!: string;

  @Column({ type: 'varchar', length: 128, name: 'host_identifier' })
  hostIdentifier!: string;

  @Column({ type: 'bigint', name: 'maintained_app_id' })
  maintainedAppId!: number;

  @Column({ type: 'bigint', name: 'maintained_app_version_id' })
  maintainedAppVersionId!: number;

  @Column({ type: 'varchar', length: 20 })
  action!: WindowsPatchJobAction;

  @Column({ type: 'varchar', length: 20, default: 'pending' })
  status!: WindowsPatchJobStatus;

  @Column({ type: 'integer', nullable: true, name: 'requested_by_user_id' })
  requestedByUserId!: number | null;

  @Column({ type: 'varchar', length: 255, nullable: true, name: 'requested_by_email' })
  requestedByEmail!: string | null;

  @Column({ type: 'text', nullable: true, name: 'request_reason' })
  requestReason!: string | null;

  @CreateDateColumn({ type: 'timestamptz', name: 'requested_at' })
  requestedAt!: Date;

  @Column({ type: 'timestamptz', nullable: true, name: 'acknowledged_at' })
  acknowledgedAt!: Date | null;

  @Column({ type: 'timestamptz', nullable: true, name: 'completed_at' })
  completedAt!: Date | null;

  @Column({ type: 'integer', nullable: true, name: 'exit_code' })
  exitCode!: number | null;

  // Agent's failure `reason` string (see the wire-contract's catalog of
  // observed reason strings) — this is the field to surface as the outcome.
  @Column({ type: 'text', nullable: true, name: 'outcome_reason' })
  outcomeReason!: string | null;

  @Column({ type: 'varchar', length: 50, nullable: true, name: 'installed_version' })
  installedVersion!: string | null;

  @Column({ type: 'integer', nullable: true, name: 'duration_ms' })
  durationMs!: number | null;
}
