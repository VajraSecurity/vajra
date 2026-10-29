import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';

// 'reboot' (Phase 4): a native-dispatched osupdate 'reboot' action — see
// controllers/nodes/patch_management.ts's triggerPatchReboot. Plumbing-only
// as of Phase 4: the Go agent has no 'reboot' action handler yet (only
// check/upgrade/apply_bundle), so a dispatched reboot job will cleanly fail
// with "unknown osupdate action" until a future agent build adds it.
// 'apply_bundle' (Phase 4): a deliberate, admin-pinned application of one
// exact patch_bundles row (rollback / version-pin) — see
// POST /api/patch/bundles/:id/apply. Always source='bundle', bundleId set;
// like every other 'bundle'-source job, dispatch is wired — createPatchJob's
// 'bundle' branch (controllers/nodes/patch_management.ts) sends an
// apply_bundle action built from the bundle row's stored signed
// {payload, signature} bytes.
export type PatchJobOperation = 'check' | 'upgrade' | 'upgrade_packages' | 'reboot' | 'apply_bundle';
export type PatchJobSource = 'native' | 'bundle';

/**
 * One row per admin-triggered Patch Management action (check / upgrade /
 * upgrade_packages / reboot / apply_bundle) across a set of nodes. See
 * PatchJobNode for the per-host outcome.
 *
 * `source` distinguishes a normal native-package-manager job from a
 * `POST /api/patch/apply/fallback` or `POST /api/patch/bundles/:id/apply`
 * job — both 'bundle'-source, the former carries `fallback_of_job_id`
 * pointing back at the original failed job, the latter carries `bundleId`
 * pinning it to one exact patch_bundles row (see that column's comment).
 * Schema-tracked by migration
 * backend/migrations/005_add_patch_management_tables.sql (base columns) and
 * 007_add_patch_scheduling_and_bundle_pin.sql (scheduledAt/bundleId) — this
 * codebase's controllers use raw fleetDb.query(...) against this table name
 * throughout (see controllers/nodes/patch_management.ts); this entity exists
 * for schema consistency/drift-detection, not as the query interface.
 */
@Entity('patch_jobs')
@Index(['source'])
@Index(['fallbackOfJobId'])
@Index(['bundleId'])
export class PatchJob {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'text' })
  operation!: PatchJobOperation;

  @Column({ type: 'integer', nullable: true, name: 'created_by_id' })
  createdById!: number | null;

  @Column({ type: 'text', nullable: true, name: 'created_by_email' })
  createdByEmail!: string | null;

  @Column({ type: 'text', nullable: true })
  reason!: string | null;

  @Column({ type: 'text', default: 'native' })
  source!: PatchJobSource;

  @Column({ type: 'integer', nullable: true, name: 'fallback_of_job_id' })
  fallbackOfJobId!: number | null;

  /**
   * Single-shot scheduling (Phase 4). NULL means "dispatched immediately at
   * creation time" — every pre-Phase-4 job. When set at creation, dispatch is
   * deferred until the sweep (see patch_management.ts) finds
   * scheduled_at <= NOW() — which atomically clears this column back to NULL
   * as its one-time firing marker, so this is never a recurring schedule.
   */
  @Column({ type: 'timestamptz', nullable: true, name: 'scheduled_at' })
  scheduledAt!: Date | null;

  /**
   * The exact patch_bundles row (numeric id, not the manifest's bundle_id
   * uuid) this 'bundle'-source job is pinned to — set only by
   * POST /api/patch/bundles/:id/apply. NULL for every other job, including
   * POST /api/patch/apply/fallback's jobs (which select no bundle at all).
   */
  // Matches migration 007's actual column type: BIGINT REFERENCES
  // patch_bundles(id), and patch_bundles.id is BIGSERIAL — was mistakenly
  // 'integer' here, which fails at this entity's one job (drift-detection)
  // for the exact column it exists to track.
  @Column({ type: 'bigint', nullable: true, name: 'bundle_id' })
  bundleId!: number | null;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;
}
