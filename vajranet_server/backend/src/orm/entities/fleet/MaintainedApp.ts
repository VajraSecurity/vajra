import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Catalog root for the Windows "maintained apps" software install/uninstall
 * feature — one row per app (e.g. "Brave Browser"), NOT Windows Update/OS
 * patching. See WINDOWS_AGENT_PATCH_MANAGEMENT.md for the full agent-side
 * contract this catalog feeds.
 *
 * Schema-tracked by migration backend/migrations/011_add_windows_maintained_apps.sql
 * — this codebase's controllers use raw fleetDb.query(...) throughout (see
 * controllers/nodes/windows_patch_management.ts), same convention as
 * PatchJob.ts; this entity exists for schema consistency/drift-detection
 * (and so `synchronize:true` creates the table in non-production), not as
 * the query interface.
 */
@Entity('maintained_apps')
@Index('idx_maintained_apps_slug', ['slug'], { unique: true })
@Index('idx_maintained_apps_active', ['isActive'])
export class MaintainedApp {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  // e.g. "brave-browser/windows" — matches the agent payload's app_slug
  // once the trailing "/windows" is stripped at import time.
  @Column({ type: 'varchar', length: 150 })
  slug!: string;

  @Column({ type: 'varchar', length: 200 })
  name!: string;

  @Column({ type: 'varchar', length: 200, nullable: true })
  publisher!: string | null;

  // Future-proofing only — this feature targets 'windows' exclusively today.
  @Column({ type: 'varchar', length: 20, default: 'windows' })
  platform!: string;

  @Column({ type: 'varchar', length: 200, nullable: true, name: 'package_identifier' })
  packageIdentifier!: string | null;

  // Passed through verbatim to the agent's job payload as display_name_match.
  @Column({ type: 'varchar', length: 200, name: 'display_name_match' })
  displayNameMatch!: string;

  @Column({ type: 'boolean', default: false, name: 'fuzzy_match_name' })
  fuzzyMatchName!: boolean;

  @Column({ type: 'varchar', length: 100, nullable: true })
  category!: string | null;

  // Soft-disable without deleting version history.
  @Column({ type: 'boolean', default: true, name: 'is_active' })
  isActive!: boolean;

  @CreateDateColumn({ type: 'timestamptz', name: 'created_at' })
  createdAt!: Date;

  @UpdateDateColumn({ type: 'timestamptz', name: 'updated_at' })
  updatedAt!: Date;
}
