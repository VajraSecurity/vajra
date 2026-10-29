import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  Index,
  Unique,
} from 'typeorm';

/**
 * Per-host/per-manager snapshot-replace table (same shape as
 * packages_snapshot), populated from a completed "check" operation's
 * available_packages list — see websocket/node.ts's osupdate_result
 * handling. Backs the wizard's per-host "review available updates" step and
 * the fleet-wide "most common pending updates" summary
 * (GET /api/patch/available).
 */
@Entity('patch_available_updates')
@Index(['hostIdentifier'])
@Unique(['hostIdentifier', 'manager', 'name'])
export class PatchAvailableUpdate {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'text', name: 'host_identifier' })
  hostIdentifier!: string;

  @Column({ type: 'text' })
  manager!: string;

  @Column({ type: 'text' })
  name!: string;

  @Column({ type: 'text', nullable: true, name: 'installed_version' })
  installedVersion!: string | null;

  @Column({ type: 'text', name: 'available_version' })
  availableVersion!: string;

  @Column({ type: 'timestamptz', name: 'updated_at' })
  updatedAt!: Date;
}
