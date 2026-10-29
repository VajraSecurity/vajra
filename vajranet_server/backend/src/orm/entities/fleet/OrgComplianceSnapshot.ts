import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';

@Entity('historical_compliance')
@Index('idx_hc_snapshot_at', ['snapshotAt'])
export class OrgComplianceSnapshot {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'bigint', nullable: false })
  snapshotAt!: number;

  @Column({ type: 'int', nullable: true })
  totalNodes!: number | null;

  @Column({ type: 'int', nullable: true })
  windowsHosts!: number | null;

  @Column({ type: 'int', nullable: true })
  windowsWithResults!: number | null;

  @Column({ type: 'int', nullable: true })
  avgCompliancePercent!: number | null;

  @Column({ type: 'int', nullable: true })
  strongCount!: number | null;

  @Column({ type: 'int', nullable: true })
  moderateCount!: number | null;

  @Column({ type: 'int', nullable: true })
  needsAttentionCount!: number | null;

  @Column({ type: 'jsonb', nullable: false })
  controlPassRates!: Array<{
    key: string;
    label: string;
    passRatePct: number | null;
    passHosts: number;
    failHosts: number;
    eligibleHosts: number;
  }>;

  @Column({ type: 'jsonb', nullable: true, default: null })
  fullyCompliantNodesList!: string[] | null;

  @Column({ type: 'jsonb', nullable: true, default: null })
  nonCompliantNodesList!: Array<{
    host_identifier: string;
    failed_checks: string[];
  }> | null;

  @Column({ type: 'varchar', length: 20, nullable: false, default: 'live' })
  source!: string;

  // Group id(s) in scope for the caller who triggered this sweep. NULL means
  // fleet-wide/legacy (saved by an unrestricted/Super Admin caller, or before
  // this column existed) — visible only to unrestricted viewers, never to a
  // scoped Group Admin/Viewer. See utils/nodeScope.ts.
  @Column({ type: 'text', array: true, nullable: true, default: null, name: 'owner_group_ids' })
  ownerGroupIds!: string[] | null;
}
