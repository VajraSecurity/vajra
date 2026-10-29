import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

export type DomainReputationTargetType = 'domain' | 'ip';

/**
 * The Threat Intel tab's scheduled watchlist (VirusTotal/AbuseIPDB only —
 * the manual server's Manual Check tab has no scheduling).
 */
@Entity('domain_reputation_targets')
@Index('idx_drt_active', ['isActive'])
@Index('idx_drt_group', ['groupId'])
export class DomainReputationTarget {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  // Soft reference to nodes_groups.group_id / user_group_memberships.group_id.
  // NULL = an org-wide watchlist entry: visible read-only to every Group
  // Admin, but only Super Administrator may create/edit/delete/run it. See
  // targetsController.ts and DomainReputationSchedulerService.runCheck.
  @Column({ type: 'varchar', length: 255, nullable: true, name: 'group_id' })
  groupId!: string | null;

  @Column({ type: 'varchar', length: 255, nullable: false })
  value!: string;

  @Column({ type: 'varchar', length: 10, nullable: false })
  type!: DomainReputationTargetType;

  // Subset of ['virustotal', 'abuseipdb'].
  @Column({ type: 'jsonb', nullable: false })
  providers!: string[];

  @Column({ type: 'varchar', length: 100, nullable: false })
  cronExpression!: string;

  @Column({ type: 'boolean', default: true })
  isActive!: boolean;

  @Column({ type: 'varchar', length: 20, nullable: true })
  lastVerdict!: string | null;

  @Column({ type: 'timestamptz', nullable: true })
  lastCheckedAt!: Date | null;

  @Column({ type: 'bigint', nullable: true })
  created_by_user_id!: number | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  created_by_name!: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at!: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at!: Date;
}
