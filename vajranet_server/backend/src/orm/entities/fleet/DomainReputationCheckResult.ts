import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';
import type { DomainReputationTargetType } from './DomainReputationTarget';
import type { DomainReputationProviderName } from './DomainReputationProviderConfig';

export type DomainReputationVerdict = 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'error';
export type DomainReputationTrigger = 'manual' | 'schedule';

/** Append-only history of every check, from either tab, manual or scheduled. */
@Entity('domain_reputation_check_results')
@Index('idx_drcr_value_provider', ['value', 'provider'])
@Index('idx_drcr_target', ['target_id'])
@Index('idx_drcr_group', ['group_id'])
export class DomainReputationCheckResult {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'bigint', nullable: true })
  target_id!: number | null;

  /**
   * Group this result belongs to, stamped at insert time — from the resolved
   * write group in manualCheck, or the target's own groupId for a scheduled
   * run. target_id is NULL for every ad-hoc check, so there is no indirect
   * way to attribute a row to a group after the fact; it has to be recorded
   * here. NULL means an ungrouped check: the Vajra Reputation Engine
   * ('manual') provider, a Super Administrator's own check, or a row that
   * predates this column. See listHistory for how NULL is scoped on read.
   */
  @Column({ type: 'varchar', length: 255, nullable: true })
  group_id!: string | null;

  @Column({ type: 'varchar', length: 255, nullable: false })
  value!: string;

  @Column({ type: 'varchar', length: 10, nullable: false })
  type!: DomainReputationTargetType;

  @Column({ type: 'varchar', length: 32, nullable: false })
  provider!: DomainReputationProviderName;

  @Column({ type: 'varchar', length: 20, nullable: false })
  verdict!: DomainReputationVerdict;

  @Column({ type: 'numeric', nullable: true })
  score!: number | null;

  @Column({ type: 'text', nullable: true })
  summary!: string | null;

  @Column({ type: 'jsonb', nullable: true })
  raw_response!: any | null;

  @Column({ type: 'varchar', length: 10, nullable: false })
  triggered_by!: DomainReputationTrigger;

  @Column({ type: 'bigint', nullable: true })
  checked_by_user_id!: number | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  checked_by_name!: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at!: Date;
}
