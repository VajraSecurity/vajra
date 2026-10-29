import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
  Unique,
} from 'typeorm';

@Entity('policies')
@Index('idx_policies_type', ['type'])
@Index('idx_policies_enabled', ['enabled'])
@Unique('uq_policies_name', ['name'])
export class Policy {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'varchar', length: 255 })
  name!: string;

  /** 'network' | 'device-control' | 'compliance' | 'custom' */
  @Column({ type: 'varchar', length: 50 })
  type!: string;

  @Column({ type: 'text', nullable: true })
  description!: string | null;

  @Column({ type: 'boolean', default: true })
  enabled!: boolean;

  @Column({ type: 'text', array: true, default: () => "'{}'::text[]" })
  platforms!: string[];

  /** Stores portRules / ipRules / usb / bluetooth / complianceChecks / customQuery */
  @Column({ type: 'jsonb', default: () => "'{}'::jsonb" })
  config!: Record<string, unknown>;

  /** 'all' | 'nodes' | 'groups' */
  @Column({ type: 'varchar', length: 20, default: 'all' })
  target_mode!: string;

  @Column({ type: 'text', array: true, default: () => "'{}'::text[]" })
  target_node_ids!: string[];

  // Targets by nodes_groups.group_id (unique), not by display name — a
  // group's `name` has no uniqueness constraint, so name-based targeting
  // was ambiguous when two groups shared a name. See
  // backend/src/migrations/add_policy_target_group_ids.sql.
  @Column({ type: 'text', array: true, default: () => "'{}'::text[]" })
  target_group_ids!: string[];

  @Column({ type: 'varchar', length: 255, nullable: true })
  created_by!: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at!: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at!: Date;
}
