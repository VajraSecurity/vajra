import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Persists user-created threat hunting queries.
 * Lives in the secondary (fleet) database alongside nodes, alerts, etc.
 */
@Entity('saved_queries')
@Index('idx_sq_created_by', ['created_by_user_id'])
@Index('idx_sq_platform', ['platform'])
export class SavedQuery {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'varchar', length: 255, nullable: false })
  name!: string;

  @Column({ type: 'text', nullable: true })
  description!: string | null;

  @Column({ type: 'text', nullable: false })
  query!: string;

  @Column({ type: 'varchar', length: 50, default: 'all', nullable: false })
  platform!: string;

  @Column({ type: 'varchar', length: 20, default: 'both', nullable: false })
  node_state!: 'historic' | 'live' | 'both';

  @Column({ type: 'text', array: true, default: () => 'ARRAY[]::text[]', nullable: false })
  defense_kit!: string[];

  @Column({ type: 'text', array: true, default: () => 'ARRAY[]::text[]', nullable: false })
  detection_subtypes!: string[];

  @Column({ type: 'bigint', nullable: true })
  created_by_user_id!: number | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  created_by_name!: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at!: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at!: Date;
}
