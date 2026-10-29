import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ENCRYPTED_FIELD_HEX_LENGTH } from '../../../consts/database';

@Entity('nessus_configs')
@Index('idx_nessus_config_active', ['isActive'])
@Index('idx_nessus_config_group', ['groupId'])
export class NessusConfig {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  // Soft reference to the fleet DB's nodes_groups.group_id, same pattern as
  // UserGroupMembership/nodes.owner_group_id (see backend/src/utils/nodeScope.ts) —
  // null means this is the Super Administrator's own config, not tied to any
  // group. Enforced to have at most one active row per group (including the
  // null/"Super Admin's own" bucket) by idx_nessus_config_active_group_unique,
  // a partial unique index on COALESCE(group_id, '') WHERE is_active — see the
  // bootstrap block in index.ts, since TypeORM's @Index can't express a
  // COALESCE expression index directly.
  @Column({ type: 'varchar', length: 255, name: 'group_id', nullable: true })
  groupId!: string | null;

  @Column({ type: 'varchar', length: 500, nullable: false })
  nessusUrl!: string;

  @Column({ type: 'text', nullable: false })
  accessKeyEncrypted!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  accessKeyIv!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  accessKeyAuthTag!: string;

  @Column({ type: 'text', nullable: false })
  secretKeyEncrypted!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  secretKeyIv!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  secretKeyAuthTag!: string;

  @Column({ type: 'varchar', length: 8, default: '' })
  accessKeySuffix!: string;

  @Column({ type: 'varchar', length: 8, default: '' })
  secretKeySuffix!: string;

  @Column({ type: 'boolean', default: true })
  isActive!: boolean;

  @Column({ type: 'bigint', nullable: true })
  created_by_user_id!: number | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  created_by_name!: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at!: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at!: Date;
}
