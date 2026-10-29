import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ENCRYPTED_FIELD_HEX_LENGTH } from '../../../consts/database';

@Entity('burpsuite_configs')
@Index('idx_burpsuite_config_active', ['isActive'])
@Index('idx_burpsuite_config_group', ['groupId'])
export class BurpsuiteConfig {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  // See NessusConfig.groupId for the full explanation — same soft-reference,
  // same null-means-Super-Admins-own-config, same partial unique index
  // pattern (idx_burpsuite_config_active_group_unique, in index.ts).
  @Column({ type: 'varchar', length: 255, name: 'group_id', nullable: true })
  groupId!: string | null;

  @Column({ name: 'api_url', type: 'varchar', length: 500, nullable: false })
  apiUrl!: string;

  @Column({ type: 'text', nullable: false })
  apiKeyEncrypted!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  apiKeyIv!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  apiKeyAuthTag!: string;

  @Column({ type: 'varchar', length: 16, nullable: true })
  apiKeySuffix!: string | null;

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
