import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ENCRYPTED_FIELD_HEX_LENGTH } from '../../../consts/database';

@Entity('openvas_configs')
@Index('idx_openvas_config_active', ['isActive'])
@Index('idx_openvas_config_group', ['groupId'])
export class OpenVASConfig {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  // See NessusConfig.groupId for the full explanation — same soft-reference,
  // same null-means-Super-Admins-own-config, same partial unique index
  // pattern (idx_openvas_config_active_group_unique, in index.ts).
  @Column({ type: 'varchar', length: 255, name: 'group_id', nullable: true })
  groupId!: string | null;

  @Column({ type: 'varchar', length: 500, nullable: false })
  nessusUrl!: string;

  @Column({ type: 'varchar', length: 255, nullable: false })
  gmpUsername!: string;

  @Column({ type: 'text', nullable: false })
  gmpPasswordEncrypted!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  gmpPasswordIv!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  gmpPasswordAuthTag!: string;

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
