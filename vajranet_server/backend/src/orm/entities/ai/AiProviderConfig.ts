import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ENCRYPTED_FIELD_HEX_LENGTH } from '../../../consts/database';

export type AiProvider = 'anthropic' | 'openai';

@Entity('ai_provider_configs')
@Index('idx_ai_provider_config_active', ['isActive'])
export class AiProviderConfig {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'varchar', length: 20, nullable: false })
  provider!: AiProvider;

  @Column({ type: 'text', nullable: false })
  apiKeyEncrypted!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  apiKeyIv!: string;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: false })
  apiKeyAuthTag!: string;

  @Column({ type: 'varchar', length: 8, default: '' })
  apiKeySuffix!: string;

  @Column({ type: 'varchar', length: 100, nullable: true })
  model!: string | null;

  @Column({ type: 'varchar', length: 500, nullable: true })
  baseUrl!: string | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  organization!: string | null;

  @Column({ type: 'integer', nullable: true })
  maxOutputTokens!: number | null;

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
