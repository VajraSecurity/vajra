import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ENCRYPTED_FIELD_HEX_LENGTH } from '../../../consts/database';

export type DomainReputationProviderName = 'manual' | 'virustotal' | 'abuseipdb';
export type DomainReputationAuthMode = 'none' | 'header' | 'bearer';

@Entity('domain_reputation_provider_configs')
@Index('idx_drpc_provider_group', ['provider', 'groupId'])
export class DomainReputationProviderConfig {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'varchar', length: 32, nullable: false })
  provider!: DomainReputationProviderName;

  // Soft reference to nodes_groups.group_id / user_group_memberships.group_id.
  // NULL = the org-wide default (Super Admin's own scope). Always NULL for
  // provider === 'manual', which has no group scoping at all; only ever set
  // for 'virustotal'/'abuseipdb' rows. See providerConfigController.ts.
  // A true "one active row per (provider, group)" uniqueness constraint is
  // enforced by migration 014's partial unique index — not expressible via
  // a TypeORM decorator (it needs COALESCE), so it isn't declared here.
  @Column({ type: 'varchar', length: 255, nullable: true, name: 'group_id' })
  groupId!: string | null;

  // Only used by 'manual' — VirusTotal/AbuseIPDB call fixed public base URLs.
  @Column({ type: 'varchar', length: 500, nullable: true })
  baseUrl!: string | null;

  // Only used by 'manual', whose auth scheme isn't finalized yet.
  @Column({ type: 'varchar', length: 16, default: 'bearer' })
  authMode!: DomainReputationAuthMode;

  // Only used by 'manual' when authMode = 'header'.
  @Column({ type: 'varchar', length: 100, default: 'X-API-Key' })
  authHeaderName!: string;

  @Column({ type: 'text', nullable: true })
  apiKeyEncrypted!: string | null;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: true })
  apiKeyIv!: string | null;

  @Column({ type: 'varchar', length: ENCRYPTED_FIELD_HEX_LENGTH, nullable: true })
  apiKeyAuthTag!: string | null;

  @Column({ type: 'varchar', length: 8, default: '' })
  apiKeySuffix!: string;

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
