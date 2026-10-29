import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { TOKEN_STATUS_ACTIVE, TokenStatus } from '../../../consts/database';

export type AgentCertProvisioningTokenStatus = TokenStatus;

/**
 * A one-time, host-bound provisioning token for the agent's mTLS client
 * certificate — NOT osquery's own enrollment (enroll_secret -> node_key
 * against the separate C++ fleet server). This backs only the certificate
 * the Go extension presents on its WebSocket connections to this backend.
 *
 * Only the SHA-256 hash of the bearer token is stored — same principle as an
 * API-key table — so a DB read alone never yields a usable credential.
 * host_identifier binds the token to exactly one identity at issuance; the
 * provisioning endpoint forces the issued certificate's CN to this value
 * regardless of what the agent's CSR claims, so a stolen token can only ever
 * mint a cert for the one host_identifier the admin authorized.
 */
@Entity('agent_cert_provisioning_tokens')
@Index(['tokenHash'], { unique: true })
@Index(['hostIdentifier'])
@Index(['status'])
export class AgentCertProvisioningToken {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'varchar', length: 64, unique: true, name: 'token_hash' })
  tokenHash!: string;

  @Column({ type: 'varchar', length: 255, name: 'host_identifier' })
  hostIdentifier!: string;

  @Column({ type: 'integer', name: 'issued_by_id' })
  issuedById!: number;

  @Column({ type: 'varchar', length: 255, name: 'issued_by_email' })
  issuedByEmail!: string;

  @Column({ type: 'varchar', length: 20, default: TOKEN_STATUS_ACTIVE })
  status!: AgentCertProvisioningTokenStatus;

  @CreateDateColumn({ type: 'timestamptz', name: 'issued_at' })
  issuedAt!: Date;

  @Column({ type: 'timestamptz', name: 'expires_at' })
  expiresAt!: Date;

  @Column({ type: 'timestamptz', nullable: true, name: 'used_at' })
  usedAt!: Date | null;

  @Column({ type: 'timestamptz', nullable: true, name: 'revoked_at' })
  revokedAt!: Date | null;

  @Column({ type: 'integer', nullable: true, name: 'revoked_by_id' })
  revokedById!: number | null;
}
