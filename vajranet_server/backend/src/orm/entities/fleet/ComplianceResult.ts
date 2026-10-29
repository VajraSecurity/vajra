import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';

/**
 * Stores the result of each compliance check run against a node.
 * Lives in the secondary (fleet) database alongside nodes, alerts, etc.
 *
 * Schema:
 *   id              — auto-increment PK
 *   host_identifier — the node's unique identifier (matches nodes.host_identifier)
 *   unixtime        — unix epoch (seconds) when the compliance check was recorded
 *   compliance_data — raw JSON array of { command_key, output } objects from the agent
 */
@Entity('compliance_results')
@Index('idx_cr_host', ['host_identifier'])
@Index('idx_cr_host_unixtime', ['host_identifier', 'unixtime'])
export class ComplianceResult {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'varchar', nullable: false })
  host_identifier!: string;

  @Column({ type: 'bigint', nullable: false })
  unixtime!: number;

  @Column({ type: 'jsonb', nullable: false })
  compliance_data!: Array<{ command_key: string; output: string }>;
}
