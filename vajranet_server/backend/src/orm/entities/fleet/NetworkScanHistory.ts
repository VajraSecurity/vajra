import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';
import { SCAN_STATUS_PENDING } from '../../../consts/scanning';

/**
 * Persists user-initiated network scans (Nmap) and their output.
 * Lives in the secondary (fleet) database alongside nodes, alerts, etc.
 */
@Entity('network_scan_history')
@Index('idx_nsh_created_by', ['created_by_user_id'])
@Index('idx_nsh_status_created_at', ['status', 'created_at'])
@Index('idx_nsh_target', ['target'])
export class NetworkScanHistory {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'varchar', length: 50, default: SCAN_STATUS_PENDING })
  status!: string;

  @Column({ type: 'int', default: 0 })
  progress!: number;

  @Column({ type: 'text', default: '' })
  target!: string;

  @Column({ type: 'varchar', length: 50, default: '' })
  scanType!: string;

  @Column({ type: 'varchar', length: 500, default: '' })
  reason!: string;

  @Column({ type: 'text', default: '' })
  command!: string;

  @Column({ type: 'text', default: '' })
  output!: string;

  @Column({ type: 'int', nullable: true })
  pid!: number | null;

  @Column({ type: 'bigint', nullable: true })
  created_by_user_id!: number | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  created_by_name!: string | null;

  @Column({ type: 'jsonb', nullable: true })
  chart_data!: any | null;

  @Column({ type: 'bigint', nullable: true })
  parent_id!: number | null;

  @Column({ type: 'bigint', nullable: true })
  @Index('idx_nsh_schedule_id')
  schedule_id!: number | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at!: Date;
}
