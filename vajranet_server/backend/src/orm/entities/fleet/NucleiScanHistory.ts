import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
} from 'typeorm';
import { SCAN_STATUS_PENDING } from '../../../consts/scanning';

@Entity('nuclei_scan_history')
@Index('idx_nuclei_created_by', ['created_by_user_id'])
@Index('idx_nuclei_status', ['status'])
@Index('idx_nuclei_created_at', ['created_at'])
export class NucleiScanHistory {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  @Column({ type: 'varchar', length: 50, default: SCAN_STATUS_PENDING })
  status!: string;

  @Column({ type: 'int', default: 0 })
  progress!: number;

  @Column({ type: 'text', nullable: false })
  target!: string;

  @Column({ type: 'varchar', length: 50, nullable: false })
  scanType!: string;

  @Column({ type: 'varchar', length: 500, nullable: false })
  reason!: string;

  @Column({ type: 'text', nullable: false })
  command!: string;

  @Column({ type: 'text', nullable: false, default: '' })
  rawOutput!: string;

  @Column({ type: 'jsonb', nullable: true })
  findings!: any[] | null;

  @Column({ type: 'jsonb', nullable: true })
  summary!: Record<string, any> | null;

  @Column({ type: 'int', nullable: true })
  pid!: number | null;

  @Column({ type: 'bigint', nullable: true })
  network_scan_id!: number | null;

  @Column({ type: 'bigint', nullable: true })
  created_by_user_id!: number | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  created_by_name!: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at!: Date;
}
