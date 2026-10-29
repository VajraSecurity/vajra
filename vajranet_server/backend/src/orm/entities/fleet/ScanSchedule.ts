import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { SCAN_SCHEDULE_FREQUENCY_PRESETS } from '../../../consts/scanning';

/**
 * A recurring nmap discovery scan of a single /16 subnet. On each cron tick,
 * ScanSchedulerService re-scans `target`, and any IP with no matching `nodes`/
 * `interface_addresses` row (i.e. no Vajra agent) gets an automatic advanced
 * scan plus an `alerts` row — see backend/src/services/scanSchedulerService.ts.
 */
@Entity('scan_schedules')
@Index('idx_scan_schedules_group', ['groupId'])
export class ScanSchedule {
  @PrimaryGeneratedColumn()
  id: number;

  // Owning group (soft reference to nodes_groups.group_id, see nodeScope.ts) —
  // null means a Super Administrator created this schedule outside any group
  // ("fleet-wide", visible only to Super Admins). A Group Admin's schedules
  // always carry their group's id; scoped via backend/src/utils/scannerScope.ts.
  @Column({ type: 'varchar', length: 255, name: 'group_id', nullable: true })
  groupId: string | null;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'boolean', default: true })
  enabled: boolean;

  @Column({ type: 'varchar', length: 20 })
  target: string; // single /16 CIDR, e.g. "10.0.0.0/16"

  @Column({ type: 'varchar', length: 20, name: 'frequency_preset' })
  frequencyPreset: typeof SCAN_SCHEDULE_FREQUENCY_PRESETS[number];

  @Column({ type: 'varchar', length: 100, name: 'cron_expression' })
  cronExpression: string;

  @Column({ type: 'varchar', length: 500, default: '' })
  reason: string;

  // IPs the user has explicitly marked as known-but-unmanageable (e.g. a
  // router/printer that can never run the Vajra agent) — excluded from
  // "unmanaged host" detection for this schedule, every run, permanently.
  @Column({ type: 'jsonb', name: 'known_ips', default: () => "'[]'" })
  knownIps: string[];

  @Column({ type: 'int', name: 'created_by_user_id', nullable: true })
  createdByUserId: number | null;

  @Column({ type: 'varchar', length: 255, name: 'created_by_name', nullable: true })
  createdByName: string | null;

  @Column({ type: 'timestamptz', name: 'last_run_at', nullable: true })
  lastRunAt: Date | null;

  @Column({ type: 'varchar', length: 20, name: 'last_run_status', nullable: true })
  lastRunStatus: 'running' | 'success' | 'failed' | null;

  @Column({ type: 'bigint', name: 'last_run_history_id', nullable: true })
  lastRunHistoryId: number | null;

  @Column({ type: 'int', name: 'last_new_ip_count', nullable: true })
  lastNewIpCount: number | null;

  // How many unmanaged IPs were still waiting (past MAX_ADVANCED_SCANS_PER_RUN)
  // when this run ended — surfaces the truncation instead of hiding it.
  @Column({ type: 'int', name: 'last_pending_ip_count', nullable: true })
  lastPendingIpCount: number | null;

  // How many IPs matched a registered device that is currently offline (its
  // agent isn't connected/recently seen) — a possible DHCP IP-reuse case
  // rather than a brand-new host, see ScanSchedulerService.
  @Column({ type: 'int', name: 'last_reused_ip_count', nullable: true })
  lastReusedIpCount: number | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
