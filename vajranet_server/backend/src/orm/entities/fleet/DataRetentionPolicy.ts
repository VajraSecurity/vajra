import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn
} from 'typeorm';
import { DB_SOURCE_FLEET } from '../../../consts/database';

/** Cron pattern meaning "once a day, at midnight" — used as the daily-schedule default across scan/retention scheduling. */
export const CRON_DAILY_AT_MIDNIGHT = '0 0 * * *';

/** Default `cleanupTime` (HH:mm) for a retention policy when the caller doesn't supply one. */
export const DEFAULT_RETENTION_CLEANUP_TIME = '00:00';

@Entity('data_retention_policies')
export class DataRetentionPolicy {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ type: 'simple-array' })
    tableNames: string[];

    @Column({ type: 'varchar', length: 100, default: DB_SOURCE_FLEET })
    databaseName: string;

    // Matches the controller's own default and the column the osquery telemetry
    // tables actually carry; 'created_at' exists on almost none of them.
    @Column({ type: 'varchar', length: 100, default: 'unixtime' })
    timestampColumn: string;

    @Column({ type: 'varchar', length: 20, default: 'time' })
    retentionType: 'time' | 'row_count';

    @Column({ type: 'int', nullable: true })
    retentionDays: number | null; // 0 or null = keep forever

    @Column({ type: 'int', nullable: true })
    rowCountLimit: number | null; // null = keep forever

    @Column({ type: 'varchar', length: 20, default: 'daily' })
    scheduleType: 'daily' | 'weekly' | 'monthly' | 'custom';

    @Column({ type: 'varchar', length: 50, default: CRON_DAILY_AT_MIDNIGHT })
    cronExpression: string; // fallback cron

    @Column({ type: 'varchar', length: 5, default: DEFAULT_RETENTION_CLEANUP_TIME })
    cleanupTime: string; // HH:mm format (legacy/UI helper)

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;
}
