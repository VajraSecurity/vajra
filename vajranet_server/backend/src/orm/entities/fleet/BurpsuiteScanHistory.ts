import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Index,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('burpsuite_scan_history')
@Index('idx_burpsuite_history_group', ['groupId'])
@Index('idx_burpsuite_history_normalized_target', ['normalizedTarget'])
export class BurpsuiteScanHistory {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  // Which scope launched this scan — the group the caller was acting as at
  // launch time (via burpsuiteController's resolveScannerGroupContext), or
  // null for the Super Administrator's own scope. Unlike Nessus/OpenVAS
  // (which proxy live to a remote server and have no local scan storage),
  // Burp Suite scan results ARE cached locally here, so this is the only one
  // of the three scanners where a Super Admin's "see everyone's results" view
  // is a genuine merged list rather than a per-group context switch.
  @Column({ type: 'varchar', length: 255, name: 'group_id', nullable: true })
  groupId!: string | null;

  @Column({ type: 'varchar', length: 255, nullable: false })
  taskId!: string;

  @Column({ type: 'varchar', length: 500, nullable: false })
  target!: string;

  // Computed at insert time by controllers/burpsuiteAssets/normalizedTarget.ts
  // (normalizeBurpTarget from utils/urlIdentity.ts) -- host[:port] only, no
  // scheme/www./path/query, e.g. "example.com" or "example.com:8080". Backs
  // the Burp Suite Assets feature's SQL-side GROUP BY (see
  // controllers/burpsuiteAssets/listBurpsuiteAssets.ts): the aggregation used
  // to pull every scoped row into Node and group there, which does not scale;
  // this column lets Postgres do the grouping/pagination itself. Nullable
  // because a target that fails to parse (see normalizeBurpTarget's own
  // defensive null case) is legitimately un-groupable and excluded from the
  // Assets view entirely, same behavior as before this column existed.
  @Column({ type: 'varchar', length: 255, name: 'normalized_target', nullable: true })
  normalizedTarget!: string | null;

  @Column({ type: 'varchar', length: 50, nullable: false, default: 'running' })
  status!: string;

  @Column({ type: 'int', default: 0 })
  issuesTotal!: number;

  @Column({ type: 'int', default: 0 })
  issuesHigh!: number;

  @Column({ type: 'int', default: 0 })
  issuesMedium!: number;

  @Column({ type: 'int', default: 0 })
  issuesLow!: number;

  // Cached copy of the Burp `issue_events` / `scan_metrics` payloads so scan
  // results remain viewable after the task ages out of Burp's own history.
  @Column({ type: 'text', nullable: true })
  resultsJson!: string | null;

  @Column({ type: 'text', nullable: true })
  metricsJson!: string | null;

  @CreateDateColumn({ type: 'timestamptz' })
  created_at!: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updated_at!: Date;
}
