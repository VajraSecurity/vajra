import { Entity, PrimaryColumn, Column } from 'typeorm';
import type { ObservationSource } from '../../../types/assetIdentity';

/**
 * Per-feeder watermark for AssetResolutionService — one row per
 * ObservationSource, so a cron tick reads only rows a previous tick has not
 * already ingested instead of re-scanning 1,630 nmap scans every ten minutes.
 *
 * Deleting a row (or zeroing `last_source_id`) is the intended way to force a
 * full re-ingest: UNIQUE (source, source_ref) on asset_observations makes the
 * replay a no-op rather than a duplicate.
 *
 * @see backend/src/services/assetIdentity/assetResolutionService.ts
 */
@Entity('asset_feed_state')
export class AssetFeedState {
  @PrimaryColumn({ type: 'varchar', length: 32, name: 'source' })
  source!: ObservationSource;

  // Highest source-table id already ingested for this feeder (e.g.
  // network_scan_history.id). NULL means the feeder has never run. Feeders with
  // no monotonic source id — the agent feeder, which re-reads all 57 `nodes`
  // rows each tick, and the OpenVAS feeder, which is a full re-read on every
  // cron tick (services/assetIdentity/openvasFeeder.ts's pollOpenvasForAssets,
  // SPEC.md Addendum 3) as well as being driven eagerly by report views — leave
  // this NULL and use last_run_at only.
  @Column({ type: 'bigint', name: 'last_source_id', nullable: true })
  lastSourceId!: string | null;

  @Column({ type: 'timestamptz', name: 'last_run_at', nullable: true })
  lastRunAt!: Date | null;

  // Message from the most recent failed run, cleared on the next success.
  // Kept so a feeder that has been silently failing for days is visible in the
  // table rather than only in the log ring buffer.
  @Column({ type: 'text', name: 'last_error', nullable: true })
  lastError!: string | null;
}
