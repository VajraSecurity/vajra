import { Entity, PrimaryGeneratedColumn, Column, Index } from 'typeorm';
import type {
  MatchReason,
  ObservationSource,
  ObservedAttrs,
} from '../../../types/assetIdentity';

/**
 * One sighting of one host by one scan — the per-asset timeline behind the
 * Assets view, and the audit trail for every identity decision the matcher
 * made.
 *
 * `source_ref` is per-HOST, never per-scan ('nsh:1631:10.0.5.22',
 * 'ovas:<report-uuid>:10.0.5.40', 'agent:<host_identifier>'), and
 * UNIQUE (source, source_ref) is what makes a replayed feed a no-op: feeders
 * insert with ON CONFLICT DO NOTHING, so re-reading an nmap scan after a
 * watermark reset cannot duplicate rows.
 *
 * Rows are append-only. `asset_uuid` is never rewritten — not even by a merge,
 * which only sets assets.merged_into — so an observation always records which
 * asset the matcher chose at the time it ran, and any merge stays reversible.
 *
 * @see backend/src/services/assetIdentity/
 */
@Entity('asset_observations')
@Index('idx_asset_obs_source_ref', ['source', 'sourceRef'], { unique: true })
@Index('idx_asset_obs_asset_observed', ['assetUuid', 'observedAt'])
@Index('idx_asset_obs_source_observed', ['source', 'observedAt'])
export class AssetObservation {
  // node-postgres returns a bigint PK as a string despite the `number`
  // annotation — coerce with Number() before using it as a Map/Set key.
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id!: number;

  // Nullable because the matcher also records observations it declined to
  // resolve ('skipped_no_identities' / 'skipped_no_mint'): the reason those
  // were dropped is exactly what an operator asking "why is this host not in
  // Assets?" needs to see. Every other decision writes a real asset_uuid.
  @Column({ type: 'uuid', name: 'asset_uuid', nullable: true })
  assetUuid!: string | null;

  @Column({ type: 'varchar', length: 32, name: 'source' })
  source!: ObservationSource;

  @Column({ type: 'varchar', length: 512, name: 'source_ref' })
  sourceRef!: string;

  @Column({ type: 'timestamptz', name: 'observed_at', default: () => 'NOW()' })
  observedAt!: Date;

  // The raw, un-normalized attributes the feeder read from its source, kept so
  // a normalization bug can be re-run against the original input without
  // re-scanning the network.
  @Column({ type: 'jsonb', name: 'attrs', default: () => "'{}'::jsonb" })
  attrs!: ObservedAttrs;

  @Column({ type: 'smallint', name: 'match_score', default: 0 })
  matchScore!: number;

  // The full scoring explanation: decision, winner/runner-up scores, candidates
  // (capped at MATCH_REASON_MAX_CANDIDATES), vetoes, matched and dropped
  // identities. Capped at MATCH_REASON_MAX_BYTES before insert.
  @Column({ type: 'jsonb', name: 'match_reason', nullable: true })
  matchReason!: MatchReason | null;
}
