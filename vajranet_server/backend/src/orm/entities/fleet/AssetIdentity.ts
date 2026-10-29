import { Entity, PrimaryColumn, Column, Index } from 'typeorm';
import type { IdentityKind } from '../../../types/assetIdentity';

/**
 * One normalized piece of evidence about an asset — a MAC, a BIOS UUID, a
 * hostname, an OS family, an IP. This is the matcher's entire working set.
 *
 * Identities are MULTI-VALUED and ACCUMULATE: a host with four NICs owns four
 * `mac` rows, and a changed IP adds a row rather than overwriting one, so
 * `last_seen` per value doubles as that value's history (which IP this machine
 * held, and when). Nothing here is ever overwritten in place except
 * `last_seen`.
 *
 * `value_norm` is post-normalization only (lowercase colon-form MAC, uppercase
 * BIOS UUID, suffix-stripped lowercase hostname, os family, IP) — raw values
 * that the normalizer rejected never reach this table; they are recorded as
 * DroppedIdentity entries in asset_observations.match_reason so a match stays
 * auditable.
 *
 * @see backend/src/utils/assetIdentity/normalize.ts
 */
@Entity('asset_identities')
// THIS index is the matcher: resolveAsset() issues exactly one indexed lookup
// per observation, `WHERE (kind, value_norm) IN (...)`. Without it the matcher
// sequential-scans the identity table once per observation.
@Index('idx_asset_identities_kind_value', ['kind', 'valueNorm'])
// Concurrency backstop. Two feeders resolving the same machine at once can both
// miss in the candidate query and both mint an asset; this makes the second
// insert fail loudly instead of silently creating a duplicate. Restricted to
// the two globally-unique kinds — a hostname, os family or IP is legitimately
// shared by many assets.
@Index('idx_asset_identities_strong_unique', ['kind', 'valueNorm'], {
  unique: true,
  where: "kind IN ('bios_uuid', 'mac')",
})
export class AssetIdentity {
  @PrimaryColumn({ type: 'uuid', name: 'asset_uuid' })
  assetUuid!: string;

  @PrimaryColumn({ type: 'varchar', length: 32, name: 'kind' })
  kind!: IdentityKind;

  @PrimaryColumn({ type: 'varchar', length: 255, name: 'value_norm' })
  valueNorm!: string;

  // Denormalized copy of IDENTITY_WEIGHTS[kind] at insert time, so a scoring
  // decision recorded in match_reason can still be explained after the weights
  // in consts/assets.ts are retuned.
  @Column({ type: 'smallint', name: 'weight', default: 0 })
  weight!: number;

  @Column({ type: 'timestamptz', name: 'first_seen', default: () => 'NOW()' })
  firstSeen!: Date;

  @Column({ type: 'timestamptz', name: 'last_seen', default: () => 'NOW()' })
  lastSeen!: Date;
}
