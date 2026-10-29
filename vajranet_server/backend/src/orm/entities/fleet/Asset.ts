import { Entity, PrimaryColumn, Column, Index } from 'typeorm';

/**
 * A physical or virtual machine as Vajra believes it to exist, independent of
 * how it was observed. Agent-reported hosts (`nodes`), nmap sweeps
 * (`network_scan_history`), nuclei runs and live OpenVAS reports all resolve
 * into rows of this table, which is what finally ties "the machine at
 * 10.0.5.40 that OpenVAS scanned" to "the agent node DESKTOP-EXAMPLE".
 *
 * `asset_uuid` is RANDOM on first sight and never changes — it is deliberately
 * not derived or hashed from attributes, because scanners see only a subset of
 * a machine's attributes and IP/hostname change over time. Identity is instead
 * resolved by weighted matching over `asset_identities`; see
 * backend/src/utils/assetIdentity/resolveAsset.ts and the weights in
 * consts/assets.ts.
 *
 * Rows are NEVER deleted and observations are never re-pointed: a merge sets
 * the loser's `merged_into` to the winner, which keeps every merge reversible.
 */
@Entity('assets')
@Index('idx_assets_needs_review', ['needsReview'], { where: 'needs_review' })
@Index('idx_assets_owner_group', ['ownerGroupId'])
@Index('idx_assets_merged_into', ['mergedInto'])
@Index('idx_assets_last_seen', ['lastSeen'])
export class Asset {
  @PrimaryColumn({ type: 'uuid', name: 'asset_uuid', default: () => 'gen_random_uuid()' })
  assetUuid!: string;

  @Column({ type: 'timestamptz', name: 'first_seen', default: () => 'NOW()' })
  firstSeen!: Date;

  @Column({ type: 'timestamptz', name: 'last_seen', default: () => 'NOW()' })
  lastSeen!: Date;

  // Weight of the strongest identity anchor ever seen for this asset:
  // 100 bios_uuid, 80 mac, 40 hostname, 5 ip, 0 none. It only ever ratchets
  // upward, and the ip-only attach rule in the matcher must not raise it
  // above 5 — that is what stops a re-scanned subnet from looking
  // well-identified when all Vajra ever saw was a DHCP lease.
  @Column({ type: 'smallint', name: 'identity_confidence', default: 0 })
  identityConfidence!: number;

  // Set when the matcher attached on weak evidence (score below
  // ATTACH_THRESHOLD) or refused to choose between two near-equal candidates.
  // Surfaced as a filter in the Assets view for human confirmation.
  @Column({ type: 'boolean', name: 'needs_review', default: false })
  needsReview!: boolean;

  // Soft, reversible merge pointer to the surviving asset. Non-null means this
  // row is a duplicate that has been folded into another; its observations stay
  // attached to it so unmerging is a single UPDATE. Never a hard FK — the
  // pointed-at row is in this same table and a cycle must be repairable.
  @Column({ type: 'uuid', name: 'merged_into', nullable: true })
  mergedInto!: string | null;

  // Owning group, copied from nodes.owner_group_id when an agent observation
  // resolves here. Soft reference to nodes_groups.group_id (no FK — groups live
  // in a separate DataSource), same pattern as every other group-scoped fleet
  // table. NULL means "unassigned / discovered": an asset that only agentless
  // scanners have ever seen has no group, so a Group Admin will not see it
  // until it merges with an agent-backed asset. That is by design, not a bug.
  @Column({ type: 'varchar', length: 255, name: 'owner_group_id', nullable: true })
  ownerGroupId!: string | null;
}
