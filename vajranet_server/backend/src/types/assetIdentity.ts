/**
 * Shared contract for asset identity resolution.
 *
 * Identity is resolved by WEIGHTED MATCHING, never by hashing attributes into
 * an id: scanners see only a subset of attributes (an unauthenticated scanner
 * cannot read SMBIOS) and IP/hostname change over time. Every asset therefore
 * gets a RANDOM uuid on first sight which never changes, and observations are
 * scored against the identities already recorded for existing assets.
 *
 * The normalizer/matcher (backend/src/utils/assetIdentity/), the feeders
 * (backend/src/services/assetIdentity/) and the read API
 * (backend/src/controllers/assets/) all import these types and must not
 * redefine them.
 */

export type IdentityKind =
  | 'bios_uuid'      // 100
  | 'mac'            // 80
  | 'hostname'       // 40
  | 'os'             // 10
  | 'ip'             // 5
  | 'osquery_uuid';  // 0 — stored as evidence only, never scored.
                     // nodes.host_identifier on the 36 Linux agents is
                     // osquery-generated, NOT hardware. Never a bios_uuid.

export type ObservationSource = 'agent' | 'nmap' | 'openvas' | 'nuclei' | 'arp';
export type OsFamily = 'windows' | 'linux' | 'other';

/** Raw, un-normalized attributes as a feeder read them from its source. */
/**
 * A scan's vulnerability findings for one host, bucketed by the same 4-tier
 * scheme already used everywhere else OpenVAS results are shown in this app
 * (controllers/openvas/openvasController.ts's `getReport`,
 * VulnerabilityScanner/OpenVASScanDetail.tsx's `getSeverityLevel`): CVSS
 * >= 7.0 high, >= 4.0 medium, > 0 low, else log. Captured once per
 * observation (services/assetIdentity/openvasFeeder.ts) so a per-asset
 * severity-over-time graph does not need to re-fetch every historical report.
 */
export interface SeverityCounts {
  high: number;
  medium: number;
  low: number;
  log: number;
}

export interface ObservedAttrsExtra {
  reportId?: string;
  scanStart?: string | null;
  scanEnd?: string | null;
  severityCounts?: SeverityCounts;
  openvasMachineId?: string;
  [key: string]: unknown;
}

export interface ObservedAttrs {
  biosUuid?: string | null;
  osqueryUuid?: string | null;
  macs?: string[];
  hostname?: string | null;
  os?: string | null;      // raw, e.g. "Microsoft Windows 11 Pro"
  ips?: string[];
  /** Free-form extras persisted into asset_observations.attrs; never scored. */
  extra?: ObservedAttrsExtra;
}

export type DropReason =
  | 'zero_mac' | 'broadcast_mac' | 'locally_administered_mac' | 'malformed_mac'
  | 'zero_bios_uuid' | 'junk_bios_uuid' | 'malformed_bios_uuid'
  | 'generic_hostname' | 'empty_hostname'
  | 'loopback_ip' | 'link_local_ip' | 'malformed_ip'
  | 'unrecognized_os';

export interface NormalizedIdentity { kind: IdentityKind; value: string; weight: number; }
export interface DroppedIdentity { kind: IdentityKind; raw: string; reason: DropReason; }

export interface NormalizedObservation {
  identities: NormalizedIdentity[];
  biosUuid: string | null;   // hoisted for veto rules
  macs: string[];
  osFamily: OsFamily | null;
  dropped: DroppedIdentity[];
  maxPossibleScore: number;
}

export interface Observation {
  source: ObservationSource;
  /** Per-HOST and stable: 'nsh:1631:10.0.5.22', 'ovas:<report-uuid>:10.0.5.40',
   *  'agent:<host_identifier>'. Backs UNIQUE (source, source_ref). */
  sourceRef: string;
  observedAt: Date;
  attrs: ObservedAttrs;
  /** nodes.owner_group_id for agent obs; null for agentless. */
  ownerGroupId?: string | null;
  /** false for low-information sources that must never create an asset (nuclei).
   *  Default true. */
  mintIfNoMatch?: boolean;
}

export type VetoReason = 'bios_uuid_conflict' | 'mac_conflict' | 'os_family_conflict' | 'ambiguous_candidates';

export interface CandidateScore {
  assetUuid: string; score: number;
  matched: NormalizedIdentity[];
  vetoedBy: VetoReason[];   // empty = eligible
}

export type ResolveDecision =
  | 'attached' | 'attached_needs_review' | 'new_asset' | 'ambiguous_new_asset'
  | 'skipped_no_identities' | 'skipped_no_mint';

/** Persisted verbatim into asset_observations.match_reason (jsonb). */
export interface MatchReason {
  decision: ResolveDecision;
  winnerScore: number;
  runnerUpScore: number | null;
  candidates: CandidateScore[];   // cap at top 5 before persisting
  vetoes: VetoReason[];
  matched: NormalizedIdentity[];
  dropped: DroppedIdentity[];
}

export interface ResolveResult {
  assetUuid: string | null;      // null only for the two 'skipped_*' decisions
  score: number;
  created: boolean;
  needsReview: boolean;
  identityConfidence: number;    // 100 | 80 | 40 | 5 | 0
  decision: ResolveDecision;
  reason: MatchReason;
  observationId: string | null;  // bigserial as string
}

/**
 * Read-API DTOs. Chunk 3 (backend/src/controllers/assets/) returns these;
 * chunk 5 (frontend/src/api/services/assetsApi.ts) mirrors them. Field names
 * are snake_case because they are projected straight out of SQL, matching the
 * convention of every other list endpoint in this codebase.
 */
export interface AssetListItemDto {
  asset_uuid: string;
  hostname: string | null;      // best hostname identity, most recent
  ips: string[];                // ip identities, last_seen DESC, cap 5
  macs: string[];
  os_family: string | null;
  identity_confidence: number;
  needs_review: boolean;
  sources: ObservationSource[]; // distinct sources seen
  observation_count: number;
  first_seen: string; last_seen: string;
  owner_group_id: string | null;
  merged_into: string | null;
}

export interface AssetIdentityDto {
  kind: IdentityKind; value_norm: string; weight: number;
  first_seen: string; last_seen: string;
}

export interface AssetDetailDto { asset: AssetListItemDto; identities: AssetIdentityDto[]; }

export interface AssetObservationDto {
  id: string; source: ObservationSource; source_ref: string | null;
  observed_at: string; attrs: ObservedAttrs;
  match_score: number; match_reason: MatchReason;
}
