/**
 * Asset identity resolution — read API.
 *
 * Backed by backend/src/controllers/assets/ (routes/api/assets.ts). The router
 * is gated `[checkJwt, requireAdmin]`, i.e. Super Administrator or Group Admin;
 * unlike /network there is no requireOnPrem, so these endpoints work in a cloud
 * deployment too.
 *
 * The types below hand-mirror backend/src/types/assetIdentity.ts — that file is
 * the written contract, and the two must stay in step. Field names are
 * snake_case because the backend projects them straight out of SQL.
 */

import api from '../axiosInstance';

export type IdentityKind =
  | 'bios_uuid'      // 100 — hardware SMBIOS uuid, the strongest anchor
  | 'mac'            // 80
  | 'hostname'       // 40
  | 'os'             // 10
  | 'ip'             // 5
  | 'osquery_uuid';  // 0 — evidence only, never scored

export type ObservationSource = 'agent' | 'nmap' | 'openvas' | 'nuclei' | 'arp';
export type OsFamily = 'windows' | 'linux' | 'other';

/**
 * A scan's findings for one host, bucketed by the same 4-tier scheme already
 * used everywhere else OpenVAS results are shown in this app
 * (VulnerabilityScanner/OpenVASScanDetail.tsx's `getSeverityLevel`): CVSS
 * >= 7.0 high, >= 4.0 medium, > 0 low, else log. Captured once per
 * observation on the backend (2026-09-08) so a per-asset severity-over-time
 * graph does not need to re-fetch every historical report — observations
 * from before that change have no `severityCounts` (backfilled lazily; see
 * backend/src/controllers/assets/getAssetObservations.ts), so this is always
 * optional, never assume it is present.
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

/** Raw, un-normalized attributes as a feeder read them from its source. */
export interface ObservedAttrs {
  biosUuid?: string | null;
  osqueryUuid?: string | null;
  macs?: string[];
  hostname?: string | null;
  os?: string | null;
  ips?: string[];
  extra?: ObservedAttrsExtra;
}

export type DropReason =
  | 'zero_mac' | 'broadcast_mac' | 'locally_administered_mac' | 'malformed_mac'
  | 'zero_bios_uuid' | 'junk_bios_uuid' | 'malformed_bios_uuid'
  | 'generic_hostname' | 'empty_hostname'
  | 'loopback_ip' | 'link_local_ip' | 'malformed_ip'
  | 'unrecognized_os';

export interface NormalizedIdentity { kind: IdentityKind; value: string; weight: number }
export interface DroppedIdentity { kind: IdentityKind; raw: string; reason: DropReason }

export type VetoReason = 'bios_uuid_conflict' | 'mac_conflict' | 'os_family_conflict' | 'ambiguous_candidates';

export interface CandidateScore {
  assetUuid: string;
  score: number;
  matched: NormalizedIdentity[];
  /** Empty means the candidate was eligible to win. */
  vetoedBy: VetoReason[];
}

export type ResolveDecision =
  | 'attached' | 'attached_needs_review' | 'new_asset' | 'ambiguous_new_asset'
  | 'skipped_no_identities' | 'skipped_no_mint';

/** Persisted verbatim into asset_observations.match_reason (jsonb). */
export interface MatchReason {
  decision: ResolveDecision;
  winnerScore: number;
  runnerUpScore: number | null;
  candidates: CandidateScore[];
  vetoes: VetoReason[];
  matched: NormalizedIdentity[];
  dropped: DroppedIdentity[];
}

export interface AssetListItem {
  asset_uuid: string;
  /** Best hostname identity, most recent. Null for a host only ever seen by IP. */
  hostname: string | null;
  ips: string[];
  macs: string[];
  os_family: string | null;
  /** 100 bios_uuid | 80 mac | 40 hostname | 5 ip | 0 none — see ui.tsx. */
  identity_confidence: number;
  needs_review: boolean;
  sources: ObservationSource[];
  observation_count: number;
  first_seen: string;
  last_seen: string;
  /**
   * Null means no agent has ever claimed this host — only a scanner saw it.
   * Such rows are visible to Super Administrators only and must be labelled
   * "Unassigned / discovered" rather than rendered as a missing value.
   */
  owner_group_id: string | null;
  /** Set when this asset was soft-merged into another; the list hides these unless include_merged. */
  merged_into: string | null;
}

export interface AssetIdentityRow {
  kind: IdentityKind;
  value_norm: string;
  weight: number;
  first_seen: string;
  last_seen: string;
}

export interface AssetDetail {
  asset: AssetListItem;
  identities: AssetIdentityRow[];
}

export interface AssetObservation {
  /** bigserial, kept as a string so a large id cannot lose precision. */
  id: string;
  source: ObservationSource;
  source_ref: string | null;
  observed_at: string;
  attrs: ObservedAttrs;
  match_score: number;
  /**
   * asset_observations.match_reason is a nullable jsonb column (the matcher can
   * write an audit row without one), so this is typed nullable here even though
   * the backend DTO casts it — every consumer must tolerate null.
   */
  match_reason: MatchReason | null;
}

/** Paginated envelope shared by the list and observation endpoints. */
export interface AssetPageResponse<T> {
  success: boolean;
  total: number;
  count: number;
  page: number;
  rows: number;
  data: T[];
}

export interface AssetListParams {
  rows?: number;
  pageno?: number;
  /** true also returns assets that were soft-merged into another; the default is merged_into IS NULL. */
  include_merged?: boolean;
}

export const getAssets = async (
  params: AssetListParams = {},
  signal?: AbortSignal,
): Promise<AssetPageResponse<AssetListItem>> => {
  const response = await api.get('/assets', {
    signal,
    params: {
      rows: params.rows,
      pageno: params.pageno,
      // The backend reads this as the literal string 'true'; omit it
      // entirely when off so the query string stays clean.
      include_merged: params.include_merged ? 'true' : undefined,
    },
  });
  return response.data;
};

export const getAsset = async (
  assetUuid: string,
  signal?: AbortSignal,
): Promise<{ success: boolean; data: AssetDetail }> => {
  const response = await api.get(`/assets/${encodeURIComponent(assetUuid)}`, { signal });
  return response.data;
};

export const getAssetObservations = async (
  assetUuid: string,
  params: { rows?: number; pageno?: number } = {},
  signal?: AbortSignal,
): Promise<AssetPageResponse<AssetObservation>> => {
  const response = await api.get(`/assets/${encodeURIComponent(assetUuid)}/observations`, {
    signal,
    params: { rows: params.rows, pageno: params.pageno },
  });
  return response.data;
};
