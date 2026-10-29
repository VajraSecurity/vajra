/**
 * Burp Suite Assets — read API.
 *
 * A sibling of api/services/assetsApi.ts (OpenVAS's cross-source identity
 * resolution), not a copy of it: Burp Suite has no identity-confidence
 * scoring, no merge concept and nothing to reconcile across scanners — a
 * "Burp asset" is just the distinct websites Burp Suite scans have targeted,
 * grouped by normalized host[:port], each with its own scan history and
 * current High/Medium/Low/Total issue counts.
 *
 * Backed by the already-mounted, already-verified `/api/burpsuite/assets`
 * router — same auth (cookie session + CSRF) as every other Burp Suite
 * endpoint, handled for free by the shared axios instance below. Field names
 * on the wire are snake_case because the backend projects them straight out
 * of SQL, same convention assetsApi.ts uses for its own DTOs.
 */

import api from '../axiosInstance';

export interface BurpsuiteAssetListItem {
  /** Grouping key, e.g. "example.com" or "example.com:8080". */
  normalized_target: string;
  /** Same value as normalized_target today — kept distinct in the DTO in
   *  case the two ever diverge, so callers don't need to change later. */
  display_host: string;
  scan_count: number;
  /** Burp's own free-form status string (running/crawling/auditing/paused/succeeded/failed/…). */
  last_status: string;
  last_scanned_at: string | null;
  first_scanned_at: string;
  issues_high: number;
  issues_medium: number;
  issues_low: number;
  issues_total: number;
  group_id: string | null;
}

export interface BurpsuiteScanSummary {
  id: number;
  taskId: string;
  /** The raw, original scanned URL (e.g. "https://www.example.com/login") —
   *  NOT normalized; show this verbatim in a scan-history timeline. */
  target: string;
  status: string;
  issues_high: number;
  issues_medium: number;
  issues_low: number;
  issues_total: number;
  created_at: string;
  updated_at: string;
}

export interface BurpsuiteAssetDetail {
  asset: BurpsuiteAssetListItem;
  /** Every raw scan row for this target, newest first. */
  scans: BurpsuiteScanSummary[];
}

/** Paginated envelope shared by this endpoint — same shape as
 *  AssetPageResponse in assetsApi.ts. */
export interface BurpsuiteAssetPageResponse<T> {
  success: boolean;
  total: number;
  count: number;
  page: number;
  rows: number;
  data: T[];
}

export interface BurpsuiteAssetListParams {
  rows?: number;
  pageno?: number;
  /**
   * Pass a specific group id to view that group's assets, `null`/omit the
   * field's VALUE for the caller's own default ("self") scope, or omit the
   * FIELD entirely for a Super Administrator to get the same all-groups-merged
   * view listBurpsuiteScans's own bare-omit gives (see resolveBurpAssetsScope
   * in listBurpsuiteAssets.ts — an unrestricted caller with no `?groupId=` at
   * all resolves to `{kind: 'all'}`, not narrowed to "self"). The current UI
   * (BurpsuiteAssetsList.tsx) always passes an explicit selectedGroupId and
   * never actually omits this field, so that merged view isn't reachable from
   * this app today — but a future caller of this function that does omit it
   * should get the real backend behavior, not a narrower one this comment used
   * to (incorrectly) promise.
   */
  groupId?: string | null;
}

export const getBurpsuiteAssets = async (
  params: BurpsuiteAssetListParams = {},
  signal?: AbortSignal,
): Promise<BurpsuiteAssetPageResponse<BurpsuiteAssetListItem>> => {
  const response = await api.get('/burpsuite/assets', {
    signal,
    params: {
      rows: params.rows,
      pageno: params.pageno,
      groupId: params.groupId !== undefined ? (params.groupId ?? 'self') : undefined,
    },
  });
  return response.data;
};

export const getBurpsuiteAsset = async (
  normalizedTarget: string,
  signal?: AbortSignal,
): Promise<{ success: boolean; data: BurpsuiteAssetDetail }> => {
  const response = await api.get(`/burpsuite/assets/${encodeURIComponent(normalizedTarget)}`, { signal });
  return response.data;
};
