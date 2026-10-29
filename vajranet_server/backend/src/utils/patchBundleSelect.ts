/**
 * Shared "which patch_bundles row applies to this host" selection logic.
 *
 * Extracted so the auto-selection heuristic used by the bundle-dispatch path
 * (controllers/nodes/patch_management.ts's createPatchJob, for
 * source==='bundle' jobs with no explicit bundleId pin) and the fleet-wide
 * gap computation (controllers/nodes/patch_gap.ts) can never independently
 * drift on what "the applicable bundle for this host" means — the exact kind
 * of duplicated-invariant risk this project's phase reviews have repeatedly
 * flagged (e.g. patchDispatch.ts's BUSY_STATUSES vs findHostsInFlight).
 *
 * Selection (best-effort, Phase 1 scope — see patch_gap.ts's header comment
 * for the full rationale): prefer the newest bundle whose os_match text
 * contains (case-insensitively) the host's os_platform and, if set,
 * os_major; if none matches, fall back to the single newest bundle for the
 * family regardless of os_match.
 */

import { getLogger } from './logger';

const logger = getLogger('patch.bundleSelect');

export type PatchBundleFamilyForGap = 'deb' | 'rpm';

/**
 * SQL condition fragment testing whether `bundleAlias`.os_match matches
 * `nodeAlias`'s os_platform/os_major. Callers embed this into their own
 * query (different call sites need different table aliases/join shapes), so
 * this returns text, not a runnable query.
 *
 * Tokenized, not raw substring `LIKE '%val%'`: os_major is a bare 1-2 digit
 * value (e.g. "22"), and os_match is fully free text with no word-boundary
 * anchoring — a host with os_major=22 would otherwise positively match any
 * bundle whose os_match contains "22" anywhere, e.g. an operator-authored
 * "ubuntu-20.04-2022-snapshot" string, not just an intended "ubuntu-22.04"
 * bundle. Splitting os_match on non-alphanumeric separators and requiring an
 * EXACT token match closes that collision cheaply while keeping the same
 * "no real OS-version parser" approximate scope this phase explicitly
 * allows.
 */
export function bundleOsMatchCondition(bundleAlias: string, nodeAlias: string): string {
  return `${nodeAlias}.os_platform IS NOT NULL AND ${nodeAlias}.os_platform <> ''
     AND EXISTS (
       SELECT 1 FROM regexp_split_to_table(LOWER(${bundleAlias}.os_match), '[^a-z0-9]+') AS tok
        WHERE tok = LOWER(${nodeAlias}.os_platform)
     )
     AND (
       ${nodeAlias}.os_major IS NULL OR ${nodeAlias}.os_major = '' OR EXISTS (
         SELECT 1 FROM regexp_split_to_table(LOWER(${bundleAlias}.os_match), '[^a-z0-9]+') AS tok
          WHERE tok = LOWER(${nodeAlias}.os_major)
       )
     )`;
}

export interface SelectedPatchBundle {
  id: number;
  bundle_id: string;
  family: string;
  payload: string | null;
  signature: string | null;
}

/**
 * Single-host bundle auto-selection for `family`, applying the same
 * os-match-then-newest-fallback heuristic as patch_gap.ts's bulk query.
 * Returns null only when no patch_bundles row exists for the family at all.
 */
export async function selectBundleForHostFamily(
  fleetDb: any,
  family: string,
  host: string,
): Promise<SelectedPatchBundle | null> {
  let osMatchRows: SelectedPatchBundle[];
  try {
    osMatchRows = await fleetDb.query(
      `SELECT pb.id, pb.bundle_id, pb.family, pb.payload, pb.signature
         FROM patch_bundles pb
         JOIN nodes n ON LOWER(n.host_identifier) = LOWER($2)
        WHERE pb.family = $1 AND ${bundleOsMatchCondition('pb', 'n')}
        ORDER BY pb.created_at DESC
        LIMIT 1`,
      [family, host],
    );
  } catch (err) {
    logger.error({ err, family, host, step: 'os-match query' }, 'Bundle auto-selection query failed');
    throw err;
  }
  if (osMatchRows.length > 0) return osMatchRows[0];

  let fallbackRows: SelectedPatchBundle[];
  try {
    fallbackRows = await fleetDb.query(
      `SELECT id, bundle_id, family, payload, signature
         FROM patch_bundles
        WHERE family = $1
        ORDER BY created_at DESC
        LIMIT 1`,
      [family],
    );
  } catch (err) {
    logger.error({ err, family, host, step: 'fallback query' }, 'Bundle auto-selection query failed');
    throw err;
  }
  // Applying a bundle never matched against this host's OS is worth a trace.
  // Debug rather than warn because this runs once per host in createPatchJob's
  // dispatch loop, and the fallback still dispatches successfully: at warn, a
  // bulk push across a fleet with incomplete os_match data would emit one
  // near-duplicate line per host.
  if (fallbackRows[0]) {
    logger.debug(
      { family, host, bundleId: fallbackRows[0].bundle_id },
      'No OS-matched patch bundle for host, falling back to newest bundle for family regardless of os_match',
    );
  }
  return fallbackRows[0] ?? null;
}

/**
 * Best-effort family detection for a host, mirroring patch_gap.ts's rule:
 * "a host is in-scope for a family simply by having any rows in that
 * family's package table." Only deb/rpm are supported for auto-selection
 * (matching patch_gap.ts's own scope boundary — pacman/apk bundles can only
 * be applied via an explicit bundleId pin, e.g. POST
 * /api/patch/bundles/:id/apply, never auto-selected).
 */
export async function detectHostPackageFamily(fleetDb: any, host: string): Promise<PatchBundleFamilyForGap | null> {
  let deb: unknown[];
  let rpm: unknown[];
  try {
    [deb, rpm] = await Promise.all([
      fleetDb.query(`SELECT 1 FROM deb_packages WHERE LOWER(host_identifier) = LOWER($1) LIMIT 1`, [host]),
      fleetDb.query(`SELECT 1 FROM rpm_packages WHERE LOWER(host_identifier) = LOWER($1) LIMIT 1`, [host]),
    ]);
  } catch (err) {
    // Same rationale as selectBundleForHostFamily's own try/catch below:
    // without host/step context here, a DB failure surfaces to the caller's
    // batch-level catch indistinguishable from any other query failure in
    // the same request.
    logger.error({ err, host, step: 'detectHostPackageFamily' }, 'Host package family detection query failed');
    throw err;
  }
  if (deb.length > 0) return 'deb';
  if (rpm.length > 0) return 'rpm';
  return null;
}

/**
 * Batched form of detectHostPackageFamily for callers checking many hosts at
 * once (e.g. patch_bundles.ts's applyPatchBundle family gate) — two queries
 * total instead of two-per-host, same precedence (deb wins over rpm if a
 * host somehow has rows in both). A host absent from the returned map has no
 * detectable family (same as detectHostPackageFamily returning null).
 */
export async function detectHostPackageFamilies(fleetDb: any, hosts: string[]): Promise<Map<string, PatchBundleFamilyForGap>> {
  const map = new Map<string, PatchBundleFamilyForGap>();
  if (hosts.length === 0) return map;
  const lowerHosts = hosts.map((h) => h.toLowerCase());
  let debRows: { host_identifier: string }[];
  let rpmRows: { host_identifier: string }[];
  try {
    [debRows, rpmRows] = await Promise.all([
      fleetDb.query(`SELECT DISTINCT LOWER(host_identifier) AS host_identifier FROM deb_packages WHERE LOWER(host_identifier) = ANY($1)`, [lowerHosts]),
      fleetDb.query(`SELECT DISTINCT LOWER(host_identifier) AS host_identifier FROM rpm_packages WHERE LOWER(host_identifier) = ANY($1)`, [lowerHosts]),
    ]);
  } catch (err) {
    logger.error({ err, hostCount: hosts.length, step: 'detectHostPackageFamilies' }, 'Batched host package family detection query failed');
    throw err;
  }
  for (const r of debRows) map.set(r.host_identifier, 'deb');
  for (const r of rpmRows) if (!map.has(r.host_identifier)) map.set(r.host_identifier, 'rpm');
  return map;
}
