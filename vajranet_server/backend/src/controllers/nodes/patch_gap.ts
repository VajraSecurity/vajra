/**
 * Patch gap computation — the "unification" piece tying together the
 * offline Patch Bundle content pipeline (patch_bundles, see
 * patch_bundles.ts) with the read-only osquery-ingested package inventory
 * (deb_packages / rpm_packages) and the vulnexus CVE-correlation tables, to
 * answer: "for each host+package, what's installed vs. what's available in
 * a signed bundle, and how bad is the gap?"
 *
 * READ-ONLY against deb_packages, rpm_packages, and every vulnexus_* table
 * — this file only ever SELECTs from them, matching the same rule the
 * parallel vulnexus-read-layer (`/api/vulnerabilities/*`) follows; nothing
 * here writes to those tables.
 *
 * Bundle selection
 * A host is in-scope for a family ('deb'/'rpm') simply by having any rows in
 * that family's package table — no separate OS-detection service exists, so
 * this is the simplest correct signal available today.
 *
 * Among patch_bundles rows for that family, the applicable bundle for a host is chosen
 * as follows. Both steps are deliberately simple tokenized matching rather than a real
 * OS-version parser; see utils/patchBundleSelect.ts's bundleOsMatchCondition for why
 * the match is token-exact instead of a raw substring `LIKE '%val%'`:
 *   1. Prefer the most-recently-created bundle whose `os_match` text,
 *      split into tokens on non-alphanumeric separators, contains
 *      (case-insensitively) an exact token equal to both the host's
 *      `os_platform` (e.g. "ubuntu", "rhel") and, if set, its `os_major`
 *      (e.g. "22", "9") — e.g. os_match "ubuntu-22.04" tokenizes to
 *      {ubuntu, 22, 04}, matching a host with os_platform='ubuntu',
 *      os_major='22'.
 *   2. If no bundle's os_match matches that host, fall back to the single
 *      most-recently-created bundle for the family regardless of os_match.
 *      This intentionally means an operator who has uploaded bundles for
 *      multiple OS variants of the same family, with no bundle matching a
 *      given host's OS, will get a (probably noisy/wrong) gap comparison
 *      against an unrelated OS's bundle rather than silently skipping the
 *      host — flagged as a known limitation in this endpoint's docs.
 *
 * A bundle is a full snapshot (see patchBundle.ts's header comment), so
 * exactly one bundle's package list is used as "the available catalog" per
 * host — this is not a per-package "latest across all bundles" merge.
 *
 * Package identity and version comparison
 * deb_packages/rpm_packages accumulate one row per osquery check-in, so the same
 * host+name(+arch) has many near-duplicate rows differing only by ingestion time. This
 * endpoint dedupes to the newest row per host+name+arch (by unixtime, falling back to
 * id) before comparing — without that, both the gap rows and the CVE counts joined onto
 * them would be multiplied by the duplicate factor.
 *
 * For rpm, "installed_version" is version+'-'+release (rpm's real identity, stored as
 * two columns) so it compares fairly against whatever string the bundle publisher put
 * in the package's `version` field. Version comparison itself is plain string
 * (in)equality — no dpkg/rpm-aware ordering — which is approximate by design.
 *
 * CVE annotation
 * LEFT JOINed from vulnexus_package_cves (deb) / vulnexus_rpm_package_cves (rpm)
 * against vulnexus_nvd_cves1 for cvss3_score, using the join keys documented in
 * src/migrations/create_grafana_views.sql's mv_linux_package_cves view. `exploited` is
 * always null: the schema has no CISA-KEV/known-exploited table, and defaulting it to
 * false would assert something untrue.
 *
 * host_identifier comparisons are wrapped in LOWER() throughout, matching the
 * convention in patch_management.ts and src/migrations/create_grafana_views.sql.
 */

import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { missingTableErrors } from '../../utils/missingTable';
import { bundleOsMatchCondition } from '../../utils/patchBundleSelect';
import { MAX_HOSTS, validateHostIdentifiers } from './patch_management';
import { getLogger } from '../../utils/logger';
import { PATCH_FLEETWIDE_ROW_LIMIT } from '../../consts/pagination';

const logger = getLogger('nodes.patchGap');

function getFleetDb() {
  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length < 2) return null;
  return dbSources[1];
}

export interface PatchGapRow {
  host_identifier: string;
  family: 'deb' | 'rpm';
  name: string;
  installed_version: string;
  available_version: string;
  bundle_id: string;
  cve_count: number;
  worst_cvss: number | null;
  exploited: boolean | null;
}

// Fleet-wide (no host_identifier filter) responses are capped as a
// defense-in-depth safety valve — a single-host query is naturally bounded
// by that host's package count and is never capped. Revisit with real
// pagination if a fleet's gap set regularly exceeds this.
const FLEETWIDE_ROW_LIMIT = PATCH_FLEETWIDE_ROW_LIMIT;

/**
 * Builds the parameterized gap query for one family.
 *
 * The host filter is branched in JS rather than expressed in SQL as
 * `WHERE $1::text[] IS NULL OR LOWER(host_identifier) = ANY($1::text[])`. That
 * disjunction's first branch ignores the column, so it can never become an index
 * condition on its own; it only performs today because node-postgres sends unnamed
 * prepared statements, which Postgres plans with the bound value in hand and so
 * constant-folds the dead branch away. That is a property of the driver, not of the
 * SQL — a named statement or a generic plan anywhere upstream stops the folding, and a
 * single-host request then pays the full fleet-wide scan once per family.
 *
 * When `scoped`, $1 is the lowercased host_identifier array and is the query's only
 * parameter; otherwise the query takes no parameters and the caller must pass none.
 */
function buildFamilyGapQuery(family: 'deb' | 'rpm', scoped: boolean): string {
  const pkgTable = family === 'deb' ? 'deb_packages' : 'rpm_packages';
  const cveTable = family === 'deb' ? 'vulnexus_package_cves' : 'vulnexus_rpm_package_cves';
  // rpm's real package identity is version+release. deb_packages has no equivalent
  // split — its `version` already embeds the Debian revision — so it is used as-is.
  const installedVersionExpr =
    family === 'deb'
      ? 'p.version'
      : `(p.version || CASE WHEN p.release IS NOT NULL AND p.release <> '' THEN '-' || p.release ELSE '' END)`;
  // Both deb_packages and rpm_packages carry a `unixtime` column, so the
  // per-host+name+arch dedupe orders by it for either family.
  const dedupeOrderExpr = 'p.unixtime DESC NULLS LAST, p.id DESC';
  // Fetch one row past the cap so the caller can detect truncation (see
  // getPatchGap's `truncated` flag) without a separate COUNT(*) query.
  const limitClause = `LIMIT ${FLEETWIDE_ROW_LIMIT + 1}`;

  // target_hosts is "the requested hosts that actually have rows in this family's
  // package table" (fleet-wide: every host that does). The two shapes are the same
  // predicate simplified: with no host filter the clause is unconditionally true, and
  // with one it reduces to the ANY clause.
  const targetHostsCte = scoped
    ? `SELECT DISTINCT LOWER(host_identifier) AS host_identifier
         FROM ${pkgTable}
        WHERE LOWER(host_identifier) = ANY($1::text[])`
    : `SELECT DISTINCT LOWER(host_identifier) AS host_identifier
         FROM ${pkgTable}`;

  return `
    WITH target_hosts AS (
      ${targetHostsCte}
    ),
    host_bundle_os AS (
      -- Best-effort OS match: bundle.os_match must textually contain both
      -- the host's os_platform and (if known) os_major. See header comment.
      SELECT th.host_identifier, pb.id AS bundle_row_id, pb.created_at
        FROM target_hosts th
        JOIN nodes n ON LOWER(n.host_identifier) = th.host_identifier
        JOIN patch_bundles pb ON pb.family = '${family}'
         AND ${bundleOsMatchCondition('pb', 'n')}
    ),
    host_bundle_os_top AS (
      SELECT DISTINCT ON (host_identifier) host_identifier, bundle_row_id
        FROM host_bundle_os
       ORDER BY host_identifier, created_at DESC
    ),
    host_bundle_fallback AS (
      -- No os_match-compatible bundle for this host: fall back to the
      -- single most recent bundle of the family, regardless of os_match.
      SELECT th.host_identifier,
             (SELECT id FROM patch_bundles WHERE family = '${family}' ORDER BY created_at DESC LIMIT 1) AS bundle_row_id
        FROM target_hosts th
       WHERE th.host_identifier NOT IN (SELECT host_identifier FROM host_bundle_os_top)
    ),
    resolved AS (
      SELECT * FROM host_bundle_os_top
       UNION ALL
      SELECT * FROM host_bundle_fallback
    ),
    bundle_pkgs AS (
      SELECT pb.id AS bundle_row_id, pb.bundle_id,
             (pkg->>'name') AS name, (pkg->>'arch') AS arch, (pkg->>'version') AS available_version
        FROM patch_bundles pb, jsonb_array_elements(pb.manifest_json->'packages') AS pkg
       WHERE pb.id IN (SELECT DISTINCT bundle_row_id FROM resolved WHERE bundle_row_id IS NOT NULL)
    ),
    canonical_pkgs AS (
      -- Newest row per host+name+arch — see header comment on osquery
      -- check-in duplicates.
      SELECT DISTINCT ON (LOWER(p.host_identifier), p.name, p.arch)
             p.id AS package_row_id, LOWER(p.host_identifier) AS host_identifier, p.name, p.arch,
             ${installedVersionExpr} AS installed_version
        FROM ${pkgTable} p
       WHERE LOWER(p.host_identifier) IN (SELECT host_identifier FROM target_hosts)
       ORDER BY LOWER(p.host_identifier), p.name, p.arch, ${dedupeOrderExpr}
    ),
    gap AS (
      SELECT r.host_identifier, dp.package_row_id, dp.name, dp.installed_version,
             bp.available_version, bp.bundle_id
        FROM resolved r
        JOIN canonical_pkgs dp ON dp.host_identifier = r.host_identifier
        JOIN bundle_pkgs bp ON bp.bundle_row_id = r.bundle_row_id AND LOWER(bp.name) = LOWER(dp.name)
         -- Case-insensitive, matching every other identity comparison in this
         -- file (host_identifier, name) — a manifest publisher writing "AMD64"
         -- must still match osquery's "amd64" rather than silently never
         -- surfacing as available.
         AND (bp.arch IS NULL OR bp.arch = '' OR dp.arch IS NULL OR dp.arch = '' OR LOWER(bp.arch) = LOWER(dp.arch))
       WHERE bp.available_version IS DISTINCT FROM dp.installed_version
    ),
    cve_agg AS (
      SELECT c.package_id, COUNT(DISTINCT c.cve_id) AS cve_count, MAX(cv.cvss3_score) AS worst_cvss
        FROM ${cveTable} c
        LEFT JOIN vulnexus_nvd_cves1 cv ON cv.cve_id = c.cve_id
       WHERE c.package_id IN (SELECT package_row_id FROM gap)
       GROUP BY c.package_id
    )
    SELECT g.host_identifier, '${family}' AS family, g.name,
           g.installed_version, g.available_version, g.bundle_id,
           COALESCE(ca.cve_count, 0)::int AS cve_count, ca.worst_cvss,
           NULL::boolean AS exploited
      FROM gap g
      LEFT JOIN cve_agg ca ON ca.package_id = g.package_row_id
     ORDER BY ca.worst_cvss DESC NULLS LAST, g.host_identifier, g.name
     ${limitClause}
  `;
}

/**
 * GET /api/patch/gap?host_identifier=... | ?host_identifiers=a,b,c
 * Fleet-wide (all deb + rpm hosts) if neither param is given. `host_identifier` scopes
 * to exactly one host; `host_identifiers` (comma-separated) scopes to a batch in one
 * query, so callers with a known host set — e.g. useApplyPatchToAffectedHosts.ts working
 * through a CVE's affected hosts — do not have to issue one request per host. The batch
 * form reuses validateHostIdentifiers' MAX_HOSTS cap and rejects an oversized list
 * rather than silently truncating it.
 *
 * See this file's header comment for the bundle-selection, versioning and
 * CVE-annotation methodology.
 */
export const getPatchGap = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const hostRaw = typeof req.query.host_identifier === 'string' ? req.query.host_identifier.trim() : '';
    const hostsRaw = typeof req.query.host_identifiers === 'string' ? req.query.host_identifiers : '';

    let hosts: string[] | null = null;
    if (hostsRaw) {
      const split = hostsRaw.split(',').map((h) => h.trim()).filter(Boolean);
      hosts = validateHostIdentifiers(split);
      if (!hosts) {
        return res.status(400).json({ status: 'Fail', message: `host_identifiers must be a non-empty array (max ${MAX_HOSTS})` });
      }
    } else if (hostRaw) {
      hosts = [hostRaw];
    }
    const hostsParam = hosts ? hosts.map((h) => h.toLowerCase()) : null;

    // buildFamilyGapQuery emits the host filter (or omits it) at build time,
    // so the fleet-wide shape references no parameters — passing one would be
    // rejected by the bind step ("supplies 1 parameters, but prepared
    // statement requires 0").
    const scoped = hostsParam !== null;
    const gapParams = scoped ? [hostsParam] : [];
    const [debRowsRaw, rpmRowsRaw] = await Promise.all([
      fleetDb.query(buildFamilyGapQuery('deb', scoped), gapParams),
      fleetDb.query(buildFamilyGapQuery('rpm', scoped), gapParams),
    ]);
    // Each query fetched FLEETWIDE_ROW_LIMIT+1 rows (see buildFamilyGapQuery) —
    // more than the cap for either family means this response is incomplete.
    // Applied per-family, since a fleet with >10k deb gaps AND >10k rpm gaps
    // could otherwise silently drop up to ~20k rows with no signal at all.
    const debTruncated = debRowsRaw.length > FLEETWIDE_ROW_LIMIT;
    const rpmTruncated = rpmRowsRaw.length > FLEETWIDE_ROW_LIMIT;
    const debRows = debTruncated ? debRowsRaw.slice(0, FLEETWIDE_ROW_LIMIT) : debRowsRaw;
    const rpmRows = rpmTruncated ? rpmRowsRaw.slice(0, FLEETWIDE_ROW_LIMIT) : rpmRowsRaw;

    const gaps: PatchGapRow[] = [...debRows, ...rpmRows].map((r: any) => ({
      host_identifier: r.host_identifier,
      family: r.family,
      name: r.name,
      installed_version: r.installed_version,
      available_version: r.available_version,
      bundle_id: r.bundle_id,
      cve_count: Number(r.cve_count) || 0,
      worst_cvss: r.worst_cvss === null || r.worst_cvss === undefined ? null : Number(r.worst_cvss),
      exploited: r.exploited === null || r.exploited === undefined ? null : Boolean(r.exploited),
    }));
    // debRows/rpmRows are each individually ORDER BY worst_cvss DESC NULLS
    // LAST, but concatenating two independently-sorted lists is not itself
    // sorted — without this, every deb row would precede every rpm row
    // regardless of actual severity for any multi-family (fleet-wide or
    // batch) request. Stable re-sort across the combined set, same
    // null-last convention as the SQL.
    gaps.sort((a, b) => {
      if (a.worst_cvss === b.worst_cvss) return 0;
      if (a.worst_cvss === null) return 1;
      if (b.worst_cvss === null) return -1;
      return b.worst_cvss - a.worst_cvss;
    });

    if (debTruncated || rpmTruncated) {
      logger.warn(
        { debTruncated, rpmTruncated, limit: FLEETWIDE_ROW_LIMIT },
        'Patch gap response truncated at the fleet-wide row limit',
      );
    }

    logger.debug(
      { host_count: hosts ? hosts.length : null, count: gaps.length, truncated: debTruncated || rpmTruncated },
      'Patch gap computed',
    );

    return res.status(200).json({
      status: 'Success',
      host_identifier: hostRaw || null,
      // Distinct from host_identifier (which only ever reflects the
      // singular ?host_identifier= form): echoes the actual resolved host
      // list for BOTH the singular and batch (?host_identifiers=) forms, so
      // a caller can tell "scoped to N hosts" apart from a genuinely
      // unscoped fleet-wide request — host_identifier alone reports null for
      // both, which is indistinguishable.
      host_identifiers: hosts,
      gaps,
      truncated: debTruncated || rpmTruncated,
    });
  } catch (error) {
    logger.error(
      { err: error, host_identifier: req.query?.host_identifier, host_identifiers: req.query?.host_identifiers },
      'Failed to compute patch gap',
    );
    return next(new CustomError(500, 'Raw', 'Failed to compute patch gap', missingTableErrors(error), error));
  }
};
