/**
 * Read-only in-product access to the vulnexus CVE-matching pipeline's data.
 *
 * `vajra-vulnexus` (an external Python service, code not in this repo) owns a
 * local NVD mirror and CPE-matches every host's installed software against
 * it, writing results into `vulnexus_*` tables plus a handful of
 * materialized views. src/migrations/create_grafana_views.sql is the
 * authoritative schema reference for everything queried here. The same data
 * is also surfaced by a Grafana iframe over a separate `grafana_reader`-role
 * connection (frontend/src/features/Analytics/index.tsx's "CVE Analysis"
 * tab); this module is the backend's own live read path for it.
 *
 * STRICTLY READ-ONLY: every query below is a SELECT. Nothing here ever
 * writes to vulnexus_*, deb_packages, rpm_packages, or programs — that
 * pipeline (and osquery ingestion, for the package/program tables) owns its
 * own data exclusively.
 *
 * Cross-platform coverage, per the vulnexus schema:
 *  - Windows: vulnexus_host_vulnerabilities (program_id -> cve_id, its own
 *    severity/cvss_score) joined to `programs`.
 *  - Debian/Ubuntu: vulnexus_package_cves joined to `deb_packages`.
 *  - RHEL/CentOS: vulnexus_rpm_package_cves joined to `rpm_packages`.
 *  - CVE-level metadata (description, published date, CVSS3 score/severity)
 *    comes from vulnexus_nvd_cves1, LEFT JOINed since not every hv/pc/rc
 *    match necessarily has a corresponding NVD row synced locally — when it
 *    doesn't, a per-host-match fallback (severity/cvss_score straight off
 *    vulnexus_host_vulnerabilities) is used instead so the row still shows
 *    *something* rather than nulling out severity entirely.
 *
 * NOT AVAILABLE in this schema (checked against create_grafana_views.sql —
 * nothing there references it, and no other file in this repo does either):
 * there is no CISA-KEV / "known exploited" flag and no EPSS score anywhere
 * in the vulnexus_* tables. `exploited_only` is accepted as a query param
 * for forward-compatibility but is a no-op today; callers get a `warnings`
 * entry back explaining why, rather than a silently-wrong filter or a
 * reference to a column that doesn't exist.
 *
 * host_identifier comparisons are wrapped in LOWER() at query time throughout,
 * matching the convention in src/migrations/create_grafana_views.sql and
 * nodes/patch_management.ts. Stored casing is never rewritten.
 *
 * Node-group scoping: every endpoint here resolves the caller's NodeScope
 * (getUserNodeScope) and restricts results to nodes.owner_group_id within
 * that scope, exactly like nodes.ts / alert_list.ts / node_details.ts — a
 * Group-scoped user must not see CVE data for hosts outside their group(s).
 * Route-level gating is checkAccessJwt + apiDataLimiter only (no
 * requireAdmin), matching how other read-mostly fleet-data GET endpoints in
 * this codebase are gated (e.g. nodes.ts's /list, /details/:host_identifier,
 * /storage/:host_identifier) — this is deliberately looser than
 * routes/api/patch.ts's blanket Super-Admin gate, since patch.ts's mutating
 * endpoints (apply/check) are a different risk class than a read-only CVE
 * list.
 */

import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { JwtPayload } from '../../types/JwtPayload';
import { getUserNodeScope, scopeGroupIds, assertHostInScope, NodeScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { missingTableErrors } from '../../utils/missingTable';
import { PAGINATION_MAX_ROWS_VULNERABILITIES } from '../../consts/pagination';

const logger = getLogger('controllers.vulnerabilities.vulnexusRead');

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = PAGINATION_MAX_ROWS_VULNERABILITIES;
// CVE-YYYY-NNNN (4+ trailing digits, per CVE.org's format since 2014).
const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;

function getFleetDb() {
  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length < 2) return null;
  return dbSources[1];
}

async function resolveScope(req: Request): Promise<NodeScope> {
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  return jwtPayload?.id ? await getUserNodeScope(jwtPayload.id) : { unrestricted: false, groups: [] };
}

/**
 * Builds the `win` / `deb` / `rpm` / `combined` CTEs that union Windows
 * programs, Debian packages, and RPM packages against their respective
 * vulnexus CVE-match tables, each restricted to the caller's node-group scope.
 *
 * `scopeParamIndex` is the query's `$N` placeholder for the scope's group-id
 * array (or null when the caller is unrestricted, in which case no scope
 * clause is emitted at all). The same placeholder is referenced identically
 * in all three source CTEs — reusing one `$N` multiple times in a single
 * query is valid Postgres, and it's the same array value each time, so
 * there's no need for three separate params.
 *
 * Pre-aggregation. Each branch emits one row per (cve_id, node) rather than one
 * row per CVE-match, so the caller's `per_host` HashAggregate never sees the
 * ~1.1M-row intermediate the three branches would otherwise produce, and stops
 * spilling to temp files at work_mem=4MB. It also makes each branch a
 * self-contained aggregate, which lets the planner put the UNION ALL under a
 * Parallel Append where nothing else prevents it.
 *
 * The grouping key is `n.id` (int4 PK) rather than LOWER(n.host_identifier) (a
 * ~36-char string). That is a substitution, not an approximation:
 * nodes_pkey is UNIQUE on host_identifier, so node id and lowered
 * host_identifier are in bijection and counting distinct values of one counts
 * distinct values of the other. The narrower key shrinks both the hash entries
 * and any tuples that still spill.
 *
 * detected_at is cast to timestamptz *inside* each branch's MIN(). The three
 * source columns are not the same type — hv.detected_at and rc.created_at are
 * timestamptz, pc.detected_at is a bare timestamp — so a UNION ALL over them
 * coerces the deb branch using the session TimeZone. Casting before the MIN
 * means the MIN is taken over exactly the values the UNION would produce, so
 * MIN-of-MINs is the same value even if the cast were non-monotonic, and the
 * identity does not rest on the server's timezone setting.
 *
 * Map-first join order for deb/rpm. Those branches join `nodes` to a
 * pre-restricted package_id -> node_id map rather than to the CVE-match stream
 * directly. This is a pure re-association of three inner joins plus one
 * redundant filter (see the equivalence note below), and it removes hundreds of
 * thousands of LOWER() calls per request.
 *
 * Why LOWER() is the dominant cost here, which is not obvious: the `fleet`
 * database is C.UTF-8 with locale provider `c`, and PostgreSQL only takes its
 * fast single-byte lowercasing path when lc_ctype is literally "C" or "POSIX".
 * "C.UTF-8" is neither, so `lower()` goes through the multibyte path —
 * pg_mb2wchar, one towlower() per character, pg_wchar2mb, plus two pallocs —
 * for every value, costing microseconds per row on 36-character
 * host_identifiers. Evaluating the join after expanding to one row per
 * CVE-match therefore lowercases hundreds of thousands of host_identifiers per
 * call. A package_id determines its host, and only a small fraction of
 * deb_packages/rpm_packages rows are ever referenced by a CVE-match, so
 * building the map first lowercases roughly an order of magnitude fewer values
 * and turns the wide join into a bigint = bigint hash join. The `win` branch is
 * deliberately left alone: the planner already builds `programs` JOIN `nodes`
 * first there, so it only lowercases the `programs` rows.
 *
 * `OFFSET 0` is an optimisation fence and is load-bearing. Without it the
 * planner flattens the subquery back into a four-way join and reverts to the
 * Nested Loop / Memoize / deb_packages_pkey plan that lowercases every
 * CVE-match row. It is a semantic no-op by definition (skip zero rows, no ORDER
 * BY involved), so unlike a plan hint or a rewritten predicate it cannot alter
 * the result. What it costs: a fenced branch is ineligible for the Parallel
 * Append above, so the three branches run serially in one backend. Every fenced
 * variant tried (OFFSET 0, GROUP BY, DISTINCT) lost the Parallel Append and
 * every unfenced variant kept it but also kept the slow join order;
 * serial-but-cheap measured faster, so that is what ships. The deb map itself is
 * still internally parallel under its own Gather.
 *
 * Equivalence of the map-first re-association: inner joins are associative and
 * commutative, so `(pc JOIN dp) JOIN n` and `pc JOIN (dp JOIN n)` produce the
 * same multiset, including any row multiplication a duplicate `nodes` match
 * would cause. The added `dp.id IN (SELECT package_id FROM
 * vulnexus_package_cves)` is a semi-join, not a set-returning unnest, so it
 * cannot duplicate a dp row, and it only removes dp rows that have no pc partner
 * and could never have survived `dn.package_id = pc.package_id`.
 *
 * Two further rewrites were measured and rejected; recorded so the next reader
 * does not re-derive them.
 *
 * (1) Map-first join order for the `win` branch too. The arithmetic looks
 * identical to deb/rpm — only a few thousand of the `programs` rows are ever
 * referenced by a CVE-match, so the map form evaluates LOWER() far fewer times
 * and shrinks the hash table feeding the 600k-row probe side — and benchmarked
 * on its own it wins clearly. It buys nothing in situ, which is the measurement
 * that decides: inside the full statement the win branch's HashAggregate takes
 * the same time either way and the two forms are indistinguishable end to end.
 * Under the Append the branch is planned differently from how it is planned as a
 * whole query, and the isolated speedup is an artefact of that. A correlated
 * subquery plus an optimisation fence is real added complexity for nothing here.
 *
 * (2) The `deb_packages (id) INCLUDE (host_identifier)` covering index proposed
 * by src/migrations/add_package_covering_indexes.sql. Its stated rationale —
 * eliminating heap fetches from the Memoize probes — no longer describes this
 * query, because there are no Memoize probes left. Measured, the index-probe
 * plan (forced by disabling seqscan) is substantially slower than the map's
 * current Parallel Seq Scan, so removing the heap fetches cannot break even.
 * Writing the map node-first (FROM nodes JOIN deb_packages ...) to reach an
 * index-only scan of the existing idx_deb_packages_host_lower_dedupe does not
 * work either: the planner re-associates it straight back to the
 * deb_packages-driven plan, byte-identical EXPLAIN output. That migration exists
 * and is unapplied; it is not re-proposed here.
 *
 * What would actually help is not a code change. deb_packages, rpm_packages and
 * `programs` each carry around half their heap as post-vacuum free space (dead
 * tuple counts are negligible), which only VACUUM FULL or pg_repack returns to
 * the OS. The map's Parallel Seq Scan therefore reads roughly twice the pages it
 * needs, and it is the single most expensive scan left in this statement.
 * Repacking is an operational action, deliberately not attempted from here.
 */
function buildCombinedCveCte(scopeParamIndex: number | null): string {
  const scopeClause = scopeParamIndex ? `AND n.owner_group_id = ANY($${scopeParamIndex}::text[])` : '';
  return `
    win AS (
      SELECT hv.cve_id, n.id AS node_id, MIN(hv.detected_at::timestamptz) AS first_detected_at
      FROM vulnexus_host_vulnerabilities hv
      JOIN programs p ON p.id = hv.program_id
      JOIN nodes n ON LOWER(n.host_identifier) = LOWER(p.host_identifier)
      WHERE 1=1 ${scopeClause}
      GROUP BY hv.cve_id, n.id
    ),
    deb AS (
      SELECT pc.cve_id, dn.node_id, MIN(pc.detected_at::timestamptz) AS first_detected_at
      FROM vulnexus_package_cves pc
      JOIN (
        SELECT dp.id AS package_id, n.id AS node_id
        FROM deb_packages dp
        JOIN nodes n ON LOWER(n.host_identifier) = LOWER(dp.host_identifier)
        WHERE dp.id IN (SELECT pc2.package_id FROM vulnexus_package_cves pc2) ${scopeClause}
        OFFSET 0
      ) dn ON dn.package_id = pc.package_id
      GROUP BY pc.cve_id, dn.node_id
    ),
    rpm AS (
      SELECT rc.cve_id, rn.node_id, MIN(rc.created_at::timestamptz) AS first_detected_at
      FROM vulnexus_rpm_package_cves rc
      JOIN (
        SELECT rp.id AS package_id, n.id AS node_id
        FROM rpm_packages rp
        JOIN nodes n ON LOWER(n.host_identifier) = LOWER(rp.host_identifier)
        WHERE rp.id IN (SELECT rc2.package_id FROM vulnexus_rpm_package_cves rc2) ${scopeClause}
        OFFSET 0
      ) rn ON rn.package_id = rc.package_id
      GROUP BY rc.cve_id, rn.node_id
    ),
    combined AS (
      SELECT cve_id, node_id, first_detected_at FROM win
      UNION ALL
      SELECT cve_id, node_id, first_detected_at FROM deb
      UNION ALL
      SELECT cve_id, node_id, first_detected_at FROM rpm
    )
  `;
}

/**
 * GET /api/vulnerabilities
 * Query: search?, min_cvss?, max_cvss?, exploited_only? (no-op, see file
 * header), page? (default 1), page_size? (default 50, max 500).
 *
 * Fleet-wide CVE list, one row per unique CVE across Windows programs + deb +
 * rpm packages, sorted by severity/host-count descending by default.
 */
export const listVulnerabilities = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const scope = await resolveScope(req);
    const params: unknown[] = [];
    let idx = 1;
    let scopeParamIndex: number | null = null;
    if (!scope.unrestricted) {
      scopeParamIndex = idx++;
      params.push(scopeGroupIds(scope));
    }

    const search = typeof req.query.search === 'string' ? req.query.search.trim().slice(0, 200) : '';
    const minCvssRaw = typeof req.query.min_cvss === 'string' ? req.query.min_cvss : undefined;
    const maxCvssRaw = typeof req.query.max_cvss === 'string' ? req.query.max_cvss : undefined;
    const minCvss = minCvssRaw !== undefined && minCvssRaw !== '' && !Number.isNaN(Number(minCvssRaw)) ? Number(minCvssRaw) : null;
    const maxCvss = maxCvssRaw !== undefined && maxCvssRaw !== '' && !Number.isNaN(Number(maxCvssRaw)) ? Number(maxCvssRaw) : null;
    const exploitedOnly = req.query.exploited_only === 'true' || req.query.exploited_only === '1';

    const page = Math.max(parseInt(String(req.query.page ?? '1'), 10) || 1, 1);
    const pageSize = Math.min(
      Math.max(parseInt(String(req.query.page_size ?? String(DEFAULT_PAGE_SIZE)), 10) || DEFAULT_PAGE_SIZE, 1),
      MAX_PAGE_SIZE,
    );
    const offset = (page - 1) * pageSize;

    const filterConditions: string[] = [];
    let searchIdx: number | null = null;
    if (search) {
      searchIdx = idx++;
      params.push(`%${search}%`);
      filterConditions.push(`(cve_id ILIKE $${searchIdx} OR description ILIKE $${searchIdx})`);
    }
    if (minCvss !== null) {
      const minIdx = idx++;
      params.push(minCvss);
      filterConditions.push(`cvss_score >= $${minIdx}`);
    }
    if (maxCvss !== null) {
      const maxIdx = idx++;
      params.push(maxCvss);
      filterConditions.push(`cvss_score <= $${maxIdx}`);
    }
    const filterWhere = filterConditions.length ? `WHERE ${filterConditions.join(' AND ')}` : '';

    const limitIdx = idx++;
    params.push(pageSize);
    const offsetIdx = idx++;
    params.push(offset);

    const query = `
      WITH ${buildCombinedCveCte(scopeParamIndex)},
      -- Two-step aggregation instead of a single COUNT(DISTINCT host).
      -- COUNT(DISTINCT) forces Postgres into a sort-based GroupAggregate over
      -- every row of \`combined\`, which spilled an 82MB external merge sort to
      -- disk on every single call. Collapsing to one row per (cve_id, node)
      -- first lets the planner use HashAggregate for both levels (73,180
      -- distinct pairs), replacing that sort with a hash pass.
      --
      -- Identical by construction: COUNT(DISTINCT h) = the number of distinct
      -- non-null h, which is exactly the number of (cve_id, h) groups with h
      -- NOT NULL; and MIN over per-group MINs = MIN over the whole group (MIN
      -- ignores NULLs at both levels). node_id is in fact never null here (it
      -- is nodes.id, the PK, off an inner join) but the FILTER keeps the
      -- identity true without depending on that.
      --
      -- \`combined\` now arrives already grouped per (cve_id, node) by
      -- buildCombinedCveCte — see the long note there. This level is still
      -- required, and is NOT redundant: the three branches can legitimately
      -- report the same CVE on the same host (a host may carry both a
      -- vulnerable Windows program and a vulnerable deb/rpm package matching
      -- one CVE), so the UNION ALL can still contain up to three rows per
      -- pair. It just gets 73,180 rows to chew on instead of 1,146,314.
      --
      -- Measured on prod (82GB fleet db, shared_buffers=128MB, work_mem=4MB),
      -- default first page, three warm runs each, alternating old/new:
      --   before: 2,799 / 2,757 / 2,730 ms
      --   after:  1,266 / 1,259 / 1,233 ms   (2.2x)
      -- Cold, as pg_stat_statements first caught it, the gap is wider still:
      -- 6,137ms for a single call, 94,082 shared blocks read and 3,324ms of
      -- that spent purely waiting on I/O. It was the single slowest statement
      -- in the database and the only one to breach log_min_duration_statement
      -- (5s). Temp spill over the same page: 44,816kB -> 1,608kB.
      --
      -- Equivalence proven against production before shipping: old and new
      -- both materialised and diffed with EXCEPT ALL in BOTH directions,
      -- 0 rows each way, over 11 parameter combinations -- unrestricted,
      -- single-group, two-group, empty-group and non-existent-group scopes,
      -- search-only, min_cvss, max_cvss, a cvss range, and scope+search+range
      -- together (20,453 / 4,240 / 3,289 / 0 / 0 / 67 / 3,625 / 8,544 /
      -- 17,510 / 46 / 66 rows respectively). The diffed projection included
      -- row_number() OVER (<the client-visible ORDER BY>), so pagination and
      -- ordering are covered, not just set membership -- and that ordering is
      -- a total order, because cve_id is unique in \`enriched\` (20,453 rows,
      -- 20,453 distinct cve_id: agg groups by it, the nvd join is on that
      -- table's PK, and the lateral is LIMIT 1).
      per_host AS (
        SELECT cve_id, node_id, MIN(first_detected_at) AS first_detected_at
        FROM combined
        GROUP BY cve_id, node_id
      ),
      agg AS (
        SELECT cve_id,
               COUNT(*) FILTER (WHERE node_id IS NOT NULL)::bigint AS affected_host_count,
               MIN(first_detected_at) AS first_detected_at
        FROM per_host
        GROUP BY cve_id
      ),
      enriched AS (
        SELECT
          agg.cve_id AS cve_id,
          COALESCE(cv.cvss3_severity, hvf.severity) AS severity,
          COALESCE(cv.cvss3_score, hvf.cvss_score) AS cvss_score,
          cv.published AS published,
          cv.description AS description,
          agg.first_detected_at AS first_detected_at,
          agg.affected_host_count AS affected_host_count
        FROM agg
        LEFT JOIN vulnexus_nvd_cves1 cv ON cv.cve_id = agg.cve_id
        -- The guard is the whole point of this lateral's cost profile.
        -- hvf is read in exactly two places, both directly above:
        -- COALESCE(cv.cvss3_severity, hvf.severity) and
        -- COALESCE(cv.cvss3_score, hvf.cvss_score). When BOTH cv columns are
        -- non-null, both COALESCEs return the cv value and hvf is discarded
        -- entirely -- so forcing the subquery to return no row in that case
        -- cannot change any output column. When either is null the guard is
        -- true and the subquery runs exactly as it always did. It is a LEFT
        -- JOIN, so suppressing the inner row never drops an outer row.
        --
        -- On prod that skips 18,764 of 20,453 index scans (91.7%): only 1,689
        -- CVEs are missing a cvss3_severity or cvss3_score in
        -- vulnexus_nvd_cves1, and only 26 have no NVD row at all. Because the
        -- predicate references no column of hv2, the planner hoists it to a
        -- one-time filter and skips the idx_hv_cve_id_cvss probe outright
        -- rather than scanning and discarding.
        LEFT JOIN LATERAL (
          SELECT hv2.severity, hv2.cvss_score
          FROM vulnexus_host_vulnerabilities hv2
          WHERE hv2.cve_id = agg.cve_id
            AND (cv.cvss3_severity IS NULL OR cv.cvss3_score IS NULL)
          ORDER BY hv2.cvss_score DESC NULLS LAST
          LIMIT 1
        ) hvf ON true
      )
      SELECT cve_id, severity, cvss_score, published, first_detected_at, affected_host_count,
             COUNT(*) OVER()::int AS total_count
      FROM enriched
      ${filterWhere}
      ORDER BY cvss_score DESC NULLS LAST, affected_host_count DESC, cve_id ASC
      LIMIT $${limitIdx} OFFSET $${offsetIdx}
    `;

    const rows = await fleetDb.query(query, params);
    const total = rows.length > 0 ? Number(rows[0].total_count) : 0;

    const cves = rows.map((r: any) => ({
      cve_id: r.cve_id,
      severity: r.severity ?? null,
      cvss_score: r.cvss_score !== null && r.cvss_score !== undefined ? Number(r.cvss_score) : null,
      published: r.published,
      first_detected_at: r.first_detected_at,
      affected_host_count: Number(r.affected_host_count),
    }));

    const warnings: string[] = [];
    if (exploitedOnly) {
      warnings.push(
        'exploited_only was requested but ignored: this schema has no CISA-KEV / exploited-in-the-wild or EPSS column (vulnexus_nvd_cves1 has no such field, per create_grafana_views.sql)',
      );
      logger.debug({}, 'Vulnerabilities list request: exploited_only filter requested but ignored (unsupported by schema)');
    }

    logger.debug({ count: cves.length, total, page }, 'Vulnerabilities listed');
    return res.status(200).json({
      status: 'Success',
      page,
      page_size: pageSize,
      total,
      cves,
      ...(warnings.length ? { warnings } : {}),
    });
  } catch (error) {
    logger.error({
      err: error,
      search: req.query.search,
      minCvss: req.query.min_cvss,
      maxCvss: req.query.max_cvss,
      page: req.query.page,
    }, 'Failed to list vulnerabilities');
    return next(new CustomError(500, 'Raw', 'Failed to list vulnerabilities', missingTableErrors(error), error));
  }
};

/**
 * GET /api/vulnerabilities/:cve
 * Per-CVE detail: description, severity/CVSS, published date, affected
 * software (name + version + host count, Windows + deb + rpm), and the
 * affected host list itself (inline — fleet sizes here are small enough that
 * this is never large; frontend can additionally cross-reference against
 * GET /api/nodes/identifiers for a fleet-wide host picker/deep-link).
 */
export const getVulnerabilityDetail = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const cveId = typeof req.params.cve === 'string' ? req.params.cve.trim().toUpperCase() : '';
    if (!CVE_ID_RE.test(cveId)) {
      return res.status(400).json({ status: 'Fail', message: 'Invalid CVE id format (expected CVE-YYYY-NNNN)' });
    }

    const scope = await resolveScope(req);
    const scopeClauseN = scope.unrestricted ? '' : `AND n.owner_group_id = ANY($2::text[])`;
    const scopeParams: unknown[] = scope.unrestricted ? [] : [scopeGroupIds(scope)];

    const [nvdRows, fallbackRows, winRows, debRows, rpmRows, hostRows] = await Promise.all([
      fleetDb.query(
        `SELECT cve_id, description, published, cvss3_score, cvss3_severity FROM vulnexus_nvd_cves1 WHERE cve_id = $1`,
        [cveId],
      ),
      fleetDb.query(
        `SELECT severity, cvss_score FROM vulnexus_host_vulnerabilities WHERE cve_id = $1 ORDER BY cvss_score DESC NULLS LAST LIMIT 1`,
        [cveId],
      ),
      fleetDb.query(
        `SELECT p.name AS software_name, p.version AS software_version, 'windows' AS platform,
                COUNT(DISTINCT LOWER(n.host_identifier)) AS host_count
           FROM vulnexus_host_vulnerabilities hv
           JOIN programs p ON p.id = hv.program_id
           JOIN nodes n ON LOWER(n.host_identifier) = LOWER(p.host_identifier)
          WHERE hv.cve_id = $1 ${scopeClauseN}
          GROUP BY p.name, p.version
          ORDER BY host_count DESC, p.name`,
        [cveId, ...scopeParams],
      ),
      fleetDb.query(
        `SELECT dp.name AS software_name, dp.version AS software_version, 'linux-deb' AS platform,
                COUNT(DISTINCT LOWER(n.host_identifier)) AS host_count
           FROM vulnexus_package_cves pc
           JOIN deb_packages dp ON dp.id = pc.package_id
           JOIN nodes n ON LOWER(n.host_identifier) = LOWER(dp.host_identifier)
          WHERE pc.cve_id = $1 ${scopeClauseN}
          GROUP BY dp.name, dp.version
          ORDER BY host_count DESC, dp.name`,
        [cveId, ...scopeParams],
      ),
      fleetDb.query(
        `SELECT rp.name AS software_name, rp.version AS software_version, 'linux-rpm' AS platform,
                COUNT(DISTINCT LOWER(n.host_identifier)) AS host_count
           FROM vulnexus_rpm_package_cves rc
           JOIN rpm_packages rp ON rp.id = rc.package_id
           JOIN nodes n ON LOWER(n.host_identifier) = LOWER(rp.host_identifier)
          WHERE rc.cve_id = $1 ${scopeClauseN}
          GROUP BY rp.name, rp.version
          ORDER BY host_count DESC, rp.name`,
        [cveId, ...scopeParams],
      ),
      fleetDb.query(
        `SELECT DISTINCT LOWER(n.host_identifier) AS host_identifier, n.hostname, n.os_platform
           FROM (
             SELECT p.host_identifier FROM vulnexus_host_vulnerabilities hv JOIN programs p ON p.id = hv.program_id WHERE hv.cve_id = $1
             UNION
             SELECT dp.host_identifier FROM vulnexus_package_cves pc JOIN deb_packages dp ON dp.id = pc.package_id WHERE pc.cve_id = $1
             UNION
             SELECT rp.host_identifier FROM vulnexus_rpm_package_cves rc JOIN rpm_packages rp ON rp.id = rc.package_id WHERE rc.cve_id = $1
           ) hosts
           JOIN nodes n ON LOWER(n.host_identifier) = LOWER(hosts.host_identifier)
          WHERE 1=1 ${scopeClauseN}
          ORDER BY n.hostname`,
        [cveId, ...scopeParams],
      ),
    ]);

    const nvd = nvdRows[0];
    const fallback = fallbackRows[0];
    const hasAnyMatch = winRows.length > 0 || debRows.length > 0 || rpmRows.length > 0 || hostRows.length > 0;
    if (!nvd && !hasAnyMatch) {
      return res.status(404).json({ status: 'Fail', message: 'CVE not found in fleet data' });
    }

    const affectedSoftware = [...winRows, ...debRows, ...rpmRows].map((r: any) => ({
      software_name: r.software_name,
      software_version: r.software_version,
      platform: r.platform,
      host_count: Number(r.host_count),
    }));

    const cvssScore =
      nvd?.cvss3_score !== undefined && nvd?.cvss3_score !== null
        ? Number(nvd.cvss3_score)
        : fallback?.cvss_score !== undefined && fallback?.cvss_score !== null
          ? Number(fallback.cvss_score)
          : null;

    logger.debug({ cveId, affectedHostCount: hostRows.length }, 'Vulnerability detail retrieved');
    return res.status(200).json({
      status: 'Success',
      cve: {
        cve_id: cveId,
        description: nvd?.description ?? null,
        severity: nvd?.cvss3_severity ?? fallback?.severity ?? null,
        cvss_score: cvssScore,
        published: nvd?.published ?? null,
        // Not available in this schema — no CISA-KEV/EPSS column exists in
        // vulnexus_nvd_cves1 or anywhere else in the vulnexus_* tables.
        exploited: null,
      },
      affected_software: affectedSoftware,
      affected_host_count: hostRows.length,
      affected_hosts: hostRows.map((r: any) => ({
        host_identifier: r.host_identifier,
        hostname: r.hostname,
        os_platform: r.os_platform,
      })),
      // Cross-reference for a fleet-wide host picker / "view all hosts" deep-link.
      hosts_lookup_hint: '/api/nodes/identifiers',
    });
  } catch (error) {
    logger.error({ err: error, cve: req.params.cve }, 'Failed to get vulnerability detail');
    return next(new CustomError(500, 'Raw', 'Failed to get vulnerability detail', missingTableErrors(error), error));
  }
};

/**
 * GET /api/vulnerabilities/host/:host_identifier
 * Per-host rollup: every CVE affecting that host's installed software, with
 * the specific package/program name+version each CVE is matched against.
 * host_identifier is resolved case-insensitively (LOWER()) then re-checked
 * against the caller's node-group scope via assertHostInScope — same
 * pattern as node_details.ts.
 */
export const getHostVulnerabilities = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const hostParam = typeof req.params.host_identifier === 'string' ? req.params.host_identifier.trim() : '';
    if (!hostParam) {
      return res.status(400).json({ status: 'Fail', message: 'host_identifier is required' });
    }

    const nodeRows = await fleetDb.query(
      `SELECT host_identifier, hostname, os_platform FROM nodes WHERE LOWER(host_identifier) = LOWER($1) LIMIT 1`,
      [hostParam],
    );
    if (nodeRows.length === 0) {
      return res.status(404).json({ status: 'Fail', message: 'Node not found' });
    }
    const node = nodeRows[0];

    const scope = await resolveScope(req);
    if (!(await assertHostInScope(scope, node.host_identifier))) {
      const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
      logger.warn({ host_identifier: node.host_identifier, userId: jwtPayload?.id ?? null }, "Host vulnerabilities fetch denied: host outside caller's node scope");
      return res.status(404).json({ status: 'Fail', message: 'Node not found' });
    }

    const [winRows, debRows, rpmRows] = await Promise.all([
      fleetDb.query(
        `SELECT hv.cve_id, hv.severity, hv.cvss_score, hv.detected_at,
                p.name AS package_name, p.version AS package_version, 'windows' AS platform,
                NULL::text AS patched_version, cv.description AS cve_description, cv.published AS cve_published
           FROM vulnexus_host_vulnerabilities hv
           JOIN programs p ON p.id = hv.program_id
           LEFT JOIN vulnexus_nvd_cves1 cv ON cv.cve_id = hv.cve_id
          WHERE LOWER(p.host_identifier) = LOWER($1)
          ORDER BY hv.cvss_score DESC NULLS LAST, hv.cve_id`,
        [node.host_identifier],
      ),
      fleetDb.query(
        `SELECT pc.cve_id, cv.cvss3_severity AS severity, cv.cvss3_score AS cvss_score, pc.detected_at,
                dp.name AS package_name, dp.version AS package_version, 'linux-deb' AS platform,
                pc.patched_version, cv.description AS cve_description, cv.published AS cve_published
           FROM vulnexus_package_cves pc
           JOIN deb_packages dp ON dp.id = pc.package_id
           LEFT JOIN vulnexus_nvd_cves1 cv ON cv.cve_id = pc.cve_id
          WHERE LOWER(dp.host_identifier) = LOWER($1)
          ORDER BY cv.cvss3_score DESC NULLS LAST, pc.cve_id`,
        [node.host_identifier],
      ),
      fleetDb.query(
        `SELECT rc.cve_id, cv.cvss3_severity AS severity, cv.cvss3_score AS cvss_score, rc.created_at AS detected_at,
                rp.name AS package_name, rp.version AS package_version, 'linux-rpm' AS platform,
                rc.patched_version, cv.description AS cve_description, cv.published AS cve_published
           FROM vulnexus_rpm_package_cves rc
           JOIN rpm_packages rp ON rp.id = rc.package_id
           LEFT JOIN vulnexus_nvd_cves1 cv ON cv.cve_id = rc.cve_id
          WHERE LOWER(rp.host_identifier) = LOWER($1)
          ORDER BY cv.cvss3_score DESC NULLS LAST, rc.cve_id`,
        [node.host_identifier],
      ),
    ]);

    const vulnerabilities = [...winRows, ...debRows, ...rpmRows].map((r: any) => ({
      cve_id: r.cve_id,
      severity: r.severity ?? null,
      cvss_score: r.cvss_score !== null && r.cvss_score !== undefined ? Number(r.cvss_score) : null,
      package_name: r.package_name,
      package_version: r.package_version,
      patched_version: r.patched_version ?? null,
      platform: r.platform,
      detected_at: r.detected_at,
      cve_description: r.cve_description ?? null,
      cve_published: r.cve_published ?? null,
    }));

    logger.debug({ host_identifier: node.host_identifier, vulnerability_count: vulnerabilities.length }, 'Host vulnerabilities retrieved');
    return res.status(200).json({
      status: 'Success',
      host_identifier: node.host_identifier,
      hostname: node.hostname,
      os_platform: node.os_platform,
      vulnerability_count: vulnerabilities.length,
      unique_cve_count: new Set(vulnerabilities.map((v) => v.cve_id)).size,
      vulnerabilities,
    });
  } catch (error) {
    logger.error({ err: error, host_identifier: req.params.host_identifier }, 'Failed to get host vulnerabilities');
    return next(new CustomError(500, 'Raw', 'Failed to get host vulnerabilities', missingTableErrors(error), error));
  }
};
