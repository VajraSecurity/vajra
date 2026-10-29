import { dbSourceConnection } from '../../index';
import { Request, Response, NextFunction } from 'express';
import { getUserNodeScope, assertHostInScope } from '../../utils/nodeScope';
import { getLogger } from '../../utils/logger';
import { RECENT_ROWS_ID_WINDOW } from '../../consts/database';

const logger = getLogger('nodes.nodePrograms');

/** CVE-YYYY-NNNN */
const CVE_REGEX = /CVE-(\d{4})-(\d+)/i;

/**
 * `programs` is an externally-owned table (populated by the osquery/vulnexus
 * pipeline, not migrated in this repo — see add_vulnexus_cve_indexes.sql).
 * Its Windows query below names an explicit column list rather than `SELECT
 * *`, so unlike the deb/rpm queries (which use `SELECT *` and silently omit
 * a column that isn't there yet), naming `has_kev_cve` directly would throw
 * `column "has_kev_cve" does not exist` on any deployment where the external
 * pipeline hasn't added it yet — and since this query runs inside the
 * isWindows branch's Promise.all, that failure would 500 the entire
 * Programs tab, not just drop the KEV badge.
 *
 * Checked once per process (via information_schema, not a schema migration
 * this repo owns) and cached — only the positive result is cached, so a
 * column added by the external pipeline while this process is still running
 * is picked up on the next request instead of staying stuck on a stale
 * "absent" reading from before the pipeline ran.
 */
let programsHasKevCveColumn = false;
const checkProgramsHasKevCveColumn = async (entityManager: { query: (sql: string) => Promise<unknown[]> }): Promise<boolean> => {
    if (programsHasKevCveColumn) return true;
    try {
        const rows = await entityManager.query(
            `SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'programs' AND column_name = 'has_kev_cve' LIMIT 1`
        );
        programsHasKevCveColumn = rows.length > 0;
    } catch (err) {
        logger.debug({ err }, 'has_kev_cve column existence check failed; treating as absent for this request');
    }
    return programsHasKevCveColumn;
};

/** Normalizes cve_match to an object, accepting strings, nulls and parsed JSONB. */
const normalizeCveMatch = (value: any): Record<string, any> => {
    if (!value) return {};
    if (typeof value === 'object' && !Array.isArray(value)) return value;

    try {
        const parsed = typeof value === 'string' ? JSON.parse(value) : value;
        return (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) ? parsed : {};
    } catch {
        return {};
    }
};

/** Highest severity found among the values of a cve_match object. */
const vulnerabilityTagger = (cveMatchObj: Record<string, any>): string => {
    const items = Object.values(cveMatchObj);
    let highest = "LOW";

    for (const cve of items) {
        const severity = cve?.severity?.toUpperCase(); 

        if (severity === "HIGH") return "HIGH";
        if (severity === "MEDIUM") highest = "MEDIUM";
    }

    return highest;
};

/**
 * Sort CVE IDs by newest first (Year then Number)
 */
const cveSorter = (ids: string[] = []) => {
    return ids.sort((a, b) => {
        const matchA = a.match(CVE_REGEX);
        const matchB = b.match(CVE_REGEX);

        if (!matchA || !matchB) return 0;

        const yearA = parseInt(matchA[1], 10);
        const yearB = parseInt(matchB[1], 10);

        if (yearA !== yearB) return yearB - yearA;

        const numA = parseInt(matchA[2], 10);
        const numB = parseInt(matchB[2], 10);

        return numB - numA;
    });
};

export const node_programs = async (req: Request, res: Response, _next: NextFunction) => {
    const { host_identifier, os_name } = req.body;

    if (!host_identifier || !os_name) {
        return res.status(400).json({
            status: 'Error',
            message: "Bad Request: Missing host_identifier or os_name"
        });
    }

    try {
        const connections = dbSourceConnection();
        const entityManager = connections?.[1];

        if (!entityManager) {
            logger.error({ host_identifier }, 'Database connection failed');
            return res.status(500).json({
                status: 'Error',
                message: "Database connection failed"
            });
        }

        const jwtPayload = (req as any).jwtPayload;
        const scope = jwtPayload?.id
          ? await getUserNodeScope(jwtPayload.id)
          : { unrestricted: false as const, groups: [] };
        if (!(await assertHostInScope(scope, host_identifier))) {
            logger.warn({ host_identifier }, 'Node programs request rejected: host out of scope for caller');
            return res.status(404).json({ status: 'Error', message: 'Node not found' });
        }

        const isWindows = String(os_name).toLowerCase().includes('windows');

        // Only the Windows branch queries `programs`, so only check/build its
        // conditional column there — see checkProgramsHasKevCveColumn's comment.
        const kevColumnExpr = isWindows && (await checkProgramsHasKevCveColumn(entityManager))
            ? 'has_kev_cve'
            : 'NULL::boolean AS has_kev_cve';

        // The `DISTINCT ON` queries below are output-nondeterministic as written. Treat
        // them as frozen: any change that can shift the chosen plan also silently changes
        // WHICH ROW the API returns, so no rewrite can be proven equivalent.
        //
        // Cause: `ORDER BY name, unixtime DESC` does not fully order the group. These
        // tables hold many (name, unixtime) ties whose rows differ in content, and
        // DISTINCT ON keeps whichever tied row the executor happens to emit first — a
        // property of the plan, not of the data. Forcing three different plan shapes over
        // the same rows produces three different results.
        //
        // The fix is to append `, id DESC` to each ORDER BY, which removes every tie since
        // id is the primary key. That is a visible behaviour change — a subset of rows
        // would start returning a different version/publisher/cve_match — so it needs
        // product sign-off and is deliberately not applied here.
        //
        // For whoever picks that up: the `id >` window guard is inert on these tables,
        // whose MAX(id) sits below RECENT_ROWS_ID_WINDOW; it only matters on the
        // high-volume Windows telemetry tables. There is no usable index either —
        // idx_deb_packages_host_lower_dedupe is keyed on lower(host_identifier) while this
        // predicate uses the plain column, and matching it would be a different query.
        const queries = {
            programs: `
                SELECT DISTINCT ON (name)
                    name, version, install_location, install_source, language,
                    publisher, uninstall_string, install_date, identifying_number,
                    cpe_string, cve_match, is_processed, is_cve_processed, ${kevColumnExpr},
                    bundle_name, bundle_publisher, bundle_version
                FROM programs
                WHERE host_identifier = $1
                AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM programs)
                AND name IS NOT NULL
                AND name <> ''
                ORDER BY name, unixtime DESC
            `,
            choco: `SELECT DISTINCT ON (name) * FROM chocolatey_packages WHERE host_identifier = $1 AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM chocolatey_packages) ORDER BY name, unixtime DESC`,
            deb: `SELECT DISTINCT ON (name) * FROM deb_packages WHERE host_identifier = $1 AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM deb_packages) ORDER BY name, unixtime DESC`,
            rpm: `SELECT DISTINCT ON (name) * FROM rpm_packages WHERE host_identifier = $1 AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM rpm_packages) ORDER BY name, unixtime DESC`,
            chrome: `SELECT DISTINCT ON (name) * FROM chrome_extensions WHERE host_identifier = $1 AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM chrome_extensions) ORDER BY name, unixtime DESC`,
            npm: `SELECT DISTINCT ON (name) * FROM npm_packages WHERE host_identifier = $1 AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM npm_packages) ORDER BY name, unixtime DESC`,
            portage: `SELECT DISTINCT ON (package) * FROM portage_packages WHERE host_identifier = $1 AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM portage_packages) ORDER BY package, unixtime DESC`,
            ie: `SELECT DISTINCT ON (name) * FROM ie_extensions WHERE host_identifier = $1 AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM ie_extensions) ORDER BY name, unixtime DESC`,
            firefox: `SELECT DISTINCT ON (name) * FROM firefox_addons WHERE host_identifier = $1 AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM firefox_addons) ORDER BY name, unixtime DESC`,
            snap: `SELECT DISTINCT ON (name) * FROM packages_snapshot WHERE host_identifier = $1 AND source = 'snap' ORDER BY name`,
            pacman: `SELECT DISTINCT ON (name) * FROM packages_snapshot WHERE host_identifier = $1 AND source = 'pacman' ORDER BY name`,
            flatpak: `SELECT DISTINCT ON (name) * FROM packages_snapshot WHERE host_identifier = $1 AND source = 'flatpak' ORDER BY name`
        };

        let finalResult: any = {};

        // Each query below is tagged with a `step` on failure — without it, a
        // failure in any one of these parallel Promise.all queries (e.g. a
        // missing/locked table for just one source) is indistinguishable in
        // the outer catch's generic "Failed to fetch node programs" log from
        // a failure in any of the others.
        const taggedQuery = (step: string, query: string) =>
            entityManager.query(query, [host_identifier]).catch((err: unknown) => {
                logger.debug({ err, host_identifier, step }, 'Node programs query failed for one data source');
                throw err;
            });

        if (isWindows) {
            const [programs, choco, chrome, npm, ie, firefox] = await Promise.all([
                taggedQuery('programs', queries.programs),
                taggedQuery('choco', queries.choco),
                taggedQuery('chrome', queries.chrome),
                taggedQuery('npm', queries.npm),
                taggedQuery('ie', queries.ie),
                taggedQuery('firefox', queries.firefox)
            ]);

            const vulStats = { LOW: 0, MEDIUM: 0, HIGH: 0 };

            const processedPrograms = programs.map((prog: any) => {
                const cveMatch = normalizeCveMatch(prog.cve_match);
                const cveIds = Object.keys(cveMatch); // Keys are the CVE IDs

                if (cveIds.length === 0) {
                    return { ...prog, severity: null, first_reported_at: null };
                }

                const severity = vulnerabilityTagger(cveMatch);
                const sortedCves = cveSorter(cveIds);

                vulStats[severity as keyof typeof vulStats]++;

                return {
                    ...prog,
                    severity,
                    // Returns top 2 most recent CVEs as a comma-separated string
                    first_reported_at: sortedCves.slice(0, 2).join(',')
                };
            });

            const totalVul = vulStats.LOW + vulStats.MEDIUM + vulStats.HIGH;

            finalResult = {
                programs: processedPrograms,
                choco,
                chrome_extensions: chrome,
                npm_packages: npm,
                ie_extensions: ie,
                firefox_addons: firefox,
                vul_programs_piechart: totalVul > 0
                    ? Object.entries(vulStats).map(([name, count]) => ({ name, count }))
                    : []
            };

        } else {
            const [deb, rpm, chrome, npm, portage, firefox, snap, pacman, flatpak] = await Promise.all([
                taggedQuery('deb', queries.deb),
                taggedQuery('rpm', queries.rpm),
                taggedQuery('chrome', queries.chrome),
                taggedQuery('npm', queries.npm),
                taggedQuery('portage', queries.portage),
                taggedQuery('firefox', queries.firefox),
                entityManager.query(queries.snap, [host_identifier]).catch((err: unknown) => {
                    logger.warn({ err, host_identifier, source: 'snap' }, 'Failed to query optional package source, returning empty');
                    return [];
                }),
                entityManager.query(queries.pacman, [host_identifier]).catch((err: unknown) => {
                    logger.warn({ err, host_identifier, source: 'pacman' }, 'Failed to query optional package source, returning empty');
                    return [];
                }),
                entityManager.query(queries.flatpak, [host_identifier]).catch((err: unknown) => {
                    logger.warn({ err, host_identifier, source: 'flatpak' }, 'Failed to query optional package source, returning empty');
                    return [];
                })
            ]);

            finalResult = {
                deb,
                rpm,
                snap_packages: snap,
                pacman_packages: pacman,
                flatpak_packages: flatpak,
                chrome_extensions: chrome,
                npm_packages: npm,
                portage_packages: portage,
                firefox_addons: firefox
            };
        }

        logger.debug({ host_identifier, is_windows: isWindows }, 'Node programs retrieved');
        return res.status(200).json(finalResult);

    } catch (err) {
        logger.error({ err, host_identifier }, 'Failed to fetch node programs');
        return res.status(500).json({
            status: 'Error',
            message: "Error in fetching programs list"
        });
    }
};