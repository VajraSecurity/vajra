/**
 * Windows maintained-app software install/uninstall management.
 *
 * Unrelated to controllers/nodes/patch_management.ts (Linux OS-package
 * osupdate patching) — this feature installs/uninstalls third-party
 * software (browsers, editors, utilities — vendor installers, not Windows
 * Update KBs) via the Windows agent's `patchManagement` module. See
 * WINDOWS_AGENT_PATCH_MANAGEMENT.md for the full agent-side wire contract.
 *
 * The catalog (maintained_apps / maintained_app_versions) is populated offline by
 * scripts/import-maintained-apps-catalog.ts — nothing here ever writes
 * install_script/uninstall_script text.
 *
 * Every route is Super-Admin-only (see routes/api/windowsPatchManagement.ts)
 * — same risk class as routes/api/patch.ts (dispatches code execution on a
 * host). The install/uninstall trigger additionally requires MFA, mirroring
 * agent_cert_provisioning.ts's generateCertProvisioningToken and
 * patch_management.ts's own requireMfa (deliberately re-implemented here
 * rather than shared — this codebase's stated convention).
 *
 * Dispatch itself is NOT done here: /install builds a WsActionProposal and
 * hands it to services/pendingActions.ts, exactly like an AI-proposed
 * action. The frontend confirms through the existing
 * POST /api/ai/confirm/:id route — reusing the one confirm-and-dispatch
 * path this codebase has for every high-risk agent action, AI-triggered or
 * not, rather than adding a second one.
 */

import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';
import { dbSourceConnection } from '../../index';
import { VajraUser } from '../../orm/entities/users/Users';
import { JwtPayload } from '../../types/JwtPayload';
import { getUserNodeScope, assertHostInScope, assertCanActOnHost, scopeGroupIds } from '../../utils/nodeScope';
import { validateWsAction, WsActionProposal } from '../../mcp/guardrails';
import { verifyTotpCode } from '../../utils/totp';
import { createPendingAction } from '../../services/pendingActions';
import { MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL } from '../../utils/maintainedAppKnownAliases';
import { getLogger } from '../../utils/logger';
import { claimTotpCodeOnce } from '../../utils/redisClient';
import { PATCH_LIST_DEFAULT_ROWS } from '../../consts/pagination';
import { RECENT_ROWS_ID_WINDOW } from '../../consts/database';
import { returningRows } from '../../utils/returningRows';

const logger = getLogger('nodes.windowsPatchManagement');

/**
 * Compares two dotted version strings numerically, segment by segment (e.g.
 * "10.0.19045" vs "10.0.9" — a plain string/lexicographic compare would get
 * this backwards). Missing trailing segments compare as 0, so "1.2" ==
 * "1.2.0". Not real semver (installer version strings aren't guaranteed to
 * be valid semver — 4+ dotted segments like "24.09.1.116" are common and
 * semver rejects those): non-numeric segments fall back to a plain string
 * compare of just that segment rather than throwing.
 * Returns <0 if a<b, 0 if equal, >0 if a>b.
 */
function compareVersions(a: string, b: string): number {
  const partsA = a.trim().split(/[.\-_]/);
  const partsB = b.trim().split(/[.\-_]/);
  const len = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < len; i++) {
    const rawA = partsA[i] ?? '0';
    const rawB = partsB[i] ?? '0';
    const numA = Number(rawA);
    const numB = Number(rawB);
    if (Number.isFinite(numA) && Number.isFinite(numB)) {
      if (numA !== numB) return numA - numB;
    } else if (rawA !== rawB) {
      return rawA < rawB ? -1 : 1;
    }
  }
  return 0;
}

function getFleetDb() {
  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length < 2) return null;
  return dbSources[1];
}

function getUsersDb() {
  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length < 1) return null;
  return dbSources[0];
}

function getJwtPayload(req: Request): JwtPayload | undefined {
  return (req as any).jwtPayload as JwtPayload | undefined;
}

/**
 * Verifies the caller's MFA TOTP. Copied from patch_management.ts's
 * requireMfa — same shape, same library, deliberately not shared (see this
 * file's header comment).
 */
async function requireMfa(req: Request, res: Response, usersDb: any): Promise<VajraUser | null> {
  const jwtPayload = getJwtPayload(req);
  if (!jwtPayload?.id) {
    res.status(401).json({ status: 'Fail', message: 'Unauthorized' });
    return null;
  }
  const { totp_code } = req.body ?? {};
  if (!totp_code) {
    res.status(400).json({ status: 'Fail', message: 'Missing totp_code' });
    return null;
  }
  const user = await usersDb.getRepository(VajraUser).findOne({ where: { id: jwtPayload.id } });
  if (!user || !user.mfa_enabled || !user.mfa_secret) {
    logger.warn({ user_id: jwtPayload.id }, 'Windows patch install/uninstall denied: MFA not enabled for user');
    res.status(403).json({ status: 'Fail', message: 'MFA must be enabled for install/uninstall operations' });
    return null;
  }
  const verified = verifyTotpCode(user.mfa_secret, totp_code);
  if (!verified) {
    logger.warn({ user_id: jwtPayload.id }, 'Windows patch install/uninstall denied: invalid TOTP code');
    res.status(401).json({ status: 'Fail', message: 'Invalid TOTP code' });
    return null;
  }
  if (!(await claimTotpCodeOnce(jwtPayload.id, totp_code))) {
    logger.warn({ user_id: jwtPayload.id }, 'Windows patch install/uninstall denied: TOTP code already used');
    res.status(401).json({ status: 'Fail', message: 'Invalid TOTP code' });
    return null;
  }
  return user;
}

/**
 * GET /api/patch-management/catalog
 * List maintained apps + their current version (script text omitted — this
 * is a browse endpoint, not the dispatch path).
 */
export const listCatalog = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return res.status(500).json({ status: 'Error', message: 'Database connection missing' });

    const rows = await fleetDb.query(
      `SELECT ma.id, ma.slug, ma.name, ma.publisher, ma.category, ma.is_active,
              mav.id AS version_id, mav.version,
              (mav.installer_url IS NOT NULL) AS has_installer_url,
              (mav.sha256 IS NOT NULL) AS has_sha256
         FROM maintained_apps ma
         LEFT JOIN maintained_app_versions mav ON mav.maintained_app_id = ma.id AND mav.is_current = true
        WHERE ma.is_active = true
        ORDER BY ma.name`,
    );

    return res.json({
      status: 'Success',
      count: rows.length,
      apps: rows.map((r: any) => ({
        id: r.id, slug: r.slug, name: r.name, publisher: r.publisher, category: r.category,
        current_version: r.version_id
          ? { id: r.version_id, version: r.version, has_installer_url: r.has_installer_url, has_sha256: r.has_sha256 }
          : null,
      })),
    });
  } catch (err) {
    logger.error({ err }, 'Failed to list maintained-apps catalog');
    return next(err);
  }
};

/**
 * GET /api/patch-management/catalog/:slug
 * One app + its full version history (script text still omitted).
 */
export const getCatalogApp = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return res.status(500).json({ status: 'Error', message: 'Database connection missing' });

    const slug = String(req.params['slug'] ?? '');
    if (!slug) return res.status(400).json({ status: 'Fail', message: 'slug is required' });

    const appRows = await fleetDb.query(`SELECT * FROM maintained_apps WHERE slug = $1`, [slug]);
    if (appRows.length === 0) return res.status(404).json({ status: 'Fail', message: 'App not found' });
    const app = appRows[0];

    const versions = await fleetDb.query(
      `SELECT id, version, is_current, source_ref, created_at,
              (installer_url IS NOT NULL) AS has_installer_url, (sha256 IS NOT NULL) AS has_sha256
         FROM maintained_app_versions
        WHERE maintained_app_id = $1
        ORDER BY created_at DESC`,
      [app.id],
    );

    return res.json({
      status: 'Success',
      app: {
        id: app.id, slug: app.slug, name: app.name, publisher: app.publisher,
        category: app.category, is_active: app.is_active,
        display_name_match: app.display_name_match, fuzzy_match_name: app.fuzzy_match_name,
      },
      versions,
    });
  } catch (err) {
    logger.error({ err }, 'Failed to get maintained-app detail');
    return next(err);
  }
};

/**
 * GET /api/patch-management/availability?host_identifier=&all=
 *
 * Compares maintained_app_versions (is_current) against the host's already-
 * synced `programs` inventory (see node_programs.ts's identical DISTINCT ON
 * (name) / id-window idiom) — this is the PRIMARY availability signal per
 * WINDOWS_AGENT_PATCH_MANAGEMENT.md's server-side spec §3; the agent's own
 * on-demand `check` action is supplementary, not required for this list.
 *
 * Driven FROM the host's installed programs (INNER JOIN out to the catalog),
 * not from the catalog outward — this endpoint only ever reports on software
 * actually present on this host. It never returns catalog apps the host
 * doesn't have installed (that's listCatalog's job, a separate browse-only
 * endpoint); a host with no synced `programs` rows yet correctly returns an
 * empty list here instead of the full catalog. By default only outdated
 * installed apps are returned; pass all=true to also include up_to_date
 * installed apps.
 */
export const getAvailability = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return res.status(500).json({ status: 'Error', message: 'Database connection missing' });

    const hostIdentifier = String(req.query['host_identifier'] ?? '').trim();
    if (!hostIdentifier) return res.status(400).json({ status: 'Fail', message: 'host_identifier is required' });

    const jwtPayload = getJwtPayload(req);
    const scope = jwtPayload?.id ? await getUserNodeScope(jwtPayload.id) : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, hostIdentifier))) {
      logger.warn({ hostIdentifier, userId: jwtPayload?.id }, 'Windows patch availability lookup denied, host out of caller scope');
      return res.status(404).json({ status: 'Fail', message: 'Node not found' });
    }

    const rows = await fleetDb.query(
      `WITH latest_programs AS (
         SELECT DISTINCT ON (name) name, version
           FROM programs
          WHERE host_identifier = $1
            AND id > (SELECT COALESCE(MAX(id), 0) - ${RECENT_ROWS_ID_WINDOW} FROM programs)
            AND name IS NOT NULL AND name <> ''
          ORDER BY name, unixtime DESC
       )
       SELECT DISTINCT ON (x.id) x.id, x.slug, x.name, x.publisher, x.category,
              x.version_id, x.current_version, x.installed_version
         FROM (
           SELECT ma.id, ma.slug, ma.name, ma.publisher, ma.category, ma.display_name_match,
                  mav.id AS version_id, mav.version AS current_version,
                  lp.name AS matched_program_name, lp.version AS installed_version
             FROM latest_programs lp
             -- Word-boundary fuzzy match (not a bare substring ILIKE) plus
             -- the known Store/OEM package aliases — see
             -- utils/maintainedAppKnownAliases.ts's
             -- MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL for the full
             -- rationale (confirmed "Arc" matching "Microsoft.Windows.
             -- Search" false positive, etc.) and why this lives in one
             -- shared constant rather than being copy-pasted here and in
             -- websocket/node.ts's post-install version UPDATE.
             JOIN maintained_apps ma ON ma.is_active = true AND (
               ${MAINTAINED_APP_FUZZY_MATCH_CONDITION_SQL}
             )
             JOIN maintained_app_versions mav ON mav.maintained_app_id = ma.id AND mav.is_current = true
         ) x
        -- A fuzzy_match_name catalog entry (e.g. display_name_match='Java')
        -- can still word-boundary-match several distinct installed program
        -- names (multiple JDK/JRE installs, etc.) — without this DISTINCT
        -- ON, one maintained
        -- app would come back as multiple rows sharing the same
        -- maintained_app_id, which the frontend keys its list on, silently
        -- dropping rows via duplicate React keys. Prefer the exact-name
        -- match when one exists, else the alphabetically-first fuzzy match,
        -- for deterministic output.
        ORDER BY x.id, (LOWER(x.matched_program_name) = LOWER(x.display_name_match)) DESC, x.matched_program_name`,
      [hostIdentifier],
    );
    rows.sort((a: any, b: any) => String(a.name).localeCompare(String(b.name)));

    const includeAll = String(req.query['all'] ?? '').toLowerCase() === 'true';
    const apps = rows
      .map((r: any) => {
        // Real numeric version ordering (see compareVersions above), not a
        // plain (in)equality check — a host running a version *ahead* of the
        // catalog's current_version (e.g. manually upgraded, or a beta
        // build) must not be flagged "outdated"; only a strictly lower
        // installed version is an available update. `programs.version` has
        // no NOT NULL constraint (some registry-derived entries genuinely
        // have no DisplayVersion) — compareVersions would throw on a null
        // input, so treat "installed but version unknown" as needing
        // attention (outdated) rather than crashing the whole request.
        const status = r.installed_version == null || compareVersions(r.installed_version, r.current_version) < 0
          ? 'outdated'
          : 'up_to_date';
        return {
          maintained_app_id: r.id, slug: r.slug, name: r.name, publisher: r.publisher, category: r.category,
          maintained_app_version_id: r.version_id, current_version: r.current_version,
          installed_version: r.installed_version, status,
        };
      })
      .filter((a: any) => includeAll || a.status !== 'up_to_date');

    return res.json({ status: 'Success', host_identifier: hostIdentifier, count: apps.length, apps });
  } catch (err) {
    logger.error({ err }, 'Failed to compute Windows patch availability');
    return next(err);
  }
};

/**
 * POST /api/patch-management/install
 * Body: { host_identifier, maintained_app_version_id, action: 'install'|'uninstall', totp_code, reason? }
 *
 * Creates the windows_patch_jobs row (status='pending') and a pending HITL
 * action — does NOT dispatch. The frontend confirms via the existing
 * POST /api/ai/confirm/:id, which is what actually calls dispatchToAgent.
 */
export const requestInstall = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    const usersDb = getUsersDb();
    if (!fleetDb || !usersDb) return res.status(500).json({ status: 'Error', message: 'Database connection missing' });

    const jwtPayload = getJwtPayload(req);
    if (!jwtPayload?.id) return res.status(401).json({ status: 'Fail', message: 'Unauthorized' });

    const { host_identifier, maintained_app_version_id, action, reason } = req.body ?? {};
    if (!host_identifier || typeof host_identifier !== 'string') {
      return res.status(400).json({ status: 'Fail', message: 'host_identifier is required' });
    }
    const versionId = Number(maintained_app_version_id);
    if (!Number.isInteger(versionId) || versionId <= 0) {
      return res.status(400).json({ status: 'Fail', message: 'maintained_app_version_id is required' });
    }
    if (action !== 'install' && action !== 'uninstall') {
      return res.status(400).json({ status: 'Fail', message: "action must be 'install' or 'uninstall'" });
    }

    const scope = await getUserNodeScope(jwtPayload.id);
    if (!(await assertCanActOnHost(scope, host_identifier))) {
      logger.warn({ host_identifier, userId: jwtPayload.id }, 'Windows patch install/uninstall denied, host out of caller scope');
      return res.status(404).json({ status: 'Fail', message: 'Node not found' });
    }

    const user = await requireMfa(req, res, usersDb);
    if (!user) return; // requireMfa already sent the response

    const rows = await fleetDb.query(
      `SELECT mav.id AS version_id, mav.version, mav.installer_url, mav.sha256,
              mav.install_script, mav.uninstall_script,
              ma.id AS app_id, ma.slug, ma.name, ma.display_name_match, ma.fuzzy_match_name, ma.is_active
         FROM maintained_app_versions mav
         JOIN maintained_apps ma ON ma.id = mav.maintained_app_id
        WHERE mav.id = $1`,
      [versionId],
    );
    if (rows.length === 0) return res.status(404).json({ status: 'Fail', message: 'App version not found' });
    const v = rows[0];
    if (!v.is_active) return res.status(400).json({ status: 'Fail', message: 'App is not active in the catalog' });

    // Reject a malformed catalog entry here rather than letting it reach the
    // agent (which would reject it too, but this gives a clearer error) —
    // mirrors the agent's own installer_url+sha256 pairing rule.
    if ((v.installer_url != null) !== (v.sha256 != null)) {
      logger.error({ versionId }, 'Malformed catalog entry: installer_url/sha256 not paired');
      return res.status(500).json({ status: 'Error', message: 'Catalog entry is malformed (installer_url/sha256 mismatch) — contact an administrator' });
    }

    const jobId = randomUUID();
    const jobPayload = JSON.stringify({
      app_slug: v.slug,
      version: v.version,
      installer_url: v.installer_url,
      sha256: v.sha256,
      install_script: action === 'install' ? v.install_script : undefined,
      uninstall_script: action === 'uninstall' ? v.uninstall_script : undefined,
      display_name_match: v.display_name_match,
      fuzzy: v.fuzzy_match_name,
      timeout_seconds: 1200,
    });

    const proposal: WsActionProposal = {
      action_type: action === 'install' ? 'patch_install' : 'patch_uninstall',
      host_identifier,
      params: { job_id: jobId, job_payload: jobPayload },
      description: `${action === 'install' ? 'Install' : 'Uninstall'} ${v.name} ${v.version} on ${host_identifier}`,
      risk: 'high',
    };
    const validation = validateWsAction(proposal);
    if (!validation.valid) {
      logger.error({ jobId, reason: validation.reason }, 'Windows patch job payload failed guardrail validation before insert');
      return res.status(500).json({ status: 'Error', message: `Internal validation failed: ${validation.reason}` });
    }

    await fleetDb.query(
      `INSERT INTO windows_patch_jobs
         (id, host_identifier, maintained_app_id, maintained_app_version_id, action, status,
          requested_by_user_id, requested_by_email, request_reason)
       VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$8)`,
      [jobId, host_identifier, v.app_id, v.version_id, action, jwtPayload.id, jwtPayload.email ?? null, reason ?? null],
    );

    const hostnameRows = await fleetDb.query(`SELECT hostname FROM nodes WHERE host_identifier = $1 LIMIT 1`, [host_identifier]);
    const hostname = hostnameRows?.[0]?.hostname != null ? String(hostnameRows[0].hostname) : undefined;

    const { id: pendingActionId } = createPendingAction(proposal, hostname, jwtPayload.id);

    logger.info({ jobId, pendingActionId, host_identifier, action, appSlug: v.slug, userId: jwtPayload.id }, 'Windows patch job created, awaiting confirmation');
    return res.json({ status: 'Success', job_id: jobId, pending_action_id: pendingActionId });
  } catch (err) {
    logger.error({ err }, 'Failed to create Windows patch install/uninstall job');
    return next(err);
  }
};

/**
 * GET /api/patch-management/jobs?host_identifier=
 * host_identifier omitted -> every job across hosts in the caller's scope
 * (unrestricted callers see everything), newest first.
 */
const MAX_JOBS_PAGE_SIZE = PATCH_LIST_DEFAULT_ROWS;

export const listJobs = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return res.status(500).json({ status: 'Error', message: 'Database connection missing' });

    const hostIdentifier = req.query['host_identifier'] ? String(req.query['host_identifier']).trim() : null;
    const jwtPayload = getJwtPayload(req);
    const scope = jwtPayload?.id ? await getUserNodeScope(jwtPayload.id) : { unrestricted: false as const, groups: [] };

    // Bounded limit/offset paging. Defaults and clamps to MAX_JOBS_PAGE_SIZE so callers
    // that pass neither param see an unchanged response shape, while callers that need
    // more than the newest page can reach it via `offset`.
    const rawLimit = req.query['limit'] ? parseInt(String(req.query['limit']), 10) : MAX_JOBS_PAGE_SIZE;
    const limit = Number.isFinite(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, MAX_JOBS_PAGE_SIZE) : MAX_JOBS_PAGE_SIZE;
    const rawOffset = req.query['offset'] ? parseInt(String(req.query['offset']), 10) : 0;
    const offset = Number.isFinite(rawOffset) && rawOffset > 0 ? rawOffset : 0;

    let rows: any[];
    if (hostIdentifier) {
      if (!(await assertHostInScope(scope, hostIdentifier))) {
        logger.warn({ hostIdentifier, userId: jwtPayload?.id }, 'Windows patch job list denied, host out of caller scope');
        return res.status(404).json({ status: 'Fail', message: 'Node not found' });
      }
      rows = await fleetDb.query(
        `SELECT wpj.*, ma.slug AS app_slug, ma.name AS app_name, mav.version
           FROM windows_patch_jobs wpj
           JOIN maintained_apps ma ON ma.id = wpj.maintained_app_id
           JOIN maintained_app_versions mav ON mav.id = wpj.maintained_app_version_id
          WHERE LOWER(wpj.host_identifier) = LOWER($1)
          ORDER BY wpj.requested_at DESC
          LIMIT $2 OFFSET $3`,
        [hostIdentifier, limit, offset],
      );
    } else if (scope.unrestricted) {
      rows = await fleetDb.query(
        `SELECT wpj.*, ma.slug AS app_slug, ma.name AS app_name, mav.version
           FROM windows_patch_jobs wpj
           JOIN maintained_apps ma ON ma.id = wpj.maintained_app_id
           JOIN maintained_app_versions mav ON mav.id = wpj.maintained_app_version_id
          ORDER BY wpj.requested_at DESC
          LIMIT $1 OFFSET $2`,
        [limit, offset],
      );
    } else {
      rows = await fleetDb.query(
        `SELECT wpj.*, ma.slug AS app_slug, ma.name AS app_name, mav.version
           FROM windows_patch_jobs wpj
           JOIN maintained_apps ma ON ma.id = wpj.maintained_app_id
           JOIN maintained_app_versions mav ON mav.id = wpj.maintained_app_version_id
           JOIN nodes n ON n.host_identifier = wpj.host_identifier
          WHERE n.owner_group_id = ANY($1::text[])
          ORDER BY wpj.requested_at DESC
          LIMIT $2 OFFSET $3`,
        [scopeGroupIds(scope), limit, offset],
      );
    }

    return res.json({
      status: 'Success',
      count: rows.length,
      jobs: rows,
      limit,
      offset,
      has_more: rows.length === limit,
    });
  } catch (err) {
    logger.error({ err }, 'Failed to list Windows patch jobs');
    return next(err);
  }
};

/**
 * GET /api/patch-management/jobs/:job_id
 */
export const getJobDetail = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return res.status(500).json({ status: 'Error', message: 'Database connection missing' });

    const jobId = String(req.params['job_id'] ?? '');
    if (!jobId) return res.status(400).json({ status: 'Fail', message: 'job_id is required' });

    const rows = await fleetDb.query(
      `SELECT wpj.*, ma.slug AS app_slug, ma.name AS app_name, mav.version
         FROM windows_patch_jobs wpj
         JOIN maintained_apps ma ON ma.id = wpj.maintained_app_id
         JOIN maintained_app_versions mav ON mav.id = wpj.maintained_app_version_id
        WHERE wpj.id = $1`,
      [jobId],
    );
    if (rows.length === 0) return res.status(404).json({ status: 'Fail', message: 'Job not found' });
    const job = rows[0];

    const jwtPayload = getJwtPayload(req);
    const scope = jwtPayload?.id ? await getUserNodeScope(jwtPayload.id) : { unrestricted: false as const, groups: [] };
    if (!(await assertHostInScope(scope, job.host_identifier))) {
      logger.warn({ jobId, userId: jwtPayload?.id }, 'Windows patch job detail denied, host out of caller scope');
      return res.status(404).json({ status: 'Fail', message: 'Job not found' });
    }

    return res.json({ status: 'Success', job });
  } catch (err) {
    logger.error({ err }, 'Failed to get Windows patch job detail');
    return next(err);
  }
};

// Stale-job reaper, mirroring patch_management.ts's sweepStalePatchJobs. A
// windows_patch_jobs row can stick at 'pending' two ways: the pending HITL action
// created alongside it (services/pendingActions.ts) expires unconfirmed after
// PENDING_ACTION_TTL_MS without touching the job row, or it was confirmed and
// dispatched but the host was offline or the completion push was lost — this feature has
// no offline-queue fallback the way Linux patch dispatch does.
// STUCK_PENDING_GRACE_MINUTES is well past the HITL TTL so a job a user is still about
// to confirm is never mislabeled.
const STUCK_PENDING_GRACE_MINUTES = 15;
const WINDOWS_PATCH_SWEEP_INTERVAL_MS = 5 * 60 * 1000;

async function sweepStaleWindowsPatchJobs(): Promise<void> {
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb || !fleetDb.isInitialized) return;
    // returningRows unwraps TypeORM's [rows, rowCount] tuple; read raw, `rows.length`
    // is always 2 and the warn below fires on every sweep.
    const rows = returningRows<{ id: string }>(await fleetDb.query(
      `UPDATE windows_patch_jobs
          SET status = 'timed_out', completed_at = NOW(), outcome_reason = 'No completion push arrived in time (job never left pending)'
        WHERE status = 'pending'
          AND requested_at < NOW() - ($1 * INTERVAL '1 minute')
        RETURNING id`,
      [STUCK_PENDING_GRACE_MINUTES],
    ));
    if (rows.length > 0) {
      logger.warn({ timed_out_count: rows.length }, 'Stale Windows patch job sweep relabeled stuck-pending jobs');
    }
  } catch (err) {
    logger.error({ err }, 'Stale Windows patch job sweep failed');
  }
}

setInterval(() => {
  void sweepStaleWindowsPatchJobs();
}, WINDOWS_PATCH_SWEEP_INTERVAL_MS).unref();
