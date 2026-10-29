/**
 * Rule Engine proxy routes.
 *
 * Re-exposes the rule engine's unauthenticated internal console
 * (RULE_ENGINE_API_URL, default http://127.0.0.1:8001)
 * under this app's own authenticated /api/rule-engine/* prefix. This file's
 * only jobs are authn/authz and forwarding — no rule storage, validation, or
 * DSL logic lives here, that's all real work done on the other side; see
 * services/ruleEngineClient.ts for the actual outbound calls.
 *
 * Auth convention (mirrors alerts.ts / nodes.ts, with one deliberate
 * departure from policies.ts explained below):
 *   - checkAccessJwt: every route requires a real logged-in session.
 *   - GETs and non-mutating test/validate calls (browsing rules/correlation
 *     rules/lists/feeds/health, POST .../validate, POST /test-event, POST
 *     .../preview) stay at checkAccessJwt only — same "any authenticated
 *     user" bar this app already uses for read-heavy security-data views
 *     (alerts.ts's GET routes). None of these write anything, on either
 *     side.
 *   - Every write that changes detection/enforcement/infra behavior (rules,
 *     correlation rules, threat-intel feeds, live-instance config + reload,
 *     and IP watch-group create/delete/enable-disable) requires
 *     requireSuperAdmin, not requireAdmin. This used to be requireAdmin
 *     (Super Administrator or Group Admin), modeled on policies.ts — but
 *     unlike Policy, none of these resources have any way to scope
 *     *enforcement* to one group: the sibling engine console has no group/
 *     tenant concept at all (flat JSON files, a single global live-instance
 *     process — see services/ruleEngineClient.ts's header comment), so a
 *     Group Admin write here would silently affect the entire fleet, not
 *     just their own group. Giving that capability to every Group Admin
 *     broke tenant isolation; see the code review that caught this.
 *   - The one write genuinely safe to scope: adding/removing individual IPs
 *     within an *existing* IP watch group. That doesn't change which nodes
 *     the resulting detection fires against (still fleet-wide once loaded —
 *     see IpWatchGroupsTab.tsx's notice), but it's a bounded, low-risk
 *     action, and it's the one a Group Admin most plausibly needs day to
 *     day (adding an IP their own group cares about). It's gated by
 *     requireCanActOnRuleEngineResource, a real per-resource ownership
 *     check backed by rule_engine_resource_owners — see
 *     utils/ruleEngineScope.ts's header comment for the full design and why
 *     it fails closed for resources with no assigned owner.
 */

import { Router, Request, Response } from 'express';
import multer from 'multer';
import { checkAccessJwt } from '../../middleware/checkJwt';
import { requireSuperAdmin } from '../../middleware/requireSuperAdmin';
import { checkCsrf } from '../../middleware/checkCSRFToken';
import { apiDataLimiter, apiMutationLimiter } from '../../middleware/rateLimiters';
import { getLogger } from '../../utils/logger';
import * as ruleEngine from '../../services/ruleEngineClient';
import type { RuleEngineResult } from '../../services/ruleEngineClient';
import { getUserNodeScope, actableGroupIds } from '../../utils/nodeScope';
import {
  requireCanActOnRuleEngineResource,
  getRuleEngineResourceOwners,
  setRuleEngineResourceOwner,
  deleteRuleEngineResourceOwner,
} from '../../utils/ruleEngineScope';
import type { JwtPayload } from '../../types/JwtPayload';

const logger = getLogger('routes.rule-engine');
const router = Router();

// Every route requires a real authenticated session.
router.use(checkAccessJwt);

// In-memory only — forwarded straight through as multipart to the engine
// console, never written to disk here.
const csvUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
});

/**
 * `csvUpload.single('file')` used directly as router middleware calls
 * `next(err)` on a MulterError (an oversized file, a missing/wrong
 * multipart field) — that bypasses this file's own `handler()` wrapper
 * entirely and lands in the global error handler, which doesn't special-
 * case MulterError and falls through to a generic 500 (logged as a server
 * fault, plus a stack trace back to the client in development) for what's
 * actually an ordinary 413/400 client error. Wrapping it here catches that
 * case before it ever reaches `next()`.
 */
function handleCsvUpload(req: Request, res: Response, next: (err?: unknown) => void) {
  csvUpload.single('file')(req, res, (err: unknown) => {
    if (!err) { next(); return; }
    if (err instanceof multer.MulterError) {
      const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
      res.status(status).json({ error: err.message });
      return;
    }
    next(err);
  });
}

/** Route param values come back typed string | string[] under this app's Express 5 types; every param this file uses is a single plain path segment, never repeated. */
function param(req: Request, name: string): string {
  return req.params[name] as string;
}

/**
 * Sends the engine's real status+body through unchanged; a network-level
 * failure (engine unreachable) becomes a 502 with a clear message instead
 * of masquerading as the engine's own response.
 *
 * 401/429 get one deliberate exception to "unchanged": the engine has no
 * auth or rate-limiting of its own today (see this file's header comment),
 * so either code can currently only mean something now sits in front of it
 * — not that THIS app's caller has a problem. Passed through verbatim, the
 * frontend's global axios interceptor reads a 401 as ITS OWN session
 * having died (forced logout) and a 429 as ITS OWN rate limit (a banner
 * attributed to this app) — remapped here so a future change on the engine
 * side can't silently sign out or rate-limit every admin browsing rules.
 * Every other status, including a real engine-domain 403 (e.g. "delete a
 * non-custom rule") or 422 (validation), still passes through unchanged —
 * that's the whole point of this function.
 */
function relay(res: Response, result: RuleEngineResult): void {
  if (result.unreachable) {
    res.status(502).json({ error: 'Rule engine console unreachable', detail: result.errorMessage });
    return;
  }
  if (result.status === 401 || result.status === 429) {
    logger.warn({ status: result.status }, 'Rule engine console returned 401/429 — remapped to 502 rather than passed through, since the engine has no auth/rate-limit of its own');
    res.status(502).json({ error: 'Rule engine console returned an unexpected auth/rate-limit response', detail: result.data });
    return;
  }
  res.status(result.status).json(result.data);
}

function handler(fn: (req: Request, res: Response) => Promise<void>) {
  return (req: Request, res: Response) => {
    fn(req, res).catch((err) => {
      logger.error({ err, path: req.originalUrl }, 'Rule engine proxy route threw unexpectedly');
      if (!res.headersSent) res.status(500).json({ error: 'Internal error proxying rule engine request' });
    });
  };
}

// ─── Health ─────────────────────────────────────────────────────────────────

router.get('/health', [apiDataLimiter], handler(async (_req, res) => {
  relay(res, await ruleEngine.getHealth());
}));

// ─── Detection rules ────────────────────────────────────────────────────────

router.get('/rules', [apiDataLimiter], handler(async (req, res) => {
  relay(res, await ruleEngine.listRules(req.query as Record<string, unknown>));
}));

router.get('/rules/:source/:id', [apiDataLimiter], handler(async (req, res) => {
  relay(res, await ruleEngine.getRule(param(req, 'source'), param(req, 'id')));
}));

router.post('/rules/validate', [apiDataLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.validateRule(req.body));
}));

router.post('/rules', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.createRule(req.body));
}));

router.patch('/rules/:source/:id', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.patchRule(param(req, 'source'), param(req, 'id'), req.body));
}));

router.delete('/rules/:source/:id', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.deleteRule(param(req, 'source'), param(req, 'id')));
}));

// ─── Correlation rules ──────────────────────────────────────────────────────

router.get('/correlation-rules', [apiDataLimiter], handler(async (req, res) => {
  relay(res, await ruleEngine.listCorrelationRules(req.query as Record<string, unknown>));
}));

router.get('/correlation-rules/:source/:id', [apiDataLimiter], handler(async (req, res) => {
  relay(res, await ruleEngine.getCorrelationRule(param(req, 'source'), param(req, 'id')));
}));

router.post('/correlation-rules/validate', [apiDataLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.validateCorrelationRule(req.body));
}));

router.post('/correlation-rules', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.createCorrelationRule(req.body));
}));

router.patch('/correlation-rules/:source/:id', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.patchCorrelationRule(param(req, 'source'), param(req, 'id'), req.body));
}));

// ─── Lists / test-event / metrics ──────────────────────────────────────────

router.get('/lists', [apiDataLimiter], handler(async (_req, res) => {
  relay(res, await ruleEngine.getLists());
}));

router.get('/test-event/examples', [apiDataLimiter], handler(async (_req, res) => {
  relay(res, await ruleEngine.getTestEventExamples());
}));

router.post('/test-event', [apiDataLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.postTestEvent(req.body));
}));

router.get('/metrics', [apiDataLimiter], handler(async (_req, res) => {
  relay(res, await ruleEngine.getMetrics());
}));

// Correlation Simulation — not in API_CONTRACT.md/_V2.md; confirmed live by
// reading rule_engine_ui/backend/simulate.py directly (see
// services/ruleEngineClient.ts's comment). Same non-mutating "test" bar as
// /test-event and /rules/validate — feeds a sample/custom event sequence
// through the real engine, persists nothing.
router.get('/simulate-correlation/samples', [apiDataLimiter], handler(async (_req, res) => {
  relay(res, await ruleEngine.getSimulationSamples());
}));

router.post('/simulate-correlation', [apiDataLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.simulateCorrelation(req.body));
}));

// ─── Live instance / reload (v2) — pushes a ruleset + SIGHUP to a real live engine ──

router.get('/live-instance', [apiDataLimiter], handler(async (_req, res) => {
  relay(res, await ruleEngine.getLiveInstance());
}));

router.post('/live-instance', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.setLiveInstance(req.body));
}));

router.post('/live-instance/reload', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (_req, res) => {
  relay(res, await ruleEngine.reloadLiveInstance());
}));

// ─── IP watch groups (v2) ───────────────────────────────────────────────────

// Enriches the list with canManageIps per item — Super Admin always true;
// Group Admin true only if they hold act-level membership on the group
// tracked as this watch group's owner (see utils/ruleEngineScope.ts). The
// frontend uses this to decide whether the "IPs" add/remove control is
// enabled for that row; create/delete/enable-disable stay hidden for every
// non-Super-Admin regardless, since those routes are requireSuperAdmin.
router.get('/ip-watch-groups', [apiDataLimiter], handler(async (req, res) => {
  const result = await ruleEngine.listIpWatchGroups();
  if (result.unreachable) {
    res.status(502).json({ error: 'Rule engine console unreachable', detail: result.errorMessage });
    return;
  }
  if (result.status < 200 || result.status >= 300) {
    res.status(result.status).json(result.data);
    return;
  }

  const items = Array.isArray((result.data as any)?.items) ? ((result.data as any).items as Array<Record<string, unknown>>) : [];
  const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
  const scope = jwtPayload?.id ? await getUserNodeScope(jwtPayload.id) : { unrestricted: false as const, groups: [] };

  let canManageByName: Map<string, boolean>;
  if (scope.unrestricted) {
    canManageByName = new Map(items.map((item) => [String(item.name), true]));
  } else {
    const names = items.map((item) => String(item.name));
    const owners = await getRuleEngineResourceOwners('ip_watch_group', names);
    const groupIds = new Set(actableGroupIds(scope));
    canManageByName = new Map(names.map((name) => {
      const owner = owners.get(name);
      return [name, !!owner && groupIds.has(owner)];
    }));
  }

  const enriched = items.map((item) => ({ ...item, canManageIps: canManageByName.get(String(item.name)) ?? false }));
  res.status(result.status).json({ ...(result.data as object), items: enriched });
}));

// Super Admin only (see this file's header comment). Accepts an optional
// ownerGroupId — a vajranet group id to record as this watch group's owner
// in rule_engine_resource_owners, so a Group Admin on that group can later
// add/remove IPs on it. Stripped before forwarding to the engine, which has
// no idea this concept exists.
router.post('/ip-watch-groups', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  const { ownerGroupId, ...body } = (req.body ?? {}) as Record<string, unknown>;
  const result = await ruleEngine.createIpWatchGroup(body);
  if (!result.unreachable && result.status >= 200 && result.status < 300 && typeof ownerGroupId === 'string' && ownerGroupId.trim()) {
    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    const name = typeof body.name === 'string' ? body.name : undefined;
    if (name) {
      try {
        await setRuleEngineResourceOwner('ip_watch_group', name, ownerGroupId.trim(), jwtPayload?.email ?? null);
      } catch (err) {
        logger.error({ err, name, ownerGroupId }, 'Failed to persist rule engine resource ownership after create');
      }
    }
  }
  relay(res, result);
}));

router.patch('/ip-watch-groups/:name', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.patchIpWatchGroup(param(req, 'name'), req.body));
}));

router.delete('/ip-watch-groups/:name', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  const name = param(req, 'name');
  const result = await ruleEngine.deleteIpWatchGroup(name);
  if (!result.unreachable && result.status >= 200 && result.status < 300) {
    deleteRuleEngineResourceOwner('ip_watch_group', name).catch((err) =>
      logger.error({ err, name }, 'Failed to clean up rule engine resource ownership after delete'),
    );
  }
  relay(res, result);
}));

router.get('/ip-watch-groups/:name/ips', [apiDataLimiter], handler(async (req, res) => {
  relay(res, await ruleEngine.listIpWatchGroupIps(param(req, 'name'), req.query as Record<string, unknown>));
}));

// Scoped, not requireSuperAdmin — see this file's header comment and
// utils/ruleEngineScope.ts for why this is the one Group Admin write.
router.post(
  '/ip-watch-groups/:name/ips',
  [requireCanActOnRuleEngineResource('ip_watch_group', 'name'), apiMutationLimiter, checkCsrf],
  handler(async (req, res) => {
    relay(res, await ruleEngine.addIpWatchGroupIps(param(req, 'name'), req.body));
  }),
);

router.post(
  '/ip-watch-groups/:name/ips/csv',
  [requireCanActOnRuleEngineResource('ip_watch_group', 'name'), apiMutationLimiter, checkCsrf, handleCsvUpload],
  handler(async (req, res) => {
    const file = (req as Request & { file?: Express.Multer.File }).file;
    if (!file) {
      res.status(400).json({ error: 'file is required (multipart field name: "file")' });
      return;
    }
    relay(res, await ruleEngine.importIpWatchGroupIpsCsv(param(req, 'name'), file.buffer, file.originalname, file.mimetype));
  }),
);

router.delete(
  '/ip-watch-groups/:name/ips/:ip',
  [requireCanActOnRuleEngineResource('ip_watch_group', 'name'), apiMutationLimiter, checkCsrf],
  handler(async (req, res) => {
    relay(res, await ruleEngine.deleteIpWatchGroupIp(param(req, 'name'), param(req, 'ip')));
  }),
);

// ─── Threat-intel feeds (v2) ────────────────────────────────────────────────

router.get('/threat-intel-feeds', [apiDataLimiter], handler(async (_req, res) => {
  relay(res, await ruleEngine.listThreatIntelFeeds());
}));

router.post('/threat-intel-feeds', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.createThreatIntelFeed(req.body));
}));

router.patch('/threat-intel-feeds/:name', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.patchThreatIntelFeed(param(req, 'name'), req.body));
}));

router.delete('/threat-intel-feeds/:name', [requireSuperAdmin, apiMutationLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.deleteThreatIntelFeed(param(req, 'name')));
}));

// Real outbound fetch of an operator-configured feed URL, but doesn't persist
// anything — same non-mutating "test" bar as /rules/validate and /test-event.
router.post('/threat-intel-feeds/:name/preview', [apiDataLimiter, checkCsrf], handler(async (req, res) => {
  relay(res, await ruleEngine.previewThreatIntelFeed(param(req, 'name')));
}));

export default router;
