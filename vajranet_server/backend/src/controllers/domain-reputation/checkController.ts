import { Request, Response, NextFunction } from 'express';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { checkVirusTotal } from '../../services/domainReputation/providers/virustotal';
import { checkAbuseIPDB } from '../../services/domainReputation/providers/abuseipdb';
import { checkManualServer } from '../../services/domainReputation/providers/manualServer';
import { normalizeDomainInput, normalizeIpInput } from '../../services/domainReputation/validation';
import { getDomainReputationScopeContext, resolveWriteGroupId } from '../../services/domainReputation/scopeContext';
import type { NormalizedReputationResult, ReputationChecker } from '../../services/domainReputation/providers/types';
import type { DomainReputationProviderName } from '../../orm/entities/fleet/DomainReputationProviderConfig';
import type { DomainReputationTargetType } from '../../orm/entities/fleet/DomainReputationTarget';
import { PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_DOMAIN_REPUTATION } from '../../consts';
import { getLogger } from '../../utils/logger';
import { jwtFrom, clientIpFrom } from '../../utils/requestContext';

const logger = getLogger('controllers.domainReputation.check');

const CHECKERS: Record<DomainReputationProviderName, ReputationChecker> = {
  manual: checkManualServer,
  virustotal: checkVirusTotal,
  abuseipdb: checkAbuseIPDB,
};

function isValidType(value: unknown): value is DomainReputationTargetType {
  return value === 'domain' || value === 'ip';
}

const MAX_ERROR_DETAIL_LEN = 500;

/**
 * Builds the stored row for a provider whose check threw. An axios failure
 * carries the upstream's own JSON error body — for the manual server that's
 * { error, requestId } — and throwing it away leaves an operator debugging a
 * failed check with nothing but "Request failed with status code 400" and a
 * null raw_response. Keep the body in raw_response and prefer its message,
 * with the requestId in the summary so the failure can be correlated with the
 * manual server's own logs.
 */
function errorResultFor(provider: DomainReputationProviderName, reason: any): NormalizedReputationResult {
  const body = reason?.response?.data;
  const rawDetail = typeof body === 'string' ? body : body?.error ?? body?.message ?? body?.summary;
  const detail = typeof rawDetail === 'string' && rawDetail.trim()
    ? rawDetail.trim().slice(0, MAX_ERROR_DETAIL_LEN)
    : null;
  const requestId = typeof body?.requestId === 'string' && body.requestId ? body.requestId : null;

  return {
    provider,
    verdict: 'error',
    score: null,
    summary: [detail || reason?.message || 'Check failed', requestId ? `(requestId: ${requestId})` : null]
      .filter(Boolean)
      .join(' '),
    raw: body ?? null,
    requestId,
  };
}

async function getRepos() {
  const { dbSourceConnection } = await import('../../index');
  const { DomainReputationCheckResult } = await import('../../orm/entities/fleet/DomainReputationCheckResult');
  const ds = dbSourceConnection();
  if (!ds || ds.length < 2 || !ds[1].isInitialized) {
    throw new Error('Fleet database not available');
  }
  return { resultRepo: ds[1].getRepository(DomainReputationCheckResult) };
}

export const manualCheck = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const { value, type, providers } = req.body;

    if (!value || typeof value !== 'string' || !value.trim()) {
      return res.status(400).json({ success: false, message: 'value is required' });
    }
    if (!isValidType(type)) {
      return res.status(400).json({ success: false, message: `type must be 'domain' or 'ip'` });
    }
    if (!Array.isArray(providers) || providers.length === 0) {
      return res.status(400).json({ success: false, message: 'providers must be a non-empty array' });
    }
    const requested = providers.filter((p): p is DomainReputationProviderName => Object.prototype.hasOwnProperty.call(CHECKERS, p));
    if (requested.length === 0) {
      return res.status(400).json({ success: false, message: 'No valid providers requested' });
    }

    const cleanValue = type === 'ip' ? normalizeIpInput(value) : normalizeDomainInput(value);
    if (!cleanValue) {
      return res.status(400).json({ success: false, message: `"${value}" doesn't look like a valid ${type === 'ip' ? 'IP address' : 'domain'}` });
    }

    // 'manual' is never group-scoped, so a check for it alone needs no scope
    // resolution — a Group Admin with zero group memberships can still run a
    // Manual Check. Only requesting virustotal/abuseipdb requires resolving
    // which group's key to use.
    let groupId: string | null = null;
    if (requested.some((p) => p !== 'manual')) {
      const ctx = await getDomainReputationScopeContext(req);
      const resolution = resolveWriteGroupId(ctx, typeof req.body?.group_id === 'string' && req.body.group_id.trim() ? req.body.group_id.trim() : undefined);
      if (!resolution.ok) {
        if (resolution.reason === 'ambiguous') {
          return res.status(400).json({ success: false, message: `group_id is required — you administer multiple groups: ${resolution.actGroupIds.join(', ')}` });
        }
        return res.status(403).json({ success: false, message: 'You can only run a check using a group you administer' });
      }
      groupId = resolution.groupId;
    }

    const { resultRepo } = await getRepos();
    const jwt = jwtFrom(req);

    const settled = await Promise.allSettled(requested.map((provider) => CHECKERS[provider](cleanValue, type, groupId)));

    const results: NormalizedReputationResult[] = settled.map((outcome, idx) => (
      outcome.status === 'fulfilled' ? outcome.value : errorResultFor(requested[idx], outcome.reason)
    ));

    try {
      await Promise.all(results.map((result) => resultRepo.save(resultRepo.create({
        target_id: null,
        group_id: groupId,
        value: cleanValue,
        type,
        provider: result.provider,
        verdict: result.verdict,
        score: result.score,
        summary: result.summary,
        raw_response: result.raw,
        triggered_by: 'manual',
        checked_by_user_id: jwt?.id ?? null,
        checked_by_name: jwt?.name ?? null,
      })).catch((saveErr) => {
        // Tags which specific provider's row failed before it reaches the
        // batch catch below — Promise.all's rejection alone doesn't say
        // which of the N concurrent saves threw, and with several providers
        // checked at once that ambiguity would otherwise require guessing.
        logger.error({ err: saveErr, value: cleanValue, type, provider: result.provider }, 'Failed to persist domain reputation check result for provider');
        throw saveErr;
      })));
    } catch (saveErr) {
      logger.error({ err: saveErr, value: cleanValue, type, providers: requested }, 'Failed to persist domain reputation check results');
      throw saveErr;
    }

    if (jwt?.id) {
      logAuditTrail({
        action: 'DOMAIN_REPUTATION_CHECK',
        status: 'success',
        userId: jwt.id,
        email: jwt.email ?? null,
        ipAddress: clientIpFrom(req),
        userAgent: null,
        details: { value: cleanValue, type, providers: requested, group_id: groupId },
      }).catch(err => logger.error({ err }, 'Failed to log audit trail'));
    }

    const failedCount = results.filter((r) => r.verdict === 'error').length;
    logger.info({ value: cleanValue, type, providers: requested, count: results.length, failedCount }, 'Manual domain reputation check completed');
    return res.status(200).json({ success: true, data: results });
  } catch (err: any) {
    logger.error({ err, value: req.body?.value, type: req.body?.type }, 'Manual domain reputation check failed');
    return res.status(500).json({ success: false, message: err.message || 'Check failed' });
  }
};

export const listHistory = async (req: Request, res: Response, _next: NextFunction) => {
  try {
    const { resultRepo } = await getRepos();
    const ctx = await getDomainReputationScopeContext(req);

    const rows = Math.min(parseInt(req.query.rows as string, 10) || PAGINATION_DEFAULT_ROWS, PAGINATION_MAX_ROWS_DOMAIN_REPUTATION);
    const pageno = Math.max(parseInt(req.query.pageno as string, 10) || 1, 1);
    const offset = (pageno - 1) * rows;

    const search = ((req.query.search as string) ?? '').trim();
    const verdict = ((req.query.verdict as string) ?? '').trim();
    const type = ((req.query.type as string) ?? '').trim();

    // `provider` may be a single value, a comma-separated list, or a repeated
    // query param, so a tab covering multiple providers (e.g. Threat Intel's
    // virustotal+abuseipdb) can page through one combined, correctly-ordered
    // result set instead of merging separately-paginated queries client-side.
    const providerRaw = req.query.provider;
    const providerValues = Array.isArray(providerRaw) ? providerRaw : providerRaw ? [providerRaw] : [];
    const providers = providerValues
      .flatMap((p) => String(p).split(','))
      .map((p) => p.trim())
      .filter(Boolean);

    const qb = resultRepo.createQueryBuilder('r').orderBy('r.id', 'DESC');

    // Group scoping. Unlike a NULL-group *target* — an org-wide watchlist
    // entry every Group Admin is meant to see read-only (isTargetVisible in
    // targetsController.ts) — a NULL-group *result* row is unattributable
    // history with no read-only use case, so it is NOT shown org-wide: this
    // fails closed rather than exposing rows that predate r.group_id or that
    // belong to another group. The checked_by_user_id escape hatch keeps a
    // scoped caller's own ungrouped checks visible to them, which is the
    // Vajra Reputation Engine ('manual') provider path — it never resolves a
    // group (see manualCheck), so those rows are always NULL-group.
    if (!ctx.scope.unrestricted) {
      const viewGroupIds = [...ctx.viewGroupIds];
      const selfId = jwtFrom(req)?.id ?? null;
      if (viewGroupIds.length && selfId != null) {
        qb.andWhere(
          '(r.group_id = ANY(:viewGroupIds) OR (r.group_id IS NULL AND r.checked_by_user_id = :selfId))',
          { viewGroupIds, selfId },
        );
      } else if (viewGroupIds.length) {
        qb.andWhere('r.group_id = ANY(:viewGroupIds)', { viewGroupIds });
      } else if (selfId != null) {
        qb.andWhere('r.group_id IS NULL AND r.checked_by_user_id = :selfId', { selfId });
      } else {
        // No groups and no identifiable caller — nothing is attributable to
        // them, so return an empty page rather than the whole table.
        qb.andWhere('1 = 0');
      }
    }

    if (search) {
      qb.andWhere('r.value ILIKE :search', { search: `%${search}%` });
    }
    if (providers.length === 1) {
      qb.andWhere('r.provider = :provider', { provider: providers[0] });
    } else if (providers.length > 1) {
      qb.andWhere('r.provider IN (:...providers)', { providers });
    }
    if (verdict) {
      qb.andWhere('r.verdict = :verdict', { verdict });
    }
    if (type) {
      qb.andWhere('r.type = :type', { type });
    }

    const [items, total] = await qb.skip(offset).take(rows).getManyAndCount();

    logger.debug({ count: items.length, total, page: pageno }, 'Domain reputation check history retrieved');
    return res.status(200).json({
      success: true,
      total,
      count: items.length,
      page: pageno,
      rows,
      data: items,
    });
  } catch (err: any) {
    logger.error({ err }, 'Failed to load domain reputation check history');
    return res.status(500).json({ success: false, message: err.message || 'Failed to load history' });
  }
};
