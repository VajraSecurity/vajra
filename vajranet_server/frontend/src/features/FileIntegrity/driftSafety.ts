import type { FimAlert, FimBulkItemResult, FimDrift, FimDriftExpected } from '../../api/services/fimApi';
import { errStatus } from './constants';

type DriftLike = Pick<FimDrift, 'path' | 'kind' | 'policyName' | 'source' | 'reverted' | 'confirmedAt' | 'severity'>;

export const AWAITING_TEXT = 'Waiting for confirmation scan (up to about a minute)';

export const isRegistryDrift = (d: Pick<FimDrift, 'path'>) => typeof d.path === 'string' && d.path.startsWith('registry|');

/** Registry item of a managed (Registry coverage) policy: protected coverage. */
export const isProtectedCoverage = (d: DriftLike) =>
  (d.kind ?? 'file') === 'item' && isRegistryDrift(d) && typeof d.policyName === 'string' && d.policyName.startsWith('Registry coverage: ');

/** Real-time registry drift that no check scan has confirmed yet: Approve is refused by the server. */
export const isUnconfirmed = (d: DriftLike) => d.source === 'realtime' && isRegistryDrift(d) && !d.confirmedAt;

export interface RiskCounts { critical: number; protectedCov: number; reverted: number; unconfirmed: number }

export function riskCounts(items: DriftLike[]): RiskCounts {
  return {
    critical: items.filter((d) => d.severity === 'critical').length,
    protectedCov: items.filter(isProtectedCoverage).length,
    reverted: items.filter((d) => !!d.reverted).length,
    unconfirmed: items.filter(isUnconfirmed).length,
  };
}

export const anyRisk = (c: RiskCounts) => c.critical + c.protectedCov + c.reverted + c.unconfirmed > 0;

/**
 * The server's 409 for approving unconfirmed real-time registry drift:
 * {message:'Awaiting confirmation scan...', errors:['awaiting_confirmation', '<driftId>', ...]}.
 * Returns null for any other error (e.g. the "never hashed" 409).
 */
export function awaitingConfirmation(e: unknown): { message: string; ids: number[] } | null {
  if (errStatus(e) !== 409) return null;
  const data = (e as { response?: { data?: { message?: unknown; errors?: unknown } } })?.response?.data;
  const errors = Array.isArray(data?.errors) ? data.errors : [];
  if (errors[0] !== 'awaiting_confirmation') return null;
  const ids = errors.slice(1).map((x) => Number(x)).filter((n) => Number.isInteger(n) && n > 0);
  const message = typeof data?.message === 'string' && data.message ? data.message : 'Awaiting confirmation scan';
  return { message, ids };
}

const validHash = (h: unknown): h is string => typeof h === 'string' && h.length > 0;

/**
 * `expected` body for approving: the content digest the analyst reviewed for each displayed drift,
 * `{ "<driftId>": { contentHash } }`. Occurrences / last-seen are deliberately NOT sent (a rescan
 * that only bumps them must not invalidate the approval). Null when a drift carries no
 * contentHash (the list must be reloaded before approving).
 */
export function expectedOf(items: Pick<FimDrift, 'id' | 'contentHash'>[]): FimDriftExpected | null {
  const out: FimDriftExpected = {};
  for (const d of items) {
    if (!validHash(d.contentHash)) return null;
    out[String(d.id)] = { contentHash: d.contentHash };
  }
  return out;
}

/**
 * `expected` for approving the alerts' linked drift, keyed by driftId. Alerts without linked drift
 * are excluded; null when a linked drift carries no contentHash (reload first).
 */
export function expectedOfAlerts(alerts: Pick<FimAlert, 'driftId' | 'contentHash'>[]): FimDriftExpected | null {
  const out: FimDriftExpected = {};
  for (const a of alerts) {
    if (a.driftId == null) continue;
    if (!validHash(a.contentHash)) return null;
    out[String(a.driftId)] = { contentHash: a.contentHash };
  }
  return out;
}

export interface DriftChangedItem { id: number; contentHash: string | null; newSha256: string | null; changeType: string; lastSeenAt: number | null; newAttrs: unknown }

/**
 * The server's 409 when a drift changed after it was displayed:
 * {message:'The drift changed since it was reviewed...', errors:['drift_changed', '<json {id,contentHash,newSha256,changeType,lastSeenAt,newAttrs}>', ...]}.
 */
export function driftChanged(e: unknown): { message: string; items: DriftChangedItem[] } | null {
  if (errStatus(e) !== 409) return null;
  const data = (e as { response?: { data?: { message?: unknown; errors?: unknown } } })?.response?.data;
  const errors = Array.isArray(data?.errors) ? data.errors : [];
  if (errors[0] !== 'drift_changed') return null;
  const items: DriftChangedItem[] = [];
  for (const raw of errors.slice(1)) {
    try {
      const o = (typeof raw === 'string' ? JSON.parse(raw) : raw) as Record<string, unknown>;
      const id = Number(o?.id);
      if (!Number.isInteger(id)) continue;
      items.push({
        id,
        contentHash: typeof o.contentHash === 'string' ? o.contentHash : null,
        newSha256: typeof o.newSha256 === 'string' ? o.newSha256 : null,
        changeType: typeof o.changeType === 'string' ? o.changeType : String(o.changeType ?? ''),
        lastSeenAt: typeof o.lastSeenAt === 'number' ? o.lastSeenAt : null,
        newAttrs: o.newAttrs ?? null,
      });
    } catch { /* unparsable entry: ignored, the message still says something changed */ }
  }
  const message = typeof data?.message === 'string' && data.message ? data.message : 'The drift changed since it was reviewed';
  return { message, items };
}

/** Why a bulk item was NOT resolved / closed. */
export type BulkRefusalReason = 'drift_changed' | 'awaiting_confirmation' | 'skipped';
export interface BulkRefusal { id: number; driftId: number | null; reason: BulkRefusalReason; current?: FimBulkItemResult['current'] }
export interface BulkSummary {
  /** Ids the server reports as done (resolved / closed). */
  done: number[];
  /** Requested ids that were NOT done, with the reason. */
  refused: BulkRefusal[];
  /** True when the response carried no per-item results (counts only). */
  unknown: boolean;
}

export const REFUSAL_TEXT: Record<BulkRefusalReason, string> = {
  drift_changed: 'Needs re-review: the content changed since you reviewed it',
  awaiting_confirmation: 'Needs re-review: waiting for a confirmation scan',
  skipped: 'Not processed: already resolved, not visible or not permitted',
};

/**
 * Per-item result of POST /fim/drift/resolve (okOutcome 'resolved', ids = drift ids) or
 * /fim/alerts/close (okOutcome 'closed', ids = alert ids). A requested id missing from `results`
 * counts as skipped, so a partial result can never look like a total success.
 */
export function summarizeBulk(requested: number[], res: { results?: FimBulkItemResult[] | null; ids?: number[] | null } | null | undefined, okOutcome: 'resolved' | 'closed'): BulkSummary {
  const results = Array.isArray(res?.results) ? res.results : null;
  if (!results) {
    const done = Array.isArray(res?.ids) ? res.ids.map(Number) : [];
    return { done, refused: [], unknown: true };
  }
  const byId = new Map<number, FimBulkItemResult>();
  for (const r of results) if (r && Number.isInteger(Number(r.id))) byId.set(Number(r.id), r);
  const done: number[] = [];
  const refused: BulkRefusal[] = [];
  for (const id of requested) {
    const r = byId.get(id);
    if (r && r.outcome === okOutcome) { done.push(id); continue; }
    const reason: BulkRefusalReason = r && (r.outcome === 'drift_changed' || r.outcome === 'awaiting_confirmation') ? r.outcome : 'skipped';
    refused.push({ id, driftId: r?.driftId ?? (okOutcome === 'resolved' ? id : null), reason, ...(r?.current ? { current: r.current } : {}) });
  }
  return { done, refused, unknown: false };
}

/** Refusals that need the analyst to review the item again (not merely skipped). */
export const needsReview = (s: BulkSummary) => s.refused.filter((r) => r.reason !== 'skipped');
