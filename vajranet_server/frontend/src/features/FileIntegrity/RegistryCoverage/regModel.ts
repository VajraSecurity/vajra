import type {
  FimRegWaiver, FimRegCatalogItem, FimRegChange, FimRegEntry, FimRegLayer, FimRegOp, FimRegRule, FimRegRuleInput,
  FimRegSourceBadge, FimRegStatus, FimRegTier, FimRegWaiverAction, FimSeverity,
} from '../../../api/services/fimApi';

export const TIERS: FimRegTier[] = ['essential', 'recommended', 'comprehensive'];
export const TIER_LABEL: Record<FimRegTier, string> = { essential: 'Essential', recommended: 'Recommended', comprehensive: 'Comprehensive' };
export const TIER_HELP: Record<FimRegTier, string> = {
  essential: 'Autostart pointers, security-control switches and auth packages. On for every Windows node; every entry is protected.',
  recommended: 'Essential plus more persistence and hardening keys. Suggested for servers.',
  comprehensive: 'Recommended plus larger or noisier keys, for high-value servers and investigations.',
};

export const STATUS_META: Record<FimRegStatus, { label: string; cls: string; hint: string }> = {
  in_sync: { label: 'In sync', cls: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300', hint: 'The published policy matches the current configuration.' },
  pending: { label: 'Pending publish', cls: 'bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300', hint: 'The configuration changed since the last publish. Click Apply to publish it.' },
  needs_init: { label: 'Needs init', cls: 'bg-blue-100 text-blue-700 dark:bg-blue-500/15 dark:text-blue-300', hint: 'Some published entries have no baseline yet and are not monitored until initialised.' },
  invalid: { label: 'Invalid', cls: 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-300', hint: 'The configuration cannot be resolved. The last good published config keeps running.' },
  unmanaged: { label: 'Unmanaged', cls: 'bg-slate-100 text-slate-600 dark:bg-white/10 dark:text-slate-300', hint: 'No managed registry policy for this node (feature disabled or not a Windows node).' },
};
export const STATUSES = Object.keys(STATUS_META) as FimRegStatus[];

export const OP_LABEL: Record<FimRegOp, string> = { add: 'Add', disable: 'Disable', exclude: 'Exclude', filter: 'Narrow values', severity: 'Severity' };
export const LAYER_LABEL: Record<FimRegLayer, string> = { profile: 'Profile', group: 'Group', node: 'Node' };

export const WAIVER_ACTION_LABEL: Record<FimRegWaiverAction, string> = {
  disable: 'Disable', narrow: 'Narrow', lower_severity: 'Lower severity', opt_out: 'Opt out',
};

const SEV_RANK: Record<FimSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
export const sevRank = (s: FimSeverity) => SEV_RANK[s] ?? 0;

/** Row actions offered on an entry. */
export type RowAction = 'severity' | 'filter' | 'exclude' | 'disable';

export function sourceLabel(b: FimRegSourceBadge): { label: string; title: string } {
  switch (b.layer) {
    case 'builtin': return { label: `Built-in · ${TIER_LABEL[b.tier] ?? b.tier}`, title: `From the built-in catalog (${b.tier} tier)` };
    case 'profile': return { label: 'Profile', title: `Profile ${b.scopeValue} rule #${b.ruleId} (${b.op})` };
    case 'group': return { label: 'Group', title: `Group ${b.scopeValue} rule #${b.ruleId} (${b.op})` };
    case 'node': return { label: 'Node', title: `Node rule #${b.ruleId} (${b.op})` };
    case 'merge': return { label: 'Merged', title: `Identical patterns merged from: ${b.from.join(', ')}` };
    case 'carve': return { label: 'Carved', title: `Carved out of ${b.from}` };
    default: return { label: 'Unknown', title: '' };
  }
}

export function isNarrowingFilter(current: string[], next: string[]): boolean {
  if (next.length === 0) return false; // empty = all values = widest
  if (current.length === 0) return true;
  const n = new Set(next.map((v) => v.toLowerCase()));
  return !current.every((v) => n.has(v.toLowerCase()));
}

/** The waiver action a rule needs on a protected entry, or null when the change is free. */
export function waiverNeeded(entry: Pick<FimRegEntry, 'protected' | 'severity' | 'values'>, op: FimRegOp, spec: Record<string, unknown>): FimRegWaiverAction | null {
  if (!entry.protected) return null;
  if (op === 'disable') return 'disable';
  if (op === 'exclude') {
    const iv = (spec.ignoreValues as string[] | undefined) ?? [];
    const ek = (spec.excludeKeys as string[] | undefined) ?? [];
    return iv.length || ek.length ? 'narrow' : null;
  }
  if (op === 'filter') return isNarrowingFilter(entry.values, (spec.values as string[] | undefined) ?? []) ? 'narrow' : null;
  if (op === 'severity') return sevRank(spec.severity as FimSeverity) < sevRank(entry.severity) ? 'lower_severity' : null;
  return null;
}

/** A catalog item shown with the same table as resolved entries (profile view, before rules). */
export function catalogToEntry(c: FimRegCatalogItem): FimRegEntry {
  return {
    slot: null, entryKey: c.id, path: c.path, values: c.values, ignoreValues: c.ignoreValues, excludeKeys: [],
    includeSubkeys: c.includeSubkeys, anchor: c.anchor, hiveScoped: c.hiveScoped, redactValues: c.redactValues,
    severity: c.severity, category: c.category, label: c.label, protected: c.protected, verified: c.verified,
    realtimeRequired: c.realtimeRequired, tier: c.tier, sources: [{ layer: 'builtin', tier: c.tier }], attack: c.attack,
    estimate: c.estimate, fingerprint: '', baseline: null, hives: null, pending: null, needsInit: false,
  };
}

export function tierIncludes(selected: FimRegTier, itemTier: FimRegTier): boolean {
  return TIERS.indexOf(itemTier) <= TIERS.indexOf(selected);
}

/** Rule body without layer/scope (what a preview change and the action modals produce). */
export type RuleDraft = Omit<FimRegRuleInput, 'layer' | 'scopeValue'>;

export function specSummary(op: FimRegOp, spec: Record<string, unknown>): string {
  const list = (k: string) => ((spec[k] as unknown[] | undefined) ?? []).map(String);
  switch (op) {
    case 'severity': return `severity -> ${String(spec.severity ?? '?')}`;
    case 'filter': { const v = list('values'); return v.length ? `values: ${v.join(', ')}` : 'values: all'; }
    case 'exclude': {
      const parts: string[] = [];
      if (list('ignoreValues').length) parts.push(`ignore values: ${list('ignoreValues').join(', ')}`);
      if (list('excludeKeys').length) parts.push(`exclude subkeys: ${list('excludeKeys').join(', ')}`);
      return parts.join('; ') || 'no exclusions';
    }
    case 'add': return spec.path ? `custom key ${String(spec.path)}` : 'catalog entry';
    case 'disable': return 'drop the entry';
    default: return '';
  }
}

export function draftSummary(d: RuleDraft): string {
  return `${OP_LABEL[d.op]} ${d.target}: ${specSummary(d.op, d.spec)}${d.waiverId ? ` (waiver #${d.waiverId})` : ''}`;
}

export function ruleSummary(r: FimRegRule): string {
  return `${OP_LABEL[r.op] ?? r.op} ${r.target}: ${specSummary(r.op, r.spec ?? {})}`;
}

/** Waiver request form data kept with a pending node change; POSTed only during Apply. */
export interface WaiverDraft { entryKey: string; action: FimRegWaiverAction; reason: string; expiresAt: number }

/**
 * One locally collected, not yet persisted node change. With `waiver`, Apply requests that waiver
 * (bound to this exact rule) instead of creating the rule; the rule is created later from the
 * approved waiver ("Apply approved change"). `needsWaiverFor`: the server refused the change as a
 * reduction of protected coverage of that catalog entry; a waiver must be added before Apply.
 */
export interface PendingChange { id: string; change: FimRegChange; summary: string; waiver?: WaiverDraft; needsWaiverFor?: string }

let seq = 0;
export const newPendingId = () => `p${Date.now().toString(36)}${(seq++).toString(36)}`;

/** Changes sent to the preview / saved directly on Apply (waiver-bound changes are not: they wait for approval). */
export function changesOf(p: PendingChange[]): FimRegChange[] {
  return p.filter((x) => !x.waiver).map((x) => x.change);
}

/** The rule body a waiver is bound to. */
export function waiverRuleOf(d: RuleDraft): { op: string; target: string; spec: Record<string, unknown> } {
  return { op: d.op, target: d.target, spec: d.spec };
}

/** Catalog id named by a 422 "protected coverage: <id> ..." refusal of a custom add, else null. */
export function protectedCoverageEntry(message: string | null | undefined): string | null {
  if (!message) return null;
  const m = /^protected coverage:\s*(\S+)/.exec(message.trim());
  return m ? m[1].replace(/[.,;:]+$/, '') : null;
}

export const WAIVER_FLOW_TEXT = "The change itself is not made yet: after a different Super Admin (or a designated approver) approves the waiver, open the waiver and click 'Apply approved change'.";

export function waiverRequestedText(id: number): string {
  return `Waiver #${id} requested. The change is applied after a different Super Admin approves it: open the waiver and click 'Apply approved change'.`;
}

/** Max days for a waiver (falls back to the design value). */
export const WAIVER_MAX_DAYS_DEFAULT = 30;

/** "YYYY-MM-DD" for a date input, local time. */
export function dateInputValue(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** True when a warning text is about slot compaction. */
export function mentionsCompaction(warnings: string[]): boolean {
  return warnings.some((w) => /compact|retired slot|tombstone/i.test(w));
}

/**
 * Target sent for a custom 'add' rule. The contract stores custom targets as custom:<16 hex> computed
 * by the server from the spec; the client cannot compute that id, so it sends this placeholder and
 * the full spec (path, values, ...) and the server assigns the real target.
 */
export const CUSTOM_TARGET = 'custom';

/** Approved, not yet used, unexpired waiver the caller may turn into its rule ("Apply approved change"). */
export function canApplyWaiver(w: FimRegWaiver, isSuperAdmin: boolean, nowMs: number = Date.now()): boolean {
  return w.status === 'approved' && w.ruleId == null && (w.canRevoke || isSuperAdmin) && w.expiresAt * 1000 > nowMs;
}

/** Per-step timeout for interactive multi-step flows (Apply). */
export const STEP_TIMEOUT_MS = 30_000;

/** Rejects with a clear message when `p` does not settle within `ms` (the request may still complete on the server). */
export function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let t: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    t = setTimeout(() => reject(new Error(`${what} timed out after ${Math.round(ms / 1000)} s (it may still complete on the server; reload to check).`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => { if (t) clearTimeout(t); });
}

/** Shown wherever registry settings / health are shown when settings.historyKeyed === false. */
export const HISTORY_UNKEYED_TEXT = 'History hash chain is NOT keyed (FIM_HISTORY_HMAC_KEY missing; FIM_HISTORY_ALLOW_UNKEYED=1): tamper evidence is weaker';

/** true only when the server explicitly reports an unkeyed chain (older servers omit the field). */
export const historyUnkeyed = (s: { historyKeyed?: boolean } | null | undefined) => s?.historyKeyed === false;

export interface ChainView { status: 'ok' | 'unverifiable' | 'broken'; tone: 'ok' | 'warn' | 'error'; headline: string; detail: string | null }

/**
 * How the history hash chain is presented. Three states with accurate wording: only `broken`
 * (a real mismatch) suggests tampering; `unverifiable` means it cannot be checked right now.
 * Older servers without chainStatus fall back to chainOk.
 */
export function chainView(d: {
  chainOk: boolean; chainBrokenAt: number | null; chainStatus?: string; chainReason?: string | null;
  chainKeyed?: boolean; chainAnchored?: boolean; chainUnkeyedRows?: number;
}): ChainView {
  const status = d.chainStatus === 'ok' || d.chainStatus === 'unverifiable' || d.chainStatus === 'broken' ? d.chainStatus : d.chainOk ? 'ok' : 'broken';
  const reason = typeof d.chainReason === 'string' && d.chainReason.trim() ? d.chainReason.trim() : null;
  if (status === 'broken') {
    return {
      status, tone: 'error',
      headline: `Hash chain broken${d.chainBrokenAt != null ? ` at row ${d.chainBrokenAt}` : ''}${reason ? `: ${reason}` : ''}`,
      detail: 'The stored history does not match its hash chain: it may have been tampered with. The server-side integrity check (reconcile job) raises a critical alert for this; a Super Administrator should review the history.',
    };
  }
  if (status === 'unverifiable') {
    return {
      status, tone: 'warn',
      headline: `Integrity cannot be verified right now${reason ? `: ${reason}` : ''}`,
      detail: 'This is not evidence of tampering: the chain could not be checked (for example, the history key is unavailable). Re-check once the server is fixed.',
    };
  }
  const extras: string[] = [];
  if (d.chainUnkeyedRows && d.chainUnkeyedRows > 0) extras.push(`${d.chainUnkeyedRows} row(s) were written without the history key`);
  if (d.chainAnchored === false) extras.push('the chain head is not anchored');
  if (d.chainKeyed === false) {
    return { status, tone: 'warn', headline: 'Hash chain consistent, but NOT keyed: tamper evidence is weaker', detail: extras.length ? `${extras.join('; ')}.` : null };
  }
  return { status, tone: 'ok', headline: 'Hash chain verified', detail: extras.length ? `${extras.join('; ')}.` : null };
}
