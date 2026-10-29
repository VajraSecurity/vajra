import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { recheckFimDrift } from '../../api/services/fimApi';
import { errMsg, errStatus } from './constants';
import { safeText } from './safeText';
import { btnGhost } from './styles';
import { AWAITING_TEXT, REFUSAL_TEXT, type BulkSummary, type DriftChangedItem } from './driftSafety';
import { RegText } from './UntrustedText';

/** "Re-check now" for one unconfirmed real-time registry drift (POST /fim/drift/:id/recheck). */
export function RecheckButton({ driftId, compact }: { driftId: number; compact?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: 'ok' | 'warn' | 'err'; text: string } | null>(null);
  const [until, setUntil] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (until <= now) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [until, now]);
  const wait = Math.max(0, Math.ceil((until - now) / 1000));

  const go = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await recheckFimDrift(driftId);
      const secs = Math.max(0, Math.round(Number(r.retryAfterSecs) || 0));
      if (secs > 0) { setUntil(Date.now() + secs * 1000); setNow(Date.now()); }
      setMsg(r.queued
        ? { tone: 'ok', text: 'Check scan requested; the result normally arrives within about a minute. Reload to see it.' }
        : { tone: 'warn', text: `A check scan is already pending; retry in ${secs} s.` });
    } catch (e) {
      const st = errStatus(e);
      setMsg({ tone: 'err', text: st === 404 ? 'This drift is not visible to you (or no longer exists).'
        : st === 409 ? `No check scan is possible: the drift is not an open real-time registry drift (it may already be confirmed or resolved; reload). ${errMsg(e, '')}`
          : errMsg(e, 'Re-check request failed') });
    } finally { setBusy(false); }
  };

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <button type="button" className={compact ? `${btnGhost} px-2 py-1 text-xs` : btnGhost} disabled={busy || wait > 0} onClick={go}>
        <RefreshCw className={`h-3.5 w-3.5 ${busy ? 'animate-spin' : ''}`} />{wait > 0 ? `Re-check in ${wait} s` : busy ? 'Requesting...' : 'Re-check now'}
      </button>
      {msg && <span role="status" className={`text-xs ${msg.tone === 'ok' ? 'text-emerald-700 dark:text-emerald-300' : msg.tone === 'warn' ? 'text-amber-700 dark:text-amber-300' : 'text-red-700 dark:text-red-300'}`}>{safeText(msg.text)}</span>}
    </span>
  );
}

/**
 * The server refused an approval because drift changed after it was displayed. Shows old (what the
 * analyst saw) vs new values; nothing was approved and nothing is retried automatically.
 */
export type DriftBefore = Record<string, { newSha256: string | null; changeType: string; lastSeenAt: number | null; label?: string }>;

export function DriftChangedNotice({ info, before }: {
  info: { message: string; items: DriftChangedItem[] };
  before: DriftBefore;
}) {
  const fmt = (t: number | null | undefined) => (t ? new Date(t * 1000).toLocaleString() : '-');
  return (
    <div role="alert" className="space-y-2 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-500/10 dark:text-red-300">
      <p><b>{safeText(info.message)}</b></p>
      <p className="text-xs">Nothing was approved. The list was reloaded: review the changed item(s) again before deciding.</p>
      {info.items.length > 0 && (
        <ul className="space-y-1 text-xs">
          {info.items.map((c) => {
            const b = before[String(c.id)];
            return (
              <li key={c.id} className="rounded bg-white/60 p-2 dark:bg-white/5">
                <span className="font-semibold">drift #{c.id}</span>{b?.label ? <> <RegText value={b.label} mono /></> : null}
                <span className="block">change: <RegText value={b?.changeType ?? '?'} /> -&gt; <RegText value={c.changeType} /></span>
                <span className="block">SHA-256: <RegText value={b?.newSha256 ?? '-'} mono /> -&gt; <RegText value={c.newSha256 ?? '-'} mono /></span>
                <span className="block">last seen: {fmt(b?.lastSeenAt)} -&gt; {fmt(c.lastSeenAt)}</span>
                {c.newAttrs != null && <span className="block">new attributes: <RegText value={typeof c.newAttrs === 'string' ? c.newAttrs : JSON.stringify(c.newAttrs)} mono /></span>}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/** Chip + re-check for an unconfirmed real-time registry drift. */
export function AwaitingConfirmation({ driftId }: { driftId: number }) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg bg-blue-50 px-3 py-2 text-sm text-blue-900 dark:bg-blue-500/10 dark:text-blue-200">
      <span><b>{AWAITING_TEXT}.</b> A real-time registry change cannot be approved until a check scan confirms it; Reject and Ignore stay available.</span>
      <RecheckButton driftId={driftId} compact />
    </div>
  );
}

/**
 * Result of a multi-item approve / close where some items were NOT processed. States plainly how
 * many were done and lists every item that was not, with the reason; the items needing re-review
 * stay open (and selected in the list) for a new decision.
 */
export function BulkRefusedNotice({ summary, total, verb, unit, labelOf, before }: {
  summary: BulkSummary;
  total: number;
  /** e.g. 'approved', 'closed'. */
  verb: string;
  /** e.g. 'drift item', 'alert'. */
  unit: string;
  labelOf: (id: number) => string | null | undefined;
  /** What the analyst saw, keyed by drift id. */
  before: DriftBefore;
}) {
  const review = summary.refused.filter((r) => r.reason !== 'skipped').length;
  return (
    <div role="alert" data-testid="fim-bulk-refused" className="space-y-2 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:bg-amber-500/10 dark:text-amber-200">
      <p><b>Partially done: {summary.done.length} of {total} {unit}(s) {verb}; {summary.refused.length} NOT {verb}.</b></p>
      <p className="text-xs">{review > 0 ? `${review} item(s) need re-review and are still open: they stay selected in the reloaded list. Review them again before deciding.` : 'The items below were not processed.'}</p>
      <ul className="space-y-1 text-xs">
        {summary.refused.map((r) => {
          const label = labelOf(r.id);
          const b = r.driftId != null ? before[String(r.driftId)] : undefined;
          return (
            <li key={r.id} data-testid={`fim-refused-${r.id}`} className="rounded bg-white/60 p-2 dark:bg-white/5">
              <span className="font-semibold">{unit} #{r.id}</span>{label ? <> <RegText value={label} mono /></> : null}
              <span className="block font-semibold">{REFUSAL_TEXT[r.reason]}</span>
              {r.reason === 'drift_changed' && r.current && (
                <>
                  <span className="block">change: <RegText value={b?.changeType ?? '?'} /> -&gt; <RegText value={r.current.changeType} /></span>
                  <span className="block">SHA-256: <RegText value={b?.newSha256 ?? '-'} mono /> -&gt; <RegText value={r.current.newSha256 ?? '-'} mono /></span>
                </>
              )}
              {r.reason === 'awaiting_confirmation' && r.driftId != null && <span className="mt-1 block"><RecheckButton driftId={r.driftId} compact /></span>}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
