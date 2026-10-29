/**
 * The evidence view — the answer to "why does the system think these are the
 * same machine?".
 *
 * Two halves:
 *  - the identities recorded for the asset, grouped by kind and carrying the
 *    weight each contributes to a match (bios_uuid 100, mac 80, hostname 40,
 *    os 10, ip 5, osquery_uuid 0). Identities accumulate and are never
 *    overwritten, so a kind with several values is address/NIC history.
 *  - the match_reason the matcher persisted for a given observation: which
 *    kinds matched, what the runner-up scored, which vetoes fired, and every
 *    value normalisation dropped along with the reason it was dropped.
 */
import { Fragment, useMemo, useState } from 'react';
import {
  ChevronDown, Fingerprint, ScrollText, Scale, Ban, Trash2, CircleCheck, Users,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { AssetIdentityRow, IdentityKind, MatchReason } from '@/api/services/assetsApi';
import {
  DROP_REASON_LABEL, DecisionBadge, KIND_META, KindBadge, VetoBadge, formatTimestamp,
} from './ui';
import { OPENVAS_BRAND, Panel, PlainHeader, TONE_ROW } from '../VulnerabilityScanner/scannerUI';

/** Strongest evidence first, matching the backend's ORDER BY weight DESC. */
const KIND_ORDER: IdentityKind[] = ['bios_uuid', 'mac', 'hostname', 'os', 'ip', 'osquery_uuid'];

/**
 * The score breakdown for a single observation. Rendered both under the
 * identity list (for the most recent observation) and inline in the timeline
 * when a row is expanded.
 */
export function MatchReasonBreakdown({ reason, score }: { reason: MatchReason | null; score: number }) {
  if (!reason) {
    return (
      <p className="text-xs text-slate-400">
        No match reason was recorded for this observation.
      </p>
    );
  }

  const matched = reason.matched ?? [];
  const dropped = reason.dropped ?? [];
  const vetoes = reason.vetoes ?? [];
  const candidates = reason.candidates ?? [];

  // A single busy host (many Docker/veth/bridge interfaces) can drop 30+ MACs
  // for the exact same reason — rendering one full-sentence explanation per
  // value produces a wall of near-identical text. Group by (kind, reason) and
  // say it once, with a few real values as examples rather than all of them.
  // Plain computation, not useMemo: this function already returns early above
  // when `reason` is null, so a hook here would violate the rules of hooks
  // the moment `reason` toggled from null to present between renders.
  const droppedGroups: { kind: (typeof dropped)[number]['kind']; reason: (typeof dropped)[number]['reason']; values: string[] }[] = [];
  {
    const byGroup = new Map<string, { kind: (typeof dropped)[number]['kind']; reason: (typeof dropped)[number]['reason']; values: string[] }>();
    for (const drop of dropped) {
      const key = `${drop.kind}::${drop.reason}`;
      const group = byGroup.get(key);
      if (group) group.values.push(drop.raw || '(empty)');
      else byGroup.set(key, { kind: drop.kind, reason: drop.reason, values: [drop.raw || '(empty)'] });
    }
    droppedGroups.push(...byGroup.values());
  }

  return (
    <div className="space-y-4 text-xs">
      {/* Decision + score as one compact summary strip, set apart from the
          sections below by its own tinted band, rather than sitting as bare
          text at the same visual weight as everything that follows it. */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg border border-slate-200/70 bg-slate-50/70 px-3 py-2">
        <DecisionBadge decision={reason.decision} />
        <span className="inline-flex items-center gap-1 text-black dark:text-slate-400">
          <Scale className="size-3 text-slate-400" />
          Score <span className="font-semibold tabular-nums text-slate-700">{reason.winnerScore ?? score}</span>
          {reason.runnerUpScore !== null && reason.runnerUpScore !== undefined && (
            <> · runner-up <span className="font-semibold tabular-nums text-slate-700">{reason.runnerUpScore}</span></>
          )}
        </span>
      </div>

      {/* Every section below follows the same shape: an icon + label heading,
          then (where there's tabular content) its own bordered white card —
          so "Matched on" and "Dropped before matching" read as distinct,
          scannable groups instead of one long run of same-weight lines. */}
      <section>
        <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-slate-600">
          <CircleCheck className="size-3.5 text-emerald-500" />
          Matched on
        </h4>
        {matched.length === 0 ? (
          <p className="text-slate-400">Nothing matched an existing asset.</p>
        ) : (
          // 2-column grid rather than one column of stacked rows: with
          // usually 3-4 matched kinds, a single tall column left a lot of
          // unused width in the card. Each cell holds its own badge+value
          // pair, so instead of chasing a fixed badge-width column across an
          // entire list, only the two items sharing a row need to fit side
          // by side — min-w-0 lets a long value truncate within its cell
          // rather than pushing the row wider than the card.
          <div className="rounded-lg border border-slate-200/70 bg-white p-2.5">
            <div className="grid grid-cols-2 gap-x-4 gap-y-2">
              {matched.map((identity, i) => (
                <div key={`${identity.kind}-${identity.value}-${i}`} className="flex min-w-0 items-center gap-2">
                  <KindBadge kind={identity.kind} weight={identity.weight} />
                  <span className="truncate font-mono font-semibold text-slate-700" title={identity.value}>
                    {identity.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
        <p className="mt-1.5 text-[11px] font-medium text-slate-400">
          Scoring is per kind, not per value — a host with four matching MACs still scores 80.
        </p>
      </section>

      {vetoes.length > 0 && (
        <section>
          <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-slate-600">
            <Ban className="size-3.5 text-red-400" />
            Vetoes
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {vetoes.map((veto) => <VetoBadge key={veto} veto={veto} />)}
          </div>
          <p className="mt-1.5 text-[11px] font-medium text-slate-400">
            A veto beats the score outright: rather than risk a wrong merge, the matcher keeps the machines apart.
          </p>
        </section>
      )}

      {candidates.length > 0 && (
        <section>
          <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-slate-600">
            <Users className="size-3.5 text-slate-400" />
            Candidates considered
          </h4>
          <div className="rounded-lg border border-slate-200/70 bg-white p-2.5">
            <div className="grid grid-cols-[2.5rem_1fr] items-center gap-x-3 gap-y-1.5">
              {candidates.map((candidate) => (
                <Fragment key={candidate.assetUuid}>
                  <span className="justify-self-end tabular-nums font-semibold text-slate-700">{candidate.score}</span>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate font-mono text-[11px] text-slate-500" title={candidate.assetUuid}>
                      {candidate.assetUuid}
                    </span>
                    {(candidate.vetoedBy ?? []).map((veto) => <VetoBadge key={veto} veto={veto} />)}
                  </div>
                </Fragment>
              ))}
            </div>
          </div>
        </section>
      )}

      {droppedGroups.length > 0 && (
        <section>
          <h4 className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-slate-600">
            <Trash2 className="size-3.5 text-slate-400" />
            Dropped before matching
            <span className="font-medium text-slate-400">({dropped.length})</span>
          </h4>
          {/* Grouped by (kind, reason) rather than one line per value: a busy
              host's Docker/veth/bridge interfaces alone can drop 30+ MACs for
              the identical reason, and repeating the same sentence 30 times
              is the wall of text this used to render. Same fixed first
              column as "Matched on" above, so the dropped values line up in
              a column instead of starting wherever each KindBadge happens to
              end; the reason sits on its own line under the values rather
              than fighting them for space on one row. */}
          <div className="rounded-lg border border-slate-200/70 bg-white p-2.5">
            <div className="grid grid-cols-[6.5rem_1fr] items-start justify-items-start gap-x-3 gap-y-2">
              {droppedGroups.map((group) => {
                const SAMPLE_CAP = 4;
                const shown = group.values.slice(0, SAMPLE_CAP);
                const remaining = group.values.length - shown.length;
                return (
                  <Fragment key={`${group.kind}::${group.reason}`}>
                    <div className="flex items-center gap-1.5 pt-px">
                      <KindBadge kind={group.kind} />
                      {group.values.length > 1 && (
                        <span className="shrink-0 rounded-md bg-slate-100 px-1.5 py-0.5 text-[10px] font-bold tabular-nums text-slate-500 ring-1 ring-slate-200">
                          ×{group.values.length}
                        </span>
                      )}
                    </div>
                    <div>
                      <span className="font-mono font-semibold text-slate-600">
                        {shown.join(', ')}
                        {remaining > 0 && <span className="font-sans text-slate-400"> +{remaining} more</span>}
                      </span>
                      <div className="mt-0.5 text-slate-400">{DROP_REASON_LABEL[group.reason] ?? group.reason}</div>
                    </div>
                  </Fragment>
                );
              })}
            </div>
          </div>
          <p className="mt-1.5 text-[11px] font-medium text-slate-400">
            Values like the all-zero MAC or a generic hostname are held by many machines at once, so matching on them would collapse the fleet into one asset.
          </p>
        </section>
      )}
    </div>
  );
}

interface IdentityEvidenceProps {
  identities: AssetIdentityRow[];
  /** match_reason of the most recent observation, if there is one. */
  latestReason: MatchReason | null;
  latestScore: number;
  latestObservedAt: string | null;
}

const IdentityEvidence = ({ identities, latestReason, latestScore, latestObservedAt }: IdentityEvidenceProps) => {
  const [showBreakdown, setShowBreakdown] = useState(true);

  const grouped = useMemo(() => {
    const byKind = new Map<IdentityKind, AssetIdentityRow[]>();
    for (const identity of identities) {
      const list = byKind.get(identity.kind);
      if (list) list.push(identity);
      else byKind.set(identity.kind, [identity]);
    }
    return KIND_ORDER
      .filter((kind) => byKind.has(kind))
      // Any kind the backend adds later still shows up, just after the known ones.
      .concat([...byKind.keys()].filter((kind) => !KIND_ORDER.includes(kind)))
      .map((kind) => ({ kind, rows: byKind.get(kind) ?? [] }));
  }, [identities]);

  return (
    <Panel className="flex min-h-0 flex-col overflow-hidden">
      <PlainHeader
        brand={OPENVAS_BRAND}
        icon={<Fingerprint className="size-4" />}
        title="Identity evidence"
        subtitle="What the system knows about this machine, and what each piece is worth when matching."
      />
      {/* Same max-h bound as AssetTimeline's scroll body, and for the same
          reason — see the comment there. */}
      <div className="min-h-0 max-h-[560px] flex-1 overflow-auto scrollbar-auto-hide hover:scrollbar-auto-show p-4">
        {grouped.length === 0 ? (
          <p className="py-6 text-center text-sm text-slate-400">
            No identities recorded — every value seen for this host was dropped by normalisation.
          </p>
        ) : (
          // Kind badge + count as a plain (unboxed) group label, then each
          // value as its own bordered card: value on the left, first/last
          // seen stacked as two right-aligned lines rather than two more
          // table columns — reads as "this value, seen this long" per row
          // instead of a dense three-column table.
          <div className="space-y-4">
            {grouped.map(({ kind, rows }) => (
              <div key={kind}>
                <div className="mb-1.5 flex flex-wrap items-center gap-2">
                  <KindBadge kind={kind} />
                  <span className="text-[11px] font-medium text-black dark:text-slate-400">
                    {rows.length} value{rows.length === 1 ? '' : 's'}
                    {rows.length > 1 && (kind === 'ip' || kind === 'mac') && ' — history, newest values are simply added, never overwritten'}
                    {KIND_META[kind]?.weight === 0 && ' — kept as evidence for a human, never used to match'}
                  </span>
                </div>
                <div className="space-y-1.5">
                  {rows.map((row) => (
                    <div
                      key={`${row.kind}-${row.value_norm}`}
                      className="relative flex flex-wrap items-center justify-between gap-x-4 gap-y-1 overflow-hidden rounded-lg border border-slate-200/70 bg-white py-2 pl-4 pr-3 transition-colors hover:bg-slate-50/60"
                    >
                      {/* Left accent tied to the kind's own tone (the same
                          color its KindBadge above uses) — lets the eye sort
                          strong vs. weak evidence down the whole list by
                          color alone, without re-reading every badge. */}
                      <span
                        aria-hidden="true"
                        className={cn('absolute inset-y-0 left-0 w-1', TONE_ROW[KIND_META[kind]?.tone ?? 'neutral'].accent)}
                      />
                      <span className="truncate font-mono text-sm font-semibold text-slate-800">{row.value_norm}</span>
                      <div className="shrink-0 text-right text-[11px] leading-tight">
                        <div className="text-black dark:text-slate-400">first seen {formatTimestamp(row.first_seen)}</div>
                        <div className="text-black dark:text-slate-400">last seen {formatTimestamp(row.last_seen)}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="mt-5 border-t border-slate-100 pt-4">
          <button
            type="button"
            onClick={() => setShowBreakdown((v) => !v)}
            aria-expanded={showBreakdown}
            className="flex w-full items-center justify-between gap-2 text-left text-xs font-bold uppercase tracking-wide text-black dark:text-slate-400 transition-colors hover:text-slate-700"
          >
            <span className="flex items-center gap-1.5">
              <ScrollText className="size-3.5 text-slate-400" />
              How the latest observation was matched
              {latestObservedAt && (
                <span className="font-medium normal-case tracking-normal text-slate-400">
                  · {formatTimestamp(latestObservedAt)}
                </span>
              )}
            </span>
            <ChevronDown className={cn('size-4 shrink-0 transition-transform', showBreakdown && 'rotate-180')} />
          </button>
          {showBreakdown && (
            <div className="mt-3">
              <MatchReasonBreakdown reason={latestReason} score={latestScore} />
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
};

export default IdentityEvidence;
