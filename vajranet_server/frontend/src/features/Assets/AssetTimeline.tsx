/**
 * The observation timeline — "scan 1, scan 2, …" for one machine.
 *
 * Every time any source observed this host it left one asset_observations row:
 * the agent checking in, an nmap sweep, an OpenVAS report someone opened, a
 * Nuclei run, an ARP cache. This lists them newest first (the order the API
 * returns) with the source, the timestamp and the score that attached the
 * observation to this asset; expanding a row shows the full match reason.
 *
 * A timeline has no direct analog on the OpenVAS scanner pages, so rather
 * than force it into a borrowed table/row component it keeps its own
 * connector-line layout — but the card chrome, spacing and header now come
 * from the shared `Panel`/`PlainHeader`/`EmptyState`/`ErrorState` components
 * in scannerUI.tsx, the same ones OpenVASScanDetail.tsx uses, so it visually
 * belongs to the same family. See ADDENDUM 5 in the asset-identity spec.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { ChevronDown, History } from 'lucide-react';
import Pagination from '@/components/ui/pagination';
import { cn } from '@/lib/utils';
import { getAssetObservations } from '@/api/services/assetsApi';
import type { AssetObservation } from '@/api/services/assetsApi';
import { MatchReasonBreakdown } from './IdentityEvidence';
import { SourceBadge, confidenceLevel, formatRelative, formatTimestamp } from './ui';
import {
  Btn, EmptyState, ErrorState, OPENVAS_BRAND, Panel, PlainHeader, TableSkeleton,
} from '../VulnerabilityScanner/scannerUI';
import { TONE_CLASSES } from '../VulnerabilityScanner/scannerTokens';

const DEFAULT_ROWS_PER_PAGE = 25;
const ROWS_PER_PAGE_OPTIONS = [10, 25, 50, 100];

// A single busy host (Docker/veth/bridge interfaces, an authenticated OpenVAS
// scan) can report a dozen-plus IPs/MACs on one observation — rendering every
// value inline turns one collapsed-preview row into a multi-line wall of text.
// Cap the inline preview and let "+N more" carry the true count, same
// treatment (and same cap) as IdentityEvidence.tsx's dropped-value grouping.
const ATTR_SAMPLE_CAP = 4;

interface AssetTimelineProps {
  assetUuid: string;
  /** Bumped by the parent to force a refetch. */
  refreshKey?: number;
}

const AssetTimeline = ({ assetUuid, refreshKey = 0 }: AssetTimelineProps) => {
  const [rows, setRows] = useState<AssetObservation[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(DEFAULT_ROWS_PER_PAGE);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSeqRef = useRef(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const seq = ++fetchSeqRef.current;
    try {
      const result = await getAssetObservations(assetUuid, { rows: rowsPerPage, pageno: page });
      if (seq !== fetchSeqRef.current) return; // stale response, a newer request is in flight
      setRows(result.data ?? []);
      setTotal(result.total ?? 0);
    } catch {
      if (seq !== fetchSeqRef.current) return;
      setRows([]);
      setTotal(0);
      setError("Couldn't load the timeline — try again");
    } finally {
      if (seq === fetchSeqRef.current) setLoading(false);
    }
  }, [assetUuid, page, rowsPerPage]);

  useEffect(() => { load(); }, [load, refreshKey]);
  // rowsPerPage's own reset used to live here too, keyed on [assetUuid,
  // rowsPerPage]: that fired AFTER the effect above had already re-run
  // `load()` once with the OLD page (load's identity changes the instant
  // rowsPerPage changes) -- one wasted request per page-size change,
  // superseded a moment later by the page-1 refetch. Moved to Pagination's
  // onPageSizeChange handler below instead, so setRowsPerPage/setPage/
  // setExpanded batch into the one render `load` reacts to once. assetUuid
  // stays here: it changes via a prop from the parent (switching which
  // asset's timeline this is), not a local event handler, so there is no
  // single handler to batch it into the same way.
  useEffect(() => { setPage(1); setExpanded(null); }, [assetUuid]);

  const totalPages = Math.max(1, Math.ceil(total / rowsPerPage));
  const offset = (page - 1) * rowsPerPage;
  const showSkeleton = loading && rows.length === 0;

  return (
    <Panel className="flex min-h-0 flex-col overflow-hidden">
      <PlainHeader
        brand={OPENVAS_BRAND}
        icon={<History className="size-4" />}
        title="Observation timeline"
        subtitle="Every scan and agent check-in that ever saw this machine, newest first. #1 is the earliest."
      />
      {/* max-h bounds this independently of the sibling Identity-evidence panel:
          without it, `flex-1`/`overflow-auto` have no parent height to fill in a
          plain grid row, so an expanded row with many dropped values grows this
          panel to whatever height its content needs — leaving the shorter
          sibling panel looking like broken blank space beside it. */}
      <div className="min-h-0 max-h-[560px] flex-1 overflow-auto scrollbar-auto-hide hover:scrollbar-auto-show p-4">
        {showSkeleton && <TableSkeleton columns={1} rows={4} />}
        {!showSkeleton && error && (
          <ErrorState message={error} action={<Btn variant="secondary" size="sm" onClick={() => load()}>Retry</Btn>} />
        )}
        {!showSkeleton && !error && rows.length === 0 && (
          <EmptyState icon={<History className="size-6" />} title="No observations recorded for this asset yet" />
        )}

        {!error && rows.length > 0 && (
          <ol className={cn('relative space-y-3 border-l border-slate-200 pl-5 transition-opacity', loading && 'pointer-events-none opacity-60')}>
            {rows.map((observation, index) => {
              // Newest first, so the sequence number counts down the page.
              const sequence = Math.max(1, total - offset - index);
              // Only meaningful on page 1 — the true newest observation, not
              // just the top row of whatever page happens to be showing.
              const isLatest = page === 1 && index === 0;
              const isOpen = expanded === observation.id;
              const attrs = observation.attrs ?? {};
              const ips = attrs.ips ?? [];
              const macs = attrs.macs ?? [];
              const shownIps = ips.slice(0, ATTR_SAMPLE_CAP);
              const hiddenIpsCount = ips.length - shownIps.length;
              const shownMacs = macs.slice(0, ATTR_SAMPLE_CAP);
              const hiddenMacsCount = macs.length - shownMacs.length;
              const scoreTone = confidenceLevel(observation.match_score).tone;
              return (
                <li key={observation.id} className="relative">
                  {/* The newest observation's own dot picks up the brand
                      color instead of the usual gray — a quick visual anchor
                      for "this is the current state" at the top of a list
                      that otherwise reads as one undifferentiated color. */}
                  <span
                    aria-hidden="true"
                    className={cn(
                      'absolute -left-[27px] top-3 flex size-4 items-center justify-center rounded-full border-2 border-white shadow-sm',
                      isLatest ? OPENVAS_BRAND.solid : 'bg-slate-300',
                    )}
                  />
                  <div
                    className={cn(
                      'rounded-xl border bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04)]',
                      isLatest ? 'border-teal-200 ring-1 ring-teal-100' : 'border-slate-200/80',
                    )}
                  >
                    <button
                      type="button"
                      onClick={() => setExpanded(isOpen ? null : observation.id)}
                      aria-expanded={isOpen}
                      className="flex w-full flex-wrap items-center gap-2 px-3.5 py-2.5 text-left transition-colors hover:bg-slate-50/80 rounded-t-xl"
                    >
                      <span className="shrink-0 rounded-md bg-slate-100 px-1.5 py-0.5 text-[11px] font-bold tabular-nums text-slate-500 ring-1 ring-slate-200">
                        #{sequence}
                      </span>
                      {isLatest && (
                        <span className={cn('shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide', OPENVAS_BRAND.softBg, OPENVAS_BRAND.softText)}>
                          Latest
                        </span>
                      )}
                      <SourceBadge source={observation.source} />
                      <span className="text-xs font-medium tabular-nums text-slate-600">{formatTimestamp(observation.observed_at)}</span>
                      <span className="text-[11px] text-black dark:text-slate-400">{formatRelative(observation.observed_at)}</span>
                      <span className="ml-auto flex items-center gap-2">
                        {/* A colored pill rather than plain gray text — the
                            same tone scale ConfidenceBadge uses, so a strong
                            vs. weak match is scannable by color down the
                            whole list instead of requiring every number to
                            be read and mentally compared. */}
                        <span className="inline-flex items-center gap-1 text-[11px] text-black dark:text-slate-400">
                          score
                          <span className={cn('rounded-full px-1.5 py-0.5 text-[11px] font-bold tabular-nums', TONE_CLASSES[scoreTone])}>
                            {observation.match_score}
                          </span>
                        </span>
                        <ChevronDown className={cn('size-4 shrink-0 text-slate-300 transition-transform', isOpen && 'rotate-180')} />
                      </span>
                    </button>

                    <div className="flex flex-wrap items-baseline gap-x-5 gap-y-1.5 border-t border-slate-100 px-3.5 py-2.5 text-[11px] text-black dark:text-slate-400">
                      {/* Uppercase micro-labels rather than bare lowercase words —
                          matches the label convention used everywhere else on this
                          page (KindBadge, column headers) instead of reading like a
                          casual sentence fragment. */}
                      {attrs.hostname && (
                        <span className="inline-flex items-baseline gap-1.5">
                          <span className="text-[10px] font-semibold uppercase tracking-wide text-black dark:text-slate-400">Host</span>
                          <span className="font-mono text-slate-700">{attrs.hostname}</span>
                        </span>
                      )}
                      {ips.length > 0 && (
                        <span className="inline-flex items-baseline gap-1.5">
                          <span className="text-[10px] font-semibold uppercase tracking-wide text-black dark:text-slate-400">IP</span>
                          <span className="font-mono text-slate-700">
                            {shownIps.join(', ')}
                            {hiddenIpsCount > 0 && (
                              <span className="font-sans text-slate-400" title={ips.join(', ')}> +{hiddenIpsCount} more</span>
                            )}
                          </span>
                        </span>
                      )}
                      {macs.length > 0 && (
                        <span className="inline-flex items-baseline gap-1.5">
                          <span className="text-[10px] font-semibold uppercase tracking-wide text-black dark:text-slate-400">MAC</span>
                          <span className="font-mono text-slate-700">
                            {shownMacs.join(', ')}
                            {hiddenMacsCount > 0 && (
                              <span className="font-sans text-slate-400" title={macs.join(', ')}> +{hiddenMacsCount} more</span>
                            )}
                          </span>
                        </span>
                      )}
                      {attrs.os && (
                        <span className="inline-flex items-baseline gap-1.5">
                          <span className="text-[10px] font-semibold uppercase tracking-wide text-black dark:text-slate-400">OS</span>
                          <span className="text-slate-700">{attrs.os}</span>
                        </span>
                      )}
                    </div>

                    {/* Its own footer line rather than `ml-auto` inside the
                        wrapping attrs row above: once that row wraps to a
                        second line, `ml-auto` stranded this alone on its own
                        right-aligned line — technically positioned, but it
                        read as an orphaned scrap of text with nothing to
                        anchor it. A dedicated line reads as what it is: a
                        secondary, muted reference, not another attribute. */}
                    {observation.source_ref && (
                      <div className="truncate border-t border-slate-100 px-3.5 py-1.5 text-[10px] text-slate-400">
                        <span className="font-semibold uppercase tracking-wide">Ref</span>{' '}
                        <span className="font-mono" title="Stable per-host reference to the scan this came from">
                          {observation.source_ref}
                        </span>
                      </div>
                    )}

                    {isOpen && (
                      <div className="border-t border-slate-100 bg-slate-50/60 px-3.5 py-3 rounded-b-xl">
                        <MatchReasonBreakdown reason={observation.match_reason} score={observation.match_score} />
                      </div>
                    )}
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </div>

      {(rows.length > 0 || !loading) && (
        <div className="shrink-0">
          <Pagination
            page={page}
            totalPages={totalPages}
            total={total}
            pageSize={rowsPerPage}
            onPageChange={setPage}
            onPageSizeChange={(size) => { setRowsPerPage(size); setPage(1); setExpanded(null); }}
            pageSizeOptions={ROWS_PER_PAGE_OPTIONS}
            itemLabel="observations"
            className="border-slate-200"
          />
        </div>
      )}
    </Panel>
  );
};

export default AssetTimeline;
