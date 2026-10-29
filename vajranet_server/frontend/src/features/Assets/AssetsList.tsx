/**
 * The asset table: one row per resolved machine.
 *
 * Reads GET /api/assets, which defaults to `merged_into IS NULL` (the
 * "Include merged" checkbox below opts into the rest). Group Admins see only
 * assets in their own groups; assets no agent ever claimed (owner_group_id
 * NULL) reach Super Administrators only.
 *
 * Hosted inside the Vulnerability Scanner tab's OpenVAS sub-view, as its
 * "Assets" tab (features/VulnerabilityScanner/index.tsx), rather than a route
 * of its own, so row selection is reported via `onOpenAsset` instead of a
 * direct navigate() — the parent tab decides how to represent "which asset is
 * open" in the URL.
 *
 * Renders as the body of the `Panel`/`PanelHeader` the parent (index.tsx)
 * wraps it in — the same table-shell/row-accent-bar/pagination-footer
 * conventions OpenVASScans.tsx uses for its task table, so Assets reads as
 * part of the same visual family instead of keeping its own bespoke markup.
 * See ADDENDUM 5 in the asset-identity spec.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { motion } from 'motion/react';
import { HelpCircle, Layers } from 'lucide-react';
import { cn } from '@/lib/utils';
import Pagination from '@/components/ui/pagination';
import { getAssets } from '@/api/services/assetsApi';
import type { AssetListItem } from '@/api/services/assetsApi';
import {
  Checkbox, ConfidenceBadge, MergedBadge, SourceBadge,
  confidenceLevel, formatTimestamp,
} from './ui';
import {
  Btn, EmptyState, ErrorState, RowAccentBar, RowChevron, SimpleTip, TableSkeleton, TONE_ROW, type Tone,
} from '../VulnerabilityScanner/scannerUI';

const DEFAULT_ROWS_PER_PAGE = 25;
const ROWS_PER_PAGE_OPTIONS = [10, 25, 50, 100];

/** ips is already capped at 5 by the backend; show a few and count the rest. */
const IP_PREVIEW_COUNT = 3;

const OS_LABEL: Record<string, string> = {
  windows: 'Windows',
  linux: 'Linux',
  other: 'Other',
};

/**
 * Which of the shared TONE_ROW tints a row gets — mirrors the priority a
 * person actually cares about: a flagged review beats a soft-merge, which
 * beats the asset's own identity-confidence tone.
 */
// Driven purely by confidence (+ merged status) now, not `needs_review` —
// that flag is sticky (sess never clears once set, even after later scans
// bring stronger evidence — see the removed Status/Review indicator this
// session) and was producing exactly this inconsistency: two rows both
// showing "Strong 80" tinted differently for a reason nothing on screen
// explains. Same confidence now always reads as the same row color.
const rowTone = (asset: AssetListItem): Tone => {
  if (asset.merged_into) return 'neutral';
  return confidenceLevel(asset.identity_confidence).tone;
};

interface AssetsListProps {
  /** Called with the asset_uuid of a clicked row; the caller decides how to represent that in the URL. */
  onOpenAsset: (assetUuid: string) => void;
}

const AssetsList = ({ onOpenAsset }: AssetsListProps) => {
  const [rows, setRows] = useState<AssetListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(DEFAULT_ROWS_PER_PAGE);
  const [includeMerged, setIncludeMerged] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Guards against a slower earlier response landing after a newer one and
  // overwriting fresher results.
  const fetchSeqRef = useRef(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const seq = ++fetchSeqRef.current;
    try {
      const result = await getAssets({
        rows: rowsPerPage,
        pageno: page,
        include_merged: includeMerged || undefined,
      });
      if (seq !== fetchSeqRef.current) return; // stale response, a newer request is in flight
      setRows(result.data ?? []);
      setTotal(result.total ?? 0);
    } catch {
      if (seq !== fetchSeqRef.current) return;
      setRows([]);
      setTotal(0);
      setError("Couldn't load assets — try again");
    } finally {
      if (seq === fetchSeqRef.current) setLoading(false);
    }
  }, [page, rowsPerPage, includeMerged]);

  useEffect(() => { load(); }, [load]);
  // No separate "reset page on filter/page-size change" effect: that used to
  // be its own useEffect keyed on [includeMerged, rowsPerPage], which fires
  // AFTER the effect above already re-ran `load()` once with the OLD page
  // number (load's own identity already changed the moment includeMerged/
  // rowsPerPage changed) -- one wasted network request per toggle, superseded
  // a moment later by the page-1 refetch. setPage(1) is instead called
  // directly in the two handlers that change includeMerged/rowsPerPage below
  // (the checkbox and Pagination's onPageSizeChange), so React 18 batches
  // both state updates into the one render `load` reacts to once.

  const totalPages = Math.max(1, Math.ceil(total / rowsPerPage));
  // Only the first fetch (or one starting from empty, e.g. after an error)
  // shows the full-panel skeleton; a background refetch keeps rows mounted
  // and just dims the table while it's in flight.
  const showSkeleton = loading && rows.length === 0;

  return (
    <>
      <div className="px-5 py-3 border-b border-slate-200 bg-gradient-to-r from-slate-50 to-white flex flex-wrap items-center justify-between gap-3">
        <label className="flex cursor-pointer items-center gap-2 text-xs font-medium text-slate-600">
          <Checkbox
            checked={includeMerged}
            onChange={() => { setIncludeMerged((v) => !v); setPage(1); }}
            aria-label="Include merged assets"
          />
          Include merged
          <SimpleTip
            trigger={
              <button
                type="button"
                aria-label="What does Include merged do?"
                className="inline-flex items-center rounded-full text-slate-400 hover:text-slate-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300"
              >
                <HelpCircle className="size-3.5" />
              </button>
            }
            panelClassName="w-64"
          >
            Also show assets that were resolved as duplicates and soft-merged into another asset
            (each tagged with which one). Hidden by default so the list only shows the live,
            canonical machines.
          </SimpleTip>
        </label>
        {!loading && !error && (
          <span className="text-xs font-medium text-slate-400 shrink-0">
            {total.toLocaleString()} asset{total === 1 ? '' : 's'}
          </span>
        )}
      </div>

      {showSkeleton ? (
        <TableSkeleton columns={6} />
      ) : error ? (
        <ErrorState message={error} action={<Btn variant="secondary" onClick={() => load()}>Retry</Btn>} />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={<Layers className="size-6" />}
          title="No assets yet"
          description="Assets appear as authenticated OpenVAS scans see hosts."
        />
      ) : (
        <div className="overflow-x-auto bg-slate-50/60">
          {/* table-fixed + explicit per-column widths, rather than leaving
              auto-layout to guess: with one fewer column than this table was
              originally built for, auto-layout either left a large dead gap
              at the right edge or (once nudged with a plain `w-full` hint)
              over-inflated Host far past what its content needs — both
              confirmed live. Fixed percentages settle it deterministically. */}
          <table className="w-full table-fixed text-sm min-w-[900px] border-separate border-spacing-0">
            <thead>
              <tr className="text-left text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                <th className="w-[26%] whitespace-nowrap px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Host</th>
                <th className="w-[19%] whitespace-nowrap px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">IP addresses</th>
                <th className="w-[19%] whitespace-nowrap px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Identity confidence</th>
                <th className="w-[16%] whitespace-nowrap px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Seen by</th>
                <th className="w-[16%] whitespace-nowrap px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Last seen</th>
                <th className="w-[4%] px-3 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]" aria-hidden="true" />
              </tr>
            </thead>
            <tbody className={cn('divide-y divide-slate-200/70 transition-opacity', loading && 'pointer-events-none opacity-60')}>
              {rows.map((asset, i) => {
                const extraIps = Math.max(0, asset.ips.length - IP_PREVIEW_COUNT);
                const row = TONE_ROW[rowTone(asset)];
                return (
                  <motion.tr
                    key={asset.asset_uuid}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.2, delay: Math.min(i, 8) * 0.03 }}
                    onClick={() => onOpenAsset(asset.asset_uuid)}
                    onKeyDown={(e) => { if (e.key === 'Enter') onOpenAsset(asset.asset_uuid); }}
                    tabIndex={0}
                    role="link"
                    aria-label={`Open ${asset.hostname ?? asset.asset_uuid}`}
                    className={cn(
                      'group cursor-pointer transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-teal-300',
                      row.hover,
                    )}
                  >
                    <td className="relative px-5 py-3 font-semibold text-slate-800 group-hover:text-teal-800 transition-colors">
                      <RowAccentBar colorClass={row.accent} />
                      <div className="flex items-center gap-1.5">
                        {/* A scanner-only host genuinely has no name; say so instead of rendering a blank cell. */}
                        {asset.hostname ?? <span className="font-normal italic text-slate-400">No hostname seen</span>}
                        {asset.merged_into && <MergedBadge mergedInto={asset.merged_into} />}
                      </div>
                      <div className="mt-0.5 flex items-center gap-1.5 text-[11px] font-medium text-slate-400">
                        {asset.os_family && <span>{OS_LABEL[asset.os_family] ?? asset.os_family}</span>}
                        {asset.os_family && <span aria-hidden="true">·</span>}
                        <span>{asset.observation_count.toLocaleString()} observation{asset.observation_count === 1 ? '' : 's'}</span>
                      </div>
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-600">
                      {asset.ips.length === 0
                        ? <span className="font-sans text-slate-400">—</span>
                        : (
                          <>
                            {asset.ips.slice(0, IP_PREVIEW_COUNT).join(', ')}
                            {extraIps > 0 && <span className="font-sans text-slate-400"> +{extraIps}</span>}
                          </>
                        )}
                    </td>
                    <td className="px-5 py-3">
                      <ConfidenceBadge value={asset.identity_confidence} />
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex flex-wrap gap-1">
                        {asset.sources.length === 0
                          ? <span className="text-slate-400">—</span>
                          : asset.sources.map((source) => <SourceBadge key={source} source={source} />)}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-5 py-3 tabular-nums text-slate-500">
                      {formatTimestamp(asset.last_seen)}
                    </td>
                    <td className="px-3 py-3"><RowChevron /></td>
                  </motion.tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {(rows.length > 0 || !loading) && (
        <div className="shrink-0">
          <Pagination
            page={page}
            totalPages={totalPages}
            total={total}
            pageSize={rowsPerPage}
            onPageChange={setPage}
            onPageSizeChange={(size) => { setRowsPerPage(size); setPage(1); }}
            pageSizeOptions={ROWS_PER_PAGE_OPTIONS}
            itemLabel="assets"
            className="border-slate-200"
          />
        </div>
      )}
    </>
  );
};

export default AssetsList;
