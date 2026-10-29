/**
 * The Burp Suite asset table: one row per distinct website Burp Suite scans
 * have targeted, grouped by normalized host[:port] (GET /api/burpsuite/assets).
 *
 * A sibling of features/Assets/AssetsList.tsx, not a nested copy — Burp Suite
 * has nothing to reconcile across sources (there is only one source: Burp
 * itself), so there is no "include merged" toggle, no identity-confidence
 * column, nothing to soft-merge. Just websites, their current High/Medium/Low
 * issue counts, and how many times they've been scanned.
 *
 * Hosted inside the Vulnerability Scanner tab's Burp Suite sub-view, as its
 * "Assets" tab (features/VulnerabilityScanner/index.tsx), so row selection is
 * reported via `onOpenAsset` rather than a direct navigate() — the parent tab
 * owns how "which asset is open" is represented in the URL, same convention
 * AssetsList.tsx uses.
 *
 * Reuses the shared Panel/PanelHeader/table-shell/pagination conventions from
 * scannerUI.tsx (the same ones BurpsuiteView.tsx's own scan table uses) so
 * this tab reads as part of the same visual family, painted with BURP_BRAND
 * instead of OPENVAS_BRAND.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { motion } from 'motion/react';
import { Globe } from 'lucide-react';
import { cn } from '@/lib/utils';
import Pagination from '@/components/ui/pagination';
import { getBurpsuiteAssets } from '@/api/api';
import type { BurpsuiteAssetListItem } from '@/api/api';
import { IssueSeverityChips, burpStatusTone, formatBurpTimestamp, isBurpStatusActive } from './ui';
import {
  Btn, EmptyState, ErrorState, RowAccentBar, RowChevron, StatusPill, TableSkeleton, TONE_ROW,
} from '../VulnerabilityScanner/scannerUI';

const DEFAULT_ROWS_PER_PAGE = 25;
const ROWS_PER_PAGE_OPTIONS = [10, 25, 50, 100];

interface BurpsuiteAssetsListProps {
  /** Called with the normalized_target of a clicked row; the caller decides how to represent that in the URL. */
  onOpenAsset: (normalizedTarget: string) => void;
  /** Same shared group-scope state VulnerabilityScanner/index.tsx already lifts
   *  for OpenVASScans/NessusScans — null means the caller's own default scope. */
  selectedGroupId: string | null;
}

const BurpsuiteAssetsList = ({ onOpenAsset, selectedGroupId }: BurpsuiteAssetsListProps) => {
  const [rows, setRows] = useState<BurpsuiteAssetListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(DEFAULT_ROWS_PER_PAGE);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Guards against a slower earlier response landing after a newer one and
  // overwriting fresher results — same idiom as AssetsList.tsx.
  const fetchSeqRef = useRef(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const seq = ++fetchSeqRef.current;
    try {
      const result = await getBurpsuiteAssets({ rows: rowsPerPage, pageno: page, groupId: selectedGroupId });
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
  }, [page, rowsPerPage, selectedGroupId]);

  useEffect(() => { load(); }, [load]);
  // Resets to page 1 on a scope change rather than a combined effect that
  // would re-run `load` twice in a row — same reasoning AssetsList.tsx's own
  // comment gives for its includeMerged/rowsPerPage handlers, just keyed here
  // on the one filter this table has (group scope, driven by a prop rather
  // than a local checkbox).
  useEffect(() => { setPage(1); }, [selectedGroupId]);

  const totalPages = Math.max(1, Math.ceil(total / rowsPerPage));
  // Only the first fetch (or one starting from empty, e.g. after an error)
  // shows the full-panel skeleton; a background refetch keeps rows mounted
  // and just dims the table while it's in flight.
  const showSkeleton = loading && rows.length === 0;

  return (
    <>
      {!loading && !error && rows.length > 0 && (
        <div className="px-5 py-3 border-b border-slate-200 bg-gradient-to-r from-slate-50 to-white flex items-center justify-end gap-3">
          <span className="text-xs font-medium text-slate-400 shrink-0">
            {total.toLocaleString()} website{total === 1 ? '' : 's'}
          </span>
        </div>
      )}

      {showSkeleton ? (
        <TableSkeleton columns={5} />
      ) : error ? (
        <ErrorState message={error} action={<Btn variant="secondary" onClick={() => load()}>Retry</Btn>} />
      ) : rows.length === 0 ? (
        <EmptyState
          icon={<Globe className="size-6" />}
          title="No websites scanned yet"
          description="Websites appear here once a Burp Suite scan has targeted them."
        />
      ) : (
        <div className="overflow-x-auto bg-slate-50/60">
          <table className="w-full table-fixed text-sm min-w-[760px] border-separate border-spacing-0">
            <thead>
              <tr className="text-left text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                <th className="w-[34%] whitespace-nowrap px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Website</th>
                <th className="w-[26%] whitespace-nowrap px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Severity</th>
                <th className="w-[12%] whitespace-nowrap px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Scans</th>
                <th className="w-[24%] whitespace-nowrap px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Last Scanned</th>
                <th className="w-[4%] px-3 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]" aria-hidden="true" />
              </tr>
            </thead>
            <tbody className={cn('divide-y divide-slate-200/70 transition-opacity', loading && 'pointer-events-none opacity-60')}>
              {rows.map((asset, i) => {
                const tone = burpStatusTone(asset.last_status);
                const row = TONE_ROW[tone];
                return (
                  <motion.tr
                    key={asset.normalized_target}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.2, delay: Math.min(i, 8) * 0.03 }}
                    onClick={() => onOpenAsset(asset.normalized_target)}
                    onKeyDown={(e) => { if (e.key === 'Enter') onOpenAsset(asset.normalized_target); }}
                    tabIndex={0}
                    role="link"
                    aria-label={`Open ${asset.display_host}`}
                    className={cn(
                      'group cursor-pointer transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-orange-300',
                      row.hover,
                    )}
                  >
                    <td className="relative px-5 py-3 font-semibold text-slate-800 group-hover:text-orange-800 transition-colors">
                      <RowAccentBar colorClass={row.accent} />
                      <div className="truncate">{asset.display_host}</div>
                      <div className="mt-1">
                        <StatusPill label={asset.last_status} tone={tone} pulse={isBurpStatusActive(asset.last_status)} />
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <IssueSeverityChips high={asset.issues_high} medium={asset.issues_medium} low={asset.issues_low} />
                    </td>
                    <td className="px-5 py-3 tabular-nums text-slate-600">{asset.scan_count.toLocaleString()}</td>
                    <td className="whitespace-nowrap px-5 py-3 text-xs font-medium text-slate-500">
                      {formatBurpTimestamp(asset.last_scanned_at)}
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
            itemLabel="websites"
            className="border-slate-200"
          />
        </div>
      )}
    </>
  );
};

export default BurpsuiteAssetsList;
