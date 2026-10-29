/**
 * Per-website detail view, hosted inside the Vulnerability Scanner tab's Burp
 * Suite sub-view, as its "Assets" tab (features/VulnerabilityScanner/index.tsx)
 * rather than a route of its own — the tab passes `normalizedTarget` (read
 * from its own `?burpAsset=` query param) and `onBack` to clear it, the same
 * list/detail-within-one-tab convention this app already uses for
 * VulnerabilityScanner/OpenVASScans.tsx's `?taskId=` and features/Assets's
 * `?assetUuid=`.
 *
 * The backend answers 404 both for a target that does not exist and for one
 * out of the caller's scope — deliberately, so this page cannot be used to
 * probe for assets outside a caller's own groups — so both land on the same
 * "not found" state, same as AssetDetail.tsx.
 *
 * Unlike OpenVAS's AssetDetail.tsx, there is no identity evidence to show and
 * no severity-over-time graph to build: Burp Suite's four severity counts
 * (High/Medium/Low/Total) are genuine *siblings* answering one question
 * ("how bad is this site right now"), so — like BurpsuiteScanDetail.tsx's own
 * per-scan severity tiles — they fill one flat StatGrid row exactly, with no
 * need to split "identity" from "activity" the way OpenVAS's AssetDetail.tsx
 * does. What follows is a plain, newest-first table of every raw scan Burp
 * Suite has ever run against this target — no pagination, since the backend
 * already returns the full (typically short) history in one response.
 */
import { useCallback, useEffect, useState } from 'react';
import {
  CalendarPlus, ChevronLeft, Clock, Globe, History, Radar, SearchX,
} from 'lucide-react';
import { getBurpsuiteAsset } from '@/api/api';
import type { BurpsuiteAssetDetail as BurpsuiteAssetDetailDto, BurpsuiteScanSummary } from '@/api/api';
import { IssueSeverityChips, burpStatusTone, formatBurpTimestamp, isBurpStatusActive } from './ui';
import {
  BURP_BRAND, Btn, EmptyState, ErrorState, HeaderSkeleton, Panel, PanelHeader, PlainHeader,
  RowAccentBar, SEVERITY_RING, SEVERITY_TINT, StatGrid, StatGridSkeleton, StatTile, StatusPill,
  TableSkeleton, TONE_ROW,
} from '../VulnerabilityScanner/scannerUI';

interface BurpsuiteAssetDetailProps {
  normalizedTarget: string;
  onBack: () => void;
}

const BurpsuiteAssetDetailPage = ({ normalizedTarget, onBack }: BurpsuiteAssetDetailProps) => {
  const [detail, setDetail] = useState<BurpsuiteAssetDetailDto | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setNotFound(false);
    try {
      const response = await getBurpsuiteAsset(normalizedTarget);
      setDetail(response.data);
    } catch (err) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      if (status === 404) {
        setNotFound(true);
      } else {
        setError("Couldn't load this asset — try again");
      }
      setDetail(null);
    } finally {
      setLoading(false);
    }
  }, [normalizedTarget]);

  useEffect(() => { load(); }, [load]);

  const asset = detail?.asset ?? null;
  const scans: BurpsuiteScanSummary[] = detail?.scans ?? [];

  if (loading) {
    return (
      <div className="space-y-4">
        <Panel><HeaderSkeleton /></Panel>
        <StatGridSkeleton />
        <Panel><TableSkeleton columns={4} /></Panel>
      </div>
    );
  }

  if (notFound) {
    return (
      <div>
        <Btn variant="ghost" onClick={onBack} icon={<ChevronLeft className="size-4" />} className="mb-3">All websites</Btn>
        <Panel>
          <EmptyState icon={<SearchX className="size-6" />} title="Asset not found" description="It either does not exist or belongs to a group you cannot see." />
        </Panel>
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <Btn variant="ghost" onClick={onBack} icon={<ChevronLeft className="size-4" />} className="mb-3">All websites</Btn>
        <Panel>
          <ErrorState message={error} action={<Btn variant="secondary" onClick={() => load()}>Try again</Btn>} />
        </Panel>
      </div>
    );
  }

  if (!asset) return null;

  const tone = burpStatusTone(asset.last_status);

  return (
    <div className="space-y-4">
      <Panel>
        <PanelHeader
          brand={BURP_BRAND}
          icon={<Globe className="size-5" />}
          onBack={onBack}
          title={asset.display_host}
          subtitle={<span className="font-mono">{asset.normalized_target}</span>}
        />
        {/* Activity-at-a-glance strip: same border-t/bg-slate-50/60 treatment
            AssetDetail.tsx and BurpsuiteScanDetail.tsx's own post-header
            strips use, so this reads as the same kind of header extension
            rather than a new pattern. */}
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-slate-100 bg-slate-50/60 px-5 py-3 sm:px-6">
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500">
            <StatusPill label={asset.last_status} tone={tone} pulse={isBurpStatusActive(asset.last_status)} />
          </span>
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500">
            <CalendarPlus className="size-3.5 text-slate-400" />
            First scanned <span className="font-semibold tabular-nums text-slate-700">{formatBurpTimestamp(asset.first_scanned_at)}</span>
          </span>
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500">
            <Clock className="size-3.5 text-slate-400" />
            Last scanned <span className="font-semibold tabular-nums text-slate-700">{formatBurpTimestamp(asset.last_scanned_at)}</span>
          </span>
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500">
            <Radar className="size-3.5 text-slate-400" />
            <span className="font-semibold tabular-nums text-slate-700">{asset.scan_count.toLocaleString()}</span>
            {asset.scan_count === 1 ? ' scan' : ' scans'}
          </span>
        </div>
      </Panel>

      <StatGrid>
        <StatTile index={0} label="High" dot="bg-red-500" value={asset.issues_high} tintClass={SEVERITY_TINT.high} ringClass={SEVERITY_RING.high} />
        <StatTile index={1} label="Medium" dot="bg-orange-400" value={asset.issues_medium} tintClass={SEVERITY_TINT.medium} ringClass={SEVERITY_RING.medium} />
        <StatTile index={2} label="Low" dot="bg-yellow-400" value={asset.issues_low} tintClass={SEVERITY_TINT.low} ringClass={SEVERITY_RING.low} />
        <StatTile index={3} label="Total" dot="bg-slate-400" value={asset.issues_total} />
      </StatGrid>

      <Panel className="overflow-hidden">
        <PlainHeader
          brand={BURP_BRAND}
          icon={<History className="size-4" />}
          title="Scan history"
          subtitle="Every Burp Suite scan that has targeted this website, newest first."
        />
        {scans.length === 0 ? (
          <EmptyState icon={<History className="size-6" />} title="No scans recorded for this website yet" />
        ) : (
          <div className="overflow-x-auto bg-slate-50/60">
            <table className="w-full text-sm min-w-[640px] border-separate border-spacing-0">
              <thead>
                <tr className="text-left text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                  <th className="px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Target</th>
                  <th className="px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Status</th>
                  <th className="px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Severity</th>
                  <th className="px-5 py-3.5 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Scanned</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/70">
                {scans.map((scan) => {
                  const scanTone = burpStatusTone(scan.status);
                  const row = TONE_ROW[scanTone];
                  return (
                    <tr key={scan.id} className={row.hover}>
                      <td className="relative px-5 py-3 font-medium text-slate-700 text-xs break-all">
                        <RowAccentBar colorClass={row.accent} />
                        {scan.target}
                      </td>
                      <td className="px-5 py-3">
                        <StatusPill label={scan.status} tone={scanTone} pulse={isBurpStatusActive(scan.status)} />
                      </td>
                      <td className="px-5 py-3">
                        <IssueSeverityChips high={scan.issues_high} medium={scan.issues_medium} low={scan.issues_low} />
                      </td>
                      <td className="whitespace-nowrap px-5 py-3 text-xs font-medium text-slate-500">
                        {formatBurpTimestamp(scan.created_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
};

export default BurpsuiteAssetDetailPage;
