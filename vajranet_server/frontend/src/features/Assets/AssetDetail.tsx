/**
 * Per-asset detail view, hosted inside the Vulnerability Scanner tab's
 * OpenVAS sub-view, as its "Assets" tab (features/VulnerabilityScanner/
 * index.tsx) rather than a route of its own — the tab passes `assetUuid`
 * (read from its own `?assetUuid=` query param) and `onBack` to clear it, the
 * same list/detail-within-one-tab convention VulnerabilityScanner/
 * OpenVASScans.tsx already uses for `?taskId=`.
 *
 * Pairs the evidence view (what the system knows and what it is worth) with
 * the observation timeline (every scan that ever saw this machine). The
 * backend answers 404 both for an asset that does not exist and for one out of
 * the caller's group scope — deliberately, so the page cannot be used to probe
 * for assets in another group — so both land on the same "not found" state.
 *
 * Shares OpenVASScanDetail.tsx's chrome (`Panel`/`PanelHeader`/`StatGrid`/
 * `StatTile`) but not its flat one-row layout: OpenVAS's severity counts are
 * four *siblings* (High/Medium/Low/Log all answer the same question), while
 * this page's seven fields are two different questions — "who is this
 * machine" vs. "what has it been doing" — that a single undifferentiated
 * StatGrid rendered as one uneven 4-then-3 wrap with no hint either way. Split
 * to match:
 *  - a compact metadata strip under the header for the *activity* facts
 *    (first/last seen, observation count) — exactly what AssetTimeline below
 *    elaborates on, so the strip previews the section it sits above;
 *  - a full, evenly-filled `StatGrid` of exactly the four *identity* facts
 *    (confidence, OS, IPs, MACs) — exactly what IdentityEvidence below
 *    elaborates on, for the same reason.
 * Same fields, same values, no new data — just grouped by what question each
 * one answers instead of listed in one flat row.
 */
import { useCallback, useEffect, useState } from 'react';
import {
  CalendarPlus, ChevronLeft, Clock, Fingerprint, Radar, SearchX,
} from 'lucide-react';
import { getAsset, getAssetObservations } from '@/api/services/assetsApi';
import type { AssetDetail as AssetDetailDto, AssetObservation } from '@/api/services/assetsApi';
import AssetSeverityGraph from './AssetSeverityGraph';
import AssetTimeline from './AssetTimeline';
import IdentityEvidence from './IdentityEvidence';
import {
  ConfidenceBadge, MergedBadge, TONE_TINT,
  confidenceLevel, formatTimestamp,
} from './ui';
import { TONE_DOT } from '../VulnerabilityScanner/scannerTokens';
import {
  Btn, EmptyState, ErrorState, HeaderSkeleton, OPENVAS_BRAND, Panel, PanelHeader, StatGrid, StatGridSkeleton,
  StatTile, TableSkeleton,
} from '../VulnerabilityScanner/scannerUI';

// Same shape the backend validates the path param with; checking it here means
// an obviously wrong id renders a clean message instead of a 400 round-trip.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const OS_LABEL: Record<string, string> = { windows: 'Windows', linux: 'Linux', other: 'Other' };

interface AssetDetailProps {
  assetUuid: string;
  onBack: () => void;
}

const AssetDetailPage = ({ assetUuid, onBack }: AssetDetailProps) => {
  const [detail, setDetail] = useState<AssetDetailDto | null>(null);
  const [latest, setLatest] = useState<AssetObservation | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const valid = UUID_RE.test(assetUuid);

  const load = useCallback(async () => {
    if (!valid) return;
    setLoading(true);
    setError(null);
    setNotFound(false);
    try {
      const response = await getAsset(assetUuid);
      setDetail(response.data);
      // One extra request for the newest observation, so the evidence panel can
      // show the match reason that produced the asset's current state without
      // reaching into the timeline's own paging.
      try {
        const observations = await getAssetObservations(assetUuid, { rows: 1, pageno: 1 });
        setLatest(observations.data?.[0] ?? null);
      } catch {
        // A failed timeline probe must not take the whole page down.
        setLatest(null);
      }
    } catch (err) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      if (status === 404 || status === 400) {
        setNotFound(true);
      } else {
        setError("Couldn't load this asset — try again");
      }
      setDetail(null);
    } finally {
      setLoading(false);
    }
  }, [assetUuid, valid]);

  useEffect(() => { load(); }, [load]);

  const asset = detail?.asset ?? null;

  if (!valid) {
    return (
      <div>
        <Btn variant="ghost" onClick={onBack} icon={<ChevronLeft className="size-4" />} className="mb-3">All assets</Btn>
        <Panel>
          <EmptyState icon={<SearchX className="size-6" />} title="That is not a valid asset id" description="Asset ids are UUIDs assigned when a machine is first seen." />
        </Panel>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <Panel><HeaderSkeleton /></Panel>
        <StatGridSkeleton />
        <div className="grid grid-cols-1 items-stretch gap-5 xl:grid-cols-2">
          <Panel className="flex flex-col"><TableSkeleton columns={3} /></Panel>
          <Panel className="flex flex-col"><TableSkeleton columns={1} /></Panel>
        </div>
      </div>
    );
  }

  if (notFound) {
    return (
      <div>
        <Btn variant="ghost" onClick={onBack} icon={<ChevronLeft className="size-4" />} className="mb-3">All assets</Btn>
        <Panel>
          <EmptyState icon={<SearchX className="size-6" />} title="Asset not found" description="It either does not exist or belongs to a group you cannot see." />
        </Panel>
      </div>
    );
  }

  if (error) {
    return (
      <div>
        <Btn variant="ghost" onClick={onBack} icon={<ChevronLeft className="size-4" />} className="mb-3">All assets</Btn>
        <Panel>
          <ErrorState message={error} action={<Btn variant="secondary" onClick={() => load()}>Try again</Btn>} />
        </Panel>
      </div>
    );
  }

  if (!asset || !detail) return null;

  const confidence = confidenceLevel(asset.identity_confidence);

  return (
    <div className="space-y-4">
      <Panel>
        <PanelHeader
          brand={OPENVAS_BRAND}
          icon={<Fingerprint className="size-5" />}
          onBack={onBack}
          title={
            <span className="inline-flex flex-wrap items-center gap-2">
              {asset.hostname ?? 'Asset'}
              {asset.merged_into && <MergedBadge mergedInto={asset.merged_into} />}
            </span>
          }
          subtitle={<span className="font-mono">{assetUuid}</span>}
        />
        {/* Activity-at-a-glance strip: the three "what has it been doing"
            facts, demoted from full stat tiles to a single compact line right
            under the hero — a preview of the Observation timeline panel
            further down, not a duplicate of it. Same border-t/bg-slate-50/60
            treatment OpenVASScanDetail.tsx uses for its own post-header
            strips (progress bar, stalled banner), so this reads as the same
            kind of header extension rather than a new pattern. */}
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-slate-100 bg-slate-50/60 px-5 py-3 sm:px-6">
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500">
            <CalendarPlus className="size-3.5 text-slate-400" />
            First seen <span className="font-semibold tabular-nums text-slate-700">{formatTimestamp(asset.first_seen)}</span>
          </span>
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500">
            <Clock className="size-3.5 text-slate-400" />
            Last seen <span className="font-semibold tabular-nums text-slate-700">{formatTimestamp(asset.last_seen)}</span>
          </span>
          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500">
            <Radar className="size-3.5 text-slate-400" />
            <span className="font-semibold tabular-nums text-slate-700">{asset.observation_count.toLocaleString()}</span>
            {asset.observation_count === 1 ? ' observation' : ' observations'}
          </span>
        </div>
      </Panel>

      {/* Identity cluster: the four "who is this machine" facts, filling the
          StatGrid's own 4-column row exactly (no more uneven 4-then-3 wrap),
          and previewing the Identity evidence panel further down the same
          way the strip above previews the timeline. */}
      <div>
        <div className="mb-2 flex items-center gap-1.5 px-1">
          <Fingerprint className="size-3.5 text-slate-400" />
          <h3 className="text-xs font-bold uppercase tracking-wide text-slate-400">Identity</h3>
        </div>
        <StatGrid>
          <StatTile
            label="Identity confidence" dot={TONE_DOT[confidence.tone]} valueClassName="text-sm"
            tintClass={TONE_TINT[confidence.tone]} value={<ConfidenceBadge value={asset.identity_confidence} size="md" />}
          />
          <StatTile
            label="Operating system" dot="bg-slate-300" valueClassName="text-sm"
            value={asset.os_family ? (OS_LABEL[asset.os_family] ?? asset.os_family) : <span className="text-slate-400 text-sm font-semibold">Unknown</span>}
          />
          <StatTile
            label="IP addresses" dot="bg-slate-300" valueClassName="text-sm"
            value={asset.ips.length === 0
              ? <span className="text-slate-400 text-sm font-semibold">None seen</span>
              // break-words: a host with several IPs renders a long comma-joined
              // run with no natural break point, which otherwise overflows the
              // tile width instead of wrapping onto a second line.
              : <span className="font-mono font-semibold text-sm break-words">{asset.ips.join(', ')}</span>}
          />
          <StatTile
            label="MAC addresses" dot="bg-slate-300" valueClassName="text-sm"
            value={asset.macs.length === 0
              ? <span className="text-slate-400 text-sm font-semibold">None seen</span>
              : <span className="font-mono font-semibold text-sm break-words">{asset.macs.join(', ')}</span>}
          />
        </StatGrid>
      </div>

      <AssetSeverityGraph assetUuid={asset.asset_uuid} />

      <div className="grid grid-cols-1 items-stretch gap-5 xl:grid-cols-2">
        <IdentityEvidence
          identities={detail.identities}
          latestReason={latest?.match_reason ?? null}
          latestScore={latest?.match_score ?? 0}
          latestObservedAt={latest?.observed_at ?? null}
        />
        <AssetTimeline assetUuid={asset.asset_uuid} />
      </div>
    </div>
  );
};

export default AssetDetailPage;
