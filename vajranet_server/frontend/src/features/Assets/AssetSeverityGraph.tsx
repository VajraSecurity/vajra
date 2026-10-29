/**
 * "Did this machine improve, degrade, or stay the same?" — a per-asset trend
 * view of vulnerability findings across every OpenVAS scan that ever saw it,
 * bucketed by the same 4-tier severity scheme already used everywhere else
 * OpenVAS results are shown in this app (VulnerabilityScanner/
 * OpenVASScanDetail.tsx's `getSeverityLevel`; see SeverityCounts in
 * api/services/assetsApi.ts for the exact thresholds).
 *
 * The data is `attrs.extra.severityCounts` on each observation — captured
 * once at ingest time (backend/src/services/assetIdentity/openvasFeeder.ts,
 * 2026-09-08) rather than recomputed here, so this component's only job is to
 * fetch the asset's observations and plot whichever of them happen to carry
 * that field. Older observations from before that change (and any from a
 * source other than OpenVAS) simply have none — they are filtered out rather
 * than shown as a false "zero findings" data point, and the panel says so
 * plainly when there are not yet enough points to plot.
 *
 * DESIGN — one chart, log-scaled Y axis:
 * live data across the fleet (checked directly against Postgres) looks like
 * `{ high: 0-24, medium: 0-39, low: 0-3, log: 50-127 }`, i.e. "log" is
 * routinely 2-10x every other tier combined, while the tiers people actually
 * act on (high/medium/low) sit in a much smaller range that a shared *linear*
 * axis flattens into an invisible hairline. Two headline-card / small-multiples
 * composites were tried and rejected (too much chrome for "a graph"); a
 * logarithmic Y axis solves the actual scale problem on a single ordinary
 * multi-line chart instead of fragmenting into separate mini-charts — the
 * standard technique for plotting series of very different magnitude
 * together (Grafana/Datadog use it for exactly this). Checked against real
 * per-asset history (most assets have only 2-5 scans on record): even with
 * that few points, log-space keeps all four tiers' lines at visibly distinct
 * heights instead of collapsing high/medium/low onto the axis floor, so it
 * reads correctly in both the log-dominated common case and the bare
 * 2-point minimum.
 *
 * A log axis has no representation for 0 (log(0) is undefined), but a tier
 * sitting at 0 is a normal, common data point here (e.g. "medium: 0"). Each
 * series therefore plots `value > 0 ? value : LOG_FLOOR` — a small constant
 * placed exactly at the axis floor so a zero renders as a visible point at
 * the bottom of the chart rather than breaking the scale or vanishing. This
 * floor is a *display-only* substitution: the tooltip below always reads the
 * true stored count (0, not 0.5) for every tier.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ResponsiveContainer, LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip,
} from 'recharts';
import { LineChart as LineChartIcon } from 'lucide-react';
import { getAssetObservations } from '@/api/services/assetsApi';
import {
  Panel, PlainHeader, EmptyState, ErrorState, Btn, OPENVAS_BRAND,
} from '../VulnerabilityScanner/scannerUI';
import { formatTimestamp } from './ui';

/**
 * The exact hex values behind scannerTokens.ts's SEVERITY_META dot colors
 * (`bg-red-500`, `bg-orange-400`, `bg-yellow-400`, `bg-slate-300`) — mirrored
 * here rather than imported because SEVERITY_META carries Tailwind class
 * names, not the raw color values recharts' `stroke` prop needs.
 * Keep these in sync with SEVERITY_META if that palette ever changes.
 */
const SEVERITY_COLORS = {
  high: '#ef4444',
  medium: '#fb923c',
  low: '#facc15',
  log: '#cbd5e1',
} as const;

type SeverityKey = keyof typeof SEVERITY_COLORS;

/** Declared in severity order (high -> log) so the legend and tooltip render
 * in the same convention used everywhere else in this app, rather than
 * whatever order Object.keys hands back. */
const SEVERITY_TIERS: { key: SeverityKey; label: string; color: string }[] = [
  { key: 'high', label: 'High', color: SEVERITY_COLORS.high },
  { key: 'medium', label: 'Medium', color: SEVERITY_COLORS.medium },
  { key: 'low', label: 'Low', color: SEVERITY_COLORS.low },
  { key: 'log', label: 'Log', color: SEVERITY_COLORS.log },
];

const MAX_OBSERVATIONS_FOR_GRAPH = 500;

/** Where a zero-valued tier gets plotted on the log axis — see the DESIGN
 * note above. Sits exactly on the axis floor (`Y_DOMAIN` below starts here
 * too) so a zero draws as a real, visible point at the bottom of the chart
 * rather than being clipped or dropped. */
const LOG_FLOOR = 0.5;
const Y_DOMAIN: [number, 'auto'] = [LOG_FLOOR, 'auto'];
/** Candidate Y-axis tick values, filtered down to whatever fits the data's
 * actual max — supplied explicitly rather than left to recharts' default log
 * tick generator, which would otherwise print a `0.5` tick at the floor. */
const Y_TICK_CANDIDATES = [1, 2, 5, 10, 20, 50, 100, 200, 500];

// A full "Sep 7, 2026, 3:45 PM" (formatTimestamp, used for the tooltip) is far
// too wide to repeat as an X-axis tick across many points — a short
// month/day label does the job there instead.
const AXIS_LABEL_FORMATTER = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });

const toPlotValue = (value: number) => (value > 0 ? value : LOG_FLOOR);

interface GraphPoint {
  observedAt: string;
  /** Full timestamp, for the tooltip. */
  label: string;
  /** Short month/day, for the X axis. */
  axisLabel: string;
  // True counts, exactly as stored — always what the tooltip shows.
  high: number;
  medium: number;
  low: number;
  log: number;
  // Same counts with zero substituted for LOG_FLOOR — only ever used as the
  // plotted line values, never displayed as text.
  highPlot: number;
  mediumPlot: number;
  lowPlot: number;
  logPlot: number;
}

interface AssetSeverityGraphProps {
  assetUuid: string;
  /** Bumped by the parent to force a refetch, same convention as AssetTimeline. */
  refreshKey?: number;
}

/* ---- tooltip: true (non-floored) values per tier + the scan timestamp,
   same shape/pattern as NetworkScanCharts's PortTooltip/ServiceTooltip: a
   plain props interface passed as a React element, which recharts clones
   with `active`/`payload` at render time. All four lines share one X value
   per scan, so `payload[0]` alone carries the full point regardless of which
   line is under the cursor. ---- */

interface SeverityTrendTooltipProps {
  active?: boolean;
  payload?: { payload?: GraphPoint }[];
}

function SeverityTrendTooltip({ active, payload }: SeverityTrendTooltipProps) {
  if (!active || !payload?.length) return null;
  const point = payload[0]?.payload;
  if (!point) return null;
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs shadow-lg dark:border-slate-700 dark:bg-slate-800">
      <div className="font-semibold text-slate-500 dark:text-slate-400">{point.label}</div>
      <div className="mt-1.5 space-y-1">
        {SEVERITY_TIERS.map((tier) => (
          <div key={tier.key} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-1.5 font-medium text-slate-600 dark:text-slate-300">
              <span className="size-2 rounded-full" style={{ background: tier.color }} />
              {tier.label}
            </span>
            <span className="font-bold tabular-nums text-slate-900 dark:text-white">{point[tier.key]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const AssetSeverityGraph = ({ assetUuid, refreshKey = 0 }: AssetSeverityGraphProps) => {
  const [points, setPoints] = useState<GraphPoint[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Same guard-against-stale-response idiom as AssetTimeline.tsx: a sequence
  // number rather than an AbortController, so a fast Retry click right after
  // a slow initial request cannot have the stale response overwrite it.
  const fetchSeqRef = useRef(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const seq = ++fetchSeqRef.current;
    try {
      const result = await getAssetObservations(assetUuid, { rows: MAX_OBSERVATIONS_FOR_GRAPH, pageno: 1 });
      if (seq !== fetchSeqRef.current) return;
      const withSeverity = (result.data ?? [])
        .filter((o) => o.attrs?.extra?.severityCounts !== undefined)
        // The API returns newest-first; a left-to-right trend graph reads
        // oldest-first.
        .sort((a, b) => new Date(a.observed_at).getTime() - new Date(b.observed_at).getTime())
        .map((o): GraphPoint => {
          const counts = o.attrs.extra!.severityCounts!;
          return {
            observedAt: o.observed_at,
            label: formatTimestamp(o.observed_at),
            axisLabel: AXIS_LABEL_FORMATTER.format(new Date(o.observed_at)),
            high: counts.high,
            medium: counts.medium,
            low: counts.low,
            log: counts.log,
            highPlot: toPlotValue(counts.high),
            mediumPlot: toPlotValue(counts.medium),
            lowPlot: toPlotValue(counts.low),
            logPlot: toPlotValue(counts.log),
          };
        });
      setPoints(withSeverity);
    } catch {
      if (seq !== fetchSeqRef.current) return;
      setError("Couldn't load the vulnerability trend — try again");
      setPoints(null);
    } finally {
      if (seq === fetchSeqRef.current) setLoading(false);
    }
  }, [assetUuid]);

  useEffect(() => { load(); }, [load, refreshKey]);

  const hasEnoughData = (points?.length ?? 0) >= 2;

  // Explicit Y-axis ticks, trimmed to whatever the data's real (non-floored)
  // max actually needs — avoids both a stray "0.5" floor tick and a string of
  // huge unused ticks (e.g. 500) on a calm, low-count host.
  const yTicks = useMemo(() => {
    const maxValue = Math.max(1, ...(points ?? []).flatMap((p) => [p.high, p.medium, p.low, p.log]));
    return Y_TICK_CANDIDATES.filter((t) => t === 1 || t <= maxValue * 1.5);
  }, [points]);

  // Thin the X-axis ticks for assets with a long scan history so labels never
  // overlap; small histories (the common case here) just show every point.
  const xAxisInterval = (points?.length ?? 0) > 8 ? Math.ceil((points?.length ?? 0) / 8) - 1 : 0;

  return (
    <Panel className="flex min-h-0 flex-col overflow-hidden">
      <PlainHeader
        brand={OPENVAS_BRAND}
        icon={<LineChartIcon className="size-4" />}
        title="Vulnerability trend"
        subtitle="Findings across every OpenVAS scan of this machine. The Y axis is logarithmic so smaller high/medium/low counts stay visible next to much larger log totals."
      />
      <div className="p-4">
        {loading && (
          <div className="flex h-64 items-center justify-center text-sm font-medium text-slate-400">Loading…</div>
        )}
        {!loading && error && (
          <ErrorState message={error} action={<Btn variant="secondary" size="sm" onClick={load}>Retry</Btn>} />
        )}
        {!loading && !error && !hasEnoughData && (
          <EmptyState
            icon={<LineChartIcon className="size-6" />}
            title="Not enough scan history yet"
            description={
              (points?.length ?? 0) === 0
                ? 'No OpenVAS scan of this host has recorded vulnerability counts yet. This fills in automatically as scans complete.'
                : 'Only one scan so far has vulnerability counts recorded — a trend needs at least two to compare.'
            }
          />
        )}
        {!loading && !error && hasEnoughData && points && (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-4 px-1">
              {SEVERITY_TIERS.map((tier) => (
                <span key={tier.key} className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 dark:text-slate-400">
                  <span className="size-2 rounded-full" style={{ background: tier.color }} />
                  {tier.label}
                </span>
              ))}
            </div>
            <div className="h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={points} margin={{ top: 8, right: 12, left: 0, bottom: 4 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                  <XAxis
                    dataKey="axisLabel"
                    tick={{ fill: '#64748b', fontSize: 11 }}
                    tickLine={false}
                    axisLine={{ stroke: '#cbd5e1' }}
                    interval={xAxisInterval}
                  />
                  <YAxis
                    scale="log"
                    domain={Y_DOMAIN}
                    allowDataOverflow
                    ticks={yTicks}
                    tick={{ fill: '#64748b', fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                    width={32}
                  />
                  <Tooltip content={<SeverityTrendTooltip />} cursor={{ stroke: '#cbd5e1', strokeDasharray: '3 3' }} />
                  {SEVERITY_TIERS.map((tier) => (
                    <Line
                      key={tier.key}
                      type="linear"
                      dataKey={`${tier.key}Plot`}
                      name={tier.label}
                      stroke={tier.color}
                      strokeWidth={2}
                      // "Log" is tracked but, per the DESIGN note above, isn't a
                      // security signal the way the other three tiers are — a
                      // dashed stroke marks it as the odd one out without
                      // introducing any new chart chrome.
                      strokeDasharray={tier.key === 'log' ? '4 3' : undefined}
                      dot={{ r: 3, strokeWidth: 0, fill: tier.color }}
                      activeDot={{ r: 4 }}
                      isAnimationActive={false}
                    />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
};

export default AssetSeverityGraph;
