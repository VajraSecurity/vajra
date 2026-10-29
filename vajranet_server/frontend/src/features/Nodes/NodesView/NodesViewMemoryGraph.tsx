/**
 * Memory Command View for a node, rendered inside the Storage tab.
 *
 * Extracted verbatim from the former NodesViewGraph ("Graph" tab), which was
 * removed. Only the memory chart moved; the Alert Severity Distribution,
 * Firewall Rules Changes and Compliance Status cards that shared that tab were
 * dropped with it. The Compliance tab's own gauge is a separate component and
 * is deliberately untouched.
 *
 * The markup and derivations below are unchanged from the original, so the card
 * renders exactly as it did on the Graph tab. The 10s refresh is also unchanged
 * for a visible tab; it additionally skips while the tab is hidden and refetches
 * on foreground, matching the gating used by the alerts and MyDevices polls.
 *
 * API: dashboardApi.getMemoryGraph
 */

import { useState, useEffect } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Area,
  Line,
  ReferenceLine,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import type { NodeData } from './types';
import { DuoSpinner } from '@/components/ui/loading';
import { dashboardApi, type MemoryHealthResponse } from '../../../pages/Dashboard/api/dashboardApi';

function memoryGraphAxiosMessage(err: unknown): string {
  if (err && typeof err === 'object' && 'response' in err) {
    const data = (err as { response?: { data?: { message?: string } } }).response?.data;
    if (data && typeof data.message === 'string' && data.message.trim()) return data.message.trim();
  }
  if (err instanceof Error && err.message) return err.message;
  return 'Could not load memory metrics.';
}

function parseMemoryGraphResult(memData: MemoryHealthResponse | null): {
  series: Array<{ time: number; memory_usage: number; memory_total: number }> | null;
  unavailable: string | null;
} {
  if (!memData) return { series: null, unavailable: null };
  if (memData.status === 'Unavailable') {
    return {
      series: [],
      unavailable: memData.message || 'Memory metrics unavailable.',
    };
  }
  if (memData.status === 'Error') {
    return {
      series: [],
      unavailable: memData.message || 'Memory metrics request failed.',
    };
  }
  return { series: memData.data ?? [], unavailable: null };
}

/** Subset of the former Graph-tab palette that the memory card actually uses. */
const COLORS = {
  primary: '#1d4ed8',
  secondary: '#0ea5e9',
  warning: '#d97706',
  neutral: '#334155',
  border: '#e2e8f0',
  surface: '#ffffff',
  surfaceAlt: '#f1f7ff',
};

interface NodesViewMemoryGraphProps {
  node: NodeData;
}

const NodesViewMemoryGraph = ({ node }: NodesViewMemoryGraphProps) => {
  const [memoryData, setMemoryData] = useState<Array<{ time: number; memory_usage: number; memory_total: number }> | null>(null);
  const [memoryMetricsError, setMemoryMetricsError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [memoryWindow] = useState<50 | 25 | 10>(50);
  const [memoryMetric] = useState<'usage' | 'usedGB'>('usage');

  const hostId = node.host_identifier || String(node.id);
  // Only the Ubuntu branch is needed here — the original component's isWindows
  // flag drove the severity/firewall cards, which did not move.
  const isUbuntu = node.os_platform?.toLowerCase().includes('ubuntu');

  // Initial load. The Graph tab fetched this alongside severity/firewall/
  // compliance in one Promise.all; standing alone it only needs its own series.
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const memData = await dashboardApi.getMemoryGraph(hostId);
        if (cancelled) return;
        const parsed = parseMemoryGraphResult(memData);
        setMemoryMetricsError(parsed.unavailable);
        setMemoryData(parsed.unavailable ? [] : (parsed.series ?? []));
      } catch (e) {
        if (cancelled) return;
        setMemoryMetricsError(memoryGraphAxiosMessage(e));
        setMemoryData([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    return () => { cancelled = true; };
  }, [hostId]);

  /** Refresh memory time series every 10s so the chart stays current */
  useEffect(() => {
    const id = window.setInterval(async () => {
      // Skip while the tab is hidden — nothing is on screen to update, and the
      // series is refetched on mount anyway. Matches the gating already applied
      // to the alerts and node-list polls.
      if (document.hidden) return;
      try {
        const memData = await dashboardApi.getMemoryGraph(hostId);
        const parsed = parseMemoryGraphResult(memData);
        setMemoryMetricsError(parsed.unavailable);
        if (parsed.unavailable) {
          setMemoryData([]);
        } else if (parsed.series) {
          setMemoryData(parsed.series);
        }
      } catch (e) {
        setMemoryMetricsError(memoryGraphAxiosMessage(e));
        setMemoryData([]);
      }
    }, 10_000);

    // Catch-up on foreground. Without this the hidden-tab skip above leaves the
    // chart showing data up to 10s stale after the user returns — the alerts
    // and MyDevices polls both pair their gate with this listener, and so do
    // the pre-existing VulnerabilityScanner pollers.
    const onVisibility = () => {
      if (document.hidden) return;
      void (async () => {
        try {
          const memData = await dashboardApi.getMemoryGraph(hostId);
          const parsed = parseMemoryGraphResult(memData);
          setMemoryMetricsError(parsed.unavailable);
          setMemoryData(parsed.unavailable ? [] : (parsed.series ?? []));
        } catch (e) {
          setMemoryMetricsError(memoryGraphAxiosMessage(e));
          setMemoryData([]);
        }
      })();
    };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [hostId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <DuoSpinner size="lg" className="text-blue-500" />
      </div>
    );
  }

  const memoryHealth = memoryData || [];
  const memoryChartData = memoryHealth.map((d) => {
    const total = Number(d.memory_total) || 1;
    const used = Number(d.memory_usage) || 0;
    const usagePercent = total > 0 ? Math.min(100, ((used / total) * 100)) : 0;
    const date = new Date(d.time * 1000);
    return {
      time: date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      usage: parseFloat(usagePercent.toFixed(2)),
      usedGB: parseFloat((used / (1024 * 1024 * 1024)).toFixed(2)),
      totalGB: parseFloat((total / (1024 * 1024 * 1024)).toFixed(2)),
    };
  });

  const latestUsage = memoryChartData.length ? memoryChartData[memoryChartData.length - 1].usage : 0;
  const avgUsage = memoryChartData.length
    ? memoryChartData.reduce((sum, d) => sum + d.usage, 0) / memoryChartData.length
    : 0;
  const peakUsage = memoryChartData.length
    ? Math.max(...memoryChartData.map((d) => d.usage))
    : 0;

  const visibleMemoryData = memoryChartData.slice(-memoryWindow);
  const memoryDataKey = memoryMetric === 'usage' ? 'usage' : 'usedGB';
  const memoryYAxisLabel = memoryMetric === 'usage' ? 'Memory %' : 'Used GB';
  const memoryLineColor = memoryMetric === 'usage' ? COLORS.primary : COLORS.secondary;
  const memoryMaxY =
    memoryMetric === 'usage'
      ? 100
      : Math.max(1, ...visibleMemoryData.map((item) => item.usedGB), ...visibleMemoryData.map((item) => item.totalGB));

  const memoryChartHeight = isUbuntu ? 280 : 310;

  return (

    <div
      className="bg-white rounded-2xl border p-6 md:p-7 h-full flex flex-col min-h-0"
      style={{
        borderColor: COLORS.border,
        boxShadow: '0 18px 34px rgba(29, 78, 216, 0.1)',
        borderTop: `4px solid ${COLORS.primary}`,
      }}
    >
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6 shrink-0">
        <div>
          <h3 className="font-semibold text-slate-900 text-base md:text-lg flex items-center gap-2">
            <i className="fa fa-chart-line" style={{ color: COLORS.primary }} />
            Memory Command View
          </h3>
          <p className="text-xs text-slate-500 mt-1">
            Live memory utilization profile for this node.
          </p>
        </div>
        {!memoryMetricsError ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
            <div className="rounded-xl border px-3 py-2" style={{ borderColor: COLORS.border, backgroundColor: COLORS.surfaceAlt }}>
              <p className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: COLORS.neutral }}>Current</p>
              <p className="text-base font-bold text-slate-900">{latestUsage.toFixed(1)}%</p>
            </div>
            <div className="rounded-xl border px-3 py-2" style={{ borderColor: COLORS.border, backgroundColor: COLORS.surfaceAlt }}>
              <p className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: COLORS.neutral }}>Average</p>
              <p className="text-base font-bold" style={{ color: COLORS.primary }}>{avgUsage.toFixed(1)}%</p>
            </div>
            <div className="rounded-xl border px-3 py-2" style={{ borderColor: COLORS.border, backgroundColor: COLORS.surfaceAlt }}>
              <p className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: COLORS.neutral }}>Peak</p>
              <p className="text-base font-bold" style={{ color: COLORS.warning }}>{peakUsage.toFixed(1)}%</p>
            </div>
            <div className="rounded-xl border px-3 py-2" style={{ borderColor: COLORS.border, backgroundColor: COLORS.surfaceAlt }}>
              <p className="text-[10px] font-semibold uppercase tracking-wide" style={{ color: COLORS.neutral }}>Samples</p>
              <p className="text-base font-bold text-slate-900">{memoryChartData.length}</p>
            </div>
          </div>
        ) : null}
      </div>
      {memoryMetricsError ? (
        <div
          className="flex flex-col items-center justify-center gap-2 h-64 rounded-xl border px-4 text-center"
          style={{ borderColor: COLORS.border, backgroundColor: COLORS.surfaceAlt }}
        >
          <i className="fa fa-database text-amber-600 text-xl" aria-hidden />
          <p className="text-sm font-medium text-slate-800">Memory metrics unavailable</p>
          <p className="text-xs text-slate-600 max-w-md">{memoryMetricsError}</p>
        </div>
      ) : memoryChartData.length > 0 ? (
        <div className="flex-1 min-h-[240px]">
          <ResponsiveContainer width="100%" height={memoryChartHeight}>
            <LineChart data={visibleMemoryData}>
              <defs>
                <linearGradient id="memoryFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={memoryLineColor} stopOpacity={0.22} />
                  <stop offset="95%" stopColor={memoryLineColor} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="4 4" stroke={COLORS.border} vertical={false} />
              <XAxis dataKey="time" stroke={COLORS.neutral} tick={{ fill: COLORS.neutral, fontSize: 11 }} />
              <YAxis
                stroke={COLORS.neutral}
                tick={{ fill: COLORS.neutral, fontSize: 11 }}
                domain={[0, memoryMaxY]}
                label={{ value: memoryYAxisLabel, angle: -90, position: 'insideLeft', style: { fill: COLORS.neutral, fontSize: 11 } }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: COLORS.surface,
                  border: `1px solid ${COLORS.border}`,
                  borderRadius: '10px',
                  boxShadow: '0 6px 18px rgba(15, 23, 42, 0.12)',
                }}
                formatter={(value, name) => {
                  if (value === undefined) return ['N/A', name || ''];
                  const numericValue = Number(Array.isArray(value) ? value[0] : value);
                  if (!Number.isFinite(numericValue)) return ['N/A', name || ''];
                  if (memoryMetric === 'usage') return [`${numericValue.toFixed(2)}%`, 'Utilization'];
                  return [`${numericValue.toFixed(2)} GB`, 'Used Memory'];
                }}
              />
              {memoryMetric === 'usage' ? (
                <ReferenceLine
                  y={80}
                  stroke={COLORS.warning}
                  strokeDasharray="3 3"
                  label={{ value: '80% threshold', fill: COLORS.warning, fontSize: 10 }}
                />
              ) : null}
              <Area type="monotone" dataKey={memoryDataKey} fill="url(#memoryFill)" stroke="none" />
              <Line
                type="monotone"
                dataKey={memoryDataKey}
                stroke={memoryLineColor}
                strokeWidth={2.5}
                dot={false}
                activeDot={{ r: 4, stroke: '#ffffff', strokeWidth: 2 }}
                name={memoryDataKey}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div
          className="flex items-center justify-center h-64 rounded-xl border"
          style={{ borderColor: COLORS.border, backgroundColor: COLORS.surfaceAlt }}
        >
          <p className="text-gray-500 text-sm">No memory data available (node may be offline)</p>
        </div>
      )}
    </div>
  
  );
};

export default NodesViewMemoryGraph;
