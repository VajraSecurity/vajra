import { useMemo, useEffect } from 'react';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis, PieChart, Pie, Tooltip as RTooltip } from 'recharts';
import type { ParsedNmapResult } from './utils/parseNmapOutput';

// Reuses colors already present elsewhere in the app (badges, header gradients,
// the Compliance page's bar/pie charts) rather than introducing a new palette.
const CHART_COLORS = ['#3b82f6', '#0d9488', '#fbbf24', '#ab3428', '#8b5cf6', '#10b981', '#f97316', '#64748b'];

export interface ChartPortDatum {
  port: string;
  count: number;
}

export interface ChartServiceDatum {
  name: string;
  value: number;
  fill: string;
}

interface NetworkScanChartsProps {
  advancedScanResultsMap?: Record<string, ParsedNmapResult>;
  sessionId?: number | null;
  // The persisted shape (networkScanApi's NetworkScanHistory.chart_data) only guarantees
  // arrays of unknown backend JSON; we know at runtime it's exactly what this component
  // itself produced and saved via updateScanCharts below, so it's narrowed to the real
  // ChartPortDatum/ChartServiceDatum shape once accepted.
  staticChartData?: { portData: unknown[]; serviceData: unknown[]; hasData: boolean };
  verticalOnly?: boolean;
}

interface PortTooltipProps {
  active?: boolean;
  payload?: { payload: ChartPortDatum; color?: string; fill?: string; value: number }[];
}

function PortTooltip({ active, payload }: PortTooltipProps) {
  if (!active || !payload?.length) return null;
  const item = payload[0];
  const [portNum, protocol] = String(item.payload.port).split('/');
  return (
    <div className="bg-white rounded-lg shadow-lg border border-slate-200 px-3 py-2">
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color || item.fill }} />
        <span className="text-sm text-slate-600">Port {portNum}{protocol ? ` (${protocol})` : ''}</span>
      </div>
      <div className="mt-1 text-sm font-semibold text-slate-900">{item.value} host{item.value === 1 ? '' : 's'}</div>
    </div>
  );
}

interface ServiceTooltipProps {
  active?: boolean;
  payload?: { name: string; value: number; payload: ChartServiceDatum }[];
}

function ServiceTooltip({ active, payload }: ServiceTooltipProps) {
  if (!active || !payload?.length) return null;
  const item = payload[0];
  return (
    <div className="bg-white rounded-lg shadow-lg border border-slate-200 px-3 py-2">
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.payload.fill }} />
        <span className="text-sm text-slate-600">{item.name}</span>
      </div>
      <div className="mt-1 text-sm font-semibold text-slate-900">{item.value} open port{item.value === 1 ? '' : 's'}</div>
    </div>
  );
}

const NetworkScanCharts = ({ advancedScanResultsMap, sessionId, staticChartData, verticalOnly }: NetworkScanChartsProps) => {
  const chartData = useMemo(() => {
    if (staticChartData) return staticChartData as unknown as { portData: ChartPortDatum[]; serviceData: ChartServiceDatum[]; hasData: boolean };

    if (!advancedScanResultsMap) return { portData: [], serviceData: [], hasData: false };

    const portCounts: Record<string, number> = {};
    const serviceCounts: Record<string, number> = {};

    Object.values(advancedScanResultsMap).forEach(result => {
      result.ports?.forEach(p => {
        if (!p.state?.toLowerCase().startsWith('open')) return;
        // Keyed by port+protocol — TCP/53 and UDP/53 on the same host are two
        // distinct open ports, not one "port 53" counted twice.
        const protocol = p.protocol?.trim() || 'tcp';
        const portKey = `${p.port}/${protocol}`;
        portCounts[portKey] = (portCounts[portKey] || 0) + 1;
        const service = p.service?.trim() || 'unknown';
        serviceCounts[service] = (serviceCounts[service] || 0) + 1;
      });
    });

    const portData = Object.entries(portCounts)
      .map(([port, count]) => ({ port, count }))
      .sort((a, b) => b.count - a.count || parseInt(a.port, 10) - parseInt(b.port, 10))
      .slice(0, 15);

    const serviceEntries = Object.entries(serviceCounts).sort((a, b) => b[1] - a[1]);
    const TOP_N = 7;
    const serviceData = serviceEntries.slice(0, TOP_N).map(([name, value], idx) => ({
      name, value, fill: CHART_COLORS[idx % CHART_COLORS.length],
    }));
    const otherTotal = serviceEntries.slice(TOP_N).reduce((sum, [, v]) => sum + v, 0);
    if (otherTotal > 0) {
      serviceData.push({ name: 'Other', value: otherTotal, fill: CHART_COLORS[TOP_N % CHART_COLORS.length] });
    }

    return { portData, serviceData, hasData: Object.keys(advancedScanResultsMap).length > 0 };
  }, [advancedScanResultsMap, staticChartData]);

  const { portData, serviceData, hasData } = chartData;

  useEffect(() => {
    if (sessionId && hasData && !staticChartData) {
      import('../../api/api').then(({ updateScanCharts }) => {
        updateScanCharts(sessionId, chartData).catch(console.error);
      });
    }
  }, [chartData, sessionId, hasData, staticChartData]);

  if (!hasData) return null;

  return (
    <div className={`grid grid-cols-1 ${verticalOnly ? '' : 'lg:grid-cols-2'} gap-5`}>
      <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
        <h3 className="text-sm font-bold text-slate-700">Open Ports Distribution</h3>
        <p className="text-xs text-slate-500 mt-0.5 mb-3">Number of hosts with each port open (from Advanced Scans)</p>
        <div className="h-[250px]">
          {portData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-sm text-slate-400">No open ports found yet</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={portData}
                margin={{ top: 14, right: 8, left: 2, bottom: 20 }}
                desc={`Bar chart showing the number of hosts with each open port, across ${portData.length} port(s) found in advanced scans.`}
              >
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                <XAxis dataKey="port" tick={{ fill: '#64748b', fontSize: 12 }} tickLine={false} axisLine={{ stroke: '#cbd5e1' }} />
                <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 12 }} tickLine={false} axisLine={false} width={28} />
                <Tooltip cursor={{ fill: 'rgba(148, 163, 184, 0.12)' }} content={<PortTooltip />} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]} maxBarSize={44}>
                  {portData.map((entry) => (
                    <Cell key={entry.port} fill="#3b82f6" />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
        <h3 className="text-sm font-bold text-slate-700">Services Detected</h3>
        <p className="text-xs text-slate-500 mt-0.5 mb-3">Breakdown of services found on open ports</p>
        <div className="h-[250px] flex items-center gap-4">
          {serviceData.length === 0 ? (
            <div className="h-full w-full flex items-center justify-center text-sm text-slate-400">No services found yet</div>
          ) : (
            <>
              <div className="h-full w-1/2 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart margin={{ top: 10, bottom: 10 }}>
                    <Pie
                      data={serviceData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%" cy="50%"
                      innerRadius={45} outerRadius={85}
                      stroke="#fff" strokeWidth={2} cornerRadius={6}
                    >
                      {serviceData.map((entry) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                    <RTooltip content={<ServiceTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex-1 space-y-1.5 overflow-y-auto max-h-[250px] pr-1">
                {serviceData.map(entry => (
                  <div key={entry.name} className="flex items-center justify-between gap-2 text-xs">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: entry.fill }} />
                      <span className="text-slate-600 truncate">{entry.name}</span>
                    </div>
                    <span className="font-semibold text-slate-800 shrink-0">{entry.value}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default NetworkScanCharts;
