import { useCallback, useEffect, useState } from 'react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { getFimSummary, type FimSummary } from '../../api/services/fimApi';
import { KIND_LABEL, SEVERITIES, SEVERITY_COLOR, errMsg } from './constants';
import { ErrorBanner, LoadingRows, EmptyBox } from './ui';
import { cardCls, btnGhost } from './styles';
import { safeText } from './safeText';
import { RegText } from './UntrustedText';

function Stat({ label, value, color, sub }: { label: string; value: number; color?: string; sub?: string }) {
  return (
    <div className={`${cardCls} p-4`}>
      <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
      <div className="mt-1 text-2xl font-bold tabular-nums" style={color ? { color } : undefined}>{value.toLocaleString()}</div>
      {sub && <div className="text-xs text-slate-400">{sub}</div>}
    </div>
  );
}

export default function OverviewTab({ onOpenDrift, onOpenAlerts }: { onOpenDrift: (f: { severity?: string; host?: string }) => void; onOpenAlerts: (f: { severity?: string }) => void }) {
  const [data, setData] = useState<FimSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await getFimSummary());
    } catch (e) {
      setError(errMsg(e, 'Failed to load summary'));
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  if (loading && !data) return <LoadingRows label="Loading overview" />;
  if (error && !data) return <ErrorBanner message={error} onRetry={load} />;
  if (!data) return <EmptyBox title="No overview data" />;

  const by = data.bySeverity ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const trend = (data.trend ?? []).map((t) => ({ ...t, label: t.day.slice(5) }));
  const maxHost = Math.max(1, ...(data.topHosts ?? []).map((h) => h.count));
  const maxPath = Math.max(1, ...(data.topPaths ?? []).map((p) => p.count));
  const nothing = data.hostsMonitored === 0 && data.baselineFiles === 0;

  return (
    <div className={`space-y-4 overflow-y-auto h-full pb-6 ${error ? '[&>*:not(:first-child)]:opacity-60' : ''}`}>
      {error && <ErrorBanner message={error} onRetry={load} stale />}
      {nothing && (
        <div className={`${cardCls} p-2`}>
          <EmptyBox title="No hosts are being monitored yet" description="Create a policy in the Policies tab, publish it, and initialize their baselines (Policies tab) - hosts are not monitored until then." />
        </div>
      )}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="Open drift" value={data.openDrift} color={data.openDrift > 0 ? '#dc2626' : undefined} sub={`${data.driftLast24h} in last 24h`} />
        <Stat label="Hosts monitored" value={data.hostsMonitored} />
        <Stat label="Hosts not baselined" value={data.hostsNotBaselined ?? data.hostsLearning} color={(data.hostsNotBaselined ?? data.hostsLearning) > 0 ? '#d97706' : undefined} sub={`${data.hostsBaselined ?? data.hostsLocked} baselined - not monitored until initialized`} />
        <Stat label="Baseline files" value={data.baselineFiles} />
      </div>

      <section className={`${cardCls} p-4`} aria-label="What is covered">
        <h3 className="mb-2 text-sm font-semibold text-slate-800 dark:text-slate-100">What is covered</h3>
        {Object.values(data.entriesByKind ?? {}).every((n) => !n) ? <p className="text-xs text-slate-400">No enabled policy has entries yet.</p> : (
          <ul className="flex flex-wrap gap-2">
            {(['path', 'xattr', 'registry', 'acl', 'table'] as const).filter((k) => (data.entriesByKind?.[k] ?? 0) > 0).map((k) => (
              <li key={k} className="rounded-lg border border-slate-200 dark:border-white/10 px-3 py-1.5 text-sm"><span className="font-bold tabular-nums">{data.entriesByKind?.[k]}</span> <span className="text-slate-500">{KIND_LABEL[k]}</span></li>
            ))}
          </ul>
        )}
        <p className="mt-2 text-xs text-slate-400">Baseline: {(data.baselineByKind?.file ?? 0).toLocaleString()} files, {(data.baselineByKind?.directory ?? 0).toLocaleString()} directories, {(data.baselineByKind?.item ?? 0).toLocaleString()} config items. Entries of enabled policies.</p>
      </section>

      <section className={`${cardCls} p-4`} aria-label="Open FIM alerts">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-100">Open FIM alerts: <span className="tabular-nums" style={{ color: (data.openAlerts ?? 0) > 0 ? '#dc2626' : undefined }}>{(data.openAlerts ?? 0).toLocaleString()}</span></h3>
          <button className={btnGhost} onClick={() => onOpenAlerts({})}>View alerts</button>
        </div>
        <div className="mt-2 flex flex-wrap gap-2">
          {SEVERITIES.map((s) => (
            <button key={s} onClick={() => onOpenAlerts({ severity: s })} className="rounded-lg border border-slate-200 dark:border-white/10 px-3 py-1.5 text-left hover:border-indigo-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400">
              <span className="text-xs font-semibold capitalize" style={{ color: SEVERITY_COLOR[s] }}>{s}</span>
              <span className="ml-2 text-sm font-bold tabular-nums text-slate-800 dark:text-slate-100">{(data.openAlertsBySeverity?.[s] ?? 0).toLocaleString()}</span>
            </button>
          ))}
        </div>
      </section>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {SEVERITIES.map((s) => (
          <button key={s} onClick={() => onOpenDrift({ severity: s })} className={`${cardCls} p-4 text-left hover:border-indigo-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-400`} aria-label={`${by[s]} open ${s} drift, view`}>
            <div className="text-xs font-semibold uppercase tracking-wide capitalize" style={{ color: SEVERITY_COLOR[s] }}>{s}</div>
            <div className="mt-1 text-2xl font-bold tabular-nums text-slate-800 dark:text-slate-100">{(by[s] ?? 0).toLocaleString()}</div>
            <div className="text-xs text-slate-400">open</div>
          </button>
        ))}
      </div>

      <section className={`${cardCls} p-4`} aria-label="Drift trend, last 14 days">
        <h3 className="mb-2 text-sm font-semibold text-slate-800 dark:text-slate-100">Drift detected, last 14 days</h3>
        {trend.length === 0 ? <EmptyBox title="No trend data yet" /> : (
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#94a3b833" />
                <XAxis dataKey="label" tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
                <Tooltip />
                <Area type="monotone" dataKey="count" name="Drift events" stroke="#4f46e5" fill="#4f46e533" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </section>

      <div className="grid lg:grid-cols-2 gap-4">
        <section className={`${cardCls} p-4`} aria-label="Top hosts">
          <h3 className="mb-3 text-sm font-semibold text-slate-800 dark:text-slate-100">Top hosts by open drift</h3>
          {(data.topHosts ?? []).length === 0 ? <EmptyBox title="No open drift" /> : (
            <ul className="space-y-2">
              {data.topHosts.map((h) => (
                <li key={h.hostIdentifier}>
                  <button className="w-full text-left" onClick={() => onOpenDrift({ host: h.hostIdentifier })}>
                    <div className="flex justify-between text-sm"><span className="truncate text-slate-700 dark:text-slate-200"><RegText value={h.hostname || h.hostIdentifier} nowrap /></span><span className="tabular-nums font-semibold">{h.count}</span></div>
                    <div className="mt-1 h-1.5 rounded bg-slate-100 dark:bg-white/10"><div className="h-1.5 rounded bg-indigo-500" style={{ width: `${(h.count / maxHost) * 100}%` }} /></div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className={`${cardCls} p-4`} aria-label="Top paths">
          <h3 className="mb-3 text-sm font-semibold text-slate-800 dark:text-slate-100">Top changed paths</h3>
          {(data.topPaths ?? []).length === 0 ? <EmptyBox title="No open drift" /> : (
            <ul className="space-y-2">
              {data.topPaths.map((p) => (
                <li key={p.path}>
                  <div className="flex justify-between gap-2 text-sm"><span className="truncate font-mono text-xs text-slate-700 dark:text-slate-200" title={safeText(p.path)}><RegText value={p.path} nowrap /></span><span className="tabular-nums font-semibold">{p.count}</span></div>
                  <div className="mt-1 h-1.5 rounded bg-slate-100 dark:bg-white/10"><div className="h-1.5 rounded bg-amber-500" style={{ width: `${(p.count / maxPath) * 100}%` }} /></div>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
      <button onClick={load} className={btnGhost} disabled={loading}>{loading ? 'Refreshing...' : 'Refresh'}</button>
    </div>
  );
}
