import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import UsbIcon from '@mui/icons-material/Usb';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import { motion } from 'motion/react';
import { Meteors } from '../../components/ui/meteors';
import { DashboardIcon } from '../../components/icons/navIcons';
import { getStoredUser } from '../../services/auth';
import { getProfile } from '../../api/api';
import { dashboardApi, type OsCountItem, type AlertStatusItem, type TopMachineAlert, type TopMachineUsb } from './api/dashboardApi';
import { COLORS } from './constants';
import DashboardSkeleton from './components/DashboardSkeleton';
import { useRateLimit } from '../../context/useRateLimit';

type RiskLevel = 'High' | 'Medium' | 'Low';

const getRiskColor = (risk: RiskLevel) => {
  if (risk === 'High') return COLORS.alert;
  if (risk === 'Medium') return COLORS.warning;
  return COLORS.success;
};

type PieChartData = {
  name: string;
  value: number;
  color: string;
};

type WeeklyAlertPoint = {
  day: string;
  date: string;
  [alertType: string]: string | number;
};

const isWeeklyAlertsDateKey = (k: string) => /^\d{1,2}\/\d{1,2}\/\d{4}$/.test(k);

const formatCountdown = (totalSeconds: number) => {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes}:${seconds.toString().padStart(2, '0')}` : `${seconds}s`;
};

const DonutMetricCard = ({
  data,
  title,
  subtitle,
  accent,
  emptyMessage = 'No data available',
}: {
  data: PieChartData[];
  title: string;
  subtitle: string;
  accent: string;
  emptyMessage?: string;
}) => {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  const chartData = data.filter((item) => item.value > 0);

  let currentPercent = 0;
  const conicStops = chartData
    .map((item) => {
      const start = currentPercent;
      const slicePercent = (item.value / total) * 100;
      currentPercent += slicePercent;
      return `${item.color} ${start.toFixed(2)}% ${Math.min(currentPercent, 100).toFixed(2)}%`;
    })
    .join(', ');

  if (total === 0) {
    return (
      <div
        className="bg-white rounded-2xl border p-6 h-full"
        style={{
          borderColor: COLORS.border,
          boxShadow: '0 12px 28px rgba(15, 23, 42, 0.06)',
          borderTop: `4px solid ${accent}`,
        }}
      >
        <h3 className="font-semibold text-gray-900 text-sm md:text-base">{title}</h3>
        <p className="text-xs text-slate-500 mt-1 leading-relaxed">{subtitle}</p>
        <div className="flex items-center justify-center h-44 px-4">
          <p className="text-gray-500 text-sm text-center">{emptyMessage}</p>
        </div>
      </div>
    );
  }

  return (
    <div
      className="bg-white rounded-2xl border p-5 md:p-6 h-full"
      style={{
        borderColor: COLORS.border,
        boxShadow: '0 12px 28px rgba(15, 23, 42, 0.06)',
        borderTop: `4px solid ${accent}`,
      }}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-semibold text-gray-900 text-sm md:text-base">{title}</h3>
          <p className="text-xs text-slate-500 mt-1 leading-relaxed">{subtitle}</p>
        </div>
        <span
          className="text-[11px] font-semibold px-2.5 py-1 rounded-full"
          style={{ backgroundColor: COLORS.surfaceAlt, color: accent }}
        >
          {total} Total
        </span>
      </div>

      <div className="mt-4 grid grid-cols-1 sm:grid-cols-[168px_1fr] gap-4 items-center">
        <div className="relative w-[168px] h-[168px] mx-auto">
          <div
            className="absolute inset-0 rounded-full"
            style={{
              background: `conic-gradient(from -90deg, ${conicStops})`,
              boxShadow: `0 10px 24px ${accent}26`,
            }}
          />
          <div
            className="absolute inset-[18px] rounded-full border flex flex-col items-center justify-center"
            style={{ borderColor: COLORS.border, backgroundColor: COLORS.surface }}
          >
            <p className="text-3xl font-bold" style={{ color: accent }}>
              {total}
            </p>
            <p className="text-[11px] font-semibold uppercase tracking-wide" style={{ color: COLORS.slate }}>
              Total
            </p>
          </div>
          <div
            className="absolute inset-[6px] rounded-full border"
            style={{ borderColor: `${accent}30` }}
          />
        </div>

        <div className="space-y-3">
          {data.map((item, i) => (
            <div key={i}>
              <div className="flex items-center justify-between text-sm gap-3">
                <div className="flex items-center gap-2 min-w-0">
                  <div
                    className="w-2.5 h-2.5 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="font-medium text-gray-700 truncate">{item.name}</span>
                </div>
                <div className="text-right whitespace-nowrap">
                  <p className="font-semibold text-slate-800">
                    {item.value}
                  </p>
                  <p className="text-xs text-gray-500">
                    {((item.value / total) * 100).toFixed(1)}%
                  </p>
                </div>
              </div>
              <div className="mt-1.5 h-1.5 rounded-full" style={{ backgroundColor: COLORS.surfaceAlt }}>
                <div
                  className="h-full rounded-full"
                  style={{ width: `${(item.value / total) * 100}%`, backgroundColor: item.color }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const OS_COLOR_MAP: { [key: string]: string } = {
  'Windows': '#0078D4',
  'Linux': '#FCC624',
  'MacOS': '#A2AAAD',
  'Other': '#9CA3AF'
};

const Dashboard = () => {
  const [loading, setLoading] = useState(true);
  const [, setUserName] = useState('');
  // Drives whether the Analytics link is offered at all. /analytics is Super
  // Admin and Group Admin only (see App.tsx and
  // controllers/auth/validateGrafana.ts), so for a Viewer the link would only
  // bounce them back here.
  const [canViewAnalytics, setCanViewAnalytics] = useState(false);
  const [fetchError, setFetchError] = useState(false);
  const [osFailed, setOsFailed] = useState(false);
  const [defenderFailed, setDefenderFailed] = useState(false);
  const [alertsFailed, setAlertsFailed] = useState(false);
  const [topAlertsFailed, setTopAlertsFailed] = useState(false);
  const [topUsbFailed, setTopUsbFailed] = useState(false);
  // Rate limiting is a global, app-wide condition (backend limits per
  // user/IP across every route, not per page) — RateLimitProvider tracks
  // the shared countdown centrally; this page just reacts to it.
  const { isRateLimited, secondsLeft: rateLimitSecondsLeft } = useRateLimit();

  const [nodesByOS, setNodesByOS] = useState<{ name: string; value: number; color: string }[]>([]);
  const [defenderStatus, setDefenderStatus] = useState<{ name: string; value: number; color: string }[]>([]);
  const [alertsStatus, setAlertsStatus] = useState<{ name: string; value: number; color: string }[]>([]);
  const [weeklyAlertsData, setWeeklyAlertsData] = useState<WeeklyAlertPoint[]>([]);
  const [topAlertsMachines, setTopAlertsMachines] = useState<Array<{
    machine: string;
    alerts: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    information: number;
  }>>([]);
  const [topUSBAlertsMachines, setTopUSBAlertsMachines] = useState<Array<{
    machine: string;
    usbEvents: number;
    risk: RiskLevel;
  }>>([]);

  const fetchDashboardData = useCallback(async () => {
    setOsFailed(false);
    setDefenderFailed(false);
    setAlertsFailed(false);
    setTopAlertsFailed(false);
    setTopUsbFailed(false);
    setFetchError(false);

    const markFailed = () => setFetchError(true);

    const [osData, defenderData, alertData, weeklyData, top5Alerts, top5Usb] = await Promise.all([
      dashboardApi.getOsCount().catch(() => { markFailed(); setOsFailed(true); return []; }),
      dashboardApi.getDefenderCount().catch(() => { markFailed(); setDefenderFailed(true); return { data: { on: 0, off: 0 } }; }),
      dashboardApi.getAlertStatus().catch(() => { markFailed(); setAlertsFailed(true); return []; }),
      dashboardApi.getWeeklyAlerts().catch(() => { markFailed(); return {}; }),
      dashboardApi.getTop5MachineAlerts().catch(() => { markFailed(); setTopAlertsFailed(true); return { data: [] }; }),
      dashboardApi.getTop5MachineUsb().catch(() => { markFailed(); setTopUsbFailed(true); return { data: [] }; }),
    ]);

    const osByOSFormatted = osData.map((item: OsCountItem) => ({
      name: item.name,
      value: item.count,
      color: OS_COLOR_MAP[item.name] || '#9CA3AF',
    }));
    setNodesByOS(osByOSFormatted);

    const defenderFormatted = [
      { name: 'Defender On', value: defenderData.data.on, color: COLORS.success },
      { name: 'Defender Off', value: defenderData.data.off, color: COLORS.alert },
    ];
    setDefenderStatus(defenderFormatted);

    const alertsFormatted = alertData.map((item: AlertStatusItem) => ({
      name: item.name === 'Online' ? 'Alerts Open' : 'Alerts Close',
      value: item.count,
      color: item.name === 'Online' ? COLORS.primary : COLORS.neutral,
    }));
    setAlertsStatus(alertsFormatted);

    const rawWeekly = (weeklyData || {}) as Record<string, unknown>;
    const weeklyDates = Object.keys(rawWeekly)
      .filter(
        (k) =>
          isWeeklyAlertsDateKey(k) &&
          rawWeekly[k] !== null &&
          typeof rawWeekly[k] === 'object' &&
          !Array.isArray(rawWeekly[k]),
      )
      .sort((a, b) => {
        const [aDay, aMonth, aYear] = a.split('/');
        const [bDay, bMonth, bYear] = b.split('/');
        return (
          new Date(parseInt(aYear, 10), parseInt(aMonth, 10) - 1, parseInt(aDay, 10)).getTime() -
          new Date(parseInt(bYear, 10), parseInt(bMonth, 10) - 1, parseInt(bDay, 10)).getTime()
        );
      });

    const allAlertTypes = new Set<string>();
    for (const date of weeklyDates) {
      const dayObj = rawWeekly[date] as Record<string, number>;
      Object.keys(dayObj).forEach((t) => allAlertTypes.add(t));
    }
    const typeOrder = Array.from(allAlertTypes).sort();

    const weeklyFormatted: WeeklyAlertPoint[] = weeklyDates.map((date) => {
      const [day, month, year] = date.split('/');
      const dateObj = new Date(parseInt(year, 10), parseInt(month, 10) - 1, parseInt(day, 10));
      const dayName = dateObj.toLocaleDateString('en-US', { weekday: 'short' });
      const alertTypes = (rawWeekly[date] as Record<string, number>) || {};
      const row: WeeklyAlertPoint = { day: dayName, date };
      for (const t of typeOrder) {
        row[t] = Number(alertTypes[t]) || 0;
      }
      return row;
    });

    setWeeklyAlertsData(weeklyFormatted);

    const top5AlertsFormatted = top5Alerts.data.map((item: TopMachineAlert) => ({
      machine: item.hostname,
      alerts: item.total_alerts,
      critical: typeof item.critical === 'string' ? parseInt(item.critical, 10) || 0 : item.critical || 0,
      high: typeof item.high === 'string' ? parseInt(item.high, 10) || 0 : item.high || 0,
      medium: typeof item.medium === 'string' ? parseInt(item.medium, 10) || 0 : item.medium || 0,
      low: typeof item.low === 'string' ? parseInt(item.low, 10) || 0 : item.low || 0,
      information: typeof item.information === 'string' ? parseInt(item.information, 10) || 0 : item.information || 0,
    }));
    setTopAlertsMachines(top5AlertsFormatted);

    const top5UsbFormatted = top5Usb.data.map((item: TopMachineUsb) => ({
      machine: item.hostname,
      usbEvents: item.usb_alert_count,
      risk: (item.usb_alert_count > 15 ? 'High' : item.usb_alert_count > 8 ? 'Medium' : 'Low') as RiskLevel,
    }));
    setTopUSBAlertsMachines(top5UsbFormatted);
  }, []);

  useEffect(() => {
    const init = async () => {
      try {
        const user = getStoredUser();
        const profile = await getProfile().catch(() => null);
        setUserName(profile?.data?.name || user?.name || '');
        const role = profile?.data?.role ?? user?.role;
        setCanViewAnalytics(role === 'Super Administrator' || role === 'Group Admin');
        await fetchDashboardData();
      } finally {
        setLoading(false);
      }
    };

    void init();
  }, [fetchDashboardData]);

  // The shared countdown (RateLimitProvider) clearing means the backend is
  // accepting requests again — if this page has failed/stale data from
  // being rate limited, retry once automatically instead of waiting on a
  // manual refresh.
  const wasRateLimited = useRef(false);
  useEffect(() => {
    if (wasRateLimited.current && !isRateLimited && fetchError) {
      void fetchDashboardData();
    }
    wasRateLimited.current = isRateLimited;
  }, [isRateLimited, fetchError, fetchDashboardData]);

  const totalNodes = useMemo(
    () => nodesByOS.reduce((sum, item) => sum + item.value, 0),
    [nodesByOS],
  );

  const defenderOn = useMemo(
    () => defenderStatus.find((item) => item.name === 'Defender On')?.value || 0,
    [defenderStatus],
  );

  const totalDefender = useMemo(
    () => defenderStatus.reduce((sum, item) => sum + item.value, 0),
    [defenderStatus],
  );

  const defenderCoveragePct = totalDefender ? (defenderOn / totalDefender) * 100 : 0;

  const alertsOn = useMemo(
    () => alertsStatus.find((item) => item.name === 'Alerts Open')?.value || 0,
    [alertsStatus],
  );

  const totalAlertsStatus = useMemo(
    () => alertsStatus.reduce((sum, item) => sum + item.value, 0),
    [alertsStatus],
  );

  const alertsOpenPct = totalAlertsStatus ? (alertsOn / totalAlertsStatus) * 100 : 0;

  const weeklyTotalAlerts = useMemo(
    () =>
      weeklyAlertsData.reduce((sum, item) => {
        let rowSum = 0;
        for (const [k, v] of Object.entries(item)) {
          if (k !== 'day' && k !== 'date' && typeof v === 'number') rowSum += v;
        }
        return sum + rowSum;
      }, 0),
    [weeklyAlertsData],
  );

  // Shared copy for any card that failed to load, distinguishing "we're
  // being rate limited, and here's when that clears" from a plain failure.
  const failureSubtext = isRateLimited && rateLimitSecondsLeft !== null
    ? `Too many requests — retrying in ${formatCountdown(rateLimitSecondsLeft)}`
    : 'Data unavailable — refresh to retry';

  if (loading) {
    return <DashboardSkeleton />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-white to-slate-50">
      <main className="mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5 space-y-8">
        {/* The global RateLimitBanner (mounted app-wide in App.tsx) already
            explains a 429 and its countdown, so this banner only covers
            other, non-rate-limit failures to avoid saying the same thing twice. */}
        {fetchError && !isRateLimited && (
          <div
            className="flex items-center gap-2 rounded-lg border px-4 py-2.5 text-xs font-medium"
            style={{ borderColor: '#fde68a', backgroundColor: '#fffbeb', color: '#92400e' }}
            role="alert"
          >
            <WarningAmberIcon sx={{ fontSize: 16 }} />
            Some dashboard data couldn&apos;t be loaded — refresh to retry.
          </div>
        )}

        {/* Hero Header — same gradient + Meteors treatment used across the dashboard */}
        <motion.header
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 text-white"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
        >
          <Meteors number={30} className="!bg-white before:!from-white before:!to-transparent" />
          <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
                <DashboardIcon className="w-6 h-6 mr-2" />
                Security posture at a glance
              </h1>
              <p className="mt-1 text-sm text-blue-100 max-w-2xl">
                Snapshot of nodes, endpoint defense, and alert behavior as of your last refresh.
              </p>
            </div>
            {canViewAnalytics && (
              <div className="flex flex-col sm:items-end gap-3 shrink-0">
                <Link
                  to="/analytics"
                  className="inline-flex h-10 items-center gap-1.5 rounded-xl border border-white/20 bg-white/10 backdrop-blur-sm px-4 text-sm font-semibold text-white shadow-sm transition-all hover:bg-white/20"
                >
                  Go to Analytics dashboard
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M9 5l7 7-7 7" /></svg>
                </Link>
              </div>
            )}
          </div>
        </motion.header>

        {/* Stat cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Link to="/my-devices" className={`bg-white rounded-xl shadow-lg p-4 border border-slate-200 border-b-2 block transition-shadow hover:shadow-xl ${osFailed ? 'border-b-slate-300' : 'border-b-slate-500'}`}>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Total Nodes</p>
            <p className={`mt-2 text-2xl font-bold ${osFailed ? 'text-slate-400' : 'text-slate-900'}`}>{osFailed ? 'N/A' : totalNodes}</p>
            <p className="text-xs mt-1 text-slate-800">{osFailed ? failureSubtext : 'Across all onboarded systems'}</p>
          </Link>

          <Link to="/my-devices" className={`bg-white rounded-xl shadow-lg p-4 border border-slate-200 border-b-2 block transition-shadow hover:shadow-xl ${defenderFailed ? 'border-b-slate-300' : defenderCoveragePct >= 80 ? 'border-b-green-500' : defenderCoveragePct >= 50 ? 'border-b-amber-500' : 'border-b-red-500'}`}>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Defender Coverage</p>
            <p className={`mt-2 text-2xl font-bold ${defenderFailed ? 'text-slate-400' : defenderCoveragePct >= 80 ? 'text-green-600' : defenderCoveragePct >= 50 ? 'text-amber-600' : 'text-red-600'}`}>
              {defenderFailed ? 'N/A' : totalDefender ? `${defenderCoveragePct.toFixed(1)}%` : '0%'}
            </p>
            <p className="text-xs mt-1 text-slate-800">{defenderFailed ? failureSubtext : `${defenderOn} endpoints with Defender on`}</p>
          </Link>

          <Link to="/alerts" className={`bg-white rounded-xl shadow-lg p-4 border border-slate-200 border-b-2 block transition-shadow hover:shadow-xl ${alertsFailed ? 'border-b-slate-300' : alertsOpenPct <= 20 ? 'border-b-green-500' : alertsOpenPct <= 50 ? 'border-b-amber-500' : 'border-b-red-500'}`}>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Alerting Active</p>
            <p className={`mt-2 text-2xl font-bold ${alertsFailed ? 'text-slate-400' : alertsOpenPct <= 20 ? 'text-green-600' : alertsOpenPct <= 50 ? 'text-amber-600' : 'text-red-600'}`}>
              {alertsFailed ? 'N/A' : totalAlertsStatus ? `${alertsOpenPct.toFixed(1)}%` : '0%'}
            </p>
            <p className="text-xs mt-1 text-slate-800">{alertsFailed ? failureSubtext : `${alertsOn} reported open alerts`}</p>
          </Link>

          <Link to="/alerts" className="bg-white rounded-xl shadow-lg p-4 border border-slate-200 border-b-2 border-b-red-500 block transition-shadow hover:shadow-xl">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Weekly Alert Volume</p>
            <p className="mt-2 text-2xl font-bold text-red-500">{weeklyTotalAlerts}</p>
            <p className="text-xs mt-1 text-slate-800">Summed across severity classes</p>
          </Link>
        </div>
        <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <DonutMetricCard
            data={nodesByOS}
            title="Node Distribution"
            subtitle="Operating system spread"
            accent={COLORS.primary}
            emptyMessage={osFailed ? failureSubtext : undefined}
          />
          <DonutMetricCard
            data={defenderStatus}
            title="Defender Status"
            subtitle="Defender state on endpoints"
            accent={COLORS.success}
            emptyMessage={defenderFailed ? failureSubtext : undefined}
          />
          <DonutMetricCard
            data={alertsStatus}
            title="Alerting Status"
            subtitle="Open vs. closed alert volume"
            accent={COLORS.secondary}
            emptyMessage={alertsFailed ? failureSubtext : undefined}
          />
        </section>

        <section className="grid grid-cols-1 xl:grid-cols-9 gap-6">
          <div
            className="xl:col-span-5 bg-white rounded-2xl border overflow-hidden"
            style={{
              borderColor: COLORS.border,
              boxShadow: '0 8px 24px rgba(15, 23, 42, 0.05)',
              borderTop: `4px solid ${COLORS.alert}`,
            }}
          >
            <div
              className="px-6 py-5 border-b flex items-center justify-between"
              style={{
                borderColor: COLORS.border,
                backgroundColor: COLORS.light,
              }}
            >
              <div className="flex items-center gap-4">
                <div className="p-2 rounded-lg" style={{ backgroundColor: COLORS.surfaceAlt }}>
                  <WarningAmberIcon sx={{ fontSize: 20, color: COLORS.alert }} />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900 text-sm md:text-base">
                    Top Alerts Machines
                  </h3>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Machines with highest alert counts
                  </p>
                </div>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm border-separate border-spacing-0">
                <thead>
                  <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      #
                    </th>
                    <th
                      className="px-4 py-3 text-left font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      Machine
                    </th>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      Total
                    </th>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      Critical
                    </th>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      High
                    </th>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      Medium
                    </th>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      Low
                    </th>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      Information
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {topAlertsMachines.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-12 text-center text-sm text-slate-500">
                        {topAlertsFailed ? failureSubtext : 'No alert activity to show yet.'}
                      </td>
                    </tr>
                  )}
                  {topAlertsMachines.map((row, i) => (
                    <tr
                      key={i}
                      style={{
                        borderBottom: `1px solid ${COLORS.border}`,
                        backgroundColor: i % 2 === 0 ? COLORS.surface : COLORS.light,
                      }}
                    >
                      <td className="px-4 py-4 text-center text-xs font-semibold" style={{ color: COLORS.slate }}>
                        {i + 1}
                      </td>
                      <td className="px-4 py-4">
                        <Link to={`/my-devices?q=${encodeURIComponent(row.machine)}`} className="font-semibold text-gray-900 text-sm hover:text-blue-600 hover:underline">
                          {row.machine}
                        </Link>
                      </td>
                      <td className="px-4 py-4 text-center">
                        <span
                          className="px-3 py-1 rounded-md text-xs font-bold text-white"
                          style={{ backgroundColor: COLORS.primary }}
                        >
                          {row.alerts}
                        </span>
                      </td>
                      <td className="px-4 py-4 text-center">
                        <span className="text-sm font-bold" style={{ color: COLORS.alert }}>
                          {row.critical}
                        </span>
                      </td>
                      <td className="px-4 py-4 text-center">
                        <span className="text-sm font-bold" style={{ color: COLORS.high }}>
                          {row.high}
                        </span>
                      </td>
                      <td className="px-4 py-4 text-center">
                        <span className="text-sm font-bold" style={{ color: COLORS.warning }}>
                          {row.medium}
                        </span>
                      </td>
                      <td className="px-4 py-4 text-center">
                        <span className="text-sm font-bold" style={{ color: COLORS.success }}>
                          {row.low}
                        </span>
                      </td>
                      <td className="px-4 py-4 text-center">
                        <span className="text-sm font-bold" style={{ color: COLORS.slate }}>
                          {row.information}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div
            className="xl:col-span-4 bg-white rounded-2xl border overflow-hidden"
            style={{
              borderColor: COLORS.border,
              boxShadow: '0 8px 24px rgba(15, 23, 42, 0.05)',
              borderTop: `4px solid ${COLORS.warning}`,
            }}
          >
            <div
              className="px-6 py-5 border-b flex items-center justify-between"
              style={{
                borderColor: COLORS.border,
                backgroundColor: COLORS.light,
              }}
            >
              <div className="flex items-center gap-4">
                <div className="p-2 rounded-lg" style={{ backgroundColor: COLORS.surfaceAlt }}>
                  <UsbIcon sx={{ fontSize: 20, color: COLORS.warning }} />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900 text-sm md:text-base">
                    USB Activity
                  </h3>
                  <p className="text-xs text-gray-500 mt-0.5">
                    Machines with highest USB activity
                  </p>
                </div>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm border-separate border-spacing-0">
                <thead>
                  <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      #
                    </th>
                    <th
                      className="px-4 py-3 text-left font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      Machine
                    </th>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                    >
                      Events
                    </th>
                    <th
                      className="px-4 py-3 text-center font-semibold text-xs sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                      style={{ color: COLORS.primary, backgroundColor: COLORS.light }}
                      title="Relative tier based on USB event count in this period: Low ≤8, Medium 9-15, High >15. Not a security risk assessment."
                    >
                      Activity Level
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {topUSBAlertsMachines.length === 0 && (
                    <tr>
                      <td colSpan={4} className="px-4 py-12 text-center text-sm text-slate-500">
                        {topUsbFailed ? failureSubtext : 'No USB activity to show yet.'}
                      </td>
                    </tr>
                  )}
                  {topUSBAlertsMachines.map((row, i) => (
                    <tr
                      key={i}
                      style={{
                        borderBottom: `1px solid ${COLORS.border}`,
                        backgroundColor: i % 2 === 0 ? COLORS.surface : COLORS.light,
                      }}
                    >
                      <td className="px-4 py-4 text-center text-xs font-semibold" style={{ color: COLORS.slate }}>
                        {i + 1}
                      </td>
                      <td className="px-4 py-4">
                        <Link to={`/my-devices?q=${encodeURIComponent(row.machine)}`} className="font-semibold text-gray-900 text-sm hover:text-blue-600 hover:underline">
                          {row.machine}
                        </Link>
                      </td>
                      <td className="px-4 py-4 text-center">
                        <span
                          className="px-3 py-1 rounded-md text-xs font-bold text-white"
                          style={{ backgroundColor: COLORS.secondary }}
                        >
                          {row.usbEvents}
                        </span>
                      </td>
                      <td className="px-4 py-4 text-center">
                        <span
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold text-white"
                          style={{ backgroundColor: getRiskColor(row.risk) }}
                        >
                          {row.risk}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </section>
      </main>
    </div>
  );
};

export default Dashboard;
