import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis, PieChart, Pie, Tooltip as RTooltip } from 'recharts';
import { PIE_COLORS, renderActiveShape, CustomTooltip as SimpleTooltip, CustomTooltipWithHosts as CustomTooltip } from './shared/ComplianceChart';
// The three registers are ~206KB of code that only renders once a framework tab
// is opened. Loading them lazily keeps the compliance overview (and every route
// that mounts this page) from downloading all three up front.
const NodesViewIRDAIHotCompliance = lazy(() => import('../Nodes/NodesView/NodesViewIRDAIHotCompliance'));
const NodesViewCertInCompliance = lazy(() => import('../Nodes/NodesView/NodesViewCertInCompliance'));
const NodesViewSebiHotCompliance = lazy(() => import('../Nodes/NodesView/NodesViewSebiHotCompliance'));
import type { NodeData } from '../Nodes/NodesView/types';
import { API_BASE_URL, NODES_URLS } from '../../api/urls';
import { csrfHeadersJson, fetchWithCsrf } from '../../api/csrfClient';
import { dashboardApi, type AlertStatusItem, type DefenderCountResponse, type WeeklyAlertsData } from '../../pages/Dashboard/api/dashboardApi';
import { useNodeWebSocket } from '../../hooks/useNodeWebSocket';
import { useSafeFetch, SKIP } from '../../hooks/useSafeFetch';
import { useLiveData } from '../../context/useLiveData';
import { motion } from 'motion/react';
import { Meteors } from '@/components/ui/meteors';
import { ComplianceIcon } from '@/components/icons/navIcons';
import { DuoSpinner, InlineSpinner } from '@/components/ui/loading';
import LiveConnectionBadge from '@/components/ui/LiveConnectionBadge';
import { useToast } from '../../context/useToast';
import { getStoredUser } from '../../services/auth';
import type { ControlPassRate, ComplianceOverview, OrgSnapshot, ComplianceType, ComplianceRouteState } from './types';
import {
  COMPLIANCE_CONTROL_LABELS, COMPLIANCE_KEYS, isWeeklyAlertsDateKey, parseComplianceVerdict,
  mapWithConcurrency, toNodeDataForCompliance, normalizeStatus, summariseSnapshotCoverage,
} from './utils/complianceHelpers';
import { fmtRelative, snapshotAgeTone, snapshotAgeToneClasses } from './shared/complianceDateUtils';











export default function Compliance() {
  const { showToast } = useToast();
  const location = useLocation();
  const searchParams = useMemo(() => new URLSearchParams(location.search), [location.search]);

  const typeParam = searchParams.get('type');
  const activeType: ComplianceType =
    typeParam === 'irdai'
      ? 'irdai'
      : typeParam === 'certin'
        ? 'certin'
        : typeParam === 'sebi-hot'
          ? 'sebi'
          : typeParam === 'iso27001'
            ? 'iso27001'
            : typeParam === 'soc2'
              ? 'soc2'
              : typeParam === 'overview'
                ? 'overview'
                : typeParam === 'sebi'
                  ? 'sebi'
                  : 'overview';
  const hostIdentifierParam = searchParams.get('host_identifier') ?? '';

  const routeState = location.state as ComplianceRouteState;
  const nodeFromState = routeState?.node ?? null;

  const [node, setNode] = useState<NodeData | null>(nodeFromState);
  const [nodeLoading, setNodeLoading] = useState(false);
  const [nodeError, setNodeError] = useState<string | null>(null);

  const [overviewLoading, setOverviewLoading] = useState(false);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [overviewData, setOverviewData] = useState<ComplianceOverview | null>(null);
  // Bumped by the retry affordances below to re-run the overview effect.
  const [overviewReloadKey, setOverviewReloadKey] = useState(0);
  const retryOverview = useCallback(() => setOverviewReloadKey((k) => k + 1), []);

  // Org compliance history (from historical_compliance table)
  // History is supplementary, so a fetch failure isn't shown as a blocking error —
  // but it must still be visually distinguishable from "no snapshot exists yet".
  const { data: orgHistory, loading: orgHistoryLoading, error: orgHistoryError, run: runOrgHistory } = useSafeFetch<OrgSnapshot[]>([]);

  // Live compliance sweep state
  const [liveRefreshLoading, setLiveRefreshLoading] = useState(false);
  const [downloadLoading, setDownloadLoading] = useState(false);
  // GET /api/compliance/reports/pdf is Super-Admin-only (requireSuperAdmin) —
  // hide the button for everyone else instead of letting them click through
  // to a guaranteed 403. Mirrors Sidebar.tsx's cached-role read.
  const isSuperAdmin = getStoredUser()?.role === 'Super Administrator';
  const [liveControlRates, setLiveControlRates] = useState<ControlPassRate[] | null>(null);
  const [liveNodeStats, setLiveNodeStats] = useState<
    { queried: number; responded: number; nonResponding: Array<{ hostId: string; hostname: string | null }> } | null
  >(null);
  const [wsEnabled, setWsEnabled] = useState(false);
  const [, setLiveTopNonCompliant] = useState<Array<{ hostId: string; hostname: string | null; percent: number }>>([]);
  // Populated by the overview useEffect. This used to be a bare ref, which meant
  // neither the render body nor onlineWindowsCount ever observed it landing: the
  // Refresh Live button stayed enabled while claiming "No online Windows nodes"
  // and did nothing when clicked. It is state now so both recompute.
  const [windowsNodes, setWindowsNodes] = useState<Array<{ hostId: string; hostname: string | null }>>([]);
  // Why the last Refresh Live click did nothing, shown inline next to the button.
  const [liveRefreshNotice, setLiveRefreshNotice] = useState<string | null>(null);
  // A snapshot POST that failed must be visible: this row is the sole writer of
  // historical_compliance and it feeds the Vajra headline score in the PDF.
  const [snapshotSaveError, setSnapshotSaveError] = useState<string | null>(null);

  // Cancellation for the org sweep. A sweep torn down half-way (unmount, tab
  // switch, socket drop) must NOT persist its partial result as a completed
  // snapshot: a torn-down sweep is not-assessed, so the correct outcome is no
  // row at all.
  const liveRunTokenRef = useRef(0);
  const liveRunActiveRef = useRef<number | null>(null);
  const liveRunDisruptedRef = useRef(false);

  const { data: sebiOrgHistory, loading: sebiOrgHistoryLoading, error: sebiOrgHistoryError, run: runSebiOrgHistory } = useSafeFetch<OrgSnapshot[]>([]);

  const { data: irdaiOrgHistory, loading: irdaiOrgHistoryLoading, error: irdaiOrgHistoryError, run: runIrdaiOrgHistory } = useSafeFetch<OrgSnapshot[]>([]);

  const { data: certinOrgHistory, loading: certinOrgHistoryLoading, error: certinOrgHistoryError, run: runCertinOrgHistory } = useSafeFetch<OrgSnapshot[]>([]);
  const [, setActiveIndex] = useState(0);

  // Node-group names in the viewer's scope — empty for an unrestricted (Super Admin)
  // viewer or a scoped user with no group assigned. Used only to label the page,
  // not to filter anything (the backend already scopes every request).
  const [, setScopeGroupNames] = useState<string[]>([]);

  useEffect(() => {
    let cancelled = false;
    fetch(NODES_URLS.GROUPS, { credentials: 'include' })
      .then((res) => (res.ok ? res.json() : null))
      .then((json) => {
        if (cancelled || !json) return;
        if (json?.status === 'Success' && Array.isArray(json.groups)) {
          setScopeGroupNames(json.groups as string[]);
        }
      })
      .catch(() => {
        // silently ignore — this only drives a supplementary label
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const fetchOrgHistory = useCallback(() => runOrgHistory(async (signal) => {
    const res = await fetch(NODES_URLS.ORG_COMPLIANCE_HISTORY, { credentials: 'include', signal });
    if (!res.ok) throw new Error('Failed to load org compliance history');
    const json = await res.json();
    if (json?.success && Array.isArray(json.data)) {
      return json.data as OrgSnapshot[];
    }
    return SKIP;
  }), [runOrgHistory]);

  const { nodeStatus } = useLiveData();
  const { connected: wsConnected, sendMessage: wsSendMessage } = useNodeWebSocket(
    '__org_compliance__',
    wsEnabled,
  );

  useEffect(() => {
    if (nodeFromState) {
      setNode(nodeFromState);
      return;
    }

    if (!hostIdentifierParam) return;

    let cancelled = false;
    setNodeLoading(true);
    setNodeError(null);

    fetch(`${NODES_URLS.NODE}${encodeURIComponent(hostIdentifierParam)}`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
    })
      .then((res) => {
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        return res.json();
      })
      .then((data) => {
        if (cancelled) return;
        const raw = (data && typeof data === 'object' && 'data' in data ? data.data : data) as unknown;
        setNode(toNodeDataForCompliance(raw));
      })
      .catch((err) => {
        if (cancelled) return;
        console.error('Failed to load node details', err);
        setNodeError('Failed to load node details. Please try again.');
      })
      .finally(() => {
        if (cancelled) return;
        setNodeLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [hostIdentifierParam, nodeFromState]);

  useEffect(() => {
    if (activeType !== 'overview') return;

    let cancelled = false;
    const run = async () => {
      setOverviewLoading(true);
      setOverviewError(null);

      try {
        const generatedAt = Date.now();

        // 1) Fleet inventory (enrolled machines) + per-node metadata (online/offline heuristics).
        const res = await fetch(NODES_URLS.NODES_IDENTIFIERS, {
          method: 'GET',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
          },
        });

        if (!res.ok) throw new Error(`Failed to fetch nodes: HTTP ${res.status}`);
        const json = await res.json();
        let nodesArray: Array<Record<string, unknown>> = [];
        if (json?.data) nodesArray = Array.isArray(json.data) ? json.data : [];
        else if (json?.nodes) nodesArray = Array.isArray(json.nodes) ? json.nodes : [];
        else if (Array.isArray(json)) nodesArray = json;

        const totalNodes = nodesArray.length;
        const onlineNodes = nodesArray.filter(
          (n) => n?.agent_online === true || normalizeStatus(n?.status) === 'online',
        ).length;
        const offlineNodes = Math.max(0, totalNodes - onlineNodes);

        const osBreakdown = (() => {
          const m = new Map<string, number>();
          for (const n of nodesArray) {
            const os = String(n?.os_name ?? n?.os_platform ?? '').trim();
            if (!os) continue;
            m.set(os, (m.get(os) ?? 0) + 1);
          }
          return Array.from(m.entries())
            .map(([name, count]) => ({ name, count }))
            .sort((a, b) => b.count - a.count);
        })();

        const windowsHostsArr = nodesArray
          .filter((n) => String(n?.os_platform ?? '').toLowerCase().includes('windows'))
          .map((n) => {
            const hostId = String(n?.host_identifier ?? n?.id ?? '').trim();
            return {
              hostId,
              hostname: typeof n?.hostname === 'string' ? n.hostname : null,
            };
          })
          .filter((x) => x.hostId.length > 0);

        // Held in state (not a ref) so the Refresh Live button's enabled state and
        // its online-node count actually re-render once the fleet list lands.
        if (!cancelled) setWindowsNodes(windowsHostsArr);

        const windowsHosts = windowsHostsArr.length;

        // 2) Fleet analytics (alerts + defender + OS summary).
        const graphResults = await Promise.allSettled([
          dashboardApi.getOsCount(),
          dashboardApi.getDefenderCount(),
          dashboardApi.getAlertStatus(),
          dashboardApi.getWeeklyAlerts(),
          dashboardApi.getTop5MachineAlerts(),
        ]);

        const osCountSettled = graphResults[0];
        const osCount = osCountSettled.status === 'fulfilled' && Array.isArray(osCountSettled.value) ? osCountSettled.value : [];
        const osBreakdownFromGraph = osCount.map((item) => ({ name: String(item.name), count: Number(item.count) || 0 }));

        const defenderResults = graphResults[1];
        const defenderFulfilled = defenderResults.status === 'fulfilled' ? defenderResults.value : undefined;
        // No payload means the zeros below are a placeholder, not a reading.
        const defenderFailed = !defenderFulfilled?.data;
        const defenderData: DefenderCountResponse['data'] =
          defenderFulfilled?.data
            ? defenderFulfilled.data
            : { on: 0, off: 0, total_hosts: defenderFulfilled?.data?.total_hosts ?? 0 };

        const alertsStatusResults = graphResults[2];
        const alertsFailed = !(alertsStatusResults.status === 'fulfilled' && Array.isArray(alertsStatusResults.value));
        const alertStatusItems: AlertStatusItem[] =
          alertsStatusResults.status === 'fulfilled' && Array.isArray(alertsStatusResults.value) ? alertsStatusResults.value : [];

        const openCount = alertStatusItems
          .filter((i) => String(i.name).toLowerCase() === 'online')
          .reduce((sum, i) => sum + (Number(i.count) || 0), 0);
        const closeCount = alertStatusItems
          .filter((i) => String(i.name).toLowerCase() !== 'online')
          .reduce((sum, i) => sum + (Number(i.count) || 0), 0);

        const weeklyResults = graphResults[3];
        const weeklyAlertsFailed = weeklyResults.status !== 'fulfilled';
        const weeklyData: WeeklyAlertsData = weeklyResults.status === 'fulfilled' ? (weeklyResults.value ?? {}) : {};
        const weeklyTotals = (() => {
          const keys = Object.keys(weeklyData || {}).filter((k) => isWeeklyAlertsDateKey(k));
          keys.sort((a, b) => {
            const [ad, am, ay] = a.split('/');
            const [bd, bm, by] = b.split('/');
            return new Date(parseInt(ay, 10), parseInt(am, 10) - 1, parseInt(ad, 10)).getTime() -
              new Date(parseInt(by, 10), parseInt(bm, 10) - 1, parseInt(bd, 10)).getTime();
          });
          const lastKeys = keys.slice(-7);
          return lastKeys.map((dateKey) => {
            const dayObj = weeklyData[dateKey] as Record<string, unknown> | undefined;
            const total = dayObj
              ? (Object.values(dayObj) as unknown[]).reduce(
                (sum: number, v) => sum + (typeof v === 'number' ? v : Number(v) || 0),
                0,
              )
              : 0;
            // Make a readable label (e.g., "Mon, 01 Jan 2026")
            const [d, m, y] = dateKey.split('/');
            const dateObj = new Date(parseInt(y, 10), parseInt(m, 10) - 1, parseInt(d, 10));
            const dateLabel = Number.isFinite(dateObj.getTime())
              ? dateObj.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: '2-digit' })
              : dateKey;
            return { dateLabel, dateKey, total };
          });
        })();

        const topAlertsResults = graphResults[4];
        const topMachineAlerts = (() => {
          if (topAlertsResults.status !== 'fulfilled') return [];
          const data = topAlertsResults.value?.data;
          if (!Array.isArray(data)) return [];
          return data.slice(0, 5).map((item) => ({
            hostname: String(item.hostname ?? ''),
            hostIdentifier: String(item.host_identifier ?? ''),
            totalAlerts: Number(item.total_alerts) || 0,
            critical: typeof item.critical === 'string' ? parseInt(item.critical, 10) || 0 : Number(item.critical) || 0,
            high: typeof item.high === 'string' ? parseInt(item.high, 10) || 0 : Number(item.high) || 0,
            medium: typeof item.medium === 'string' ? parseInt(item.medium, 10) || 0 : Number(item.medium) || 0,
            low: typeof item.low === 'string' ? parseInt(item.low, 10) || 0 : Number(item.low) || 0,
            information: typeof item.information === 'string' ? parseInt(item.information, 10) || 0 : Number(item.information) || 0,
          }));
        })();


        const overview: ComplianceOverview = {
          generatedAt,
          failed: {
            defender: defenderFailed,
            alerts: alertsFailed,
            weeklyAlerts: weeklyAlertsFailed,
          },
          totalNodes,
          onlineNodes,
          offlineNodes,
          osBreakdown: (osBreakdownFromGraph.length ? osBreakdownFromGraph : osBreakdown).map((x) => ({
            name: x.name,
            count: x.count,
          })),
          windowsHosts,

          alerts: {
            openCount,
            closeCount,
            weeklyTotals,
            topMachines: topMachineAlerts,
          },

          defender: {
            on: Number(defenderData.on) || 0,
            off: Number(defenderData.off) || 0,
            total: Number(defenderData.total_hosts) || (Number(defenderData.on) || 0) + (Number(defenderData.off) || 0),
          },
        };

        if (!cancelled) setOverviewData(overview);
      } catch (err: unknown) {
        if (cancelled) return;
        console.error('Failed to load compliance overview', err);
        setOverviewError('Failed to load compliance overview. Please try again.');
      } finally {
        if (!cancelled) setOverviewLoading(false);
      }
    };

    void run();
    return () => {
      cancelled = true;
    };
  }, [activeType, overviewReloadKey]);

  // Enable the WS connection while the overview or sebi tab is active;
  // clear live overview data when leaving the overview tab.
  useEffect(() => {
    if (activeType === 'overview' || activeType === 'sebi' || activeType === 'irdai' || activeType === 'certin') {
      setWsEnabled(true);
    } else {
      setWsEnabled(false);
    }
    if (activeType !== 'overview') {
      // Leaving the overview tears down the sweep's consumer, so mark any
      // in-flight run cancelled before its results can be persisted.
      liveRunActiveRef.current = null;
      setLiveControlRates(null);
      setLiveNodeStats(null);
      setLiveTopNonCompliant([]);
    }
  }, [activeType]);

  // Unmount cancels any in-flight sweep for the same reason.
  useEffect(() => () => { liveRunActiveRef.current = null; }, []);

  // A socket drop while a sweep is running means the remaining hosts were never
  // asked. Record it so the partial result is not written as a complete run.
  useEffect(() => {
    if (!wsConnected && liveRunActiveRef.current !== null) {
      liveRunDisruptedRef.current = true;
    }
  }, [wsConnected]);

  // Fetch org compliance history whenever the overview tab is active
  useEffect(() => {
    if (activeType === 'overview') {
      void fetchOrgHistory();
    }
  }, [activeType, fetchOrgHistory]);

  const fetchSebiOrgHistory = useCallback(() => runSebiOrgHistory(async (signal) => {
    const res = await fetch(NODES_URLS.SEBI_COMPLIANCE_HISTORY, { credentials: 'include', signal });
    if (!res.ok) throw new Error('Failed to load SEBI org compliance history');
    const json = await res.json();
    if (json?.success && Array.isArray(json.data)) {
      return json.data as OrgSnapshot[];
    }
    return SKIP;
  }), [runSebiOrgHistory]);

  const fetchIrdaiOrgHistory = useCallback(() => runIrdaiOrgHistory(async (signal) => {
    const res = await fetch(NODES_URLS.IRDAI_COMPLIANCE_HISTORY, { credentials: 'include', signal });
    if (!res.ok) throw new Error('Failed to load IRDAI org compliance history');
    const json = await res.json();
    if (json?.success && Array.isArray(json.data)) {
      return json.data as OrgSnapshot[];
    }
    return SKIP;
  }), [runIrdaiOrgHistory]);

  const fetchCertinOrgHistory = useCallback(() => runCertinOrgHistory(async (signal) => {
    const res = await fetch(NODES_URLS.CERTIN_COMPLIANCE_HISTORY, { credentials: 'include', signal });
    if (!res.ok) throw new Error('Failed to load CERT-In org compliance history');
    const json = await res.json();
    if (json?.success && Array.isArray(json.data)) {
      return json.data as OrgSnapshot[];
    }
    return SKIP;
  }), [runCertinOrgHistory]);

  useEffect(() => {
    void fetchSebiOrgHistory();
    void fetchIrdaiOrgHistory();
    void fetchCertinOrgHistory();
  }, [fetchSebiOrgHistory, fetchIrdaiOrgHistory, fetchCertinOrgHistory]);

  // Sends all 18 compliance keys to every online Windows node in parallel (concurrency 4)
  // and aggregates the per-control pass/fail counts for the live table.
  const handleLiveRefresh = useCallback(async () => {
    if (!wsConnected || liveRefreshLoading) return;

    setLiveRefreshNotice(null);
    setSnapshotSaveError(null);

    const onlineIds = new Set(nodeStatus?.agentOnline ?? []);
    const targets = windowsNodes.filter((n) => onlineIds.has(n.hostId));
    if (targets.length === 0) {
      // Used to be a bare `return` — no spinner, no message, no state change, so
      // the click looked like a broken button. Say what is actually missing.
      const notice = windowsNodes.length === 0
        ? 'No Windows nodes are enrolled in your scope, so there is nothing to sweep.'
        : `No online Windows node to query — ${windowsNodes.length} Windows node${windowsNodes.length !== 1 ? 's' : ''} enrolled, none reachable right now.`;
      setLiveRefreshNotice(notice);
      showToast(notice, 'error');
      return;
    }

    const runToken = liveRunTokenRef.current + 1;
    liveRunTokenRef.current = runToken;
    liveRunActiveRef.current = runToken;
    liveRunDisruptedRef.current = false;

    setLiveRefreshLoading(true);
    setLiveControlRates(null);
    setLiveNodeStats(null);
    try {
      const rawResults = await mapWithConcurrency(
        targets,
        4,
        async ({ hostId }) => {
          try {
            const resp = await wsSendMessage(
              {
                type: 'agent',
                params: { agent: 'powershell', action: 'allow', command_keys: COMPLIANCE_KEYS },
                host_identifier: hostId,
              },
              { timeoutMs: 45_000 },
            );
            const raw = resp?.response;
            let rows: Array<{ command_key: string; output: string }> = [];
            if (typeof raw === 'string') {
              const parsed = JSON.parse(raw);
              rows = Array.isArray(parsed) ? parsed : [];
            } else if (Array.isArray(raw)) {
              rows = raw;
            }
            if (rows.length === 0) return null;
            const passByKey: Record<string, boolean> = {};
            const eligibleByKey: Record<string, boolean> = {};
            for (const r of rows) {
              const k = String(r.command_key);
              const verdict = parseComplianceVerdict(k, String(r.output));
              // not_assessed leaves eligibleByKey[k] unset, so the host neither
              // passes nor fails this control. Unreadable output is not a failure.
              if (verdict === 'not_assessed') continue;
              eligibleByKey[k] = true;
              passByKey[k] = verdict === 'pass';
            }
            return { passByKey, eligibleByKey };
          } catch {
            return null;
          }
        },
      );

      // If the sweep was torn down (unmount, tab switch, socket drop) the hosts
      // that never answered were never asked — the run is not a measurement of
      // the fleet, so it is discarded rather than written as a complete snapshot.
      if (liveRunActiveRef.current !== runToken || liveRunDisruptedRef.current) {
        const notice = 'Compliance sweep was interrupted before it finished — no snapshot was saved. Re-run it while staying on this page.';
        setLiveRefreshNotice(notice);
        showToast(notice, 'error');
        return;
      }

      const responded = rawResults.filter((r): r is NonNullable<typeof r> => r !== null);
      const nonResponding = targets.filter((_, i) => rawResults[i] === null);

      const rates = COMPLIANCE_KEYS.map((key) => {
        let eligibleHosts = 0;
        let passHosts = 0;
        for (const r of responded) {
          if (!r.eligibleByKey[key]) continue;
          eligibleHosts++;
          if (r.passByKey[key]) passHosts++;
        }
        return {
          key,
          label: COMPLIANCE_CONTROL_LABELS[key] ?? `Control ${key}`,
          passRatePct: eligibleHosts > 0 ? Math.round((passHosts / eligibleHosts) * 100) : null,
          passHosts,
          failHosts: eligibleHosts - passHosts,
          eligibleHosts,
        };
      });

      setLiveControlRates(rates);
      setLiveNodeStats({ queried: targets.length, responded: responded.length, nonResponding });

      // Compute per-host compliance scores for aggregates and top non-compliant list
      const hostScoresWithMeta = rawResults.map((r, i) => {
        if (r === null) return null;
        const eligible = COMPLIANCE_KEYS.filter((k) => r.eligibleByKey[k]);
        if (eligible.length === 0) return null;
        const passed = eligible.filter((k) => r.passByKey[k]).length;
        return {
          hostId: targets[i].hostId,
          hostname: targets[i].hostname,
          percent: Math.round((passed / eligible.length) * 100),
        };
      }).filter((s): s is NonNullable<typeof s> => s !== null);

      const hostScores = hostScoresWithMeta.map((s) => s.percent);
      setLiveTopNonCompliant(
        [...hostScoresWithMeta].sort((a, b) => a.percent - b.percent).slice(0, 5),
      );

      const liveAvg = hostScores.length ? Math.round(hostScores.reduce((a, b) => a + b, 0) / hostScores.length) : null;
      const liveStrong = hostScores.filter((s) => s >= 90).length;
      const liveModerate = hostScores.filter((s) => s >= 75 && s < 90).length;
      const liveNeeds = hostScores.filter((s) => s < 75).length;

      // Save snapshot to historical_compliance table
      try {
        const res = await fetchWithCsrf(NODES_URLS.ORG_COMPLIANCE_SNAPSHOT, {
          method: 'POST',
          credentials: 'include',
          headers: csrfHeadersJson(),
          body: JSON.stringify({
            snapshotAt: Math.floor(Date.now() / 1000),
            totalNodes: windowsNodes.length,
            windowsHosts: targets.length,
            windowsWithResults: responded.length,
            avgCompliancePercent: liveAvg,
            strongCount: liveStrong,
            moderateCount: liveModerate,
            needsAttentionCount: liveNeeds,
            controlPassRates: rates,
            // The org history endpoint has no fully_compliant_nodes column; it
            // derives that figure from these lists, so a snapshot that omits
            // them renders as 0 compliant / everything non-compliant.
            fullyCompliantNodesList: hostScoresWithMeta.filter((h) => h.percent === 100).map((h) => h.hostId),
            nonCompliantNodesList: hostScoresWithMeta.filter((h) => h.percent < 100).map((h) => h.hostId),
            source: 'live',
          }),
        });
        if (!res.ok) {
          // Do NOT refresh the history list — nothing was written.
          const message = `Compliance snapshot was not saved (HTTP ${res.status}). The sweep results below were not recorded.`;
          console.error('Org compliance snapshot save failed', { status: res.status, statusText: res.statusText });
          setSnapshotSaveError(message);
          showToast(message, 'error');
        } else {
          // Refresh history list after saving
          void fetchOrgHistory();
        }
      } catch (err) {
        const message = 'Compliance snapshot could not be saved — the sweep results below were not recorded.';
        console.error('Org compliance snapshot save failed', err);
        setSnapshotSaveError(message);
        showToast(message, 'error');
      }
    } finally {
      if (liveRunActiveRef.current === runToken) liveRunActiveRef.current = null;
      setLiveRefreshLoading(false);
    }
  }, [wsConnected, liveRefreshLoading, nodeStatus, windowsNodes, wsSendMessage, fetchOrgHistory, showToast]);

  // The sweep's WebSocket is owned by this page (useNodeWebSocket below) and
  // has no pause/resume — navigating away or closing the tab mid-sweep kills
  // every in-flight and not-yet-started request instantly, silently, with
  // whatever subset had already responded reported as if the sweep were
  // complete. Warn on tab close/reload; there's no equivalent browser hook
  // for in-app SPA navigation, so this only covers the close/reload case.
  useEffect(() => {
    if (!liveRefreshLoading) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [liveRefreshLoading]);

  const handleDownloadVajraCompliance = useCallback(async () => {
    if (downloadLoading) return;

    setDownloadLoading(true);
    try {
      const downloadUrl = `${API_BASE_URL}/api/compliance/reports/pdf`;
      const response = await fetch(downloadUrl, {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        throw new Error(errorText || `Download failed with status ${response.status}`);
      }

      const contentType = response.headers.get('content-type') ?? '';
      if (!contentType.toLowerCase().includes('pdf')) {
        const preview = await response.text().catch(() => '');
        throw new Error(preview || `Unexpected response type: ${contentType || 'unknown'}`);
      }

      const blob = await response.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = 'vajra-compliance.pdf';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(objectUrl);
    } catch (error) {
      console.error('Failed to download Vajra Compliance PDF', error);
      showToast('Failed to download the compliance report. Please try again.', 'error');
    } finally {
      setDownloadLoading(false);
    }
  }, [downloadLoading, showToast]);

  // Count of online Windows nodes available for a live sweep
  const onlineWindowsCount = useMemo(
    () => {
      const ids = new Set(nodeStatus?.agentOnline ?? []);
      return windowsNodes.filter((n) => ids.has(n.hostId)).length;
    },
    [nodeStatus, windowsNodes],
  );

  const activeSnapshot = useMemo(() => orgHistory.length > 0 ? orgHistory[0] : null, [orgHistory]);

  const nodeToRender: NodeData = useMemo(() => {
    if (node) return node;
    return {
      id: 0,
      name: 'Unknown node',
      status: 'offline',
      host_identifier: hostIdentifierParam || undefined,
    };
  }, [node, hostIdentifierParam]);

  // nodeStatus.agentOnline is a fleet-length array, so this was a linear scan
  // written inline in the render body — and written three times over, once per
  // compliance-type branch below. Live snapshots re-render this page, so it
  // ran on each of them.
  const hotComplianceAgentOnline = useMemo(
    () =>
      nodeToRender.host_identifier
        ? (nodeStatus?.agentOnline?.includes(nodeToRender.host_identifier) ?? nodeToRender.agent_online ?? false)
        : true,
    [nodeStatus, nodeToRender],
  );

  const buildTypeLink = (nextType: ComplianceType) => {
    const base = `/compliance?type=${encodeURIComponent(nextType)}`;
    return hostIdentifierParam ? `${base}&host_identifier=${encodeURIComponent(hostIdentifierParam)}` : base;
  };

  const weeklyAlertChartData = useMemo(() => {
    const fromApi = overviewData?.alerts?.weeklyTotals ?? [];
    if (fromApi.length > 0) {
      return fromApi.map((d) => ({
        ...d,
        shortLabel: d.dateLabel.replace(',', ''),
      }));
    }

    // Empty-state fallback: still render a 7-day chart shell with zero values.
    return Array.from({ length: 7 }).map((_, idx) => {
      const dt = new Date();
      dt.setDate(dt.getDate() - (6 - idx));
      const dateLabel = dt.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: '2-digit' });
      const dateKey = `${dt.getDate()}/${dt.getMonth() + 1}/${dt.getFullYear()}`;
      return {
        dateLabel,
        dateKey,
        total: 0,
        shortLabel: dateLabel.replace(',', ''),
      };
    });
  }, [overviewData]);

  // Gated on the fetch succeeding, so the placeholder bars can't read as a quiet week.
  const hasWeeklyAlertVolume = useMemo(
    () => !overviewData?.failed.weeklyAlerts && weeklyAlertChartData.some((d) => d.total > 0),
    [overviewData, weeklyAlertChartData],
  );

  const failedOverviewWidgetLabels = useMemo(() => {
    const failed = overviewData?.failed;
    if (!failed) return [];
    const labels: string[] = [];
    if (failed.alerts) labels.push('alert counts');
    if (failed.weeklyAlerts) labels.push('weekly alert volume');
    if (failed.defender) labels.push('Defender coverage');
    return labels;
  }, [overviewData]);

  const hasFailedOverviewWidgets = failedOverviewWidgetLabels.length > 0;

  const weeklyYAxisMax = useMemo(() => {
    if (!hasWeeklyAlertVolume) return 200;
    const peak = Math.max(...weeklyAlertChartData.map((d) => d.total));
    return Math.ceil((peak + 25) / 50) * 50;
  }, [hasWeeklyAlertVolume, weeklyAlertChartData]);

  const peakWeeklyAlert = useMemo(() => {
    if (!hasWeeklyAlertVolume) {
      return { dateKey: '', total: 0 };
    }
    return weeklyAlertChartData.reduce(
      (max, item) => (item.total > max.total ? item : max),
      { dateKey: '', total: -1 } as { dateKey: string; total: number },
    );
  }, [hasWeeklyAlertVolume, weeklyAlertChartData]);

  // null = no snapshot / no assessed nodes yet, distinct from a real 0%
  // compliant reading — do not fold this into 0, or the "no data" empty
  // state below becomes unreachable (0 >= 0 is always true).
  const latestSebiData: number | null =
    (sebiOrgHistory?.[0]?.windows_with_results ?? 0) > 0
      ? ((sebiOrgHistory[0].fully_compliant_nodes ?? 0) /
        (sebiOrgHistory[0].windows_with_results ?? 1)) * 100
      : null;

  const latestIrdaiData: number | null =
    (irdaiOrgHistory?.[0]?.windows_with_results ?? 0) > 0
      ? ((irdaiOrgHistory[0].fully_compliant_nodes ?? 0) /
        (irdaiOrgHistory[0].windows_with_results ?? 1)) * 100
      : null;

  const latestCertinData: number | null =
    (certinOrgHistory?.[0]?.windows_with_results ?? 0) > 0
      ? ((certinOrgHistory[0].fully_compliant_nodes ?? 0) /
        (certinOrgHistory[0].windows_with_results ?? 1)) * 100
      : null;

  // This page also holds live-sweep WebSocket state, so it re-renders on every
  // fleet status change. Unmemoised, each of those renders re-spreads, merges
  // and re-sorts all four history arrays (up to 200 freshly allocated objects)
  // to arrive at the same top 10.
  const recentSnapshots = useMemo(
    () => {
      // certin_historical_compliance stores total_nodes and windows_hosts with
      // their meanings transposed relative to the SEBI and IRDAI tables (the
      // CERT-In writer persists totalNodes = hosts swept, windowsHosts = fleet
      // Windows hosts). The PDF already compensates on read; this table did not.
      // Stored rows are never rewritten — the two are swapped back here only.
      const normalise = (snapshot: OrgSnapshot, complianceType: string) => {
        const transposed = complianceType === 'CERT-IN';
        const fleetWindowsHosts = transposed ? snapshot.windows_hosts : snapshot.total_nodes;
        const sweptWindowsHosts = transposed ? snapshot.total_nodes : snapshot.windows_hosts;

        // historical_compliance (VAJRA) has no fully_compliant_nodes column, so
        // the endpoint cannot return one. Derive the count from the stored node
        // list instead of folding the absent value into a measured 0.
        const fullyCompliantCount: number | null =
          snapshot.fully_compliant_nodes != null
            ? Number(snapshot.fully_compliant_nodes)
            : Array.isArray(snapshot.fully_compliant_nodes_list)
              ? snapshot.fully_compliant_nodes_list.length
              : null;

        const respondedHosts = snapshot.windows_with_results == null ? null : Number(snapshot.windows_with_results);
        // Derived from the same two numbers as the score column so the badge and
        // the percentage can never disagree; the stored list is only a fallback.
        const notFullyCompliantCount: number | null =
          respondedHosts != null && fullyCompliantCount != null
            ? respondedHosts - fullyCompliantCount
            : Array.isArray(snapshot.non_compliant_nodes_list)
              ? snapshot.non_compliant_nodes_list.length
              : null;

        return {
          ...snapshot,
          complianceType,
          fleetWindowsHosts,
          sweptWindowsHosts,
          respondedHosts,
          fullyCompliantCount,
          notFullyCompliantCount,
        };
      };

      return [
        ...sebiOrgHistory.map((snapshot) => normalise(snapshot, 'SEBI')),
        ...irdaiOrgHistory.map((snapshot) => normalise(snapshot, 'IRDAI')),
        ...certinOrgHistory.map((snapshot) => normalise(snapshot, 'CERT-IN')),
        ...orgHistory.map((snapshot) => normalise(snapshot, 'VAJRA')),
      ]
        .sort((a, b) => Number(b.snapshot_at) - Number(a.snapshot_at))
        .slice(0, 10);
    },
    [sebiOrgHistory, irdaiOrgHistory, certinOrgHistory, orgHistory],
  );

  const averageSebiNodePieData =
    latestSebiData !== null
      ? [
        {
          name: 'Compliant',
          value: Number(latestSebiData.toFixed(2)),
          hosts: sebiOrgHistory[0]?.fully_compliant_nodes_list ?? [],
        },
        {
          name: 'Non-Compliant',
          value: 100 - Number(latestSebiData.toFixed(2)),
          hosts: sebiOrgHistory[0]?.non_compliant_nodes_list ?? [],
        },
      ]
      : [];

  const averageIrdaiNodePieData =
    latestIrdaiData !== null
      ? [
        {
          name: 'Compliant',
          value: Number(latestIrdaiData.toFixed(2)),
          hosts: irdaiOrgHistory[0]?.fully_compliant_nodes_list ?? [],
        },
        {
          name: 'Non-Compliant',
          value: 100 - Number(latestIrdaiData.toFixed(2)),
          hosts: irdaiOrgHistory[0]?.non_compliant_nodes_list ?? [],
        },
      ]
      : [];

  const averageCertinNodePieData =
    latestCertinData !== null
      ? [
        {
          name: 'Compliant',
          value: Number(latestCertinData.toFixed(2)),
          hosts: certinOrgHistory[0]?.fully_compliant_nodes_list ?? [],
        },
        {
          name: 'Non-Compliant',
          value: 100 - Number(latestCertinData.toFixed(2)),
          hosts: certinOrgHistory[0]?.non_compliant_nodes_list ?? [],
        },
      ]
      : [];

  // NOTE: unlike the three framework donuts (share of HOSTS fully compliant),
  // this one plots avg_compliance_percent — the share of CONTROLS passing,
  // averaged over hosts. The two differ by tens of points on the same fleet, so
  // it is labelled for what it measures and carries no per-host breakdown.
  const averageVajraNodePieData =
    activeSnapshot?.avg_compliance_percent !== null && activeSnapshot?.avg_compliance_percent !== undefined
      ? [
        {
          name: 'Controls passing',
          value: Number(Number(activeSnapshot?.avg_compliance_percent ?? 0).toFixed(2)),
        },
        {
          name: 'Controls failing',
          value: 100 - Number(Number(activeSnapshot?.avg_compliance_percent ?? 0).toFixed(2)),
        },
      ]
      : [];

  // A month-old score must not render identically to a fresh one, and a donut
  // that covers 6 of 14 endpoints must say so on the card, not only in a toolbar
  // on another tab.
  const renderSnapshotMeta = (snap: OrgSnapshot | undefined, complianceType: 'SEBI' | 'IRDAI' | 'CERT-IN') => {
    if (!snap) return null;
    // CERT-In stores total_nodes/windows_hosts transposed (see recentSnapshots).
    const transposed = complianceType === 'CERT-IN';
    const sweptHosts = transposed ? snap.total_nodes : snap.windows_hosts;
    const respondedHosts = snap.windows_with_results;
    const relative = fmtRelative(snap.snapshot_at);
    const tone = snapshotAgeTone(snap.snapshot_at);
    // AGG-11: the donut plots fully_compliant_nodes / windows_with_results, and
    // "fully compliant" means the host passed every control IT was measured on —
    // a denominator that varies host by host and is never the framework's whole
    // control set. The figure is only readable next to that denominator, so it
    // is published here rather than left implicit.
    const fullyCompliant: number | null =
      snap.fully_compliant_nodes != null
        ? Number(snap.fully_compliant_nodes)
        : Array.isArray(snap.fully_compliant_nodes_list)
          ? snap.fully_compliant_nodes_list.length
          : null;
    const coverage = summariseSnapshotCoverage(snap);
    return (
      <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
        <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-semibold ${snapshotAgeToneClasses(tone)}`}>
          <i className="fa fa-clock-rotate-left text-[9px]" aria-hidden="true" />
          {new Date(Number(snap.snapshot_at) * 1000).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' })}
          {relative ? ` — ${relative}` : ''}
        </span>
        <span className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 font-semibold text-slate-600">
          <i className="fa fa-server text-[9px]" aria-hidden="true" />
          Coverage {respondedHosts ?? '—'} / {sweptHosts ?? '—'} endpoints
        </span>
        {fullyCompliant != null && respondedHosts != null && (
          <span className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 font-semibold text-slate-600">
            <i className="fa fa-list-check text-[9px]" aria-hidden="true" />
            {fullyCompliant} / {respondedHosts} hosts fully compliant on the controls each was measured on
          </span>
        )}
        {coverage && coverage.meanControlsPerHost != null && (
          <span
            className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 font-semibold text-slate-600"
            title={`${coverage.assessedPairs} measured (host, control) pairs across ${coverage.respondedHosts} responding host(s). The snapshot stores fleet totals only, so this is the mean per host — the per-host assessed count is not persisted, and no per-host coverage floor can be applied on read.`}
          >
            <i className="fa fa-ruler text-[9px]" aria-hidden="true" />
            Mean {coverage.meanControlsPerHost} of {coverage.recordedControls} recorded controls measured per host
            {' · '}{coverage.measuredControls} control{coverage.measuredControls === 1 ? '' : 's'} carried any measurement
          </span>
        )}
        {tone === 'expired' && (
          <span className="font-semibold text-red-700">Older than 30 days — re-run before relying on this figure.</span>
        )}
        {coverage && coverage.universalFailureLabels.length > 0 && (
          <p className="w-full text-[11px] leading-snug text-slate-500">
            <span className="font-semibold text-slate-600">What drives this score:</span>{' '}
            every responding host failed {coverage.universalFailureLabels.length} control
            {coverage.universalFailureLabels.length === 1 ? '' : 's'} —{' '}
            {coverage.universalFailureLabels.slice(0, 3).join('; ')}
            {coverage.universalFailureLabels.length > 3 ? `; +${coverage.universalFailureLabels.length - 3} more` : ''}.
            A host that fails any one of these cannot be fully compliant, whatever the rest of the framework shows.
          </p>
        )}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 via-white to-slate-50">
      <div className="max-w-full mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5">

        {/* Organization Header Card (Meteor Header) */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 mb-5 text-white"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
        >
          <Meteors number={25} className="!bg-white before:!from-white before:!to-transparent" />
          <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <h2 className="flex items-center text-2xl font-bold tracking-tight text-white">
                <ComplianceIcon className="w-6 h-6 mr-2" />
                {activeType === 'overview' && 'Organization Compliance Overview'}
                {activeType === 'sebi' && 'SEBI Compliance'}
                {activeType === 'irdai' && 'IRDAI Compliance'}
                {activeType === 'certin' && 'CERT-In Compliance'}
                {activeType === 'iso27001' && 'ISO 27001 Compliance'}
                {activeType === 'soc2' && 'SOC 2 Compliance'}
              </h2>
              <p className="mt-1 text-sm text-blue-100">
                {activeType === 'overview' && 'Track and manage regulatory compliance posture across your entire fleet.'}
                {activeType === 'sebi' && 'Monitor and enforce SEBI cybersecurity and cyber resilience framework.'}
                {activeType === 'irdai' && 'Ensure adherence to IRDAI information and cybersecurity guidelines.'}
                {activeType === 'certin' && 'Track compliance with CERT-In directions and cybersecurity best practices.'}
              </p>
            </div>

            <div className="flex items-center justify-between gap-4 flex-wrap">
              <div className="flex items-center gap-3 whitespace-nowrap">
                <div className="px-3 py-2 rounded-lg bg-white/10 border border-white/20 text-white text-sm font-medium">
                  Total Node:
                  <span className="font-bold text-white">{overviewData?.totalNodes ?? '-'}</span>
                </div>
                <div className="px-3 py-2 rounded-lg bg-white/10 border border-white/20 text-white text-sm font-medium">
                  Window Node:
                  <span className="font-bold text-white">{overviewData?.windowsHosts ?? '-'}</span>
                </div>
                <LiveConnectionBadge label="Live node status offline" />
              </div>

              <div className="relative inline-flex items-center gap-0.5 rounded-full border border-white/20 bg-white/10 backdrop-blur-sm p-1 overflow-x-auto scrollbar-hide max-w-full">
                <Link
                  to={(() => {
                    const base = `/compliance?type=overview`;
                    return hostIdentifierParam
                      ? `${base}&host_identifier=${encodeURIComponent(hostIdentifierParam)}`
                      : base;
                  })()}
                  state={nodeFromState ? { node: nodeFromState } : undefined}
                  className={`relative z-10 inline-flex items-center gap-1.5 rounded-lg font-semibold transition-colors duration-150 px-3 py-1.5 text-sm whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300 ${activeType === 'overview'
                    ? 'text-[rgb(4,34,119)]'
                    : 'text-blue-100 hover:text-white'
                    }`}
                  style={{ transformStyle: 'preserve-3d' }}
                >
                  {activeType === 'overview' && (
                    <motion.div
                      layoutId="complianceNavBackground"
                      transition={{ type: "spring", bounce: 0.2, duration: 0.5 }}
                      className="absolute inset-0 bg-white rounded-full shadow-sm"
                      style={{ zIndex: -1 }}
                    />
                  )}
                  <span>Overview</span>
                </Link>

                <Link
                  to={buildTypeLink('sebi')}
                  state={nodeFromState ? { node: nodeFromState } : undefined}
                  className={`relative z-10 inline-flex items-center gap-1.5 rounded-lg font-semibold transition-colors duration-150 px-3 py-1.5 text-sm whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300 ${activeType === 'sebi'
                    ? 'text-[rgb(4,34,119)]'
                    : 'text-blue-100 hover:text-white'
                    }`}
                  style={{ transformStyle: 'preserve-3d' }}
                >
                  {activeType === 'sebi' && (
                    <motion.div
                      layoutId="complianceNavBackground"
                      transition={{ type: "spring", bounce: 0.2, duration: 0.5 }}
                      className="absolute inset-0 bg-white rounded-full shadow-sm"
                      style={{ zIndex: -1 }}
                    />
                  )}
                  <span>SEBI</span>
                </Link>

                <Link
                  to={buildTypeLink('irdai')}
                  state={nodeFromState ? { node: nodeFromState } : undefined}
                  className={`relative z-10 inline-flex items-center gap-1.5 rounded-lg font-semibold transition-colors duration-150 px-3 py-1.5 text-sm whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300 ${activeType === 'irdai'
                    ? 'text-[rgb(4,34,119)]'
                    : 'text-blue-100 hover:text-white'
                    }`}
                  style={{ transformStyle: 'preserve-3d' }}
                >
                  {activeType === 'irdai' && (
                    <motion.div
                      layoutId="complianceNavBackground"
                      transition={{ type: "spring", bounce: 0.2, duration: 0.5 }}
                      className="absolute inset-0 bg-white rounded-full shadow-sm"
                      style={{ zIndex: -1 }}
                    />
                  )}
                  <span>IRDAI</span>
                </Link>

                <Link
                  to={buildTypeLink('certin')}
                  state={nodeFromState ? { node: nodeFromState } : undefined}
                  className={`relative z-10 inline-flex items-center gap-1.5 rounded-lg font-semibold transition-colors duration-150 px-3 py-1.5 text-sm whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300 ${activeType === 'certin'
                    ? 'text-[rgb(4,34,119)]'
                    : 'text-blue-100 hover:text-white'
                    }`}
                  style={{ transformStyle: 'preserve-3d' }}
                >
                  {activeType === 'certin' && (
                    <motion.div
                      layoutId="complianceNavBackground"
                      transition={{ type: "spring", bounce: 0.2, duration: 0.5 }}
                      className="absolute inset-0 bg-white rounded-full shadow-sm"
                      style={{ zIndex: -1 }}
                    />
                  )}
                  <span>CERT-In</span>
                </Link>
              </div>
            </div>
          </div>
        </motion.div>

        <div className="bg-white rounded-xl lg:rounded-2xl border border-blue-100 shadow-sm overflow-hidden">
          {nodeLoading && activeType !== 'overview' && (
            <div className="mx-4 mt-4 rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600">
              <InlineSpinner text="Loading node context..." />
            </div>
          )}

          {nodeError && (
            <div className="mx-4 mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
              {nodeError}
            </div>
          )}

          <div className="min-h-[300px] sm:min-h-[400px] bg-white">
            <Suspense
              fallback={
                <div className="p-6">
                  <InlineSpinner text="Loading compliance register…" />
                </div>
              }
            >
            {activeType === 'irdai' ? (
              <NodesViewIRDAIHotCompliance
                node={nodeToRender}
                wsConnected={wsConnected}
                wsSendMessage={wsSendMessage as (message: unknown) => Promise<unknown>}
                agentOnline={hotComplianceAgentOnline}
              />
            ) : activeType === 'sebi' ? (
              <NodesViewSebiHotCompliance
                node={nodeToRender}
                wsConnected={wsConnected}
                wsSendMessage={wsSendMessage as (message: unknown) => Promise<unknown>}
                agentOnline={hotComplianceAgentOnline}
              />
            ) : activeType === 'certin' ? (
              <NodesViewCertInCompliance
                node={nodeToRender}
                wsConnected={wsConnected}
                wsSendMessage={wsSendMessage as (message: unknown) => Promise<unknown>}
                agentOnline={hotComplianceAgentOnline}
              />) : (
              <div className="p-4 sm:p-6">
                {overviewLoading && (
                  <div className="bg-white rounded-2xl border border-slate-200 p-6">
                    <div className="flex items-center gap-3">
                      <InlineSpinner text="" size="xs" />
                      <div>
                        <h3 className="text-base sm:text-lg font-semibold text-slate-800">Building compliance overview…</h3>
                        <p className="mt-1 text-sm text-slate-600">Aggregating enrolled machines, alerting, and latest stored compliance runs.</p>
                      </div>
                    </div>
                  </div>
                )}

                {overviewError && (
                  <div className="bg-white rounded-2xl border border-red-200 p-6">
                    <div className="flex items-start gap-3">
                      <div className="inline-flex h-10 w-10 items-center justify-center rounded-lg bg-red-600 text-white shrink-0">
                        <i className="fa fa-triangle-exclamation" />
                      </div>
                      <div>
                        <h3 className="text-base sm:text-lg font-semibold text-red-800">Could not load overview</h3>
                        <p className="mt-1 text-sm text-red-700">{overviewError}</p>
                        <button
                          type="button"
                          onClick={retryOverview}
                          className="mt-3 inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-3 py-1.5 text-xs font-semibold text-red-700 transition hover:bg-red-50"
                        >
                          <i className="fa fa-rotate-right text-[10px]" aria-hidden="true" />
                          Retry
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {overviewData && !overviewLoading && !overviewError && (
                  <div className="space-y-6 mt-2">

                    {hasFailedOverviewWidgets && (
                      <div
                        className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-medium text-amber-800"
                        role="alert"
                      >
                        <i className="fa fa-triangle-exclamation text-amber-500" aria-hidden="true" />
                        <span>
                          Some figures couldn&apos;t be loaded ({failedOverviewWidgetLabels.join(', ')}) and are shown as
                          {' '}<span className="font-semibold">N/A</span> — they are not zero, they are unknown.
                        </span>
                        <button
                          type="button"
                          onClick={retryOverview}
                          className="inline-flex items-center gap-2 rounded-lg border border-amber-300 bg-white px-3 py-1 text-xs font-semibold text-amber-800 transition hover:bg-amber-100"
                        >
                          <i className="fa fa-rotate-right text-[10px]" aria-hidden="true" />
                          Retry
                        </button>
                      </div>
                    )}

                    {/* Executive metrics */}
                    <div className="bg-blue-50 rounded-xl border border-slate-200 overflow-hidden">
                      <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-slate-700 flex items-center justify-between">
                        <span className="font-semibold text-white text-base">
                          Statistics Overview
                        </span>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 p-4 gap-4">
                        <div className="rounded-2xl border border-slate-200 bg-white p-5 md:p-6">
                          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Enrolled nodes</p>
                          <p className="mt-2 text-3xl font-bold text-slate-900">{overviewData.totalNodes}</p>
                          <p className="mt-1 text-sm text-slate-600">
                            {overviewData.onlineNodes} online · {overviewData.offlineNodes} offline
                          </p>
                        </div>
                        <div className="rounded-2xl border border-slate-200 bg-white p-5 md:p-6">
                          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Windows compliance coverage</p>
                          <p className="mt-2 text-3xl font-bold text-slate-900">
                            {overviewData.windowsHosts > 0 && (activeSnapshot?.windows_with_results ?? 0) > 0
                              ? `${Math.min(100, Math.round(((activeSnapshot?.windows_with_results ?? 0) / overviewData.windowsHosts) * 100))}%`
                              : 'N/A'}
                          </p>
                          <p className="mt-1 text-sm text-slate-600">
                            {activeSnapshot?.windows_with_results ?? '—'} of {overviewData.windowsHosts} Windows nodes have results
                          </p>
                        </div>
                        <div className="rounded-2xl border border-slate-200 bg-white p-5 md:p-6">
                          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Avg control pass rate</p>
                          <p className="mt-2 text-3xl font-bold text-slate-900">
                            {(activeSnapshot?.avg_compliance_percent ?? null) == null ? '—' : `${activeSnapshot!.avg_compliance_percent}%`}
                          </p>
                          <p className="mt-1 text-sm text-slate-600">
                            Share of Vajra baseline controls passing, averaged over the {activeSnapshot?.windows_with_results ?? '—'} endpoint(s) that returned results — not a share of fully compliant endpoints
                          </p>
                        </div>
                        <div className="rounded-2xl border border-slate-200 bg-white p-5 md:p-6">
                          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Open alerts</p>
                          <p className={`mt-2 text-3xl font-bold ${overviewData.failed.alerts ? 'text-slate-400' : 'text-slate-900'}`}>
                            {overviewData.failed.alerts ? 'N/A' : overviewData.alerts.openCount}
                          </p>
                          <p className="mt-1 text-sm text-slate-600">
                            {overviewData.failed.alerts
                              ? 'Alert counts unavailable — retry to reload'
                              : `${overviewData.alerts.closeCount} closed · Total ${overviewData.alerts.openCount + overviewData.alerts.closeCount}`}
                          </p>
                        </div>
                      </div>

                      {/* Compliance summary */}
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 p-4 -mt-2">
                        <div className="rounded-2xl border border-slate-200 bg-white p-5 md:p-6 lg:col-span-1 flex flex-col">
                          <div className="flex items-center justify-between mb-2">
                            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Vajra average control pass rate</p>
                            <span className="inline-flex items-center rounded-full bg-slate-50 border border-slate-200 px-2.5 py-1 text-[11px] font-semibold text-slate-600">
                              <i className="fa fa-shield-heart text-slate-400 mr-1" />
                              {activeSnapshot?.avg_compliance_percent == null ? 'N/A' : `${Number(activeSnapshot.avg_compliance_percent).toFixed(0)}%`}
                            </span>
                          </div>
                          <p className="mb-2 text-[11px] text-slate-500">
                            Share of the 18 Windows guidelines passing, averaged across assessed endpoints — not the share of endpoints that are fully compliant.
                          </p>
                          {activeSnapshot && (
                            <div className="mb-1 flex flex-wrap items-center gap-2 text-[11px]">
                              <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-semibold ${snapshotAgeToneClasses(snapshotAgeTone(activeSnapshot.snapshot_at))}`}>
                                <i className="fa fa-clock-rotate-left text-[9px]" aria-hidden="true" />
                                {new Date(Number(activeSnapshot.snapshot_at) * 1000).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' })}
                                {fmtRelative(activeSnapshot.snapshot_at) ? ` — ${fmtRelative(activeSnapshot.snapshot_at)}` : ''}
                              </span>
                              <span className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 font-semibold text-slate-600">
                                <i className="fa fa-server text-[9px]" aria-hidden="true" />
                                Coverage {activeSnapshot.windows_with_results ?? '—'} / {activeSnapshot.windows_hosts ?? '—'} endpoints
                              </span>
                            </div>
                          )}

                          <div className="flex justify-center gap-5 mt-2">
                            <div className="flex items-center gap-2">
                              <div
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: PIE_COLORS[0] }}
                              />
                              <span className="text-sm text-slate-600">Controls passing</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <div
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: PIE_COLORS[1] }}
                              />
                              <span className="text-sm text-slate-600">Controls failing</span>
                            </div>
                          </div>

                          <div className="flex-1 flex items-center justify-center mt-2 min-h-[220px]">
                            {averageVajraNodePieData.length > 0 ? (
                              <ResponsiveContainer width="100%" height={220}>
                                <PieChart>
                                  <Pie
                                    data={averageVajraNodePieData}
                                    activeShape={renderActiveShape}
                                    onMouseEnter={(_, index) => setActiveIndex(index)}
                                    dataKey="value"
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={0}
                                    outerRadius={95}
                                    stroke="#fff"
                                    strokeWidth={2}
                                    cornerRadius={6}
                                  >
                                    {averageVajraNodePieData.map((_, idx) => (
                                      <Cell
                                        key={idx}
                                        fill={PIE_COLORS[idx % PIE_COLORS.length]}
                                      />
                                    ))}
                                  </Pie>
                                  <RTooltip content={<SimpleTooltip />} />
                                </PieChart>
                              </ResponsiveContainer>
                            ) : orgHistoryError ? (
                              <div className="flex flex-col items-center justify-center text-amber-400 gap-2">
                                <i className="fa fa-triangle-exclamation text-4xl" />
                                <span className="text-xs font-medium text-amber-600">Couldn&apos;t load snapshot history</span>
                              </div>
                            ) : (
                              <div className="flex flex-col items-center justify-center text-gray-300 gap-2">
                                <i className="fa fa-chart-pie text-5xl" />
                                <span className="text-xs font-medium text-slate-400">No data available</span>
                              </div>
                            )}
                          </div>
                        </div>
                        <div className="rounded-2xl border border-slate-200 bg-white p-5 md:p-6 lg:col-span-1">
                          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Recency</p>
                          <div className="mt-3 space-y-3">
                            <div className="flex items-start justify-between gap-3">
                              <p className="text-sm font-semibold text-slate-800">Latest snapshot</p>
                              <p className="text-sm font-mono text-slate-900">
                                {orgHistory[0]?.snapshot_at ? new Date(Number(orgHistory[0].snapshot_at) * 1000).toLocaleString() : '—'}
                                {orgHistory[0]?.snapshot_at && fmtRelative(orgHistory[0].snapshot_at) && (
                                  <span className={`ml-2 inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-semibold ${snapshotAgeToneClasses(snapshotAgeTone(orgHistory[0].snapshot_at))}`}>
                                    {fmtRelative(orgHistory[0].snapshot_at)}
                                  </span>
                                )}
                              </p>
                            </div>
                            <div className="flex items-start justify-between gap-3">
                              <p className="text-sm font-semibold text-slate-800">Snapshots saved</p>
                              <p className="text-sm font-mono text-slate-900">{orgHistory.length}</p>
                            </div>
                          </div>
                          <p className="mt-3 text-xs text-slate-500 leading-relaxed">
                            Timestamps are from the saved compliance snapshots table.
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
                      <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-slate-700 flex items-center justify-between">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <span className="font-semibold text-white text-base">Latest Organization Compliance Statistics</span>
                            <p className="mt-1 text-sm text-slate-300">
                              Statistics from the latest SEBI, IRDAI, and CERT-In compliance runs.
                            </p>
                          </div>
                        </div>
                      </div>
                      <div className="grid bg-blue-50 grid-cols-1 lg:grid-cols-3 gap-4 p-4">
                        {/* Score card */}

                        {/* Pie chart */}
                        <div className="bg-white rounded-xl border border-blue-200 p-4 min-h-[340px]">
                          <div className="flex items-center gap-2">
                            <p className="font-semibold text-slate-700 text-sm">
                              SEBI Latest Organization Compliance Distribution
                            </p>

                            <div className="group relative">
                              <i
                                className="fa fa-circle-info text-slate-400 text-xs cursor-help"
                                role="button"
                                tabIndex={0}
                                aria-label="More info"
                              />

                              <div className="absolute right-full -mr-6 top-6 z-50 hidden w-72 max-w-[calc(100vw-2rem)] rounded-lg border border-white/10 bg-gray-900 p-3 text-xs text-white shadow-2xl group-hover:block group-focus-within:block">
                                <p className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                  Share of responding hosts that passed every SEBI control they were measured on. This is a share of HOSTS, not the share of controls passing.
                                </p>

                                <p className="text-white font-semibold text-[11px] leading-snug whitespace-normal mt-2">
                                  The percentage is calculated using the formula:
                                </p>

                                <div className="bg-white/5 border border-white/10 rounded-md p-2 flex items-center justify-center gap-2 text-xs mt-2">
                                  <div className="flex flex-col items-center">
                                    <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                      Hosts fully compliant
                                    </span>

                                    <span className="w-full border-t border-white/20 my-1" />

                                    <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                      Hosts that returned results
                                    </span>
                                  </div>

                                  <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                    × 100%
                                  </span>
                                </div>

                                <p className="mt-2 text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                  The per-host denominator is the controls that host was actually measured on, which varies host by host and is smaller than the full SEBI control set — see the coverage badges under this chart. Controls no host could be measured on are excluded from both sides, never scored as failures.
                                </p>
                              </div>
                            </div>
                          </div>

                          <div className="flex justify-center gap-5 mt-4">

                            <div className="flex items-center gap-2">
                              <div
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: PIE_COLORS[0] }}
                              />
                              <span className="text-sm text-slate-600">
                                Fully compliant hosts
                              </span>
                            </div>

                            <div className="flex items-center gap-2">
                              <div
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: PIE_COLORS[1] }}
                              />
                              <span className="text-sm text-slate-600">
                                Not fully compliant hosts
                              </span>
                            </div>

                          </div>

                          {renderSnapshotMeta(sebiOrgHistory[0], 'SEBI')}

                          {sebiOrgHistory.length > 0 && !sebiOrgHistoryLoading ? (
                            <ResponsiveContainer width="100%" height={250}>
                              <PieChart>
                                <Pie
                                  data={averageSebiNodePieData}
                                  activeShape={renderActiveShape}
                                  onMouseEnter={(_, index) => setActiveIndex(index)}
                                  dataKey="value"
                                  cx="50%"
                                  cy="50%"
                                  innerRadius={0}
                                  outerRadius={105}
                                  stroke="#fff"
                                  strokeWidth={2}
                                  cornerRadius={6}
                                >
                                  {averageSebiNodePieData.map((_, idx) => (
                                    <Cell
                                      key={idx}
                                      fill={PIE_COLORS[idx % PIE_COLORS.length]}
                                    />
                                  ))}
                                </Pie>

                                <RTooltip content={<CustomTooltip />} />
                              </PieChart>
                            </ResponsiveContainer>
                          ) : sebiOrgHistoryError ? (
                            <div className="flex flex-col items-center justify-center h-[210px] text-amber-400 gap-2 px-6 text-center">
                              <i className="fa fa-triangle-exclamation text-4xl" />
                              <p className="text-sm font-medium text-amber-600">Couldn&apos;t load SEBI history</p>
                              <p className="text-xs text-gray-400 max-w-xs">
                                The latest SEBI snapshot could not be fetched. Refresh the page to try again.
                              </p>
                            </div>
                          ) : (
                            <div className="flex flex-col items-center justify-center h-[210px] text-gray-300 gap-2 px-6 text-center">
                              <i className="fa fa-chart-pie text-6xl" />
                              <button
                                disabled
                                title="No SEBI snapshot yet. SEBI compliance is assessed per node — open a node's SEBI tab to run it, then it will appear here."
                                className="px-4 py-2 rounded-lg bg-gray-300 text-gray-600 text-sm font-medium cursor-not-allowed"
                              >
                                No SEBI Snapshot Yet
                              </button>
                              <p className="text-xs text-gray-400 max-w-xs">
                                SEBI compliance runs per node — open a node&apos;s SEBI tab to assess it, then check back here.
                              </p>
                            </div>
                          )}

                        </div>
                        <div className="bg-white rounded-xl border border-blue-200 p-4 min-h-[340px]">
                          <div className="flex items-center gap-2">
                            <p className="font-semibold text-slate-700 text-sm">
                              IRDAI Latest Organization Compliance Distribution
                            </p>

                            <div className="group relative">
                              <i
                                className="fa fa-circle-info text-slate-400 text-xs cursor-help"
                                role="button"
                                tabIndex={0}
                                aria-label="More info"
                              />

                              <div className="absolute right-full -mr-6 top-6 z-50 hidden w-72 max-w-[calc(100vw-2rem)] rounded-lg border border-white/10 bg-gray-900 p-3 text-xs text-white shadow-2xl group-hover:block group-focus-within:block">
                                <p className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                  Share of responding hosts that passed every IRDAI control they were measured on. This is a share of HOSTS, not the share of controls passing.
                                </p>

                                <p className="text-white font-semibold text-[11px] leading-snug whitespace-normal mt-2">
                                  The percentage is calculated using the formula:
                                </p>

                                <div className="bg-white/5 border border-white/10 rounded-md p-2 flex items-center justify-center gap-2 text-xs mt-2">
                                  <div className="flex flex-col items-center">
                                    <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                      Hosts fully compliant
                                    </span>

                                    <span className="w-full border-t border-white/20 my-1" />

                                    <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                      Hosts that returned results
                                    </span>
                                  </div>

                                  <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                    × 100%
                                  </span>
                                </div>

                                <p className="mt-2 text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                  The per-host denominator is the controls that host was actually measured on, which varies host by host and is smaller than the full IRDAI control set — see the coverage badges under this chart. Controls no host could be measured on are excluded from both sides, never scored as failures.
                                </p>
                              </div>
                            </div>
                          </div>

                          <div className="flex justify-center gap-5 mt-4">

                            <div className="flex items-center gap-2">
                              <div
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: PIE_COLORS[0] }}
                              />
                              <span className="text-sm text-slate-600">
                                Fully compliant hosts
                              </span>
                            </div>

                            <div className="flex items-center gap-2">
                              <div
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: PIE_COLORS[1] }}
                              />
                              <span className="text-sm text-slate-600">
                                Not fully compliant hosts
                              </span>
                            </div>

                          </div>

                          {renderSnapshotMeta(irdaiOrgHistory[0], 'IRDAI')}

                          {averageIrdaiNodePieData.length > 0 && !irdaiOrgHistoryLoading ? (
                            <ResponsiveContainer width="100%" height={250}>
                              <PieChart>
                                <Pie
                                  data={averageIrdaiNodePieData}
                                  activeShape={renderActiveShape}
                                  onMouseEnter={(_, index) => setActiveIndex(index)}
                                  dataKey="value"
                                  cx="50%"
                                  cy="50%"
                                  innerRadius={0}
                                  outerRadius={105}
                                  stroke="#fff"
                                  strokeWidth={2}
                                  cornerRadius={6}
                                >
                                  {averageIrdaiNodePieData.map((_, idx) => (
                                    <Cell
                                      key={idx}
                                      fill={PIE_COLORS[idx % PIE_COLORS.length]}
                                    />
                                  ))}
                                </Pie>

                                <RTooltip content={<CustomTooltip />} />
                              </PieChart>
                            </ResponsiveContainer>
                          ) : irdaiOrgHistoryError ? (
                            <div className="flex flex-col items-center justify-center h-[210px] text-amber-400 gap-2 px-6 text-center">
                              <i className="fa fa-triangle-exclamation text-4xl" />
                              <p className="text-sm font-medium text-amber-600">Couldn&apos;t load IRDAI history</p>
                              <p className="text-xs text-gray-400 max-w-xs">
                                The latest IRDAI snapshot could not be fetched. Refresh the page to try again.
                              </p>
                            </div>
                          ) : (
                            <div className="flex flex-col items-center justify-center h-[210px] text-gray-300 gap-2 px-6 text-center">
                              <i className="fa fa-chart-pie text-6xl" />
                              <button
                                disabled
                                title="No IRDAI snapshot yet. IRDAI compliance is assessed per node — open a node's IRDAI tab to run it, then it will appear here."
                                className="px-4 py-2 rounded-lg bg-gray-300 text-gray-600 text-sm font-medium cursor-not-allowed"
                              >
                                No IRDAI Snapshot Yet
                              </button>
                              <p className="text-xs text-gray-400 max-w-xs">
                                IRDAI compliance runs per node — open a node&apos;s IRDAI tab to assess it, then check back here.
                              </p>
                            </div>
                          )}

                        </div>
                        {/* Pie chart */}
                        <div className="bg-white rounded-xl border border-blue-200 p-4 min-h-[340px]">
                          <div className="flex items-center gap-2">
                            <p className="font-semibold text-slate-700 text-sm">
                              Cert-In Latest Organization Compliance Distribution
                            </p>

                            <div className="group relative">
                              <i
                                className="fa fa-circle-info text-slate-400 text-xs cursor-help"
                                role="button"
                                tabIndex={0}
                                aria-label="More info"
                              />

                              <div className="absolute right-full -mr-6 top-6 z-50 hidden w-72 max-w-[calc(100vw-2rem)] rounded-lg border border-white/10 bg-gray-900 p-3 text-xs text-white shadow-2xl group-hover:block group-focus-within:block">
                                <p className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                  Share of responding hosts that passed every Cert-In control they were measured on. This is a share of HOSTS, not the share of controls passing.
                                </p>

                                <p className="text-white font-semibold text-[11px] leading-snug whitespace-normal mt-2">
                                  The percentage is calculated using the formula:
                                </p>

                                <div className="bg-white/5 border border-white/10 rounded-md p-2 flex items-center justify-center gap-2 text-xs mt-2">
                                  <div className="flex flex-col items-center">
                                    <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                      Hosts fully compliant
                                    </span>

                                    <span className="w-full border-t border-white/20 my-1" />

                                    <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                      Hosts that returned results
                                    </span>
                                  </div>

                                  <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                    × 100%
                                  </span>
                                </div>

                                <p className="mt-2 text-white font-semibold text-[11px] leading-snug whitespace-normal">
                                  The per-host denominator is the controls that host was actually measured on, which varies host by host and is smaller than the full Cert-In control set — see the coverage badges under this chart. Controls no host could be measured on are excluded from both sides, never scored as failures.
                                </p>
                              </div>
                            </div>
                          </div>

                          <div className="flex justify-center gap-5 mt-4">

                            <div className="flex items-center gap-2">
                              <div
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: PIE_COLORS[0] }}
                              />
                              <span className="text-sm text-slate-600">
                                Fully compliant hosts
                              </span>
                            </div>

                            <div className="flex items-center gap-2">
                              <div
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: PIE_COLORS[1] }}
                              />
                              <span className="text-sm text-slate-600">
                                Not fully compliant hosts
                              </span>
                            </div>

                          </div>

                          {renderSnapshotMeta(certinOrgHistory[0], 'CERT-IN')}

                          {averageCertinNodePieData.length && !certinOrgHistoryLoading ? (
                            <ResponsiveContainer width="100%" height={250}>
                              <PieChart>
                                <Pie
                                  data={averageCertinNodePieData}
                                  activeShape={renderActiveShape}
                                  onMouseEnter={(_, index) => setActiveIndex(index)}
                                  dataKey="value"
                                  cx="50%"
                                  cy="50%"
                                  innerRadius={0}
                                  outerRadius={105}
                                  stroke="#fff"
                                  strokeWidth={2}
                                  cornerRadius={6}
                                >
                                  {averageCertinNodePieData.map((_, idx) => (
                                    <Cell
                                      key={idx}
                                      fill={PIE_COLORS[idx % PIE_COLORS.length]}
                                    />
                                  ))}
                                </Pie>

                                <RTooltip content={<CustomTooltip />} />
                              </PieChart>
                            </ResponsiveContainer>
                          ) : certinOrgHistoryError ? (
                            <div className="flex flex-col items-center justify-center h-[210px] text-amber-400 gap-2 px-6 text-center">
                              <i className="fa fa-triangle-exclamation text-4xl" />
                              <p className="text-sm font-medium text-amber-600">Couldn&apos;t load CERT-In history</p>
                              <p className="text-xs text-gray-400 max-w-xs">
                                The latest CERT-In snapshot could not be fetched. Refresh the page to try again.
                              </p>
                            </div>
                          ) : (
                            <div className="flex flex-col items-center justify-center h-[210px] text-gray-300 gap-2 px-6 text-center">
                              <i className="fa fa-chart-pie text-6xl" />
                              <button
                                disabled
                                title="No CERT-In snapshot yet. CERT-In compliance is assessed per node — open a node's CERT-In tab to run it, then it will appear here."
                                className="px-4 py-2 rounded-lg bg-gray-300 text-gray-600 text-sm font-medium cursor-not-allowed"
                              >
                                No CERT-In Snapshot Yet
                              </button>
                              <p className="text-xs text-gray-400 max-w-xs">
                                CERT-In compliance runs per node — open a node&apos;s CERT-In tab to assess it, then check back here.
                              </p>
                            </div>
                          )}

                        </div>
                      </div>
                    </div>

                    {/* Control pass rates */}
                    <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
                      <div className="px-6 py-4 border-b border-slate-200 bg-gradient-to-br from-teal-700 to-teal-600">
                        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <h4 className="text-base font-semibold text-white">Control pass-rate for Vajra Compliance</h4>
                              {liveControlRates ? (
                                <span className="inline-flex items-center rounded-full bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700">
                                  <i className="fa fa-bolt mr-1 text-[10px]" />
                                  Live
                                  {liveNodeStats && ` · ${liveNodeStats.responded}/${liveNodeStats.queried} nodes`}
                                </span>
                              ) : (
                                <span className="inline-flex items-center rounded-full bg-slate-100 border border-slate-200 px-2.5 py-0.5 text-[11px] font-semibold text-slate-700">
                                  Historical
                                </span>
                              )}
                            </div>
                            <p className="mt-1 text-sm text-slate-200">
                              {liveControlRates
                                ? `Real-time results from ${liveNodeStats?.responded ?? 0} online Windows node${(liveNodeStats?.responded ?? 0) !== 1 ? 's' : ''}.`
                                : activeSnapshot
                                  ? 'Each row shows how many Windows nodes passed that guideline in the latest saved snapshot.'
                                  : 'No snapshot yet — click Refresh Live to run the first compliance sweep.'}
                            </p>
                            {/* A host that was queried but never answered is not
                                assessed — excluding it from the denominator is
                                correct, but the gap has to be visible or the
                                score silently covers fewer machines than it says. */}
                            {liveNodeStats && liveNodeStats.responded < liveNodeStats.queried && (
                              <div className="mt-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900" role="alert">
                                <span className="font-semibold">
                                  Coverage gap: {liveNodeStats.queried - liveNodeStats.responded} of {liveNodeStats.queried} queried node
                                  {liveNodeStats.queried !== 1 ? 's' : ''} did not answer
                                </span>
                                {' '}— they are not assessed and are excluded from every pass rate below, so this run covers{' '}
                                {liveNodeStats.responded} node{liveNodeStats.responded !== 1 ? 's' : ''}, not {liveNodeStats.queried}.
                                {liveNodeStats.nonResponding.length > 0 && (
                                  <div className="mt-1 font-mono break-all">
                                    {liveNodeStats.nonResponding.map((h) => h.hostname || h.hostId).join(', ')}
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-2 flex-wrap shrink-0">
                            <span className="inline-flex items-center rounded-full bg-slate-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
                              <i className="fa fa-list-check text-slate-400 mr-2" />
                              18 Windows guidelines
                            </span>
                            <button
                              type="button"
                              onClick={handleLiveRefresh}
                              // Greyed state must match the tooltip: with no online
                              // Windows node the sweep has nothing to query.
                              disabled={!wsConnected || liveRefreshLoading || onlineWindowsCount === 0}
                              title={
                                !wsConnected
                                  ? 'WebSocket not connected'
                                  : onlineWindowsCount === 0
                                    ? `No online Windows nodes (${windowsNodes.length} enrolled, none reachable right now)`
                                    : `Query ${onlineWindowsCount} online Windows node${onlineWindowsCount !== 1 ? 's' : ''} live`
                              }
                              className="inline-flex items-center gap-1.5 rounded-full bg-blue-300 px-3 py-1 text-xs font-semibold text-slate-800 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                            >
                              {liveRefreshLoading
                                ? <InlineSpinner text="Querying…" size="xs" />
                                : <><i className="fa fa-bolt text-[10px]" /> Refresh Live</>}
                            </button>
                            {liveRefreshLoading && (
                              <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-50 border border-amber-200 px-3 py-1 text-xs font-semibold text-amber-700">
                                <i className="fa fa-triangle-exclamation text-[10px]" />
                                Stay on this page until the sweep finishes, or it will be cut short
                              </span>
                            )}
                            {liveRefreshNotice && !liveRefreshLoading && (
                              <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-50 border border-amber-200 px-3 py-1 text-xs font-semibold text-amber-800" role="status">
                                <i className="fa fa-circle-info text-[10px]" aria-hidden="true" />
                                {liveRefreshNotice}
                              </span>
                            )}
                            {snapshotSaveError && (
                              <span className="inline-flex items-center gap-1.5 rounded-full bg-red-50 border border-red-200 px-3 py-1 text-xs font-semibold text-red-800" role="alert">
                                <i className="fa fa-triangle-exclamation text-[10px]" aria-hidden="true" />
                                {snapshotSaveError}
                              </span>
                            )}
                            {isSuperAdmin && (
                              <button
                                type="button"
                                onClick={handleDownloadVajraCompliance}
                                disabled={downloadLoading}
                                title={downloadLoading ? 'Preparing download…' : 'Download the latest Vajra compliance report'}
                                className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-700 border border-slate-200 hover:bg-slate-200 disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap transition-colors"
                              >
                                {downloadLoading ? <DuoSpinner size="xs" /> : <i className="fa fa-download text-[10px]" />}
                                {downloadLoading ? 'Downloading…' : 'Download Vajra Compliance'}
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm border-separate border-spacing-0">
                          <thead>
                            <tr>
                              <th className="py-3 px-6 text-left text-xs font-semibold uppercase tracking-wide text-slate-500 w-10 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">#</th>
                              <th className="py-3 px-2 text-left text-xs font-semibold uppercase tracking-wide text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Guideline</th>
                              <th className="py-3 px-2 text-right text-xs font-semibold uppercase tracking-wide text-slate-500 w-32 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Pass rate</th>
                              <th className="py-3 px-2 text-right text-xs font-semibold uppercase tracking-wide text-slate-500 w-40 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Hosts</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {(liveControlRates ?? activeSnapshot?.control_pass_rates ?? []).length === 0 ? (
                              <tr>
                                <td colSpan={4} className="py-10 px-6 text-center text-sm text-slate-600">
                                  No compliance snapshot yet. Click <span className="font-semibold">Refresh Live</span> to run the first sweep and save a snapshot.
                                </td>
                              </tr>
                            ) : (liveControlRates ?? activeSnapshot?.control_pass_rates ?? []).map((row) => (
                              <tr key={row.key} className="hover:bg-slate-50/70 transition-colors">
                                <td className="py-3 px-6 text-slate-500 font-semibold">{row.key}</td>
                                <td className="py-3 px-2">
                                  <div className="min-w-[18rem]">
                                    <p className="font-semibold text-slate-800 leading-tight">{row.label}</p>
                                  </div>
                                </td>
                                <td className="py-3 px-2 text-right">
                                  {row.passRatePct == null ? (
                                    <span className="text-slate-400 font-semibold">N/A</span>
                                  ) : (
                                    <span className={`inline-flex items-center justify-end gap-1.5 font-semibold ${row.passRatePct >= 90 ? 'text-emerald-700' : row.passRatePct >= 75 ? 'text-amber-700' : 'text-red-700'}`}>
                                      <i className={`fa ${row.passRatePct >= 90 ? 'fa-circle-check' : row.passRatePct >= 75 ? 'fa-triangle-exclamation' : 'fa-circle-xmark'} text-[10px]`} aria-hidden="true" />
                                      {row.passRatePct}%
                                    </span>
                                  )}
                                </td>
                                <td className="py-3 px-2 text-right text-slate-700 font-semibold">
                                  {row.eligibleHosts > 0 ? (
                                    <>
                                      <span className="text-emerald-700">{row.passHosts}</span> / <span className="text-slate-700">{row.eligibleHosts}</span> passed
                                    </>
                                  ) : (
                                    <span className="text-slate-400">No data</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <div className="px-6 py-4 border-t border-slate-200 bg-blue-50/40">
                        <p className="text-xs text-slate-600 leading-relaxed">
                          {liveControlRates
                            ? <>Live data queried directly from online agents via WebSocket. <span className="font-semibold">Default Hostname Changed</span> uses inverted pass/fail logic; <span className="font-semibold">Minimum Password Length Policy</span> passes when the configured length is greater than 0. Offline nodes are excluded.</>
                            : <>Historical data from stored compliance runs. <span className="font-semibold">Default Hostname Changed</span> uses inverted pass/fail logic (false = compliant); <span className="font-semibold">Minimum Password Length Policy</span> passes when the configured length is greater than 0. Click <span className="font-semibold">Refresh Live</span> to query online agents now.</>}
                        </p>
                      </div>
                    </div>

                    {/* Alerts + Defender */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="bg-blue-50 rounded-2xl border border-slate-200 p-6 shadow-sm">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <h4 className="text-2xl font-bold text-slate-900">Alerting Status</h4>
                            <p className="mt-1 text-sm text-slate-600">Current open vs closed alerts snapshot.</p>
                          </div>
                          <span className="inline-flex items-center rounded-full bg-slate-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
                            <i className="fa fa-bell text-slate-400 mr-2" />
                            Live graph feed
                          </span>
                        </div>
                        <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-3">
                          <div className="rounded-2xl border border-blue-300/90 bg-gradient-to-br from-white via-blue-50/40 to-blue-100/50 p-5 shadow-[0_6px_20px_-10px_rgba(37,99,235,0.45)]">
                            <p className={`text-2xl font-bold leading-none ${overviewData.failed.alerts ? 'text-slate-400' : 'text-slate-900'}`}>
                              {overviewData.failed.alerts ? 'N/A' : overviewData.alerts.openCount}
                            </p>
                            <p className="mt-2 text-xs font-semibold uppercase tracking-wide text-blue-700">Open</p>
                            <p className="mt-1 text-xs text-slate-600">{overviewData.failed.alerts ? 'Unavailable' : 'Currently reported'}</p>
                          </div>
                          <div className="rounded-2xl border border-emerald-200/90 bg-gradient-to-br from-white via-emerald-50/30 to-emerald-100/50 p-5 shadow-[0_6px_20px_-10px_rgba(16,185,129,0.35)]">
                            <p className={`text-2xl font-bold leading-none ${overviewData.failed.alerts ? 'text-slate-400' : 'text-slate-900'}`}>
                              {overviewData.failed.alerts ? 'N/A' : overviewData.alerts.closeCount}
                            </p>
                            <p className="mt-2 text-xs font-semibold uppercase tracking-wide text-emerald-700">Closed</p>
                            <p className="mt-1 text-xs text-slate-600">{overviewData.failed.alerts ? 'Unavailable' : 'Resolved/closed'}</p>
                          </div>
                        </div>
                        <div className="mt-6">
                          <h5 className="text-sm font-semibold text-slate-900">Weekly alert volume (last 7 days)</h5>
                          <div className="mt-3">
                            <div className="relative h-[250px]">
                              {!hasWeeklyAlertVolume && (
                                <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center px-6">
                                  {overviewData.failed.weeklyAlerts ? (
                                    <p className="rounded-md bg-white/80 px-3 py-1 text-center text-sm font-medium text-amber-700">
                                      <i className="fa fa-triangle-exclamation mr-2" aria-hidden="true" />
                                      Couldn&apos;t load weekly alert volume — the bars below are a placeholder, not a reading
                                    </p>
                                  ) : (
                                    <p className="rounded-md bg-white/70 px-3 py-1 text-center text-sm text-slate-500">
                                      No alerts reported in the last 7 days
                                    </p>
                                  )}
                                </div>
                              )}
                              <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={weeklyAlertChartData} margin={{ top: 14, right: 8, left: 2, bottom: 10 }}>
                                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                                  <XAxis
                                    dataKey="shortLabel"
                                    tick={{ fill: '#64748b', fontSize: 12 }}
                                    tickLine={false}
                                    axisLine={{ stroke: '#cbd5e1' }}
                                  />
                                  <YAxis
                                    domain={[0, weeklyYAxisMax]}
                                    tick={{ fill: '#64748b', fontSize: 12 }}
                                    tickLine={false}
                                    axisLine={false}
                                    allowDecimals={false}
                                    width={34}
                                  />
                                  <Tooltip
                                    cursor={{ fill: 'rgba(148, 163, 184, 0.12)' }}
                                    formatter={(value) => [
                                      Number(Array.isArray(value) ? value[0] : value) || 0,
                                      'Alerts',
                                    ]}
                                    contentStyle={{
                                      borderRadius: 10,
                                      border: '1px solid #cbd5e1',
                                      boxShadow: '0 10px 30px rgba(15, 23, 42, 0.08)',
                                    }}
                                  />
                                  <Bar dataKey="total" radius={[6, 6, 0, 0]} maxBarSize={74} minPointSize={hasWeeklyAlertVolume ? 0 : 10}>
                                    {weeklyAlertChartData.map((entry) => (
                                      <Cell
                                        key={entry.dateKey}
                                        fill={
                                          !hasWeeklyAlertVolume
                                            ? '#9dbdea'
                                            : entry.dateKey === peakWeeklyAlert.dateKey
                                              ? '#fbbf24'
                                              : '#3b82f6'
                                        }
                                      />
                                    ))}
                                  </Bar>
                                </BarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="bg-blue-50 rounded-2xl border border-slate-200 p-6">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <h4 className="text-base font-semibold text-slate-900">Node protection & evidence readiness</h4>
                            <p className="mt-1 text-sm text-slate-600">Defender coverage across your enrolled nodes.</p>
                          </div>
                          <span className="inline-flex items-center rounded-full bg-slate-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
                            <i className="fa fa-shield-halved text-slate-400 mr-2" />
                            Defender graph
                          </span>
                        </div>

                        <div className="mt-4 grid grid-cols-2 gap-3">
                          <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Defender On</p>
                            <p className={`mt-2 text-2xl font-bold ${overviewData.failed.defender ? 'text-slate-400' : 'text-emerald-700'}`}>
                              {overviewData.failed.defender ? 'N/A' : overviewData.defender.on}
                            </p>
                            <p className="mt-1 text-xs text-slate-600">{overviewData.failed.defender ? 'Coverage unknown' : 'Protected nodes'}</p>
                          </div>
                          <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Defender Off</p>
                            <p className={`mt-2 text-2xl font-bold ${overviewData.failed.defender ? 'text-slate-400' : 'text-red-700'}`}>
                              {overviewData.failed.defender ? 'N/A' : overviewData.defender.off}
                            </p>
                            <p className="mt-1 text-xs text-slate-600">{overviewData.failed.defender ? 'Coverage unknown' : 'Needs remediation'}</p>
                          </div>
                        </div>

                        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50/60 p-4">
                          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence sources in this report</p>
                          <div className="mt-2 space-y-1 text-sm text-slate-700">
                            <p><span className="font-semibold">Compliance outputs:</span> stored command results per Windows host (pass/fail derived from agent output).</p>
                            <p><span className="font-semibold">Alerting metrics:</span> alert status and weekly volumes from the analytics graph.</p>
                            <p><span className="font-semibold">Defender coverage:</span> on/off node counts from defender graph.</p>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Organisation Compliance History */}
                    <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
                      <div className="px-6 py-4 border-b border-slate-200 bg-gradient-to-br from-teal-700 to-teal-600">
                        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
                          <div>
                            <div className="flex flex-wrap items-center gap-2">
                              <h4 className="text-base font-semibold text-white">Organisation Compliance History</h4>
                              {orgHistoryLoading && (
                                <span className="inline-flex items-center rounded-full bg-slate-100 border border-slate-200 px-2.5 py-0.5 text-[11px] font-semibold text-slate-500">
                                  <InlineSpinner text="Loading…" size="xs" />
                                </span>
                              )}
                            </div>
                            <p className="mt-1 text-sm text-slate-300">
                              Saved snapshots from live compliance sweeps. Each row is created when you click <span className="font-semibold">Refresh Live</span>.
                            </p>
                          </div>
                          <span className="inline-flex items-center rounded-full bg-indigo-50 border border-indigo-200 px-3 py-1 text-xs font-semibold text-indigo-700 shrink-0">
                            <i className="fa fa-clock-rotate-left text-indigo-400 mr-2" />
                            {recentSnapshots.length} snapshot{recentSnapshots.length !== 1 ? 's' : ''}
                          </span>
                        </div>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm border-separate border-spacing-0">
                          <thead>
                            <tr>
                              <th className="py-3 px-4 text-left text-xs font-semibold uppercase tracking-wide text-slate-500 w-44 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Timestamp</th>
                              <th className="py-3 px-2 text-right text-xs font-semibold uppercase tracking-wide text-slate-500 w-32 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Score (unit per row)</th>
                              <th className="py-3 px-2 text-right text-xs font-semibold uppercase tracking-wide text-slate-500 w-28 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Windows</th>
                              <th className="py-3 px-2 text-center text-xs font-semibold uppercase tracking-wide text-slate-500 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Distribution</th>
                              <th className="py-3 px-2 text-center text-xs font-semibold uppercase tracking-wide text-slate-500 w-20 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Source</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-100">
                            {recentSnapshots.length === 0 ? (
                              <tr>
                                <td
                                  colSpan={5}
                                  className="py-10 px-6 text-center text-sm text-slate-600"
                                >
                                  No compliance snapshots found.
                                </td>
                              </tr>
                            ) : (
                              recentSnapshots.map((snap, index) => {
                                // VAJRA (org-level) snapshots don't carry a fully_compliant_nodes
                                // column — only SEBI/IRDAI/CERT-In do — so fall back to the
                                // stored avg_compliance_percent for those rows instead of always
                                // computing 0%.
                                // VAJRA rows score the average control pass rate
                                // (avg_compliance_percent, an integer column); the
                                // framework rows score the share of hosts that were
                                // fully compliant. These are different quantities —
                                // do not compute one from the other.
                                const scoreMetric: 'controls' | 'hosts' = snap.complianceType === 'VAJRA' ? 'controls' : 'hosts';
                                const complianceScore = scoreMetric === 'controls'
                                  ? (snap.avg_compliance_percent == null ? null : Number(snap.avg_compliance_percent))
                                  : snap.respondedHosts && snap.fullyCompliantCount != null
                                    ? Number(((snap.fullyCompliantCount / snap.respondedHosts) * 100).toFixed(2))
                                    : null;
                                // avg_compliance_percent is stored as an integer, so a
                                // decimal place there is a fabricated precision.
                                const scoreDigits = scoreMetric === 'controls' ? 0 : 1;
                                return (
                                  <tr
                                    key={`${snap.source}-${snap.id}-${index}`}
                                    className="hover:bg-slate-50/70 transition-colors"
                                  >
                                    {/* Timestamp */}
                                    <td className="py-3 px-4 text-slate-700 font-mono text-xs whitespace-nowrap">
                                      {new Date(
                                        snap.snapshot_at * 1000
                                      ).toLocaleString()}
                                      {fmtRelative(snap.snapshot_at) && (
                                        <span className={`ml-2 inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-semibold ${snapshotAgeToneClasses(snapshotAgeTone(snap.snapshot_at))}`}>
                                          {fmtRelative(snap.snapshot_at)}
                                        </span>
                                      )}
                                    </td>

                                    {/* Score — the unit differs by row, so it is printed
                                        with the number and the red/amber/green banding is
                                        applied only to the metric it was defined for. A
                                        share of fully compliant HOSTS and an average
                                        CONTROL pass rate are different quantities; they
                                        must not share a colour scale. */}
                                    <td className="py-3 px-2 text-right">
                                      {complianceScore === null ? (
                                        <span className="text-slate-400 font-semibold">
                                          N/A
                                        </span>
                                      ) : scoreMetric === 'hosts' ? (
                                        <span
                                          title="Share of responding hosts that passed every control they were measured on."
                                          className={`inline-flex items-center justify-end gap-1.5 font-semibold ${complianceScore >= 90
                                            ? 'text-emerald-700'
                                            : complianceScore >= 75
                                              ? 'text-amber-700'
                                              : 'text-red-700'
                                            }`}
                                        >
                                          <i
                                            className={`fa ${complianceScore >= 90
                                              ? 'fa-circle-check'
                                              : complianceScore >= 75
                                                ? 'fa-triangle-exclamation'
                                                : 'fa-circle-xmark'
                                              } text-[10px]`}
                                            aria-hidden="true"
                                          />
                                          {complianceScore.toFixed(scoreDigits)}% hosts
                                        </span>
                                      ) : (
                                        <span
                                          title="Average share of the baseline controls passing, over the hosts that returned results. Not a share of hosts, and deliberately uncoloured — there is no agreed pass/fail banding for this metric."
                                          className="inline-flex items-center justify-end gap-1.5 font-semibold text-slate-700"
                                        >
                                          <i className="fa fa-chart-simple text-[10px]" aria-hidden="true" />
                                          {complianceScore.toFixed(scoreDigits)}% controls
                                        </span>
                                      )}
                                    </td>

                                    {/* Windows: responded / swept (CERT-In columns un-transposed above) */}
                                    <td className="py-3 px-2 text-right text-slate-700 font-semibold">
                                      <span title={`${snap.respondedHosts ?? '—'} of ${snap.sweptWindowsHosts ?? '—'} swept endpoints returned results · ${snap.fleetWindowsHosts ?? '—'} Windows endpoints in the fleet`}>
                                        {snap.respondedHosts ?? '—'} /{' '}
                                        {snap.sweptWindowsHosts ?? '—'}
                                      </span>
                                    </td>

                                    {/* Distribution */}
                                    <td className="py-3 px-2">
                                      <div className="flex items-center justify-center gap-2 flex-wrap">
                                        {/* An absent count is unknown, not a measured zero — render an em dash. */}
                                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 border border-emerald-100 px-2 py-0.5 text-[11px] font-semibold text-emerald-700">
                                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                                          {snap.fullyCompliantCount ?? '—'}
                                        </span>

                                        <span className="inline-flex items-center gap-1 rounded-full bg-red-50 border border-red-100 px-2 py-0.5 text-[11px] font-semibold text-red-700">
                                          <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                                          {snap.notFullyCompliantCount ?? '—'}
                                        </span>
                                      </div>
                                    </td>

                                    {/* Source */}
                                    <td className="py-3 px-2 text-center">
                                      <span
                                        className={`inline-flex items-center whitespace-nowrap rounded-full px-2.5 py-0.5 text-[11px] font-semibold ${snap.complianceType === 'SEBI'
                                          ? 'bg-pink-50 text-pink-700 border border-pink-200'
                                          : snap.complianceType === 'IRDAI'
                                            ? 'bg-blue-50 text-blue-700 border border-blue-200'
                                            : snap.complianceType === 'CERT-IN'
                                              ? 'bg-purple-50 text-purple-700 border border-purple-200'
                                              : 'bg-slate-50 text-slate-700 border border-slate-200'
                                          }`}
                                      >
                                        {snap.complianceType ?? 'Unknown'}
                                      </span>
                                    </td>
                                  </tr>
                                );
                              })
                            )}
                          </tbody>
                        </table>
                      </div>
                      {orgHistory.length > 0 && (
                        <div className="px-6 py-3 border-t border-slate-200 bg-slate-50/40">
                          <p className="text-xs text-slate-500">
                            Distribution legend: <span className="text-emerald-700 font-semibold">green</span> = fully compliant nodes, <span className="text-red-700 font-semibold">red</span> = not fully compliant nodes; an em dash means the snapshot does not record that count (unknown, not zero).
                            {' '}The score column carries two different measurements and prints its unit on every row: <span className="font-semibold">% hosts</span> (SEBI / IRDAI / CERT-In — share of responding endpoints that passed every control they were measured on) and <span className="font-semibold">% controls</span> (VAJRA — average share of baseline controls passing). Only the <span className="font-semibold">% hosts</span> rows are colour-banded; the control pass rate has no agreed banding, so it is left uncoloured rather than judged on a scale built for the other metric.
                            {' '}The Windows column is <span className="font-semibold">responded / swept</span>.
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
            </Suspense>
          </div>
        </div>
      </div>
    </div>
  );
}
