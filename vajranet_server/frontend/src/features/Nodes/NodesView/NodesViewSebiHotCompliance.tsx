/**
 * NodesViewSebiHotCompliance
 *
 * SEBI Hot compliance checklist for a single node.
 * Layout mirrors Vajra Compliance: numbered guidelines table (left) + score card
 * + donut pie (right) + compliance history trend chart (bottom).
 *
 * SEBI_HOT_GUIDELINES holds the 41 SEBI CSCRF guideline points. Each entry:
 *   '<key>': { label: 'Human-readable name', tooltip: 'What is checked / why it matters' }
 *
 * Pass/Fail evaluation mirrors the Vajra compliance logic.
 * INVERTED_KEYS holds keys where a raw "false" output means PASS (inverted logic).
 * Add key '18'-style numeric keys to NUMERIC_KEYS if any point returns a number.
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { debugLog } from '@/lib/debugLog';
import {
  PieChart, Pie, Cell, Tooltip as RTooltip, Legend,
  LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer,
} from 'recharts';
import type { NodeData } from './types';
import { PIE_COLORS, renderActiveShape, CustomTooltipWithHosts as CustomTooltip } from '../../Compliance/shared/ComplianceChart';
import { fmtDate, fmtDateTime, fmtTime } from '../../Compliance/shared/complianceDateUtils';
import { API_BASE_URL, NODES_URLS } from '../../../api/urls';
import api from '../../../api/axiosInstance';
import { csrfHeadersJson, fetchWithCsrf } from '../../../api/csrfClient';

import { LoadingScreen, DuoSpinner } from '@/components/ui/loading';
import {
  SEBI_HOT_GUIDELINES,
  SEBI_HOT_REASON_DETAIL,
  HIDDEN_GUIDELINES,
  SEBI_HOT_COMMAND_KEYS,
  STRUCTURALLY_UNMEASURABLE_SEBI_KEYS,
} from './constants/sebiHotGuidelines';
import type { StaticCheckResult, GuidelineResult } from './utils/sebiComplianceChecks';
import { buildRows, calcPassPercent, staticComplianceChecks, SEBI_VISIBLE_COMMAND_KEYS } from './utils/sebiComplianceChecks';
import { InfoTooltip } from './components/InfoTooltip';
import { mapWithConcurrency } from '../../Compliance/utils/complianceHelpers';
// Types





type ControlPassRate = {
  key: string;
  label: string;
  passRatePct: number | null;
  passHosts: number;
  failHosts: number;
  eligibleHosts: number;
  /**
   * Hosts the sweep could not assess this control on. Written from this run's
   * own count rather than derived on restore: deriving it from
   * windows_with_results erases every host whose sweep failed or produced
   * nothing at all, because those hosts are excluded from that total. Absent on
   * rows written before this field existed, hence optional.
   */
  notAssessedHosts?: number | null;
};

type OrgSnapshot = {
  id: number;
  snapshot_at: number;
  total_nodes: number | null;
  windows_hosts: number | null;
  windows_with_results: number | null;
  fully_compliant_nodes: number | null;
  avg_compliance_percent: number | null;
  strong_count: number | null;
  moderate_count: number | null;
  needs_attention_count: number | null;
  control_pass_rates: ControlPassRate[];
  source: string;
  fully_compliant_nodes_list?: string[] | null;
  // Newer snapshots store objects ({ host_identifier, failed_checks }); older
  // rows stored bare host identifier strings. Both must keep rendering.
  non_compliant_nodes_list?: Array<string | { host_identifier?: string; failed_checks?: string[] }> | null;
};

/** Accepts both the object and the legacy string form of a non-compliant node entry. */
function toHostIdentifier(entry: string | { host_identifier?: string; failed_checks?: string[] }): string {
  return typeof entry === 'string' ? entry : (entry?.host_identifier ?? '');
}

interface NodesViewSebiHotComplianceProps {
  node: NodeData;
  wsConnected?: boolean;
  /**
   * The real signature of useNodeWebSocket's sendMessage: the second argument
   * overrides the 15 s default per-request timeout. It used to be dropped from
   * this prop type, so this register could never hand the agent channel a budget.
   */
  wsSendMessage?: (message: unknown, options?: { timeoutMs?: number }) => Promise<unknown>;
  agentOnline?: boolean;
}


interface ComplianceRecord {
  id: number;
  host_identifier: string;
  unixtime: number;
  compliance_data: Array<{ command_key: string; output: string }>;
}

interface FleetPointStat {
  /** Hosts that were assessed for this control AND passed it. */
  passed: number;
  /** Hosts that were actually assessed for this control (the denominator). */
  total: number;
  /** Hosts the control could not be assessed on — excluded from passed/total. */
  notAssessed?: number;
}

/**
 * Persisted verdict for a single control. 'not_assessed' means the control was
 * not measured on the endpoint: it is neither a pass nor a fail and is excluded
 * from both numerator and denominator. Legacy rows only ever hold 'true'/'false'.
 */
const NOT_ASSESSED = 'not_assessed';

/**
 * Fleet-level verdict for one control, derived from the assessed hosts only.
 * 'satisfied_partial_coverage' is a pass on every host the control could be
 * measured on while at least one swept host was left unmeasured — it is never
 * rendered as a fleet-wide green tick, because the hosts nothing was read from
 * are not evidence of compliance.
 */
type ControlVerdict = 'satisfied' | 'satisfied_partial_coverage' | 'partial' | 'non_compliant' | 'not_assessed';

const VERDICT_BADGE_CLASS: Record<ControlVerdict, string> = {
  satisfied: 'bg-green-100 text-green-700',
  satisfied_partial_coverage: 'bg-sky-100 text-sky-700',
  partial: 'bg-amber-100 text-amber-700',
  non_compliant: 'bg-red-100 text-red-700',
  not_assessed: 'bg-slate-100 text-slate-600',
};

const VERDICT_ICON_CLASS: Record<ControlVerdict, string> = {
  satisfied: 'fa-check',
  satisfied_partial_coverage: 'fa-circle-check',
  partial: 'fa-circle-half-stroke',
  non_compliant: 'fa-xmark',
  not_assessed: 'fa-circle-minus',
};

const VERDICT_ROW_HOVER_CLASS: Record<ControlVerdict, string> = {
  satisfied: 'hover:bg-green-50',
  satisfied_partial_coverage: 'hover:bg-sky-50',
  partial: 'hover:bg-amber-50',
  non_compliant: 'hover:bg-red-50',
  not_assessed: 'hover:bg-slate-50',
};

const VERDICT_LABEL: Record<ControlVerdict, string> = {
  satisfied: 'Compliant',
  satisfied_partial_coverage: 'Compliant on assessed hosts',
  partial: 'Partially Compliant',
  non_compliant: 'Non-Compliant',
  not_assessed: 'Not Assessed',
};

/**
 * Fleet verdict for one control, derived from the ASSESSED hosts only:
 * satisfied when every assessed host passed, partial when only some did,
 * non-compliant when none did, and not-assessed when no host could be assessed.
 * Hosts that were not assessed are already excluded from both sides of the
 * passed/total fraction, so they never tip the verdict either way.
 */
function deriveControlVerdict(check: StaticCheckResult, fleetStat?: FleetPointStat): ControlVerdict {
  if (check.assessed === false) return 'not_assessed';
  if (fleetStat) {
    if (fleetStat.total === 0) return 'not_assessed';
    if (fleetStat.passed >= fleetStat.total) {
      // An all-pass over an incomplete population is not a fleet pass. While any
      // swept host was left unmeasured the verdict keeps its own badge, so the
      // control is never promoted to a green tick on the strength of the hosts
      // that answered alone.
      return (fleetStat.notAssessed ?? 0) > 0 ? 'satisfied_partial_coverage' : 'satisfied';
    }
    return fleetStat.passed === 0 ? 'non_compliant' : 'partial';
  }
  return check.compliant ? 'satisfied' : 'non_compliant';
}

/** Colour for the per-node donut: pass, fail, then the neutral not-assessed slice. */
const NODE_PIE_COLORS = [PIE_COLORS[0], PIE_COLORS[1], '#94a3b8'];

/**
 * The controls the current SEBI evaluator can actually MEASURE on an endpoint.
 * Source of truth: utils/sebiComplianceChecks.ts — every other key it returns is
 * a capability statement, i.e. explicitly not-assessed.
 *
 * Snapshots written before the three-value contract existed hold a bare
 * 'true'/'false' for every control, including the ones nothing measures, so
 * replaying a stored row verbatim resurrects a measured pass for a control that
 * was never measured. Restoring is therefore intersected with this set and
 * everything outside it comes back as not-assessed. Telling a legacy row apart
 * from a current one would need a snapshot-version column (a schema change, out
 * of scope here), so the conservative intersection is applied to every row: a
 * current snapshot already stores 'not_assessed' for those controls, so nothing
 * measured is lost.
 */
const MEASURABLE_SEBI_KEYS: ReadonlySet<string> = new Set([
  '1', '2', '3', '6', '11', '12', '15', '22', '23',
  '25', '26', '33', '34', '36', '38', '39',
]);

/**
 * The measurable set for one stored snapshot.
 *
 * Legacy (pre-three-value-contract) snapshots hold a bare 'true'/'false' for
 * every control, including the ones nothing measures at the time they were
 * written, so replaying one verbatim would resurrect a measured pass for a
 * control that was never measured. Telling a legacy row apart from a current
 * one would need a snapshot-version column (a schema change, out of scope
 * here), so a legacy row is restricted to MEASURABLE_SEBI_KEYS — the set of
 * controls that already had a real evaluator before the contract landed.
 *
 * A snapshot written under the three-value contract is different: it already
 * carries an explicit 'not_assessed' marker (or a non-zero notAssessedHosts
 * count on the fleet path) for every control that was not measured, so THAT
 * marker — not a static allow-list — is authoritative for what to restore.
 * Clamping a contract-era row to MEASURABLE_SEBI_KEYS as well would silently
 * discard real, already-computed measurements for any control whose evaluator
 * was added or extended after this list was last updated — which is exactly
 * what happened to controls 4, 5, 7, 8, 10, 16 and 17: each now has a working
 * evaluator and real stored fleet results, but was excluded here from an
 * earlier round when it had none. So for a contract-era snapshot, restore
 * every key the register defines and let each entry's own not-assessed marker
 * decide, rather than intersecting with this list.
 */
function measurableSebiKeys(isContractEra: boolean): ReadonlySet<string> {
  if (!isContractEra) return MEASURABLE_SEBI_KEYS;
  return new Set(SEBI_HOT_COMMAND_KEYS);
}

/**
 * Reason shown for a control the organisation snapshot recorded a verdict for
 * that the current evaluator cannot measure on an endpoint. The stored figure is
 * not replayed as a fleet pass: it predates the not-assessed contract.
 */
const ORG_UNMEASURABLE_REASON =
  'Not assessed — this control has no endpoint evaluator, so the fleet figure stored for it came from a snapshot predating the not-assessed contract and is not a measured result.';

const RESTORED_LEGACY_REASON =
  'Not assessed — this control has no evaluator on the endpoint, so the stored verdict was restored from a snapshot predating the not-assessed contract and cannot be reported as a measured result.';

const RESTORED_NOT_ASSESSED_REASON =
  'Not assessed — this control was not measured on this endpoint during the compliance run that produced the stored snapshot.';

/**
 * Hosts swept in parallel.
 *
 * 2026-09-07: lowered from 4 to 2, and paired with the admission pacer below.
 * WHY: organisation snapshot sebi_historical_compliance id=57 (13 Windows
 * hosts, all 13 answering) reported 13/13 eligible hosts on every control fed
 * by a WebSocket probe (keys 10, 12, 23, 38) or by the once-per-sweep fleet
 * node list (keys 1, 6, 11, 33), and only 9/13 on EVERY control fed by a
 * per-host REST read (keys 2, 3, 7, 8, 15, 16, 22, 25, 26, 30, 32, 34, 36, 39)
 * — 8/13 on the three that also need the baseline probe row (4, 5, 24, where
 * one further host simply has no fresh row). The irdai_historical_compliance
 * sweep 216 seconds later read the identical evidence for the identical 13
 * hosts through a sequential loop and lost nobody: its ported twins of SEBI
 * 2/3/7/8 all report 13/13, and its key 3 — whose key set is documented
 * in-code as "deliberately the same as REQUIRED_AUDIT_KEYS in
 * utils/sebiComplianceChecks.ts" — reaches 12/13.
 *
 * A whole-host deadline trip cannot produce that split: it nulls the host's
 * entire result set and would have cost keys 10/12/23/38 the same four hosts.
 * The transport is what differs, and the arithmetic matches the server's own
 * budget: staticComplianceChecks issues ~10 apiDataLimiter-guarded reads per
 * host (programs, profile_info, storage, firewall rules, update history,
 * listening ports, uptime, compliance/latest, device alerts, node details)
 * against RATE_LIMIT_MAX_API_DATA = 200 requests per 60 s per user
 * (backend/src/consts/rateLimit.ts, middleware/rateLimiters.ts apiDataLimiter),
 * shared with this page's own polling. Thirteen hosts is ~130 reads, and at
 * concurrency 4 the whole fan-out lands inside one 60 s window; once the
 * budget is spent the remaining wave gets 429s, settle() carries them as
 * values and the evaluators — correctly — record not-assessed. The 4-host loss
 * is exactly one wave. IRDAI's sequential loop spreads the same ~130 reads
 * over minutes and never approaches the limit.
 *
 * Two registers reading the same evidence about the same fleet must not
 * disagree on how many hosts they could measure, so the SEBI sweep is now
 * paced to stay inside the server's budget rather than racing it.
 */
const SWEEP_CONCURRENCY = 2;

/** Per-WebSocket-request budget handed to the evidence collectors. */
const WS_REQUEST_TIMEOUT_MS = 20_000;

/**
 * Worst-case WebSocket time one host can consume.
 *
 * staticComplianceChecks chains the three agent commands serially — usb, then
 * wifi, then bluetooth (utils/sebiComplianceChecks.ts) — because they share one
 * socket and one agent. The usb leg itself makes up to two attempts with a
 * 2.5 s backoff between them (fetchUsbStatusForCompliance), so the chain is
 * four WebSocket waits plus one backoff: 4 x 20 s + 2.5 s = 82.5 s. Derived
 * rather than hard-coded so it tracks WS_REQUEST_TIMEOUT_MS.
 */
const WS_CHAIN_WORST_CASE_MS = WS_REQUEST_TIMEOUT_MS * 4 + 2_500;

/**
 * Whole-host budget for one sweep iteration. A wedged agent used to cost one
 * WebSocket timeout per unanswered call, serialised behind every other host;
 * the deadline caps a bad host at one timeout for the host.
 *
 * 2026-09-07: raised from a flat 60 s to the worst-case WebSocket chain plus
 * headroom. WHY: at 60 s the deadline was arithmetically shorter than the
 * evidence collection it was bounding — the WebSocket chain alone can reach
 * 82.5 s (see WS_CHAIN_WORST_CASE_MS) — so a merely slow agent, not a wedged
 * one, could trip it. A trip is all-or-nothing: the driver below sets
 * checks = null and marks EVERY SEBI control not-assessed for that host,
 * discarding REST evidence that had already resolved. IRDAI imposes no
 * per-host deadline at all, which is one reason its coverage is unaffected.
 * This did not fire in snapshot id=57 (the WebSocket-sourced controls all
 * reached 13/13), but the budget was reachable and the blast radius is a whole
 * host, so the deadline now bounds a genuinely stuck host rather than a slow
 * one. The better shape — a deadline per evidence source, keeping whatever
 * partial evidence resolved before it — needs staticComplianceChecks to return
 * partials and is left for that change.
 */
const PER_HOST_SWEEP_TIMEOUT_MS = WS_CHAIN_WORST_CASE_MS + 30_000;

/**
 * Client-side mirror of the server's data-read budget, used to pace the sweep.
 *
 * These deliberately duplicate RATE_LIMIT_MAX_API_DATA and
 * RATE_LIMIT_WINDOW_MS_1MIN (backend/src/consts/rateLimit.ts): the frontend
 * cannot import backend constants, so they are named here so the next reader
 * knows exactly which server figure they are shadowing. If the server budget
 * changes, this pacing has to be revisited — being wrong here costs coverage,
 * not correctness, because a throttled read is still recorded as not-assessed
 * and never as a failure.
 */
const API_DATA_BUDGET_PER_WINDOW = 200;
const API_DATA_WINDOW_MS = 60_000;

/**
 * Reads staticComplianceChecks issues per host that the apiDataLimiter counts:
 * programs, security profile, storage, firewall rules, update history,
 * listening ports, network uptime, compliance/latest, device alerts, and (only
 * on hosts whose fleet row carries no hardware_* fields) node details. Counted
 * at the maximum, and rounded up, because under-counting is what spends the
 * budget. The fleet node list is excluded: it is fetched once per sweep and
 * served from the shared cache for every later host.
 */
const REST_READS_PER_HOST = 11;

/**
 * Requests per window left unspent for everything else the page does while a
 * sweep runs — node-list polling, alert counts, the history refresh at the end
 * of the run, and whatever another open tab is doing under the same user id.
 * The limiter is keyed per user, not per page, so the sweep cannot assume it
 * owns the whole budget.
 */
const SWEEP_BUDGET_RESERVE = 80;

/** Hosts the sweep may START within any API_DATA_WINDOW_MS. */
const SWEEP_HOSTS_PER_WINDOW = Math.max(
  1,
  Math.floor((API_DATA_BUDGET_PER_WINDOW - SWEEP_BUDGET_RESERVE) / REST_READS_PER_HOST),
);

/**
 * Admission gate for the per-host REST fan-out.
 *
 * Holds the timestamp of every host this sweep has admitted and refuses to let
 * a new one start until fewer than SWEEP_HOSTS_PER_WINDOW of them fall inside
 * the trailing API_DATA_WINDOW_MS. The server's limiter uses a FIXED window, so
 * a trailing-window gate on the client is strictly the more conservative of the
 * two: N admissions in any 60 s span implies at most N in any fixed 60 s
 * window, whatever the phase offset between client and server.
 *
 * This paces host STARTS rather than individual requests, which is coarse but
 * sufficient — the fan-out per host is a known, fixed set — and it keeps the
 * gate in the sweep driver instead of threading a token bucket through the
 * shared evidence module that the report and the single-host run also call.
 * A sweep of a large fleet therefore takes longer than it used to; that is the
 * point. Coverage that is comparable with the IRDAI register over the same
 * fleet is worth more than a fast run whose denominators are wrong.
 */
function createHostAdmissionPacer(
  hostsPerWindow: number,
  windowMs: number,
): () => Promise<void> {
  const admittedAt: number[] = [];
  return async function admitHost(): Promise<void> {
    for (;;) {
      const now = Date.now();
      while (admittedAt.length > 0 && now - admittedAt[0] >= windowMs) admittedAt.shift();
      if (admittedAt.length < hostsPerWindow) {
        admittedAt.push(now);
        return;
      }
      // Wait out the oldest admission, plus a small margin so the shift above
      // is guaranteed to drop it on the next pass and this cannot spin.
      const waitMs = Math.max(50, windowMs - (now - admittedAt[0]) + 50);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
  };
}

class HostSweepTimeoutError extends Error {
  constructor(hostIdentifier: string, ms: number) {
    super(`Host ${hostIdentifier} did not finish its compliance checks within ${ms}ms`);
    this.name = 'HostSweepTimeoutError';
  }
}

/** Rejects once the deadline passes; the timer is always cleared. */
function withDeadline<T>(promise: Promise<T>, ms: number, hostIdentifier: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new HostSweepTimeoutError(hostIdentifier, ms)), ms);
  });
  return Promise.race([promise, deadline]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  }) as Promise<T>;
}

// Stable identities for the recharts config objects. Rebuilding these literals on
// every render hands recharts "new" props and re-triggers its animations.
const TREND_CHART_MARGIN = { top: 8, right: 20, bottom: 4, left: 0 };
const TREND_LINE_DOT = { r: 3, fill: '#e11d48' };
const TREND_LINE_ACTIVE_DOT = { r: 5 };
const TREND_AXIS_TICK = { fontSize: 11 };
const TREND_LEGEND_WRAPPER = { fontSize: 12 };








// Component

export default function NodesViewSebiHotCompliance({
  node,
  wsConnected = false,
  wsSendMessage,
  agentOnline = true,
}: NodesViewSebiHotComplianceProps) {
  const hostId = node.host_identifier || String(node.id);

  const [guidelines, setGuidelines] = useState<GuidelineResult[]>([]);
  const [runLoading, setRunLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [bulkRunSummary, setBulkRunSummary] = useState<{ headline: string; lines: string[]; failed: boolean } | null>(null);
  /** Non-null only while a fleet sweep is in flight. Drives the progress counter. */
  const [sweepProgress, setSweepProgress] = useState<{ done: number; total: number } | null>(null);
  const [fleetPointStats, setFleetPointStats] = useState<Record<string, FleetPointStat>>({});

  const [history, setHistory] = useState<ComplianceRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState(false);
  const [sortBy, setSortBy] = useState<'default' | '100_compliant' | 'not_100_compliant'>('default');

  const [pointsLoading, setPointsLoading] = useState(false);

  // Static evaluations for Point 1 (Critical Node Marking) and Point 2 (Software Inventory)
  // These are determined from platform API data, not from the agent command sweep.
  const [staticChecks, setStaticChecks] = useState<Record<string, StaticCheckResult>>({});

  const [downloadLoading, setDownloadLoading] = useState(false);

  // Org compliance history (from historical_compliance table)
  const [orgHistory, setOrgHistory] = useState<OrgSnapshot[]>([]);
  const [orgHistoryLoading, setOrgHistoryLoading] = useState(false);
  const [orgHistoryError, setOrgHistoryError] = useState(false);

  const [oneDeviceCompliance, setOneDeviceCompliance] = useState(false);

  const [onlineNodes, setOnlineNodes] = useState(0);
  const [totalWindowsNodes, setTotalWindowsNodes] = useState(0);

  const [passCount, setPassCount] = useState(0);
  const [failCount, setFailCount] = useState(0);
  const [notAssessedCount, setNotAssessedCount] = useState(0);
  const [totalNodes, setTotalNodes] = useState(0);
  /**
   * Windows hosts the latest sweep set out to cover. Distinct from totalNodes,
   * which counts only the hosts that produced a result, and from
   * totalWindowsNodes, which counts the whole Windows estate. All three are
   * needed to say honestly what population a fleet pass fraction came from.
   */
  const [sweptWindowsHosts, setSweptWindowsHosts] = useState(0);
  const [fullyCompliantNodes, setFullyCompliantNodes] = useState(0);
  const [fullyCompliantNodesList, setFullyCompliantNodesList] = useState<string[]>([]);
  const [nonCompliantNodesList, setNonCompliantNodesList] = useState<string[]>([]);

  // Sequence numbers + abort controllers: a slow response for a host the user has
  // already navigated away from must never land on the host now on screen. Every
  // call supersedes (and aborts) the one before it; a stale response is discarded.
  const historySeqRef = useRef(0);
  const historyAbortRef = useRef<AbortController | null>(null);
  const orgHistorySeqRef = useRef(0);
  const orgHistoryAbortRef = useRef<AbortController | null>(null);
  const onlineNodesSeqRef = useRef(0);
  const onlineNodesAbortRef = useRef<AbortController | null>(null);

  // Fetch this node's stored compliance history. history[0] IS the node's latest
  // record, so the separate /latest call this component used to make — the same
  // row of the same table, one projection apart — was removed: the guidelines
  // table, the score and the trend now all come from a single read.
  const fetchHistory = useCallback(async () => {
    historyAbortRef.current?.abort();
    const controller = new AbortController();
    historyAbortRef.current = controller;
    const seq = ++historySeqRef.current;

    setHistoryLoading(true);
    setHistoryError(false);
    try {
      const res = await api.get(
        `${NODES_URLS.SEBI_NODE_COMPLIANCE_HISTORY}${encodeURIComponent(hostId)}`,
        { signal: controller.signal },
      );
      if (seq !== historySeqRef.current) return;
      const json = res.data;
      if (json.success) {
        setHistory(json.data ?? []);
        setHistoryError(false);
      } else {
        setHistoryError(true);
      }
    } catch (err: unknown) {
      if (seq !== historySeqRef.current) return;
      if (import.meta.env.DEV) console.warn('SEBI Hot history fetch:', err);
      setHistoryError(true);
    } finally {
      if (seq === historySeqRef.current) setHistoryLoading(false);
    }
  }, [hostId]);

  const fetchOrgHistory = useCallback(async () => {
    orgHistoryAbortRef.current?.abort();
    const controller = new AbortController();
    orgHistoryAbortRef.current = controller;
    const seq = ++orgHistorySeqRef.current;

    setOrgHistoryLoading(true);
    setOrgHistoryError(false);
    try {
      const res = await api.get(NODES_URLS.SEBI_COMPLIANCE_HISTORY, { signal: controller.signal });
      if (seq !== orgHistorySeqRef.current) return;
      const json = res.data;
      if (json?.success && Array.isArray(json.data)) {
        setOrgHistory(json.data as OrgSnapshot[]);
        setOrgHistoryError(false);
      } else {
        setOrgHistoryError(true);
      }
    } catch {
      if (seq !== orgHistorySeqRef.current) return;
      setOrgHistoryError(true);
    } finally {
      if (seq === orgHistorySeqRef.current) setOrgHistoryLoading(false);
    }
  }, []);

  const fetchOnlineNodes = useCallback(async () => {
    onlineNodesAbortRef.current?.abort();
    const controller = new AbortController();
    onlineNodesAbortRef.current = controller;
    const seq = ++onlineNodesSeqRef.current;

    try {
      const res = await api.get(NODES_URLS.NODES_IDENTIFIERS, { signal: controller.signal });
      if (seq !== onlineNodesSeqRef.current) return;
      const json = res.data;
      const nodesArray: Array<Record<string, unknown>> = Array.isArray(json?.data)
        ? json.data
        : Array.isArray(json?.nodes)
          ? json.nodes
          : Array.isArray(json)
            ? json
            : [];

      const isWindowsNode = (n: Record<string, unknown>) => {
        const osName = String(n?.os_name ?? '').toLowerCase();
        const osPlatform = String(n?.os_platform ?? '').toLowerCase();
        return osName.includes('windows') || osPlatform.includes('windows');
      };

      const isOnlineNode = (n: Record<string, unknown>) => {
        const status = String(n?.status ?? n?.displayStatus ?? '').toLowerCase();
        return n?.agent_online === true || status === 'online';
      };

      const windowsCandidates = nodesArray.filter(isWindowsNode);
      const windowsOnline = windowsCandidates.filter(isOnlineNode);
      setOnlineNodes(windowsOnline.length);
      setTotalWindowsNodes(windowsCandidates.length);
    } catch (err: unknown) {
      // A superseded (aborted) call is not a failure; anything else only affects
      // the "Nodes Online" pill, so it must not blank the rest of the view.
      if (seq !== onlineNodesSeqRef.current) return;
      if (import.meta.env.DEV) console.warn('SEBI Hot online-node fetch:', err);
    }
  }, []);

  useEffect(() => {
    if (hostId === '0') {
      setGuidelines([]);
      fetchOrgHistory();
      fetchOnlineNodes();
      setOneDeviceCompliance(false);
    }
    else {
      setGuidelines([]);
      setStaticChecks({});
      setPassCount(0);
      setFailCount(0);
      setNotAssessedCount(0);
      fetchHistory();
      setOneDeviceCompliance(true);
    }
  }, [fetchHistory, fetchOnlineNodes, fetchOrgHistory, hostId]);

  useEffect(() => {
    setPointsLoading(true);
    if (hostId !== '0') {
      setPointsLoading(false);
      return;
    }
  
    const latest = orgHistory?.[0];

    if (!latest) {
      setPointsLoading(false);
      return;
    }

    const nextStats: Record<string, FleetPointStat> = {};
    const nextChecks: Record<string, StaticCheckResult> = {};

    // The organisation restore used to replay control_pass_rates verbatim, so a
    // control the per-node tab renders as not-assessed came back here as a fleet
    // pass from the very same snapshot. Both paths now intersect with the same
    // measurable set.
    const isContractEra = latest.control_pass_rates.some(
      (control) => (control.eligibleHosts ?? 0) === 0 || control.notAssessedHosts != null
    );
    const restorableKeys = measurableSebiKeys(isContractEra);

    // Hosts the sweep set out to cover. windows_with_results excludes every host
    // whose sweep failed or assessed nothing, so deriving the per-control
    // not-assessed count from it erased exactly those hosts; windows_hosts is the
    // population the sweep actually addressed.
    const sweptHosts = latest.windows_hosts ?? latest.windows_with_results ?? 0;

    latest.control_pass_rates.forEach((control) => {
      // Dropped from this register's table entirely — a stored row for one of
      // these (including rows saved before this exclusion existed) must not
      // populate the fleet stats/checks state a restored snapshot renders from.
      if (STRUCTURALLY_UNMEASURABLE_SEBI_KEYS.has(String(control.key))) return;
      const isRestorable = restorableKeys.has(String(control.key));
      const passHosts = isRestorable ? (control.passHosts ?? 0) : 0;
      const eligibleHosts = isRestorable ? (control.eligibleHosts ?? 0) : 0;

      nextStats[control.key] = {
        passed: passHosts,
        total: eligibleHosts,
        // Hosts the control was not assessed on. Taken from the count this run
        // recorded where the snapshot carries one, and otherwise derived against
        // the swept-host population rather than against the hosts that returned
        // results. They sit outside passed/total and are surfaced on their own.
        notAssessed: isRestorable
          ? (control.notAssessedHosts ?? Math.max(0, sweptHosts - eligibleHosts))
          : sweptHosts,
      };

      // Satisfied only when every assessed host passed. A single passing host is a
      // partial result, and no assessed host at all is not-assessed, never a fail.
      nextChecks[control.key] = eligibleHosts === 0
        ? {
            compliant: false,
            assessed: false,
            reason: isRestorable
              ? 'Not assessed — no host was assessed for this control during the latest compliance run.'
              : ORG_UNMEASURABLE_REASON,
            detail: 'Not assessed — no host assessed',
          }
        : {
            compliant: passHosts === eligibleHosts,
            reason: `${passHosts} of ${eligibleHosts} assessed Windows nodes passed this check`
              + `${nextStats[control.key].notAssessed ? `; ${nextStats[control.key].notAssessed} of the ${sweptHosts} swept hosts could not be assessed for it` : ''}.`,
            detail: `${control.passRatePct}% pass rate`,
          };

    });

    setPointsLoading(false);
    setStaticChecks(nextChecks);
    setFleetPointStats(nextStats);

    setTotalNodes(
      latest.windows_with_results ?? 0
    );

    setSweptWindowsHosts(sweptHosts);

    setFullyCompliantNodes(
      latest.fully_compliant_nodes ?? 0
    );

    setFullyCompliantNodesList(latest.fully_compliant_nodes_list ?? []);
    setNonCompliantNodesList(
      (latest.non_compliant_nodes_list ?? []).map(toHostIdentifier).filter((id) => id.length > 0)
    );
  }, [orgHistory, hostId]);

  useEffect(() => {
    setPointsLoading(true);
    if (hostId === '0') {
      setPointsLoading(false);
      return;
    }
  
    const latest = history?.[0];

    if (!latest) {
      setPointsLoading(false);
      return;
    }

    // Structurally unmeasurable controls are dropped from this register's table
    // entirely, so a stored row for one of them (including rows saved by an
    // older snapshot, before this exclusion existed) must not count toward any
    // denominator computed below — not the assessed/not-assessed KPI cards, not
    // the guideline rows.
    const visibleComplianceData = latest.compliance_data.filter(
      (r) => !STRUCTURALLY_UNMEASURABLE_SEBI_KEYS.has(String(r.command_key))
    );

    // 'not_assessed' rows are neither a pass nor a fail: they leave both the
    // numerator and the denominator.
    const isNotAssessedRow = (output: string) => String(output).trim() === NOT_ASSESSED;

    // A stored 'true'/'false' is only replayed as a MEASURED verdict for a control
    // the current evaluator can actually measure. Legacy snapshots (written before
    // the three-value contract) hold a bare boolean for all 41 controls, so without
    // this intersection a control nothing measures would come back as a measured
    // pass on page load.
    //
    // Whether this row was written under the current write-side contract decides
    // whether contract-era-only keys (4, 5, 7, 8, 10, 16, 17, 24, 28, 30, 32 and any
    // control whose evaluator was added/extended after MEASURABLE_SEBI_KEYS was last
    // updated) may be replayed as real measurements.
    //
    // This must NOT be "does any row hold not_assessed": a row where every single
    // control was actually measured (zero not_assessed entries — the healthiest
    // possible outcome) is indistinguishable from a legacy row by that test, so it
    // fell back to the narrow legacy allow-list and real, freshly-measured FAILs on
    // contract-era-only keys came back mislabelled "Not Assessed — restored from a
    // legacy snapshot" (sebi_compliance_results id=14: 27/27 controls measured, 7
    // real fails, all misreported as not-assessed by the old test).
    //
    // Read this off latest.compliance_data — the RAW stored row, before the
    // visibleComplianceData filter above, which already strips
    // STRUCTURALLY_UNMEASURABLE_SEBI_KEYS ("Class A") rows out and so can never be
    // used to detect their presence. staticComplianceChecks — the only writer of
    // this table (utils/sebiComplianceChecks.ts) — filters its command-key
    // iteration through SEBI_VISIBLE_COMMAND_KEYS, which excludes every Class A key,
    // before building the object this table's rows are persisted from. A row
    // written by current code can therefore structurally never contain an entry
    // (not even 'not_assessed') for one of them — confirmed live: sebi_compliance_
    // results id=14 (current code) carries zero of the 10 Class A keys, while every
    // one of ids 1,2,...,13 (genuinely legacy) carries all ten, each hardcoded
    // 'true'. Presence of even one is therefore unambiguous, positive proof the row
    // predates that filter.
    const isContractEra = !latest.compliance_data.some(
      (row) => STRUCTURALLY_UNMEASURABLE_SEBI_KEYS.has(String(row.command_key))
    );
    const restorableKeys = measurableSebiKeys(isContractEra);

    const isRestorableVerdict = (row: { command_key: string; output: string }) =>
      !isNotAssessedRow(row.output) && restorableKeys.has(String(row.command_key));

    const passedChecks = visibleComplianceData.filter(
      (check) => isRestorableVerdict(check) && check.output === 'true'
    ).length;

    const assessedChecks = visibleComplianceData.filter(isRestorableVerdict).length;

    const notAssessedChecks = visibleComplianceData.length - assessedChecks;

    const nextChecks: Record<string, StaticCheckResult> = {};

    visibleComplianceData.forEach((item) => {
      if (!isRestorableVerdict(item)) {
        const wasStoredNotAssessed = isNotAssessedRow(item.output);
        nextChecks[item.command_key] = {
          compliant: false,
          assessed: false,
          detail: wasStoredNotAssessed
            ? 'Not assessed — not measured on this endpoint'
            : 'Not assessed — restored from a legacy snapshot',
          reason: wasStoredNotAssessed ? RESTORED_NOT_ASSESSED_REASON : RESTORED_LEGACY_REASON,
        };
        return;
      }
      const compliant = item.output === 'true';
      nextChecks[item.command_key] = {
        compliant,
        detail: compliant ? 'Compliant based on latest agent data' : 'Non-compliant based on latest agent data',
        // Never `item.output`: 'true' is not a justification for itself.
        reason: compliant
          ? 'Compliant — the stored result of the latest compliance run on this endpoint recorded this control as passing.'
          : 'Non-compliant — the stored result of the latest compliance run on this endpoint recorded this control as failing.',
      };
    });

    // The guidelines table used to come from a second fetch of this very row
    // (/compliance/sebi/latest/:host). It is derived here instead, so numerator
    // and denominator are two projections of ONE read.
    const sebiData = SEBI_HOT_COMMAND_KEYS.length > 0
      ? visibleComplianceData.filter((r) => SEBI_HOT_COMMAND_KEYS.includes(r.command_key))
      : visibleComplianceData;
    setGuidelines(buildRows(sebiData));

    setPassCount(passedChecks);
    setFailCount(assessedChecks - passedChecks);
    setNotAssessedCount(notAssessedChecks);

    setStaticChecks(nextChecks);
    
    setPointsLoading(false);
  
  }, [history, hostId]);

  // A bounded agent channel: the evidence collectors take a plain
  // `(message) => Promise`, so the per-request budget is bound here rather than
  // left at useNodeWebSocket's 15 s default.
  const boundedWsSendMessage = useMemo(() => {
    if (!wsSendMessage) return undefined;
    return (message: unknown) => wsSendMessage(message, { timeoutMs: WS_REQUEST_TIMEOUT_MS });
  }, [wsSendMessage]);

  // A sweep in flight is killed instantly by a tab close/reload, leaving whatever
  // subset had already responded on screen as if the run had completed.
  useEffect(() => {
    if (!runLoading && sweepProgress === null) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [runLoading, sweepProgress]);

  const handleDownloadVajraCompliance = useCallback(async () => {
    if (downloadLoading) return;

    setDownloadLoading(true);
    try {
      const downloadUrl = `${API_BASE_URL}/api/compliance/reports/sebi-pdf`;
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
      link.download = 'vajra-sebi-compliance.pdf';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(objectUrl);
    } catch (err) {
      // The download used to fail silently: the button simply stopped spinning.
      console.error('Failed to download Vajra Compliance PDF', err);
      setError(
        `Failed to download the SEBI compliance report: ${err instanceof Error ? err.message : 'the request failed'}. Please try again.`
      );
    } finally {
      setDownloadLoading(false);
    }
  }, [downloadLoading]);
  
  const handleOneDeviceCompliance = useCallback(async () => {
    // In-flight guard: without it a double-click starts a second run that writes a
    // second evidence row for the same moment.
    if (runLoading || pointsLoading) return;
    setRunLoading(true);
    setPointsLoading(true);
    setError(null);
    try {
      const checks = await staticComplianceChecks(
        hostId,
        node,
        wsConnected,
        boundedWsSendMessage
      );

      let pass = 0;
      let fail = 0;
      let notAssessed = 0;

      Object.values(checks).forEach((result) => {
        if (!result) return;

        // A control Vajra could not measure is not a failure: it is counted
        // separately and stays out of the pass/fail score entirely.
        if (result.assessed === false) {
          notAssessed += 1;
        } else if (result.compliant) {
          pass += 1;
        } else {
          fail += 1;
        }
      });

      setPassCount(pass);
      setFailCount(fail);
      setNotAssessedCount(notAssessed);

      debugLog('[SEBI Hot] One-device compliance', {
        hostId,
        pass,
        fail,
        notAssessed,
        total: pass + fail,
      });
      setPointsLoading(false);
      setStaticChecks(checks);

      // Three-value persisted contract: 'true' | 'false' | 'not_assessed'.
      // Missing evidence (an absent result or assessed === false) is recorded as
      // not-assessed so it can never be read back as a fabricated failure.
      const complianceData = Object.entries(checks).map(([command_key, result]) => ({
        command_key,
        output: (!result || result.assessed === false)
          ? NOT_ASSESSED
          : (result.compliant ? 'true' : 'false'),
      }));

      try {
        // fetchWithCsrf resolves for 4xx/5xx too, so the response has to be read:
        // discarding it made a rejected save look like a completed run.
        const saveRes = await fetchWithCsrf(`${NODES_URLS.SEBI_NODE_COMPLIANCE_SNAPSHOT}${encodeURIComponent(hostId)}`, {
          method: 'POST',
          credentials: 'include',
          headers: csrfHeadersJson(),
          body: JSON.stringify({
            hostIdentifier: hostId,
            unixtime: Math.floor(Date.now() / 1000),
            complianceData,
          }),
        });

        if (!saveRes.ok) {
          console.error(`[SEBI Hot] Failed to save snapshot: HTTP ${saveRes.status}`);
          // Do NOT refresh history here: the stored row is the previous run, and
          // re-reading it would present a stale timestamp as this run's result.
          setError(
            `SEBI compliance was calculated but NOT saved (HTTP ${saveRes.status}). The scores below are this run's; the stored evidence and the "Last Compliance Run" timestamp still belong to the previous run.`
          );
        } else {
          // Refresh history after saving (history[0] is the new latest record)
          void fetchHistory();
        }
      } catch (err) {
        console.error('[SEBI Hot] Failed to save snapshot:', err);
        setError(
          `SEBI compliance was calculated but NOT saved: ${err instanceof Error ? err.message : 'the save request failed'}. The scores below are this run's; the stored evidence still belongs to the previous run.`
        );
      }
    } catch (err) {
      console.error('[SEBI Hot] Failed to calculate compliance:', err);
      setError(
        `Could not complete the SEBI compliance run for this endpoint: ${err instanceof Error ? err.message : 'the compliance checks failed'}. No result was computed or saved.`
      );
    } finally {
      // Both flags reset unconditionally: a throw used to leave the "Calculating…"
      // screen up for ever with no error and a still-clickable refresh button.
      setPointsLoading(false);
      setRunLoading(false);
    }
  }, [boundedWsSendMessage, fetchHistory, hostId, node, pointsLoading, runLoading, wsConnected]);

  const [noWindowsNodes, setNoWindowsNodes] = useState(false);

  // Run SEBI Hot compliance across online Windows nodes
  const handleRefreshWindows = async () => {
    if (runLoading || pointsLoading) return;
    setBulkRunSummary(null);
    setRunLoading(true);
    setPointsLoading(true);
    setNoWindowsNodes(false);
    setError(null);
    try {
      // The leading scan of the currently-viewed host was removed: that host is
      // covered by the sweep below, and every key of the leading result was
      // overwritten by the fleet aggregate afterwards anyway.
      const res = await api.get(NODES_URLS.NODES_IDENTIFIERS);
      const json = res.data;
      const nodesArray: Array<Record<string, unknown>> = Array.isArray(json?.data)
        ? json.data
        : Array.isArray(json?.nodes)
          ? json.nodes
          : Array.isArray(json)
            ? json
            : [];

      const isWindowsNode = (n: Record<string, unknown>) => {
        const osName = String(n?.os_name ?? '').toLowerCase();
        const osPlatform = String(n?.os_platform ?? '').toLowerCase();
        return osName.includes('windows') || osPlatform.includes('windows');
      };

      const isOnlineNode = (n: Record<string, unknown>) => {
        const status = String(n?.status ?? n?.displayStatus ?? '').toLowerCase();
        return n?.agent_online === true || status === 'online';
      };

      const windowsCandidates = nodesArray.filter(isWindowsNode);
      const windowsOnline = windowsCandidates.filter(isOnlineNode);

      debugLog('[SEBI Hot] Windows candidates:', windowsCandidates.map((n) => ({
        id: n?.id,
        host_identifier: n?.host_identifier,
        hostname: n?.hostname,
        os_name: n?.os_name,
        os_platform: n?.os_platform,
        agent_online: n?.agent_online,
        status: n?.status,
        displayStatus: n?.displayStatus,
      })));

      debugLog('[SEBI Hot] Online Windows nodes:', windowsOnline.map((n) => ({
        id: n?.id,
        host_identifier: n?.host_identifier,
        hostname: n?.hostname,
        os_name: n?.os_name,
        os_platform: n?.os_platform,
        agent_online: n?.agent_online,
        status: n?.status,
        displayStatus: n?.displayStatus,
      })));

      const hostIds = windowsOnline
        .map((n) => String(n?.host_identifier ?? n?.id ?? '').trim())
        .filter((id) => id.length > 0);

      if (hostIds.length === 0) {
        setBulkRunSummary({
          headline: 'No Windows nodes found to run SEBI Hot compliance.',
          lines: [],
          failed: true,
        });
        setNoWindowsNodes(true);
        return;
      }

      let successCount = 0;
      let failureCount = 0;
      let cumulativeNodePercent = 0;
      let processedNodes = 0;
      let fullyCompliantCount = 0;
      let notAssessedNodes = 0;

      const resultLines: string[] = [];
      const nextFleetPointStats: Record<string, FleetPointStat> = 
        SEBI_VISIBLE_COMMAND_KEYS.reduce<Record<string, FleetPointStat>>(
          (acc, key) => {
            acc[key] = { passed: 0, total: 0, notAssessed: 0 };
            return acc;
          },
          {}
        );

      const fullyCompliantNodesList: string[] = [];
      const nonCompliantNodesList: string[] = [];
      const nonCompliantNodesWithChecks: Array<{ host_identifier: string; failed_checks: string[] }> = [];

      // Hosts are swept in parallel (the same helper and concurrency the org sweep
      // uses) instead of strictly one at a time, and each host runs against its own
      // deadline so one wedged agent costs one timeout for that host rather than
      // stalling every host behind it. Results are collected in input order, so the
      // per-key fleet accumulation below stays deterministic.
      setSweepProgress({ done: 0, total: hostIds.length });
      const markHostDone = () =>
        setSweepProgress((prev) => ({ done: (prev?.done ?? 0) + 1, total: hostIds.length }));

      type SweepOutcome = {
        id: string;
        checks: Record<string, StaticCheckResult> | null;
        failureReason: string | null;
      };

      // One pacer per sweep: the gate is about this run's own fan-out, so it
      // starts empty on every run and is never shared with a later one.
      const admitHost = createHostAdmissionPacer(SWEEP_HOSTS_PER_WINDOW, API_DATA_WINDOW_MS);

      const sweepOutcomes = await mapWithConcurrency<string, SweepOutcome>(
        hostIds,
        SWEEP_CONCURRENCY,
        async (id) => {
          const targetNode = windowsOnline.find((n) => String(n?.host_identifier ?? n?.id ?? '').trim() === id) as NodeData | undefined;
          if (!targetNode) {
            markHostDone();
            return { id, checks: null, failureReason: 'skipped (offline)' };
          }
          // Waiting for admission happens OUTSIDE the per-host deadline: the
          // deadline exists to bound a stuck agent, and time spent queued
          // behind the rate-limit budget is not the agent being slow.
          await admitHost();
          try {
            const checks = await withDeadline(
              staticComplianceChecks(id, targetNode, wsConnected, boundedWsSendMessage),
              PER_HOST_SWEEP_TIMEOUT_MS,
              id,
            );
            return { id, checks, failureReason: null };
          } catch (err) {
            console.error(`[SEBI Hot] Failed to run compliance checks on node ${id}:`, err);
            return {
              id,
              checks: null,
              failureReason: err instanceof HostSweepTimeoutError
                ? `timed out after ${Math.round(PER_HOST_SWEEP_TIMEOUT_MS / 1000)}s`
                : 'failed',
            };
          } finally {
            markHostDone();
          }
        },
      );

      for (const outcome of sweepOutcomes) {
        const { id, checks, failureReason } = outcome;
        {
          if (failureReason !== null || checks === null) {
            failureCount += 1;
            // A host whose sweep failed was measured for nothing: it is counted
            // as not-assessed on every control rather than dropped, so the
            // per-control coverage figure describes the hosts the sweep set out
            // to cover and not only those that answered.
            SEBI_VISIBLE_COMMAND_KEYS.forEach((key) => {
              nextFleetPointStats[key].notAssessed = (nextFleetPointStats[key].notAssessed ?? 0) + 1;
            });
            resultLines.push(`${id}: ${failureReason ?? 'failed'}`);
            debugLog(`[SEBI Hot] ${id} ${failureReason ?? 'failed'}`);
            continue;
          }

          // Controls that could not be measured on this node leave both the
          // numerator and the denominator — they are not failures.
          const pass = Object.values(checks)
            .filter((c) => c != null && c.assessed !== false && c.compliant)
            .length;

          const total = Object.values(checks)
            .filter((c) => c != null && c.assessed !== false)
            .length;

          debugLog(total)

          if (total === 0) {
            // Nothing was assessed on this node, so it is neither compliant nor
            // non-compliant and must not be scored either way.
            notAssessedNodes += 1;
            successCount += 1;
            resultLines.push(`${id}: not assessed`);
            debugLog(`[SEBI Hot] ${id} produced no assessed control, recorded as not assessed`);
            SEBI_VISIBLE_COMMAND_KEYS.forEach((key) => {
              nextFleetPointStats[key].notAssessed = (nextFleetPointStats[key].notAssessed ?? 0) + 1;
            });
            if (id === hostId) {
              setStaticChecks(checks);
            }
            continue;
          }

          if (pass === total) {
            fullyCompliantCount += 1;
            fullyCompliantNodesList.push(id);
          } else {
            nonCompliantNodesList.push(id);
            const failedChecks = Object.entries(checks)
              .filter(([, v]) => v != null && v.assessed !== false && !v.compliant)
              .map(([k]) => k);
            nonCompliantNodesWithChecks.push({ host_identifier: id, failed_checks: failedChecks });
          }

          const nodePercent = (pass / total) * 100;

          cumulativeNodePercent += nodePercent;
          processedNodes++;

          if (id === hostId) {
            setStaticChecks(checks);
          }

          SEBI_VISIBLE_COMMAND_KEYS.forEach((key) => {
            const check = checks[key];
            // A host the control was not assessed on is counted separately and
            // stays out of the passed/total fraction.
            if (!check || check.assessed === false) {
              nextFleetPointStats[key].notAssessed = (nextFleetPointStats[key].notAssessed ?? 0) + 1;
              return;
            }
            nextFleetPointStats[key].total += 1;
            if (check.compliant) {
              nextFleetPointStats[key].passed += 1;
            }
          });

          successCount += 1;
          resultLines.push(`${id}: success`);
          debugLog(`[SEBI Hot] ${id} success`);
        }
      }

      setBulkRunSummary({
        headline:
          `Ran SEBI Hot compliance on ${successCount} Windows node${successCount !== 1 ? 's' : ''}`
          + (failureCount > 0 ? `, ${failureCount} failed.` : '.')
          + (notAssessedNodes > 0 ? ` ${notAssessedNodes} node${notAssessedNodes !== 1 ? 's' : ''} produced no assessable control.` : ''),
        lines: resultLines,
        failed: failureCount > 0,
      });

      setTotalNodes(processedNodes);
      setSweptWindowsHosts(hostIds.length);
      setFullyCompliantNodes(fullyCompliantCount);
      setFullyCompliantNodesList(fullyCompliantNodesList);
      setNonCompliantNodesList(nonCompliantNodesList);

      const averageNodeCompliance =
        processedNodes > 0
          ? cumulativeNodePercent / processedNodes
          : 0;

      let totalPassed = 0;
      let totalChecks = 0;
      Object.entries(nextFleetPointStats).forEach(([key, stat]) => {
        if (HIDDEN_GUIDELINES.has(key)) return;

        totalPassed += stat.passed;
        totalChecks += stat.total;
      });

      const aggregateFleetCompliance =
        totalChecks > 0
          ? Number((totalPassed / totalChecks) * 100)
          : 0;

      debugLog('[SEBI Hot] Compliance results:', {
        successCount,
        failureCount,
        notAssessedNodes,
        averageNodeCompliance,
        aggregateFleetCompliance,
        pointStats: nextFleetPointStats,
      });

      const fleetAwareChecks: Record<string, StaticCheckResult> = {};
      Object.entries(nextFleetPointStats).forEach(([key, stat]) => {
        if (HIDDEN_GUIDELINES.has(key)) return;
        if (stat.total === 0) {
          // No host could be assessed for this control: neither a pass nor a
          // fail for the fleet, so it is recorded as not assessed.
          fleetAwareChecks[key] = {
            compliant: false,
            assessed: false,
            reason: `None of the ${hostIds.length} swept Windows node${hostIds.length !== 1 ? 's' : ''} could be assessed for this check during this compliance run, so it is neither passed nor failed for the fleet.`,
            detail: 'Not assessed — no host assessed',
          };
          return;
        }
        // The fleet only satisfies a control when EVERY assessed host passed it.
        // One passing host out of many is a partial result, never a fleet pass;
        // the real fraction (stat.passed/stat.total) is what the row renders.
        fleetAwareChecks[key] = {
          compliant: stat.passed === stat.total,
          reason: `${stat.passed} of ${stat.total} assessed Windows nodes passed this check during this compliance run`
            + `${(stat.notAssessed ?? 0) > 0 ? `; ${stat.notAssessed} of the ${hostIds.length} swept hosts could not be assessed for it` : ''}.`,
          detail: `${stat.passed}/${stat.total} nodes passed`,
        };
      });

      const controlPassRates =
        Object.entries(nextFleetPointStats)
          .filter(([key]) => !HIDDEN_GUIDELINES.has(key))
          .map(([key, stat]) => ({
            key,
            label: SEBI_HOT_GUIDELINES[key].label,
            passRatePct:
              stat.total > 0
                ? Number(((stat.passed / stat.total) * 100).toFixed(2))
                : null,
            passHosts: stat.passed,
            failHosts: stat.total - stat.passed,
            eligibleHosts: stat.total,
            // Persisted rather than re-derived on restore: the derivation used
            // windows_with_results, which excludes the very hosts this counts.
            notAssessedHosts: stat.notAssessed ?? 0,
          }));

      setPointsLoading(false);

      setStaticChecks(fleetAwareChecks);
      setFleetPointStats(nextFleetPointStats);

      try {
        const snapshotRes = await fetchWithCsrf(NODES_URLS.SEBI_COMPLIANCE_SNAPSHOT, {
          method: 'POST',
          credentials: 'include',
          headers: csrfHeadersJson(),
          body: JSON.stringify({
            snapshotAt: Math.floor(Date.now() / 1000),

            totalNodes: windowsCandidates.length,

            windowsHosts: hostIds.length,

            // Nodes on which nothing at all could be assessed are neither
            // compliant nor non-compliant, so they stay out of this denominator
            // (processedNodes === successCount - notAssessedNodes).
            windowsWithResults: processedNodes,

            fullyCompliantNodes: fullyCompliantCount,

            avgCompliancePercent: averageNodeCompliance.toFixed(2),

            strongCount: 0,
            moderateCount: 0,
            needsAttentionCount: 0,

            controlPassRates,

            source: 'live',

            fullyCompliantNodesList,
            // Send the rich per-host entries ({ host_identifier, failed_checks }) rather than
            // bare identifiers: the report's stored-snapshot branch can only score a host when
            // failed_checks is present, and renders "Score not recorded" otherwise. Legacy rows
            // holding bare strings are still read by the backend's toHostIdentifier helper.
            nonCompliantNodesList: nonCompliantNodesWithChecks,
          }),
        });
        if (!snapshotRes.ok) {
          console.warn(`[SEBI Hot] Compliance snapshot save failed: HTTP ${snapshotRes.status}`);
          setError(
            `The fleet SEBI compliance run finished but its snapshot was NOT saved (HTTP ${snapshotRes.status}). The figures below are this run's; the stored organisation history still shows the previous run.`
          );
        } else {
          debugLog('[SEBI Hot] Compliance snapshot saved successfully');
          void fetchOrgHistory();
        }
      } catch (err) {
        console.warn('[SEBI Hot] Compliance snapshot save failed:', err);
        setError(
          `The fleet SEBI compliance run finished but its snapshot was NOT saved: ${err instanceof Error ? err.message : 'the save request failed'}. The figures below are this run's; the stored organisation history still shows the previous run.`
        );
      }
    } catch (err: unknown) {
      setBulkRunSummary({
        headline: err instanceof Error ? `Error: ${err.message}` : 'Failed to run compliance checks on Windows nodes.',
        lines: [],
        failed: true,
      });
      setError(
        `Could not complete the fleet SEBI compliance run: ${err instanceof Error ? err.message : 'the compliance run failed'}.`
      );
    } finally {
      setPointsLoading(false);
      setRunLoading(false);
      setSweepProgress(null);
    }
  };

  // Every derived dataset below is memoized on its real inputs. Rebuilt in the
  // render body they handed recharts a new array identity on any of the 30-odd
  // state changes in this component, re-running the sort and re-animating the
  // charts for state that never touched them.
  const visibleGuidelines = useMemo(
    () => guidelines.filter((g) => !HIDDEN_GUIDELINES.has(g.key) && !STRUCTURALLY_UNMEASURABLE_SEBI_KEYS.has(g.key)),
    [guidelines]
  );

  // Derived values
  const totalChecks = passCount + failCount;

  const pieData = useMemo(
    () => (passCount + failCount > 0
      ? [
          { name: 'Pass', value: passCount },
          { name: 'Fail', value: failCount },
          // Not assessed is neither a pass nor a fail: it gets its own neutral
          // slice and stays out of the percentage shown in the centre.
          ...(notAssessedCount > 0
            ? [{ name: 'Not Assessed', value: notAssessedCount }]
            : []),
        ]
      : []),
    [passCount, failCount, notAssessedCount]
  );

  const chartData = useMemo(() => [...history].reverse().map((rec) => {
    const sebiData = SEBI_VISIBLE_COMMAND_KEYS.length > 0
      ? rec.compliance_data.filter((r) => SEBI_VISIBLE_COMMAND_KEYS.includes(r.command_key))
      : rec.compliance_data;
    // 'not_assessed' rows are neither a pass nor a fail, so they leave both the
    // numerator and the denominator of the trend. The same era test the register
    // applies when restoring a snapshot applies here (same root cause, same fix —
    // see the isContractEra derivation above), so the trend and the header
    // describe the same population: a fully-measured contract-era record keeps
    // every real value, and only a genuinely legacy record is clamped to the
    // narrow allow-list.
    const recordIsContractEra = !rec.compliance_data.some(
      (r) => STRUCTURALLY_UNMEASURABLE_SEBI_KEYS.has(String(r.command_key))
    );
    const recordKeys = measurableSebiKeys(recordIsContractEra);
    const assessedData = sebiData.filter(
      (r) => String(r.output).trim() !== NOT_ASSESSED && recordKeys.has(String(r.command_key))
    );
    return {
      label: fmtDate(rec.unixtime),
      tooltip: fmtDateTime(rec.unixtime),
      percent: calcPassPercent(buildRows(assessedData)),
    };
  }), [history]);

  const chartOrgData = useMemo(() => [...orgHistory]
    .reverse()
    .map((snapshot) => ({
      label: `${fmtDate(snapshot.snapshot_at)}|${fmtTime(snapshot.snapshot_at)}`,
      tooltip: fmtDateTime(snapshot.snapshot_at),
      // null, never 0: a snapshot in which no host produced a measurement has no pass
      // rate at all, and plotting it as 0% reads as "the entire fleet failed". recharts
      // renders a null as a gap in the line, which is what "not assessed" looks like.
      percent: snapshot.windows_with_results
        ? ((snapshot.fully_compliant_nodes ?? 0) / snapshot.windows_with_results) * 100
        : null,
      nodeCount: snapshot.windows_with_results ?? 0,
    })), [orgHistory]);


  const fullyCompliantChartData = useMemo(
    () => (totalNodes > 0 ? [
      { name: 'Fully Compliant',
        value: Number(((fullyCompliantNodes / totalNodes) * 100).toFixed(2)),
        hosts: fullyCompliantNodesList,
      },
      {
        name: 'Not Fully Compliant',
        value: Number((100 - (fullyCompliantNodes / totalNodes) * 100).toFixed(2)),
        hosts: nonCompliantNodesList,
      },
    ] : []),
    [totalNodes, fullyCompliantNodes, fullyCompliantNodesList, nonCompliantNodesList]
  );

  const orgLatestSnapshot = orgHistory?.[0];

  // Whether the latest STORED org snapshot's fully_compliant_nodes scalar agrees with the
  // length of its own fully_compliant_nodes_list. Ported from NodesViewCertInCompliance.tsx's
  // orgSnapshotListReconciles, which caught a real live self-contradiction (a stored snapshot
  // claiming N fully-compliant hosts against an empty evidence list) — SEBI has the identical
  // unguarded shape (confirmed live: 8 of the oldest stored rows carry this same mismatch,
  // though the current/latest row does not). SEBI has no manual "Save Compliance" button and
  // no scoreIsLive/scoreProvenance concept — this state is populated identically whether from
  // a live sweep or a restored snapshot — so unlike CERT-In's save-button guard, this is a
  // display-only gate: it stops the donut from ever rendering an unsubstantiated percentage.
  const orgSnapshotListReconciles = orgLatestSnapshot == null
    || Number(orgLatestSnapshot.fully_compliant_nodes ?? 0) === (orgLatestSnapshot.fully_compliant_nodes_list ?? []).length;

  const guidelineResultMap = useMemo(
    () => new Map(visibleGuidelines.map((g) => [g.key, g])),
    [visibleGuidelines]
  );

  // The sort used to run as an inline IIFE in the render body, re-sorting every
  // visible control on every render regardless of what changed.
  const sortedGuidelineKeys = useMemo(() => {
    const allKeys = Object.keys(SEBI_HOT_GUIDELINES).filter(
      (key) => !HIDDEN_GUIDELINES.has(key) && !STRUCTURALLY_UNMEASURABLE_SEBI_KEYS.has(key)
    );

    const getComplianceFraction = (key: string) => {
      if (staticChecks[key] !== undefined) {
        if (staticChecks[key]!.fraction) {
          return staticChecks[key]!.fraction!.total > 0 ? staticChecks[key]!.fraction!.value / staticChecks[key]!.fraction!.total : 0;
        }
        if (fleetPointStats[key] && fleetPointStats[key].total > 0 && !noWindowsNodes && !oneDeviceCompliance) {
          return fleetPointStats[key].passed / fleetPointStats[key].total;
        }
        return staticChecks[key]!.compliant ? 1 : 0;
      }
      const result = guidelineResultMap.get(key);
      if (!result) return 0;
      if (fleetPointStats[key] && fleetPointStats[key].total > 0 && !noWindowsNodes && !oneDeviceCompliance) {
        return fleetPointStats[key].passed / fleetPointStats[key].total;
      }
      return result.passed ? 1 : 0;
    };

    if (sortBy === '100_compliant') {
      allKeys.sort((a, b) => getComplianceFraction(b) - getComplianceFraction(a));
    } else if (sortBy === 'not_100_compliant') {
      allKeys.sort((a, b) => getComplianceFraction(a) - getComplianceFraction(b));
    }

    return allKeys;
  }, [sortBy, staticChecks, fleetPointStats, guidelineResultMap, noWindowsNodes, oneDeviceCompliance]);

  /**
   * The population every fleet pass fraction was drawn from. The per-control
   * denominator counts the hosts the control was measured on, which is a subset
   * of the hosts that returned results, which is itself a subset of the Windows
   * estate — and none of that was visible next to the fraction. Null when the
   * population is unknown (nothing swept, or the node list did not load), so an
   * unknown coverage is never printed as full coverage.
   */
  const fleetCoverageNote = useMemo(() => {
    if (oneDeviceCompliance || noWindowsNodes) return null;
    if (totalWindowsNodes <= 0 || sweptWindowsHosts <= 0) return null;
    const notSwept = Math.max(0, totalWindowsNodes - sweptWindowsHosts);
    return notSwept > 0
      ? `${notSwept} of ${totalWindowsNodes} Windows hosts not swept`
      : `all ${totalWindowsNodes} Windows hosts swept`;
  }, [noWindowsNodes, oneDeviceCompliance, sweptWindowsHosts, totalWindowsNodes]);

    const latestSnapshot = orgHistory?.[0];

    // A failed history read means the stored result is UNKNOWN, not absent, and a
    // node that has never run is not the same as one whose history would not load.
    const lastRunText = orgHistoryError
      ? 'Unavailable — history could not be loaded'
      : latestSnapshot
        ? fmtDateTime(latestSnapshot.snapshot_at)
        : 'Not yet assessed';

    const latestNodeSnapshot = history?.[0];

    const lastNodeRunText = historyError
      ? 'Unavailable — history could not be loaded'
      : latestNodeSnapshot
        ? fmtDateTime(latestNodeSnapshot.unixtime)
        : 'Not yet assessed';


  return (
    <div className="px-4 pb-4 space-y-4">

      {/* Sebi Toolbar */}
        <div className="mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
          <div className="flex flex-wrap items-center gap-5 w-full">
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                <span className="text-xs font-semibold text-slate-500">Compliance Checks:</span>
                <span className="text-sm font-semibold text-slate-800 tabular-nums">{SEBI_VISIBLE_COMMAND_KEYS.length} points</span>
              </div>
              {!oneDeviceCompliance && (
                <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500" aria-hidden="true" />
                  <span className="text-xs font-semibold text-slate-500">Nodes Online:</span>
                  <span className="text-sm font-semibold text-slate-800 tabular-nums">{onlineNodes} / {totalWindowsNodes}</span>
                </div>
              )}
              {oneDeviceCompliance && (
                <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                  <span className="text-xs font-semibold text-slate-500">Last Compliance Run:</span>
                  <span className="text-sm font-semibold text-slate-800 tabular-nums">{lastNodeRunText}</span>
                </div>
              )}
              {oneDeviceCompliance && (
                  <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                    <span className="text-xs font-semibold text-slate-500">Device Name:</span>
                    <span className="text-sm font-semibold text-slate-800">{node.hostname || node.name || hostId}</span>
                  </div>
                )
              }
              {!oneDeviceCompliance && (
                <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                  <span className="text-xs font-semibold text-slate-500">Last Compliance Run:</span>
                  <span className="text-sm font-semibold text-slate-800 tabular-nums">{lastRunText}</span>
                </div>
              )}
            </div>
            <div className="flex items-center gap-2 ml-auto pl-5 border-l border-slate-200 shrink-0">
              {!oneDeviceCompliance && (
                <>
                  <button
                    type="button"
                    onClick={handleRefreshWindows}
                    disabled={pointsLoading || runLoading}
                    className="inline-flex items-center gap-2 rounded-lg bg-[rgb(4,34,119)] px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-[rgb(10,50,150)] focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 disabled:opacity-60 disabled:cursor-not-allowed"
                  >
                    {pointsLoading
                      ? <DuoSpinner size="xs" className="text-white" />
                      : <i className="fa fa-people-arrows text-xs text-blue-200" />}
                    {pointsLoading
                      ? (sweepProgress
                          ? `Fetching… ${sweepProgress.done}/${sweepProgress.total} nodes`
                          : 'Fetching…')
                      : 'Fetch Endpoint Data'}
                  </button>
                  <button
                    type="button"
                    onClick={handleDownloadVajraCompliance}
                    disabled={downloadLoading}
                    className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm transition-colors hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 disabled:opacity-60 disabled:cursor-not-allowed"
                  >
                    {downloadLoading
                      ? <DuoSpinner size="xs" className="text-slate-500" />
                      : <i className="fa fa-download text-xs" />}
                    {downloadLoading ? 'Downloading…' : 'Download Report'}
                  </button>
                </>
              )}
              {oneDeviceCompliance && agentOnline && (
                <button
                  type="button"
                  onClick={handleOneDeviceCompliance}
                  // Without the live agent channel the WebSocket-backed controls
                  // cannot be measured, and the run would persist a snapshot full of
                  // not-assessed rows that reads like a completed assessment.
                  disabled={!wsConnected || runLoading || pointsLoading}
                  title={!wsConnected
                    ? 'Live agent channel not connected — live-queried controls cannot be measured'
                    : undefined}
                  className="inline-flex items-center gap-2 rounded-lg bg-[rgb(4,34,119)] px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-[rgb(10,50,150)] focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {runLoading
                    ? <DuoSpinner size="xs" className="text-white" />
                    : <i className="fa fa-rotate-right text-xs text-blue-200" />}
                  {runLoading ? 'Running…' : 'Refresh SEBI Compliance'}
                </button>
              )}
            </div>
          </div>
        </div>

      {!agentOnline && oneDeviceCompliance && (
        <div className="flex gap-3 rounded-xl border border-blue-200 bg-blue-100 px-4 py-3 text-sm text-slate-700 mb-4" role="status">
          <i className="fa fa-clock-rotate-left mt-0.5 shrink-0 text-slate-600" aria-hidden />
          <div>
            <p className="font-semibold text-slate-900">Agent is offline.</p>
            <p className="mt-1 text-slate-700/90">Latest compliance can only be checked when the agent is online.</p>
          </div>
        </div>
      )}

      {oneDeviceCompliance && agentOnline && !wsConnected && (
        <div className="flex gap-3 rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900 mb-4" role="alert">
          <i className="fa fa-plug-circle-xmark mt-0.5 shrink-0 text-amber-600" aria-hidden />
          <div>
            <p className="font-semibold">Live agent channel not connected.</p>
            <p className="mt-1">
              The controls that are answered by querying the agent live (USB control, Wi-Fi and Bluetooth state, screen lock)
              cannot be measured right now, so a run started in this state would record them as not assessed rather than as a
              result. Refresh is disabled until the channel reconnects.
            </p>
          </div>
        </div>
      )}

      {bulkRunSummary && (
        <div
          className={`flex gap-3 rounded-xl border px-4 py-3 text-sm ${bulkRunSummary.failed
            ? 'border-red-200 bg-red-50 text-red-800'
            : 'border-slate-200 bg-white text-slate-700'}`}
          role={bulkRunSummary.failed ? 'alert' : 'status'}
        >
          <i
            className={`fa mt-0.5 shrink-0 ${bulkRunSummary.failed
              ? 'fa-circle-exclamation text-red-600'
              : 'fa-circle-check text-emerald-600'}`}
            aria-hidden
          />
          <div className="min-w-0 flex-1">
            <p className="font-semibold">{bulkRunSummary.headline}</p>
            {bulkRunSummary.lines.length > 0 && (
              <details className="mt-1">
                <summary className="cursor-pointer text-xs font-semibold text-slate-600 hover:text-slate-800">
                  Per-node results ({bulkRunSummary.lines.length})
                </summary>
                <ul className="mt-1 max-h-40 overflow-auto rounded-lg bg-slate-50 p-2 text-xs font-mono text-slate-700">
                  {bulkRunSummary.lines.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </details>
            )}
          </div>
          <button
            type="button"
            onClick={() => setBulkRunSummary(null)}
            aria-label="Dismiss run summary"
            className="shrink-0 rounded-md px-2 py-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600"
          >
            <i className="fa fa-xmark" />
          </button>
        </div>
      )}

      {noWindowsNodes && (
        <div className="flex gap-3 rounded-xl border border-blue-200 bg-blue-100 px-4 py-3 text-sm text-slate-700" role="status">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-slate-600" aria-hidden />
          <div>
            <p className="font-semibold text-slate-900">No Windows nodes found</p>
            <p className="mt-1 text-slate-700/90">
              SEBI Hot compliance checks are only applicable to Windows devices. No Windows nodes were found to run compliance checks on.
            </p>
          </div>
        </div>
      )}

      {
        !pointsLoading && orgHistoryError && !oneDeviceCompliance && (
          <div className="flex gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 mb-4" role="alert">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-red-600" aria-hidden />
          <div>
            <p className="font-semibold">Organisation compliance history could not be loaded</p>
            <p className="mt-1">
              The stored organisation results are <span className="font-semibold">unknown, not absent</span>. Nothing below reflects a
              measured fleet result until the history loads or a new compliance run completes.
            </p>
            <button
              type="button"
              onClick={() => { void fetchOrgHistory(); }}
              className="mt-2 inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-3 py-1.5 text-xs font-semibold text-red-700 shadow-sm transition-colors hover:bg-red-50"
            >
              <i className="fa fa-rotate-right text-[10px]" />
              Retry
            </button>
          </div>
        </div>
        )
      }

      {
        !pointsLoading && historyError && oneDeviceCompliance && (
          <div className="flex gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 mb-4" role="alert">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-red-600" aria-hidden />
          <div>
            <p className="font-semibold">Compliance history for this node could not be loaded</p>
            <p className="mt-1">
              The stored results for this endpoint are <span className="font-semibold">unknown, not absent</span> — this is not
              evidence that the node has never been assessed, and nothing below is a measured verdict for it.
            </p>
            <button
              type="button"
              onClick={() => { void fetchHistory(); }}
              className="mt-2 inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-3 py-1.5 text-xs font-semibold text-red-700 shadow-sm transition-colors hover:bg-red-50"
            >
              <i className="fa fa-rotate-right text-[10px]" />
              Retry
            </button>
          </div>
        </div>
        )
      }


      {error && (
        <div className="text-sm px-4 py-3 rounded-lg bg-red-50 text-red-700 border border-red-200">{error}</div>
      )}

      {/* Main two-column layout */}
      {historyLoading && visibleGuidelines.length === 0 ? (
        <div className="flex items-center justify-center h-48">
          <DuoSpinner size="lg" className="text-rose-500" />
        </div>
      ) :
      pointsLoading ? (
        <div className="mt-4 rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-600">
          <LoadingScreen
            title="Calculating SEBI compliance..."
            subtitle="This may take a few moments depending on number of endpoints and network conditions."
            size="md"
            fullScreen={false}
            className="text-blue-600"
          />
        </div>
      ) :
      (
        <>
        <div className="flex flex-col lg:flex-row gap-4 lg:items-stretch">

          {/* Left: guidelines table */}
          <div className="flex-1 min-w-0 bg-white rounded-xl border border-gray-200 overflow-hidden">
            <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
              <span className="font-semibold text-white text-base">SEBI Guidelines</span>
              
              <div className="flex items-center gap-3">
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value as 'default' | '100_compliant' | 'not_100_compliant')}
                  className="bg-white border border-blue-200 text-blue-900 text-xs font-medium rounded-lg px-2 py-1 outline-none focus:ring-2 focus:ring-blue-500/50 transition-shadow"
                >
                  <option value="default">Default Order</option>
                  <option value="100_compliant">Highest Compliance First</option>
                  <option value="not_100_compliant">Lowest Compliance First</option>
                </select>

                {!oneDeviceCompliance && !noWindowsNodes && (
                  <span className="inline-flex items-center rounded-full bg-blue-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
                    <i className="fa fa-arrow-down-wide-short text-slate-400 mr-2" />
                    {orgHistoryError
                      ? 'Compliance history unavailable'
                      : latestSnapshot
                        ? `Fetched from last successful compliance run on ${lastRunText}`
                        : 'Not yet assessed — no compliance run recorded'}
                  </span>
                )}
                {oneDeviceCompliance && (
                  <span className="inline-flex items-center rounded-full bg-blue-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
                    <i className="fa fa-arrow-down-wide-short text-slate-400 mr-2" />
                    {historyError
                      ? 'Compliance history unavailable'
                      : latestNodeSnapshot
                        ? `Fetched from last successful compliance run on ${lastNodeRunText}`
                        : 'Not yet assessed — no compliance run recorded'}
                  </span>
                )}
              </div>
              {/* Numerator and denominator must describe the same population: the
                  assessed controls. Counting not-assessed controls in the total made
                  every unmeasurable control read as a failure. */}
              {(passCount + failCount > 0 || notAssessedCount > 0) && (
                <span className="text-xs text-gray-100">
                  {passCount}/{passCount + failCount} assessed passed
                  {notAssessedCount > 0 ? ` · ${notAssessedCount} not assessed` : ''}
                </span>
              )}
            </div>

            {historyError && oneDeviceCompliance ? (
              // A failed history read is not an unassessed node: rendering every
              // control as "Not checked" would present unknown stored evidence as
              // an absence of evidence.
              <div className="px-4 py-8 text-sm text-slate-700" role="alert">
                <p className="font-semibold text-red-700">Compliance history could not be loaded</p>
                <p className="mt-1 text-slate-600">
                  The stored results for this node are <span className="font-semibold">unknown, not absent</span>. No control below can
                  be shown as passed, failed or unchecked until the history loads or a new compliance run completes.
                </p>
                <button
                  type="button"
                  onClick={() => { void fetchHistory(); }}
                  className="mt-3 inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-sm transition-colors hover:bg-slate-50"
                >
                  <i className="fa fa-rotate-right text-[10px]" />
                  Retry
                </button>
              </div>
            ) : (() => {
              // Lookup map and ordering are memoized above; this block only renders.
              const resultMap = guidelineResultMap;
              const allKeys = sortedGuidelineKeys;

              return (
                <div className="table-scrollbar overflow-auto max-h-[430px]">
                  <table className="w-full text-sm border-separate border-spacing-0">
                    <thead>
                      <tr className="bg-blue-50 border-b border-gray-200">
                        <th className="py-2 px-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide w-8 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">#</th>
                        <th className="py-2 px-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Guideline</th>
                        <th className="py-2 px-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wide w-36 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {allKeys.map((key, i) => {
                        const meta = SEBI_HOT_GUIDELINES[key];
                        const result = resultMap.get(key);
                        const fleetStat = fleetPointStats[key];
                        const check = staticChecks[key];
                        // Fleet stats only describe a multi-node run; the single
                        // device view keeps its own per-host verdict.
                        const verdictStat = !noWindowsNodes && !oneDeviceCompliance ? fleetStat : undefined;
                        const verdict = check !== undefined
                          ? deriveControlVerdict(check, verdictStat)
                          : null;
                        return (
                          <tr
                            key={key}
                            className={`border-b border-gray-100 transition-colors ${
                              verdict !== null
                                ? VERDICT_ROW_HOVER_CLASS[verdict]
                                : result
                                  ? result.passed ? 'hover:bg-green-50' : 'hover:bg-red-50'
                                  : 'hover:bg-gray-50'
                            }`}
                          >
                            <td className="py-2.5 px-3 text-gray-400 text-xs">{i + 1}</td>
                            <td className="py-2.5 px-3 text-gray-800">
                              <span className="inline-flex items-center">
                                {meta.label}
                                {meta.tooltip && (
                                  <InfoTooltip text={meta.tooltip} description={SEBI_HOT_REASON_DETAIL[key]?.reason} withDescription align="right" />
                                )}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-center">
                              {check !== undefined && verdict !== null ? (
                                // Platform-evaluated compliance. The badge shows the
                                // fleet verdict: green only when every assessed host
                                // passed, amber while only some did, neutral when the
                                // control could not be assessed at all.
                                <div className="inline-flex flex-col items-center gap-0.5 w-full">
                                  <div className="inline-flex items-center gap-1">
                                    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${VERDICT_BADGE_CLASS[verdict]}`}>
                                      <i className={`fa ${VERDICT_ICON_CLASS[verdict]} text-[9px]`} />
                                      {verdict === 'not_assessed'
                                        ? VERDICT_LABEL.not_assessed
                                        : (check.fraction
                                            ? `${check.fraction.value}/${check.fraction.total} nodes passed`
                                            : (verdictStat && verdictStat.total > 0
                                                // The denominator is the hosts the control was
                                                // measured on, so the badge says so, and an
                                                // all-pass over an incomplete population carries
                                                // the unmeasured remainder with it.
                                                ? `${verdictStat.passed}/${verdictStat.total} assessed passed`
                                                  + (verdict === 'satisfied_partial_coverage'
                                                      ? ` · ${verdictStat.notAssessed} not assessed`
                                                      : '')
                                                : VERDICT_LABEL[verdict]))}
                                    </span>
                                  </div>
                                  {verdict === 'not_assessed' ? (
                                    <span className="text-[10px] text-gray-400 font-medium">{check.detail ?? 'Not assessed on this endpoint'}</span>
                                  ) : check.fraction ? (() => {
                                    const fr = check.fraction!;
                                    const pct = fr.total > 0 ? (fr.value / fr.total) * 100 : 0;
                                    return (
                                      <div className="w-full mt-0.5 px-1">
                                        <div className="h-1 w-full max-w-[96px] mx-auto bg-gray-100 rounded-full overflow-hidden">
                                          <div
                                            className="h-full rounded-full bg-rose-400 transition-all duration-500"
                                            style={{ width: `${Math.max(pct > 0 ? 4 : 0, pct)}%` }}
                                          />
                                        </div>
                                      </div>
                                    );
                                  })() : verdictStat && verdictStat.total > 0 ? (() => {
                                    const fs = verdictStat;
                                    const pct = fs.total > 0 ? (fs.passed / fs.total) * 100 : 0;
                                    return (
                                      <div className="w-full mt-0.5 px-1">
                                        <div className="h-1 w-full max-w-[96px] mx-auto bg-gray-100 rounded-full overflow-hidden">
                                          <div
                                            className="h-full rounded-full bg-sky-500 transition-all duration-500"
                                            style={{ width: `${Math.max(pct > 0 ? 4 : 0, pct)}%` }}
                                          />
                                        </div>
                                        {(fs.notAssessed ?? 0) > 0 && verdict !== 'satisfied_partial_coverage' && (
                                          <div className="mt-0.5 text-[10px] text-gray-400 font-medium">
                                            {fs.notAssessed} not assessed
                                          </div>
                                        )}
                                        {/* The pass fraction is drawn from the swept hosts only;
                                            printing the denominator without the population it came
                                            from let a control evidenced on a third of the estate
                                            read as a fleet-wide result. */}
                                        {fleetCoverageNote && (
                                          <div className="mt-0.5 text-[10px] text-gray-400 font-medium">
                                            {fleetCoverageNote}
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })() : check.detail ? (
                                    <span className="text-[10px] text-gray-400 font-medium">{check.detail}</span>
                                  ) : null}
                                </div>
                              ) : !result ? (
                                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-500">
                                  <i className="fa fa-minus text-[9px]" />
                                  Not checked
                                </span>
                              ) : result.rawOutput === NOT_ASSESSED ? (
                                // Stored row that was never measured — its own neutral
                                // badge, never rendered as a failure. Legacy rows only
                                // ever hold 'true'/'false' and skip this branch.
                                <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${VERDICT_BADGE_CLASS.not_assessed}`}>
                                  <i className={`fa ${VERDICT_ICON_CLASS.not_assessed} text-[9px]`} />
                                  {VERDICT_LABEL.not_assessed}
                                </span>
                              ) : result.showRaw ? (
                                <span className={`font-semibold text-sm ${result.passed ? 'text-green-600' : 'text-red-600'}`}>
                                  {result.rawOutput === '0'
                                    ? <span title="Not enforced">0 (not set)</span>
                                    : <span title={`Value: ${result.rawOutput}`}>{result.rawOutput}</span>}
                                </span>
                              ) : (
                                <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                                  result.passed ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                                }`}>
                                  <i className={`fa ${result.passed ? 'fa-check' : 'fa-xmark'} text-[9px]`} />
                                  {fleetStat && fleetStat.total > 0 && !noWindowsNodes 
                                    ? `${fleetStat.passed}/${fleetStat.total} nodes passed` 
                                    : (result.passed ? 'Passed' : 'Failed')}
                                </span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              );
            })()}
          </div>

          {/* Right: score + pie */}
          {oneDeviceCompliance && (
            <div className="w-full lg:w-96 shrink-0 flex flex-col">

              <div className="bg-blue-50 rounded-xl border border-blue-200 overflow-hidden">
                <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-slate-700 flex items-center justify-between">
                  <span className="font-semibold text-white text-base">Compliance Score</span>
                </div>

                {pieData.length > 0 ? (
                  <div className="p-4">

                    <div className="flex justify-center gap-5 mt-4">

                      <div className="flex items-center gap-2">
                        <div
                          className="w-3 h-3 rounded-full"
                          style={{ backgroundColor: PIE_COLORS[0] }}
                        />
                        <span className="text-sm text-slate-600">
                          Passed
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <div
                          className="w-3 h-3 rounded-full"
                          style={{ backgroundColor: PIE_COLORS[1] }}
                        />
                        <span className="text-sm text-slate-600">
                          Failed
                        </span>
                      </div>

                      {notAssessedCount > 0 && (
                        <div className="flex items-center gap-2">
                          <div
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: NODE_PIE_COLORS[2] }}
                          />
                          <span className="text-sm text-slate-600">
                            Not Assessed
                          </span>
                        </div>
                      )}

                    </div>

                    {/* Donut */}
                    <div className="flex justify-center">
                      <ResponsiveContainer width="100%" height={280}>
                        
                        <PieChart>
                          <Pie
                            data={pieData}
                            activeShape={renderActiveShape}
                            dataKey="value"
                            cx="50%"
                            cy="50%"
                            innerRadius={65}
                            outerRadius={115}
                            stroke="#fff"
                            strokeWidth={4}
                            cornerRadius={6}
                            isAnimationActive={false}
                          >
                            {pieData.map((_, idx) => (
                              <Cell
                                key={idx}
                                fill={NODE_PIE_COLORS[idx % NODE_PIE_COLORS.length]}
                              />
                            ))}
                          </Pie>

                          {/* Center Label */}
                          <text
                            x="50%"
                            y="46%"
                            textAnchor="middle"
                            dominantBaseline="middle"
                          >
                            <tspan
                              fontSize="34"
                              fontWeight="700"
                              fill="#0F172A"
                            >
                              {(
                                (pieData[0]?.value /
                                  ((pieData[0]?.value ?? 0) +
                                    (pieData[1]?.value ?? 0) || 1)) *
                                100
                              ).toFixed(1)}
                              %
                            </tspan>

                            <tspan
                              x="50%"
                              dy="22"
                              fontSize="14"
                              fill="#64748B"
                            >
                              Checks Passed
                            </tspan>
                          </text>

                          <RTooltip content={<CustomTooltip />} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>

                    {/* KPI Cards */}
                    <div className="grid grid-cols-4 gap-2 mt-2">

                      <div className="rounded-xl bg-[#136f63]/10 py-3 text-center">
                        <div className="text-2xl font-bold text-[#136f63]">
                          {passCount}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                          Passed
                        </div>
                      </div>

                      <div className="rounded-xl bg-[#ab3428]/15 py-3 text-center">
                        <div className="text-2xl font-bold text-[#ab3428]">
                          {failCount}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                          Failed
                        </div>
                      </div>

                      {/* Not assessed is reported on its own: it is excluded from
                          both Passed and Failed and from the Total assessed. */}
                      <div className="rounded-xl bg-slate-500/10 py-3 text-center">
                        <div className="text-2xl font-bold text-slate-600">
                          {notAssessedCount}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                          Not Assessed
                        </div>
                      </div>

                      <div className="rounded-xl bg-[#023047]/10 py-3 text-center">
                        <div className="text-2xl font-bold text-[#023047]">
                          {totalChecks}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                          Assessed
                        </div>
                      </div>

                    </div>

                    {/* Legend */}

                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-[300px] px-6 text-center text-slate-500">
                    <i className="fa fa-chart-pie text-5xl text-gray-200 mb-3" />
                    {historyError ? (
                      <p className="text-sm">Compliance history could not be loaded, so no score can be shown for this endpoint.</p>
                    ) : !latestNodeSnapshot ? (
                      <p className="text-sm">
                        No compliance run yet — click <span className="font-semibold">Refresh SEBI Compliance</span> to assess this endpoint.
                      </p>
                    ) : (
                      <p className="text-sm">
                        The last run measured none of this endpoint&apos;s {notAssessedCount} controls, so there is no pass/fail score to plot.
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>)
          }

          {!oneDeviceCompliance && (
            <div className="w-full lg:w-96 shrink-0 flex flex-col">

              <div className="bg-blue-50 rounded-xl border border-blue-200 overflow-hidden">
                <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-slate-700 flex items-center justify-between">
                  <span className="font-semibold text-white text-base">Compliance Score</span>
                </div>

                {fullyCompliantChartData.length > 0 && !noWindowsNodes && orgSnapshotListReconciles ? (
                  <div className="p-4">

                    <div className="flex justify-center gap-5 mt-4">

                      <div className="flex items-center gap-2">
                        <div
                          className="w-3 h-3 rounded-full"
                          style={{ backgroundColor: PIE_COLORS[0] }}
                        />
                        <span className="text-sm text-slate-600">
                          Fully Compliant
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <div
                          className="w-3 h-3 rounded-full"
                          style={{ backgroundColor: PIE_COLORS[1] }}
                        />
                        <span className="text-sm text-slate-600">
                          Not Fully Compliant
                        </span>
                      </div>

                    </div>

                    {/* Donut */}
                    <div className="flex justify-center">
                      <ResponsiveContainer width="100%" height={280}>
                        
                        <PieChart>
                          <Pie
                            data={fullyCompliantChartData}
                            activeShape={renderActiveShape}
                            dataKey="value"
                            cx="50%"
                            cy="50%"
                            innerRadius={65}
                            outerRadius={115}
                            stroke="#fff"
                            strokeWidth={4}
                            cornerRadius={6}
                            isAnimationActive={false}
                          >
                            {fullyCompliantChartData.map((_, idx) => (
                              <Cell
                                key={idx}
                                fill={PIE_COLORS[idx % PIE_COLORS.length]}
                              />
                            ))}
                          </Pie>

                          {/* Center Label */}
                          <text
                            x="50%"
                            y="46%"
                            textAnchor="middle"
                            dominantBaseline="middle"
                          >
                            <tspan
                              fontSize="34"
                              fontWeight="700"
                              fill="#0F172A"
                            >
                              {(
                                totalNodes ?
                                ((fullyCompliantNodes ?? 0) / totalNodes) * 100 : 0
                              ).toFixed(1)}
                              %
                            </tspan>

                            <tspan
                              x="50%"
                              dy="22"
                              fontSize="14"
                              fill="#64748B"
                            >
                              Fully Compliant
                            </tspan>
                          </text>

                          <RTooltip content={<CustomTooltip />} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>

                    {/* KPI Cards */}
                    <div className="grid grid-cols-3 gap-3 mt-2">

                      <div className="rounded-xl bg-[#136f63]/10 py-3 text-center">
                        <div className="text-2xl font-bold text-[#136f63]">
                          {fullyCompliantNodes ?? 0}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                          Compliant
                        </div>
                      </div>

                      <div className="rounded-xl bg-[#ab3428]/15 py-3 text-center">
                        <div className="text-2xl font-bold text-[#ab3428]">
                          {(totalNodes || 0) - (fullyCompliantNodes || 0)}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                          Non-Compliant
                        </div>
                      </div>

                      <div className="rounded-xl bg-[#023047]/10 py-3 text-center">
                        <div className="text-2xl font-bold text-[#023047]">
                          {totalNodes ?? 0}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                          Total
                        </div>
                      </div>

                    </div>

                    {/* Legend */}

                  </div>
                ) : !noWindowsNodes && !orgSnapshotListReconciles ? (
                  // Evidence gap, not a score: the stored snapshot's compliant-node count
                  // does not match the length of its own evidence list (see
                  // orgSnapshotListReconciles above), so there is no trustworthy number to
                  // draw a donut from. Showing the raw scalar here would be the exact
                  // "N/M = X% Fully Compliant, evidence list empty" leak this guards
                  // against — reports.ts's PDF already refuses to render this section on the
                  // identical mismatch rather than print an unsubstantiated figure.
                  <div className="flex flex-col items-center justify-center h-[27rem] gap-2 px-6 text-center">
                    <i className="fa fa-triangle-exclamation text-3xl text-amber-500" aria-hidden />
                    <p className="text-sm font-semibold text-slate-700">Compliant-node count unavailable</p>
                    <p className="text-xs text-slate-500">
                      The saved snapshot&apos;s compliant-node count doesn&apos;t match its own evidence list, so it
                      can&apos;t be shown here. Run a fresh compliance sweep to refresh it.
                    </p>
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-[27rem] text-gray-300">
                    <i className="fa fa-chart-pie text-6xl" />
                  </div>
                )}
              </div>
            </div>)
          }
        </div>

        
        </>
      )}

      {/* History trend chart */}
      {!oneDeviceCompliance && !pointsLoading && (<div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
          <span className="font-semibold text-white text-base">Organization SEBI Compliance History</span>
          {!orgHistoryLoading && orgHistory.length > 0 && (
            <span className="inline-flex items-center rounded-full bg-blue-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
            <i className="fa fa-arrow-down-wide-short text-slate-400 mr-2" />
              {orgHistory.length} record{orgHistory.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div className="p-4 bg-blue-50">
          {orgHistoryLoading ? (
            <div className="flex items-center justify-center h-[180px]">
              <DuoSpinner size="md" className="text-rose-400" />
            </div>
          ) : chartOrgData.length >= 2 ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={chartOrgData} margin={TREND_CHART_MARGIN}>
                <CartesianGrid strokeDasharray="3 3" stroke="#d8d8d8" />
                <XAxis
                  dataKey="label"
                  tick={({ x, y, payload }) => {
                    const [date, time] = String(payload.value).split('|');

                    return (
                      <g transform={`translate(${x},${y})`}>
                        <text
                          textAnchor="middle"
                          fill="#666"
                          fontSize={11}
                        >
                          <tspan x="0" dy="0">
                            {date}
                          </tspan>
                          <tspan x="0" dy="12">
                            {time}
                          </tspan>
                        </text>
                      </g>
                    );
                  }}
                />
                <YAxis domain={[0, 100]} tick={TREND_AXIS_TICK} tickLine={false} unit="%" width={38} />
                <RTooltip
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;

                    const point = payload[0].payload;

                    return (
                      <div className="rounded-lg border border-slate-200 bg-white p-3 shadow-lg">
                        <div className="font-medium text-slate-800">
                          {point.tooltip}
                        </div>

                        <div className="mt-2 text-rose-600">
                          Pass Rate: {point.percent.toFixed(2)}%
                        </div>

                        <div className="mt-1 text-slate-600">
                          Windows Nodes Processed: {point.nodeCount}
                        </div>
                      </div>
                    );
                  }}
                />
                <Legend iconType="circle" iconSize={10} wrapperStyle={TREND_LEGEND_WRAPPER} />
                <Line
                  type="monotone"
                  dataKey="percent"
                  name="Pass rate %"
                  stroke="#e11d48"
                  strokeWidth={2}
                  dot={TREND_LINE_DOT}
                  activeDot={TREND_LINE_ACTIVE_DOT}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : chartOrgData.length === 1 ? (
            <div className="flex items-center justify-center h-[180px] text-gray-400 text-sm text-center">
              Only 1 record — run another compliance check to see the trend.
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-[180px] text-gray-400">
              <i className="fa fa-chart-line text-4xl mb-3 opacity-20" />
              <p className="text-sm font-medium">No history yet</p>
              <p className="text-xs mt-1">History builds as you run compliance checks</p>
            </div>
          )}
        </div>
      </div>)}

      {/* History trend chart */}
      {oneDeviceCompliance && !pointsLoading && (<div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
          <span className="font-semibold text-white text-base">Node SEBI Compliance History</span>
          {!historyLoading && history.length > 0 && (
            <span className="inline-flex items-center rounded-full bg-blue-50 border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600">
            <i className="fa fa-arrow-down-wide-short text-slate-400 mr-2" />
              {history.length} record{history.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
        <div className="bg-blue-50 p-4">
          {historyLoading ? (
            <div className="flex items-center justify-center h-[180px]">
              <DuoSpinner size="md" className="text-rose-400" />
            </div>
          ) : chartData.length >= 2 ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={chartData} margin={TREND_CHART_MARGIN}>
                <CartesianGrid strokeDasharray="3 3" stroke="#d8d8d8" />
                <XAxis
                  dataKey="label"
                  tick={({ x, y, payload }) => {
                    const [date, time] = String(payload.value).split('|');

                    return (
                      <g transform={`translate(${x},${y})`}>
                        <text
                          textAnchor="middle"
                          fill="#666"
                          fontSize={11}
                        >
                          <tspan x="0" dy="0">
                            {date}
                          </tspan>
                          <tspan x="0" dy="12">
                            {time}
                          </tspan>
                        </text>
                      </g>
                    );
                  }}
                />
                <YAxis domain={[0, 100]} tick={TREND_AXIS_TICK} tickLine={false} unit="%" width={38} />
                <RTooltip
                  formatter={(value) => [`${Number(Array.isArray(value) ? value[0] : value) || 0}%`, 'Pass rate']}
                  labelFormatter={(label: React.ReactNode, payload?: unknown) => {
                    const items = Array.isArray(payload) ? payload as Array<{ payload?: { tooltip?: string } }> : [];
                    return items[0]?.payload?.tooltip ?? label;
                  }}
                />
                <Legend iconType="circle" iconSize={10} wrapperStyle={TREND_LEGEND_WRAPPER} />
                <Line
                  type="monotone"
                  dataKey="percent"
                  name="Pass rate %"
                  stroke="#e11d48"
                  strokeWidth={2}
                  dot={TREND_LINE_DOT}
                  activeDot={TREND_LINE_ACTIVE_DOT}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : chartData.length === 1 ? (
            <div className="flex items-center justify-center h-[180px] text-gray-400 text-sm text-center">
              Only 1 record — run another compliance check to see the trend.
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-[180px] text-gray-400">
              <i className="fa fa-chart-line text-4xl mb-3 opacity-20" />
              <p className="text-sm font-medium">No history yet</p>
              <p className="text-xs mt-1">History builds as you run compliance checks</p>
            </div>
          )}
        </div>
      </div>)}

    </div>
  );
}