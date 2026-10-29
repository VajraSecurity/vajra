import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { debugLog } from '@/lib/debugLog';
import { getCertinCompliance, resetCertinCompliance, saveCertinCompliance } from '../../../api/certinCompliance';
import type { NodeData } from './types';
import { API_BASE_URL, NODES_URLS } from '../../../api/urls';
import api from '../../../api/axiosInstance';
import { getStoredUser } from '../../../services/auth';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip as RTooltip,
  Legend,
  XAxis,
  CartesianGrid,
  LineChart,
  YAxis,
  Line,
} from 'recharts';
import { PIE_COLORS, renderActiveShape, CustomTooltip } from '../../Compliance/shared/ComplianceChart';
import { fmtDate, fmtDateTime, fmtTime } from '../../Compliance/shared/complianceDateUtils';

import { csrfHeadersJson, fetchWithCsrf } from '@/api/csrfClient';
import { useConfirm } from '../../../context/useConfirm';
import { LoadingScreen, DuoSpinner } from '@/components/ui/loading';
import { CERTIN_PENDING_POINTS, STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS, CERTIN_AUTOMATED_POINT_DETAILS } from './constants/certinPendingPoints';
import type { CertInSection, CertInPointer } from './utils/certinHierarchy';
import { buildCertInSections, buildHierarchy } from './utils/certinHierarchy';
import { NestedChildren } from './components/NestedChildren';
import { InfoTooltip } from './components/InfoTooltip';
import type { StaticCheckResult } from './utils/certinComplianceChecks';
import { staticComplianceChecks } from './utils/certinComplianceChecks';

type CompliancePoint = {
  marker: string;
  status: 'yes' | 'no' | 'not_assessed';
  source: 'automatic' | 'manual';
};




type ControlPassRate = {
  key: string;
  label: string;
  passRatePct: number | null;
  passHosts: number;
  failHosts: number;
  eligibleHosts: number;
  // True where the row records an operator's organisation-level Yes/No answer rather
  // than a per-host measurement. Such a row carries no host counts at all; the report
  // renders it as "Attested" instead of as a pass rate.
  attested?: boolean;
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
  // Newer snapshots store objects ({ host_identifier, failed_checks }); rows written
  // before that stored bare host identifier strings. Both must keep rehydrating.
  non_compliant_nodes_list?: Array<string | { host_identifier?: string; failed_checks?: string[] }> | null;
};

/**
 * Normalises a stored non-compliant entry back into the shape the snapshot payload
 * uses. A legacy bare string carries no failed_checks, and that array must stay
 * *absent* rather than become an empty one: reports.ts treats a missing
 * failed_checks as "score not recorded", while an empty array reads as "this host
 * failed nothing".
 */
function toNonCompliantEntry(
  entry: string | { host_identifier?: string; failed_checks?: string[] },
): { host_identifier: string; failed_checks?: string[] } {
  if (typeof entry === 'string') return { host_identifier: entry };
  const hostIdentifier = entry?.host_identifier ?? '';
  return Array.isArray(entry?.failed_checks)
    ? { host_identifier: hostIdentifier, failed_checks: entry.failed_checks }
    : { host_identifier: hostIdentifier };
}

interface ComplianceRecord {
  id: number;
  host_identifier: string;
  unixtime: number;
  compliance_data: Array<{ command_key: string; output: string }>;
}


const PUBLIC_JSON_PATH = `${import.meta.env.BASE_URL}certin-compliance.json`;

// Drops the Class A (STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS) automated-point rows out of
// the raw checklist JSON before it is ever turned into sections/pointers, so every count
// derived from the resulting tree (section pointer counts, "N pointers" per standard
// group, etc.) is already correct with no separate recompute step needed downstream. Only
// top-level guideline entries carry a CERT-In point marker in this dataset (no automated
// marker is ever nested under another point's `children`), so a shallow filter per section
// is sufficient — this must never reach into a pointer's own children, which are sub-detail
// text for a manual point, not a sibling checklist row.
function stripStructurallyUnmeasurablePoints(raw: unknown): unknown {
  if (!Array.isArray(raw)) return raw;
  return raw.map((section) => {
    if (!section || typeof section !== 'object') return section;
    const obj = section as Record<string, unknown>;
    if (!Array.isArray(obj.children)) return section;
    return {
      ...obj,
      children: obj.children.filter((point) => {
        const marker = String((point as Record<string, unknown> | null)?.marker ?? '').trim();
        return !STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS.has(marker);
      }),
    };
  });
}






type FleetCompliancePoint = {
  marker: string;
  passedNodes: number;
  failedNodes: number;
  totalNodes: number;
  passRate: number;
};




interface FleetPointStat {
  passed: number;
  total: number;
}

interface NodesViewCertInComplianceProps {
  node: NodeData;
  wsConnected?: boolean;
  wsSendMessage?: (message: unknown) => Promise<unknown>;
  agentOnline?: boolean;
}

// Sentinel nodeHostIdentifier for the org-level aggregate CERT-In view (no
// single node backs it — see ORG_LEVEL_HOST_ID in backend/certin_compliance.ts).
// Must match the backend constant exactly. The leading underscore is
// deliberate: real host identifiers must start with an alphanumeric
// character (HOST_IDENTIFIER_PATTERN in agentCertProvisioning.ts), so this
// value can never collide with a real enrolled node's identifier.
const ORG_LEVEL_HOST_ID = '__org_level__';

// Third persisted value of the shared compliance contract, alongside 'true' and
// 'false': the control was not measured on this host. Readers must keep it out
// of both the numerator and the denominator of any score and surface it
// separately — it is neither a pass nor a failure. Legacy snapshots hold only
// 'true'/'false' and keep scoring exactly as before.
const NOT_ASSESSED = 'not_assessed';

// CERT-In points whose verdict comes from automated detection rather than the manual
// Yes/No checklist, keyed by marker (e.g. '1.4'). CERTIN_AUTOMATED_POINTS is
// CERTIN_PENDING_POINTS with the Class A markers (STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS —
// every code path in utils/certinComplianceChecks.ts resolves unconditionally to
// notAssessed(), confirmed by the 2026-09-03 live-sweep verification pass) removed: those
// rows are dropped from the rendered checklist entirely rather than rendered as
// permanently "Not Assessed", and every count/stat/snapshot derived from the automated-point
// set below is built from this filtered map so nothing still counts a removed row. This is
// a completely different, untouched category from the manual Yes/No points (operator-
// attested, never in this map at all) — the removal here must never touch those.
//
// isPendingPoint is keyed by marker rather than by `${section}|${subSection}|${pointerIndex}`
// on purpose: an index-based key breaks the moment a pointer earlier in the same section is
// filtered out of the rendered array (every later index shifts down by one), which is
// exactly what removing the Class A markers does. A marker is unique and stable regardless
// of which other rows are present, and the lookup is still an O(1) hash hit.
//
// 3.4, 3.5, 3.6, 4.2 and 5.10 are deliberately absent from CERTIN_PENDING_POINTS itself:
// they have no automated detection, and listing them here permanently stuck them on
// "Not Checked" instead of falling back to the manual checklist like every other
// unautomated guideline. 3.4 and 5.10 ask about a Government offered / CERT-In and
// NIC-CERT recommended AV-EDR product. 4.2 asks whether the entity retains the logs of
// its own ICT systems for 180 days, which Vajra does not currently measure. None of the
// three can be evidenced from the telemetry Vajra collects.
const CERTIN_AUTOMATED_POINTS: Record<string, { label: string }> = Object.fromEntries(
  Object.entries(CERTIN_PENDING_POINTS).filter(([marker]) => !STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS.has(marker)),
);

function isPendingPoint(marker: string) {
  return Object.prototype.hasOwnProperty.call(CERTIN_AUTOMATED_POINTS, marker);
}

// LEGACY_REWRITTEN_CERTIN_KEYS — the automated points whose evidentiary basis
// commit 530cdf7 ('Fixed inaccessible points for compliance', 2026-09-03) replaced
// outright, confirmed by reading utils/certinComplianceChecks.ts before and after
// that commit:
//   4.1   was answered purely from Vajra agent check-in recency ("reported
//         telemetry X hour(s) ago" -> compliant:true) — the doctrine-forbidden
//         "Vajra IS the EDR -> logging enabled" inference. Now a 12-subcategory
//         advanced audit-policy baseline read from the endpoint itself.
//   5.11  was answered from Windows Update install history — OS patch currency,
//         not antivirus signature currency; the current code's own comment calls
//         this exact old approach "fabricated". Now AV-signature-currency
//         telemetry (windows_security_products.signatures_up_to_date).
//   1.10  was "did the firewall-rules fetch return any rows" — success in
//         returning data proving compliance, no rule content ever inspected. Now
//         a lateral-movement port/scope analysis of the actual rules.
//   3.3   was "did update-history fetch return rows" — no update-source setting
//         inspected. Now reads windows_security_center.autoupdate state.
//   3.7   was "did the security-profile fetch return any rows" — no password
//         setting inspected. Now checks MIN_PASSWORD_LENGTH.
//   3.8   had inverted polarity: `usbStatus?.enabled === true` was marked
//         COMPLIANT, i.e. USB storage being ENABLED passed — the opposite of the
//         CERT-In requirement. Now storageBlocked = enabled === false.
//   1.4   went through the same failure mode on a narrower window: between
//         e490fb6 (2026-09-01) and 3418ba0 (2026-09-03 16:10) it was answered
//         with `if (checks['1.4'] === undefined) { checks['1.4'] = { compliant:
//         true, reason: 'The Vajra Agent continuously collects installed
//         software inventory ... enabling SBOM generation ...' }; }` — an
//         unconditional agent-presence fabrication, the doctrine-forbidden
//         "Vajra IS the EDR" inference applied to a control it says nothing
//         about. 178add7 (2026-09-03 12:46) still carried this fabrication
//         verbatim; 3418ba0 replaced it with the real populated>=3-fields
//         branch current code still uses. The isContractEra detector below
//         (based on the 1.12 Class A marker, removed only at 530cdf7) cannot
//         tell an e490fb6-era fabricated '1.4' row apart from a 3418ba0-era
//         genuine one — both predate 530cdf7 and both carry the marker — so
//         1.4 is included here too even though it downgrades some genuine
//         3418ba0-era rows along with the fabricated ones: a false
//         not_assessed is the safe direction to be wrong in, a false pass is
//         not.
// A row written before 530cdf7 holds a verdict for each of these that current
// code would not recognise as its own measurement — replaying it verbatim as a
// freshly-restored pass/fail (see the per-node restore effect below) resurrects a
// fabricated-fetch-succeeded pass, or an inverted-polarity verdict, under the
// current, corrected semantics. 1.12 belongs to this same rewritten set but is
// omitted here: it is also a Class A (STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS)
// marker, so it is already excluded from CERTIN_AUTOMATED_POINTS and never
// reaches the restore effect's currentPoints filter in the first place.
const LEGACY_REWRITTEN_CERTIN_KEYS: ReadonlySet<string> = new Set([
  '4.1', '5.11', '1.10', '3.3', '3.7', '3.8', '1.4',
]);

export default function NodesViewCertInCompliance({
  node,
  wsConnected = false,
  wsSendMessage,
  agentOnline = true,
}: NodesViewCertInComplianceProps) {
  const [sections, setSections] = useState<CertInSection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const hostLabel = node.hostname || node.name || `Node ${node.id}`;
  const hostId = node.host_identifier || (node.id === 0 ? ORG_LEVEL_HOST_ID : String(node.id));
  const confirm = useConfirm();

  useEffect(() => {
    let cancelled = false;
    const loadData = async () => {
      setLoading(true);
      setError(null);

      try {
        const response = await fetch(PUBLIC_JSON_PATH, { cache: 'no-store' });
        if (!response.ok) {
          throw new Error(`Failed to load CERT-In data: ${response.status}`);
        }

        const data = await response.json();
        if (!cancelled) {
          setSections(buildCertInSections(stripStructurallyUnmeasurablePoints(data)));
        }
      } catch (err) {
        console.error('[CERT-In] Failed to load checklist definition:', err);
        if (!cancelled) {
          setError('Unable to load the CERT-In checklist right now. Please refresh the page or try again in a moment.');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void loadData();
    return () => {
      cancelled = true;
    };
  }, []);

  const sectionCount = sections.length;
  const sectionTree = useMemo(() => sections, [sections]);
  const hierarchy = useMemo(() => buildHierarchy(sectionTree), [sectionTree]);
  // Manual checklist answers. A pointer that is ABSENT from this map is *unanswered* —
  // it is neither a recorded Yes nor a recorded No, and it is never persisted. Only
  // pointers the operator actually answered appear here, which keeps the stored
  // contract (a sparse yes/no map) exactly as it was.
  const [statusByPointer, setStatusByPointer] = useState<Record<string, 'yes' | 'no'>>({});
  // Snapshot of the last statusByPointer that was *confirmed* saved to (or
  // loaded from) the backend. Used to roll back optimistic checkbox edits
  // if a save fails, and as the known-good baseline the checklist starts
  // from — it must never be clobbered by a failed load.
  const [lastSavedStatusByPointer, setLastSavedStatusByPointer] = useState<Record<string, 'yes' | 'no'>>({});
  // 'partial' is fleet-only: some but not all eligible hosts satisfy the control.
  // The checklist wording is "all systems" / "all servers", so a single passing
  // host must not roll the whole organisation up to 'yes'. 'not_assessed' means
  // no host produced a measurement for the control — never a failure.
  const [pendingPointStatusByMarker, setPendingPointStatusByMarker] = useState<Record<string, 'yes' | 'no' | 'partial' | 'not_assessed'>>({});
  const [pendingFleetStatsByMarker, setPendingFleetStatsByMarker] = useState<Record<string, FleetPointStat>>({});
  const [hasRefreshed, setHasRefreshed] = useState(false);
  const [draftLoaded, setDraftLoaded] = useState(false);
  const [checklistSaveError, setChecklistSaveError] = useState(false);
  // Set only when the GET for the saved checklist fails. While this is set,
  // statusByPointer cannot be trusted to reflect the real saved checklist,
  // so draftLoaded is intentionally kept false and autosave must not run —
  // otherwise a transient network blip would silently overwrite the real
  // saved checklist with an empty one.
  const [complianceLoadError, setComplianceLoadError] = useState<string | null>(null);
  const [reloadComplianceKey, setReloadComplianceKey] = useState(0);
  const [saveComplianceError, setSaveComplianceError] = useState<string | null>(null);

  // The backend only accepts checklist writes from Super Administrator / Group
  // Admin (requireAdmin on POST /api/alerts/certin-compliance) — a Group
  // Viewer's edits would otherwise silently 403 while the checkbox still
  // looks checked, since the autosave below swallows the failure.
  const canEditChecklist = useMemo(() => {
    const role = getStoredUser()?.role;
    return role === 'Super Administrator' || role === 'Group Admin';
  }, []);

  // Editing must additionally wait for a confirmed-successful load
  // (draftLoaded) and be blocked while a load is failed (complianceLoadError)
  // — otherwise a user could "edit" a checklist that's really just the
  // empty {} left behind by a failed GET, and those edits could get synced
  // once autosave starts. The org-level aggregate view (hostId === ORG_LEVEL_HOST_ID)
  // has no real host_identifier behind it, so its manual checklist answers are
  // saved under that synthetic host_identifier, scoped per-user by the
  // backend (see ORG_LEVEL_HOST_ID in certin_compliance.ts) — same
  // load/autosave lifecycle as a real node, just no node-scope check.
  const checklistEditable = canEditChecklist && draftLoaded && !complianceLoadError;

  const [downloadLoading, setDownloadLoading] = useState(false);

  const [oneDeviceCompliance, setOneDeviceCompliance] = useState(false);

  const [orgHistory, setOrgHistory] = useState<OrgSnapshot[]>([]);
  const [orgHistoryLoading, setOrgHistoryLoading] = useState(false);

  const [historyLoading, setHistoryLoading] = useState(false);
  const [history, setHistory] = useState<ComplianceRecord[]>([]);
  const [sortBy, setSortBy] = useState<'default' | '100_compliant' | 'not_100_compliant'>('default');

  const [pointsLoading, setPointsLoading] = useState(false);

  const [onlineNodes, setOnlineNodes] = useState<number | null>(null);
  const [windowsNodes, setWindowsNodes] = useState<number | null>(null);

  const [complianceState, setComplianceState] = useState<Record<string, CompliancePoint>>({});
  const [fleetComplianceState, setFleetComplianceState] = useState<Record<string, FleetCompliancePoint>>({});
  const [noWindowsOnline, setNoWindowsOnline] = useState(false);
  // Where the numbers in the Compliance Score donut come from. A live in-session sweep
  // and a rehydrated stored snapshot both land in the same state variables, and the
  // donut used to render either one without saying which — an operator reading "0.0 %
  // Fully Compliant" could not tell whether that was this session's sweep or the last
  // saved run, and a reload silently swapped one for the other. 'live' additionally
  // means "not persisted": a successful save refetches the org history, which restores
  // this to 'stored' with the snapshot's own timestamp.
  const [scoreProvenance, setScoreProvenance] = useState<
    { kind: 'live'; sweptAt: number } | { kind: 'stored'; snapshotAt: number } | null
  >(null);
  const [, setActiveIndex] = useState(0);

  // Fetch history for trend chart
  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const res = await api.get(`${NODES_URLS.CERTIN_NODE_COMPLIANCE_HISTORY}${encodeURIComponent(hostId)}`);
      const json = res.data;
      if (json.success) setHistory(json.data ?? []);
    } catch (err: unknown) {
      if (import.meta.env.DEV) console.warn('CERT-In history fetch:', err);
    } finally {
      setHistoryLoading(false);
    }
  }, [hostId]);

  const fetchOrgHistory = useCallback(async () => {
    setOrgHistoryLoading(true);
    try {
      const res = await api.get(NODES_URLS.CERTIN_COMPLIANCE_HISTORY);
      const json = res.data;
      if (json?.success && Array.isArray(json.data)) {
        setOrgHistory(json.data as OrgSnapshot[]);
      }
    } catch {
      // silently ignore — history is supplementary
    } finally {
      setOrgHistoryLoading(false);
    }
  }, []);

  const fetchOnlineNodes = useCallback(async () => {
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
    setOnlineNodes(windowsOnline.length);
    setWindowsNodes(windowsCandidates.length);
  }, []);

  useEffect(() => {
    if (hostId === ORG_LEVEL_HOST_ID) {
      setOneDeviceCompliance(false);
      // Same proactive reset the `else` branch below applies when switching TO a
      // single node, mirrored here for switching TO the org-level view. Without
      // it, the org-restore effect's own early exit (`const latest = orgHistory?.[0];
      // if (!latest) { setPointsLoading(false); return; }`) left whatever the
      // previously viewed HOST last wrote — hasRefreshed=true plus that host's
      // per-node pendingPointStatusByMarker/pendingFleetStatsByMarker/
      // fleetComplianceState — on screen for every render before fetchOrgHistory()
      // (async) resolves, on the ordinary first visit to the org-level view, on
      // any deployment where no org snapshot has ever been saved, and on a failed
      // fetch (its catch swallows the error with no retry state). The checklist
      // table has no other gate that would catch this: `!agentOnline &&
      // oneDeviceCompliance` no longer blocks it (oneDeviceCompliance is false
      // here), and hasRefreshed=true skips the amber "Pending" placeholder, so the
      // previous host's Yes/Passed/No/Failed badges rendered under the org-level
      // layout as if they were the fleet aggregate.
      setHasRefreshed(false);
      setPendingPointStatusByMarker({});
      setPendingFleetStatsByMarker({});
      setFleetComplianceState({});
      fetchOrgHistory();
      fetchOnlineNodes();
    }
    else {
      // Reset the previous host's restored/measured state before fetching the
      // new host's history. NodesViewCertInCompliance is never remounted on a
      // host-only route-param change (neither Nodes/NodesView/index.tsx nor
      // Compliance/index.tsx pass a `key` prop keyed on the host identifier, and
      // both call sites are reached via param-routed pages React Router does not
      // remount for a param-only change), so without this the same component
      // instance — and the same hasRefreshed/pendingPointStatusByMarker/
      // passCount/failCount/notAssessedCount state — carried the PREVIOUS host's
      // Pass/Fail/Not-Assessed verdicts onto the newly selected host's screen,
      // mislabelled as belonging to it. That is silently permanent whenever the
      // new host has zero certin_compliance_results rows (24 of the 27 Windows
      // nodes on the live fleet hold none, confirmed 2026-09-03): the restore
      // effect below exits on `if (!latest ...) return;` without ever clearing
      // the leftover state, and nothing else triggers to clear it.
      setHasRefreshed(false);
      setPendingPointStatusByMarker({});
      setPassCount(0);
      setFailCount(0);
      setNotAssessedCount(0);
      fetchHistory();
      setOneDeviceCompliance(true);
    }
  }, [fetchHistory, fetchOnlineNodes, fetchOrgHistory, hostId]);

  useEffect(() => {
    setPointsLoading(true);
    if (hostId !== ORG_LEVEL_HOST_ID) {
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

    const nextPendingPointStatusByMarker: Record<
      string,
      'yes' | 'no' | 'partial' | 'not_assessed'
    > = {};

    // Restored measurements for the automated points. Without this, a "Save Compliance"
    // click after a page load (with no fresh sweep) wrote a snapshot whose control rows
    // were all zero while the headline counts came from the restored snapshot — a row
    // whose headline its own table contradicts.
    const nextFleetState: Record<string, FleetCompliancePoint> = {};

    latest.control_pass_rates.forEach((control) => {
      // Hosts on which this control was actually decided one way or the other.
      // eligibleHosts is NOT that number: rows written before this fix carry the whole
      // swept fleet as eligibleHosts while recording neither a pass nor a fail on a
      // single host (0 | 0 | 8), so restoring on `eligibleHosts > 0` turned a control
      // nothing was measured for into a red "0/8 nodes passed" fleet-wide failure.
      // Absent evidence is not-assessed; only pass + fail counts an assessed host.
      const passHosts = Number.isFinite(Number(control.passHosts)) ? Number(control.passHosts) : 0;
      const failHosts = Number.isFinite(Number(control.failHosts)) ? Number(control.failHosts) : 0;
      const eligibleHosts = Number.isFinite(Number(control.eligibleHosts)) ? Number(control.eligibleHosts) : 0;
      const assessedHosts = passHosts + failHosts;
      const unassessedHosts = Math.max(0, eligibleHosts - assessedHosts);
      // An operator attestation is an organisation-level answer, not a per-host
      // measurement, so it contributes no assessed hosts to the fleet roll-up.
      const attested = control.attested === true;

      nextStats[control.key] = {
        passed: passHosts,
        total: assessedHosts,
      };

      nextChecks[control.key] = attested
        ? {
          compliant: false,
          assessed: false,
          reason: 'Recorded as an operator attestation for the organisation, not measured on any host.',
          detail: 'Attested — not a per-host measurement',
        }
        : assessedHosts > 0
          ? {
            compliant: passHosts === assessedHosts && unassessedHosts === 0,
            reason: unassessedHosts > 0
              ? `${passHosts}/${assessedHosts} assessed nodes passed; ${unassessedHosts} node(s) produced no measurement`
              : `${passHosts}/${assessedHosts} nodes passed`,
            detail: `${((passHosts / assessedHosts) * 100).toFixed(1)}% of assessed nodes passed`,
          }
          : {
            compliant: false,
            assessed: false,
            reason: 'No host produced a measurement for this control, so it was not assessed.',
            detail: 'Not assessed — no assessed hosts',
          };

      // The checklist asks whether a control holds across "all systems"/"all
      // servers", so the org rolls up to 'yes' only when every assessed host
      // passes AND no eligible host was left unmeasured; anything short of that is
      // 'partial' or 'no'. With no assessed host at all — or with an attestation
      // standing in for one — the control is not-assessed, never a failure.
      nextPendingPointStatusByMarker[control.key] =
        attested || assessedHosts === 0
          ? 'not_assessed'
          : passHosts === assessedHosts && unassessedHosts === 0
            ? 'yes'
            : passHosts > 0
              ? 'partial'
              : 'no';

      // Only automated points carry per-host measurements; an attested or manual row
      // contributes nothing to the fleet state, and a row with no assessed host is
      // carried as 0/0 so it re-persists as not-assessed rather than as a failure.
      if (!attested && Object.prototype.hasOwnProperty.call(CERTIN_AUTOMATED_POINTS, control.key)) {
        nextFleetState[control.key] = {
          marker: control.key,
          passedNodes: passHosts,
          failedNodes: failHosts,
          totalNodes: assessedHosts,
          passRate: assessedHosts > 0 ? (passHosts / assessedHosts) * 100 : 0,
        };
      }
    });

    setFleetComplianceState(nextFleetState);

    setPendingFleetStatsByMarker(nextStats);

    setPendingPointStatusByMarker(
      nextPendingPointStatusByMarker
    );

    setHasRefreshed(true);
    setPointsLoading(false);
    // These numbers are the stored snapshot's, not this session's, and the card says so.
    setScoreProvenance({ kind: 'stored', snapshotAt: latest.snapshot_at });
    setFullyCompliantNodes(latest.fully_compliant_nodes ?? 0);

    setAverageCompliance(
      latest.avg_compliance_percent ?? 0
    );

    setTotalNodes(
      latest.windows_with_results ?? 0
    );

    // Rehydrate the evidence LISTS alongside the scalar counts. Restoring
    // fully_compliant_nodes without fully_compliant_nodes_list meant a "Save
    // Compliance" click re-persisted a fully-compliant count with an empty evidence
    // list behind it.
    setFullyCompliantNodesList(latest.fully_compliant_nodes_list ?? []);
    setNonCompliantNodesWithChecks(
      (latest.non_compliant_nodes_list ?? [])
        .map(toNonCompliantEntry)
        .filter((entry) => entry.host_identifier.length > 0)
    );
  }, [orgHistory, hostId]);

  // Per-node restore-from-history. Without this, opening a node's CERT-In tab showed
  // every automated point as "Pending" (hasRefreshed stays false until a live sweep is
  // run) even though `history` — already fetched on mount — holds a real, recent
  // recorded verdict for this exact node. SEBI and IRDAI both restore their last stored
  // per-node row on load; CERT-In never did, so it read as far more "not assessed" /
  // "Pending" than the other two frameworks for the identical situation (a node that
  // has been swept before, just not yet this browser session).
  //
  // Filtering by CERTIN_AUTOMATED_POINTS (not the raw stored keys) is required, not
  // optional: a row written before a control was reclassified Class A and dropped
  // still carries that key forever (confirmed live — stored rows include '1.12', '2.6',
  // '5.8' with real true/false values from before the exclusion existed). Restoring
  // only keys still present in CERTIN_AUTOMATED_POINTS means a removed control can
  // never resurface just because an old snapshot happens to contain it.
  useEffect(() => {
    if (hostId === ORG_LEVEL_HOST_ID) return;

    const latest = history?.[0];
    // `history` can still be the PREVIOUS host's array for one render after
    // hostId changes — fetchHistory() is async, so the hostId-keyed effect above
    // has already fired but its response has not landed yet. Requiring the row's
    // own host_identifier to match the host currently being viewed means a stale
    // array is discarded here rather than briefly (or, if the new host's fetch
    // never returns a row for it, indefinitely) rendered under the wrong host's
    // name. The hostId-keyed effect above already reset hasRefreshed/
    // pendingPointStatusByMarker/passCount/failCount/notAssessedCount to empty
    // before this can fire, so returning here simply leaves that reset in place
    // rather than restoring anything.
    if (!latest || latest.host_identifier !== hostId) return;

    // A row is "contract-era" (written by the current staticComplianceChecks,
    // i.e. after commit 530cdf7 rewrote the evidentiary basis of most automated
    // points) only if it does NOT carry a Class A (STRUCTURALLY_UNMEASURABLE_
    // CERTIN_KEYS) marker. Current code strips those markers before persisting
    // (see the STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS.forEach(delete ...)
    // boundary filter at the end of staticComplianceChecks), so a row that still
    // carries one is structural proof it predates that filter — confirmed live:
    // every row currently in certin_compliance_results carries '1.12', '2.6' and
    // '5.8', all hardcoded 'true', and a fresh sweep under current code can never
    // write them again. This is the same detection SEBI's isContractEra already
    // uses for the identical problem.
    const isContractEra = !latest.compliance_data.some((row) =>
      STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS.has(row.command_key)
    );

    const currentPoints = latest.compliance_data.filter((row) =>
      Object.prototype.hasOwnProperty.call(CERTIN_AUTOMATED_POINTS, row.command_key)
    );

    const nextPointStatusByMarker: Record<string, 'yes' | 'no' | 'partial' | 'not_assessed'> = {};
    let pass = 0;
    let fail = 0;
    let unassessed = 0;

    currentPoints.forEach((row) => {
      // LEGACY_REWRITTEN_CERTIN_KEYS (4.1, 5.11, 1.10, 3.3, 3.7, 3.8) had their
      // evidentiary basis replaced outright by 530cdf7 — see that constant's
      // comment for what each one used to fabricate. A legacy row's stored
      // verdict for one of these is not a measurement current code would
      // recognise as its own, so on a legacy row it is reported not-assessed
      // rather than replayed as a freshly-restored pass/fail. Every other
      // automated point's evidentiary basis is unchanged since 530cdf7, and a
      // contract-era row was never affected here in the first place, so both
      // restore normally.
      if (!isContractEra && LEGACY_REWRITTEN_CERTIN_KEYS.has(row.command_key)) {
        nextPointStatusByMarker[row.command_key] = 'not_assessed';
        unassessed += 1;
        return;
      }

      if (row.output === 'true') {
        nextPointStatusByMarker[row.command_key] = 'yes';
        pass += 1;
      } else if (row.output === 'false') {
        nextPointStatusByMarker[row.command_key] = 'no';
        fail += 1;
      } else {
        nextPointStatusByMarker[row.command_key] = 'not_assessed';
        unassessed += 1;
      }
    });

    setPendingPointStatusByMarker((prev) => ({ ...prev, ...nextPointStatusByMarker }));
    setPassCount(pass);
    setFailCount(fail);
    setNotAssessedCount(unassessed);
    setHasRefreshed(true);
    setPointsLoading(false);
  }, [history, hostId]);

  const [passCount, setPassCount] = useState(0);
  const [failCount, setFailCount] = useState(0);
  // Controls Vajra did not measure on this node. Counted and shown on its own,
  // and kept out of both sides of the per-node score.
  const [notAssessedCount, setNotAssessedCount] = useState(0);

  // Records, or clears, the manual answer for one pointer. `answer === null` deletes
  // the key entirely, returning the guideline to "Not answered" — an unanswered
  // control must never be persisted or displayed as a recorded No. The no-op
  // `return prev` branches preserve reference equality so an idempotent click cannot
  // re-arm the autosave debounce.
  const setPointerAnswer = useCallback((pointer: CertInPointer, answer: 'yes' | 'no' | null) => {
    setStatusByPointer((prev) => {
      if (answer === null) {
        if (!(pointer.id in prev)) return prev;
        const next = { ...prev };
        delete next[pointer.id];
        return next;
      }
      if (prev[pointer.id] === answer) return prev;
      return { ...prev, [pointer.id]: answer };
    });
    setComplianceState((prev) => ({
      ...prev,
      [pointer.marker]: {
        marker: pointer.marker,
        // Clearing an answer is 'not_assessed', never 'no': buildFleetSnapshot reads
        // this map, and 'not_assessed' is the value that keeps the control out of both
        // sides of the org pass rate.
        status: answer ?? 'not_assessed',
        source: 'manual',
      },
    }));
  }, []);

  const handleOneDeviceCompliance = useCallback(async () => {
    try {
      setError?.(null);
      setHasRefreshed(true);
      setPointsLoading(true);

      const checks = await staticComplianceChecks(
        hostId,
        node,
        wsConnected,
        wsSendMessage
      );

      let pass = 0;
      let fail = 0;
      let unassessed = 0;

      const nextPointStatusByMarker: Record<
        string,
        'yes' | 'no' | 'partial' | 'not_assessed'
      > = {};

      Object.keys(CERTIN_AUTOMATED_POINTS).forEach((marker) => {
        const result = checks[marker];

        // No result, or a result explicitly marked unmeasured, is not a
        // failure: it is counted separately and excluded from the score.
        if (!result || result.assessed === false) {
          unassessed += 1;
          nextPointStatusByMarker[marker] = 'not_assessed';
          return;
        }

        if (result.compliant) {
          pass += 1;
          nextPointStatusByMarker[marker] = 'yes';
        } else {
          fail += 1;
          nextPointStatusByMarker[marker] = 'no';
        }
      });

      setPassCount(pass);
      setFailCount(fail);
      setNotAssessedCount(unassessed);

      debugLog('[CERT-In] one-device compliance', {
        hostId,
        pass,
        fail,
        notAssessed: unassessed,
        assessedTotal: pass + fail,
      });

      debugLog('[CERT-In] checks', checks);

      // only if you still use this state elsewhere
      setPointsLoading(false);
      setPendingPointStatusByMarker?.(nextPointStatusByMarker);

      setComplianceState(prev => {
        const next = { ...prev };

        Object.entries(checks).forEach(([marker, result]) => {
          next[marker] = {
            marker,
            status: !result || result.assessed === false
              ? "not_assessed"
              : result.compliant ? "yes" : "no",
            source: "automatic"
          };
        });

        return next;
      });

      // Three-value contract: a control Vajra did not measure is persisted as
      // 'not_assessed' so no reader can score it as a pass or a failure.
      const complianceData = Object.entries(checks).map(([command_key, result]) => ({
        command_key,
        output: !result || result.assessed === false
          ? NOT_ASSESSED
          : (result.compliant ? 'true' : 'false'),
      }));

      try {
        await fetchWithCsrf(`${NODES_URLS.CERTIN_NODE_COMPLIANCE_SNAPSHOT}${encodeURIComponent(hostId)}`, {
          method: 'POST',
          credentials: 'include',
          headers: csrfHeadersJson(),
          body: JSON.stringify({
            hostIdentifier: hostId,
            unixtime: Math.floor(Date.now() / 1000),
            complianceData,
          }),
        });

        // Refresh latest/history after saving
        void fetchHistory();
      } catch (err) {
        console.error('[CERT-In] Failed to save compliance snapshot:', err);
      }

    } catch (err) {
      console.error(
        '[CERT-In] Failed to calculate compliance:',
        err
      );

      setError?.(
        err instanceof Error
          ? err.message
          : 'Failed to run compliance.'
      );
    }
  }, [
    fetchHistory,
    hostId,
    node,
    wsConnected,
    wsSendMessage,
  ]);

  useEffect(() => {
    // hostId === ORG_LEVEL_HOST_ID is the org-level aggregate view — its
    // manual checklist answers are saved under that synthetic
    // host_identifier (see ORG_LEVEL_HOST_ID in the backend controller),
    // scoped per-user rather than to a real node, so it still needs a real
    // load here just like a single node does.
    let cancelled = false;
    // Reset per-load state whenever we (re)start a load for this host, so a
    // stale error from a previous host/attempt doesn't linger, and so
    // draftLoaded stays false (blocking autosave) until this load either
    // succeeds or fails.
    setDraftLoaded(false);
    setComplianceLoadError(null);

    const loadCompliance = async () => {
      try {
        const { data } = await getCertinCompliance(hostId);
        if (cancelled) return;
        const dbStatus = data?.compliance?.statusByPointer;
        const normalized: Record<string, 'yes' | 'no'> =
          dbStatus && typeof dbStatus === 'object' ? (dbStatus as Record<string, 'yes' | 'no'>) : {};
        setStatusByPointer(normalized);
        setLastSavedStatusByPointer(normalized);
        setComplianceLoadError(null);
        setDraftLoaded(true);
      } catch (err) {
        if (cancelled) return;
        console.error('[CERT-In] Failed to load saved compliance checklist:', err);
        setComplianceLoadError(
          err instanceof Error ? err.message : 'Failed to load the saved CERT-In checklist.'
        );
        // Important: do not setDraftLoaded(true) here. statusByPointer is
        // still {} (or stale) at this point — if we flipped draftLoaded to
        // true on failure, the autosave effect below would fire ~500ms
        // later and POST that empty/stale state, silently overwriting the
        // real saved checklist. Leaving draftLoaded false keeps autosave
        // from ever running until a load actually succeeds.
      }
    };

    void loadCompliance();
    return () => {
      cancelled = true;
    };
  }, [hostId, reloadComplianceKey]);

  // Ref mirror of lastSavedStatusByPointer. The autosave effect below reads the
  // baseline from here instead of listing it as a dependency: as a dependency, the
  // setLastSavedStatusByPointer that follows every successful save re-armed the
  // debounce and produced a second POST — and a second audit-trail record — for every
  // single edit. Declared before the autosave effect so it is refreshed first within a
  // commit.
  const lastSavedStatusRef = useRef(lastSavedStatusByPointer);
  useEffect(() => {
    lastSavedStatusRef.current = lastSavedStatusByPointer;
  }, [lastSavedStatusByPointer]);

  useEffect(() => {
    // Autosave may only run once a load has *confirmed success*
    // (draftLoaded) and must never run while the last load failed
    // (complianceLoadError) — otherwise a failed GET followed by this
    // effect would save empty/stale data over the real saved checklist.
    // This applies the same way to the org-level aggregate view
    // (hostId === ORG_LEVEL_HOST_ID), which now loads/saves for real under
    // that synthetic host_identifier (see the load effect above).
    if (!draftLoaded || !canEditChecklist || complianceLoadError) return;
    // Nothing changed since the last confirmed write, so there is nothing to save.
    // The load effect points statusByPointer and lastSavedStatusByPointer at the same
    // object, and a successful save re-points the baseline at the exact object it
    // persisted, so reference equality here means "no edit". Without this guard a
    // successful load alone scheduled a POST, writing a compliance-evidence row and an
    // audit-trail record on every page view.
    if (statusByPointer === lastSavedStatusRef.current) return;
    const timeout = window.setTimeout(() => {
      // Re-checked at fire time: an explicit save (e.g. the clear-checklist path) may
      // have caught up with this pending debounce in the meantime.
      if (statusByPointer === lastSavedStatusRef.current) return;
      const pending = statusByPointer;
      saveCertinCompliance(hostId, pending)
        .then(() => {
          setChecklistSaveError(false);
          setLastSavedStatusByPointer(pending);
        })
        .catch(() => {
          setChecklistSaveError(true);
          // Roll the optimistic UI back to the last value we know was
          // actually persisted, instead of leaving checkboxes showing
          // edits that never made it to the server.
          setStatusByPointer(lastSavedStatusRef.current);
        });
    }, 500);
    return () => window.clearTimeout(timeout);
  }, [hostId, statusByPointer, draftLoaded, canEditChecklist, complianceLoadError]);

  // Download Functionality for CERT-In compliance data

  const handleDownloadVajraCompliance = useCallback(async () => {
    if (downloadLoading) return;

    setDownloadLoading(true);
    try {
      const downloadUrl = `${API_BASE_URL}/api/compliance/reports/certin-pdf`;
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
      const now = new Date();
      const pad = (n: number) => String(n).padStart(2, '0');
      const dateStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
      link.download = `vajra-certin-compliance-${hostId}-${dateStr}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(objectUrl);
    } catch (error) {
      console.error('Failed to download Vajra Compliance PDF', error);
    } finally {
      setDownloadLoading(false);
    }
  }, [downloadLoading, hostId]);

  const [averageCompliance, setAverageCompliance] = useState(0);

  const [totalNodes, setTotalNodes] = useState(0);
  const [fullyCompliantNodes, setFullyCompliantNodes] = useState(0);
  const [fullyCompliantNodesList, setFullyCompliantNodesList] = useState<string[]>([]);
  // failed_checks is optional on purpose: entries rehydrated from a legacy snapshot row
  // (bare host identifier strings) have no recorded failure list, and it must stay
  // absent so the report renders "score not recorded" rather than "failed nothing".
  const [nonCompliantNodesWithChecks, setNonCompliantNodesWithChecks] = useState<Array<{ host_identifier: string; failed_checks?: string[] }>>([]);
  // Number of hosts the last sweep in this session actually targeted. null until a
  // sweep runs — it is not rehydrated from a stored row, because rows written before
  // the field-order fix below hold a different quantity under windows_hosts.
  const [sweptHostCount, setSweptHostCount] = useState<number | null>(null);
  const [savingCompliance, setSavingCompliance] = useState(false);

  const handleRefresh = async () => {
    try {
      setError(null);
      setHasRefreshed(true);
      setPointsLoading(true);
      setNoWindowsOnline(false);
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

      setWindowsNodes(windowsCandidates.length);
      setOnlineNodes(windowsOnline.length);

      debugLog('[CERT-In] Windows candidates:', windowsCandidates.map((n) => ({
        id: n?.id,
        host_identifier: n?.host_identifier,
        hostname: n?.hostname,
        os_name: n?.os_name,
        os_platform: n?.os_platform,
        agent_online: n?.agent_online,
        status: n?.status,
        displayStatus: n?.displayStatus,
      })));

      debugLog('[CERT-In] Online Windows nodes:', windowsOnline.map((n) => ({
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

      setSweptHostCount(hostIds.length);

      if (hostIds.length === 0) {
        setPointsLoading(false);
        setNoWindowsOnline(true);
        // throw new Error('No Windows nodes found to run CERT-In compliance.');
      }

      let successCount = 0;
      let failureCount = 0;
      let cumulativeNodePercent = 0;
      let processedNodes = 0;
      let fullyCompliantCount = 0;

      const resultLines: string[] = [];
      const localFullyCompliantNodesList: string[] = [];
      const localNonCompliantNodesWithChecks: Array<{ host_identifier: string; failed_checks: string[] }> = [];
      const nextPendingFleetStatsByMarker: Record<string, FleetPointStat> = Object.keys(CERTIN_AUTOMATED_POINTS).reduce<Record<string, FleetPointStat>>((acc, marker) => {
        acc[marker] = { passed: 0, total: 0 };
        return acc;
      }, {});

      for (const id of hostIds) {
        try {
          const targetNode = windowsOnline.find((n) => String(n?.host_identifier ?? n?.id ?? '').trim() === id) as NodeData | undefined;
          if (!targetNode) {
            failureCount += 1;
            resultLines.push(`${id}: skipped (missing candidate)`);
            debugLog(`[CERT-In] ${id} skipped because it was not found in the Windows online list`);
            continue;
          }

          const checks = await staticComplianceChecks(id, targetNode, wsConnected, wsSendMessage);

          // Only controls that were actually measured on this host count
          // towards its score — unmeasured ones are excluded from both the
          // numerator and the denominator.
          const assessedResults = Object.values(checks)
            .filter((c): c is StaticCheckResult => c != null && c.assessed !== false);

          const pass = assessedResults.filter((c) => c.compliant).length;

          const total = assessedResults.length;

          if (total === 0) {
            // Nothing was measured on this host, so it is neither fully
            // compliant nor non-compliant — it stays out of both lists.
          } else if (pass === total) {
            fullyCompliantCount += 1;
            localFullyCompliantNodesList.push(id);
          } else {
            const failedChecks = Object.entries(checks)
              .filter(([, v]) => v != null && v.assessed !== false && !v.compliant)
              .map(([k]) => k);
            localNonCompliantNodesWithChecks.push({ host_identifier: id, failed_checks: failedChecks });
          }

          // A host with nothing measured has no percentage to contribute; averaging
          // it in as 0% would report unmeasured as fully non-compliant.
          if (total > 0) {
            cumulativeNodePercent += (pass / total) * 100;
            processedNodes++;
          }

          Object.keys(CERTIN_AUTOMATED_POINTS).forEach((marker) => {
            const result = checks[marker];
            if (!result || result.assessed === false) return;
            nextPendingFleetStatsByMarker[marker].total += 1;
            if (result.compliant) {
              nextPendingFleetStatsByMarker[marker].passed += 1;
            }
          });

          const trueChecks = Object.entries(CERTIN_AUTOMATED_POINTS).reduce<Record<string, { label: string; compliant: boolean }>>((acc, [marker, meta]) => {
            const result = checks[marker];
            if (result?.compliant === true && result.assessed !== false) {
              acc[marker] = { label: meta.label, compliant: true };
            }
            return acc;
          }, {});

          debugLog('[CERT-In] pending-point true checks', {
            hostId: id,
            hostname: String(targetNode.hostname ?? targetNode.name ?? ''),
            trueChecks,
          });

          successCount += 1;
          resultLines.push(`${id}: success`);
          debugLog(`[CERT-In] ${id} success`);
        } catch (err) {
          failureCount += 1;
          resultLines.push(`${id}: failed`);
          console.error(`[CERT-In] Failed to run compliance checks on node ${id}:`, err);
        }
      }

      debugLog('[CERT-In] fleet refresh summary', {
        successCount,
        failureCount,
        total: hostIds.length,
        resultLines,
      });

      const nextPendingPointStatusByMarker: Record<string, 'yes' | 'no' | 'partial' | 'not_assessed'> = {};
      Object.entries(nextPendingFleetStatsByMarker).forEach(([marker, stat]) => {
        // "all systems"/"all servers": the control is only satisfied for the
        // organisation when every assessed host passes it, not when one does.
        // stat.total counts assessed hosts only, so a control no host measured
        // rolls up to not-assessed rather than to a failure.
        nextPendingPointStatusByMarker[marker] = stat.total > 0
          ? (stat.passed === stat.total ? 'yes' : stat.passed > 0 ? 'partial' : 'no')
          : 'not_assessed';
      });

      setPendingPointStatusByMarker(nextPendingPointStatusByMarker);
      setPendingFleetStatsByMarker(nextPendingFleetStatsByMarker);
      const averageNodeCompliance =
        processedNodes > 0
          ? cumulativeNodePercent / processedNodes
          : 0;

      setAverageCompliance(averageNodeCompliance);

      // Denominator for the fleet node score: hosts that actually produced at
      // least one measured control. A host whose run failed, or on which nothing
      // could be measured, is not evidence of a non-compliant node and so stays
      // out of both sides of the ratio.
      setTotalNodes(processedNodes);

      setFullyCompliantNodes(fullyCompliantCount);
      setFullyCompliantNodesList(localFullyCompliantNodesList);
      setNonCompliantNodesWithChecks(localNonCompliantNodesWithChecks);
      const nextFleetState: Record<string, FleetCompliancePoint> = {};

      Object.entries(nextPendingFleetStatsByMarker).forEach(
        ([marker, stat]) => {
          nextFleetState[marker] = {
            marker,

            passedNodes: stat.passed,
            failedNodes: stat.total - stat.passed,

            totalNodes: stat.total,

            passRate:
              stat.total > 0
                ? (stat.passed / stat.total) * 100
                : 0,
          };
        }
      );

      setFleetComplianceState(nextFleetState);

      // The score on screen is now this session's sweep and nothing has been persisted
      // yet, so the card is labelled live and unsaved until "Save Compliance" succeeds.
      setScoreProvenance({ kind: 'live', sweptAt: Math.floor(Date.now() / 1000) });

      setPointsLoading(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to refresh CERT-In compliance.');
    }
  };

  const handleClearChecklist = async () => {
    // Refuse to reset/save on top of a checklist we haven't confirmed a
    // successful load for — same reasoning as the autosave guard: we must
    // never overwrite the real saved checklist with defaults derived from
    // an unknown/failed-load state. Applies the same way to the org-level
    // aggregate view (hostId === ORG_LEVEL_HOST_ID), which loads/saves for
    // real under that synthetic host_identifier.
    if (!draftLoaded || complianceLoadError) return;
    const confirmed = await confirm({
      title: 'Clear all checklist answers?',
      description: 'This removes every recorded Yes/No answer for this host and returns each CERT-In guideline to "Not answered". This cannot be undone.',
      confirmLabel: 'Clear',
      variant: 'danger',
    });
    if (!confirmed) return;
    // The default state of a guideline is *unanswered*, not "No" — stamping every
    // pointer with 'no' recorded a compliance failure for every control nobody had
    // assessed. resetCertinCompliance already empties the stored map server-side, so
    // clearing is the whole operation; no follow-up write is needed.
    const previous = statusByPointer;
    const cleared: Record<string, 'yes' | 'no'> = {};
    setStatusByPointer(cleared);
    try {
      await resetCertinCompliance(hostId);
      setChecklistSaveError(false);
      setLastSavedStatusByPointer(cleared);
    } catch (err) {
      console.error('[CERT-In] Failed to clear the checklist:', err);
      // Surface the same "Not saved" signal the debounced autosave uses, and roll the
      // optimistic empty UI back — otherwise the checklist would silently show every
      // guideline unanswered while the server still holds the previous answers.
      setChecklistSaveError(true);
      setStatusByPointer(previous);
    }
  };

  // Assessed controls only — not-assessed is excluded from both the numerator
  // and the denominator of the per-node score and reported on its own tile.
  const totalChecks = passCount + failCount;

  const pieData =
    totalChecks > 0
      ? [
        { name: 'Pass', value: passCount },
        { name: 'Fail', value: failCount },
      ]
      : [];

  // totalNodes/fullyCompliantNodes only populate once "Fetch Endpoint Data"
  // has been clicked this session — before that they're 0, even though a
  // saved snapshot (orgHistory[0]) already has the last known compliance
  // numbers. Fall back to that snapshot so the donut reflects the last
  // compliance run instead of sitting empty until a fresh fetch is run.
  const orgLatestSnapshot = orgHistory?.[0];
  // Driven by provenance rather than by `totalNodes > 0`: a live sweep on which no host
  // produced a measurement leaves totalNodes at 0, and the old test then quietly fell
  // back to the stored snapshot's numbers while the card still read as this session's
  // run. A live run with nothing measured now shows no score at all, which is what it is.
  const scoreIsLive = scoreProvenance?.kind === 'live';
  const chartTotalNodes = scoreIsLive ? totalNodes : (orgLatestSnapshot?.windows_with_results ?? 0);
  const chartFullyCompliantNodes = scoreIsLive ? fullyCompliantNodes : (orgLatestSnapshot?.fully_compliant_nodes ?? 0);

  // Whether the latest STORED org snapshot's fully_compliant_nodes scalar agrees with the
  // length of its own fully_compliant_nodes_list. A fresh sweep (handleRefresh) always builds
  // fullyCompliantCount and localFullyCompliantNodesList off the identical per-host loop, so a
  // live run's own pair can never disagree — this only guards the restored/stored path.
  // reports.ts's PDF generator already refuses to trust this exact mismatch for Section D
  // (node_inventory_unavailable_reason = 'snapshot_list_empty_unreconciled'); this is that same
  // reconciliation check, applied here to the org tile and to what "Save Compliance" is allowed
  // to re-persist. Confirmed live: certin_historical_compliance id=24 (today's latest row)
  // carries fully_compliant_nodes=6 against an EMPTY fully_compliant_nodes_list, with
  // control_pass_rates showing 0/0/8 pass/fail/eligible on every key — impossible if 6/8 hosts
  // genuinely passed every control. 11 of the 24 stored rows carry this same mismatch, the
  // signature of a "restore a stored row into state, then Save without a fresh sweep" loop:
  // without this guard, an unreconciled restore re-persists the same fabricated pair as a new
  // row indefinitely.
  const orgSnapshotListReconciles = orgLatestSnapshot == null
    || Number(orgLatestSnapshot.fully_compliant_nodes ?? 0) === (orgLatestSnapshot.fully_compliant_nodes_list ?? []).length;

  // One line stating exactly which run the donut is drawn from, so a live figure and a
  // stored one are never indistinguishable in the same place.
  const scoreProvenanceText = scoreProvenance == null
    ? 'No sweep run this session and no saved snapshot — nothing to score.'
    : scoreProvenance.kind === 'live'
      ? `Live sweep, ${fmtDateTime(scoreProvenance.sweptAt)} — not saved`
      : `Saved snapshot, ${fmtDateTime(scoreProvenance.snapshotAt)}`;

  // How much of the Windows fleet the score actually covers. The percentage is over the
  // hosts that answered, not over the fleet, and stating only the percentage let a score
  // covering a third of the estate read as an estate-wide figure. Snapshots written
  // before the writer's field order was corrected do not record the fleet size
  // consistently, so the denominator is printed only where the stored row can support it.
  const snapshotFleetSize = Number(orgLatestSnapshot?.total_nodes);
  const scoreCoverageText = scoreIsLive
    ? (windowsNodes != null && windowsNodes > 0
      ? `${chartTotalNodes} of ${windowsNodes} Windows hosts produced a measurement`
      : `${chartTotalNodes} hosts produced a measurement`)
    : (Number.isFinite(snapshotFleetSize) && snapshotFleetSize >= chartTotalNodes
      ? `${chartTotalNodes} of ${snapshotFleetSize} Windows hosts recorded in that snapshot`
      : `${chartTotalNodes} hosts recorded in that snapshot; the fleet size it covered was not recorded`);

  const fullyCompliantChartData =
    chartTotalNodes > 0 ? [
      {
        name: 'Fully Compliant',
        value: Number(((chartFullyCompliantNodes / chartTotalNodes) * 100).toFixed(2)),
      },
      {
        name: 'Not Fully Compliant',
        value: 100 - Number(((chartFullyCompliantNodes / chartTotalNodes) * 100).toFixed(2)),
      },
    ] : [];


  const CERTIN_KEYS = Object.keys(CERTIN_AUTOMATED_POINTS);

  const chartData = [...history].reverse().map((rec) => {
    const certinData = rec.compliance_data.filter((r) =>
      CERTIN_KEYS.includes(r.command_key)
    );

    const passed = certinData.filter(
      (r) => r.output === "true"
    ).length;

    // Only measured verdicts are scored. Legacy snapshots hold only
    // 'true'/'false', so their percentages are unchanged.
    const total = certinData.filter(
      (r) => r.output === "true" || r.output === "false"
    ).length;

    return {
      label: fmtDate(rec.unixtime),
      tooltip: fmtDateTime(rec.unixtime),
      percent: total > 0 ? (passed / total) * 100 : 0,
      passed,
      total,
    };
  });

  const chartOrgData = [...orgHistory]
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
    }));

  const buildFleetSnapshot = () => {
    const pendingMarkers = new Set(
      Object.keys(CERTIN_AUTOMATED_POINTS)
    );

    const allMarkers = new Set<string>([
      ...Object.keys(complianceState),
      ...Object.keys(CERTIN_AUTOMATED_POINTS),
    ]);

    const controlPassRates = Array.from(allMarkers).map(
      (marker) => {
        // Pending points use live fleet refresh data
        if (pendingMarkers.has(marker)) {
          const fleetPoint =
            fleetComplianceState[marker];

          const passed =
            fleetPoint?.passedNodes ?? 0;

          const failed =
            fleetPoint?.failedNodes ?? 0;

          // Assessed hosts for THIS control, never the fleet-wide host count.
          // fleetPoint.totalNodes is already the number of hosts that produced a
          // measurement for this marker (see handleRefresh, where it is stat.total).
          // Falling back to `totalNodes` put every host that was never assessed for
          // this control into its denominator, which is what wrote the stored
          // 0 | 0 | 8 rows that then read as "0/8 nodes passed".
          const total =
            fleetPoint?.totalNodes ?? 0;

          return {
            key: marker,
            label:
              CERTIN_AUTOMATED_POINTS[marker]
                ?.label ?? marker,

            // null = no host was assessed for this control. Reporting 0% would
            // read as "every host failed" for something never measured.
            passRatePct:
              total > 0
                ? (passed / total) * 100
                : null,

            passHosts: passed,
            failHosts: failed,
            eligibleHosts: total,
          };
        }

        // Manual/non-pending points use complianceState. These are the guidelines
        // Vajra has no automated check for, so the only answer behind them is an
        // operator's organisation-level Yes/No on the checklist.
        const status =
          complianceState[marker]?.status;

        // An attestation is NOT a per-host measurement, and must never be expanded
        // into one: `passed = status === 'yes' ? totalNodes : 0` turned a single
        // checklist tick into "8/8 nodes passed" on controls no probe exists for
        // (3.4 and 5.10 name a specific Government/CERT-In-recommended AV product;
        // 4.2 is the entity's own 180-day log retention). Every manual point is
        // therefore written with zero host counts and no pass rate, flagged
        // `attested` so the report renders it as an attestation rather than as a
        // measured result. `not_assessed` — an unanswered guideline — is written the
        // same way but without the flag, so it reads as neither.
        return {
          key: marker,
          label: marker,
          passRatePct: null,
          passHosts: 0,
          failHosts: 0,
          eligibleHosts: 0,
          ...(status === 'yes' || status === 'no' ? { attested: true } : {}),
        };
      }
    );

    let strongCount = 0;
    let moderateCount = 0;
    let needsAttentionCount = 0;

    controlPassRates.forEach((point) => {
      // A control no host was assessed for belongs in none of the three
      // buckets — counting it as 0% would file it under "needs attention".
      if (point.passRatePct === null) return;
      const pct = point.passRatePct;

      if (pct >= 80) {
        strongCount++;
      } else if (pct >= 50) {
        moderateCount++;
      } else {
        needsAttentionCount++;
      }
    });

    return {
      snapshotAt: Math.floor(Date.now() / 1000),

      // These three had been assigned in the wrong order, which is why stored CERT-In
      // rows carry windows_hosts > total_nodes. They now match every other framework's
      // snapshot (cf. NodesViewSebiHotCompliance.tsx): total_nodes is the fleet-wide
      // Windows candidate count, windows_hosts the hosts this sweep targeted, and
      // windows_with_results the hosts that actually produced a measurement (the
      // `totalNodes` state variable, despite its name). Existing rows keep their
      // current meaning and are not rewritten.
      totalNodes: windowsNodes,

      windowsHosts: sweptHostCount,

      windowsWithResults: totalNodes,

      fullyCompliantNodes,

      avgCompliancePercent: averageCompliance,

      strongCount,

      moderateCount,

      needsAttentionCount,

      controlPassRates,

      source: 'live',

      fullyCompliantNodesList,
      // The report can only score a stored non-compliant host when its failed_checks array is
      // present, so the rich entries go over the wire instead of bare identifiers. Legacy rows
      // that hold bare strings are still read by the backend's toHostIdentifier helper.
      nonCompliantNodesList: nonCompliantNodesWithChecks,
    };
  };

  const handleSaveOrgCompliance = async () => {
    if (savingCompliance) return;
    // `totalNodes` here is the count of hosts that produced a measurement, and it stays
    // 0 until a sweep (or a rehydrated snapshot) fills it in. Posting anyway stored an
    // all-zero row that the trend chart then plotted as 0% compliance — a fabricated
    // fleet-wide failure. The button is disabled in this state too; this guard covers
    // the programmatic path.
    if (totalNodes <= 0) {
      setSaveComplianceError('Nothing assessed yet — run "Fetch Endpoint Data" first.');
      return;
    }
    // `fullyCompliantNodes`/`fullyCompliantNodesList` below come straight from state, and on
    // the restored (non-live) path that state was copied through from the stored snapshot with
    // no reconciliation — see orgSnapshotListReconciles above. Saving on top of an unreconciled
    // restore would re-persist the same fabricated pair as a new row. The button is disabled in
    // this state too; this guard covers the programmatic path.
    if (!scoreIsLive && !orgSnapshotListReconciles) {
      setSaveComplianceError('Saved snapshot\'s compliant-node count does not match its own evidence list — run "Fetch Endpoint Data" for a fresh sweep before saving.');
      return;
    }
    setSavingCompliance(true);
    try {
      const payload = buildFleetSnapshot();

      const res = await fetchWithCsrf(
        NODES_URLS.CERTIN_COMPLIANCE_SNAPSHOT,
        {
          method: 'POST',
          credentials: 'include',
          headers: csrfHeadersJson(),
          body: JSON.stringify(payload),
        }
      );

      if (!res.ok) {
        console.error(`[CERT-In] Fleet compliance snapshot save failed: HTTP ${res.status}`);
        setSaveComplianceError('Save failed — check your permissions and try again');
        return;
      }

      debugLog(
        '[CERT-In] Fleet compliance snapshot saved'
      );
      setSaveComplianceError(null);

      await fetchOrgHistory();
    } catch (err) {
      console.error(
        '[CERT-In] Failed to save fleet snapshot',
        err
      );
      setSaveComplianceError('Save failed — check your permissions and try again');
    } finally {
      setSavingCompliance(false);
    }
  };

  const latestSnapshot = orgHistory?.[0];

  const lastRunText = latestSnapshot
    ? fmtDateTime(latestSnapshot.snapshot_at)
    : 'Never';

  const latestNodeSnapshot = history?.[0];

  const lastNodeRunText = latestNodeSnapshot
    ? fmtDateTime(latestNodeSnapshot.unixtime)
    : 'Never';

  return (
    <div className="px-4 pb-4 space-y-4">
      {/* CERT-In Toolbar */}
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-3 shadow-sm">
        <div className="flex flex-wrap items-center gap-5 w-full">
          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
              <span className="text-xs font-semibold text-slate-500">Sections:</span>
              <span className="text-sm font-semibold text-slate-800">{sectionCount} sections</span>
            </div>
            {!oneDeviceCompliance && (
              <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500" aria-hidden="true" />
                <span className="text-xs font-semibold text-slate-500">Nodes Online:</span>
                <span className="text-sm font-semibold text-slate-800 tabular-nums">{onlineNodes}/{windowsNodes}</span>
              </div>
            )}
            {oneDeviceCompliance && (
              <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                <span className="text-xs font-semibold text-slate-500">Last Compliance Run:</span>
                <span className="text-sm font-semibold text-slate-800">{lastNodeRunText}</span>
              </div>
            )}
            {oneDeviceCompliance && (
              <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                <span className="text-xs font-semibold text-slate-500">Device Name:</span>
                <span className="text-sm font-semibold text-slate-800">{hostLabel}</span>
              </div>
            )}
            {!oneDeviceCompliance && (
              <div className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
                <span className="text-xs font-semibold text-slate-500">Last Compliance Run:</span>
                <span className="text-sm font-semibold text-slate-800">{lastRunText}</span>
              </div>
            )}
          </div>

          <div className="ml-auto flex flex-wrap items-center gap-2">
            {!oneDeviceCompliance && (
              <>
                <button
                  type="button"
                  onClick={handleRefresh}
                  disabled={pointsLoading}
                  className="inline-flex items-center gap-2 rounded-lg bg-[rgb(4,34,119)] px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-[rgb(10,50,150)] disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {pointsLoading
                    ? <DuoSpinner size="xs" className="text-white" />
                    : <i className="fa fa-people-arrows text-xs text-blue-200" />}
                  {pointsLoading ? 'Fetching…' : 'Fetch Endpoint Data'}
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
                className="inline-flex items-center gap-2 rounded-lg bg-[rgb(4,34,119)] px-4 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-[rgb(10,50,150)] disabled:opacity-60 disabled:cursor-not-allowed"
              >
                <i className="fa fa-rotate-right text-xs text-blue-200" />
                Refresh CERT-In Compliance
              </button>
            )}
          </div>
        </div>
      </div>

      {complianceLoadError && (
        <div className="flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 mb-4" role="alert">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-red-600" aria-hidden />
          <div className="flex-1 min-w-0">
            <p className="font-semibold text-red-900">Couldn't load the saved CERT-In checklist</p>
            <p className="mt-1 text-red-700/90">
              {complianceLoadError} Editing and autosave are disabled until this loads successfully, so your
              previously saved checklist isn't overwritten.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setReloadComplianceKey((k) => k + 1)}
            className="shrink-0 inline-flex items-center gap-1.5 rounded-full bg-red-600 px-3 py-1 text-xs font-semibold text-white hover:bg-red-700"
          >
            <i className="fa fa-rotate-right text-[10px]" />
            Retry
          </button>
        </div>
      )}

      {checklistSaveError && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800 mb-4" role="alert">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-rose-600" aria-hidden />
          <div className="flex-1 min-w-0">
            <p className="font-semibold text-rose-900">Checklist answer not saved</p>
            <p className="mt-1 text-rose-700/90">
              Your last checklist change could not be saved — check your permissions and try again. The answers shown
              below have been rolled back to the last ones the server confirmed.
            </p>
          </div>
        </div>
      )}

      {!oneDeviceCompliance && saveComplianceError && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800 mb-4" role="alert">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-rose-600" aria-hidden />
          <div className="flex-1 min-w-0">
            <p className="font-semibold text-rose-900">Fleet snapshot not saved</p>
            <p className="mt-1 text-rose-700/90">
              {saveComplianceError} The score and per-control results shown below are this session's sweep only —
              nothing has been written to the compliance history, and reports will continue to use the last saved
              snapshot.
            </p>
          </div>
        </div>
      )}

      {/* A sweep that is on screen but not persisted: reports and the Compliance page
          read the stored snapshot, so an unsaved run is visible here and nowhere else. */}
      {!oneDeviceCompliance && !saveComplianceError && scoreIsLive && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900 mb-4" role="status">
          <i className="fa fa-circle-info mt-0.5 shrink-0 text-amber-600" aria-hidden />
          <div className="flex-1 min-w-0">
            <p className="font-semibold text-amber-900">This run has not been saved</p>
            <p className="mt-1 text-amber-800/90">
              {scoreProvenanceText}. {scoreCoverageText}. Use “Save Compliance” to record it; until then reports keep
              using the last saved snapshot.
            </p>
          </div>
        </div>
      )}

      {noWindowsOnline && (
        <div className="flex gap-3 rounded-xl border border-blue-200 bg-blue-100 px-4 py-3 text-sm text-slate-700 mb-4" role="status">
          <i className="fa fa-triangle-exclamation mt-0.5 shrink-0 text-slate-600" aria-hidden />
          <div>
            <p className="font-semibold text-slate-900">No Windows nodes found</p>
            <p className="mt-1 text-slate-700/90">
              CERT-In compliance checks are only applicable online to Windows devices. No online Windows nodes were found to run compliance checks on.
            </p>
          </div>
        </div>
      )
      }

      {loading ? (
        <div className="mt-4 rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-600">
          Loading CERT-In checklist…
        </div>
      ) : error ? (
        <div className="mt-4 rounded-2xl border border-red-200 bg-red-50 p-6 text-sm text-red-800">
          {error}
        </div>
      ) : !agentOnline && oneDeviceCompliance ? (
        <div className="mt-4 rounded-2xl border border-amber-200 bg-amber-50 p-6 text-sm text-amber-800">
          Agent is offline. Please ensure the agent is running to view compliance data.
        </div>
      ) : pointsLoading ? (
        <div className="mt-4 rounded-2xl border border-slate-200 bg-white p-6 text-sm text-slate-600">
          <LoadingScreen
            title="Calculating CERT-In compliance..."
            subtitle="This may take a few moments depending on number of endpoints and network conditions."
            size="md"
            fullScreen={false}
          />
        </div>
      ) :
        (
          <div className="flex flex-col lg:flex-row gap-4 mt-4 lg:items-start">
            <div className="flex-1 min-w-0 bg-white rounded-xl border border-gray-200 overflow-hidden">
              <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
                <span className="font-semibold text-white text-base">CERT-In Guidelines</span>
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

                  <button
                    type="button"
                    onClick={() => { void handleClearChecklist(); }}
                    disabled={!draftLoaded || !!complianceLoadError}
                    title={
                      complianceLoadError
                        ? 'Disabled until the saved checklist loads successfully'
                        : 'Removes every recorded Yes/No answer for this host'
                    }
                    className="whitespace-nowrap inline-flex items-center gap-1.5 rounded-full bg-rose-300 px-3 py-1 text-sm font-semibold text-white border border-slate-200 hover:bg-rose-400 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Clear answers
                  </button>
                  {!oneDeviceCompliance && (
                    <>
                      <button
                        type="button"
                        onClick={() => { void handleSaveOrgCompliance(); }}
                        disabled={savingCompliance || totalNodes <= 0 || (!scoreIsLive && !orgSnapshotListReconciles)}
                        title={
                          totalNodes <= 0
                            ? 'Nothing assessed yet — run "Fetch Endpoint Data" first'
                            : (!scoreIsLive && !orgSnapshotListReconciles)
                              ? 'Saved snapshot\'s compliant-node count does not match its own evidence list — run "Fetch Endpoint Data" for a fresh sweep before saving'
                              : savingCompliance
                                ? 'Saving the fleet snapshot…'
                                : undefined
                        }
                        className="inline-flex items-center gap-1.5 rounded-full bg-green-100 px-3 py-1 text-sm font-semibold text-slate-700 border border-slate-200 hover:bg-slate-200 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {savingCompliance ? 'Saving…' : 'Save Compliance'}
                      </button>
                      {saveComplianceError && (
                        <span className="text-xs font-semibold text-rose-600">
                          {saveComplianceError}
                        </span>
                      )}
                    </>
                  )}
                </div>
              </div>
              <div className="flex-1 min-w-0 table-scrollbar overflow-auto max-h-[430px]">
                <div className="p-4 space-y-4">
                  {hierarchy.map((mainSection) => (
                    <div key={mainSection.code} className="bg-white rounded-xl border border-slate-200 overflow-hidden">
                      <div className="px-4 py-3 bg-gradient-to-r from-indigo-50 to-blue-50 border-b border-slate-200">
                        <div className="text-sm font-semibold text-slate-800">Section {mainSection.code}</div>
                      </div>

                      <div className="space-y-4 p-4">
                        {mainSection.subSections.map((subSection) => (
                          <div key={`${mainSection.code}-${subSection.code}`} className="rounded-lg border border-slate-200 overflow-hidden">
                            <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-slate-200 flex items-center justify-between gap-3">
                              <div className="min-w-0">
                                <div className="text-sm font-semibold text-slate-700 truncate">Subsection {mainSection.code}.{subSection.code}</div>
                                <div className="text-xs text-slate-500">{subSection.entries.length} standard group{subSection.entries.length !== 1 ? 's' : ''}</div>
                              </div>
                            </div>

                            <div className="space-y-3 p-3">
                              {subSection.entries.map((entry) => (
                                <div key={entry.id} className="rounded-md border border-slate-200 overflow-hidden">
                                  <div className="px-3 py-2 bg-slate-50 border-b border-slate-200 flex items-center justify-between gap-2">
                                    <span className="text-xs font-semibold text-slate-700 break-all">{entry.standards}</span>
                                    <span className="text-xs text-slate-500 shrink-0">{entry.pointers.length} pointers</span>
                                  </div>
                                  <div className="table-scrollbar overflow-auto">
                                    <table className="w-full text-sm border-separate border-spacing-0">
                                      <thead>
                                        <tr>
                                          <th className="py-2 px-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide w-20 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Point</th>
                                          <th className="py-2 px-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Requirement</th>
                                          <th className="py-2 px-3 text-left text-xs font-medium text-slate-500 uppercase tracking-wide sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Applicability</th>
                                          <th className="py-2 px-3 text-center text-xs font-medium text-slate-500 uppercase tracking-wide w-36 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Status</th>
                                        </tr>
                                      </thead>
                                      <tbody>
                                        {(() => {
                                          const allPointers = [...entry.pointers];

                                          const getComplianceFraction = (pointer: CertInPointer) => {
                                            const marker = pointer.marker;
                                            if (pendingPointStatusByMarker[marker] === 'yes') return 1;
                                            if (pendingPointStatusByMarker[marker] === 'partial') {
                                              const stat = pendingFleetStatsByMarker[marker];
                                              return stat && stat.total > 0 ? stat.passed / stat.total : 0;
                                            }
                                            if (pendingPointStatusByMarker[marker] === 'no') return 0;
                                            // Sort ordering only, not a score: an unmeasured control has no
                                            // compliance fraction, so it sorts with the lowest rather than
                                            // being represented as a pass.
                                            if (pendingPointStatusByMarker[marker] === 'not_assessed') return 0;
                                            if (pendingFleetStatsByMarker[marker] && pendingFleetStatsByMarker[marker].total > 0 && !oneDeviceCompliance) {
                                              return pendingFleetStatsByMarker[marker].passed / pendingFleetStatsByMarker[marker].total;
                                            }
                                            return statusByPointer[pointer.id] === 'yes' ? 1 : 0;
                                          };

                                          if (sortBy === '100_compliant') {
                                            allPointers.sort((a, b) => {
                                              return getComplianceFraction(b) - getComplianceFraction(a);
                                            });
                                          } else if (sortBy === 'not_100_compliant') {
                                            allPointers.sort((a, b) => {
                                              return getComplianceFraction(a) - getComplianceFraction(b);
                                            });
                                          }

                                          return allPointers.map((pointer, sortedIndex) => {
                                            return (
                                              <tr key={pointer.id} className="border-b border-slate-100 hover:bg-slate-50/60 transition-colors">
                                                <td className="py-2.5 px-3 text-slate-500 text-xs font-semibold">{sortedIndex + 1}</td>
                                                <td className="py-2.5 px-3 text-slate-800">
                                                  <div>
                                                    <div className="inline-flex items-start">
                                                      <span>{pointer.text}</span>
                                                      {isPendingPoint(pointer.marker) && (
                                                        <InfoTooltip
                                                          text={CERTIN_AUTOMATED_POINT_DETAILS[pointer.marker]?.tooltip ?? 'CERT-In Direction'}
                                                          description={CERTIN_AUTOMATED_POINT_DETAILS[pointer.marker]?.reason}
                                                          withDescription
                                                          align="right"
                                                        />
                                                      )}
                                                    </div>
                                                    <NestedChildren points={pointer.children} />
                                                  </div>
                                                </td>
                                                <td className="py-2.5 px-3">
                                                  <span className="whitespace-nowrap inline-flex items-center rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-700">
                                                    As per CERT-In
                                                  </span>
                                                </td>
                                                <td className="py-2.5 px-3 text-center">
                                                  {isPendingPoint(pointer.marker) ? (
                                                    <div className="inline-flex flex-col items-center gap-0.5 w-full">
                                                      {!hasRefreshed ? (
                                                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
                                                          <i className="fa fa-hourglass-half text-[9px]" />
                                                          Pending
                                                        </span>
                                                      ) : pendingPointStatusByMarker[pointer.marker] === 'yes' ? (
                                                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-700 border border-green-200">
                                                          <i className="fa fa-check text-[9px]" />
                                                          {pendingFleetStatsByMarker[pointer.marker] && pendingFleetStatsByMarker[pointer.marker].total > 0 && !oneDeviceCompliance
                                                            ? `${pendingFleetStatsByMarker[pointer.marker].passed}/${pendingFleetStatsByMarker[pointer.marker].total} nodes passed`
                                                            : 'Passed'}
                                                        </span>
                                                      ) : pendingPointStatusByMarker[pointer.marker] === 'partial' ? (
                                                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-700 border border-amber-200">
                                                          <i className="fa fa-circle-half-stroke text-[9px]" />
                                                          {pendingFleetStatsByMarker[pointer.marker] && pendingFleetStatsByMarker[pointer.marker].total > 0 && !oneDeviceCompliance
                                                            ? `${pendingFleetStatsByMarker[pointer.marker].passed}/${pendingFleetStatsByMarker[pointer.marker].total} nodes passed`
                                                            : 'Partially passed'}
                                                        </span>
                                                      ) : pendingPointStatusByMarker[pointer.marker] === 'no' ? (
                                                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700 border border-red-200">
                                                          <i className="fa fa-xmark text-[9px]" />
                                                          {pendingFleetStatsByMarker[pointer.marker] && pendingFleetStatsByMarker[pointer.marker].total > 0 && !oneDeviceCompliance
                                                            ? `${pendingFleetStatsByMarker[pointer.marker].passed}/${pendingFleetStatsByMarker[pointer.marker].total} nodes passed`
                                                            : 'Failed'}
                                                        </span>
                                                      ) : pendingPointStatusByMarker[pointer.marker] === 'not_assessed' ? (
                                                        // Neutral by design: Vajra measured nothing for this
                                                        // control, so it must read as neither a pass nor a failure.
                                                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-600 border border-slate-300">
                                                          <i className="fa fa-circle-minus text-[9px]" />
                                                          Not Assessed
                                                        </span>
                                                      ) : (
                                                        <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-500 border border-gray-200">
                                                          <i className="fa fa-triangle-exclamation text-[9px]" />
                                                          Not Checked
                                                        </span>
                                                      )}

                                                      {pendingFleetStatsByMarker[pointer.marker] && pendingFleetStatsByMarker[pointer.marker].total > 0 && !oneDeviceCompliance && (
                                                        <div className="w-full mt-0.5 px-1">
                                                          <div className="h-1 w-full max-w-[96px] mx-auto bg-gray-100 rounded-full overflow-hidden">
                                                            <div
                                                              className="h-full rounded-full bg-sky-400 transition-all duration-500"
                                                              style={{ width: `${Math.max((pendingFleetStatsByMarker[pointer.marker].passed / pendingFleetStatsByMarker[pointer.marker].total) * 100, pendingFleetStatsByMarker[pointer.marker].passed > 0 ? 4 : 0)}%` }}
                                                            />
                                                          </div>
                                                        </div>
                                                      )}
                                                    </div>
                                                  ) : (
                                                    <div className="inline-flex flex-col items-start gap-1">
                                                      <div className="inline-flex items-center gap-3">
                                                        <label
                                                          className={`inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 ${!checklistEditable ? 'opacity-50 cursor-not-allowed' : ''}`}
                                                          title={
                                                            !canEditChecklist
                                                              ? 'Only Group Admins and Super Administrators can edit this checklist'
                                                              : complianceLoadError
                                                                ? 'Editing is disabled until the saved checklist loads successfully'
                                                                : undefined
                                                          }
                                                        >
                                                          <input
                                                            type="checkbox"
                                                            disabled={!checklistEditable}
                                                            checked={statusByPointer[pointer.id] === 'yes'}
                                                            onChange={() =>
                                                              setPointerAnswer(
                                                                pointer,
                                                                statusByPointer[pointer.id] === 'yes' ? null : 'yes',
                                                              )
                                                            }
                                                          />
                                                          Yes
                                                        </label>
                                                        <label
                                                          className={`inline-flex items-center gap-1.5 text-xs font-semibold text-rose-700 ${!checklistEditable ? 'opacity-50 cursor-not-allowed' : ''}`}
                                                          title={
                                                            !canEditChecklist
                                                              ? 'Only Group Admins and Super Administrators can edit this checklist'
                                                              : complianceLoadError
                                                                ? 'Editing is disabled until the saved checklist loads successfully'
                                                                : undefined
                                                          }
                                                        >
                                                          <input
                                                            type="checkbox"
                                                            disabled={!checklistEditable}
                                                            checked={statusByPointer[pointer.id] === 'no'}
                                                            onChange={() =>
                                                              setPointerAnswer(
                                                                pointer,
                                                                statusByPointer[pointer.id] === 'no' ? null : 'no',
                                                              )
                                                            }
                                                          />
                                                          No
                                                        </label>
                                                      </div>
                                                      {statusByPointer[pointer.id] === undefined && (
                                                        // Neither box is ticked and the guideline reads as what it
                                                        // is: nobody has answered it. It used to render as a ticked
                                                        // "No", presenting an unanswered control as a recorded
                                                        // compliance failure.
                                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-100 text-slate-600 border border-slate-300">
                                                          <i className="fa fa-circle-minus text-[9px]" />
                                                          Not answered
                                                        </span>
                                                      )}
                                                    </div>
                                                  )}
                                                </td>
                                              </tr>
                                            );
                                          });
                                        })()}
                                      </tbody>
                                    </table>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
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

                      </div>

                      {/* Donut */}
                      <div className="flex justify-center">
                        <ResponsiveContainer width="100%" height={280}>

                          <PieChart>
                            <Pie
                              data={pieData}
                              activeShape={renderActiveShape}
                              onMouseEnter={(_, index) => setActiveIndex(index)}
                              dataKey="value"
                              cx="50%"
                              cy="50%"
                              innerRadius={65}
                              outerRadius={115}
                              stroke="#fff"
                              strokeWidth={4}
                              cornerRadius={6}
                            >
                              {pieData.map((_, idx) => (
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
                                Fully Compliant
                              </tspan>
                            </text>

                            <RTooltip content={<CustomTooltip />} />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>

                      {/* KPI Cards */}
                      <div className="grid grid-cols-4 gap-3 mt-2">

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
                    <div className="flex items-center justify-center h-[300px] text-gray-300">
                      <i className="fa fa-chart-pie text-6xl" />
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

                  {/* Provenance of the figure below — a live sweep and a saved snapshot
                      are different runs over different host sets and must never be shown
                      in the same place without saying which one this is. */}
                  <div className="px-4 py-2 border-b border-blue-200 bg-white/60">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`h-1.5 w-1.5 shrink-0 rounded-full ${scoreIsLive ? 'bg-amber-500' : 'bg-slate-400'}`}
                        aria-hidden="true"
                      />
                      <span className="text-xs font-semibold text-slate-700">{scoreProvenanceText}</span>
                    </div>
                    {scoreProvenance != null && (
                      <div className="mt-0.5 text-[11px] text-slate-500">{scoreCoverageText}</div>
                    )}
                  </div>

                  {fullyCompliantChartData.length > 0 && !noWindowsOnline && (scoreIsLive || orgSnapshotListReconciles) ? (
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
                              onMouseEnter={(_, index) => setActiveIndex(index)}
                              dataKey="value"
                              cx="50%"
                              cy="50%"
                              innerRadius={65}
                              outerRadius={115}
                              stroke="#fff"
                              strokeWidth={4}
                              cornerRadius={6}
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
                                  chartTotalNodes > 0
                                    ? (chartFullyCompliantNodes / chartTotalNodes) * 100
                                    : 0
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
                            {chartFullyCompliantNodes}
                          </div>
                          <div className="text-xs text-slate-500 mt-1">
                            Compliant
                          </div>
                        </div>

                        <div className="rounded-xl bg-[#ab3428]/15 py-3 text-center">
                          <div className="text-2xl font-bold text-[#ab3428]">
                            {chartTotalNodes - chartFullyCompliantNodes}
                          </div>
                          <div className="text-xs text-slate-500 mt-1">
                            Non-Compliant
                          </div>
                        </div>

                        <div className="rounded-xl bg-[#023047]/10 py-3 text-center">
                          <div className="text-2xl font-bold text-[#023047]">
                            {chartTotalNodes}
                          </div>
                          <div className="text-xs text-slate-500 mt-1">
                            Total
                          </div>
                        </div>

                      </div>

                      {/* Legend */}

                    </div>
                  ) : !noWindowsOnline && !scoreIsLive && !orgSnapshotListReconciles ? (
                    // Evidence gap, not a score: the stored snapshot's compliant-node count
                    // does not match the length of its own evidence list (see
                    // orgSnapshotListReconciles above), so there is no trustworthy number to
                    // draw a donut from. Showing the raw scalar here would be the exact
                    // "6/8 = 75% Fully Compliant, evidence list empty" leak this guards
                    // against — reports.ts's PDF already refuses to render Section D on the
                    // identical mismatch rather than print an unsubstantiated figure.
                    <div className="flex flex-col items-center justify-center h-[27rem] gap-2 px-6 text-center">
                      <i className="fa fa-triangle-exclamation text-3xl text-amber-500" aria-hidden />
                      <p className="text-sm font-semibold text-slate-700">Compliant-node count unavailable</p>
                      <p className="text-xs text-slate-500">
                        The saved snapshot's compliant-node count doesn't match its own evidence list, so it
                        can't be shown here. Run "Fetch Endpoint Data" for a fresh sweep, then Save Compliance.
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
        )}
      {/* History trend chart */}
      {!oneDeviceCompliance && !pointsLoading && (<div className="bg-white rounded-xl border border-gray-200 overflow-hidden mt-4">
        <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
          <span className="font-semibold text-white text-base">Organization CERT-In Compliance History</span>
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
              <LineChart data={chartOrgData} margin={{ top: 8, right: 20, bottom: 4, left: 0 }}>
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
                <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} tickLine={false} unit="%" width={38} />
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
                          Pass Rate: {typeof point.percent === 'number'
                            ? `${point.percent.toFixed(2)}%`
                            : 'Not assessed — no host produced a measurement'}
                        </div>

                        <div className="mt-1 text-slate-600">
                          Windows Nodes Processed: {point.nodeCount}
                        </div>
                      </div>
                    );
                  }}
                />
                <Legend iconType="circle" iconSize={10} wrapperStyle={{ fontSize: 12 }} />
                <Line
                  type="monotone"
                  dataKey="percent"
                  name="Pass rate %"
                  stroke="#e11d48"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#e11d48' }}
                  activeDot={{ r: 5 }}
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
      {oneDeviceCompliance && !pointsLoading && (<div className="bg-white rounded-xl border border-gray-200 overflow-hidden mt-4">
        <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-gray-200 flex items-center justify-between">
          <span className="font-semibold text-white text-base">Node CERT-In Compliance History</span>
          {!historyLoading && history.length > 0 && (
            <span className="text-xs text-gray-100">{history.length} records</span>
          )}
        </div>
        <div className="p-4">
          {historyLoading ? (
            <div className="flex items-center justify-center h-[180px]">
              <DuoSpinner size="md" className="text-rose-400" />
            </div>
          ) : chartData.length >= 2 ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={chartData} margin={{ top: 8, right: 20, bottom: 4, left: 0 }}>
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
                <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} tickLine={false} unit="%" width={38} />
                <RTooltip
                  formatter={(value) => [`${Number(Array.isArray(value) ? value[0] : value) || 0}%`, 'Pass rate']}
                  labelFormatter={(label: React.ReactNode, payload?: unknown) => {
                    const items = Array.isArray(payload) ? payload as Array<{ payload?: { tooltip?: string } }> : [];
                    return items[0]?.payload?.tooltip ?? label;
                  }}
                />
                <Legend iconType="circle" iconSize={10} wrapperStyle={{ fontSize: 12 }} />
                <Line
                  type="monotone"
                  dataKey="percent"
                  name="Pass rate %"
                  stroke="#e11d48"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#e11d48' }}
                  activeDot={{ r: 5 }}
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
