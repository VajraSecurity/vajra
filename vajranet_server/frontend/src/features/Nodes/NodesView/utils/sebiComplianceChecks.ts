/**
 * Pure compliance-check helpers for NodesViewSebiHotCompliance — WS payload
 * parsing, pass/fail evaluation, and the fleet/per-host static check builder.
 * Extracted verbatim, no logic changes.
 */

import { debugLog } from '@/lib/debugLog';
import type { NodeData } from '../types';
import { ALERTS_URLS, NODES_URLS } from '../../../../api/urls';
import api from '../../../../api/axiosInstance';
import { nodesViewApi } from '../nodesViewApi';
import { fmtDateTime } from '../../../Compliance/shared/complianceDateUtils';
import {
  SEBI_HOT_GUIDELINES,
  INVERTED_KEYS,
  NUMERIC_KEYS,
  HIDDEN_GUIDELINES,
  SEBI_HOT_COMMAND_KEYS,
  STRUCTURALLY_UNMEASURABLE_SEBI_KEYS,
} from '../constants/sebiHotGuidelines';

/**
 * Controls that ARE reachable command keys (survive HIDDEN_GUIDELINES) but are
 * still structurally unmeasurable: every branch of their evaluator resolves to
 * notAssessed(), on every host, on every run (see STRUCTURALLY_UNMEASURABLE_SEBI_KEYS
 * for the audit trail). Their evaluator code below is left exactly as written —
 * this only decides which command keys leave this module's returned/row-built
 * output, so the register's table (and anything downstream that reads this
 * module's output, e.g. the fleet sweep's per-control denominators) never
 * carries a row for them. Consumers needing "how many controls does this
 * register actually show" should use this instead of SEBI_HOT_COMMAND_KEYS.
 */
export const SEBI_VISIBLE_COMMAND_KEYS: readonly string[] = SEBI_HOT_COMMAND_KEYS.filter(
  (key) => !STRUCTURALLY_UNMEASURABLE_SEBI_KEYS.has(key)
);

export interface StaticCheckResult {
  compliant: boolean;
  reason: string;
  detail?: string;
  fraction?: { value: number; total: number; label: string };
  /**
   * Present (and false) only for controls that were NOT assessed on the endpoint.
   * `compliant` is then a fail-safe placeholder, never a measured verdict, so a
   * capability statement is not reported as a pass.
   */
  assessed?: false;
}

/**
 * Builds a result for a control Vajra can describe but has not measured on this
 * endpoint. `compliant` stays present and false so existing consumers keep
 * working and fail safe; `assessed: false` marks the verdict as unmeasured.
 */
function notAssessed(reason: string, detail?: string): StaticCheckResult {
  return { compliant: false, assessed: false, reason, detail };
}

export interface WifiStatusResponse {
  event_type?: string;
  connected?: {
    ssid?: string;
    bssid?: string;
    interface?: string;
    signal?: string;
    frequency?: string;
    channel?: string;
    bitrate?: string;
    security?: string;
    ip_address?: string;
  } | null;
  saved_profiles?: unknown[];
  timestamp?: string;
}

export interface UsbStatusResponse {
  enabled?: boolean;
  status?: 'enabled' | 'disabled' | 'unknown';
  registry_start?: number | null;
  usb_storage_policy?: 'Enabled' | 'Disabled';
  connected_devices?: unknown[];
}

export interface BluetoothStatusResponse {
  status?: 'enabled' | 'locked' | 'partial' | 'unknown';
  fully_locked?: boolean;
  enabled_device_count?: number;
  total_device_count?: number;
  bthport_start?: number | null;
  bthserv_startup?: number;
  policy_allow_bluetooth?: number | null;
  radio_blocked?: boolean;
  hard_blocked?: boolean;
  service_active?: boolean;
  service_enabled?: boolean;
  service_masked?: boolean;
  module_loaded?: boolean;
  adapters?: unknown[];
}

export interface GuidelineResult {
  key: string;
  label: string;
  tooltip: string;
  rawOutput: string;
  passed: boolean;
  showRaw: boolean;
}

export function parseWsPayload(input: unknown): unknown {
  if (input && typeof input === 'object') {
    const wrapped = input as { response?: unknown; data?: unknown };
    if ('response' in wrapped) {
      const response = wrapped.response;
      if (typeof response === 'string') {
        try {
          return JSON.parse(response);
        } catch {
          return response;
        }
      }
      return response;
    }
    if ('data' in wrapped) {
      return wrapped.data;
    }
  }

  if (typeof input === 'string') {
    try {
      return JSON.parse(input);
    } catch {
      return input;
    }
  }

  return input;
}

export async function fetchWifiStatusForCompliance(
  hostId: string,
  wsConnected: boolean,
  wsSendMessage?: (message: unknown) => Promise<unknown>,
): Promise<WifiStatusResponse | null> {
  if (!wsConnected || !wsSendMessage) return null;

  const response = await wsSendMessage({
    type: 'agent',
    params: { agent: 'wifi', action: 'status' },
    host_identifier: hostId,
  });

  const raw = parseWsPayload(response);

  if (raw && typeof raw === 'object') {
    const candidate = raw as Record<string, unknown>;
    if ('saved_profiles' in candidate || 'connected' in candidate || 'event_type' in candidate) {
      return candidate as WifiStatusResponse;
    }
  }

  return null;
}

export async function fetchUsbStatusForCompliance(
  hostId: string,
  node: NodeData,
  wsConnected: boolean,
  wsSendMessage?: (message: unknown) => Promise<unknown>,
): Promise<UsbStatusResponse | null> {
  if (!wsConnected || !wsSendMessage) return null;

  const isWindows = /windows/i.test(String(node.os_name ?? node.os_platform ?? ''));

  if (!isWindows) {
    const response = await wsSendMessage({
      type: 'agent',
      params: { agent: 'removableDevice', action: 'status' },
      host_identifier: hostId,
    });

    const raw = parseWsPayload(response);

    if (raw && typeof raw === 'object') {
      const candidate = raw as Record<string, unknown>;
      if ('usb_storage_policy' in candidate || 'status' in candidate || 'enabled' in candidate) {
        return candidate as UsbStatusResponse;
      }
    }
    return null;
  }

  // command_key 54 (Windows USB status via PowerShell) has been observed to
  // intermittently fail or time out within a single sweep while the wifi (key 23)
  // and bluetooth (key 38) probes — issued over the identical already-connected
  // websocket, on the identical host, moments apart in the same sweep — succeed.
  // That rules out host/agent unreachability as the cause, so a single failure
  // here is worth one bounded retry before falling back to not-assessed, unlike
  // an outright unreachable host which no retry could fix.
  const USB_STATUS_MAX_ATTEMPTS = 2;
  const USB_STATUS_RETRY_DELAY_MS = 2_500;

  for (let attempt = 1; attempt <= USB_STATUS_MAX_ATTEMPTS; attempt++) {
    try {
      const response = await wsSendMessage({
        type: 'agent',
        params: { agent: 'powershell', action: 'allow', command_keys: ['54'] },
        host_identifier: hostId,
      });

      const parsedTop = parseWsPayload(response);

      // 2. ensure array
      const items: unknown[] = Array.isArray(parsedTop) ? parsedTop : [parsedTop];

      // 3. find command result (loose compare)
      const item = items.find((i) =>
        i && typeof i === 'object' && String((i as Record<string, unknown>).command_key) === '54',
      ) as { output?: unknown } | undefined;

      if (!item?.output) {
        if (attempt < USB_STATUS_MAX_ATTEMPTS) {
          await new Promise((resolve) => setTimeout(resolve, USB_STATUS_RETRY_DELAY_MS));
          continue;
        }
        return null;
      }

      // 4. handle double-encoded or plain object
      return (typeof item.output === 'string' ? JSON.parse(item.output) : item.output) as UsbStatusResponse;
    } catch {
      if (attempt < USB_STATUS_MAX_ATTEMPTS) {
        await new Promise((resolve) => setTimeout(resolve, USB_STATUS_RETRY_DELAY_MS));
        continue;
      }
      return null;
    }
  }

  return null;
}

export async function fetchBluetoothStatusForCompliance(
  hostId: string,
  node: NodeData,
  wsConnected: boolean,
  wsSendMessage?: (message: unknown) => Promise<unknown>,
): Promise<BluetoothStatusResponse | null> {
  if (!wsConnected || !wsSendMessage) return null;

  const isWindows = /windows/i.test(String(node.os_name ?? node.os_platform ?? ''));

  if (!isWindows) {
    const response = await wsSendMessage({
      type: 'agent',
      params: { agent: 'bluetooth', action: 'status' },
      host_identifier: hostId,
    }) as { response?: unknown };

    const raw = typeof response.response === 'string'
      ? JSON.parse(response.response)
      : response.response;

    if (raw && typeof raw === 'object' && ('service_active' in raw || 'radio_blocked' in raw)) {
      return raw as BluetoothStatusResponse;
    }
    return null;
  }

  const response = await wsSendMessage({
    type: 'agent',
    params: { agent: 'powershell', action: 'allow', command_keys: ['55'] },
    host_identifier: hostId,
  }) as { response?: unknown };

  const items = typeof response.response === 'string'
    ? JSON.parse(response.response)
    : response.response;

  if (!Array.isArray(items)) return null;
  const item = items.find((entry) => entry && typeof entry === 'object' && (entry as { command_key?: string }).command_key === '55') as { output?: string } | undefined;
  if (!item?.output) return null;

  const parsed = JSON.parse(item.output);
  if (parsed && typeof parsed === 'object' && ('status' in parsed || 'fully_locked' in parsed)) {
    return parsed as BluetoothStatusResponse;
  }

  return null;
}

// Pass/Fail logic

export function parsePassFail(key: string, output: string): boolean {
  const v = String(output).trim().toLowerCase();

  if (NUMERIC_KEYS.has(key)) {
    const n = parseInt(v, 10);
    return !isNaN(n) && n > 0;
  }

  let rawBool: boolean;
  if (v === 'true' || v === 'pass' || v === 'passed' || v === '1') rawBool = true;
  else if (v === 'false' || v === 'fail' || v === 'failed' || v === '0') rawBool = false;
  else return false;

  return INVERTED_KEYS.has(key) ? !rawBool : rawBool;
}

export function buildRows(data: Array<{ command_key: string; output: string }>): GuidelineResult[] {
  return data
    .filter(
      (item) =>
        !HIDDEN_GUIDELINES.has(item.command_key) &&
        !STRUCTURALLY_UNMEASURABLE_SEBI_KEYS.has(item.command_key)
    )
    .map((item) => {
    const meta = SEBI_HOT_GUIDELINES[item.command_key] ?? {
      label: `Check ${item.command_key}`,
      tooltip: '',
    };
    return {
      key: item.command_key,
      label: meta.label,
      tooltip: meta.tooltip,
      rawOutput: String(item.output).trim(),
      passed: parsePassFail(item.command_key, item.output),
      showRaw: NUMERIC_KEYS.has(item.command_key),
    };
  });
}

export function calcPassPercent(rows: GuidelineResult[]): number {
  if (rows.length === 0) return 0;
  return Math.round((rows.filter((r) => r.passed).length / rows.length) * 100);
}

/**
 * Carries a settled outcome as a value so a request can be started early and
 * awaited later without ever becoming an unhandled rejection. `unwrap` re-throws
 * at the await site, so each control keeps exactly the try/catch semantics it
 * had when the request was made inline.
 */
type Settled<T> = { ok: true; value: T } | { ok: false; error: unknown };

const settle = <T>(p: Promise<T>): Promise<Settled<T>> =>
  p.then(
    (value) => ({ ok: true as const, value }),
    (error) => ({ ok: false as const, error }),
  );

const unwrap = <T>(s: Settled<T>): T => {
  if (!s.ok) throw s.error;
  return s.value;
};

/**
 * Fleet node list (`GET /api/nodes/list`), shared across the hosts of one sweep.
 *
 * This is the only endpoint that returns `critical`, `security_products`,
 * `os_name` and `agent_online`. `/nodes/identifiers` selects none of them
 * (backend/src/controllers/nodes/node_identifiers.ts) and returns a
 * `{ success, count, nodes }` envelope rather than `{ data }`, and
 * `/nodes/details/{host}` carries the hardware_* fields but no
 * security_products — so neither of the sources this module used before could
 * answer the critical-node or AV/EDR controls at all.
 *
 * The payload is fleet-wide, so fetching it per host inside a sweep repeats the
 * identical request once per node. It is cached for FLEET_NODES_TTL_MS and
 * de-duplicated while in flight; the TTL is short enough that it only ever
 * spans a single sweep, so evidence freshness within a run is unchanged and no
 * run reuses an older run's data. A failed or unparseable response resolves to
 * `null` — never to an empty fleet — so dependent controls stay not-assessed
 * instead of being scored against a fabricated zero.
 */
const FLEET_NODES_TTL_MS = 30_000;
/** Matches backend PAGINATION_MAX_ROWS_NODES; the endpoint clamps to it anyway. */
const FLEET_NODES_MAX_ROWS = 1000;
/** Matches backend PAGINATION_MAX_ROWS_ALERTS; the endpoint clamps to it anyway. */
const DEVICE_ALERT_MAX_ROWS = 500;

/**
 * How old the stored Windows baseline probe row (fleet.compliance_results) may be and
 * still describe this endpoint. A Vajra platform default, not a SEBI-published interval:
 * the probes read static machine policy, which changes rarely, so a quarter-old row is
 * still evidence; beyond it the row is treated as ABSENT — never as a failure.
 *
 * 2026-09-07: SEBI applied no cutoff at all while IRDAI discarded anything older than 90
 * days (IRDAI_BASELINE_FRESHNESS_DAYS), so on a host whose last successful probe run was
 * four months ago and reported Logon auditing Off, SEBI 4 published a measured FAIL from
 * four-month-old evidence while IRDAI 3 — reading the identical row from the identical
 * endpoint — returned not-assessed. That divergence hit every baseline-sourced pair at
 * once (SEBI 4/5/7/10/24 against IRDAI 3/4/6/15/21/24). IRDAI's behaviour is the correct
 * one under the standing rule that absent or unreliable evidence is not-assessed rather
 * than a fail: a four-month-old probe is not a statement about the endpoint today. The
 * bound is exported so both registers read ONE number instead of two that can drift.
 */
export const BASELINE_FRESHNESS_DAYS = 90;

/**
 * Window over which an alert Vajra raised for this endpoint counts as evidence that
 * automated alerting is running on it. A Vajra platform default, not a regulator-published
 * figure.
 *
 * 2026-09-07: control 16 previously passed on `alertRows.length > 0` with no date filter
 * at all, so an endpoint whose only alert was eighteen months old was certified as having
 * working automated alerting, while IRDAI control 13 — the same question, the same alert
 * rows — returned not-assessed because it bounds the same evidence to 90 days. An alert
 * from a year and a half ago is not evidence that alerting is running now, so SEBI adopts
 * the bounded reading and the constant is exported so both registers share one number.
 */
export const ALERT_EVIDENCE_WINDOW_DAYS = 90;

/**
 * How an evidence read ENDED, as opposed to what it returned.
 *
 * 2026-09-07: every failed read in this module used to collapse into the same
 * not-assessed verdict as a genuine absence of data — checks['2'] said "no inventory was
 * read back for this node" whether the programs endpoint returned an empty list or
 * rejected the request with 429, and the baseline reader treated a rejected request and a
 * host with no compliance_results row identically. The consequence was not cosmetic: org
 * snapshot sebi_historical_compliance id=57 recorded 9 of 13 eligible hosts on every
 * REST-sourced control and was read afterwards as a legitimate coverage figure, when
 * irdai_historical_compliance id=25 — the SAME 13 hosts, 216 seconds later — reached 13 of
 * 13 on the equivalent controls. A register that cannot say "I could not ask the question"
 * reports a degraded run as a smaller measured population. The outcome is therefore
 * classified and named in the reason text.
 *
 * 'no-record' is deliberately NOT a transport failure: several of these endpoints answer
 * 404 when they simply hold no row for the host (security_profile_info does exactly that),
 * which is a real, measured absence and must not be dressed up as a failed read.
 */
type EvidenceTransport =
  | 'rate-limited'
  | 'timed-out'
  | 'unauthorised'
  | 'http-error'
  | 'network-error'
  | 'no-record'
  | 'unknown';

const classifyTransport = (error: unknown): EvidenceTransport => {
  const e = (error ?? {}) as { code?: unknown; message?: unknown; response?: { status?: unknown } };
  const status = Number(e.response?.status);
  const message = String(e.message ?? '');
  if (status === 429) return 'rate-limited';
  if (status === 401 || status === 403) return 'unauthorised';
  if (status === 404) return 'no-record';
  if (status === 408 || status === 504 || e.code === 'ECONNABORTED' || /timeout/i.test(message)) return 'timed-out';
  if (Number.isFinite(status) && status > 0) return 'http-error';
  if (e.code === 'ERR_NETWORK' || /network error/i.test(message)) return 'network-error';
  return 'unknown';
};

const TRANSPORT_TEXT: Record<EvidenceTransport, string> = {
  'rate-limited': 'the request was rejected by the server\'s rate limiter (HTTP 429) while this sweep was running',
  'timed-out': 'the request timed out before the server answered',
  unauthorised: 'the request was rejected as unauthorised (HTTP 401/403)',
  'http-error': 'the server answered with an error status',
  'network-error': 'the request never reached the server',
  'no-record': '',
  unknown: 'the request failed before a usable response was returned',
};

/**
 * Clause appended to a not-assessed reason when the read FAILED rather than returned
 * nothing, so an operator reading the register can tell a degraded run from a measured
 * absence. Empty for a successful read and for a 404 (a real "no row for this host").
 */
const transportNote = (settled: { ok: boolean; error?: unknown }): string => {
  if (settled.ok) return '';
  const outcome = classifyTransport(settled.error);
  const text = TRANSPORT_TEXT[outcome];
  if (!text) return '';
  return ` Evidence collection for this control did not complete on this run: ${text}. That is a failed read, not an absence of data on the endpoint — this host is missing from this control's measured population because the question could not be asked, not because the answer was empty.`;
};

let fleetNodesCache: { at: number; nodes: Array<Record<string, unknown>> } | null = null;
let fleetNodesInFlight: Promise<Array<Record<string, unknown>> | null> | null = null;

/** Drops the cached fleet list so the next sweep re-reads it. */
export function invalidateFleetNodesCache(): void {
  fleetNodesCache = null;
}

async function fetchFleetNodes(): Promise<Array<Record<string, unknown>> | null> {
  if (fleetNodesCache && Date.now() - fleetNodesCache.at < FLEET_NODES_TTL_MS) {
    return fleetNodesCache.nodes;
  }
  if (fleetNodesInFlight) return fleetNodesInFlight;

  fleetNodesInFlight = (async () => {
    try {
      // 2026-09-07: was a raw fetch(). A raw fetch bypasses the shared axios
      // instance's interceptors (api/axiosInstance.ts:174-181), which are what turn a
      // 401 into re-authentication and a 429 into the app-wide rate-limit banner, so a
      // sweep that lost this read to rate limiting reported reduced coverage with no
      // operator-visible signal whatsoever. IRDAI's equivalent fleet-node read already
      // went through api.get, so the two copies disagreed on observability as well as on
      // coverage. axios rejects a non-2xx response, so the `res.ok` guard the fetch
      // version needed is now the catch below.
      const res = await api.get(`${NODES_URLS.NODES_LIST}?rows=${FLEET_NODES_MAX_ROWS}`);
      const json = res.data;
      const arr: Array<Record<string, unknown>> | null = Array.isArray(json?.nodes)
        ? json.nodes
        : Array.isArray(json?.data)
          ? json.data
          : Array.isArray(json)
            ? json
            : null;
      if (!arr) return null;
      fleetNodesCache = { at: Date.now(), nodes: arr };
      return arr;
    } catch {
      return null;
    } finally {
      fleetNodesInFlight = null;
    }
  })();

  return fleetNodesInFlight;
}

export async function staticComplianceChecks(
  hostId: string,
  node: NodeData,
  wsConnected = false,
  wsSendMessage?: (message: unknown) => Promise<unknown>,
  /**
   * Optional fleet node list already fetched by the caller from
   * NODES_URLS.NODES_LIST. Passing it lets a sweep read the list once for the
   * whole run; when omitted this function reads it through the shared
   * short-lived cache above.
   */
  fleetNodes?: Array<Record<string, unknown>> | null,
): Promise<Record<string, StaticCheckResult>> {
  const checks: Record<string, StaticCheckResult> = {};

          // ---- Phase 1: start every independent request -----------------------
          // No request below consumes another's result, so they are all started
          // here and awaited where they are used. settle() carries a rejection
          // as a value and unwrap() re-throws it at the await site, so every
          // control keeps the exact try/catch (and not-assessed) behaviour it
          // had when the call was made inline.
          const fleetNodesPromise: Promise<Array<Record<string, unknown>> | null> =
            Array.isArray(fleetNodes) ? Promise.resolve(fleetNodes) : fetchFleetNodes();
          // One programs read serves controls 2, 36 and 39; one storage read
          // serves controls 22, 26 and 34. Both were previously fetched twice.
          const programsPromise = settle(nodesViewApi.getProgramsList(hostId, node.os_name ?? node.os_platform));
          const profilePromise = settle(nodesViewApi.getSecurityProfileInfo(hostId));
          const storagePromise = settle(nodesViewApi.getStorage(hostId));
          const firewallPromise = settle(nodesViewApi.getFirewallRules(hostId));
          const updateHistoryPromise = settle(nodesViewApi.getUpdateHistory(hostId));
          // Listening-port inventory (GET /api/nodes/network/listening-ports/{host},
          // backend/src/controllers/nodes/node_network_posture.ts::node_listening_ports).
          // One read serves both control 30 (collection evidence) and control 13
          // (attached inventory evidence only — verdict stays not-assessed there).
          const listeningPortsPromise = settle(
            api.get(`${NODES_URLS.NETWORK_LISTENING_PORTS}${encodeURIComponent(hostId)}`),
          );
          // Last-boot / uptime (GET /api/nodes/network/uptime/{host}, same
          // controller file, node_network_uptime) for control 32.
          const networkUptimePromise = settle(
            api.get(`${NODES_URLS.NETWORK_UPTIME}${encodeURIComponent(hostId)}`),
          );
          // The Windows baseline probe row this node last posted
          // (fleet.compliance_results), read through the same endpoint the
          // Compliance tab uses. It is the only source Vajra holds for the
          // advanced-audit-policy state behind controls 4, 5 and 24, and it
          // independently corroborates control 7's password policy numbers.
          // 2026-09-07: was a raw fetch(), for the same reason as the fleet-node read
          // above and with the largest consequence of the three — this row is the sole
          // evidence behind controls 4, 5, 10 and 24 and corroborates 7, i.e. the biggest
          // coverage losses in the SEBI snapshot happened through the one path with the
          // least observability. api.get gives it the 429/401 interceptors and a
          // consistent error shape for classifyTransport() above.
          const baselinePromise = settle(
            api.get(`${NODES_URLS.COMPLIANCE_LATEST}${encodeURIComponent(hostId)}`),
          );
          // Alerts Vajra itself raised for this node (controls 10 and 16), read
          // through the same endpoint the device alert tab uses. `rows` is
          // clamped to PAGINATION_MAX_ROWS_ALERTS by the backend, so this is the
          // most recent DEVICE_ALERT_MAX_ROWS alerts, not the full history.
          const deviceAlertsPromise = settle(
            api.post(`${ALERTS_URLS.ALERTS_LIST}/device`, { host_identifier: hostId, rows: DEVICE_ALERT_MAX_ROWS }),
          );

          const nodeAny = node as unknown as Record<string, unknown>;
          const hasHardware = !!(nodeAny.hardware_model || nodeAny.hardware_vendor || nodeAny.hardware_physical_memory);
          // /nodes/details/{host} is the only source of the hardware_* fields
          // (control 3). It never returns security_products, so it is no longer
          // fetched on their account — see the fleet-list note above.
          // 2026-09-07: raw fetch() -> shared axios instance, as above.
          const detailsPromise = hasHardware
            ? null
            : settle(api.get(`${NODES_URLS.NODE}${encodeURIComponent(hostId)}`));

          // The three agent commands share one WebSocket and one agent, so they
          // are chained rather than fired together: the 15 s timeout in
          // useNodeWebSocket runs from send, and queueing three commands at an
          // agent that services them one at a time would convert measured
          // answers into timeouts. The chain still runs alongside the REST
          // requests above.
          const wsPromise = (async () => ({
            usb: await settle(fetchUsbStatusForCompliance(hostId, node, wsConnected, wsSendMessage)),
            wifi: await settle(fetchWifiStatusForCompliance(hostId, wsConnected, wsSendMessage)),
            bluetooth: await settle(fetchBluetoothStatusForCompliance(hostId, node, wsConnected, wsSendMessage)),
          }))();

          // ---- Fleet-level evidence -------------------------------------------
          const fleetNodesResolved = await fleetNodesPromise;
          const fleetRow = Array.isArray(fleetNodesResolved)
            ? fleetNodesResolved.find(
              (n) => String(n?.host_identifier ?? '').trim().toLowerCase() === String(hostId).trim().toLowerCase(),
            )
            : undefined;

          // ---- Windows baseline probe results ---------------------------------
          // fleet.compliance_results, read through GET /nodes/compliance/latest/
          // {host} — the row the Compliance tab renders. It holds the 18 probes
          // the agent last ran on this endpoint: twelve auditpol advanced-audit
          // subcategories (keys 5-16), the ProcessCreationIncludeCmdLine registry
          // policy (17), the net-accounts minimum password length (18), Secure
          // Boot (4), Defender (1) and the timezone (3).
          //
          // "True" means the probe ran and the setting is on; "False" means it
          // ran and the setting is off — a MEASURED negative, which is a real
          // finding and is scored as one. A probe that FAILED on the endpoint
          // returns an empty string (key 4 does exactly that on hosts without
          // UEFI), and an empty value is read here as unmeasured and never
          // scored in either direction.
          //
          // 2026-09-07: two behaviours added here, both so that "no baseline" stops
          // meaning three different things at once.
          //
          // (a) FRESHNESS. A row older than BASELINE_FRESHNESS_DAYS is treated as absent,
          //     exactly as IRDAI's baseline reader already did. Before this, SEBI applied
          //     no cutoff and would publish a measured FAIL on control 4 from a probe run
          //     four months earlier while IRDAI, reading the identical row, abstained.
          //     `baselineUnixtime` is still recorded for a stale row, because control 17
          //     measures telemetry RECENCY and a stale row is a true (and relevant)
          //     observation there — it is only the pass/fail probe values that are
          //     withheld.
          //
          // (b) WHY it is absent. `baselineAbsence` separates a failed request from a host
          //     that genuinely holds no row and from a row that is merely too old, and the
          //     controls below name the actual case instead of implying the endpoint was
          //     asked and had nothing to say.
          let baselineProbes: Map<string, string> | null = null;
          let baselineUnixtime: number | null = null;
          let baselineAbsence: 'present' | 'transport' | 'no-record' | 'stale' = 'present';
          let baselineStaleAgeDays: number | null = null;
          const baselineSettled = await baselinePromise;
          const baselineTransport = baselineSettled.ok ? null : classifyTransport(baselineSettled.error);
          try {
            const baselineRes = unwrap(baselineSettled);
            const row = (baselineRes.data?.data ?? null) as { unixtime?: unknown; compliance_data?: unknown } | null;
            const entries = Array.isArray(row?.compliance_data) ? row?.compliance_data as unknown[] : null;
            if (!entries) {
              baselineAbsence = 'no-record';
            } else {
              const map = new Map<string, string>();
              entries.forEach((entry) => {
                if (entry && typeof entry === 'object') {
                  const e = entry as { command_key?: unknown; output?: unknown };
                  map.set(String(e.command_key), String(e.output ?? '').trim());
                }
              });
              const ts = Number(row?.unixtime);
              baselineUnixtime = Number.isFinite(ts) && ts > 0 ? ts : null;
              const ageDays = baselineUnixtime !== null
                ? (Date.now() / 1000 - baselineUnixtime) / 86400
                : null;
              if (ageDays !== null && ageDays > BASELINE_FRESHNESS_DAYS) {
                baselineAbsence = 'stale';
                baselineStaleAgeDays = Math.round(ageDays);
              } else {
                baselineProbes = map;
              }
            }
          } catch {
            // baselineProbes stays null: every control that reads it records an
            // explicit not-assessed rather than a verdict. A 404 here is the endpoint
            // saying it holds no row for this host — a real absence — so it is recorded
            // as 'no-record' and not dressed up as a failed read.
            baselineAbsence = baselineTransport === 'no-record' ? 'no-record' : 'transport';
          }

          /**
           * Why this node's baseline record is unusable, phrased for the middle of a
           * not-assessed sentence. Only meaningful while `baselineProbes === null`.
           */
          const baselineUnavailableNote = baselineAbsence === 'transport'
            ? `the request for its Windows baseline record did not complete on this run${baselineTransport && TRANSPORT_TEXT[baselineTransport] ? ` — ${TRANSPORT_TEXT[baselineTransport]}` : ''}, which is a failed read rather than an absence of data on the endpoint`
            : baselineAbsence === 'stale'
              ? `the newest Windows baseline record Vajra holds for it was collected ${baselineStaleAgeDays} day(s) ago, beyond the ${BASELINE_FRESHNESS_DAYS}-day freshness bound both this register and the IRDAI register score against, so it is treated as absent rather than as a statement about the endpoint today`
              : 'Vajra holds no Windows baseline record for it at all';

          // Probe labels are the auditpol subcategory names the agent queries
          // (wsExtension/WindowsAgent/agent/powershell/main.go), so the reason
          // text names the exact setting an administrator has to turn on.
          const BASELINE_PROBE_LABELS: Record<string, string> = {
            '5': 'Special Logon',
            '6': 'Credential Validation',
            '9': 'Security Group Management',
            '10': 'User Account Management',
            '11': 'Process Creation',
            '12': 'Plug and Play Events',
            '14': 'Logon',
            '15': 'IPsec Driver',
            '16': 'Security System Extension',
            '17': 'Command line in process-creation events (ProcessCreationIncludeCmdLine)',
          };
          type BaselineReading = { key: string; label: string; raw: string; enabled: boolean | null };
          const readBaseline = (keys: string[]): BaselineReading[] => keys.map((key) => {
            const raw = baselineProbes?.get(key) ?? '';
            const v = raw.toLowerCase();
            return {
              key,
              label: BASELINE_PROBE_LABELS[key] ?? `baseline probe ${key}`,
              raw,
              enabled: v === 'true' ? true : v === 'false' ? false : null,
            };
          });
          const labelsOf = (readings: BaselineReading[]) => readings.map((r) => r.label).join(', ');
          const baselineMeasuredAt = baselineUnixtime !== null
            ? `measured ${fmtDateTime(baselineUnixtime)}`
            : 'measured at a time the record does not carry';
          const baselineAgeNote = baselineUnixtime !== null
            ? ` This reads the baseline probe run of ${fmtDateTime(baselineUnixtime)}, ${Math.max(0, Math.round((Date.now() / 1000 - baselineUnixtime) / 86400))} day(s) before this report.`
            : '';

          // Newest telemetry timestamps, filled in by the controls that read the
          // payloads carrying them and used by control 17 to measure whether this
          // endpoint is currently delivering live data.
          let profileUnixtime: number | null = null;
          let firewallSnapshotSec: number | null = null;

          // Point 1: Critical Node Marking (fleet-level)
          // Read from the node LIST endpoint: it is the only one that selects
          // `critical`. If the list is unavailable the control stays undefined
          // and falls through to the explicit not-assessed default below —
          // never a pass, never a fail.
          {
            if (Array.isArray(fleetNodesResolved)) {
              const totalCount = fleetNodesResolved.length;
              const criticalCount = fleetNodesResolved.filter((n) => n?.critical === true).length;
              if (totalCount > 0) {
                checks['1'] = criticalCount > 0
                  ? {
                    compliant: true,
                    reason: `${criticalCount} of ${totalCount} node${totalCount !== 1 ? 's' : ''} across the organization ${criticalCount === 1 ? 'is' : 'are'} currently marked critical in Vajra, enabling prioritised monitoring and incident response for high-value assets.`,
                    detail: `${criticalCount} / ${totalCount} nodes critical`,
                    fraction: { value: criticalCount, total: totalCount, label: 'critical' },
                  }
                  : {
                    ...notAssessed('Not assessed — Vajra provides built-in critical node marking, but no nodes are currently flagged, so the identification of critical assets could not be evaluated. Mark nodes handling sensitive financial data or critical services to record this control.', `0 / ${totalCount} nodes critical`),
                    fraction: { value: criticalCount, total: totalCount, label: 'critical' },
                  };
              }
            }
          }

          // Point 2: Software inventory (per-host)
          //
          // 2026-09-07: the failure path used to `// leave undefined`, which fell through
          // to the capability-statement fallback at the bottom of this function — "no
          // inventory was read back for this node during this run" — the SAME sentence a
          // host that answered with an empty list gets. A rate-limited read and an empty
          // inventory are not the same finding, and reporting them identically is what let
          // a degraded sweep be read afterwards as a smaller measured population.
          const programsSettled = await programsPromise;
          try {
            const res = unwrap(programsSettled);
            const data = (res.data ?? {}) as { programs?: unknown[]; deb?: unknown[]; rpm?: unknown[] };
            const isWindows = /windows/i.test(String(node.os_name ?? node.os_platform ?? ''));
            const winCount = Array.isArray(data.programs) ? data.programs.length : 0;
            const debCount = Array.isArray(data.deb) ? data.deb.length : 0;
            const rpmCount = Array.isArray(data.rpm) ? data.rpm.length : 0;
            const packageCount = isWindows ? winCount : debCount + rpmCount;
            const pkgLabel = isWindows ? 'program' : 'package';

            checks['2'] = packageCount > 0
              ? {
                compliant: true,
                reason: `Software inventory is present: ${packageCount} installed ${pkgLabel}${packageCount !== 1 ? 's' : ''} recorded for this node, enabling SBOM and vulnerability cross-referencing.`,
                detail: `${packageCount} ${pkgLabel}${packageCount !== 1 ? 's' : ''} recorded`,
              }
              : notAssessed(
                `Vajra queried the software inventory endpoint for this node but no ${isWindows ? 'Windows program' : 'deb/rpm package'} records came back, so the installed-software inventory on this node was not measured.`,
                'Not assessed — no software inventory returned',
              );
          } catch {
            checks['2'] = notAssessed(
              `Vajra could not read the installed-software inventory for this node.${transportNote(programsSettled) || ' The software inventory request failed before a usable response was returned.'}`,
              'Not assessed — software inventory read failed',
            );
          }

          // Full node details, for the hardware_* fields only (control 3).
          let detailNode: Record<string, unknown> = nodeAny;
          if (detailsPromise) {
            try {
              const res = unwrap(await detailsPromise);
              const raw = res.data?.data ?? res.data;
              if (raw && typeof raw === 'object') {
                detailNode = raw as Record<string, unknown>;
              }
            } catch {
              // fallback to provided node
            }
          }

          // `security_products` is attached by the node LIST endpoint only. The
          // node object handed to a sweep comes from /nodes/identifiers, which
          // does not carry it, and /nodes/details/{host} does not return it
          // either — so the AV/EDR controls previously had no reachable source
          // for it at all. Read it from the fleet list row for this host.
          const securityProductsRaw: unknown = Array.isArray(nodeAny.security_products)
            ? nodeAny.security_products
            : Array.isArray(fleetRow?.security_products)
              ? fleetRow?.security_products
              : undefined;

          // ---- Shared AV/EDR evidence for controls 6, 11 and 28 ----------------
          // Vajra IS the EDR/XDR product running on these endpoints: the agent
          // carries the kernel/eBPF telemetry, AV control, detection, alerting and
          // containment. Its own presence and a recent check-in are therefore a
          // direct MEASUREMENT of whether an EDR is installed and running here —
          // not a capability statement. Windows Security Center state is folded in
          // as ADDITIONAL third-party AV/EDR coverage only: Vajra does not register
          // itself with Security Center, so an empty or all-Off product list says
          // nothing about the EDR on this endpoint and must never, on its own, fail
          // a control that asks whether an EDR is present and running.
          const AGENT_CHECKIN_FRESHNESS_HOURS = 24; // Vajra platform default, not a regulator-mandated interval.
          const lastSeenRaw = node.last_seen ?? detailNode.last_seen ?? fleetRow?.last_seen;
          const lastSeenSec = (() => {
            const n = typeof lastSeenRaw === 'number' ? lastSeenRaw : parseInt(String(lastSeenRaw ?? '').trim(), 10);
            return Number.isFinite(n) && n > 0 ? n : null;
          })();
          const agentCheckinAgeHours = lastSeenSec !== null ? (Date.now() / 1000 - lastSeenSec) / 3600 : null;
          const describeAge = (hours: number) => (hours < 1
            ? `${Math.max(0, Math.round(hours * 60))} minute${Math.round(hours * 60) === 1 ? '' : 's'} ago`
            : `${Math.round(hours)} hour${Math.round(hours) === 1 ? '' : 's'} ago`);
          // Liveness is measured, never assumed: a node that has not checked in
          // inside the freshness window does not pass on agent evidence.
          const agentEvidence = (lastSeenSec !== null && agentCheckinAgeHours !== null && agentCheckinAgeHours <= AGENT_CHECKIN_FRESHNESS_HOURS)
            ? `The Vajra agent — the EDR/XDR product that runs on this endpoint and is the source of this report — is installed on this node and last checked in at ${fmtDateTime(lastSeenSec)} (${describeAge(agentCheckinAgeHours)}), inside Vajra's default ${AGENT_CHECKIN_FRESHNESS_HOURS}-hour agent check-in freshness window (a Vajra platform default, not a regulator-mandated interval).`
            : null;
          const agentStaleNote = lastSeenSec === null
            ? 'Vajra holds no agent check-in timestamp for this node, so the liveness of its own EDR agent on this endpoint could not be measured.'
            : `The Vajra agent on this node last checked in at ${fmtDateTime(lastSeenSec)}, outside Vajra's default ${AGENT_CHECKIN_FRESHNESS_HOURS}-hour check-in freshness window, so it could not be confirmed to be running now.`;

          const secProds = Array.isArray(securityProductsRaw)
            ? securityProductsRaw as Array<{ name?: string; state?: string }>
            : [];
          // The firewall entry is control 33's evidence, not AV/EDR evidence.
          const avProds = secProds.filter((p) => !/firewall/i.test(String(p.name ?? '')));
          const firewallProds = secProds.filter((p) => /firewall/i.test(String(p.name ?? '')));
          // State values are the Security Center strings ('On' / 'Off' / 'Snoozed'
          // / 'Expired') that controllers/general-graphs/defender_count.ts compares
          // against; a state string we do not recognise is not decoded into a verdict.
          const stateOf = (p: { state?: string }) => String(p.state ?? '').trim().toLowerCase();
          const activeAvProds = avProds.filter((p) => stateOf(p) === 'on');
          const inactiveAvProds = avProds.filter((p) => ['off', 'snoozed', 'expired'].includes(stateOf(p)));
          const undecodedAvProds = avProds.filter((p) => !activeAvProds.includes(p) && !inactiveAvProds.includes(p));
          const describeProds = (list: Array<{ name?: string; state?: string }>) =>
            list.map((p) => `${p.name ?? 'unnamed product'} (${String(p.state ?? '').trim() || 'no state reported'})`).join(', ');
          // The fleet list row is the only one of these sources that carries
          // os_name for a node handed in by a sweep.
          const osDescriptor = String(
            detailNode.os_name ?? detailNode.os_platform ?? fleetRow?.os_name ?? fleetRow?.os_platform ?? node.os_name ?? node.os_platform ?? '',
          );
          const isWindowsHost = /windows/i.test(osDescriptor);
          const notRegisteredNote = 'Vajra does not register itself with Windows Security Center, so that absence is not evidence about the EDR running on this endpoint.';
          const noThirdPartyNote = isWindowsHost
            ? `Windows Security Center lists no third-party antivirus/EDR product for this node. ${notRegisteredNote}`
            : 'This is not a Windows endpoint, so there is no Windows Security Center registry of antivirus products to read for additional third-party coverage.';
          const secCentreNote = !Array.isArray(securityProductsRaw)
            ? `No Windows Security Center product records were available for this node, so no additional third-party AV/EDR coverage could be read. ${notRegisteredNote}`
            : activeAvProds.length > 0
              ? `Windows Security Center additionally reports ${activeAvProds.length} of ${avProds.length} registered antivirus/EDR product${avProds.length !== 1 ? 's' : ''} in state "On": ${describeProds(activeAvProds)}.`
              : avProds.length === 0
                ? noThirdPartyNote
                : `Windows Security Center lists ${avProds.length} registered antivirus/EDR product${avProds.length !== 1 ? 's' : ''}, none of them reported On (${describeProds([...inactiveAvProds, ...undecodedAvProds])}). ${notRegisteredNote}`;

          // Point 3: Hardware inventory
          {
            const hwVendor = String(detailNode.hardware_vendor ?? '').trim();
            const hwModel = String(detailNode.hardware_model ?? '').trim();
            const hwCpu = String(detailNode.hardware_cpu_type ?? '').trim();
            const hwMemRaw = String(detailNode.hardware_physical_memory ?? '').trim();
            const hwCores = String(detailNode.hardware_cpu_logical_core ?? '').trim();
            const osName = String(detailNode.os_name ?? detailNode.os_platform ?? '').trim();
            const osBuild = String(detailNode.os_build ?? '').trim();
            const nonEmpty = (s: string) => s.length > 0 && s !== 'null' && s !== 'undefined';
            const populated = [hwVendor, hwModel, hwCpu, hwMemRaw, osName].filter(nonEmpty);
            if (populated.length >= 3) {
              const ramGb = (() => {
                const bytes = parseInt(hwMemRaw, 10);
                if (!Number.isFinite(bytes) || bytes <= 0) return null;
                return `${(bytes / 1073741824).toFixed(1)} GB RAM`;
              })();
              const parts = [
                hwVendor && hwModel ? `${hwVendor} ${hwModel}` : (hwVendor || hwModel || null),
                hwCpu || null,
                ramGb,
                hwCores ? `${hwCores} cores` : null,
                osName ? `${osName}${osBuild ? ` (${osBuild})` : ''}` : null,
              ].filter(Boolean) as string[];
              checks['3'] = {
                compliant: true,
                reason: `Hardware inventory is recorded in Vajra for this node: ${parts.join(', ')}. This satisfies the SEBI requirement for maintaining an up-to-date hardware asset record.`,
                detail: parts.slice(0, 2).join(' · ') || 'Hardware data present',
              };
            }
          }

      // Point 4: endpoint audit policy — evaluated from the Windows baseline
      // probes in the fallback section below, where the record is in hand.

      // Point 6: Vajra agent itself

      // Point 7: Strong password rules configured on this endpoint.
      //
      // security_profile_info is the secedit-derived Windows policy row this
      // function already fetches (POST /api/windows/profile_info). It carries the
      // measured numbers — minimum_password_length, password_complexity,
      // password_history_size, lockout_bad_count, maximum_password_age — and this
      // check used to fetch the row and then discard them.
      //
      // A zero is scored only where the row genuinely reports one: an absent or
      // non-numeric field is unmeasured and is never counted as a violation, and
      // when no field at all is readable the check falls back to the independent
      // net-accounts probe (baseline key 18) before recording not-assessed. The
      // 8-character minimum is a Vajra baseline, not a CSCRF-published number,
      // and the reason text says so.
      {
        const MIN_PASSWORD_LENGTH = 8; // Vajra baseline; CSCRF publishes no figure.
        const num = (v: unknown): number | null => {
          if (v === null || v === undefined || String(v).trim() === '') return null;
          const n = Number(v);
          return Number.isFinite(n) ? n : null;
        };
        const baselineMinLength = (() => {
          const raw = baselineProbes?.get('18') ?? '';
          if (raw === '') return null;
          const n = parseInt(raw, 10);
          return Number.isFinite(n) ? n : null;
        })();

        let profileRow: Record<string, unknown> | null = null;
        let profileFetchFailed = false;
        const profileSettled = await profilePromise;
        try {
          const securityProfile = unwrap(profileSettled);
          const profileRows = securityProfile.data?.status === 'Success' && Array.isArray(securityProfile.data.data)
            ? securityProfile.data.data as Array<Record<string, unknown>>
            : [];
          profileRow = profileRows.length > 0 ? profileRows[0] : null;
          profileUnixtime = num(profileRow?.unixtime);
        } catch {
          // The endpoint 404s when it holds no row for the host, which axios
          // rejects; that is missing evidence, not a measured negative.
          profileFetchFailed = true;
        }

        const mpl = num(profileRow?.minimum_password_length);
        const cx = num(profileRow?.password_complexity);
        const hist = num(profileRow?.password_history_size);
        const lock = num(profileRow?.lockout_bad_count);
        const maxAge = num(profileRow?.maximum_password_age);
        const readable = [mpl, cx, hist, lock].filter((v) => v !== null).length;

        // 2026-09-07: the length limb now falls back to the independent net-accounts
        // probe when the secedit profile row carries no readable
        // minimum_password_length, matching IRDAI 6's `profileLength ?? probeLength`.
        // Before this, SEBI tested violations against the profile value ALONE and used
        // the probe only to write a corroboration sentence, so a host whose profile row
        // reported complexity 1 and history 5 but no readable length, with the
        // net-accounts probe reporting 0, returned "Not assessed — incomplete password
        // policy row" in SEBI and a measured FAIL ("no minimum is enforced at all") in
        // IRDAI on the same evidence, the same day. A measured zero from an independent
        // probe on the endpoint is real evidence; the divergence is resolved in the
        // direction of using more of the evidence Vajra already holds, not less. The
        // reason text names which source the number came from so a reader can tell.
        const effectiveMinLength = mpl ?? baselineMinLength;
        const minLengthSource = mpl !== null
          ? 'the Windows security policy row'
          : 'the independent net-accounts probe in this node\'s Windows baseline record';

        const violations: string[] = [];
        if (effectiveMinLength !== null && effectiveMinLength < MIN_PASSWORD_LENGTH) {
          violations.push(`minimum password length is ${effectiveMinLength}${effectiveMinLength === 0 ? ' (no minimum is enforced at all)' : ''} per ${minLengthSource}, below Vajra's ${MIN_PASSWORD_LENGTH}-character baseline`);
        }
        if (cx !== null && cx !== 1) violations.push('password complexity is disabled');
        if (hist !== null && hist < 1) violations.push('password history is 0, so a previous password can be reused immediately');
        if (lock !== null && lock === 0) violations.push('the account lockout threshold is 0, so failed sign-in attempts never lock the account');
        const observed = [
          mpl !== null
            ? `minimum length ${mpl}`
            : effectiveMinLength !== null ? `minimum length ${effectiveMinLength} (net accounts probe)` : null,
          cx !== null ? `complexity ${cx === 1 ? 'enabled' : 'disabled'}` : null,
          hist !== null ? `history ${hist}` : null,
          lock !== null ? `lockout threshold ${lock}` : null,
          maxAge !== null ? `maximum age ${maxAge} days` : null,
        ].filter(Boolean).join(', ');
        const corroboration = baselineMinLength !== null && mpl !== null && baselineMinLength === mpl
          ? ` The independent net-accounts probe in this node's Windows baseline record agrees, also reporting a minimum password length of ${baselineMinLength}.`
          : '';

        if (readable > 0) {
          if (violations.length > 0) {
            checks['7'] = {
              compliant: false,
              reason: `The Windows security policy Vajra read from this node reports ${observed}. Measured against Vajra's password baseline, ${violations.join('; ')}.${corroboration} These are measured policy values from the endpoint, not an absence of data.`,
              detail: `Password policy: ${observed}`,
            };
          } else if (effectiveMinLength !== null && cx !== null && hist !== null && effectiveMinLength >= MIN_PASSWORD_LENGTH && cx === 1 && hist >= 1 && (lock === null || lock > 0)) {
            checks['7'] = {
              compliant: true,
              reason: `The Windows security policy Vajra read from this node reports ${observed}, which meets Vajra's password baseline (minimum length at least ${MIN_PASSWORD_LENGTH}, complexity enabled, password history enforced). The baseline is a Vajra default, not a regulator-published figure.`,
              detail: `Password policy: ${observed}`,
            };
          } else {
            checks['7'] = notAssessed(
              `The Windows security policy row for this node carries only part of the password policy (${observed}); the remaining values this control needs — ${[effectiveMinLength === null ? 'minimum length' : null, cx === null ? 'complexity' : null, hist === null ? 'password history' : null].filter(Boolean).join(', ')} — were not readable, so whether strong password rules are configured was not measured. Nothing measured on this node was in violation.`,
              'Not assessed — incomplete password policy row',
            );
          }
        } else if (baselineMinLength !== null) {
          // No usable profile row, but the net-accounts baseline probe ran.
          checks['7'] = baselineMinLength < MIN_PASSWORD_LENGTH
            ? {
              compliant: false,
              reason: `No Windows security policy row was readable for this node, so this verdict rests on the independent net-accounts probe in its Windows baseline record (${baselineMeasuredAt}), which reports a minimum password length of ${baselineMinLength}${baselineMinLength === 0 ? ' — no minimum is enforced at all' : `, below Vajra's ${MIN_PASSWORD_LENGTH}-character baseline`}. Password complexity, history and lockout could not be read for this node and are not part of this verdict.`,
              detail: `Minimum password length ${baselineMinLength} (net accounts)`,
            }
            : notAssessed(
              `No Windows security policy row was readable for this node. The net-accounts probe in its Windows baseline record reports a minimum password length of ${baselineMinLength}, which meets Vajra's ${MIN_PASSWORD_LENGTH}-character baseline, but password complexity, history and lockout could not be read at all, so whether strong password rules are configured was not measured.`,
              'Not assessed — only minimum length available',
            );
        } else if (profileFetchFailed) {
          checks['7'] = notAssessed(
            `Vajra holds no Windows security policy row for this node — the security profile request returned nothing — and no net-accounts baseline probe result either, so the password policy settings on this node were not measured.${transportNote(profileSettled)}`,
            'Not assessed — no security policy row',
          );
        } else {
          checks['7'] = notAssessed(
            'Vajra queried the security profile endpoint for this node but the response carried no readable password policy values, and no net-accounts baseline probe result is held either, so the password policy settings on this node were not measured.',
            'Not assessed — no readable password policy values',
          );
        }
      }

      // Point 8: are the firewall rules actually in force on this endpoint
      // scoped to specific addresses, or do they admit any remote address?
      //
      // The firewall snapshot Vajra already fetches for control 33 carries the
      // rule CONTENT — direction, action, enabled, remote_addresses, local_ports
      // — and it was previously reduced to a count of enabled rules. An enabled
      // inbound Allow rule whose remote address is "*"/"Any" admits traffic from
      // every address on the network, which is the opposite of "only approved IP
      // addresses are allowed", so those rules are the measurement here.
      //
      // Honest limits, stated in the reason: Vajra holds NO organisation-approved
      // IP/port list to compare against, so this measures the SCOPE of the rules
      // rather than approval of the individual addresses; and stock Windows ships
      // wildcard inbound Allow rules (mDNS, network discovery, delivery
      // optimisation), so a default installation fails this control. A rule whose
      // direction/action/remote address cannot be decoded is not scored.
      {
        const firewallSettled = await firewallPromise;
        try {
          const fwRes = unwrap(firewallSettled);
          const fwPayload = fwRes.data as { status?: string; data?: unknown[] } | null;
          const fwRows = fwPayload?.status === 'Success' && Array.isArray(fwPayload.data)
            ? fwPayload.data as Array<Record<string, unknown>>
            : [];
          const snapshotSec = fwRows.reduce<number | null>((acc, row) => {
            const n = Number(row?.unixtime);
            return Number.isFinite(n) && n > 0 && (acc === null || n > acc) ? n : acc;
          }, null);
          firewallSnapshotSec = snapshotSec;

          const str = (v: unknown) => String(v ?? '').trim().toLowerCase();
          const inboundAllow = fwRows.filter((row) => str(row.direction) === 'in'
            && str(row.action) === 'allow'
            && Number(row.enabled) === 1);
          const undecodableRules = fwRows.filter((row) => !['in', 'out'].includes(str(row.direction))
            || !['allow', 'block'].includes(str(row.action)));
          // An absent remote address is unmeasured, not a wildcard: only the
          // explicit any-address values are counted as unscoped.
          const isWildcard = (row: Record<string, unknown>) => ['*', 'any'].includes(str(row.remote_addresses));
          const unscopedAddress = (row: Record<string, unknown>) => row.remote_addresses === null
            || row.remote_addresses === undefined
            || str(row.remote_addresses) === '';
          const wildcardRules = inboundAllow.filter(isWildcard);
          const undecodableScope = inboundAllow.filter(unscopedAddress);
          const describeRule = (row: Record<string, unknown>) => {
            const name = String(row.name ?? row.app_name ?? 'unnamed rule').trim() || 'unnamed rule';
            const ports = String(row.local_ports ?? '').trim();
            return `${name}${ports ? ` (local ports ${ports})` : ''}`;
          };
          const snapshotNote = snapshotSec !== null ? ` Firewall snapshot taken ${fmtDateTime(snapshotSec)}.` : '';
          const noBaselineNote = 'Vajra holds no organisation-approved IP or port list for this node, so this measures whether the enabled inbound Allow rules are scoped to specific addresses at all — it does not certify the addresses that are scoped as approved.';

          if (fwRows.length === 0) {
            checks['8'] = notAssessed(
              'Vajra read back no firewall rule records for this node, so the allow/deny posture actually configured on it was not measured. An empty rule inventory is not evidence that traffic is unrestricted.',
              'Not assessed — no firewall rule records',
            );
          } else if (undecodableRules.length === fwRows.length) {
            checks['8'] = notAssessed(
              `Vajra holds ${fwRows.length} firewall rule record${fwRows.length !== 1 ? 's' : ''} for this node, but none carries a direction and action it can decode, so the allow/deny posture was not measured.`,
              'Not assessed — undecodable firewall rules',
            );
          } else if (wildcardRules.length > 0) {
            const examples = wildcardRules.slice(0, 5).map(describeRule).join('; ');
            checks['8'] = {
              compliant: false,
              reason: `${wildcardRules.length} of ${inboundAllow.length} enabled inbound Allow rule${inboundAllow.length !== 1 ? 's' : ''} on this node accept traffic from any remote address ("*"/"Any") rather than from specific approved addresses. Examples: ${examples}${wildcardRules.length > 5 ? `, and ${wildcardRules.length - 5} more` : ''}. ${noBaselineNote} Note that stock Windows ships several such wildcard inbound Allow rules (mDNS, network discovery, delivery optimisation), so an unmodified endpoint fails this control on its defaults.${snapshotNote}`,
              detail: `${wildcardRules.length} / ${inboundAllow.length} inbound allow rules accept any address`,
            };
          } else if (inboundAllow.length === 0) {
            checks['8'] = {
              compliant: true,
              reason: `No enabled inbound Allow rule is present in the firewall snapshot Vajra holds for this node (${fwRows.length} rule record${fwRows.length !== 1 ? 's' : ''} in total), so no inbound traffic is admitted by an unscoped rule. ${noBaselineNote}${snapshotNote}`,
              detail: `0 enabled inbound allow rules of ${fwRows.length}`,
            };
          } else if (undecodableScope.length === inboundAllow.length) {
            checks['8'] = notAssessed(
              `All ${inboundAllow.length} enabled inbound Allow rule${inboundAllow.length !== 1 ? 's' : ''} on this node came back without a readable remote-address scope, so whether they are limited to approved addresses was not measured.`,
              'Not assessed — no readable remote-address scope',
            );
          } else {
            checks['8'] = {
              compliant: true,
              reason: `Every one of the ${inboundAllow.length - undecodableScope.length} enabled inbound Allow rule${inboundAllow.length - undecodableScope.length !== 1 ? 's' : ''} Vajra could read on this node is scoped to specific remote addresses or to the local subnet; none admits traffic from any address. ${noBaselineNote}${undecodableScope.length > 0 ? ` ${undecodableScope.length} further inbound Allow rule${undecodableScope.length !== 1 ? 's' : ''} carried no readable remote-address scope and ${undecodableScope.length !== 1 ? 'were' : 'was'} not scored.` : ''}${snapshotNote}`,
              detail: `${inboundAllow.length - undecodableScope.length} scoped inbound allow rule${inboundAllow.length - undecodableScope.length !== 1 ? 's' : ''}`,
            };
          }
        } catch {
          checks['8'] = notAssessed(
            `Vajra read back no firewall rule inventory for this node — the request returned no rules — so the allow/deny posture configured on it was not measured. This is the expected result on a non-Windows endpoint, for which Vajra collects no Windows firewall rule snapshot.${transportNote(firewallSettled)}`,
            'Not assessed — no firewall rule inventory returned',
          );
        }
      }

      // Point 9: malicious IP/domain blocking — see the not-assessed default
      // below. Vajra holds no per-endpoint threat-intelligence blocklist state.

      // Points 10 and 16: alerts Vajra itself raised for this node.
      //
      // An alert row is a record of an alert the platform generated automatically
      // for THIS endpoint, so its existence is a measurement, not a capability
      // statement. Its absence is not: a node with no alerts cannot be told apart
      // from a node on which nothing alertable happened, so neither control can
      // ever fail here.
      {
        let alertRows: Array<Record<string, unknown>> | null = null;
        const alertsSettled = await deviceAlertsPromise;
        try {
          const alertsRes = unwrap(alertsSettled);
          const payload = alertsRes.data as { success?: boolean; alerts?: unknown[] } | null;
          alertRows = Array.isArray(payload?.alerts) ? payload?.alerts as Array<Record<string, unknown>> : null;
        } catch {
          alertRows = null;
        }
        const typeOf = (a: Record<string, unknown>) => String(a.alert_type ?? '').trim();
        const tsOf = (a: Record<string, unknown>) => {
          const n = Number(a.unixtime);
          return Number.isFinite(n) && n > 0 ? n : null;
        };
        const newestOf = (list: Array<Record<string, unknown>>) => list.reduce<number | null>((acc, a) => {
          const t = tsOf(a);
          return t !== null && (acc === null || t > acc) ? t : acc;
        }, null);
        const windowNote = `This reads the most recent ${DEVICE_ALERT_MAX_ROWS} alerts Vajra holds for this node, not its entire alert history.`;

        // Point 10: "USB and other removable-device connection events on this system
        // are logged for administrator review."
        //
        // 2026-09-07 (second change today, and a correction of the first): the verdict is
        // now the Windows Plug and Play Events advanced-audit subcategory (baseline probe
        // key '12'), the same probe control 24 already reads and the same one IRDAI
        // control 21 — "Removable media (USB, external drives) usage logs are collected
        // and reviewed" — answers from.
        //
        // Earlier today this control was moved from an alert-HISTORY check to a live
        // websocket CAPABILITY probe: it passed when the removable-device subsystem
        // returned a decodable status object. That fixed the activity-gating problem of
        // the alert-history version but did not fix the evidence mismatch, and the WHY
        // comment it carried conceded the mismatch it then relied on — those device
        // events come from the agent's own background poll-and-diff loop
        // (backend/src/websocket/node.ts usb_device_push), which is decoupled from
        // Windows' own audit log. A live subsystem response is evidence that a probe
        // answered, not that connection events are being WRITTEN anywhere for an
        // administrator to review, which is what the label claims. It also disagreed with
        // IRDAI 21 by construction: any host with PnP auditing Off whose agent websocket
        // answers normally scored PASS here and a measured FAIL there — and key 10 was
        // measured on all 13 Windows hosts in org snapshot 57, so that pass was being
        // published fleet-wide.
        //
        // Plug and Play Events is the only source Vajra holds that speaks to "logged": it
        // is the Windows subcategory that writes an event when a removable device is
        // connected. No new evidence source is introduced — this row is already fetched
        // for controls 4, 5 and 24. The live probe is kept as supporting detail in the
        // reason text, never as the verdict.
        {
          const [pnpAudit] = readBaseline(['12']);
          let liveProbeNote = '';
          try {
            const usbStatus = unwrap((await wsPromise).usb);
            const usbHasRecognisedShape = !!usbStatus && typeof usbStatus === 'object'
              && ('usb_storage_policy' in usbStatus || 'status' in usbStatus || 'enabled' in usbStatus || 'pnp_devices' in usbStatus || 'connected_devices' in usbStatus);
            liveProbeNote = usbHasRecognisedShape
              ? ' Separately, Vajra\'s own removable-device monitoring subsystem answered live on this node during this sweep, so the agent-side device poll is healthy here. That is supporting detail only: the agent poll-and-diff loop is decoupled from the Windows audit log and does not decide this verdict.'
              : ' Vajra\'s own removable-device monitoring subsystem did not return a recognisable status on this node during this sweep; that is reported as context and does not decide this verdict either way.';
          } catch {
            liveProbeNote = ' Vajra\'s own removable-device probe did not complete on this node during this sweep; that is reported as context and does not decide this verdict either way.';
          }

          if (pnpAudit.enabled === true) {
            checks['10'] = {
              compliant: true,
              reason: `Plug and Play Events auditing is enabled on this node (${baselineMeasuredAt}), so Windows writes an event to this endpoint's Security log when a USB or other removable device is connected, and those events are available for administrator review. Vajra measures that this logging is switched on; it does not ingest the resulting Security log records from any endpoint on this fleet, so no claim is made about the events' contents or about how they are reviewed.${liveProbeNote}${baselineAgeNote}`,
              detail: 'Plug and Play Events auditing On',
            };
          } else if (pnpAudit.enabled === false) {
            checks['10'] = {
              compliant: false,
              reason: `Plug and Play Events auditing is Off on this node (${baselineMeasuredAt}), so connecting a USB or other removable device writes no event to this endpoint's Security log and there is nothing for an administrator to review. This is a measured setting read from the endpoint's audit policy, not missing data. Enable Success and Failure auditing for Detailed Tracking > Audit PNP Activity under Windows Advanced Audit Policy Configuration.${liveProbeNote}${baselineAgeNote}`,
              detail: 'Plug and Play Events auditing Off',
            };
          } else if (baselineProbes === null) {
            checks['10'] = notAssessed(
              `Not assessed — ${baselineUnavailableNote}, so whether removable-device connection events are logged on this endpoint was not measured.${liveProbeNote}`,
              baselineAbsence === 'transport'
                ? 'Not assessed — baseline audit-policy read failed'
                : baselineAbsence === 'stale'
                  ? 'Not assessed — baseline audit-policy record too old'
                  : 'Not assessed — no baseline audit-policy record',
            );
          } else {
            checks['10'] = notAssessed(
              `Not assessed — the Plug and Play Events auditing probe returned no usable value for this node, so whether removable-device connection events are logged could not be measured. An empty probe result is not a measured negative.${liveProbeNote}`,
              'Not assessed — Plug and Play auditing probe returned no value',
            );
          }
        }

        // Point 16: automated alerting for suspicious or unauthorized activity.
        //
        // 2026-09-07: bounded to ALERT_EVIDENCE_WINDOW_DAYS. This control used to pass on
        // `alertRows.length > 0` with no date filter of any kind — its only temporal
        // qualifier was the row-count caveat below, which is not a recency test — so a
        // host whose newest alert was eighteen months old was certified as having working
        // automated alerting, while IRDAI control 13 returned not-assessed for that same
        // host because it bounds the identical alert rows to 90 days. A pass asserting
        // that automated alerting IS RUNNING cannot rest on an alert from a year and a
        // half ago, so the bounded reading is adopted here and the constant is shared.
        //
        // The asymmetry is deliberate and unchanged: an alert row raised for this endpoint
        // is a measurement, its absence is not — Vajra cannot tell an endpoint with
        // nothing to alert on from one where alerting is not reaching it — so silence,
        // inside the window or outside it, is never scored as a failure.
        const alertScopeNote = 'Scope limit: the alert types Vajra raises cover malware detection, removable media, process activity and patch actions. None of them covers failed authentication or unauthorized access attempts, because no Windows Security event-log data reaches Vajra from any endpoint on this fleet.';
        const alertCutoffSec = Math.floor(Date.now() / 1000) - ALERT_EVIDENCE_WINDOW_DAYS * 86400;
        const alertsInWindow = (alertRows ?? []).filter((a) => {
          const t = tsOf(a);
          return t !== null && t >= alertCutoffSec;
        });
        if (alertRows === null) {
          checks['16'] = notAssessed(
            `Vajra could not read the alert history for this node, so whether automated alerts are generated for it was not measured.${transportNote(alertsSettled)} ${alertScopeNote}`,
            'Not assessed — alert history unavailable',
          );
        } else if (alertsInWindow.length > 0) {
          const counts = new Map<string, number>();
          alertsInWindow.forEach((a) => {
            const t = typeOf(a) || 'untyped alert';
            counts.set(t, (counts.get(t) ?? 0) + 1);
          });
          const newest = newestOf(alertsInWindow);
          const breakdown = Array.from(counts.entries()).map(([t, n]) => `${t} (${n})`).join(', ');
          checks['16'] = {
            compliant: true,
            reason: `Vajra automatically generated ${alertsInWindow.length} alert${alertsInWindow.length !== 1 ? 's' : ''} for this node in the last ${ALERT_EVIDENCE_WINDOW_DAYS} days: ${breakdown}${newest !== null ? `, the most recent on ${fmtDateTime(newest)}` : ''}. Those records are evidence that automated alerting ran on this endpoint inside the evidence window. ${alertScopeNote} ${windowNote}`,
            detail: `${alertsInWindow.length} automated alert${alertsInWindow.length !== 1 ? 's' : ''} in ${ALERT_EVIDENCE_WINDOW_DAYS} days`,
          };
        } else if (alertRows.length > 0) {
          const newest = newestOf(alertRows);
          checks['16'] = notAssessed(
            `Vajra holds ${alertRows.length} alert${alertRows.length !== 1 ? 's' : ''} for this node but none inside the last ${ALERT_EVIDENCE_WINDOW_DAYS} days${newest !== null ? ` (the most recent dates from ${fmtDateTime(newest)})` : ''}, so whether automated alerting is running on this endpoint NOW was not measured. An alert older than the evidence window is not evidence that alerting is live, and alert silence is not evidence that it has stopped. ${alertScopeNote} ${windowNote}`,
            'Not assessed — no alerts inside the evidence window',
          );
        } else {
          checks['16'] = notAssessed(
            `No automatically generated alert is recorded for this node, which cannot be distinguished from a node on which nothing alertable occurred, so automated alerting was not measured. ${alertScopeNote}`,
            'Not assessed — no alerts recorded for this node',
          );
        }
      }

          // Point 11: EDR (Endpoint Detection & Response) Software Present
          // Vajra IS the EDR on this endpoint, so the agent's own presence and a
          // recent check-in answer exactly the question this control asks and are
          // used as the primary measurement (see the shared AV/EDR evidence block
          // above). Windows Security Center products in state 'On' are recorded as
          // ADDITIONAL coverage; because Vajra does not register itself with
          // Security Center, an empty or all-Off product list never fails this
          // control on its own. With neither source determinable, not assessed.
          {
            if (agentEvidence) {
              checks['11'] = {
                compliant: true,
                reason: `${agentEvidence} An EDR solution is therefore installed and actively running on this endpoint. ${secCentreNote}`,
                detail: activeAvProds.length > 0
                  ? `Vajra EDR agent live · ${activeAvProds.length} / ${avProds.length} AV/EDR product${avProds.length !== 1 ? 's' : ''} On`
                  : 'Vajra EDR agent installed and checked in',
              };
            } else if (activeAvProds.length > 0) {
              checks['11'] = {
                compliant: true,
                reason: `Windows Security Center reports ${activeAvProds.length} of ${avProds.length} antivirus/EDR product${avProds.length !== 1 ? 's' : ''} in state "On" on this node: ${describeProds(activeAvProds)}. A product reported On is actively running, satisfying the SEBI requirement for an installed and running EDR solution. ${agentStaleNote}`,
                detail: `${activeAvProds.length} / ${avProds.length} AV/EDR product${avProds.length !== 1 ? 's' : ''} On`,
              };
            } else {
              // Deliberately NOT a failure: with no recent agent check-in nothing
              // about this endpoint's current EDR state was observed, and the
              // Security Center list alone cannot establish its absence.
              checks['11'] = notAssessed(
                `${agentStaleNote} ${secCentreNote} With no recent Vajra agent check-in and no third-party antivirus/EDR product reported On, whether an EDR solution is installed and actively running on this node was not measured. This is not evidence that no EDR is present.`,
                'Not assessed — no recent agent check-in, no AV/EDR product On',
              );
            }
          }

      // Point 12: Removable Media Data Recovery Blocked
          try {
            const usbStatus = unwrap((await wsPromise).usb);
            // 'enabled' / 'Enabled' means removable storage is PERMITTED on the node,
            // so the compliant state for this control is the restricted (disabled) one.
            //
            // Decoding order matters. The Windows payload
            // (NodesViewUsbControl.tsx WindowsUsbStatus) is
            // { enabled, status: 'enabled' | 'disabled' | 'unknown', registry_start }
            // and it reports `enabled: false` alongside `status: 'unknown'` when the
            // registry value could not be read at all. NodesViewUsbControl derives
            // its own verdict from `status` ONLY, precisely so that 'unknown' is
            // neither enabled nor disabled; scoring `enabled === false` as an equal
            // disjunct turned every unreadable node into a measured PASS. `status`
            // therefore decides whenever the payload carries it, and the boolean is
            // consulted only when there is no status field (the non-Windows
            // removableDevice shape, which reports an explicit usb_storage_policy).
            const usbPolicy = String(usbStatus?.usb_storage_policy ?? '').trim().toLowerCase();
            const usbStatusField = typeof usbStatus?.status === 'string'
              ? usbStatus.status.trim().toLowerCase()
              : null;
            const isUsbRestricted = usbPolicy === 'disabled'
              || (usbPolicy === '' && (usbStatusField !== null
                ? usbStatusField === 'disabled'
                : usbStatus?.enabled === false));
            const isUsbPermitted = usbPolicy === 'enabled'
              || (usbPolicy === '' && (usbStatusField !== null
                ? usbStatusField === 'enabled'
                : usbStatus?.enabled === true));
            debugLog('USB status for compliance:', { usbStatus, isUsbRestricted, isUsbPermitted });

            const usbDetail = usbStatus
              ? (usbStatus.usb_storage_policy
                ?? usbStatus.status
                ?? (usbStatus.enabled === false ? 'disabled' : usbStatus.enabled === true ? 'enabled' : 'unknown'))
              : 'USB status unavailable';

            if (isUsbRestricted) {
              checks['12'] = {
                compliant: true,
                reason: 'Vajra queried the live removable-storage policy on this node and found it set to blocked, so removable storage is restricted at the endpoint. On Windows this reads the USBSTOR removable-storage driver start type; a restriction imposed only by Group Policy or a third-party DLP agent is not what was read here.',
                detail: usbDetail,
              };
            } else if (isUsbPermitted) {
              checks['12'] = {
                compliant: false,
                reason: 'Vajra queried the live removable-storage policy on this node and found removable storage permitted. On Windows this measures the USBSTOR removable-storage driver start type, which is set to start, so the endpoint will mount removable storage. Vajra does not read Group Policy removable-storage denials or third-party DLP state, so a restriction imposed by one of those alone would not appear here.',
                detail: usbDetail,
              };
            } else {
              checks['12'] = notAssessed(
                usbStatusField === 'unknown'
                  ? 'The agent returned a USB status of "unknown" for this node, meaning the removable-storage registry policy could not be read on the endpoint, so whether removable media is restricted was not measured. "Unknown" is not evidence that removable storage is blocked.'
                  : 'Vajra could not determine the removable storage policy for this node: the USB status response did not report a usable enabled/disabled state.',
                usbStatusField === 'unknown' ? 'USB status reported as unknown' : 'USB status unavailable',
              );
            }
          } catch {
            checks['12'] = notAssessed(
              'Vajra could not retrieve live USB telemetry for this node. The USB status query failed before a usable response was returned.',
              'USB status query failed',
            );
          }
      // Point 13: unnecessary services/ports — not measurable without an
      // approved-services baseline; see the not-assessed default below.
      {
        // TODO: USB API
      }

      // Point 14: ??

          // Point 15: Patch Management — are OS patches applied within the SLA?
          //
          // This used to read the latest-update endpoint, which returns exactly
          // ONE row: the newest windows_update_history row by Windows event date.
          // On this fleet that row is a Microsoft Defender signature refresh on
          // most hosts, which the check then correctly refused to score — so the
          // control was not assessed on most nodes, and on the rest it scored
          // whatever single record happened to be newest (a failed Microsoft
          // Store package failed a host whose OS patching was current).
          //
          // It now reads the FULL deduped update history this function already
          // fetches for control 25, and measures the operating-system quality and
          // security updates in it:
          //   * Defender signature / antimalware-platform / definition rows are
          //     excluded in either direction — signature freshness is not patch
          //     currency.
          //   * An update that has NEVER recorded a success, whose most recent
          //     attempt failed or aborted, and whose most recent attempt is more
          //     recent than the newest successful quality update, is outstanding.
          //     The last clause is the supersession guard and is load-bearing: an
          //     old KB that a later cumulative superseded is not an open failure,
          //     and flagging it would be a fabricated failure.
          //   * 'InProgress' is neither a success nor a failure and is not scored.
          // The 30-day threshold is a Vajra platform default, not a regulator
          // mandated deadline, and the reason text says so.
          {
            const isWindows = /windows/i.test(osDescriptor);
            if (!isWindows) {
              checks['15'] = notAssessed(
                'This is not a Windows endpoint, so the Windows Update record this check reads does not exist for it and patch currency on this node was not measured.',
                'Not assessed — not a Windows endpoint',
              );
            } else {
              try {
                const historyRes = unwrap(await updateHistoryPromise);
                const historyPayload = historyRes.data as { status?: string; data?: unknown[] } | null;
                const historyRows = historyPayload?.status === 'Success' && Array.isArray(historyPayload.data)
                  ? historyPayload.data as Array<Record<string, unknown>>
                  : [];

                const titleOf = (row: Record<string, unknown>) => String(row.title ?? '').trim();
                const codeOf = (row: Record<string, unknown>) => String(row.result_code ?? '').trim().toLowerCase();
                const dateOf = (row: Record<string, unknown>) => {
                  const n = Number(String(row.date ?? '').trim());
                  return Number.isFinite(n) && n > 0 ? n : null;
                };
                const kbOf = (row: Record<string, unknown>) => (titleOf(row).match(/KB\d{5,}/i)?.[0] || titleOf(row) || 'untitled update');
                const SIGNATURE_RE = /security intelligence update|antimalware platform|definition update/i;
                const QUALITY_RE = /cumulative update|servicing stack|security update|\.net framework|feature update|^windows \d+, version/i;

                const substantive = historyRows.filter((row) => !SIGNATURE_RE.test(titleOf(row)));
                const quality = substantive.filter((row) => QUALITY_RE.test(titleOf(row)));
                const lastOkSec = quality
                  .filter((row) => codeOf(row) === 'succeeded')
                  .reduce<number | null>((acc, row) => {
                    const d = dateOf(row);
                    return d !== null && (acc === null || d > acc) ? d : acc;
                  }, null);

                const attemptsByUpdate = new Map<string, Array<Record<string, unknown>>>();
                quality.forEach((row) => {
                  const id = String(row.update_id ?? '').trim() || titleOf(row);
                  const list = attemptsByUpdate.get(id);
                  if (list) list.push(row);
                  else attemptsByUpdate.set(id, [row]);
                });
                const outstanding: Array<{ label: string; when: number | null }> = [];
                attemptsByUpdate.forEach((attempts) => {
                  if (attempts.some((row) => codeOf(row) === 'succeeded')) return;
                  const newest = attempts.reduce((best, row) => {
                    const d = dateOf(row);
                    const bd = dateOf(best);
                    return d !== null && (bd === null || d > bd) ? row : best;
                  }, attempts[0]);
                  const code = codeOf(newest);
                  if (code !== 'failed' && code !== 'aborted') return;
                  const when = dateOf(newest);
                  // Supersession guard — see the block comment above.
                  if (lastOkSec !== null && (when === null || when <= lastOkSec)) return;
                  outstanding.push({ label: kbOf(newest), when });
                });

                const nowSec = Math.floor(Date.now() / 1000);
                if (historyRows.length === 0) {
                  checks['15'] = notAssessed(
                    'Vajra read back no Windows Update history for this node, so whether patches are applied within the SLA was not measured. An empty update history is not evidence that the node is unpatched.',
                    'Not assessed — no Windows Update history',
                  );
                } else if (outstanding.length > 0) {
                  const newestFailure = outstanding.reduce<number | null>((acc, o) => (
                    o.when !== null && (acc === null || o.when > acc) ? o.when : acc
                  ), null);
                  const names = outstanding.slice(0, 8).map((o) => o.label).join(', ');
                  checks['15'] = {
                    compliant: false,
                    reason: `${outstanding.length} operating-system quality/security update${outstanding.length !== 1 ? 's have' : ' has'} never installed successfully on this node and ${outstanding.length !== 1 ? 'their' : 'its'} most recent attempt failed: ${names}${outstanding.length > 8 ? `, and ${outstanding.length - 8} more` : ''}${newestFailure !== null ? `. The most recent failure was recorded on ${fmtDateTime(newestFailure)}` : ''}. Updates already superseded by a later successful cumulative are excluded, so ${outstanding.length !== 1 ? 'these are' : 'this is'} still outstanding. Unresolved failed patches leave known vulnerabilities unmitigated.`,
                    detail: `${outstanding.length} failed OS update${outstanding.length !== 1 ? 's' : ''} outstanding`,
                  };
                } else if (lastOkSec !== null) {
                  const daysOld = (nowSec - lastOkSec) / 86400;
                  checks['15'] = daysOld <= 30
                    ? {
                      compliant: true,
                      reason: `The newest operating-system quality/security update on this node installed successfully on ${fmtDateTime(lastOkSec)} (${Math.round(daysOld)} day${Math.round(daysOld) !== 1 ? 's' : ''} ago), within Vajra's default 30-day patch recency threshold, and no OS update is recorded as failing without a later success. The threshold is a Vajra platform default, not a regulator-mandated deadline. Microsoft Defender signature refreshes are excluded from this measurement.`,
                      detail: `Last OS patch ${Math.round(daysOld)} day${Math.round(daysOld) !== 1 ? 's' : ''} ago`,
                    }
                    : {
                      compliant: false,
                      reason: `The newest operating-system quality/security update on this node installed successfully on ${fmtDateTime(lastOkSec)}, ${Math.round(daysOld)} days ago — beyond Vajra's default 30-day patch recency threshold, which is a Vajra platform default rather than a regulator-mandated deadline. Microsoft Defender signature refreshes are excluded from this measurement, so recent signature activity does not offset it.`,
                      detail: `${Math.round(daysOld)} days since last OS patch`,
                    };
                } else {
                  checks['15'] = notAssessed(
                    `The Windows Update history Vajra holds for this node (${historyRows.length} record${historyRows.length !== 1 ? 's' : ''}) contains no operating-system quality-update record — only Defender signature refreshes and application packages — so patch currency was not measured. Signature freshness is not evidence of patch currency in either direction.`,
                    'Not assessed — no OS quality-update record',
                  );
                }
              } catch {
                checks['15'] = notAssessed(
                  'Vajra could not fetch the Windows Update history for this node — the request failed before any update data was returned — so patch currency on this node was not measured.',
                  'Not assessed — update history fetch failed',
                );
              }
            }
          }

      // Point 17: "Critical systems are continuously monitored in real time for threats
      // and incidents."
      //
      // 2026-09-07: scoped to nodes flagged critical, to end a doctrine violation with
      // IRDAI control 14. The two controls carry that label word for word, but SEBI 17
      // answered it as telemetry recency over EVERY host while IRDAI 14 answered it only
      // for nodes with `critical = true`, and the two used different verdict
      // vocabularies. On one fleet on one day that produced three constructible
      // disagreements: (a) a non-critical host with live telemetry — SEBI PASS, IRDAI
      // not-assessed; (b) a critical host with a live agent but only one fresh telemetry
      // family — SEBI not-assessed, IRDAI PASS; (c) a critical host whose agent has gone
      // quiet — SEBI not-assessed (it could never fail), IRDAI a published FAIL. Case (a)
      // is exactly why org snapshots 57 and 25 reported 7 and 1 eligible hosts for the
      // same question. Neither number was arithmetically wrong; they were answers to two
      // different questions printed under one label.
      //
      // The reading applied to both registers is the CONJUNCTION of the two limbs, since
      // the control names critical systems AND real-time monitoring:
      //   * scope  — nodes flagged critical (IRDAI's limb; it is what makes the control's
      //     subject correct — "critical systems", not "every endpoint");
      //   * measure — telemetry-family recency (SEBI's limb; the arrival of monitoring
      //     data is stronger evidence that monitoring is happening than an agent
      //     check-in, which only says the agent is alive).
      // Vocabulary is agreed as ABSTAIN, not fail: telemetry that stops arriving is what
      // a node that is switched off or offline looks like, and the standing rule in this
      // codebase is that absent evidence is not-assessed rather than a measured negative.
      // IRDAI 14's critical-and-stale FAIL branch is the one that has to move to match.
      {
        const nowSec = Math.floor(Date.now() / 1000);
        const windowSec = AGENT_CHECKIN_FRESHNESS_HOURS * 3600;
        const families: Array<{ name: string; at: number | null }> = [
          { name: 'Windows security policy profile', at: profileUnixtime },
          { name: 'firewall rule snapshot', at: firewallSnapshotSec },
          { name: 'Windows baseline probe run', at: baselineUnixtime },
        ];
        const fresh = families.filter((f) => f.at !== null && nowSec - f.at <= windowSec);
        const stale = families.filter((f) => f.at !== null && nowSec - f.at > windowSec);
        const absent = families.filter((f) => f.at === null);
        // The designation is carried by /api/nodes/list only; /nodes/identifiers and
        // /nodes/details/{host} do not select it. Where it could not be read the control
        // is not assessed rather than assumed non-critical — the same precedence and the
        // same three-way test IRDAI 14 applies.
        const criticalRaw = fleetRow?.critical ?? detailNode.critical ?? nodeAny.critical;
        const isCritical = criticalRaw === true || criticalRaw === 'true' || criticalRaw === 1;
        const isNotCritical = criticalRaw === false || criticalRaw === 'false' || criticalRaw === 0;

        if (!isCritical && !isNotCritical) {
          checks['17'] = notAssessed(
            'Vajra did not read back this node\'s critical-system designation on this run, so whether it is a critical system under continuous real-time monitoring could not be measured. An unreadable designation is not evidence that the node is unmonitored.',
            'Not assessed — critical designation not read back',
          );
        } else if (isNotCritical) {
          checks['17'] = notAssessed(
            'This node is not designated a critical system in Vajra, so this control — which is about how CRITICAL systems are monitored — does not resolve for it. Marking the endpoints that handle sensitive data or essential services as critical is what makes this control measurable on them. Telemetry arrival on this node is still measured and reported by the monitoring controls that are not scoped to critical assets.',
            'Not designated a critical system — not assessed',
          );
        } else if (agentEvidence && fresh.length >= 2) {
          checks['17'] = {
            compliant: true,
            reason: `This node is designated a critical system in Vajra. ${agentEvidence} Alongside that check-in, ${fresh.length} independent telemetry famil${fresh.length !== 1 ? 'ies' : 'y'} delivered data from this endpoint inside the same ${AGENT_CHECKIN_FRESHNESS_HOURS}-hour window: ${fresh.map((f) => `${f.name} (${fmtDateTime(f.at as number)})`).join(', ')}. This critical node is therefore actively delivering live telemetry to Vajra. What is measured is the arrival of monitoring data, not the quality of the detection performed on it.`,
            detail: `Critical system · agent live · ${fresh.length} telemetry famil${fresh.length !== 1 ? 'ies' : 'y'} fresh`,
          };
        } else {
          const gaps = [
            stale.length > 0 ? `stale: ${stale.map((f) => `${f.name} (last ${fmtDateTime(f.at as number)})`).join(', ')}` : null,
            absent.length > 0 ? `absent: ${absent.map((f) => f.name).join(', ')}` : null,
          ].filter(Boolean).join('; ');
          checks['17'] = notAssessed(
            `This node is designated a critical system. ${agentEvidence ? `${agentEvidence} However, fewer than two telemetry families delivered data inside that window` : agentStaleNote} — ${gaps || 'no telemetry family carried a usable timestamp'}. Whether it is under continuous real-time monitoring was therefore not measured. Telemetry that stops arriving is what a node that is switched off or offline looks like, so this is not recorded as a monitoring failure.`,
            `Not assessed — critical system, ${fresh.length} of ${families.length} telemetry families fresh`,
          );
        }
      }

      // Point 18: CPU, memory, disk and bandwidth utilisation WITH threshold
      // alerts. Only part of that is collected, so this stays not assessed — but
      // the reason carries the disk figures Vajra actually measured and names the
      // two missing pieces, instead of claiming the agent monitors all four.
      {
        let diskNote = 'Vajra read back no storage volume records for this node, so not even disk utilisation was measured here.';
        let diskDetail = '';
        try {
          const utilisationRes = unwrap(await storagePromise);
          const utilisationVolumes = (utilisationRes?.data?.data?.volumes ?? utilisationRes?.data?.volumes ?? []) as Array<Record<string, unknown>>;
          if (Array.isArray(utilisationVolumes) && utilisationVolumes.length > 0) {
            const gb = (v: unknown) => {
              const n = Number(v);
              return Number.isFinite(n) && n > 0 ? `${(n / 1073741824).toFixed(1)} GB` : null;
            };
            const described = utilisationVolumes.slice(0, 6).map((v) => {
              const name = String(v.name ?? v.mount ?? 'volume').trim() || 'volume';
              const used = gb(v.usedBytes);
              const total = gb(v.totalBytes);
              return used && total ? `${name} ${used} used of ${total}` : `${name} (size not reported)`;
            }).join('; ');
            diskNote = `Vajra did measure disk utilisation for this node: ${described}${utilisationVolumes.length > 6 ? `, and ${utilisationVolumes.length - 6} further volume(s)` : ''}.`;
            diskDetail = `${utilisationVolumes.length} volume${utilisationVolumes.length !== 1 ? 's' : ''} measured`;
          }
        } catch {
          diskNote = 'The storage telemetry read for this node failed, so disk utilisation was not measured either.';
        }
        checks['18'] = notAssessed(
          `Not assessed — this control asks for CPU, memory, disk and bandwidth utilisation together with threshold alerting. ${diskNote} Vajra also holds memory-utilisation telemetry for Windows endpoints. It does not hold the rest: CPU utilisation is not collected from any endpoint on this fleet, the network interface byte counters that are collected are cumulative and no bandwidth rate is derived from them, and the platform has no utilisation threshold or utilisation alert of any kind. What is missing: CPU utilisation telemetry and a utilisation threshold/alerting mechanism.`,
          diskDetail ? `Not assessed — disk measured (${diskDetail}); CPU and thresholds missing` : 'Not assessed — no CPU utilisation or threshold alerting',
        );
      }

      // Point 19: CERT-In Incident Reporting

      // Point 20: Log & Network Data Collection for Incident Response

      // Point 21: Detailed Incident Report Maintained

      // Point 22: Storage inventory
      try {
        const nodeStorageRes = unwrap(await storagePromise);

        const volumes =
          nodeStorageRes?.data?.data?.volumes ??
          nodeStorageRes?.data?.volumes ??
          [];

        const volumeCount = Array.isArray(volumes) ? volumes.length : 0;

        checks['22'] = volumeCount > 0
          ? {
            compliant: true,
            reason: `This node successfully reported ${volumeCount} storage volume(s) to Vajra.`,
            detail: `${volumeCount} storage volume(s) detected`,
          }
          : notAssessed(
            'Vajra received no storage volume records for this node, so whether its storage devices are tracked and monitored was not measured. An empty telemetry response is not evidence that the node has no storage.',
            'Not assessed — no storage volumes reported',
          );
      } catch {
        checks['22'] = notAssessed(
            'Vajra could not retrieve storage telemetry for this node.',
            'Storage telemetry query failed',
          );
      }

      // Point 23: Wi-Fi connection and saved-profile status is collected and reported
      // for this endpoint.
      //
      // 2026-09-04: the reason text here used to claim this provides "rogue device
      // detection" — it does not. GetWifiStatus (agent/agent/wifi/main.go) returns only
      // this endpoint's own current SSID and its saved-profile count; there is no
      // authorized-AP list, no nearby-AP scan, and no rogue-device classification
      // anywhere in the agent or evaluator, so a rogue/unauthorized-AP claim is not
      // something this data can support. Narrowed to what was actually measured,
      // matching how control 38 (Bluetooth) is scoped.

      {
        try {
          const wifiStatus = unwrap((await wsPromise).wifi);
          const connectedSsid = String(wifiStatus?.connected?.ssid ?? '').trim();
          const savedProfiles = Array.isArray(wifiStatus?.saved_profiles) ? wifiStatus?.saved_profiles.length : 0;

          if (wifiStatus) {
            checks['23'] = {
              compliant: true,
              reason: connectedSsid
                ? `Vajra queried live Wi-Fi telemetry for this node and found an active connection to SSID "${connectedSsid}" with ${savedProfiles} saved profile${savedProfiles !== 1 ? 's' : ''}. This reports this endpoint's own Wi-Fi connection and saved-profile status; it is not a scan for rogue access points or unauthorized devices.`
                : `Vajra queried live Wi-Fi telemetry for this node and found no active Wi-Fi connection, with ${savedProfiles} saved profile${savedProfiles !== 1 ? 's' : ''}. This still reports this endpoint's own Wi-Fi connection and saved-profile status; it is not a scan for rogue access points or unauthorized devices.`,
              detail: connectedSsid || `Saved profiles: ${savedProfiles}`,
            };
          } else {
            checks['23'] = notAssessed(
              'Vajra could not retrieve live Wi-Fi telemetry for this node because the WebSocket Wi-Fi status query did not return data, so wireless monitoring on this node was not measured. A silent websocket is not evidence that wireless activity is unmonitored.',
              'Not assessed — Wi-Fi status unavailable',
            );
          }
        } catch {
          checks['23'] = notAssessed(
            'Vajra could not retrieve live Wi-Fi telemetry for this node. The Wi-Fi status query failed before a usable response was returned.',
            'Wi-Fi status query failed',
          );
        }
      }

      // Point 24 vajra Agent Itself

      // Point 25: Patch and Update History
      // Point 25: Update history
      {
        try {
          const updateHistoryRes = unwrap(await updateHistoryPromise);
          const updateHistoryData = updateHistoryRes.data as { status?: string; data?: unknown[] } | null;

          if (updateHistoryData?.status === 'Success' && Array.isArray(updateHistoryData.data) && updateHistoryData.data.length > 0) {
            checks['25'] = {
              compliant: true,
              reason: `Vajra successfully fetched ${updateHistoryData.data.length} update history record(s) for this node, so the update-history visibility check is validated.`,
              detail: 'Update history fetched successfully',
            };
          } else {
            checks['25'] = notAssessed(
              'Vajra queried the update history endpoint but no update history records came back for this node, so the visibility and currency of its software update status was not measured. An empty response is not evidence that the node is unpatched.',
              'Not assessed — no update history records returned',
            );
          }
        } catch {
          checks['25'] = notAssessed(
            'Vajra could not fetch update history for this node, so the update-history visibility check could not be validated.',
            'Update history fetch failed',
          );
        }
      }

      // Point 26: Endpoint encryption for data at rest, and Point 34: whether the
      // encryption status of the system and data volumes is reported at all. Both
      // read the same BitLocker rows but answer different questions, so each gets
      // its own verdict.
      //
      // `percentage_encrypted === 100` alone is NOT evidence of protection: a volume
      // whose BitLocker protection is suspended still reports 100% encrypted while
      // its volume master key sits unprotected on disk. That is the state Windows
      // enters across firmware/BIOS updates, and the state an attacker holding local
      // admin would choose. The verdict therefore requires protection actually on
      // AND conversion complete. The status encodings are the ones
      // NodesViewStorage.tsx renders from these same rows — protection_status 1
      // Protected / 0 Unprotected / 2 Unknown, conversion_status 1 Fully Encrypted /
      // 0 Fully Decrypted / 2 Encryption in Progress / -1 Not Applicable — and a
      // value outside them is not decoded into a verdict. No minimum encryption
      // algorithm is imposed (neither CSCRF nor IRDAI publishes one), so
      // encryption_method is carried through as an observed value only.
      {
        try {
          // Same storage record as control 22 — read once, evaluated twice.
          const storageInfo = unwrap(await storagePromise);
          const bitLockerData = storageInfo?.data?.bitlocker ?? storageInfo?.data?.data?.bitlocker ?? storageInfo?.data?.volumes?.find((v: Record<string, unknown>) => v.bitlocker)?.bitlocker ?? null;
          debugLog('BitLocker data for compliance:', { bitLockerData });
          const blRows = Array.isArray(bitLockerData) ? (bitLockerData as Array<Record<string, unknown>>) : [];
          debugLog('Number of volumes with BitLocker data:', blRows.length);

          const letterOf = (v: unknown) => String(v ?? '').trim().toUpperCase().replace(/:$/, '');
          const codeOf = (v: unknown) => {
            if (v === null || v === undefined || String(v).trim() === '') return null;
            const n = Number(v);
            return Number.isFinite(n) ? n : null;
          };
          const labelOf = (row: Record<string, unknown>) => {
            const letter = letterOf(row.drive_letter) || String(row.device_id ?? '').trim() || 'volume';
            const method = String(row.encryption_method ?? '').trim();
            return `${letter}${method ? ` (${method})` : ''}`;
          };

          // The boot/system volume is called out separately where the storage
          // payload identifies one: it carries the OS, and a suspension there is
          // the case that matters most.
          const rawVolumes = storageInfo?.data?.data?.volumes ?? storageInfo?.data?.volumes ?? [];
          const bootLetters = new Set(
            (Array.isArray(rawVolumes) ? (rawVolumes as Array<Record<string, unknown>>) : [])
              .filter((v) => v?.bootPartition === true)
              .map((v) => letterOf(v?.mount ?? v?.name))
              .filter((letter) => letter.length > 0),
          );

          const protectedRows: Array<Record<string, unknown>> = [];
          const unprotectedRows: Array<Record<string, unknown>> = [];
          const undecodedRows: Array<Record<string, unknown>> = [];
          for (const row of blRows) {
            const ps = codeOf(row.protection_status);
            const cs = codeOf(row.conversion_status);
            if (ps === 1 && cs === 1) protectedRows.push(row);
            else if (ps === 0 || cs === 0 || cs === 2) unprotectedRows.push(row);
            else undecodedRows.push(row);
          }
          debugLog('BitLocker volume classification:', {
            protected: protectedRows.length,
            unprotected: unprotectedRows.length,
            undecoded: undecodedRows.length,
          });

          // The two failing states need different remediation and were being
          // printed as one sentence: a volume that was never encrypted has to be
          // encrypted, while a volume that is 100% encrypted with protection off
          // (BitLocker suspended, or an OEM pre-provisioned clear-key protector)
          // only has to have protection resumed — but until it is, its volume
          // master key sits readable on disk and Windows does not report the
          // drive as protected.
          const neverEncryptedRows = unprotectedRows.filter((row) => codeOf(row.conversion_status) === 0);
          const encryptedUnprotectedRows = unprotectedRows.filter((row) => codeOf(row.conversion_status) === 1);
          const encryptionInProgressRows = unprotectedRows.filter((row) => codeOf(row.conversion_status) === 2);

          const systemRows = blRows.filter((row) => bootLetters.has(letterOf(row.drive_letter)));
          const systemNote = systemRows.length > 0
            ? ` System volume${systemRows.length !== 1 ? 's' : ''}: ${systemRows.map((row) => `${labelOf(row)} — ${protectedRows.includes(row) ? 'protection on, conversion complete' : unprotectedRows.includes(row) ? 'protection not active' : 'status not decodable'}`).join(', ')}.`
            : '';

          if (blRows.length === 0) {
            checks['26'] = notAssessed(
              'Vajra holds no BitLocker volume records for this node, so whether endpoint encryption is enabled for data at rest was not measured. An empty record set is not evidence that the volumes are unencrypted.',
              'Not assessed — no BitLocker volume records',
            );
          } else if (unprotectedRows.length > 0) {
            checks['26'] = {
              compliant: false,
              reason: `BitLocker reports ${unprotectedRows.length} of ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} on this node without active protection.${neverEncryptedRows.length > 0 ? ` Never encrypted (BitLocker has to be turned on): ${neverEncryptedRows.map(labelOf).join(', ')}.` : ''}${encryptedUnprotectedRows.length > 0 ? ` Encrypted but unprotected — 100% encrypted with protection off, i.e. BitLocker suspended or holding only a clear-key protector, so the volume master key is readable from disk and protection has to be resumed: ${encryptedUnprotectedRows.map(labelOf).join(', ')}.` : ''}${encryptionInProgressRows.length > 0 ? ` Encryption still in progress: ${encryptionInProgressRows.map(labelOf).join(', ')}.` : ''} A volume can report 100% encrypted while its protection is suspended, so this control requires protection status "on" together with a completed conversion.${systemNote}`,
              detail: `${protectedRows.length} / ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} BitLocker-protected`,
            };
          } else if (undecodedRows.length > 0) {
            checks['26'] = notAssessed(
              `Vajra read ${blRows.length} BitLocker volume record${blRows.length !== 1 ? 's' : ''} for this node but could not decode the reported protection/conversion status of ${undecodedRows.length} of them (${undecodedRows.map(labelOf).join(', ')}), so endpoint encryption of data at rest was not measured.${systemNote}`,
              'Not assessed — undecodable BitLocker status',
            );
          } else {
            checks['26'] = {
              compliant: true,
              reason: `BitLocker reports all ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} on this node with protection on and conversion complete: ${protectedRows.map(labelOf).join(', ')}. Encryption methods are recorded as observed values; no minimum algorithm is applied, because neither CSCRF nor IRDAI publishes one.${systemNote}`,
              detail: `${protectedRows.length} / ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} BitLocker-protected`,
            };
          }

          // Point 34 is the reporting control, not the encryption control: it asks
          // whether the built-in OS encryption state of the system and data volumes
          // is visible for this node. Same rows, different question, so it is
          // evaluated here rather than copied from another control's verdict.
          const decodedCount = blRows.length - undecodedRows.length;
          if (blRows.length === 0) {
            checks['34'] = notAssessed(
              'Vajra read back no per-volume disk-encryption status for this node, so whether the encryption state of its system and data volumes is reported was not measured.',
              'Not assessed — no disk encryption status records',
            );
          } else if (decodedCount > 0) {
            checks['34'] = {
              compliant: true,
              reason: `Vajra holds a decodable built-in disk-encryption status for ${decodedCount} of ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} on this node: ${blRows.filter((row) => !undecodedRows.includes(row)).map(labelOf).join(', ')}. The encryption state of these volumes is therefore reported and reviewable.${systemNote}`,
              detail: `${decodedCount} / ${blRows.length} volume${blRows.length !== 1 ? 's' : ''} reported — ${protectedRows.length} protected, ${neverEncryptedRows.length} unencrypted, ${encryptedUnprotectedRows.length} encrypted with protection off`,
            };
          } else {
            checks['34'] = notAssessed(
              `Vajra holds ${blRows.length} BitLocker volume record${blRows.length !== 1 ? 's' : ''} for this node but none carries a decodable protection/conversion status, so the encryption state of its volumes is not reported usably.`,
              'Not assessed — undecodable BitLocker status',
            );
          }
        } catch {
          checks['26'] = notAssessed(
            'Vajra could not fetch storage encryption data for this node, so the SEBI requirement for endpoint encryption of storage data could not be validated.',
            'Storage encryption data fetch failed',
          );
          checks['34'] = notAssessed(
            'Vajra could not fetch storage encryption data for this node, so whether the encryption state of its system and data volumes is reported could not be validated.',
            'Storage encryption data fetch failed',
          );
        }
      }

      // Point 27: "User logins and session activities are tracked to detect suspicious
      // behavior."
      //
      // 2026-09-07: this control previously had NO evaluator here at all — it sat in
      // HIDDEN_GUIDELINES with the note "Only vajra user logins/logouts are audited", so a
      // SEBI customer was shown no login-tracking control on any surface. That note was
      // right that Vajra's own operator audit trail is not evidence about the endpoint, but
      // wrong that no endpoint evidence exists: the Windows advanced-audit baseline this
      // function already fetches carries the Logon subcategory (probe key '14'), which is
      // read a few controls up as part of REQUIRED_AUDIT_KEYS for control 4. IRDAI control
      // 15 carries this control's label character-for-character and has been scoring it
      // pass/fail on exactly that probe. Two registers asking the same question of the same
      // fleet from evidence both hold must not answer it in one and hide it in the other,
      // so the IRDAI 15 evaluator is ported here verbatim in shape.
      //
      // What this measures is that logon/logoff events are GENERATED on the endpoint, not
      // their contents: Vajra ingests no Windows Security event log from any host on this
      // fleet, so no suspicious-behaviour classification is claimed. Logon decides the
      // verdict alone; Special Logon (key '5') and Credential Validation (key '6') are
      // reported as coverage detail so the reason names the neighbouring settings without
      // letting them turn a measured Logon reading into a different answer.
      {
        const [logon] = readBaseline(['14']);
        const coverageReadings = readBaseline(['5', '6']);
        const describe = (r: { label: string; enabled: boolean | null }) => (
          r.enabled === null ? `${r.label} was not measured` : `${r.label} is ${r.enabled ? 'On' : 'Off'}`
        );
        const coverage = ` Alongside it on this node: ${coverageReadings.map(describe).join(', and ')}.`;

        if (logon.enabled === true) {
          checks['27'] = {
            compliant: true,
            reason: `Logon auditing is enabled on this node (${baselineMeasuredAt}), so interactive, network and remote logons and logoffs are written to the Security log and user session activity is tracked on this endpoint.${coverage} Vajra measures that this tracking is switched on; it does not ingest the resulting Security log records, so it makes no claim about detecting suspicious behaviour in them.${baselineAgeNote}`,
            detail: 'Logon auditing On',
          };
        } else if (logon.enabled === false) {
          checks['27'] = {
            compliant: false,
            reason: `Logon auditing is Off on this node (${baselineMeasuredAt}), so logons and logoffs are never written to the Security log and user login and session activity is not tracked on this endpoint.${coverage} Enable Success and Failure auditing for the Logon subcategory (Logon/Logoff > Audit Logon) under Windows Advanced Audit Policy Configuration.${baselineAgeNote}`,
            detail: 'Logon auditing Off',
          };
        } else if (baselineProbes === null) {
          checks['27'] = notAssessed(
            'Not assessed — Vajra read back no Windows advanced-audit baseline record for this node, so whether user logins and session activity are tracked on this endpoint could not be measured. Vajra keeps its own platform audit trail of operator logins, but that is Vajra\'s record of itself and is not evidence about this endpoint.',
            'Not assessed — no baseline audit-policy record',
          );
        } else {
          checks['27'] = notAssessed(
            'Not assessed — the Logon auditing probe returned no usable value for this node, so whether user logins and session activity are tracked was not measured. An empty probe result is not a measured negative.',
            'Not assessed — Logon auditing probe returned no value',
          );
        }
      }

      // Point 28: Vajra itself

      // Point 29: no evaluator — Vajra collects no local user account inventory from any
      // endpoint (no account list, no privilege levels, no last-login times), so this
      // control is Class A structurally unmeasurable and is filtered out by
      // STRUCTURALLY_UNMEASURABLE_SEBI_KEYS. (It used to be annotated "Same as 27"; that is
      // no longer true as of 2026-09-07 — 27 is answered from the Logon audit probe above,
      // which says nothing about the account inventory this control asks for.)

      // Point 30: "Active network connections and listening ports are
      // regularly collected and reviewed for unauthorized services."
      //
      // This is a collection-AND-review control. Vajra now exposes a real,
      // per-host listening-port inventory (GET
      // /api/nodes/network/listening-ports/{host}, backed by the differential
      // listening_ports table — see node_network_posture.ts for how "currently
      // listening" is derived from the added/removed rows). That measures and
      // satisfies the COLLECTION half honestly. It does NOT measure the review
      // step: Vajra performs no authorised/unauthorised classification of any
      // port, so the reason says exactly that rather than implying the full
      // control text is satisfied. An absent or empty response is not-assessed,
      // never a fail — an endpoint reporting zero listening ports back is
      // indistinguishable here from one that simply is not delivering data.
      {
        try {
          const portsRes = unwrap(await listeningPortsPromise);
          const portsBody = portsRes.data as { data?: { ports?: unknown[]; limit?: number; has_more?: boolean } | null; ports?: unknown[]; limit?: number; has_more?: boolean } | null;
          const portsPayload = portsBody?.data ?? portsBody ?? null;
          const ports = Array.isArray(portsPayload?.ports) ? portsPayload.ports as Array<Record<string, unknown>> : [];

          if (ports.length > 0) {
            const describePort = (p: Record<string, unknown>) => {
              const addr = String(p.address ?? '').trim() || '?';
              const port = p.port ?? '?';
              const proto = String(p.protocol_name ?? '').trim() || (p.protocol !== undefined && p.protocol !== null ? `proto ${p.protocol}` : '?');
              return `${addr}:${port}/${proto}`;
            };
            const sample = ports.slice(0, 5).map(describePort).join(', ');
            const pageCapNote = portsPayload?.has_more
              ? ` This is a capped first page (limit ${portsPayload?.limit ?? ports.length}); more ports are currently listening on this node beyond what is shown here.`
              : '';
            checks['30'] = {
              compliant: true,
              reason: `Vajra collects a real listening-port inventory for this node: ${ports.length} currently-listening port${ports.length !== 1 ? 's' : ''} observed, for example ${sample}.${pageCapNote} This evidences the COLLECTION half of the control. Vajra performs no authorised/unauthorised classification of these ports — the REVIEW step this control names is an organisational activity this report does not measure, and this verdict should be read as evidencing collection only, not review.`,
              detail: `${ports.length}${portsPayload?.has_more ? '+' : ''} listening port${ports.length !== 1 ? 's' : ''} collected`,
            };
          } else {
            checks['30'] = notAssessed(
              'Vajra queried the listening-port inventory for this node but no currently-listening ports were returned, so the collection of active network connections and listening ports could not be evidenced for this endpoint. An empty result is not evidence that no ports are listening.',
              'Not assessed — no listening-port records returned',
            );
          }
        } catch {
          checks['30'] = notAssessed(
            'Vajra could not fetch the listening-port inventory for this node, so collection of active network connections and listening ports was not measured for it.',
            'Not assessed — listening-port fetch failed',
          );
        }
      }

      // Point 31: Agent natively queries process tree.

      // Point 32: "System uptime and last reboot time are tracked." A pure
      // tracking control — see node_network_uptime in
      // node_network_posture.ts. Last boot is derived server-side as
      // observed_at - uptime_seconds from the endpoint's socket-event stream,
      // and only returned when that derivation is internally consistent
      // (positive, not later than the observation itself). No uptime-duration
      // threshold is applied or implied — the control only asks that uptime
      // and last reboot be tracked, and a real boot time is exactly that.
      {
        try {
          const uptimeRes = unwrap(await networkUptimePromise);
          const uptimeBody = uptimeRes.data as { data?: { boot_unixtime?: unknown; uptime_seconds?: unknown; observed_at?: unknown } | null } | { boot_unixtime?: unknown; uptime_seconds?: unknown; observed_at?: unknown } | null;
          const uptimePayload = (uptimeBody as { data?: unknown })?.data ?? uptimeBody ?? null;
          const bootUnixRaw = (uptimePayload as { boot_unixtime?: unknown } | null)?.boot_unixtime;
          const observedAtRaw = (uptimePayload as { observed_at?: unknown } | null)?.observed_at;
          const bootUnix = typeof bootUnixRaw === 'number' && Number.isFinite(bootUnixRaw) && bootUnixRaw > 0 ? bootUnixRaw : null;
          const observedAt = typeof observedAtRaw === 'number' && Number.isFinite(observedAtRaw) && observedAtRaw > 0 ? observedAtRaw : null;

          if (bootUnix !== null) {
            const ageNote = observedAt !== null
              ? (() => {
                const ageHours = Math.max(0, (Date.now() / 1000 - observedAt) / 3600);
                const ageText = ageHours < 24
                  ? `${Math.round(ageHours)} hour${Math.round(ageHours) === 1 ? '' : 's'}`
                  : `${Math.round(ageHours / 24)} day${Math.round(ageHours / 24) === 1 ? '' : 's'}`;
                return ` This was observed ${fmtDateTime(observedAt)}, ${ageText} before this report.`;
              })()
              : '';
            checks['32'] = {
              compliant: true,
              reason: `Vajra tracks system uptime and last reboot time for this node: last boot at ${fmtDateTime(bootUnix)}, derived from the endpoint's socket-event stream (boot time = observation time − reported uptime).${ageNote} No uptime-duration threshold is applied here — this control asks only that uptime and last reboot be tracked, which is what this measurement evidences.`,
              detail: `Last boot ${fmtDateTime(bootUnix)}`,
            };
          } else {
            checks['32'] = notAssessed(
              'Vajra queried the uptime/last-reboot endpoint for this node but no defensible boot time could be derived from its telemetry, so uptime and last-reboot tracking was not measured for this endpoint.',
              'Not assessed — no derivable boot time',
            );
          }
        } catch {
          checks['32'] = notAssessed(
            'Vajra could not fetch uptime/last-reboot data for this node, so uptime and last-reboot tracking was not measured for it.',
            'Not assessed — uptime fetch failed',
          );
        }
      }

      // Point 33: Firewall — is a local firewall ruleset actually in force?
      //
      // `windows_firewall_rules.enabled` is a per-RULE flag, not the state of the
      // firewall itself: a host whose Windows Firewall product reports "Off" in
      // Security Center still ships thousands of enabled rule definitions, so
      // counting enabled rules declared a firewall in force on hosts where the
      // same database says it is switched off. The verdict now comes from the
      // firewall product state Vajra already holds (windows_security_products,
      // delivered on the node list as security_products — entries such as
      // "Windows Firewall", "Bitdefender Firewall" with state On/Off/Snoozed/
      // Expired), and the rule inventory is carried as supporting detail only.
      // With no product record the control is not assessed: rule counts alone
      // cannot establish the firewall's state in either direction.
          {
            let ruleNote = 'Vajra received no firewall rule records from this node.';
            let ruleDetail = '';
            try {
              const fwRes = unwrap(await firewallPromise);
              const fwPayload = fwRes.data as { status?: string; data?: unknown[]; message?: string } | null;
              const fwData = fwPayload?.status === 'Success' && Array.isArray(fwPayload.data) ? fwPayload.data : [];
              if (fwData.length > 0) {
                const enabledRules = (fwData as Array<{ enabled?: unknown } | null>).filter((rule) => Number(rule?.enabled) === 1).length;
                ruleNote = `This node reported ${fwData.length} firewall rule definition${fwData.length !== 1 ? 's' : ''} to Vajra, ${enabledRules} of them marked enabled (a per-rule flag, not the firewall's own state).`;
                ruleDetail = ` · ${enabledRules}/${fwData.length} rules enabled`;
              }
            } catch {
              ruleNote = 'Vajra could not fetch the firewall rule inventory for this node.';
            }

            const fwOn = firewallProds.filter((p) => stateOf(p) === 'on');
            const fwOffLike = firewallProds.filter((p) => ['off', 'snoozed', 'expired'].includes(stateOf(p)));

            if (fwOn.length > 0) {
              checks['33'] = {
                compliant: true,
                reason: `Windows Security Center reports ${fwOn.length} of ${firewallProds.length} registered firewall product${firewallProds.length !== 1 ? 's' : ''} in state "On" on this node: ${describeProds(fwOn)}. A local firewall is therefore in force on the endpoint. ${ruleNote}`,
                detail: `${fwOn.length}/${firewallProds.length} firewall product${firewallProds.length !== 1 ? 's' : ''} On${ruleDetail}`,
              };
            } else if (firewallProds.length > 0 && fwOffLike.length === firewallProds.length) {
              checks['33'] = {
                compliant: false,
                reason: `Windows Security Center reports every registered firewall product on this node as not running (${describeProds(fwOffLike)}), so no local firewall is in force on the endpoint. ${ruleNote} Rule definitions remain on disk while the firewall is off and do not filter traffic.`,
                detail: `0/${firewallProds.length} firewall product${firewallProds.length !== 1 ? 's' : ''} On${ruleDetail}`,
              };
            } else if (firewallProds.length > 0) {
              checks['33'] = notAssessed(
                `Vajra holds ${firewallProds.length} firewall product record${firewallProds.length !== 1 ? 's' : ''} for this node but could not decode the reported state of ${firewallProds.length - fwOffLike.length} of them (${describeProds(firewallProds.filter((p) => !fwOffLike.includes(p)))}), so whether a local firewall is in force was not measured. ${ruleNote}`,
                `Not assessed — undecodable firewall product state${ruleDetail}`,
              );
            } else {
              checks['33'] = notAssessed(
                `No firewall product state was available for this node${isWindowsHost ? ' from Windows Security Center' : ' (this is not a Windows endpoint, so there is no Security Center firewall record to read)'}, so whether a local firewall ruleset is in force was not measured. ${ruleNote} The per-rule "enabled" flag describes individual rule definitions, not the firewall's own state, and is not scored as a verdict.`,
                `Not assessed — no firewall product state${ruleDetail}`,
              );
            }
          }

      // Point 34: Storage volume encryption status: Same api call as 22

      // Point 35: Vajra agent natively queries time and NTP configs

      // Point 36: Programs List Api for Windiows
          try {
            // Same programs response as control 2 — read once, evaluated twice.
            const getProgramsListRes = unwrap(await programsPromise);
            const rawPrograms = ((getProgramsListRes.data as { data?: unknown } | null)?.data ?? getProgramsListRes.data) as Record<string, unknown> | null;
            const programsData = (rawPrograms && typeof rawPrograms === 'object') ? rawPrograms as {
              programs?: unknown[];
              deb?: unknown[];
              rpm?: unknown[];
              chrome_extensions?: unknown[];
              firefox_addons?: unknown[];
              firefox_add_ons?: unknown[];
              npm_packages?: unknown[];
              portage_packages?: unknown[];
              choco?: unknown[];
              ie_extensions?: unknown[];
            } : {};
            const programCount = Array.isArray(programsData.programs) ? programsData.programs.length : 0;
            const debCount = Array.isArray(programsData.deb) ? programsData.deb.length : 0;
            const rpmCount = Array.isArray(programsData.rpm) ? programsData.rpm.length : 0;
            const packageCount = programCount || debCount || rpmCount;

            if (packageCount > 0) {
              checks['36'] = {
                compliant: true,
                reason: `This node has sent ${packageCount} programs to Vajra and is working`,
                detail: `Since SEBI asks for programs list, success in returning the data proves compliance`,
              };
            } else {
              checks['36'] = notAssessed(
                'Vajra queried the programs list endpoint for this node but no installed-software records came back, so whether software installations on this node are tracked and reported was not measured. An empty inventory response is not evidence that tracking is absent.',
                'Not assessed — no installed software records returned',
              );
            }

            const chromeCount = Array.isArray(programsData.chrome_extensions) ? programsData.chrome_extensions.length : 0;
            const firefoxCount = Array.isArray(programsData.firefox_add_ons)
              ? programsData.firefox_add_ons.length
              : Array.isArray(programsData.firefox_addons)
                ? programsData.firefox_addons.length
                : 0;
            if (chromeCount > 0 || firefoxCount > 0) {
              checks['39'] = { compliant: true, reason: `This node has sent ${chromeCount} Chrome extensions and ${firefoxCount} Firefox add-ons to Vajra and is working`, detail: `Since SEBI asks for browser extension/add-on info, success in returning the data proves compliance` };
            } else {
              // Zero extension records cannot be told apart from "extensions were
              // never collected", so this is not a measured verdict either way.
              checks['39'] = notAssessed(
                'Vajra received no Chrome extension or Firefox add-on records for this node, which cannot be distinguished from a node whose browser extension inventory was never collected, so the browser extension inventory was not measured.',
                'Not assessed — no browser extension records returned',
              );
            }
          } catch {
            // ignore
          }

      // Point 37: Agent collects backup info?

      // Unsure implementation!!
      // Point 38: Bluetooth api
      {
        try {
          const btStatus = unwrap((await wsPromise).bluetooth);
          const hasBluetoothTelemetry = !!btStatus;

          checks['38'] = hasBluetoothTelemetry
            ? {
              compliant: true,
              reason: 'Vajra queried live Bluetooth telemetry for this node and successfully collected the current Bluetooth / wireless interface state, satisfying the SEBI requirement to collect and report Bluetooth status.',
              detail: (btStatus.status ?? (btStatus.fully_locked ? 'locked' : 'status collected')),
            }
            : notAssessed(
              'Vajra could not retrieve live Bluetooth telemetry for this node from the websocket Bluetooth status query, so the state of its Bluetooth and other wireless interfaces was not measured. A silent websocket is not evidence that those interfaces are unreported.',
              'Not assessed — Bluetooth status unavailable',
            );
        } catch {
          checks['38'] = notAssessed(
            'Vajra could not retrieve live Bluetooth telemetry for this node. The Bluetooth status query failed before a usable response was returned.',
            'Bluetooth status query failed',
          );
        }
      }

      // Point 40: Local DNS info

      // Point 41: Software updates and patcch jobs: Update History API (Same as Point 15)

          // Fallback defaults
          // Points below are statements about what the Vajra platform can do, not
          // measurements of this endpoint, so they are recorded as not-assessed.
          if (checks['1'] === undefined) {
            checks['1'] = notAssessed('Not assessed on this endpoint — capability statement only. Vajra provides built-in critical node marking: administrators can flag any node as critical to enable prioritised monitoring, alerting, and incident response. Whether critical assets have actually been identified was not measured during this run.', 'Not measured — critical node marking available');
          }
          // Point 2 fallback: Software Asset Inventory & SBOM
          if (checks['2'] === undefined) {
            checks['2'] = notAssessed('Not assessed on this endpoint — capability statement only. The Vajra Agent can collect installed software inventory (programs, deb/rpm packages) from a node for SBOM generation and vulnerability cross-referencing, but no inventory was read back for this node during this run.', 'Not measured — software inventory collection available');
          }
          // Point 4: audit logs retained for authentication, access, privilege
          // changes and system modifications.
          //
          // Vajra measures whether those events are GENERATED at all — the
          // auditpol advanced-audit subcategories in this node's Windows baseline
          // record, each True only when the subcategory audits both Success and
          // Failure. It does NOT collect the Security channel retention settings
          // (maximum log size, retention policy, automatic backup), so this
          // control can be failed on measured evidence but can never be passed
          // here: a subcategory that is off means the events this control asks to
          // be retained are never written, while all of them being on still
          // leaves the retention PERIOD unmeasured.
          {
            const REQUIRED_AUDIT_KEYS = ['5', '6', '9', '10', '12', '14', '16'];
            const readings = readBaseline(REQUIRED_AUDIT_KEYS);
            const measured = readings.filter((r) => r.enabled !== null);
            const disabled = measured.filter((r) => r.enabled === false);
            const unmeasured = readings.filter((r) => r.enabled === null);
            const retentionNote = 'This measures whether those events are generated. Vajra collects no Windows event-log retention setting (maximum log size, retention policy, automatic backup) from any endpoint, so the retention period itself is not measured.';
            if (baselineProbes === null) {
              checks['4'] = notAssessed(
                `Not assessed — no usable advanced-audit-policy probe result is held for this node: ${baselineUnavailableNote}, so whether the authentication, access, privilege-change and system-modification events this control covers are even generated could not be measured. Vajra keeps its own platform audit trail of operator actions, but that is Vajra's record of itself and is not evidence about this endpoint.`,
                baselineAbsence === 'transport'
                  ? 'Not assessed — baseline audit-policy read failed'
                  : baselineAbsence === 'stale'
                    ? 'Not assessed — baseline audit-policy record too old'
                    : 'Not assessed — no baseline audit-policy record',
              );
            } else if (measured.length === 0) {
              checks['4'] = notAssessed(
                `Not assessed — every advanced-audit-policy probe on this node (${labelsOf(readings)}) came back empty, meaning the audit policy could not be read on the endpoint. An empty probe result is not evidence that auditing is switched off. ${retentionNote}`,
                'Not assessed — audit-policy probes returned no value',
              );
            } else if (disabled.length > 0) {
              checks['4'] = {
                compliant: false,
                reason: `Windows advanced audit policy on this node (${baselineMeasuredAt}) reports ${disabled.length} of the ${measured.length} required subcategories NOT auditing both Success and Failure: ${labelsOf(disabled)}. The authentication, access, privilege-change and system-modification events this control asks to be retained are therefore never written to this endpoint's Security log, so there is nothing to retain. ${retentionNote}${baselineAgeNote}`,
                detail: `${measured.length - disabled.length} / ${measured.length} audit subcategories enabled`,
              };
            } else if (measured.length === REQUIRED_AUDIT_KEYS.length) {
              checks['4'] = notAssessed(
                `All ${REQUIRED_AUDIT_KEYS.length} required audit subcategories are enabled on this node (${labelsOf(readings)}, ${baselineMeasuredAt}), so the events are generated — but no event-log retention setting is collected for this node, so retention itself was not measured. ${retentionNote}`,
                'Not assessed — audit generation on, retention not collected',
              );
            } else {
              checks['4'] = notAssessed(
                `Only ${measured.length} of the ${REQUIRED_AUDIT_KEYS.length} required audit subcategories returned a readable value on this node (${labelsOf(measured)}), all of them enabled; ${labelsOf(unmeasured)} returned nothing. With incomplete generation evidence and no retention setting collected, this control was not measured. ${retentionNote}`,
                'Not assessed — incomplete audit-policy evidence',
              );
            }
          }
          // Point 5: configuration changes to systems and software tracked and
          // logged ON THIS ENDPOINT. The three baseline probes below are exactly
          // that tracking, so unlike control 4 a genuine pass is available: with
          // all three on, the act of changing configuration is recorded, the
          // command that made the change is recorded with it, and service/driver/
          // security-package installation is recorded too.
          {
            const CHANGE_LIMBS: Array<{ key: string; failText: string }> = [
              { key: '11', failText: 'Process Creation auditing is off, so the act of running the tool that changes a configuration is never recorded' },
              { key: '17', failText: 'command-line capture in process-creation events is off, so even a recorded change does not show the command that made it' },
              { key: '16', failText: 'Security System Extension auditing is off, so service, driver and security-package installation is not recorded' },
            ];
            const readings = readBaseline(CHANGE_LIMBS.map((l) => l.key));
            const measured = readings.filter((r) => r.enabled !== null);
            const disabled = measured.filter((r) => r.enabled === false);
            const unmeasured = readings.filter((r) => r.enabled === null);
            if (baselineProbes === null) {
              checks['5'] = notAssessed(
                `Not assessed — ${baselineUnavailableNote}, so the change-auditing settings on it were not measured. Vajra records the security actions performed through the platform itself, but that is Vajra's own audit trail and is not evidence that configuration changes made on this endpoint are tracked and logged.`,
                baselineAbsence === 'transport'
                  ? 'Not assessed — baseline change-auditing read failed'
                  : baselineAbsence === 'stale'
                    ? 'Not assessed — baseline change-auditing record too old'
                    : 'Not assessed — no baseline change-auditing record',
              );
            } else if (measured.length === 0) {
              checks['5'] = notAssessed(
                `Not assessed — the change-auditing probes on this node (${labelsOf(readings)}) all came back empty, so the settings could not be read on the endpoint. An empty probe result is not evidence that change logging is absent.`,
                'Not assessed — change-auditing probes returned no value',
              );
            } else if (disabled.length > 0) {
              const reasons = disabled.map((r) => CHANGE_LIMBS.find((l) => l.key === r.key)?.failText ?? r.label);
              checks['5'] = {
                compliant: false,
                reason: `Configuration changes made on this node are not logged by it (${baselineMeasuredAt}): ${reasons.join('; ')}. These are measured settings read from the endpoint, not missing data.${baselineAgeNote}`,
                detail: `${measured.length - disabled.length} / ${measured.length} change-auditing settings enabled`,
              };
            } else if (measured.length === CHANGE_LIMBS.length) {
              checks['5'] = {
                compliant: true,
                reason: `This node records the configuration changes made on it (${baselineMeasuredAt}): Process Creation auditing is on, command-line capture in process-creation events is on, and Security System Extension auditing records service, driver and security-package installation. Together those three settings are the tracking and logging this control asks for.`,
                detail: `${measured.length} / ${CHANGE_LIMBS.length} change-auditing settings enabled`,
              };
            } else {
              checks['5'] = notAssessed(
                `Only ${measured.length} of the ${CHANGE_LIMBS.length} change-auditing settings returned a readable value on this node (${labelsOf(measured)}), all of them enabled; ${labelsOf(unmeasured)} returned nothing, so the tracking of configuration changes was only partly measured. Nothing measured was in violation.`,
                'Not assessed — incomplete change-auditing evidence',
              );
            }
          }
          // Point 6: Anti-Malware Controls — "protections such as EDR, AV, IP
          // blocking, and containment mechanisms are ENABLED". "such as" makes the
          // list illustrative rather than conjunctive, and this control asks about
          // enablement, which is stronger than inventory. The Vajra agent IS the
          // anti-malware/EDR layer on this endpoint, so a recent check-in is a
          // measurement that such a protection is enabled and running here — that
          // much is honestly answered. The IP-blocking and containment mechanisms
          // are Vajra capabilities whose configured posture on this node is NOT
          // measured, so the reason says so instead of claiming them.
          if (checks['6'] === undefined) {
            checks['6'] = agentEvidence
              ? {
                compliant: true,
                reason: `${agentEvidence} An EDR/anti-malware protection is therefore enabled and running on this endpoint. ${secCentreNote} Vajra additionally provides IP blocklisting, port blocking and network isolation for this node, but the blocklist and containment posture actually configured on it was not measured during this run.`,
                detail: activeAvProds.length > 0
                  ? `Vajra EDR agent enabled · ${activeAvProds.length} AV/EDR product${activeAvProds.length !== 1 ? 's' : ''} On`
                  : 'Vajra EDR agent enabled and checked in',
              }
              : activeAvProds.length > 0
                ? {
                  compliant: true,
                  reason: `Windows Security Center reports ${activeAvProds.length} of ${avProds.length} antivirus/EDR product${avProds.length !== 1 ? 's' : ''} in state "On" on this node: ${describeProds(activeAvProds)}, so an anti-malware protection is enabled here. ${agentStaleNote} The IP-blocking and containment posture configured on this node was not measured during this run.`,
                  detail: `${activeAvProds.length} / ${avProds.length} AV/EDR product${avProds.length !== 1 ? 's' : ''} On`,
                }
                : notAssessed(`${agentStaleNote} ${secCentreNote} Vajra provides multi-layer anti-malware controls — port blocking, IP blocklisting and full network isolation — but with no recent agent check-in and no antivirus/EDR product reported On, whether anti-malware protections are enabled on this node was not measured.`, 'Not assessed — no recent agent check-in, no AV/EDR product On');
          }
          // Point 8: IP & Port Whitelisting
          if (checks['8'] === undefined) {
            checks['8'] = notAssessed('Not assessed on this endpoint — no firewall rule content was read back for this node during this run, so whether inbound traffic is admitted only from approved addresses was not measured.', 'Not assessed — no firewall rule content');
          }
          // Point 9: Malicious IP & Domain Blocking
          checks['9'] = notAssessed('Not assessed — Vajra holds no evidence of malicious-IP or malicious-domain blocking on this endpoint. Its own IP blocklist carries no entries for this organisation, no DNS-filtering or proxy configuration is collected from the endpoint, the collected hosts-file table carries no rows, and the endpoint firewall rules Vajra does hold carry no field that distinguishes a threat-intelligence block from an ordinary application rule. What is missing: per-endpoint threat-intel blocklist state or DNS-filter configuration. An empty Vajra blocklist is not evidence that this endpoint fails to block malicious addresses by other means.', 'Not assessed — no threat-intel blocking state collected');
          if (checks['10'] === undefined) {
            checks['10'] = notAssessed('Not assessed on this endpoint — no connected-device detection record was read back for this node during this run, so whether connected devices on it are monitored for unauthorized or rogue hardware was not measured.', 'Not assessed — no connected-device evidence');
          }
          if (checks['11'] === undefined) {
            checks['11'] = notAssessed('Not assessed on this endpoint — capability statement only. The Vajra Agent provides endpoint detection and response (EDR) coverage, but no EDR/AV product state was read back from this node during this run.', 'Not measured — Vajra Agent provides EDR capabilities');
          }
          // Point 13: "Unnecessary services, ports, protocols and software are
          // disabled." Classifying any observed port as UNNECESSARY needs a
          // tenant approved-services baseline, which Vajra does not hold — a
          // hard-coded legacy-port list would manufacture failures on ports
          // that are legitimate on a domain-joined Windows host (135/139/445/
          // 3389/etc). The verdict stays not-assessed unconditionally; the
          // observed open-port inventory (from the same endpoint that backs
          // control 30) is attached only as EVIDENCE, never as a pass/fail
          // input, and the reason says so explicitly.
          {
            let evidenceNote = '';
            try {
              const portsRes = unwrap(await listeningPortsPromise);
              const portsBody = portsRes.data as { data?: { ports?: unknown[]; has_more?: boolean } | null; ports?: unknown[]; has_more?: boolean } | null;
              const portsPayload = portsBody?.data ?? portsBody ?? null;
              const ports = Array.isArray(portsPayload?.ports) ? portsPayload.ports as Array<Record<string, unknown>> : [];
              if (ports.length > 0) {
                const sample = ports.slice(0, 5).map((p) => {
                  const addr = String(p.address ?? '').trim() || '?';
                  const port = p.port ?? '?';
                  const proto = String(p.protocol_name ?? '').trim() || (p.protocol !== undefined && p.protocol !== null ? `proto ${p.protocol}` : '?');
                  return `${addr}:${port}/${proto}`;
                }).join(', ');
                evidenceNote = ` As EVIDENCE ONLY — this does not feed the verdict — Vajra observed ${ports.length} currently-listening port${ports.length !== 1 ? 's' : ''} on this node, for example ${sample}${portsPayload?.has_more ? ', and more beyond this first page' : ''}. This raw inventory is attached for an assessor's reference; it is not compared against any approved-services baseline and does not by itself pass or fail this control.`;
              }
            } catch {
              // No evidence to attach; the verdict text below is unaffected.
            }
            checks['13'] = notAssessed(
              `Not assessed — deciding that a listening port, service or package is UNNECESSARY requires an approved-services baseline, and Vajra holds none: its whitelist and policy stores carry no approved-service or approved-port list for this organisation. Vajra does collect a listening-port inventory and a full software inventory for Windows endpoints, but classifying any of those entries as unnecessary without an approved list would be an invented judgement, and a hard-coded legacy-port list would manufacture failures on ports that are legitimate on a domain-joined Windows endpoint. What is missing: an organisation-defined approved services/ports baseline to compare the collected inventory against.${evidenceNote}`,
              'Not assessed — no approved services/ports baseline exists',
            );
          }
          if (checks['16'] === undefined) {
            checks['16'] = notAssessed('Not assessed on this endpoint — no alert history was read back for this node during this run, so whether automated alerts are generated for it was not measured.', 'Not assessed — no alert history read');
          }
          if (checks['17'] === undefined) {
            checks['17'] = notAssessed('Not assessed on this endpoint — no telemetry timestamps were available for this node during this run, so whether it is currently delivering monitoring data was not measured.', 'Not assessed — no telemetry recency evidence');
          }
          if (checks['18'] === undefined) {
            checks['18'] = notAssessed('Not assessed on this endpoint — this control needs CPU, memory, disk and bandwidth utilisation together with threshold alerting; Vajra collects no CPU utilisation from any endpoint and has no utilisation threshold or alert, so it cannot be measured here.', 'Not assessed — no CPU utilisation or threshold alerting');
          }
          // Point 19: CERT-In Incident Reporting
          checks['19'] = notAssessed('Not assessed — Vajra holds no record that any incident was reported to CERT-In from this organisation: no submission, submission timestamp or acknowledgement is stored anywhere, and its CERT-In draft store is empty. Whether reporting happened inside the mandated timeline is an organisational record Vajra does not hold, and the report generator it provides evidences document preparation, not reporting. What is missing: a recorded CERT-In submission with its timestamp and the incident detection time it is measured against.', 'Not assessed — no CERT-In submission record held');
          // Point 20: Log & Network Data Collection
          if (checks['20'] === undefined) {
            checks['20'] = notAssessed('Not assessed — of the four log families this control names, Vajra centrally collects only the network one: endpoint socket and DNS event streams are held for Windows endpoints, while the Windows Event Log families that would carry authentication, application and system logs have never returned a row for ANY host on this fleet even though the collection queries are scheduled — which points at a collection defect rather than at each endpoint refusing to ship its logs. No API exposes those per-family counts for a node either, so nothing could be read back here. What is missing: delivery of the Windows Event Log collections into the fleet database, and a read-only endpoint reporting per-host row counts and newest timestamps per log family. Note that Vajra storing telemetry does not discharge the entity\'s own obligation to retain the logs of its ICT systems.', 'Not assessed — authentication/application/system log collection not delivering');
          }
          // Point 21: Detailed Incident Report Maintained
          checks['21'] = notAssessed('Not assessed — Vajra holds no incident record for this organisation carrying a timeline, impact assessment, root cause and remediation. Its alert store carries triage fields (status, assignee, remarks) but none of the four elements this control names, and there is no incident-documentation entity in the platform at all. Vajra\'s own action log is a record of what Vajra did, not the organisation\'s incident documentation. What is missing: an incident record with timeline, impact, root cause and remediation fields.', 'Not assessed — no incident record entity exists');
          // Point 24: changes to OS, applications and network settings tracked
          // and logged. Each limb of the control text is mapped to the baseline
          // probe that evidences it, so the reason names the limb that is
          // unevidenced rather than reporting a single opaque failure.
          {
            const SCOPE_LIMBS: Array<{ key: string; failText: string }> = [
              { key: '16', failText: 'operating-system change auditing (Security System Extension — services, drivers, security packages) is off' },
              { key: '11', failText: 'application change auditing (Process Creation) is off' },
              { key: '17', failText: 'command-line capture in process-creation events is off, so an application change that is recorded does not show what was run' },
              { key: '12', failText: 'device/network-adapter change auditing (Plug and Play Events) is off' },
              { key: '15', failText: 'network security policy auditing (IPsec Driver) is off' },
            ];
            const readings = readBaseline(SCOPE_LIMBS.map((l) => l.key));
            const measured = readings.filter((r) => r.enabled !== null);
            const disabled = measured.filter((r) => r.enabled === false);
            const unmeasured = readings.filter((r) => r.enabled === null);
            if (baselineProbes === null) {
              checks['24'] = notAssessed(
                `Not assessed — ${baselineUnavailableNote}, so whether changes to this node's operating system, applications and network settings are tracked and logged was not measured.`,
                baselineAbsence === 'transport'
                  ? 'Not assessed — baseline change-auditing read failed'
                  : baselineAbsence === 'stale'
                    ? 'Not assessed — baseline change-auditing record too old'
                    : 'Not assessed — no baseline change-auditing record',
              );
            } else if (measured.length === 0) {
              checks['24'] = notAssessed(
                `Not assessed — the OS, application and network change-auditing probes on this node (${labelsOf(readings)}) all came back empty, so nothing could be read from the endpoint.`,
                'Not assessed — change-auditing probes returned no value',
              );
            } else if (disabled.length > 0) {
              const reasons = disabled.map((r) => SCOPE_LIMBS.find((l) => l.key === r.key)?.failText ?? r.label);
              checks['24'] = {
                compliant: false,
                reason: `Changes to this node are not logged by it (${baselineMeasuredAt}): ${reasons.join('; ')}. These are measured settings read from the endpoint's audit policy, not missing data.${baselineAgeNote}`,
                detail: `${measured.length - disabled.length} / ${measured.length} change-auditing settings enabled`,
              };
            } else if (measured.length === SCOPE_LIMBS.length) {
              checks['24'] = {
                compliant: true,
                reason: `This node logs changes across all three areas the control names (${baselineMeasuredAt}): operating system (Security System Extension), applications (Process Creation with command-line capture) and network settings (Plug and Play Events, IPsec Driver).`,
                detail: `${measured.length} / ${SCOPE_LIMBS.length} change-auditing settings enabled`,
              };
            } else {
              checks['24'] = notAssessed(
                `Only ${measured.length} of the ${SCOPE_LIMBS.length} change-auditing settings returned a readable value on this node (${labelsOf(measured)}), all of them enabled; ${labelsOf(unmeasured)} returned nothing, so this control was only partly measured. Nothing measured was in violation.`,
                'Not assessed — incomplete change-auditing evidence',
              );
            }
          }
          if (checks['25'] === undefined) {
            checks['25'] = notAssessed('Vajra did not return any update history data for this node, so the patch/update timeline visibility check remains unverified.', 'Update history unavailable');
          }
          // Point 28: this control asks for an INVENTORY of the installed
          // antivirus/EDR/firewall software "showing their operational status" —
          // it does not require that software to be enabled, so holding the
          // name+state records for this node is what satisfies it. With no product
          // records at all it stays not-assessed: the Vajra agent's own presence
          // identifies one product but does not enumerate what else is installed,
          // and enumeration is the thing this control asks for.
          if (checks['28'] === undefined) {
            checks['28'] = secProds.length > 0
              ? {
                compliant: true,
                reason: `Vajra maintains a security-software inventory for this node with each product's reported operational status: ${describeProds(secProds)}${agentEvidence ? `. In addition, ${agentEvidence.charAt(0).toLowerCase()}${agentEvidence.slice(1).replace(/\.$/, '')}` : ''}. This control asks for the inventory and the status it reports, both of which are present.`,
                detail: `${secProds.length} security product${secProds.length !== 1 ? 's' : ''} inventoried`,
              }
              : notAssessed('Not assessed on this endpoint — Vajra read back no antivirus, EDR or firewall product records for this node during this run, so no inventory of the security software installed on it, with operational status, was collected.', 'Not assessed — no security software records');
          }
          // Control 29 (local account inventory with privilege levels and last
          // login times) has no evaluator here. It previously stored a copy of
          // control 7's password-policy verdict, which is a different control and
          // is not evidence for this one.
          checks['29'] = notAssessed('Not assessed — Vajra holds no local account inventory for this node. The users, groups and logged-in-users collections are scheduled for Windows endpoints but have never returned a single row for any host on this fleet, and no snapshot of them exists in the snapshot store either, so no account list, privilege level or last-login time is available. The Windows security policy row Vajra does hold carries account POLICY settings, not an account list. What is missing: delivery of the users/groups/logged_in_users collection results into the fleet database.', 'Not assessed — account inventory collection never delivers');
          checks['31'] = notAssessed('Not assessed — Vajra holds no process or service inventory for this node. The process snapshot is scheduled for Windows endpoints but has never delivered a row to the fleet database for any host, no snapshot of it exists in the snapshot store, and the startup-items collection that would cover services is likewise empty; process-creation events reached only two Windows hosts and stopped months ago. The socket-event stream does carry the names of processes that opened a network connection, but a list of processes that happened to open a socket is not an inventory of everything running and is not presented as one. What is missing: delivery of the processes and startup_items collections.', 'Not assessed — process/service inventory never delivered');
          // Control 32 is evaluated in the dedicated Point 32 block above
          // (GET /api/nodes/network/uptime/{host}), which always sets it.
          // Control 34 is evaluated from the BitLocker rows in the point 26 block
          // above. It previously stored a copy of control 22's storage-volume
          // COUNT, which measures storage inventory, not encryption status.
          if (checks['34'] === undefined) {
            checks['34'] = notAssessed('Vajra did not read back any disk-encryption status records for this node, so whether the encryption state of its system and data volumes is reported was not measured.', 'Not measured — no disk encryption status records');
          }
          checks['35'] = notAssessed('Not assessed — Vajra collects no time-synchronisation state from this endpoint: there is no NTP peer configuration, no last successful sync timestamp and no measured clock offset anywhere in the collected data, and the Windows time-service registry values are not among the collected tables. The timezone value Vajra does hold for this node describes clock DISPLAY, not clock synchronisation, and is deliberately not scored as a sync verdict. What is missing: the configured NTP source, the last successful sync time and the measured offset.', 'Not assessed — no NTP configuration or sync time collected');
          // Control 39 (browser extension inventory) previously stored a copy of
          // control 36's installed-programs verdict, which is a different control.
          if (checks['39'] === undefined) {
            checks['39'] = notAssessed('Not assessed on this endpoint — no browser extension or add-on records were read back for this node during this run, so the browser extension and plugin inventory was not measured.', 'Not measured — no browser extension inventory');
          }
          // Control 41 (scheduled software updates and patch jobs) has no
          // evaluator here. It previously stored a copy of control 25's update
          // history verdict; installed update history is not evidence about the
          // scheduled patch jobs configured on the node.
          checks['41'] = notAssessed('Not assessed — Vajra holds no scheduled software-update or patch-job configuration for this node. Every patch job recorded on this fleet is ad-hoc: none carries a schedule, no Windows host appears in the patch-job node list, and the Windows patch requests on record are one-off install/uninstall actions. The endpoint side is not collected either — the Windows Update automatic-update settings live in the registry, which is not collected, and scheduled tasks are not among the collected tables. Installed-update history is control 25\'s evidence and says nothing about jobs scheduled ahead, so it is not reused here. What is missing: either a scheduled patch job in Vajra, or collection of the endpoint Windows Update / scheduled-task configuration.', 'Not assessed — no scheduled patch job or endpoint schedule collected');

          // Every visible control must be represented in the result set. A control
          // we could not evaluate is recorded as explicitly not-assessed so it stays
          // in the denominator instead of silently dropping out of the score.
          SEBI_HOT_COMMAND_KEYS.forEach((key) => {
            if (checks[key] === undefined) {
              checks[key] = notAssessed('Vajra did not collect any usable evidence for this control on this node during this run, so it has not been assessed.', 'Not assessed — no evidence collected');
            }
          });

          const trueChecks = Object.entries(checks)
            .filter(([, result]) => result?.compliant)
            .map(([key]) => `${key}: ${SEBI_HOT_GUIDELINES[key]?.label ?? 'Unknown check'}`);

          debugLog('[SEBI Hot] True checks for node', {
            hostId,
            hostname: String(node.hostname ?? node.name ?? ''),
            trueChecks,
          });

  return Object.fromEntries(
  Object.entries(checks).filter(
    ([key]) => !HIDDEN_GUIDELINES.has(key) && !STRUCTURALLY_UNMEASURABLE_SEBI_KEYS.has(key)
  )
);
}
