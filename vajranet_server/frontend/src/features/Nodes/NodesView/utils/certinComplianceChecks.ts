/**
 * Pure compliance-check helpers for NodesViewCertInCompliance — WS payload
 * parsing, and the fleet/per-host static check builder. Originally extracted
 * verbatim; the per-control evaluators have since been corrected.
 */

import { debugLog } from '@/lib/debugLog';
import type { NodeData } from '../types';
import api from '../../../../api/axiosInstance';
import { API_BASE_URL, API_PREFIX, NODES_URLS } from '../../../../api/urls';
import { nodesViewApi } from '../nodesViewApi';
import { fmtDateTime } from '../../../Compliance/shared/complianceDateUtils';
import { CERTIN_PENDING_POINTS, STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS } from '../constants/certinPendingPoints';
import { BASELINE_FRESHNESS_DAYS } from './sebiComplianceChecks';

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

/**
 * Two Windows telemetry endpoints that exist in the backend
 * (backend/src/routes/api/windows.ts) but carry no WINDOWS_URLS entry and no
 * nodesViewApi wrapper, so they are addressed here directly. Promoting them into
 * src/api/urls.ts and nodesViewApi.ts is a follow-up in files outside this change.
 */
const WINDOWS_SECURITY_PRODUCTS_URL = `${API_BASE_URL}${API_PREFIX}/windows/security_products`;
const WINDOWS_SECURITY_CENTER_URL = `${API_BASE_URL}${API_PREFIX}/windows/security_center`;

/**
 * Resolves to null instead of rejecting. Every evidence fetch below goes through
 * this so a failed, unreachable or 404-ing probe reaches its control as "not
 * measured" rather than aborting the sweep or being read as a negative result.
 */
async function settle<T>(work: () => Promise<T>): Promise<T | null> {
  try {
    return await work();
  } catch {
    return null;
  }
}

interface ComplianceBaseline {
  /** Unix seconds the baseline sweep was taken, or null when the row carries none. */
  unixtime: number | null;
  /** command_key -> raw output string ('' when the probe returned nothing). */
  byKey: Map<string, string>;
}

/**
 * Latest compliance_results row for a node
 * (GET /api/nodes/compliance/latest/:host_identifier -> node_compliance_latest).
 * Returns null when the request failed, no row exists, or compliance_data is not
 * the expected array — all three mean "not measured", never a negative result.
 */
async function fetchComplianceBaseline(hostId: string): Promise<ComplianceBaseline | null> {
  const res = await fetch(`${NODES_URLS.COMPLIANCE_LATEST}${encodeURIComponent(hostId)}`, { credentials: 'include' });
  if (!res.ok) return null;
  const json = await res.json();
  const row = json?.data;
  if (!row || typeof row !== 'object') return null;
  const entries = (row as { compliance_data?: unknown }).compliance_data;
  if (!Array.isArray(entries)) return null;

  const byKey = new Map<string, string>();
  entries.forEach((entry) => {
    if (!entry || typeof entry !== 'object') return;
    const item = entry as { command_key?: unknown; output?: unknown };
    if (item.command_key === undefined || item.command_key === null) return;
    byKey.set(String(item.command_key), item.output === undefined || item.output === null ? '' : String(item.output));
  });

  const ts = Number((row as { unixtime?: unknown }).unixtime);
  return { unixtime: Number.isFinite(ts) && ts > 0 ? ts : null, byKey };
}

/**
 * Runs read-only PowerShell status keys over the agent WebSocket and returns
 * command_key -> output for the ones that came back with a usable string. Keys
 * passed here must be on the read-only allowlist in backend/src/websocket/node.ts.
 */
// Exported so NodesViewIRDAIHotCompliance.tsx's control 20 can read the same live
// Defender-signature telemetry (PowerShell key 64) this file's control 5.11 uses, rather
// than the two registers answering the identical "is the antivirus healthy" question from
// two different evidence sources that could disagree — see control 20's WHY-comment.
export async function fetchPowerShellOutputs(
  hostId: string,
  keys: string[],
  wsConnected: boolean,
  wsSendMessage?: (message: unknown) => Promise<unknown>,
): Promise<Map<string, string> | null> {
  if (!wsConnected || !wsSendMessage) return null;

  const response = await wsSendMessage({
    type: 'agent',
    params: { agent: 'powershell', action: 'run', command_keys: keys },
    host_identifier: hostId,
  }) as { response?: unknown };

  const raw = parseWsPayload(response);
  if (!Array.isArray(raw)) return null;

  const outputs = new Map<string, string>();
  raw.forEach((entry) => {
    if (!entry || typeof entry !== 'object') return;
    const item = entry as { command_key?: unknown; output?: unknown };
    if (item.command_key === undefined || item.command_key === null) return;
    if (typeof item.output !== 'string' || item.output.trim() === '') return;
    outputs.set(String(item.command_key), item.output);
  });
  return outputs;
}

/** JSON.parse a PowerShell output string into an array of objects, or null. */
export function parsePsObjectList(raw: string | undefined): Array<Record<string, unknown>> | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.filter((e) => e && typeof e === 'object') as Array<Record<string, unknown>>;
    if (parsed && typeof parsed === 'object') return [parsed as Record<string, unknown>];
    return null;
  } catch {
    return null;
  }
}

/** Numeric column reader: null for absent/blank/unparseable, so it is never read as 0. */
function numericField(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/**
 * Baseline command keys 5-16: the twelve Windows advanced-audit-policy
 * subcategories the agent measures with `auditpol /get /subcategory:"..."`.
 * Labels mirror GUIDELINES in NodesViewCompliance. Output "True" means the
 * subcategory audits both Success and Failure.
 */
const AUDIT_SUBCATEGORY_KEYS: ReadonlyArray<readonly [string, string]> = [
  ['5', 'Special Logon'],
  ['6', 'Credential Validation'],
  ['7', 'Computer Account Management'],
  ['8', 'Other Account Management Events'],
  ['9', 'Security Group Management'],
  ['10', 'User Account Management'],
  ['11', 'Process Creation'],
  ['12', 'Plug and Play Events'],
  ['13', 'Account Lockout'],
  ['14', 'Logon'],
  ['15', 'IPsec Driver'],
  ['16', 'Security System Extension'],
];

/**
 * compliance_results is written only when an operator runs the 18-key baseline
 * sweep, so a host can carry a months-old snapshot. Past this bound the values
 * are no longer a statement about the node's current configuration, and the
 * verdict degrades to not-assessed rather than standing on stale evidence.
 * Reads BASELINE_FRESHNESS_DAYS from sebiComplianceChecks.ts rather than a
 * second copy of the same number, so CERT-In, SEBI and IRDAI can't drift apart.
 */
const COMPLIANCE_BASELINE_MAX_AGE_DAYS = BASELINE_FRESHNESS_DAYS;

/** CERT-In password guidance floor used by control 3.7. */
const MIN_PASSWORD_LENGTH = 8;

/**
 * A Defender signature set older than this is a measured negative for control
 * 5.11 — the conventional bound for antivirus definition currency. Exported so
 * NodesViewIRDAIHotCompliance.tsx's control 20 uses the identical bound rather than a
 * second copy of the same number that could drift out of sync.
 */
export const SIGNATURE_MAX_AGE_DAYS = 7;

/**
 * Inbound remote-service ports whose exposure inside a network segment is the
 * lateral-movement path CERT-In 1.10 asks about. MITRE ATT&CK Remote Services
 * (T1021): SMB/Windows Admin Shares 445 and 139 (T1021.002), RDP 3389
 * (T1021.001), WinRM 5985 and 5986 (T1021.006).
 *
 * 135, 137 and 138 are deliberately excluded. They are the stock RPC
 * endpoint-mapper and NetBIOS name/datagram rules present on every Windows host,
 * so including them would make this control fire universally on discovery
 * traffic rather than on a remote-service path an attacker can move over.
 */
export const LATERAL_MOVEMENT_INBOUND_PORTS: ReadonlySet<string> = new Set(['139', '445', '3389', '5985', '5986']);

/**
 * local_ports is a comma-separated list ('445', '23554,23555,23556'), a range
 * ('49152-65535'), a service name ('RPC') or '*'. Only an exact port token is
 * matched: neither a range nor a wildcard identifies a specific remote service.
 */
function lateralPortInRule(localPorts: unknown): string | null {
  return String(localPorts ?? '')
    .split(',')
    .map((token) => token.trim())
    .find((token) => LATERAL_MOVEMENT_INBOUND_PORTS.has(token)) ?? null;
}

/** True when a rule's remote scope reaches the whole segment ('*', Any, LocalSubnet). */
function remoteScopeIsSegmentWide(remoteAddresses: unknown): boolean {
  const value = String(remoteAddresses ?? '').trim().toLowerCase();
  if (value === '') return false;
  if (value === '*' || value === 'any') return true;
  return value.split(',').some((token) => token.trim() === 'localsubnet');
}

/**
 * Get-NetFirewallProfile serialises DefaultInboundAction either as text or as the
 * NetSecurity enum (NotConfigured = 0, Allow = 1, Block = 2). Any other encoding
 * stays 'unknown' so it can drive neither a pass nor a failure.
 */
function normaliseInboundAction(value: unknown): 'allow' | 'block' | 'unknown' {
  const v = String(value ?? '').trim().toLowerCase();
  if (v === 'allow' || v === '1') return 'allow';
  if (v === 'block' || v === '2') return 'block';
  return 'unknown';
}

/** Boolean-ish reader for WS payloads; null when the value is not recognisable. */
function normaliseBoolean(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value;
  const v = String(value ?? '').trim().toLowerCase();
  if (v === 'true' || v === '1') return true;
  if (v === 'false' || v === '0') return false;
  return null;
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
  }) as { response?: unknown };

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
    }) as { response?: unknown };

    const raw = typeof response.response === 'string'
      ? JSON.parse(response.response)
      : response.response;

    if (raw && typeof raw === 'object' && 'usb_storage_policy' in raw) {
      return raw as UsbStatusResponse;
    }
    return null;
  }

  const response = await wsSendMessage({
    type: 'agent',
    params: { agent: 'powershell', action: 'allow', command_keys: ['54'] },
    host_identifier: hostId,
  }) as { response?: unknown };

  const items = typeof response.response === 'string'
    ? JSON.parse(response.response)
    : response.response;

  if (!Array.isArray(items)) return null;
  const item = items.find((entry) => entry && typeof entry === 'object' && (entry as { command_key?: string }).command_key === '54') as { output?: string } | undefined;
  if (!item?.output) return null;

  const parsed = JSON.parse(item.output);
  if (parsed && typeof parsed === 'object' && ('status' in parsed || 'enabled' in parsed)) {
    return parsed as UsbStatusResponse;
  }

  return null;
}

export async function staticComplianceChecks(
  hostId: string,
  node: NodeData,
  wsConnected = false,
  wsSendMessage?: (message: unknown) => Promise<unknown>,
): Promise<Record<string, StaticCheckResult | undefined>> {
  const checks: Record<string, StaticCheckResult | undefined> = {};

  // Evidence shared by several controls below, gathered once per node. Every
  // fetch settles to null rather than rejecting, so an absent, 404-ing or
  // unreachable probe reaches its control as "not measured" and can never be
  // read as a negative result.
  const [baseline, securityProducts, securityCentre, firewallRules] = await Promise.all([
    settle(() => fetchComplianceBaseline(hostId)),
    settle(async () => {
      const res = await api.post(WINDOWS_SECURITY_PRODUCTS_URL, { host_identifier: hostId });
      const payload = res.data as { status?: string; data?: unknown[] } | null;
      return payload?.status === 'Success' && Array.isArray(payload.data) && payload.data.length > 0
        ? (payload.data as Array<Record<string, unknown>>)
        : null;
    }),
    settle(async () => {
      const res = await api.post(WINDOWS_SECURITY_CENTER_URL, { host_identifier: hostId });
      const payload = res.data as { status?: string; data?: unknown[] } | null;
      return payload?.status === 'Success' && Array.isArray(payload.data) && payload.data.length > 0
        ? (payload.data[0] as Record<string, unknown>)
        : null;
    }),
    settle(async () => {
      const res = await nodesViewApi.getFirewallRules(hostId);
      const payload = res.data as { status?: string; data?: unknown[] } | null;
      return payload?.status === 'Success' && Array.isArray(payload.data) && payload.data.length > 0
        ? (payload.data as Array<Record<string, unknown>>)
        : null;
    }),
  ]);

  // Read-only PowerShell status keys, one round trip: 64 is Defender signature
  // telemetry (control 5.11) and 69 is the per-profile firewall status used by
  // control 1.10. Both are on the read-only allowlist in websocket/node.ts.
  const psOutputs = await settle(() => fetchPowerShellOutputs(hostId, ['64', '69'], wsConnected, wsSendMessage));

  /** Rows of the node's newest security-products snapshot only. */
  const currentSecurityProducts = (() => {
    if (!securityProducts) return null;
    // A host can carry a stale duplicate product name (an old 'Microsoft Defender
    // Antivirus' row alongside the current 'Antivirus Microsoft Defender'),
    // because the controller returns one row per distinct name. Pin to the
    // newest snapshot so a retired product cannot decide the verdict.
    const newest = securityProducts.reduce((max, row) => Math.max(max, numericField(row.unixtime) ?? 0), 0);
    return securityProducts.filter((row) => (numericField(row.unixtime) ?? 0) === newest);
  })();

          let isSoftwareInventoryMaintained = false;
          let isHardwareInventoryMaintained = false;
          // Point 1.4: Software inventory (per-host)
          try {
            const res = await nodesViewApi.getProgramsList(hostId, node.os_name ?? node.os_platform);
            const data = (res.data ?? {}) as { programs?: unknown[]; deb?: unknown[]; rpm?: unknown[] };
            const isWindows = /windows/i.test(String(node.os_name ?? node.os_platform ?? ''));
            const winCount = Array.isArray(data.programs) ? data.programs.length : 0;
            const debCount = Array.isArray(data.deb) ? data.deb.length : 0;
            const rpmCount = Array.isArray(data.rpm) ? data.rpm.length : 0;
            const packageCount = isWindows ? winCount : debCount + rpmCount;
            if (packageCount > 0) {
              isSoftwareInventoryMaintained = true;
            }
          } catch {
            // leave undefined
          }

          // Fetch full node details if required for hardware/sec products
          const nodeAny = node as unknown as Record<string, unknown>;
          const hasHardware = !!(nodeAny.hardware_model || nodeAny.hardware_vendor || nodeAny.hardware_physical_memory);
          const hasSecProds = Array.isArray(nodeAny.security_products);
          let detailNode: Record<string, unknown> = nodeAny;
          if (!hasHardware || !hasSecProds) {
            try {
              const res = await fetch(`${NODES_URLS.NODE}${encodeURIComponent(hostId)}`, { credentials: 'include' });
              if (res.ok) {
                const json = await res.json();
                const raw = json?.data ?? json;
                if (raw && typeof raw === 'object') detailNode = raw as Record<string, unknown>;
              }
            } catch {
              // fallback to provided node
            }
          }

          // Point 1.4: Hardware inventory
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
              if (parts.length >= 3) {
                isHardwareInventoryMaintained = true;
              }
            }
          }
          if (isHardwareInventoryMaintained && isSoftwareInventoryMaintained) {
            // Control 1.4 asks whether an inventory of AUTHORIZED hardware and
            // software is maintained — "authorized" requires comparing observed
            // assets against an approved/allow-listed baseline. This block only
            // confirms hardware fields (vendor/model/CPU/RAM/OS) and a non-empty
            // installed-software/package list are populated, i.e. that SOME
            // inventory exists, not that it is an inventory of AUTHORIZED items.
            // No approved-asset baseline is stored to compare against — the same
            // reason 3.4 ("Government-offered" AV), 5.10 ("CERT-In/NIC-CERT
            // recommended" AV) and 5.8 ("unwanted" components/services/ports) are
            // deliberately withheld from auto-answering — so the "authorized" half
            // of this control, and "the CERT-In requirement" as a whole, are not
            // claimed as satisfied here; the earlier wording overclaimed exactly
            // that and has been removed.
            checks['1.4'] = {
              compliant: true,
              reason: `Vajra holds a populated hardware and software inventory for this node (hardware fields such as vendor, model, CPU and RAM, and a non-empty installed-software/package list). This measures that an inventory exists and is populated, not that its contents are an inventory of AUTHORIZED assets specifically — no approved-hardware/software baseline is stored to compare against, so that half of the control is not assessed here.`,
              detail: 'Hardware and software inventory present (not verified against an authorized-asset baseline)',
            };
          }

          // Point 5.11: Antivirus client/server update provision
          {
            // Answered from windows_security_products.signatures_up_to_date — the
            // Windows Security Center report of whether each registered antivirus
            // product's definitions are current — corroborated where available by
            // the live Defender signature date (PowerShell key 64).
            //
            // It is still NOT answered from Windows Update install history. That is
            // OS patch currency, not antivirus signature currency: a fully patched
            // host can carry months-stale signatures, and a host that has needed no
            // OS update recently can be entirely current on signatures.
            const antivirusProducts = (currentSecurityProducts ?? []).filter(
              (row) => String(row.type ?? '').trim().toLowerCase() === 'antivirus'
                && String(row.state ?? '').trim().toLowerCase() === 'on',
            );

            // Live Defender signature telemetry, used only to add a second measured
            // negative (a definitely stale signature date); it can never turn a
            // measured negative into a pass. It speaks for Defender only, so it is
            // read solely when Defender is one of the running antivirus products —
            // on a node protected by a third-party product Defender's own signature
            // age says nothing about the product actually doing the scanning.
            const defenderIsRunning = antivirusProducts.some((row) => /defender/i.test(String(row.name ?? '')));
            const signatureTelemetry = defenderIsRunning ? (parsePsObjectList(psOutputs?.get('64'))?.[0] ?? null) : null;
            const signatureVersion = String(signatureTelemetry?.AntivirusSignatureVersion ?? '').trim();
            const signatureUpdatedRaw = String(signatureTelemetry?.AntivirusSignatureLastUpdated ?? '').trim();
            const signatureUpdatedMs = signatureUpdatedRaw ? Date.parse(signatureUpdatedRaw) : NaN;
            const signatureAgeDays = Number.isFinite(signatureUpdatedMs) && signatureUpdatedMs <= Date.now()
              ? Math.floor((Date.now() - signatureUpdatedMs) / 86400000)
              : null;
            const signatureContext = signatureVersion || signatureUpdatedRaw
              ? ` Live Defender telemetry reports signature version ${signatureVersion || 'unreported'}, last updated ${signatureUpdatedRaw || 'at an unreported time'}.`
              : '';

            const staleProducts = antivirusProducts.filter((row) => numericField(row.signatures_up_to_date) === 0);
            const unknownProducts = antivirusProducts.filter((row) => numericField(row.signatures_up_to_date) === null);
            const staleSignatureDate = signatureAgeDays !== null && signatureAgeDays > SIGNATURE_MAX_AGE_DAYS;
            const productNames = (rows: Array<Record<string, unknown>>) =>
              rows.map((row) => String(row.name ?? 'unnamed product')).join(', ');

            if (currentSecurityProducts === null) {
              checks['5.11'] = notAssessed(
                'Not assessed on this endpoint. Vajra holds no Windows security-product record for this node, so the currency of its antivirus definitions was not measured. Answering this control needs the registered antivirus product and its signature status; Windows Update install history measures OS patch currency, not antivirus signature currency, and is deliberately not used here.',
                'Not assessed — no security-product record held',
              );
            } else if (antivirusProducts.length === 0) {
              checks['5.11'] = notAssessed(
                'Not assessed on this endpoint. Vajra holds a Windows security-product record for this node, but it lists no antivirus product in a running state, so there is no product whose definition currency could be measured. An absent or stopped product is not evidence that definitions are out of date.',
                'Not assessed — no running antivirus product reported',
              );
            } else if (staleProducts.length > 0) {
              checks['5.11'] = {
                compliant: false,
                reason: `Antivirus definitions are not being kept current on this node: Windows Security Center reports the signatures of ${productNames(staleProducts)} as out of date.${signatureContext}`,
                detail: `Definitions out of date: ${productNames(staleProducts)}`,
              };
            } else if (staleSignatureDate) {
              checks['5.11'] = {
                compliant: false,
                reason: `Antivirus definitions are not being kept current on this node: the Defender signature set was last updated ${signatureAgeDays} days ago (${signatureUpdatedRaw}), beyond the ${SIGNATURE_MAX_AGE_DAYS}-day bound this check treats as current, even though Windows Security Center still reports the definitions as up to date.`,
                detail: `Defender signatures ${signatureAgeDays} days old`,
              };
            } else if (unknownProducts.length > 0) {
              checks['5.11'] = notAssessed(
                `Not assessed on this endpoint. Windows Security Center returned no signature-currency value for ${productNames(unknownProducts)} on this node, so whether its definitions are being updated was not measured.`,
                'Not assessed — signature currency not reported',
              );
            } else {
              checks['5.11'] = {
                compliant: true,
                reason: `Antivirus definitions are being kept current on this node: Windows Security Center reports the signatures of ${productNames(antivirusProducts)} as up to date.${signatureContext}`,
                detail: `Definitions up to date: ${productNames(antivirusProducts)}`,
              };
            }
          }

          // Point 4.1: logging enabled on all ICT systems
          {
            // Answered from the node's OWN advanced audit policy: baseline command
            // keys 5-16, twelve `auditpol /get /subcategory:` probes stored in
            // compliance_results. That IS the endpoint's log-channel configuration,
            // so nothing here infers compliance from Vajra storing telemetry —
            // CERT-In Direction (iv) obligates the entity for the logs of its own
            // ICT systems, and Vajra holding a copy does not discharge it.
            const measuredSubcategories: Array<{ label: string; enabled: boolean }> = [];
            AUDIT_SUBCATEGORY_KEYS.forEach(([key, label]) => {
              const value = String(baseline?.byKey.get(key) ?? '').trim().toLowerCase();
              // Anything else — key absent, empty string from a probe that failed,
              // or an unexpected value — is unmeasured and is dropped rather than
              // counted as a negative.
              if (value === 'true') measuredSubcategories.push({ label, enabled: true });
              else if (value === 'false') measuredSubcategories.push({ label, enabled: false });
            });

            const baselineAgeDays = baseline?.unixtime != null
              ? Math.floor((Date.now() / 1000 - baseline.unixtime) / 86400)
              : null;
            const measuredAt = baseline?.unixtime != null ? fmtDateTime(baseline.unixtime) : 'an unrecorded time';
            const disabledSubcategories = measuredSubcategories.filter((entry) => !entry.enabled);
            // The measurement covers this Windows endpoint's audit policy only.
            const scopeNote = " This is measured on this Windows endpoint's own advanced audit policy; servers, network devices and applications outside the Vajra-managed Windows endpoints are not covered by it.";

            if (measuredSubcategories.length === 0) {
              checks['4.1'] = notAssessed(
                'Not assessed on this endpoint. No advanced-audit-policy result is held for this node — the Windows baseline sweep that reads the twelve auditpol subcategories has either never run here or returned no usable value — so whether logging is enabled on it was not measured.',
                'Not assessed — no advanced-audit-policy result held',
              );
            } else if (baselineAgeDays !== null && baselineAgeDays > COMPLIANCE_BASELINE_MAX_AGE_DAYS) {
              checks['4.1'] = notAssessed(
                `Not assessed on this endpoint. The advanced-audit-policy result held for this node was measured on ${measuredAt}, ${baselineAgeDays} days ago, beyond the ${COMPLIANCE_BASELINE_MAX_AGE_DAYS}-day bound this check treats as current, so it is not evidence of the node's present logging configuration.`,
                `Not assessed — audit policy snapshot ${baselineAgeDays} days old`,
              );
            } else if (disabledSubcategories.length > 0) {
              checks['4.1'] = {
                compliant: false,
                reason: `Logging is not enabled as required on this node: ${disabledSubcategories.length} of the ${measuredSubcategories.length} advanced-audit-policy subcategories measured are switched off (${disabledSubcategories.map((entry) => entry.label).join(', ')}), measured on ${measuredAt}.${scopeNote}`,
                detail: `${disabledSubcategories.length} of ${measuredSubcategories.length} audit subcategories disabled`,
              };
            } else if (measuredSubcategories.length === AUDIT_SUBCATEGORY_KEYS.length) {
              checks['4.1'] = {
                compliant: true,
                reason: `Logging is enabled as required on this node: all ${measuredSubcategories.length} advanced-audit-policy subcategories are auditing both Success and Failure, measured on ${measuredAt}.${scopeNote}`,
                detail: `All ${measuredSubcategories.length} audit subcategories enabled`,
              };
            } else {
              checks['4.1'] = notAssessed(
                `Not assessed on this endpoint. Only ${measuredSubcategories.length} of the ${AUDIT_SUBCATEGORY_KEYS.length} advanced-audit-policy subcategories returned a usable value for this node (measured on ${measuredAt}), and each of those is enabled. The remaining ${AUDIT_SUBCATEGORY_KEYS.length - measuredSubcategories.length} were not measured, so logging cannot be confirmed as enabled across the required subcategories.`,
                `Not assessed — ${measuredSubcategories.length} of ${AUDIT_SUBCATEGORY_KEYS.length} subcategories measured`,
              );
            }
          }

          // Point 1.10: host firewall restricts lateral movement in the segment
          {
            // Three stages, most decisive first:
            //   1. the firewall itself being off, or its default inbound action
            //      changed to Allow (live PowerShell key 69, falling back to the
            //      Windows Security Center product state);
            //   2. an enabled inbound Allow rule that opens an SMB/RDP/WinRM port
            //      to the whole segment (windows_firewall_rules);
            //   3. a pass, which needs stage 1 to have positively established that
            //      every profile is enabled and defaults to Block — without that a
            //      node needs no permitting rule to be reachable.
            const firewallProfiles = parsePsObjectList(psOutputs?.get('69'));
            const profilesUsable = firewallProfiles !== null && firewallProfiles.length > 0;

            const disabledProfiles = (firewallProfiles ?? [])
              .filter((profile) => normaliseBoolean(profile.Enabled) === false)
              .map((profile) => String(profile.Name ?? 'unnamed'));
            const permissiveProfiles = (firewallProfiles ?? [])
              .filter((profile) => normaliseBoolean(profile.Enabled) === true
                && normaliseInboundAction(profile.DefaultInboundAction) === 'allow')
              .map((profile) => String(profile.Name ?? 'unnamed'));
            const blockingProfiles = (firewallProfiles ?? []).filter(
              (profile) => normaliseBoolean(profile.Enabled) === true
                && normaliseInboundAction(profile.DefaultInboundAction) === 'block',
            );
            const allProfilesBlocking = profilesUsable
              && blockingProfiles.length === (firewallProfiles as Array<Record<string, unknown>>).length;

            // Stage 1 fallback, used only when key 69 gave nothing: every firewall
            // product Windows Security Center knows about is reported not running.
            const firewallProducts = (currentSecurityProducts ?? []).filter(
              (row) => String(row.type ?? '').trim().toLowerCase() === 'firewall',
            );
            const allFirewallProductsOff = !profilesUsable
              && firewallProducts.length > 0
              && firewallProducts.every((row) => String(row.state ?? '').trim().toLowerCase() !== 'on');

            // Stage 2: enabled inbound Allow rules opening a lateral-movement port
            // to the whole segment.
            const permittingRules = (firewallRules ?? [])
              .map((rule) => {
                if ((numericField(rule.enabled) ?? 0) !== 1) return null;
                if (String(rule.direction ?? '').trim().toLowerCase() !== 'in') return null;
                if (String(rule.action ?? '').trim().toLowerCase() !== 'allow') return null;
                const port = lateralPortInRule(rule.local_ports);
                if (port === null) return null;
                if (!remoteScopeIsSegmentWide(rule.remote_addresses)) return null;
                return `${String(rule.name ?? 'unnamed rule')} (port ${port} from ${String(rule.remote_addresses ?? '').trim()})`;
              })
              .filter((entry): entry is string => entry !== null);

            const findings: string[] = [];
            if (disabledProfiles.length > 0) {
              findings.push(`the Windows Firewall is switched off on the ${disabledProfiles.join(', ')} profile${disabledProfiles.length !== 1 ? 's' : ''}`);
            }
            if (permissiveProfiles.length > 0) {
              findings.push(`the default inbound action is Allow on the ${permissiveProfiles.join(', ')} profile${permissiveProfiles.length !== 1 ? 's' : ''}`);
            }
            if (allFirewallProductsOff) {
              findings.push(`Windows Security Center reports every registered firewall product on this node (${firewallProducts.map((row) => String(row.name ?? 'unnamed product')).join(', ')}) as not running`);
            }
            if (permittingRules.length > 0) {
              findings.push(`${permittingRules.length} enabled inbound Allow rule${permittingRules.length !== 1 ? 's' : ''} open${permittingRules.length === 1 ? 's' : ''} a remote-service port to the whole segment (${permittingRules.join('; ')})`);
            }

            if (findings.length > 0) {
              checks['1.10'] = {
                compliant: false,
                reason: `The host firewall on this node does not restrict lateral movement within the same network segment: ${findings.join('; and ')}. Ports 139 and 445 (SMB), 3389 (RDP) and 5985/5986 (WinRM) are the remote services MITRE ATT&CK T1021 moves over; the stock RPC endpoint-mapper and NetBIOS rules on 135/137/138 are deliberately not counted.`,
                detail: permittingRules.length > 0
                  ? `${permittingRules.length} inbound rule${permittingRules.length !== 1 ? 's' : ''} permit lateral movement`
                  : 'Host firewall not enforcing inbound restriction',
              };
            } else if (profilesUsable && allProfilesBlocking && firewallRules !== null) {
              checks['1.10'] = {
                compliant: true,
                reason: `The host firewall on this node restricts lateral movement within the same network segment: every firewall profile is enabled with a default inbound action of Block, and none of the ${firewallRules.length} rules in its current snapshot permits inbound SMB (139/445), RDP (3389) or WinRM (5985/5986) from the local subnet or from any address.`,
                detail: 'All profiles enabled, default inbound Block, no permitting rule',
              };
            } else if (firewallRules === null) {
              // An empty or missing rule set cannot be distinguished from a
              // snapshot that was never collected: the collection path answers
              // "no snapshot at all" and "snapshot with no rules" with the same
              // 404, and its lookup is bounded by a recent-id window.
              checks['1.10'] = notAssessed(
                "Not assessed on this endpoint. Vajra received no usable firewall rule snapshot for this node — an empty result from this collection path cannot be distinguished from rules never having been reported for it — so no inbound rule permitting SMB, RDP or WinRM across the segment could be looked for. A rule count on its own would not establish the answer either.",
                'Not assessed — no firewall rule snapshot returned',
              );
            } else {
              checks['1.10'] = notAssessed(
                `Not assessed on this endpoint. None of the ${firewallRules.length} rules in this node's firewall snapshot permits inbound SMB (139/445), RDP (3389) or WinRM (5985/5986) from the local subnet or from any address, but that cannot be upgraded to a pass: the per-profile Enabled and DefaultInboundAction values (Get-NetFirewallProfile) were not returned for this node, and a firewall whose default inbound action has been changed to Allow needs no such rule to be reachable.`,
                'Not assessed — per-profile default inbound action not returned',
              );
            }
          }

          // Point 1.12: network firewall configured for the ministry/department
          {
            // Deliberately never answered from windows_firewall_rules: those are
            // host rules, which are the wrong subject for this control.
            checks['1.12'] = notAssessed(
              'Not assessed. No network or perimeter firewall device is enrolled in Vajra — the only firewall telemetry the platform holds is host-based (Windows Firewall rules per endpoint, and nftables/firewalld/ufw state on Linux hosts), which does not answer whether the ministry/department network firewall is configured. Separately, whether network access matches the requirements of official work is a determination against an approved network-access baseline, and no such baseline is stored.',
              'Not assessed — no network firewall enrolled, no approved access baseline',
            );
          }

          // Point 3.8: USB status from websocket
          try {
            const usbStatus = await fetchUsbStatusForCompliance(hostId, node, wsConnected, wsSendMessage);
            // `enabled: true`, `status: 'enabled'` and `usb_storage_policy: 'Enabled'`
            // all mean removable storage is PERMITTED on the node (see the
            // isEnabled/isDisabled derivation in NodesViewUsbControl), so the CERT-In
            // restriction is satisfied only when storage is reported as disabled.
            // Windows nodes answer with enabled/status, Linux nodes with
            // usb_storage_policy — both shapes have to be read here.
            const storagePermitted = usbStatus?.enabled === true
              || usbStatus?.status === 'enabled'
              || usbStatus?.usb_storage_policy === 'Enabled';
            const storageBlocked = usbStatus?.enabled === false
              || usbStatus?.status === 'disabled'
              || usbStatus?.usb_storage_policy === 'Disabled';
            debugLog('USB status for compliance check:', { usbStatus, storagePermitted, storageBlocked });

            if (storagePermitted || storageBlocked) {
              checks['3.8'] = {
                compliant: storageBlocked,
                reason: storageBlocked
                  ? 'Vajra queried live USB telemetry and confirmed that removable storage is disabled on this node, satisfying the CERT-In removable media restriction requirement.'
                  : 'Vajra queried live USB telemetry and found removable storage is still permitted on this node, so the CERT-In removable media restriction requirement is not yet satisfied.',
                detail: storageBlocked ? 'Removable storage disabled' : 'Removable storage permitted',
              };
            }
            // Neither key present (no response, or a response we could not read):
            // the removable-storage policy is unknown, so 3.8 is deliberately left
            // unset and surfaces as "Not Checked" rather than being resolved either
            // way from telemetry we never received.
          } catch {
            // A failed query is not evidence of either state — leave 3.8 unset so it
            // reports as not assessed instead of as a pass or a failure.
          }

          // Point 2.6: Wi-Fi status from websocket
          {
            try {
              const wifiStatus = await fetchWifiStatusForCompliance(hostId, wsConnected, wsSendMessage);
              const connectedSsid = String(wifiStatus?.connected?.ssid ?? '').trim();
              const savedProfiles = Array.isArray(wifiStatus?.saved_profiles) ? wifiStatus?.saved_profiles.length : 0;

              if (wifiStatus) {
                // Identifying a rogue access point, or one spoofing a corporate
                // SSID, means comparing observed BSSIDs/SSIDs against an authorised
                // access point list. Vajra holds no such list, and this response
                // carries only the node's own current association and its saved
                // profiles — no scan of neighbouring access points. A successful
                // status query therefore evidences Wi-Fi telemetry collection, not
                // the presence of rogue-AP detection tooling in the WLAN platform.
                const wifiObservation = connectedSsid
                  ? `connected to SSID "${connectedSsid}", ${savedProfiles} saved profile${savedProfiles !== 1 ? 's' : ''}`
                  : `no active Wi-Fi connection, ${savedProfiles} saved profile${savedProfiles !== 1 ? 's' : ''}`;
                checks['2.6'] = notAssessed(
                  `Vajra read live Wi-Fi status for this node (${wifiObservation}), but whether the WLAN platform has tooling to identify rogue access points or SSID spoofing was not assessed. That requires observed BSSIDs/SSIDs to be compared against an authorised access point list: Vajra holds no authorised AP/SSID list, and this response reports only the node's own association and saved profiles, with no scan of neighbouring access points.`,
                  'Not assessed — no authorised AP/SSID list, no neighbouring-AP scan',
                );
              } else {
                checks['2.6'] = notAssessed(
                  'Vajra could not retrieve live Wi-Fi telemetry for this node because the WebSocket Wi-Fi status query did not return data, so rogue access point detection was not assessed.',
                  'Not assessed — Wi-Fi status unavailable',
                );
              }
            } catch {
              checks['2.6'] = notAssessed(
                'The Wi-Fi status query for this node failed before a usable response was returned, so rogue access point detection was not assessed.',
                'Not assessed — Wi-Fi status query failed',
              );
            }
          }

      // Point 3.7: security of password enforced as per the guidelines
      {
        // Predicate kept identical to the SEBI display-7 / IRDAI-6 password
        // control so the three registers agree literally on the same node.
        // A measured 0 is a real negative (no policy enforced) and is a fail; an
        // absent or unparseable value is not measured and is never a fail.
        const profile = await settle(async () => {
          const res = await nodesViewApi.getSecurityProfileInfo(hostId);
          const payload = res.data as { status?: string; data?: unknown[] } | null;
          return payload?.status === 'Success' && Array.isArray(payload.data) && payload.data.length > 0
            ? (payload.data[0] as Record<string, unknown>)
            : null;
        });

        const minLength = numericField(profile?.minimum_password_length);
        const complexity = numericField(profile?.password_complexity);
        const history = numericField(profile?.password_history_size);
        const lockout = numericField(profile?.lockout_bad_count);

        if (minLength === null && complexity === null && history === null && lockout === null) {
          // Fallback: baseline command key 18, `net accounts` minimum password
          // length. Its empty-string output is a failed probe, not a zero.
          const rawKey18 = String(baseline?.byKey.get('18') ?? '').trim();
          const baselineMinLength = rawKey18 === '' ? null : numericField(rawKey18);

          if (baselineMinLength === null) {
            checks['3.7'] = notAssessed(
              'Not assessed on this endpoint. Vajra holds no password policy values for this node: the Windows security profile returned no usable minimum length, complexity, history or lockout value, and the baseline minimum-password-length probe (command key 18) returned no usable output either.',
              'Not assessed — no password policy values held',
            );
          } else if (baselineMinLength < MIN_PASSWORD_LENGTH) {
            checks['3.7'] = {
              compliant: false,
              reason: `Password security is not enforced as required on this node: the minimum password length is measured as ${baselineMinLength}, below the required ${MIN_PASSWORD_LENGTH}. This comes from the baseline 'net accounts' probe; the Windows security profile returned no row for this node, so complexity, history and lockout were not measured.`,
              detail: `Minimum password length ${baselineMinLength}`,
            };
          } else {
            checks['3.7'] = notAssessed(
              `Not assessed on this endpoint. Only the minimum password length was measured for this node (${baselineMinLength}, which meets the required ${MIN_PASSWORD_LENGTH}); the Windows security profile returned no row, so password complexity, history and lockout threshold were not measured and the policy cannot be confirmed as enforced.`,
              `Not assessed — only minimum length (${baselineMinLength}) measured`,
            );
          }
        } else {
          const violations: string[] = [];
          if (minLength !== null && minLength < MIN_PASSWORD_LENGTH) {
            violations.push(`the minimum password length is ${minLength}, below the required ${MIN_PASSWORD_LENGTH}`);
          }
          if (complexity !== null && complexity !== 1) {
            violations.push('password complexity is switched off');
          }
          if (history !== null && history < 1) {
            violations.push('password history is 0, so a previous password can be reused immediately');
          }
          if (lockout !== null && lockout <= 0) {
            violations.push('the account lockout threshold is 0, so failed logon attempts never lock the account');
          }

          const measuredValues = [
            minLength !== null ? `minimum length ${minLength}` : null,
            complexity !== null ? `complexity ${complexity === 1 ? 'on' : 'off'}` : null,
            history !== null ? `history ${history}` : null,
            lockout !== null ? `lockout threshold ${lockout}` : null,
          ].filter((entry): entry is string => entry !== null).join(', ');

          const unmeasured = [
            minLength === null ? 'minimum length' : null,
            complexity === null ? 'complexity' : null,
            history === null ? 'history' : null,
          ].filter((entry): entry is string => entry !== null);

          if (violations.length > 0) {
            checks['3.7'] = {
              compliant: false,
              reason: `Password security is not enforced as required on this node: ${violations.join('; ')}. Measured from the Windows security profile — ${measuredValues}.`,
              detail: measuredValues,
            };
          } else if (unmeasured.length === 0) {
            checks['3.7'] = {
              compliant: true,
              reason: `Password security is enforced as required on this node: ${measuredValues}, measured from the Windows security profile.`,
              detail: measuredValues,
            };
          } else {
            checks['3.7'] = notAssessed(
              `Not assessed on this endpoint. The Windows security profile for this node returned no value for password ${unmeasured.join(' or ')}, so the policy cannot be confirmed as enforced. What was measured — ${measuredValues} — is within the guidelines.`,
              `Not assessed — password ${unmeasured.join('/')} not returned`,
            );
          }
        }
      }

      // Point 3.3: OS update set to auto-update from a trusted source
      {
        // One-sided by design. windows_security_center.autoupdate is a measured
        // health verdict on Automatic Updates, so 'Poor'/'Error' is a real
        // negative. 'Good' is NOT upgraded to a pass: the control also requires
        // the update SOURCE to be a trusted one, and that half is not measurable
        // here. Declaring server_selection = 'WindowsUpdate' trusted would be a
        // policy judgement, not a measurement.
        const autoUpdate = String(securityCentre?.autoupdate ?? '').trim();
        const autoUpdateState = autoUpdate.toLowerCase();

        if (securityCentre === null || autoUpdate === '') {
          checks['3.3'] = notAssessed(
            'Not assessed on this endpoint. Vajra holds no Windows Security Center record carrying an Automatic Updates state for this node, so neither the auto-update setting nor the update source was measured.',
            'Not assessed — no Automatic Updates state held',
          );
        } else if (autoUpdateState === 'poor' || autoUpdateState === 'error') {
          checks['3.3'] = {
            compliant: false,
            reason: `OS update is not set to auto-update on this node: Windows Security Center reports Automatic Updates as "${autoUpdate}".`,
            detail: `Automatic Updates reported as ${autoUpdate}`,
          };
        } else {
          checks['3.3'] = notAssessed(
            `Not assessed on this endpoint. Windows Security Center reports Automatic Updates as "${autoUpdate}" on this node, but whether the update source is a TRUSTED one was not assessed: Vajra stores no list of approved update sources to compare against, and the Windows Update policy values (WUServer and AUOptions under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate) are not collected — the registry table holds no rows for this node. The update history records the service each past update came from, but that is observed history, not the configured source.`,
            'Not assessed — update source not collected, no approved-source list',
          );
        }
      }

          // Fallback defaults
          if (checks['1.4'] === undefined) {
            // Capability statement only: the Vajra Agent can collect hardware and
            // software inventory, but this run did not read a usable inventory
            // back for this node, so the control was not measured.
            checks['1.4'] = notAssessed('Not assessed on this endpoint — capability statement only. The Vajra Agent can collect installed software inventory (programs, deb/rpm packages) and hardware details from a node, but no usable hardware and software inventory was read back for this node during this run.', 'Not measured — inventory collection available');
          }
          // Points 3.4 and 5.10 are deliberately not auto-answered, and this is NOT
          // a finding that the node has no antivirus/EDR. Vajra IS the EDR on these
          // endpoints, and its agent's presence and check-in are legitimate evidence
          // that AN EDR is installed and running here. But 3.4 asks for the
          // Government-offered enterprise AV/EDR client, and 5.10 for an AV/EDR
          // client recommended by CERT-In and NIC-CERT — named-product controls.
          // Whether Vajra, or anything else installed on this node, appears on those
          // Government / CERT-In / NIC-CERT lists is a tenant fact the platform does
          // not hold: no approved-product list is stored and nothing is compared
          // against one. Neither a pass nor a failure can be measured, so both fall
          // through to the manual Yes/No checklist.
          // Point 4.2 (180-day log retention) is deliberately not auto-answered.
          // The control concerns the logs of the entity's own ICT systems, which
          // the entity is obliged to retain; Vajra does not measure that, and its
          // retention of the telemetry it collects itself answers a different
          // question. Nothing on the endpoint or the server is consulted to
          // establish it, so 4.2 falls through to the manual Yes/No checklist
          // instead of being asserted without evidence.
          // Point 5.8: the presence of the Vajra Agent is not evidence that
          // unwanted OS components, services, ports or applications have been
          // uninstalled or disabled on this node — none of that is read back
          // here — so the control is recorded as not measured.
          checks['5.8'] = notAssessed(
            'Not assessed on this endpoint. This control has four subjects and Vajra holds usable evidence for none of them. OS components: no Windows optional-features or DISM inventory is collected. Services: no Windows service inventory is collected — the platform has no services table and startup_items is empty. Applications: the installed-software inventory is collected, but no approved-software baseline is stored to judge which of them are unwanted. Ports: listening ports are collected as a differential add/remove log and can be reconstructed, but no approved-ports baseline is stored, so no listening port can be classified as unwanted or unused. Answering this control needs an organisational baseline of permitted OS components, services, ports and applications, which Vajra does not hold.',
            'Not assessed — no approved component/service/port/software baseline',
          );

          // Any pending point still without a result was not evaluated during
          // this run. Record it explicitly as not-assessed so it is excluded
          // from the score instead of being read as a pass or a failure.
          Object.keys(CERTIN_PENDING_POINTS).forEach((marker) => {
            if (checks[marker] === undefined) {
              checks[marker] = notAssessed('Vajra did not collect any usable evidence for this control on this node during this run, so it has not been assessed.', 'Not assessed — no evidence collected');
            }
          });

          const trueChecks = Object.entries(checks)
            .filter(([, result]) => result?.compliant && result.assessed !== false)
            .reduce<Record<string, { label: string; reason?: string }>>((acc, [marker, result]) => {
              if (!CERTIN_PENDING_POINTS[marker]) return acc;
              acc[marker] = {
                label: CERTIN_PENDING_POINTS[marker].label,
                reason: result?.reason,
              };
              return acc;
            }, {});

          debugLog('[CERT-In] true checks for node', {
            hostId,
            hostname: String(node.hostname ?? node.name ?? ''),
            trueChecks,
          });

          // STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS (Class A, confirmed by the 2026-09-03
          // live-sweep verification pass — every code path above for these markers resolves
          // unconditionally to notAssessed(), on every host, on every run) are stripped from
          // the returned object here, at the very end, rather than by touching any evaluator
          // block above: every notAssessed()/compliant assignment for these markers earlier
          // in this function is left exactly as written, so the evaluator logic itself is
          // unchanged. This is a pure boundary filter — it keeps every caller of
          // staticComplianceChecks (the checklist UI, the fleet-wide sweep, and the
          // snapshot persisted for history/reporting) from ever seeing a Class A marker
          // again, matching the checklist UI dropping those rows entirely instead of
          // rendering them as a permanent "Not Assessed". The manual Yes/No points are a
          // completely different, untouched category — they are never part of `checks` at
          // all, so this filter cannot reach them.
          STRUCTURALLY_UNMEASURABLE_CERTIN_KEYS.forEach((marker) => {
            delete checks[marker];
          });

  return checks;
}

