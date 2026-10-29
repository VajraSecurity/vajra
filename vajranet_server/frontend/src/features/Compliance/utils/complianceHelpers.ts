/**
 * Pure helpers for the Compliance feature — control-label lookups, control
 * verdict evaluation, concurrency-limited mapping, and node-data normalization.
 *
 * The verdict evaluator is three-state: unreadable or empty agent output is
 * `not_assessed`, never a fabricated pass and never a fabricated fail.
 */

import type { NodeData, NodeStatus } from '../../Nodes/NodesView/types';
import type { ControlPassRate } from '../types';

export const COMPLIANCE_CONTROL_LABELS: Record<string, string> = {
  '1': 'Windows Defender Enabled',
  '2': 'Default Hostname Changed',
  '3': 'Timezone Set to UTC+5:30 (IST)',
  '4': 'Secure Boot Enabled',
  '5': 'Audit Special Logon',
  '6': 'Audit Credential Validation',
  '7': 'Audit Computer Account Management',
  '8': 'Audit Other Account Management Events',
  '9': 'Audit Security Group Management',
  '10': 'Audit User Account Management',
  '11': 'Audit Process Creation',
  '12': 'Audit PnP Activity',
  '13': 'Audit Account Lockout',
  '14': 'Audit Logon Events',
  '15': 'Audit IPsec Driver',
  '16': 'Audit Security System Extension',
  '17': 'Command Line in Process Creation Events',
  '18': 'Minimum Password Length Policy',
};

export const COMPLIANCE_KEYS = Object.keys(COMPLIANCE_CONTROL_LABELS);

export const isWeeklyAlertsDateKey = (k: string) => /^\d{1,2}\/\d{1,2}\/\d{4}$/.test(k);

/**
 * Three-state control verdict. `not_assessed` is NOT a failure: it means the
 * agent returned nothing we can read, so the control was never measured on that
 * host. Callers must drop it from both the numerator and the denominator —
 * scoring it as a fail fabricates a compliance failure that was never observed.
 */
export type ComplianceVerdict = 'pass' | 'fail' | 'not_assessed';

export function parseComplianceVerdict(key: string, output: string): ComplianceVerdict {
  const v = String(output ?? '').trim().toLowerCase();

  // Nothing came back at all — unmeasured, not failed.
  if (v.length === 0) return 'not_assessed';

  // Key 18: numeric output (password length). >0 is pass, 0 is a genuine fail,
  // anything non-numeric is unreadable and therefore not assessed.
  if (key === '18') {
    const n = parseInt(v, 10);
    if (isNaN(n)) return 'not_assessed';
    return n > 0 ? 'pass' : 'fail';
  }

  let rawBool: boolean;
  if (v === 'true' || v === 'pass' || v === 'passed' || v === '1') {
    rawBool = true;
  } else if (v === 'false' || v === 'fail' || v === 'failed' || v === '0') {
    rawBool = false;
  } else {
    // Unrecognised output -> the control was not measured. Never a silent fail.
    return 'not_assessed';
  }

  // Key 2 is inverted in the Windows agent compliance output.
  const pass = key === '2' ? !rawBool : rawBool;
  return pass ? 'pass' : 'fail';
}

export async function mapWithConcurrency<T, R>(items: T[], concurrency: number, mapper: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  const workers = new Array(Math.min(concurrency, items.length)).fill(null).map(async () => {
    while (true) {
      const i = nextIndex;
      nextIndex += 1;
      if (i >= items.length) return;
      results[i] = await mapper(items[i]);
    }
  });

  await Promise.all(workers);
  return results;
}

export const ALLOWED_STATUSES: ReadonlySet<NodeStatus> = new Set<NodeStatus>([
  'online',
  'offline',
  'warning',
  'reconnecting',
]);

export const normalizeStatus = (value: unknown): NodeStatus => {
  const s = String(value ?? 'offline').toLowerCase();
  return ALLOWED_STATUSES.has(s as NodeStatus) ? (s as NodeStatus) : 'offline';
};

export const toNodeDataForCompliance = (raw: unknown): NodeData => {
  if (!raw || typeof raw !== 'object') {
    return {
      id: 0,
      name: 'Unknown node',
      status: 'offline',
    };
  }
  const o = raw as Record<string, unknown>;

  return {
    id: Number(o.id) || 0,
    name: String(o.name ?? o.hostname ?? 'Selected node'),
    status: normalizeStatus(o.status),
    host_identifier: o.host_identifier != null ? String(o.host_identifier) : undefined,
    hostname: o.hostname != null ? String(o.hostname) : undefined,
    os_platform: o.os_platform != null ? String(o.os_platform) : undefined,
    os_name: o.os_name != null ? String(o.os_name) : undefined,
    os_arch: o.os_arch != null ? String(o.os_arch) : undefined,
    os_build: o.os_build != null ? String(o.os_build) : undefined,
    // Fields required by SebiHot static compliance evaluations
    hardware_vendor: o.hardware_vendor != null ? String(o.hardware_vendor) : undefined,
    hardware_model: o.hardware_model != null ? String(o.hardware_model) : undefined,
    hardware_cpu_type: o.hardware_cpu_type != null ? String(o.hardware_cpu_type) : undefined,
    hardware_physical_memory: o.hardware_physical_memory != null ? String(o.hardware_physical_memory) : undefined,
    hardware_cpu_logical_core: o.hardware_cpu_logical_core != null ? String(o.hardware_cpu_logical_core) : undefined,
    last_seen: typeof o.last_seen === 'number' ? o.last_seen : undefined,
    enrolled_on: o.enrolled_on != null ? String(o.enrolled_on) : undefined,
    security_products: Array.isArray(o.security_products) ? o.security_products as NodeData['security_products'] : undefined,
    agent_online: typeof o.agent_online === 'boolean' ? o.agent_online : undefined,
  };
};


/* -------------------------------------------------------------------------
 * AGG-11 — coverage of a stored register snapshot.
 *
 * `fully_compliant_nodes / windows_with_results` counts a host as fully
 * compliant when it passed 100% of ITS OWN assessed controls, and that
 * per-host denominator is never the framework's control set: on SEBI id=49
 * the ten responding hosts were measured on 160 (host, control) pairs out of
 * a possible 370, i.e. a mean of 16 of 37 controls each. The percentage is
 * therefore only readable next to its denominator, so the cards publish it.
 *
 * What the stored snapshot does NOT carry is the per-host assessed count, so
 * a per-host coverage floor cannot be enforced or a median computed here —
 * only the fleet mean. Enforcing the floor needs the register writers to
 * persist per-host assessed/total counts (see the residual gap in the report).
 * ---------------------------------------------------------------------- */

export type SnapshotCoverage = {
  /** Hosts that returned results — the denominator of the headline percentage. */
  respondedHosts: number | null;
  /** Controls the snapshot recorded a pass rate for. */
  recordedControls: number;
  /** Of those, the controls at least one host was actually measured on. */
  measuredControls: number;
  /** Σ eligibleHosts — the (host, control) pairs that were genuinely measured. */
  assessedPairs: number;
  /** assessedPairs / respondedHosts. null when the denominator is unknown. */
  meanControlsPerHost: number | null;
  /** Controls that every responding host failed — the drivers of a 0% headline. */
  universalFailureLabels: string[];
};

export function summariseSnapshotCoverage(
  snapshot:
    | { windows_with_results?: number | null; control_pass_rates?: ControlPassRate[] | null }
    | null
    | undefined,
): SnapshotCoverage | null {
  if (!snapshot) return null;
  const rates = Array.isArray(snapshot.control_pass_rates) ? snapshot.control_pass_rates : null;
  // No recorded rates at all — nothing measured that we can describe. Saying
  // "0 controls" would read as a measurement; say nothing instead.
  if (!rates || rates.length === 0) return null;

  const respondedHosts =
    snapshot.windows_with_results == null || !Number.isFinite(Number(snapshot.windows_with_results))
      ? null
      : Number(snapshot.windows_with_results);

  let assessedPairs = 0;
  let measuredControls = 0;
  const universalFailureLabels: string[] = [];

  for (const rate of rates) {
    const eligible = Number(rate?.eligibleHosts);
    if (!Number.isFinite(eligible) || eligible <= 0) continue;
    const passed = Number(rate?.passHosts);
    assessedPairs += eligible;
    measuredControls += 1;
    // "Every responding host failed" — only claimable when the control was
    // measured on all of them; a control measured on 3 of 10 hosts is not a
    // fleet-wide failure.
    if (Number.isFinite(passed) && passed === 0 && respondedHosts != null && eligible === respondedHosts) {
      universalFailureLabels.push(String(rate?.label ?? `Control ${rate?.key ?? '?'}`));
    }
  }

  return {
    respondedHosts,
    recordedControls: rates.length,
    measuredControls,
    assessedPairs,
    meanControlsPerHost:
      respondedHosts != null && respondedHosts > 0
        ? Math.round((assessedPairs / respondedHosts) * 10) / 10
        : null,
    universalFailureLabels,
  };
}

/* -------------------------------------------------------------------------
 * AGG-19 — fleet-level evaluation of the Windows baseline probes stored in
 * `compliance_results` (18 command keys, present on 24 of 27 Windows hosts and
 * read today by no regulatory register).
 *
 * The verdict rules are the ones already encoded in parseComplianceVerdict:
 * empty or unparseable output is not_assessed and leaves the host out of BOTH
 * the numerator and the denominator; key 2 is inverted; key 18 is numeric and
 * a measured 0 is a genuine FAIL, not missing data.
 * ---------------------------------------------------------------------- */

export type FleetControlVerdict = 'satisfied' | 'partial' | 'non_compliant' | 'not_assessed';

export type FleetControlEvidence = {
  key: string;
  label: string;
  verdict: FleetControlVerdict;
  passHosts: number;
  failHosts: number;
  /** passHosts + failHosts — hosts whose probe returned a readable value. */
  eligibleHosts: number;
  /** Hosts in scope whose probe returned nothing readable, or never ran. */
  notAssessedHosts: number;
  passRatePct: number | null;
  reason: string;
};

/** One probe entry inside `compliance_results.compliance_data`. */
export type ComplianceProbeRow = {
  command_key?: string | number | null;
  output?: string | null;
};

/**
 * A host in the population plus its latest `compliance_results.compliance_data`.
 * `complianceData` is null/undefined for a host that has no stored row — the
 * host stays in the population and is counted as not assessed, never as a fail.
 */
export type HostComplianceResult = {
  hostId: string;
  complianceData?: ComplianceProbeRow[] | null;
};

/**
 * Normalises the `compliance_data` payload, which arrives either as the jsonb
 * array itself or as a JSON string depending on the endpoint. Anything that is
 * not a readable array is null — the host was not measured, not failed.
 */
export function parseComplianceData(raw: unknown): ComplianceProbeRow[] | null {
  if (Array.isArray(raw)) return raw as ComplianceProbeRow[];
  if (typeof raw === 'string' && raw.trim().length > 0) {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? (parsed as ComplianceProbeRow[]) : null;
    } catch {
      return null;
    }
  }
  return null;
}

const controlLabel = (key: string) => COMPLIANCE_CONTROL_LABELS[key] ?? `Control ${key}`;

/**
 * Fleet verdict for one baseline control across a host population.
 *
 * `hostOutputs` carries one entry per host IN SCOPE — pass `output: undefined`
 * for a host that has no row for this key, so it is counted as not assessed
 * rather than silently dropped from the population.
 */
export function evaluateFleetComplianceControl(
  key: string,
  hostOutputs: ReadonlyArray<{ hostId: string; output: string | null | undefined }>,
): FleetControlEvidence {
  const label = controlLabel(key);
  let passHosts = 0;
  let failHosts = 0;
  let notAssessedHosts = 0;

  for (const entry of hostOutputs) {
    const verdict = entry.output == null ? 'not_assessed' : parseComplianceVerdict(key, entry.output);
    if (verdict === 'pass') passHosts += 1;
    else if (verdict === 'fail') failHosts += 1;
    else notAssessedHosts += 1;
  }

  const eligibleHosts = passHosts + failHosts;
  const inScope = eligibleHosts + notAssessedHosts;

  // No host produced a readable value — unmeasured, never a fleet failure.
  if (eligibleHosts === 0) {
    return {
      key,
      label,
      verdict: 'not_assessed',
      passHosts,
      failHosts,
      eligibleHosts,
      notAssessedHosts,
      passRatePct: null,
      reason: inScope === 0
        ? `Not assessed — no host was in scope for the Windows baseline probe "${label}" (compliance_results command key ${key}).`
        : `Not assessed — the Windows baseline probe "${label}" (compliance_results command key ${key}) returned no readable output on any of the ${inScope} host${inScope === 1 ? '' : 's'} in scope. Missing output is not a failure.`,
    };
  }

  const passRatePct = Math.round((passHosts / eligibleHosts) * 100);
  const coverage = `Measured on ${eligibleHosts} of ${inScope} host${inScope === 1 ? '' : 's'}` +
    (notAssessedHosts > 0
      ? `; ${notAssessedHosts} host${notAssessedHosts === 1 ? '' : 's'} returned nothing readable and ${notAssessedHosts === 1 ? 'is' : 'are'} excluded from both numerator and denominator`
      : '');

  const verdict: FleetControlVerdict =
    passHosts === eligibleHosts ? 'satisfied' : passHosts === 0 ? 'non_compliant' : 'partial';

  const detail =
    verdict === 'satisfied'
      ? `all ${passHosts} passed.`
      : verdict === 'non_compliant'
        ? `all ${failHosts} returned a measured negative — an observed failure, not absent data.`
        : `${passHosts} passed, ${failHosts} failed.`;

  return {
    key,
    label,
    verdict,
    passHosts,
    failHosts,
    eligibleHosts,
    notAssessedHosts,
    passRatePct,
    reason: `${coverage}: ${detail} Source: compliance_results command key ${key} ("${label}").`,
  };
}

/**
 * Evaluates every baseline control over a host population, from each host's
 * latest `compliance_results` row.
 *
 * Callers pass the WHOLE population they are reporting on — a host with no
 * stored row, or whose row omits a key, stays in the population and lands in
 * `notAssessedHosts`, so the denominator never silently shrinks to the hosts
 * that happen to have data.
 */
export function buildFleetComplianceEvidence(
  hosts: ReadonlyArray<HostComplianceResult>,
  keys: ReadonlyArray<string> = COMPLIANCE_KEYS,
): FleetControlEvidence[] {
  const byHost = hosts.map(({ hostId, complianceData }) => {
    const outputs = new Map<string, string>();
    for (const probe of Array.isArray(complianceData) ? complianceData : []) {
      const key = probe?.command_key == null ? '' : String(probe.command_key);
      if (key.length === 0) continue;
      // First entry wins — a duplicated key is a stale repeat within the row.
      if (!outputs.has(key)) outputs.set(key, String(probe.output ?? ''));
    }
    return { hostId, outputs };
  });

  return keys.map((key) =>
    evaluateFleetComplianceControl(
      key,
      byHost.map(({ hostId, outputs }) => ({ hostId, output: outputs.get(key) })),
    ),
  );
}
