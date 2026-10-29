import { DataSource } from 'typeorm';

import type { Observation, SeverityCounts } from '../../types/assetIdentity';
import { resolveAssets } from '../../utils/assetIdentity';
import { getLogger } from '../../utils/logger';
import { EXTERNAL_API_TIMEOUT_MS } from '../../consts/timeout';
import { executeGmpCommand } from '../../utils/openvasClient';
import { sanitizeAxiosError } from '../../utils/sanitizeAxiosError';

const logger = getLogger('services.assetIdentity.openvasFeeder');

function ensureArray<T>(val: T | T[] | undefined | null): T[] {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

/**
 * One host as parsed out of a raw, already-parsed GMP `get_report` response's
 * `report.report` (or `report`, GVM's shapes are inconsistent) object — the
 * same `inner` that controllers/openvas/openvasController.ts's `getReport`
 * computes as `report.report || report`.
 */
export interface OpenvasReportHost {
  ip: string;
  start?: string | null;
  end?: string | null;
  mac?: string | null;
  /**
   * BUG FIX (SPEC.md Addendum 3, verified live 2026-09-07): GVM's per-host
   * `<detail>` list has NO entry named `hostname`. The real field is `fqdn`.
   * This was silently producing zero hostname identities from every OpenVAS
   * report until this fix — both this feeder and openvasController.ts's
   * `getReport` hosts mapper now read `fqdn`.
   */
  fqdn?: string | null;
  os?: string | null;
  /**
   * MAC addresses recovered from the generic `netinfo` `<host><detail>`
   * (a stock Greenbone feed NVT, `ip -o addr`-style raw text output) — a
   * SEPARATE, broader-firing source than the custom Asset Inventory MAC VT
   * this feeder already parses in `extractAssetInventoryFacts`. Added
   * 2026-09-10 after live investigation found hosts where the custom VT
   * produced nothing (an execution-level issue inside those NASL scripts,
   * not a missing scan-config family) but `netinfo` still fired and carried
   * a real physical-interface MAC in its free text — confirmed live for two
   * hosts that were otherwise minting a fresh `ambiguous_new_asset`
   * duplicate on every rescan for lack of any MAC evidence at all. The
   * existing `normalizeMac()` in `utils/assetIdentity/normalize.ts` already
   * correctly drops the loopback/locally-administered/docker/veth noise
   * `netinfo` also lists, so feeding it every token found is correct, the
   * same "let the normalizer filter it" pattern the custom-VT MACs already
   * use below.
   */
  netinfoMacs: string[];
}

/**
 * How many hosts one report may contribute. A GVM report over a /16 can list
 * thousands; this feed runs unawaited behind a user's report view (and, as of
 * Addendum 3, also behind a cron tick), so it is bounded rather than allowed
 * to hold a pool connection for minutes.
 */
const OPENVAS_MAX_HOSTS_PER_REPORT = 2000;

/**
 * Case-insensitive substring match for the authentication-gate signal (SPEC.md
 * Addendum 3, point 2). GVM writes a per-host `<result>` (NOT a
 * `<host><detail>`!) whose `<nvt><name>` is exactly
 * "SSH Login Successful For Authenticated Checks" when SSH credentialed
 * checks actually succeeded against that host — verified live in this
 * environment (OID 1.3.6.1.4.1.25623.1.0.108540, family General). GVM's
 * naming convention for this NVT family is
 * "<Protocol> Login Successful For Authenticated Checks", so SMB/WMI/ESXi
 * variants are expected to follow the same pattern, but only SSH was verified
 * live here — hence a substring match rather than an exact string, so every
 * protocol variant is covered generically.
 */
const AUTH_SUCCESS_SUBSTRING = 'login successful for authenticated checks';

function detailValueFrom(details: any[], name: string): string | null {
  const found = details.find((d: any) => d && d.name === name);
  const value = found?.value;
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
}

/**
 * Extracts the per-host facts this feeder cares about from a raw report body.
 *
 * `machine_id` (Linux `/etc/machine-id`) is also present in `h.detail` at
 * this point but is deliberately NOT read here (SPEC.md Addendum 3, point 4):
 * it is a real, persistent per-install identifier with a trust level roughly
 * between hostname and mac, and would be a reasonable future IdentityKind,
 * but adding one changes IDENTITY_WEIGHTS, which was not requested — left as
 * a possible future addition, nothing more. (This is the GENERIC `<host>
 * <detail name="machine_id">`, distinct from the "OS Machine ID" value the
 * user's own Serial Numbers VT reports below in `extractAssetInventoryFacts`
 * — that one IS captured, but only into `attrs.extra.openvasMachineId`, never
 * as an identity, per the same reasoning.) No BIOS-UUID-equivalent detail was
 * found live either (the verified report was a Linux host); an authenticated
 * Windows scan may expose a WMI hardware GUID under some detail name, but
 * that is unverified and not implemented.
 */
export function extractHosts(innerReport: any): OpenvasReportHost[] {
  return ensureArray(innerReport?.host)
    .map((h: any): OpenvasReportHost => {
      const details = ensureArray(h?.detail);
      // `netinfo`'s value is `ip -o addr`-style raw text, e.g. one line per
      // interface with `link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff`.
      // MAC_TOKEN_RE (defined below, safe to reference here: this function is
      // only ever called at runtime, long after module load) pulls out every
      // MAC token regardless of surrounding text/ANSI color codes GVM embeds.
      const netinfo = detailValueFrom(details, 'netinfo');
      const netinfoMacs = netinfo ? [...new Set(netinfo.match(MAC_TOKEN_RE) ?? [])] : [];
      return {
        ip: h?.ip != null ? String(h.ip).trim() : '',
        start: h?.start ?? null,
        end: h?.end ?? null,
        mac: detailValueFrom(details, 'MAC'),
        fqdn: detailValueFrom(details, 'fqdn'),
        // best_os_txt is the human string ("Microsoft Windows 11"); the CPE is
        // the fallback, and normalizeOsFamily() collapses either to a family.
        os: detailValueFrom(details, 'best_os_txt') ?? detailValueFrom(details, 'best_os_cpe'),
        netinfoMacs,
      };
    })
    .filter((h) => h.ip !== '');
}

/**
 * Returns the set of host IPs that carry a "login successful for
 * authenticated checks" result anywhere in this report. A host NOT in this
 * set is UNAUTHENTICATED for asset-identity purposes and must be skipped
 * entirely by the caller — no observation written for it at all, which is
 * stronger than an ordinary normalizer drop.
 */
/**
 * Same 4-bucket scheme already used everywhere else OpenVAS results are shown
 * in this app (controllers/openvas/openvasController.ts's `getReport`, and
 * frontend/src/features/VulnerabilityScanner/OpenVASScanDetail.tsx's
 * `getSeverityLevel`): CVSS >= 7.0 high, >= 4.0 medium, > 0 low, else log.
 * Reused verbatim rather than reinvented so a host's historical graph uses
 * the exact same severity vocabulary as the report view it came from.
 */
function emptySeverityCounts(): SeverityCounts {
  return { high: 0, medium: 0, low: 0, log: 0 };
}

/**
 * Counts this one host's findings in the report by severity tier, so each
 * observation can carry a per-scan snapshot of that host's vulnerability
 * posture — the data a historical "did this host improve or degrade"
 * graph needs. Scoped to `ip` using the same `result.host` extraction as
 * `extractAuthenticatedIps` above, so it only counts findings that actually
 * belong to this host in a multi-host report.
 *
 * Single-host lookup: an O(results) scan of the whole report for the one IP
 * asked about. Fine for its one call site (getAssetObservations.ts, at most 5
 * reports per request, one host each). NOT for a per-host loop over a whole
 * report — see `computeSeverityCountsByHost` below for that.
 */
export function computeSeverityCountsForHost(innerReport: any, ip: string): SeverityCounts {
  const counts = emptySeverityCounts();
  for (const r of ensureArray(innerReport?.results?.result)) {
    const hostRaw = r?.host;
    const host = typeof hostRaw === 'string' ? hostRaw : (hostRaw?.['#text'] || hostRaw?.ip || '');
    if (String(host ?? '').trim() !== ip) continue;
    const sev = parseFloat(r?.severity);
    if (sev >= 7.0) counts.high++;
    else if (sev >= 4.0) counts.medium++;
    else if (sev > 0) counts.low++;
    else counts.log++;
  }
  return counts;
}

/**
 * Same tally as `computeSeverityCountsForHost`, but for EVERY host in the
 * report in one pass, keyed by ip. `processOpenvasReportForAssets` below
 * calls this once per report and looks up each of up to
 * OPENVAS_MAX_HOSTS_PER_REPORT (2000) hosts in the returned map, rather than
 * calling `computeSeverityCountsForHost` per host — which would rescan the
 * entire `results.result` array (itself easily thousands of entries) once per
 * host, on the hot ingestion path (the 10-minute cron poll, and every
 * on-demand report view). Same bucket-once-up-front shape as
 * `extractAuthenticatedIps`/`extractAssetInventoryFacts` above.
 */
export function computeSeverityCountsByHost(innerReport: any): Map<string, SeverityCounts> {
  const byHost = new Map<string, SeverityCounts>();
  for (const r of ensureArray(innerReport?.results?.result)) {
    const hostRaw = r?.host;
    const host = typeof hostRaw === 'string' ? hostRaw : (hostRaw?.['#text'] || hostRaw?.ip || '');
    const ip = host != null ? String(host).trim() : '';
    if (ip === '') continue;

    let counts = byHost.get(ip);
    if (!counts) {
      counts = emptySeverityCounts();
      byHost.set(ip, counts);
    }
    const sev = parseFloat(r?.severity);
    if (sev >= 7.0) counts.high++;
    else if (sev >= 4.0) counts.medium++;
    else if (sev > 0) counts.low++;
    else counts.log++;
  }
  return byHost;
}

export function extractAuthenticatedIps(innerReport: any): Set<string> {
  const authenticated = new Set<string>();
  for (const r of ensureArray(innerReport?.results?.result)) {
    const nvtName = typeof r?.nvt?.name === 'string' ? r.nvt.name : '';
    if (!nvtName.toLowerCase().includes(AUTH_SUCCESS_SUBSTRING)) continue;
    const hostRaw = r?.host;
    const host = typeof hostRaw === 'string' ? hostRaw : (hostRaw?.['#text'] || hostRaw?.ip || '');
    const ip = host != null ? String(host).trim() : '';
    if (ip !== '') authenticated.add(ip);
  }
  return authenticated;
}

// ---------------------------------------------------------------------------
// SPEC.md Addendum 4 — the user's own custom "Asset Inventory" NASL plugins
// (read-only reference: openvas_automation_Final/custom-vts/asset_inventory/,
// never edited). These run only on an authenticated Linux/Unix-via-SSH scan
// (all 21 VTs declare `script_mandatory_keys("login/SSH/success")`), surface
// as ordinary <result> entries (NOT <host><detail>) with
// `nvt.family === 'Asset Inventory'`, and give materially better hostname/MAC
// evidence than the generic <host><detail> baseline above. There is no
// Windows/SMB/WMI equivalent anywhere in the 21 files — Windows hosts get
// ONLY the generic baseline from `extractHosts`.
// ---------------------------------------------------------------------------

const ASSET_INVENTORY_FAMILY = 'Asset Inventory';
/** OID namespace every custom Asset Inventory VT lives under. */
const ASSET_INVENTORY_OID_PREFIX = '1.3.6.1.4.1.25623.1.0.9999';

/** "Asset Inventory: Network (Linux/Unix via SSH)" — asset_network_inventory.nasl. */
const OID_ASSET_INVENTORY_NETWORK = '1.3.6.1.4.1.25623.1.0.999905';
/** "Asset Inventory: Operating System (Linux/Unix via SSH)" — asset_os_inventory.nasl. */
const OID_ASSET_INVENTORY_OS = '1.3.6.1.4.1.25623.1.0.999901';
/** "Asset Inventory: Serial Numbers (Linux/Unix via SSH)" — asset_serialnumber_inventory.nasl. */
const OID_ASSET_INVENTORY_SERIAL = '1.3.6.1.4.1.25623.1.0.999917';
/** "Asset Inventory: MAC Addresses (Linux/Unix via SSH)" — asset_macaddress_inventory.nasl. */
const OID_ASSET_INVENTORY_MACS = '1.3.6.1.4.1.25623.1.0.999920';
// Deliberately NOT parsed: "Asset Inventory: Summary" — it aggregates
// unrelated inventory (installed software, running services, cron jobs, ...)
// into one free-text blob that is not worth the parsing risk for identity.

/** Every MAC-shaped token in a blob, regardless of surrounding text. */
const MAC_TOKEN_RE = /[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}/g;

/**
 * asset_network_inventory.nasl's report body starts:
 *   "Hostname\n--------\n<value>\n\n"
 * — the host's own `hostname` command output over the authenticated session,
 * a materially better source than reverse-DNS `fqdn` (frequently unset here).
 */
const NETWORK_HOSTNAME_RE = /Hostname\r?\n-+\r?\n(.+?)\r?\n/;

/**
 * asset_os_inventory.nasl's report body starts:
 *   "Operating System\n----------------\n<pretty name>\n\n"
 */
const OS_PRETTY_NAME_RE = /Operating System\r?\n-+\r?\n(.+?)\r?\n/;

/**
 * asset_serialnumber_inventory.nasl's "UUID     : <value>" line. Verified
 * live to read "sudo: a password is required" on most hosts (the underlying
 * script only succeeds when passwordless sudo happens to be configured) —
 * that string, and "unknown (requires root privileges to read)", are BOTH
 * already rejected by normalizeBiosUuid's existing UUID-shape check
 * (verified directly: neither matches the 32-hex/8-4-4-4-12 pattern, so both
 * come back `malformed_bios_uuid` with no code change needed) — no blocklist
 * addition was required.
 */
const SERIAL_UUID_RE = /UUID\s*:\s*(.+)/;

/**
 * The same VT's trailing section:
 *   "OS Machine ID (not hardware serial/UUID - unique per OS install)\n
 *    -------------------------------------------------------------------\n
 *    <value>\n"
 * This is the same KIND of value as `nodes.host_identifier` on Linux agents
 * (an install-scoped machine-id, not hardware) — per Addendum 3 point 4, it
 * is deliberately NOT a new IdentityKind and NOT `osqueryUuid` (that field
 * means "from the agent's osquery" specifically); captured only into
 * `attrs.extra.openvasMachineId` for audit, unscored.
 */
const SERIAL_MACHINE_ID_RE = /OS Machine ID[^\n]*\r?\n-+\r?\n(.+?)\r?\n/;

/** Values these custom VTs use to mean "nothing collected" — never worth capturing. */
function isBlankInventoryValue(v: string | null): boolean {
  if (v === null) return true;
  const lower = v.trim().toLowerCase();
  return lower === '' || lower === 'unknown';
}

export interface AssetInventoryFacts {
  /** From the Network VT — preferred over generic `fqdn` when present. */
  hostname: string | null;
  /** From the MAC Addresses VT — every MAC-shaped token found, unfiltered. */
  macs: string[];
  /** Raw (un-normalized) UUID candidate from the Serial Numbers VT. */
  biosUuidCandidate: string | null;
  /** "OS Machine ID" from the same VT — audit-only, never an identity. */
  machineId: string | null;
  /** Pretty distro string from the OS VT — nice-to-have corroboration. */
  osPretty: string | null;
}

function emptyAssetInventoryFacts(): AssetInventoryFacts {
  return { hostname: null, macs: [], biosUuidCandidate: null, machineId: null, osPretty: null };
}

/**
 * Scans `results.result[]` for the user's custom Asset Inventory VTs and
 * returns what each authenticated host's results say, keyed by that host's
 * IP — the same per-result `host` field `extractAuthenticatedIps` reads.
 *
 * A result is recognised as one of these VTs by family (`Asset Inventory`) OR
 * OID prefix, then by the four specific OIDs above; anything else in that
 * family (including "Asset Inventory: Summary") is ignored on purpose.
 */
export function extractAssetInventoryFacts(innerReport: any): Map<string, AssetInventoryFacts> {
  const byHost = new Map<string, AssetInventoryFacts>();

  for (const r of ensureArray(innerReport?.results?.result)) {
    const family = typeof r?.nvt?.family === 'string' ? r.nvt.family : '';
    const oid = typeof r?.nvt?.['@_oid'] === 'string' ? r.nvt['@_oid'] : '';
    if (family !== ASSET_INVENTORY_FAMILY && !oid.startsWith(ASSET_INVENTORY_OID_PREFIX)) continue;

    const hostRaw = r?.host;
    const host = typeof hostRaw === 'string' ? hostRaw : (hostRaw?.['#text'] || hostRaw?.ip || '');
    const ip = host != null ? String(host).trim() : '';
    if (ip === '') continue;

    const description = typeof r?.description === 'string' ? r.description : '';
    if (description === '') continue;

    let facts = byHost.get(ip);
    if (!facts) {
      facts = emptyAssetInventoryFacts();
      byHost.set(ip, facts);
    }

    switch (oid) {
      case OID_ASSET_INVENTORY_NETWORK: {
        const m = description.match(NETWORK_HOSTNAME_RE);
        const value = m ? m[1].trim() : null;
        if (!isBlankInventoryValue(value)) facts.hostname = value;
        break;
      }
      case OID_ASSET_INVENTORY_MACS: {
        const tokens = description.match(MAC_TOKEN_RE) ?? [];
        for (const tok of tokens) if (!facts.macs.includes(tok)) facts.macs.push(tok);
        break;
      }
      case OID_ASSET_INVENTORY_SERIAL: {
        const uuidMatch = description.match(SERIAL_UUID_RE);
        const uuidValue = uuidMatch ? uuidMatch[1].trim() : null;
        if (!isBlankInventoryValue(uuidValue)) facts.biosUuidCandidate = uuidValue;

        const midMatch = description.match(SERIAL_MACHINE_ID_RE);
        const midValue = midMatch ? midMatch[1].trim() : null;
        if (!isBlankInventoryValue(midValue)) facts.machineId = midValue;
        break;
      }
      case OID_ASSET_INVENTORY_OS: {
        const m = description.match(OS_PRETTY_NAME_RE);
        const value = m ? m[1].trim() : null;
        if (!isBlankInventoryValue(value)) facts.osPretty = value;
        break;
      }
      default:
        // Some other Asset Inventory VT (e.g. the Summary blob, or the 21st
        // "asset_custom_inventory.nasl" that produced nothing live) — ignored.
        break;
    }
  }

  return byHost;
}

export interface OpenvasAssetFeedResult {
  observations: number;
  created: number;
  attached: number;
  /** Hosts present in the report but dropped by the authentication gate. */
  skippedUnauthenticated: number;
}

/**
 * THE shared function (SPEC.md Addendum 3): both the view-triggered
 * `getReport` controller (via `feedOpenvasReportInBackground` below) and the
 * automatic poller (`pollOpenvasForAssets` below) call exactly this function
 * on the raw report body, so the authentication gate and the `fqdn` fix can
 * never drift between the manual and automatic paths.
 *
 * `resolveAsset`'s own normalizer drop rules (bad MAC, generic hostname, ...)
 * still apply on top of the authentication gate — this only decides whether a
 * host is considered AT ALL.
 *
 * Per Addendum 4, each authenticated host's `ObservedAttrs` are built from the
 * generic `<host><detail>` baseline (`extractHosts` — the ONLY path a Windows
 * host gets), then AUGMENTED with the user's custom Asset Inventory VTs when
 * present (`extractAssetInventoryFacts`, Linux/Unix-via-SSH only): the
 * Network VT's hostname is preferred over `fqdn`, every MAC the MAC-Addresses
 * VT found is ADDED to the generic single MAC (not replaced), and the Serial
 * Numbers VT's UUID is offered to the existing `normalizeBiosUuid` exactly
 * like any other bios_uuid candidate — expected to fail on most hosts (see
 * `SERIAL_UUID_RE`'s comment above), which is correct, not a bug.
 */
export async function processOpenvasReportForAssets(
  fleetDb: DataSource,
  reportId: string,
  innerReport: any,
): Promise<OpenvasAssetFeedResult> {
  const hosts = extractHosts(innerReport).slice(0, OPENVAS_MAX_HOSTS_PER_REPORT);
  const authenticatedIps = extractAuthenticatedIps(innerReport);
  const inventoryFactsByHost = extractAssetInventoryFacts(innerReport);
  const severityCountsByHost = computeSeverityCountsByHost(innerReport);

  const observations: Observation[] = [];
  let skippedUnauthenticated = 0;

  for (const host of hosts) {
    if (!authenticatedIps.has(host.ip)) {
      // Pre-filter, not a normalizer drop: no Observation is even built, so
      // no asset_observations row is written for this host at all.
      skippedUnauthenticated++;
      continue;
    }

    // GVM's scan_start is an RFC-1123-ish string; an unparseable one falls back
    // to now() rather than poisoning the timeline with an Invalid Date.
    const started = host.start != null ? new Date(String(host.start)) : null;
    const observedAt = started !== null && !Number.isNaN(started.getTime()) ? started : new Date();

    const inv = inventoryFactsByHost.get(host.ip);

    // ADD every custom-VT MAC and every netinfo-recovered MAC to the generic
    // one (all three can be present at once); the existing normalizer already
    // drops loopback/broadcast/locally-administered MACs, so feeding it the
    // full noisy docker/veth/bridge list from any source is correct.
    const macs = host.mac ? [host.mac] : [];
    for (const m of inv?.macs ?? []) if (!macs.includes(m)) macs.push(m);
    for (const m of host.netinfoMacs) if (!macs.includes(m)) macs.push(m);

    const extra: Record<string, unknown> = {
      reportId, scanStart: host.start ?? null, scanEnd: host.end ?? null,
      severityCounts: severityCountsByHost.get(host.ip) ?? emptySeverityCounts(),
    };
    if (inv?.machineId) extra.openvasMachineId = inv.machineId;

    observations.push({
      source: 'openvas',
      sourceRef: `ovas:${reportId}:${host.ip}`,
      observedAt,
      ownerGroupId: null,
      attrs: {
        // Prefer the Network VT's own `hostname` command output over
        // reverse-DNS `fqdn`, which is frequently unset in this environment;
        // fall back to `fqdn` when the custom VT did not fire (Windows, or an
        // unauthenticated/non-Linux path — though the latter is already
        // excluded by the authentication gate above).
        hostname: inv?.hostname ?? host.fqdn ?? null,
        macs,
        // Best-effort bios_uuid candidate from the Serial Numbers VT; almost
        // always comes back rejected by normalizeBiosUuid (see comment on
        // SERIAL_UUID_RE) — that is expected, not chased further.
        biosUuid: inv?.biosUuidCandidate ?? null,
        os: host.os ?? inv?.osPretty ?? null,
        ips: [host.ip],
        extra,
      },
    });
  }

  if (observations.length === 0) {
    logger.debug(
      { reportId, hosts: hosts.length, skippedUnauthenticated },
      'OpenVAS report carried no authenticated, usable host entries',
    );
    return { observations: 0, created: 0, attached: 0, skippedUnauthenticated };
  }

  const results = await resolveAssets(fleetDb, observations);
  const created = results.filter((r) => r.created).length;
  const attached = results.filter((r) => !r.created && r.assetUuid !== null).length;

  logger.info(
    { reportId, observations: observations.length, created, attached, skippedUnauthenticated },
    'OpenVAS asset feeder finished',
  );

  return { observations: observations.length, created, attached, skippedUnauthenticated };
}

/**
 * Fire-and-forget entry point for the `getReport` handler.
 *
 * Returns void SYNCHRONOUSLY and swallows every failure, including the fleet
 * DataSource being unavailable. Viewing an OpenVAS report must not fail, hang,
 * or slow down because asset resolution had a bad day — the report is the
 * product, the asset timeline is a side effect. Anything that goes wrong here
 * is recovered on the next view of the same report, or by the automatic
 * poller below.
 */
export function feedOpenvasReportInBackground(reportId: string, innerReport: any): void {
  if (!reportId || !innerReport) return;

  void (async () => {
    try {
      // Dynamic import: index.ts imports the controllers, so a static import of
      // dbSourceConnection here would close a require cycle at module load.
      const { dbSourceConnection } = await import('../../index');
      const ds = dbSourceConnection();
      if (!ds || ds.length < 2 || !ds[1].isInitialized) {
        logger.debug({ reportId }, 'Fleet datasource unavailable — skipping OpenVAS asset feed for this report view');
        return;
      }
      await processOpenvasReportForAssets(ds[1], reportId, innerReport);
    } catch (err) {
      logger.warn({ err, reportId }, 'OpenVAS asset feed failed for this report view; the report itself was unaffected');
    }
  })();
}

/** Report-fetch timeout for the poller, matching getReport's own `180_000`. */
const OPENVAS_POLL_REPORT_TIMEOUT_MS = 180_000;

export function extractInnerReport(getReportResult: any): any | null {
  const reportWrapper = getReportResult?.get_report_response || getReportResult?.get_reports_response;
  const reports = ensureArray(reportWrapper?.report);
  if (!reports.length) return null;
  const report = reports[0];
  return report.report || report;
}

export interface OpenvasPollSummary {
  groups: number;
  tasksConsidered: number;
  reportsProcessed: number;
  observations: number;
  created: number;
  attached: number;
  skippedUnauthenticated: number;
}

/**
 * Automatic polling (SPEC.md Addendum 3, point "Add automatic polling").
 *
 * OpenVAS is now the ONLY asset-identity source (agent/arp/nmap/nuclei are
 * disabled — see assetResolutionService.ts), and view-triggered-only
 * ingestion (`feedOpenvasReportInBackground` above) would leave the Assets
 * page nearly empty in practice: nobody opens every completed report. This
 * decision — poll automatically rather than stay view-triggered-only — was
 * made directly in Addendum 3, without a further confirmation round.
 *
 * Runs on the existing every-10-minutes asset-resolution cron tick
 * (ASSET_RESOLUTION_CRON_EXPRESSION); no new cron expression was added.
 *
 * No new schema or cursor: `asset_observations` already has
 * `UNIQUE(source, source_ref)` with `ON CONFLICT DO NOTHING`, and
 * `source_ref = 'ovas:<report-uuid>:<ip>'` is stable, so reprocessing an
 * already-seen report on every tick is a correctness-preserving no-op, not a
 * growing cost, at this deployment's realistic report volume. The caller
 * (`AssetResolutionService.runFeeds`) bumps `asset_feed_state('openvas')`'s
 * `last_run_at` unconditionally on every successful tick already — no extra
 * write is needed here. A real cursor keyed on `task.modification_time` is
 * the natural upgrade if report volume grows later; deliberately not built
 * now, per the "asap" scope of this change.
 */
export async function pollOpenvasForAssets(fleetDb: DataSource): Promise<OpenvasPollSummary> {
  const summary: OpenvasPollSummary = {
    groups: 0,
    tasksConsidered: 0,
    reportsProcessed: 0,
    observations: 0,
    created: 0,
    attached: 0,
    skippedUnauthenticated: 0,
  };

  let groupRows: { group_id: string | null }[];
  try {
    // NULL group_id included deliberately: it is a Super Admin's own config,
    // exactly as getOpenVASConfig() already treats it.
    groupRows = await fleetDb.query('SELECT DISTINCT group_id FROM openvas_configs WHERE is_active = true');
  } catch (err) {
    logger.error({ err }, 'OpenVAS asset poll: could not read active OpenVAS configs');
    return summary;
  }
  summary.groups = groupRows.length;

  for (const { group_id: groupId } of groupRows) {
    let tasks: any[];
    try {
      const tasksResult = await executeGmpCommand(groupId, 'get_tasks', undefined, EXTERNAL_API_TIMEOUT_MS, { filter: 'rows=-1' });
      tasks = ensureArray(tasksResult?.get_tasks_response?.task);
    } catch (err) {
      // One group's GVM connection being down/misconfigured must not stop the
      // poll for every other group — each group has its own OpenVAS config.
      logger.warn({ err: sanitizeAxiosError(err), groupId }, 'OpenVAS asset poll: get_tasks failed for this group — skipping');
      continue;
    }

    for (const t of tasks) {
      const status = t?.status;
      const reportId = t?.last_report?.report?.['@_id'];
      if (status !== 'Done' || !reportId) continue;
      summary.tasksConsidered++;

      try {
        const reportResult = await executeGmpCommand(
          groupId,
          'get_report',
          undefined,
          OPENVAS_POLL_REPORT_TIMEOUT_MS,
          { report_id: String(reportId), details: '1', ignore_pagination: '1' },
        );
        const inner = extractInnerReport(reportResult);
        if (!inner) {
          logger.warn({ groupId, reportId }, 'OpenVAS asset poll: get_report returned no report body — skipping');
          continue;
        }
        summary.reportsProcessed++;

        const result = await processOpenvasReportForAssets(fleetDb, String(reportId), inner);
        summary.observations += result.observations;
        summary.created += result.created;
        summary.attached += result.attached;
        summary.skippedUnauthenticated += result.skippedUnauthenticated;
      } catch (err) {
        // One bad report (network hiccup, malformed XML, a stale report id)
        // must not abort the rest of this group's tasks, let alone the tick.
        logger.warn({ err: sanitizeAxiosError(err), groupId, reportId }, 'OpenVAS asset poll: failed to fetch/process a report — skipping');
      }
    }
  }

  return summary;
}

/**
 * Entry point AssetResolutionService's tick calls for the `openvas` source.
 * `maxSourceId` is always null: OpenVAS has no monotonic source id to
 * checkpoint against (see pollOpenvasForAssets's doc comment on why no cursor
 * is needed yet).
 */
export async function runOpenvasFeeder(fleetDb: DataSource): Promise<{
  rows: number;
  observations: number;
  created: number;
  attached: number;
  maxSourceId: string | null;
}> {
  const summary = await pollOpenvasForAssets(fleetDb);
  logger.info(summary, 'OpenVAS asset poll finished');
  return {
    rows: summary.tasksConsidered,
    observations: summary.observations,
    created: summary.created,
    attached: summary.attached,
    maxSourceId: null,
  };
}
