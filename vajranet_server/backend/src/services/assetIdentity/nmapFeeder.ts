import { DataSource } from 'typeorm';

import type { Observation } from '../../types/assetIdentity';
import { resolveAssets } from '../../utils/assetIdentity';
import { getLogger } from '../../utils/logger';

const logger = getLogger('services.assetIdentity.nmapFeeder');

/**
 * How many scans one tick ingests. There are 1,559 COMPLETED scans stored, and
 * a first run would otherwise resolve every host in every one of them inside a
 * single cron tick (one transaction per observation). The watermark in
 * asset_feed_state means the backlog is simply drained a batch per tick instead,
 * and steady state is a handful of new scans per tick anyway.
 */
const NMAP_MAX_SCANS_PER_TICK = 250;

/** `Nmap scan report for 10.1.2.3` / `Nmap scan report for name (10.1.2.3)` */
const SCAN_REPORT_RE = /^Nmap scan report for (?:(\S+) \(([0-9a-fA-F.:]+)\)|([0-9a-fA-F.:]+))\s*$/;
/** `MAC Address: 0C:38:3E:60:94:A7 (Fanvil Technology)` */
const MAC_LINE_RE = /^MAC Address:\s*([0-9A-Fa-f:]{17})\b/;
/** `OS details: Linux 4.15 - 5.8` — the most specific OS line nmap emits. */
const OS_DETAILS_RE = /^OS details:\s*(.+?)\s*$/;
/** `Running: Linux 4.X|5.X` — the fallback when OS details is absent. */
const RUNNING_RE = /^Running(?: \(JUST GUESSING\))?:\s*(.+?)\s*$/;
/** `Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel` — weakest fallback. */
const SERVICE_INFO_OS_RE = /^Service Info:.*\bOSs?:\s*([^;]+)/;

/** One host block parsed out of an nmap run's raw stdout. */
export interface NmapHostBlock {
  ip: string;
  /** Reverse-DNS name nmap printed alongside the IP, when it resolved one. */
  hostname: string | null;
  mac: string | null;
  os: string | null;
}

/**
 * Parse an nmap run's raw text into per-host blocks.
 *
 * LINE BY LINE INTO BLOCKS, deliberately. A `MAC Address:` line belongs to the
 * PRECEDING `Nmap scan report for` header, and in a subnet sweep those headers
 * and MAC lines alternate for dozens of hosts:
 *
 *     Nmap scan report for 10.0.5.19
 *     Host is up (0.00022s latency).
 *     MAC Address: 74:5D:22:9D:2D:06 (Unknown)
 *     Nmap scan report for 10.0.5.22
 *     ...
 *
 * Two independent whole-blob regexes (one collecting IPs, one collecting MACs)
 * would zip those two lists together and hand every MAC to the wrong host as
 * soon as a single host in the middle of the sweep has no MAC line — which is
 * exactly what happens for any host that is not on the scanner's own segment.
 * A wrong MAC is a weight-80 false merge, the single most damaging thing this
 * feature can do, so the association is made structurally instead of by
 * position.
 *
 * Exported for direct testing against stored `network_scan_history.output`.
 */
export function parseNmapHostBlocks(output: string): NmapHostBlock[] {
  const blocks: NmapHostBlock[] = [];
  let current: NmapHostBlock | null = null;
  let currentDown = false;
  let osIsFromDetails = false;

  const flush = (): void => {
    if (current !== null && !currentDown) blocks.push(current);
    current = null;
    currentDown = false;
    osIsFromDetails = false;
  };

  for (const rawLine of (output ?? '').split('\n')) {
    const line = rawLine.replace(/\r$/, '');

    const header = SCAN_REPORT_RE.exec(line);
    if (header) {
      flush();
      const named = header[1] !== undefined;
      current = {
        ip: named ? header[2] : header[3],
        hostname: named ? header[1] : null,
        mac: null,
        os: null,
      };
      continue;
    }

    if (current === null) continue;

    // `Nmap scan report for 10.0.0.9 [host down]` puts the marker on the header
    // line, but -v runs can also print it on the following line. Either way the
    // block is evidence of nothing and is discarded rather than minting an
    // asset for an address that answered nobody.
    if (/\[host down\]/i.test(line)) {
      currentDown = true;
      continue;
    }

    const mac = MAC_LINE_RE.exec(line);
    if (mac) {
      current.mac = mac[1];
      continue;
    }

    const osDetails = OS_DETAILS_RE.exec(line);
    if (osDetails) {
      current.os = osDetails[1];
      osIsFromDetails = true;
      continue;
    }

    // Weaker OS lines never overwrite an `OS details:` value.
    if (!osIsFromDetails) {
      const running = RUNNING_RE.exec(line);
      if (running) {
        current.os = running[1];
        continue;
      }
      const serviceInfo = SERVICE_INFO_OS_RE.exec(line);
      if (serviceInfo && current.os === null) {
        current.os = serviceInfo[1].trim();
      }
    }
  }
  flush();

  return blocks;
}

interface ScanRow {
  id: string;
  output: string | null;
  created_at: Date;
}

/**
 * The nmap feeder — and the feeder that actually does the work of joining the
 * agentless world to the agent world. 1,016 of the 1,630 stored scans carry
 * `MAC Address:` lines, and a MAC is the only identity an unauthenticated sweep
 * can produce that is strong enough (weight 80) to attach a scanned IP to an
 * osquery-reported host.
 *
 * `network_scan_history.chart_data` is NOT a source: it holds only
 * `{hasData, portData, serviceData}` aggregates and contains no host data at
 * all. The raw `output` column is the only place the per-host facts exist.
 *
 * Incremental: `WHERE id > last_source_id`, watermarked in asset_feed_state.
 * Zeroing that row is the supported way to force a full re-ingest — UNIQUE
 * (source, source_ref) makes the replay a no-op rather than a duplicate.
 */
export async function runNmapFeeder(
  fleetDb: DataSource,
  sinceId: string | null,
): Promise<{
  rows: number;
  observations: number;
  created: number;
  attached: number;
  maxSourceId: string | null;
}> {
  // AssetFeedState.lastSourceId is typed `string | null` because node-postgres
  // returns bigint as a string. It is passed straight back to Postgres as a
  // string and cast there, so a value beyond Number.MAX_SAFE_INTEGER can never
  // be mangled by JS number arithmetic on the way.
  const rows: ScanRow[] = await fleetDb.query(
    `
      SELECT id, output, created_at
      FROM network_scan_history
      WHERE status = 'COMPLETED'
        AND output IS NOT NULL AND output <> ''
        AND ($1::bigint IS NULL OR id > $1::bigint)
      ORDER BY id ASC
      LIMIT $2
    `,
    [sinceId, NMAP_MAX_SCANS_PER_TICK],
  );

  if (rows.length === 0) {
    logger.debug({ rows: 0, sinceId }, 'Nmap asset feeder found no new scans');
    return { rows: 0, observations: 0, created: 0, attached: 0, maxSourceId: sinceId };
  }

  const observations: Observation[] = [];
  let macBearing = 0;
  for (const row of rows) {
    for (const host of parseNmapHostBlocks(row.output ?? '')) {
      if (host.mac !== null) macBearing += 1;
      observations.push({
        source: 'nmap',
        // Per-HOST, never per-scan: one scan of a /24 is dozens of separate
        // observations, each independently resolvable and independently
        // replay-safe.
        sourceRef: `nsh:${row.id}:${host.ip}`,
        observedAt: row.created_at,
        // Agentless: no group. The asset stays "unassigned / discovered" until
        // it merges with an agent-backed one.
        ownerGroupId: null,
        attrs: {
          macs: host.mac !== null ? [host.mac] : [],
          hostname: host.hostname,
          os: host.os,
          ips: [host.ip],
          extra: { scanId: String(row.id) },
        },
      });
    }
  }

  const results = await resolveAssets(fleetDb, observations);
  const created = results.filter((r) => r.created).length;
  const attached = results.filter((r) => !r.created && r.assetUuid !== null).length;
  const maxSourceId = String(rows[rows.length - 1].id);

  logger.info(
    { rows: rows.length, observations: observations.length, macBearing, created, attached, maxSourceId },
    'Nmap asset feeder finished',
  );

  return { rows: rows.length, observations: observations.length, created, attached, maxSourceId };
}
