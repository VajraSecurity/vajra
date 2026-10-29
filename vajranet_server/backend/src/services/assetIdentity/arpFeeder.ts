import { DataSource } from 'typeorm';

import type { Observation } from '../../types/assetIdentity';
import { resolveAssets } from '../../utils/assetIdentity';
import { getLogger } from '../../utils/logger';

const logger = getLogger('services.assetIdentity.arpFeeder');

/**
 * arp_cache carries no monotonic ingest guarantee the feeder can watermark
 * against (osquery replaces the snapshot wholesale), so it is read in full and
 * de-duplicated by (address, mac). This cap stops a fleet-wide ARP table from
 * turning one tick into tens of thousands of transactions.
 */
const ARP_MAX_ROWS_PER_TICK = 5000;

interface ArpRow {
  address: string | null;
  mac: string | null;
}

/**
 * The ARP feeder: every (ip, mac) pair any agent has resolved on its local
 * segment. This is the ideal ip<->mac bridge — an agent's own kernel ARP table
 * is authoritative for its subnet — which is why it is built even though it
 * currently produces nothing.
 *
 * arp_cache HAS 0 ROWS in this deployment and no other code references it: the
 * osquery scheduled-query pack that would populate it is not deployed. That is
 * a configuration gap, not a bug here, so an empty read is logged at DEBUG
 * (`{ rows: 0 }`) rather than as a warning — a warning every ten minutes
 * forever would train operators to ignore this logger. The moment the pack is
 * enabled this feeder starts producing without a code change.
 *
 * In the meantime the real ip<->mac bridge is nmap's raw output; see
 * nmapFeeder.ts.
 *
 * mintIfNoMatch stays at its default (true): an ARP entry for a device with no
 * agent is a genuine discovery of a machine on the network, and it arrives with
 * a MAC (weight 80), which is strong enough to be worth an asset.
 */
export async function runArpFeeder(fleetDb: DataSource): Promise<{
  rows: number;
  observations: number;
  created: number;
  attached: number;
  maxSourceId: string | null;
}> {
  const rows: ArpRow[] = await fleetDb.query(
    `
      SELECT DISTINCT address, mac
      FROM arp_cache
      WHERE address IS NOT NULL AND address <> ''
        AND mac IS NOT NULL AND mac <> ''
      ORDER BY address, mac
      LIMIT $1
    `,
    [ARP_MAX_ROWS_PER_TICK],
  );

  if (rows.length === 0) {
    logger.debug({ rows: 0 }, 'ARP asset feeder found no rows (arp_cache is not populated on this deployment)');
    return { rows: 0, observations: 0, created: 0, attached: 0, maxSourceId: null };
  }

  const observedAt = new Date();
  const observations: Observation[] = rows.map((row) => ({
    source: 'arp',
    // Per-HOST, and stable across ticks: the same (ip, mac) pair re-read next
    // tick is the same observation, so UNIQUE (source, source_ref) makes the
    // re-read a no-op instead of a new row every ten minutes.
    sourceRef: `arp:${row.address}:${String(row.mac).toLowerCase()}`,
    observedAt,
    ownerGroupId: null,
    attrs: {
      macs: [String(row.mac)],
      ips: [String(row.address)],
    },
  }));

  const results = await resolveAssets(fleetDb, observations);
  const created = results.filter((r) => r.created).length;
  const attached = results.filter((r) => !r.created && r.assetUuid !== null).length;

  logger.info(
    { rows: rows.length, observations: observations.length, created, attached },
    'ARP asset feeder finished',
  );

  return { rows: rows.length, observations: observations.length, created, attached, maxSourceId: null };
}
