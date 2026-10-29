import { DataSource } from 'typeorm';

import type { Observation } from '../../types/assetIdentity';
import { resolveAssets } from '../../utils/assetIdentity';
import { getLogger } from '../../utils/logger';

const logger = getLogger('services.assetIdentity.agentFeeder');

/**
 * Bounded id window on interface_details.
 *
 * interface_details is 22.4M rows / 6.4 GB with a PRIMARY KEY on `id` and
 * NOTHING ELSE, and osquery writes to it continuously. There is deliberately no
 * index on host_identifier: building one non-CONCURRENTLY takes a SHARE lock on
 * a table that is being written to all day and would blow DB_STATEMENT_TIMEOUT_MS
 * (45s) on the way. So the feeder scans a WINDOW of the PK instead — the most
 * recent 2,000,000 ids — which the planner serves as an index range scan.
 *
 * The trade-off is real and worth stating: a 2M window covers the 32 hosts that
 * have checked in most recently, not all 57 (5M covers 41, 10M covers 49). A
 * host that has been offline long enough to fall out of the window contributes
 * no `mac` identity on this tick — it still resolves on hostname (40) + ip (5)
 * + os (10), and picks its MACs back up the moment it checks in again. Widening
 * the window is a linear cost: 2M ≈ 1.4s, 10M ≈ 6s for the whole query.
 */
const INTERFACE_DETAILS_ID_WINDOW = 2_000_000;

/**
 * Same shape, on the much smaller interface_addresses (34.6k rows total, so the
 * window is effectively "everything"). Kept as a window anyway so the query's
 * cost cannot grow without bound as the table does.
 */
const INTERFACE_ADDRESSES_ID_WINDOW = 5_000_000;

/**
 * system_info is 280k rows. 500k covers every one of the 21 Windows hosts that
 * report a SMBIOS uuid.
 */
const SYSTEM_INFO_ID_WINDOW = 500_000;

interface AgentRow {
  host_identifier: string;
  hostname: string | null;
  os_platform: string | null;
  os_name: string | null;
  owner_group_id: string | null;
  last_seen: string | null;
  bios_uuid: string | null;
  macs: string[] | null;
  ips: string[] | null;
}

/**
 * The agent feeder. Runs FIRST on every tick, and that order is load-bearing:
 * osquery is the only source that can produce a bios_uuid or a full MAC list,
 * so the high-confidence assets have to exist before a weak, ip-only nmap or
 * nuclei observation tries to attach to one. Reverse the order and every
 * scanned IP mints its own asset first and the agent then attaches to one of
 * those duplicates.
 *
 * Sources joined onto the 57 `nodes` rows:
 *  - system_info.uuid   -> bios_uuid, WINDOWS ONLY. On the 36 Linux agents
 *    nodes.host_identifier is an osquery-generated UUID, not hardware; it is
 *    fed as `osquery_uuid` (weight 0, evidence only) and must never be stored
 *    as a bios_uuid.
 *  - interface_details.mac  -> macs (bounded window, see above)
 *  - interface_addresses.address -> ips
 *  - nodes.hostname     -> hostname
 *  - nodes.owner_group_id -> assets.owner_group_id
 *
 * nodes.address is NEVER used: it is empty for all 57 rows.
 *
 * SHARED ADDRESSES ARE DROPPED, and this is load-bearing in exactly the way the
 * MAC blocklist is. Virtual bridge gateways show up in interface_addresses on
 * every host that runs the software behind them: on this fleet 172.17.0.1
 * (Docker) sits on 15 hosts, 10.0.2.15 (VirtualBox NAT) on 15, 172.22.0.1 on
 * 13, 192.168.122.1 (libvirt virbr0) on 9, 192.168.137.1 (Windows ICS) on 2.
 * They are not the machine's address on the network, they are the machine's
 * address on a private bridge that every such machine names identically.
 *
 * Feeding them collapses the fleet. Measured: with them included, 18 distinct
 * Windows laptops attached to ONE asset and 11 Linux VMs to another, because
 * the matcher's ip-only attach rule sees exactly one asset holding 172.17.0.1
 * and correctly-by-its-own-rules attaches the next host to it, and the next,
 * and the next.
 *
 * The filter is data-driven rather than a hardcoded list, for the same reason
 * the normalizer rejects locally-administered MACs by rule instead of by
 * enumeration: any address that more than one agent claims at the same time is
 * either a bridge gateway or a DHCP collision, and in neither case is it
 * evidence about WHICH machine this is. Losing a weight-5 identity costs
 * almost nothing; a false merge at weight 5 costs the whole fleet.
 *
 * There is no watermark: `nodes` has 57 rows and no monotonic ingest id, so the
 * feeder re-reads all of them every tick. That is intentional and cheap — the
 * observation row is a no-op on ON CONFLICT (source, source_ref), while the
 * identity upsert still bumps last_seen and picks up a new NIC or a new IP.
 */
export async function runAgentFeeder(fleetDb: DataSource): Promise<{
  rows: number;
  observations: number;
  created: number;
  attached: number;
  maxSourceId: string | null;
}> {
  const rows: AgentRow[] = await fleetDb.query(
    `
      WITH macs AS (
        SELECT d.host_identifier, ARRAY_AGG(DISTINCT d.mac) AS macs
        FROM interface_details d
        WHERE d.id > (SELECT COALESCE(MAX(id), 0) - $1 FROM interface_details)
          AND d.mac IS NOT NULL AND d.mac <> ''
        GROUP BY d.host_identifier
      ), host_addresses AS (
        SELECT ia.host_identifier, ia.address
        FROM interface_addresses ia
        WHERE ia.id > (SELECT COALESCE(MAX(id), 0) - $2 FROM interface_addresses)
          AND ia.address IS NOT NULL AND ia.address <> ''
        GROUP BY ia.host_identifier, ia.address
      ), shared_addresses AS (
        -- See the note on SHARED ADDRESSES above runAgentFeeder.
        SELECT address FROM host_addresses GROUP BY address HAVING COUNT(*) > 1
      ), ips AS (
        SELECT ha.host_identifier, ARRAY_AGG(ha.address) AS ips
        FROM host_addresses ha
        WHERE NOT EXISTS (SELECT 1 FROM shared_addresses s WHERE s.address = ha.address)
        GROUP BY ha.host_identifier
      ), bios AS (
        SELECT DISTINCT ON (s.host_identifier) s.host_identifier, s.uuid
        FROM system_info s
        WHERE s.id > (SELECT COALESCE(MAX(id), 0) - $3 FROM system_info)
          AND s.uuid IS NOT NULL AND s.uuid <> ''
        ORDER BY s.host_identifier, s.id DESC
      )
      SELECT
        n.host_identifier,
        n.hostname,
        n.os_platform,
        n.os_name,
        n.owner_group_id,
        n.last_seen,
        -- Windows only: on Linux osquery synthesises system_info.uuid the same
        -- way it synthesises host_identifier, so it is not hardware evidence.
        CASE WHEN LOWER(COALESCE(n.os_platform, '')) = 'windows' THEN b.uuid END AS bios_uuid,
        m.macs,
        p.ips
      FROM nodes n
      LEFT JOIN macs m ON m.host_identifier = n.host_identifier
      LEFT JOIN ips  p ON p.host_identifier = n.host_identifier
      LEFT JOIN bios b ON b.host_identifier = n.host_identifier
    `,
    [INTERFACE_DETAILS_ID_WINDOW, INTERFACE_ADDRESSES_ID_WINDOW, SYSTEM_INFO_ID_WINDOW],
  );

  const observations: Observation[] = rows.map((row) => {
    // nodes.last_seen is a unix epoch in SECONDS (bigint), and comes back from
    // node-postgres as a string. A missing/absurd value falls back to now()
    // rather than 1970, which would sort the asset to the bottom of every
    // last_seen-ordered view forever.
    const epochSeconds = row.last_seen === null ? NaN : Number(row.last_seen);
    const observedAt =
      Number.isFinite(epochSeconds) && epochSeconds > 0 ? new Date(epochSeconds * 1000) : new Date();

    return {
      source: 'agent',
      sourceRef: `agent:${row.host_identifier}`,
      observedAt,
      ownerGroupId: row.owner_group_id,
      attrs: {
        biosUuid: row.bios_uuid,
        osqueryUuid: row.host_identifier,
        macs: row.macs ?? [],
        hostname: row.hostname,
        // os_name is the human string ("Ubuntu", "Microsoft Windows 11 Pro");
        // os_platform is the short token (pop|ubuntu|windows|rhel|kali). Either
        // collapses to the same family, so os_name is preferred for the audit
        // trail and os_platform is the fallback.
        os: row.os_name || row.os_platform,
        ips: row.ips ?? [],
        extra: { hostIdentifier: row.host_identifier, osPlatform: row.os_platform },
      },
    };
  });

  const results = await resolveAssets(fleetDb, observations);
  const created = results.filter((r) => r.created).length;
  const attached = results.filter((r) => !r.created && r.assetUuid !== null).length;

  logger.info(
    { rows: rows.length, observations: observations.length, created, attached },
    'Agent asset feeder finished',
  );

  // `nodes` has no monotonic ingest id to watermark against; the feeder is
  // deliberately a full re-read each tick.
  return { rows: rows.length, observations: observations.length, created, attached, maxSourceId: null };
}
