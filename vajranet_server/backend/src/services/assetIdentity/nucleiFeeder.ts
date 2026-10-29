import { DataSource } from 'typeorm';

import type { Observation } from '../../types/assetIdentity';
import { normalizeIp, resolveAssets } from '../../utils/assetIdentity';
import { getLogger } from '../../utils/logger';

const logger = getLogger('services.assetIdentity.nucleiFeeder');

/** Same batching rationale as the nmap feeder; there are 439 stored runs. */
const NUCLEI_MAX_SCANS_PER_TICK = 250;

interface NucleiRow {
  id: string;
  target: string | null;
  created_at: Date;
}

/**
 * Split a nuclei target into the one identity it can actually carry. Targets
 * are stored as bare hosts (`10.0.5.240`) but a URL form (`https://host:8443/`)
 * is equally valid input to nuclei, so the scheme, port and path are stripped
 * before deciding whether what is left is an IP or a name.
 */
function parseNucleiTarget(target: string): { ip: string | null; hostname: string | null } {
  let value = target.trim();
  if (value === '') return { ip: null, hostname: null };

  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');   // scheme
  value = value.split('/')[0];                              // path
  value = value.split('?')[0];

  // Bracketed IPv6 literal, with or without a port.
  const v6 = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (v6) value = v6[1];
  else if (/^[^:]+:\d+$/.test(value)) value = value.split(':')[0];  // host:port (never IPv6)

  if (value === '') return { ip: null, hostname: null };
  return 'value' in normalizeIp(value) ? { ip: value, hostname: null } : { ip: null, hostname: value };
}

/**
 * The nuclei feeder. A nuclei run knows only what it was pointed at — one
 * target string, no MAC, no BIOS UUID, no OS — so its observations carry at
 * most an `ip` (weight 5) or a `hostname` (weight 40).
 *
 * mintIfNoMatch is therefore FALSE: an unmatched nuclei target must never
 * create an asset. Doing so would mint a fresh, permanently unidentifiable
 * asset for every URL anyone has ever pointed a template at, and those assets
 * could never be merged into anything because they carry no evidence to match
 * on. The observation row is still written (with a null asset_uuid and
 * `skipped_no_mint` in match_reason), so "why is this nuclei target not in
 * Assets?" stays answerable.
 *
 * The upside is real when it does match: a nuclei finding against 10.0.5.240
 * lands on the timeline of whichever asset the agent and nmap feeders have
 * already established owns that address.
 */
export async function runNucleiFeeder(
  fleetDb: DataSource,
  sinceId: string | null,
): Promise<{
  rows: number;
  observations: number;
  created: number;
  attached: number;
  maxSourceId: string | null;
}> {
  const rows: NucleiRow[] = await fleetDb.query(
    `
      SELECT id, target, created_at
      FROM nuclei_scan_history
      WHERE target IS NOT NULL AND target <> ''
        AND ($1::bigint IS NULL OR id > $1::bigint)
      ORDER BY id ASC
      LIMIT $2
    `,
    [sinceId, NUCLEI_MAX_SCANS_PER_TICK],
  );

  if (rows.length === 0) {
    logger.debug({ rows: 0, sinceId }, 'Nuclei asset feeder found no new scans');
    return { rows: 0, observations: 0, created: 0, attached: 0, maxSourceId: sinceId };
  }

  const observations: Observation[] = [];
  for (const row of rows) {
    const { ip, hostname } = parseNucleiTarget(row.target ?? '');
    if (ip === null && hostname === null) continue;
    observations.push({
      source: 'nuclei',
      sourceRef: `nuclei:${row.id}:${ip ?? hostname}`,
      observedAt: row.created_at,
      ownerGroupId: null,
      mintIfNoMatch: false,
      attrs: {
        hostname,
        ips: ip !== null ? [ip] : [],
        extra: { target: row.target, scanId: String(row.id) },
      },
    });
  }

  const results = await resolveAssets(fleetDb, observations);
  const created = results.filter((r) => r.created).length;
  const attached = results.filter((r) => !r.created && r.assetUuid !== null).length;
  const skippedNoMint = results.filter((r) => r.decision === 'skipped_no_mint').length;
  const maxSourceId = String(rows[rows.length - 1].id);

  logger.info(
    { rows: rows.length, observations: observations.length, created, attached, skippedNoMint, maxSourceId },
    'Nuclei asset feeder finished',
  );

  return { rows: rows.length, observations: observations.length, created, attached, maxSourceId };
}
