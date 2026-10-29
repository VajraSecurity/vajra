/** Asset identity resolution literal constants (no env). */

import type { IdentityKind } from '../types/assetIdentity';

/**
 * Scoring weight per identity kind. A candidate asset's score is the sum of the
 * weights of the identity kinds it shares with the incoming observation, so the
 * numbers encode how much evidence one shared value actually is:
 *
 * - bios_uuid (100) is hardware-unique and alone clears ATTACH_THRESHOLD.
 * - mac (80) is nearly unique but spoofable/cloneable, so it needs corroboration.
 * - hostname (40) collides across reimaged and template-built machines.
 * - os (10) and ip (5) are weak on their own — an IP is a DHCP lease, not a machine.
 * - osquery_uuid is scored 0 deliberately: on the 36 Linux agents
 *   nodes.host_identifier is an osquery-generated UUID, not hardware, so it is
 *   recorded as evidence for the UI/audit trail but must never pull two hosts
 *   together. It is NOT a bios_uuid and must never be stored as one.
 *
 * Max attainable score is 235 (100 + 80 + 40 + 10 + 5).
 */
export const IDENTITY_WEIGHTS: Record<IdentityKind, number> = {
  bios_uuid: 100,
  mac: 80,
  hostname: 40,
  os: 10,
  ip: 5,
  osquery_uuid: 0,
};

/** Highest attainable match score (sum of IDENTITY_WEIGHTS) — 235. */
export const MAX_IDENTITY_SCORE = Object.values(IDENTITY_WEIGHTS).reduce((a, b) => a + b, 0);

/**
 * At or above this score an observation attaches to the winning candidate with
 * no human review. Set to the bios_uuid weight so exactly one hardware-unique
 * anchor — or any weaker combination that adds up to as much evidence
 * (mac + hostname = 120, mac + os + ip = 95 does not) — is enough.
 */
export const ATTACH_THRESHOLD = 100;

/**
 * Between REVIEW_THRESHOLD and ATTACH_THRESHOLD an observation still attaches,
 * but the asset is flagged needs_review. Set to the hostname weight: a shared
 * hostname is real evidence yet collides often enough that a human should
 * confirm it.
 */
export const REVIEW_THRESHOLD = 40;

/**
 * If the top two candidates are within this many points of each other the
 * matcher refuses to pick a winner: it mints a new asset and flags it for
 * review instead. A silent wrong merge is far more costly than a duplicate,
 * because merges are reversible (merged_into is a soft pointer) while
 * conflating two machines' scan history silently is not detectable after
 * the fact.
 */
export const AMBIGUITY_MARGIN = 20;

/**
 * MAC addresses that must never be treated as an identity.
 *
 * Load-bearing, not defensive: `00:00:00:00:00:00` appears in
 * interface_details for 36 distinct hosts in the live fleet. Without this list
 * every one of those hosts scores 80 against every other and the whole fleet
 * collapses into a single asset on the first run.
 *
 * The broadcast address is here for the same reason. Locally-administered MACs
 * (second nibble in 2/6/a/e — Docker's 02:42:*, VMware/Hyper-V vNICs,
 * randomized Wi-Fi) are rejected by a rule in the normalizer rather than by
 * enumeration, since there are 2^44 of them.
 */
export const MAC_BLOCKLIST: readonly string[] = [
  '00:00:00:00:00:00',
  'ff:ff:ff:ff:ff:ff',
] as const;

/**
 * BIOS/SMBIOS UUIDs that are motherboard defaults or placeholders rather than
 * per-machine values. These are emitted verbatim by whole production runs of
 * consumer boards and by several hypervisors, so a single one of them can
 * merge dozens of unrelated machines at weight 100 — the most damaging
 * false-merge this feature can produce.
 *
 * Compared uppercase, after normalization.
 */
export const BIOS_UUID_BLOCKLIST: readonly string[] = [
  '00000000-0000-0000-0000-000000000000',
  'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF',
  '03000200-0400-0500-0006-000700080009',
  '12345678-1234-5678-1234-567812345678',
  '00020003-0004-0005-0006-000700080009',
  '4C4C4544-0000-1020-8020-808C04F02033',
  '03000200-0400-0500-0006-000700080008',
  'DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF',
] as const;

/**
 * Hostnames carrying no identifying information. Every default Ubuntu install
 * answers `ubuntu`, every container answers `localhost`, and nmap's reverse
 * DNS frequently returns the literal target back — matching on any of these at
 * weight 40 would be matching on "is a computer".
 *
 * Compared lowercase, after the DNS suffix is stripped.
 */
export const HOSTNAME_BLOCKLIST: readonly string[] = [
  'localhost',
  'localhost.localdomain',
  'ubuntu',
  'debian',
  'raspberrypi',
  'unknown',
  'localdomain',
  'none',
  'null',
  'n/a',
  '-',
] as const;

/**
 * Every valid `asset_observations.source`. Ordered as the resolution service
 * would run its feeders if all were enabled: the agent feeder goes FIRST so
 * high-confidence assets (bios_uuid/mac from osquery) already exist before
 * weak, ip-only agentless observations try to attach to them. Reversing this
 * mints a duplicate asset per scanned IP and then attaches the agent to one
 * of the duplicates.
 *
 * SCOPE NARROWED (SPEC.md Addendum 3, user decision, 2026-09-07): only
 * `openvas` is currently WIRED — see the DISABLED_SOURCES comment in
 * assetResolutionService.ts. `agent`, `arp`, `nmap` and `nuclei` remain valid
 * enum members (existing historical observations still carry them, and a
 * future re-enable needs the type to keep accepting them) but their feeders
 * are not invoked by the cron tick.
 */
export const OBSERVATION_SOURCES = ['agent', 'arp', 'nmap', 'openvas', 'nuclei'] as const;

/**
 * Cron expression for AssetResolutionService's tick. Every 10 minutes: the
 * feeders are incremental (asset_feed_state.last_source_id watermarks), so a
 * tick is cheap, but nmap/nuclei scans finish on the order of minutes and a
 * newly discovered host showing up in the Assets view within ten minutes is
 * the responsiveness this feature needs — not seconds.
 */
export const ASSET_RESOLUTION_CRON_EXPRESSION = '*/10 * * * *';

/**
 * Max candidate assets recorded in asset_observations.match_reason.candidates.
 * The matcher may score dozens of candidates on a weak (ip-only) observation;
 * only the top few explain the decision, and match_reason is written once per
 * observation across every scan ever ingested.
 */
export const MATCH_REASON_MAX_CANDIDATES = 5;

/**
 * Hard byte cap on the serialized match_reason jsonb, applied after the
 * candidate cap as a backstop (a pathological observation can carry hundreds of
 * dropped identities). Over the cap the reason is replaced by a truncated
 * summary rather than the insert being failed — an unexplained observation is
 * better than a lost one. Precedent: MAX_CHART_DATA_BYTES in
 * controllers/network/nmapController.ts.
 */
export const MATCH_REASON_MAX_BYTES = 64 * 1024;

/**
 * Hard byte cap on the serialized asset_observations.attrs jsonb. Unlike
 * match_reason, attrs is raw, un-normalized feeder input kept so a
 * normalization bug can be replayed without re-scanning — several of its
 * fields (hostname, biosUuid candidates, os) come straight out of regex
 * captures against scan output (see openvasFeeder.ts's SERIAL_UUID_RE /
 * NETWORK_HOSTNAME_RE / OS_PRETTY_NAME_RE) with no length bound of their own.
 * A misbehaving or compromised scanned host can therefore feed an arbitrarily
 * large string into this column on every scan. Smaller than
 * MATCH_REASON_MAX_BYTES because legitimate attrs are a handful of short
 * strings and short arrays — nothing here is expected to approach this size.
 */
export const ATTRS_MAX_BYTES = 16 * 1024;
