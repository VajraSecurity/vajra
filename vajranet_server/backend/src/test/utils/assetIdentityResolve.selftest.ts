/**
 * Self-contained test for utils/assetIdentity/resolveAsset.ts — the scoring
 * ladder and every veto. No test framework and NO DATABASE required:
 *
 *   node_modules/.bin/ts-node src/test/utils/assetIdentityResolve.selftest.ts
 *
 * The matcher's db handle is always injected (resolveAsset.ts never calls
 * dbSourceConnection() itself), which is exactly what makes this possible: the
 * fake below implements the one method the matcher uses, `query(sql, params)`,
 * dispatching on the statement it recognizes and answering from an in-memory
 * identity table. Every branch of the ladder is therefore reachable without a
 * Postgres server, and the assertions are about DECISIONS, not about SQL.
 *
 * The cases that matter most, and why:
 *
 *  - bios_uuid conflict. A reused DHCP lease makes an IP, and often an OS,
 *    match a machine that is not this machine. Only the hardware anchor can
 *    say no, so a differing valid bios_uuid must beat any score.
 *  - ambiguity. Two candidates within AMBIGUITY_MARGIN are not distinguishable
 *    by the evidence in hand. Minting a duplicate is reversible
 *    (assets.merged_into is a soft pointer); a silent wrong merge is not.
 *  - the ip-only attach rule. network_scan_history already holds 1630 nmap
 *    scans. Without this rule, replaying them mints a fresh asset per IP per
 *    scan — thousands of duplicates. With it they attach, but
 *    identity_confidence is pinned to the ip weight so such an asset never
 *    reads as better identified than the DHCP lease it is.
 *  - the zero MAC. Reported by 36 distinct hosts in the live interface_details
 *    table; it must never reach the candidate query at all.
 *
 * Exits non-zero on the first failure so it can gate CI.
 */

import assert from 'assert';

import { AMBIGUITY_MARGIN, MATCH_REASON_MAX_CANDIDATES } from '../../consts/assets';
import type { CandidateScore, MatchReason, Observation, ObservedAttrs } from '../../types/assetIdentity';
import {
  capMatchReason,
  resolveAssetWithQuerier,
  type AssetIdentityQuerier,
} from '../../utils/assetIdentity/resolveAsset';

interface SeedIdentity { assetUuid: string; kind: string; value: string; }

/** An asset already in the table, with the identities it owns. */
interface SeedAsset {
  assetUuid: string;
  identities: Array<{ kind: string; value: string }>;
  mergedInto?: string;
}

/**
 * In-memory stand-in for the fleet DataSource. Answers only the statements
 * resolveAsset.ts actually issues; anything else throws, so a future change to
 * the matcher's SQL fails loudly here instead of silently passing.
 */
class FakeDb implements AssetIdentityQuerier {
  identities: SeedIdentity[] = [];
  mergedInto = new Map<string, string>();
  /** Every candidate-lookup key pair the matcher asked about. */
  candidateLookups: Array<{ kind: string; value: string }> = [];
  /** Params of each UPDATE assets. */
  assetUpdates: Array<{ assetUuid: string; confidence: number; needsReview: boolean }> = [];
  /** Params of each INSERT INTO assets. */
  assetInserts: Array<{ confidence: number; needsReview: boolean; ownerGroupId: string | null }> = [];
  /** Identities written back, as 'kind=value' strings. */
  identityWrites: string[] = [];
  observationInserts: Array<{ assetUuid: string | null; matchScore: number; reason: MatchReason }> = [];
  lockKeys: string[] = [];
  /** Pre-seeded (source, sourceRef) already recorded by a "prior" resolution,
   *  for testing the idempotency guard's early-return path. */
  existingObservation: {
    source: string; sourceRef: string; assetUuid: string | null; matchScore: number;
    reason: MatchReason; identityConfidence: number | null; needsReview: boolean | null;
  } | null = null;
  private nextAsset = 1;
  private nextObservation = 1000;

  constructor(assets: SeedAsset[] = []) {
    for (const a of assets) {
      for (const i of a.identities) {
        this.identities.push({ assetUuid: a.assetUuid, kind: i.kind, value: i.value });
      }
      if (a.mergedInto) this.mergedInto.set(a.assetUuid, a.mergedInto);
    }
  }

  async query(sql: string, params: unknown[] = []): Promise<any> {
    if (sql.includes('FROM asset_observations o LEFT JOIN assets a')) {
      const [source, sourceRef] = params as [string, string];
      const e = this.existingObservation;
      if (!e || e.source !== source || e.sourceRef !== sourceRef) return [];
      // Real node-postgres deserializes jsonb columns into plain objects
      // already, not JSON strings -- match_reason comes back the same way
      // here, matching resolveAsset.ts's `row.match_reason as MatchReason`.
      return [{
        asset_uuid: e.assetUuid, match_score: e.matchScore, match_reason: e.reason,
        identity_confidence: e.identityConfidence, needs_review: e.needsReview,
      }];
    }

    if (sql.includes('pg_advisory_xact_lock')) {
      this.lockKeys.push(String(params[0]));
      return [{ pg_advisory_xact_lock: '' }];
    }

    if (sql.includes('FROM asset_identities i')) {
      const wanted: Array<{ kind: string; value: string }> = [];
      for (let i = 0; i < params.length; i += 2) {
        wanted.push({ kind: String(params[i]), value: String(params[i + 1]) });
      }
      this.candidateLookups.push(...wanted);
      return this.identities
        .filter((row) => wanted.some((w) => w.kind === row.kind && w.value === row.value))
        .map((row) => ({
          asset_uuid: this.mergedInto.get(row.assetUuid) ?? row.assetUuid,
          kind: row.kind,
          value_norm: row.value,
        }));
    }

    if (sql.includes('FROM assets a')) {
      const uuids = (params[0] as string[]) ?? [];
      const out = this.identities
        .filter((row) => uuids.includes(row.assetUuid) && (row.kind === 'bios_uuid' || row.kind === 'os' || row.kind === 'mac'))
        .map((row) => ({ asset_uuid: row.assetUuid, kind: row.kind, value_norm: row.value }));
      // Mirror the LEFT JOIN: an asset with no bios_uuid/os/mac identity still
      // comes back, with null columns.
      for (const u of uuids) {
        if (!out.some((r) => r.asset_uuid === u)) {
          out.push({ asset_uuid: u, kind: null as any, value_norm: null as any });
        }
      }
      return out;
    }

    if (sql.startsWith('UPDATE assets SET')) {
      this.assetUpdates.push({
        assetUuid: String(params[0]),
        confidence: Number(params[2]),
        needsReview: Boolean(params[3]),
      });
      return [];
    }

    if (sql.startsWith('INSERT INTO assets (')) {
      const assetUuid = 'minted-' + this.nextAsset++;
      this.assetInserts.push({
        confidence: Number(params[1]),
        needsReview: Boolean(params[2]),
        ownerGroupId: (params[3] as string | null) ?? null,
      });
      return [{ asset_uuid: assetUuid }];
    }

    if (sql.startsWith('INSERT INTO asset_identities')) {
      const assetUuid = String(params[0]);
      const kinds = params[1] as string[];
      const values = params[2] as string[];
      for (let i = 0; i < kinds.length; i++) {
        // Mirror the NOT EXISTS guard: a bios_uuid/mac already owned by a
        // different asset is skipped rather than violating the partial unique
        // index and aborting the transaction.
        const strong = kinds[i] === 'bios_uuid' || kinds[i] === 'mac';
        const ownedElsewhere = this.identities.some(
          (r) => r.kind === kinds[i] && r.value === values[i] && r.assetUuid !== assetUuid,
        );
        if (strong && ownedElsewhere) continue;
        this.identityWrites.push(kinds[i] + '=' + values[i]);
        if (!this.identities.some((r) => r.assetUuid === assetUuid && r.kind === kinds[i] && r.value === values[i])) {
          this.identities.push({ assetUuid, kind: kinds[i], value: values[i] });
        }
      }
      return [];
    }

    if (sql.startsWith('INSERT INTO asset_observations')) {
      this.observationInserts.push({
        assetUuid: (params[0] as string | null) ?? null,
        matchScore: Number(params[5]),
        reason: JSON.parse(String(params[6])) as MatchReason,
      });
      return [{ id: String(this.nextObservation++) }];
    }

    throw new Error('FakeDb: unexpected SQL issued by the matcher: ' + sql.slice(0, 120));
  }
}

/** Real values from the live fleet, so the fixtures are not invented. */
const BIOS_A = '4C4C4544-0054-5A10-8052-B7C04F374A33';   // real system_info.uuid
const BIOS_B = 'DD0C5659-BD58-6655-30AC-581122900A0E';   // real system_info.uuid
const MAC_A = '0c:38:3e:60:94:a7';                       // real, from nmap MAC Address: line
const MAC_B = 'd8:bb:c1:2a:0f:31';
const MAC_C = '58:11:22:0e:3d:bf';                       // real, from a live OpenVAS-scanned host

function obs(attrs: ObservedAttrs, over: Partial<Observation> = {}): Observation {
  return {
    source: 'nmap',
    sourceRef: 'test:' + Math.random().toString(36).slice(2),
    observedAt: new Date('2026-09-07T10:00:00.000Z'),
    attrs,
    ...over,
  };
}

interface Case {
  name: string;
  assets: SeedAsset[];
  observation: Observation;
  expect: {
    decision: string;
    assetUuid?: string | null;
    score?: number;
    created?: boolean;
    needsReview?: boolean;
    identityConfidence?: number;
    vetoes?: string[];
  };
  /** Extra assertions against the fake's recorded traffic. */
  check?: (db: FakeDb, result: Awaited<ReturnType<typeof resolveAssetWithQuerier>>) => void;
}

const CASES: Case[] = [
  // ── The ladder ─────────────────────────────────────────────────────────
  {
    name: 'bios_uuid match alone clears ATTACH_THRESHOLD',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'bios_uuid', value: BIOS_A }] }],
    observation: obs({ biosUuid: BIOS_A }, { source: 'agent' }),
    expect: { decision: 'attached', assetUuid: 'A1', score: 100, created: false, needsReview: false, identityConfidence: 100 },
  },
  {
    name: 'mac + hostname (120) attaches without review',
    assets: [{
      assetUuid: 'A1',
      identities: [{ kind: 'mac', value: MAC_A }, { kind: 'hostname', value: 'desktop-example' }],
    }],
    observation: obs({ macs: [MAC_A], hostname: 'DESKTOP-EXAMPLE.example.org' }),
    expect: { decision: 'attached', assetUuid: 'A1', score: 120, identityConfidence: 80 },
  },
  {
    name: 'mac alone (80) lands in the review band',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'mac', value: MAC_A }] }],
    observation: obs({ macs: [MAC_A] }),
    expect: { decision: 'attached_needs_review', assetUuid: 'A1', score: 80, needsReview: true, identityConfidence: 80 },
  },
  {
    name: 'hostname alone (40) is exactly REVIEW_THRESHOLD and still attaches',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'hostname', value: 'desktop-example' }] }],
    observation: obs({ hostname: 'desktop-example' }),
    expect: { decision: 'attached_needs_review', assetUuid: 'A1', score: 40, needsReview: true, identityConfidence: 40 },
  },
  {
    name: 'os + ip (15) against the single asset holding that ip attaches, confidence pinned to 5',
    assets: [{
      assetUuid: 'A1',
      identities: [{ kind: 'os', value: 'linux' }, { kind: 'ip', value: '10.0.5.22' }, { kind: 'mac', value: MAC_B }],
    }],
    observation: obs({ os: 'Ubuntu 22.04.3 LTS', ips: ['10.0.5.22'] }),
    // This is the anti-duplicate case, and getting it wrong is expensive: this
    // case previously expected `new_asset`, on the reading that a matched `os`
    // disqualifies the ip-only rule. Run against the real 1,559 stored nmap
    // scans that mints a fresh asset on EVERY re-scan of an IP whose host has
    // no MAC line -- 2,791 duplicates, ending with 188 assets all claiming
    // 10.0.5.132.
    //
    // The reasoning error was treating a matching OS family as evidence
    // AGAINST the match. Exactly one asset holds this IP and its OS family
    // agrees; that is strictly stronger than the bare-IP case the rule already
    // accepts. Confidence still pins to 5, because an OS family identifies
    // nothing.
    expect: {
      decision: 'attached_needs_review', assetUuid: 'A1', created: false,
      score: 15, needsReview: true, identityConfidence: 5,
    },
  },
  {
    name: 'os alone never surfaces a candidate — it is scored, not looked up',
    assets: [{
      assetUuid: 'A1',
      identities: [{ kind: 'os', value: 'linux' }, { kind: 'ip', value: '10.0.5.22' }],
    }],
    // Same OS family, DIFFERENT ip. `os` is not a lookup kind, so A1 is never
    // even considered. This is the property that stops one `os = 'linux'` row
    // -- held by 505 assets on the live fleet -- from dragging 500 score-10
    // candidates into every observation and tripping the ambiguity veto.
    observation: obs({ os: 'Ubuntu 22.04.3 LTS', ips: ['10.0.5.99'] }),
    expect: { decision: 'new_asset', created: true, score: 0, needsReview: false, identityConfidence: 10 },
  },
  {
    name: 'no candidates at all mints a new asset',
    assets: [],
    observation: obs({ macs: [MAC_A], hostname: 'brand-new-host' }),
    expect: { decision: 'new_asset', created: true, score: 0, needsReview: false, identityConfidence: 80 },
  },

  // ── The ip-only anti-duplicate rule ────────────────────────────────────
  {
    name: 'ip-only: exactly one candidate holds the IP, so attach rather than mint a duplicate',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'ip', value: '10.0.5.22' }] }],
    observation: obs({ ips: ['10.0.5.22'] }),
    expect: {
      decision: 'attached_needs_review', assetUuid: 'A1', score: 5,
      created: false, needsReview: true, identityConfidence: 5,
    },
  },
  {
    name: 'ip-only: identity_confidence is pinned to 5 even when the observation carries a hostname',
    // The hostname is real evidence but matched nothing, so all this
    // observation actually established is "something answered at this IP".
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'ip', value: '10.0.5.22' }] }],
    observation: obs({ hostname: 'some-unseen-host', ips: ['10.0.5.22'] }),
    expect: { decision: 'attached_needs_review', assetUuid: 'A1', score: 5, identityConfidence: 5 },
    check: (db) => {
      assert.strictEqual(db.assetUpdates.length, 1);
      assert.strictEqual(
        db.assetUpdates[0].confidence, 5,
        'the ip-only rule must never raise identity_confidence above the ip weight',
      );
    },
  },
  {
    name: 'ip-only: TWO candidates hold the IP, so the rule does not apply and ambiguity wins',
    assets: [
      { assetUuid: 'A1', identities: [{ kind: 'ip', value: '10.0.5.22' }] },
      { assetUuid: 'A2', identities: [{ kind: 'ip', value: '10.0.5.22' }] },
    ],
    observation: obs({ ips: ['10.0.5.22'] }),
    expect: { decision: 'ambiguous_new_asset', created: true, needsReview: true, vetoes: ['ambiguous_candidates'] },
  },

  // ── Veto: bios_uuid conflict ───────────────────────────────────────────
  {
    name: 'bios_uuid conflict beats a matching IP and OS (the reused DHCP lease case)',
    assets: [{
      assetUuid: 'A1',
      identities: [
        { kind: 'bios_uuid', value: BIOS_A },
        { kind: 'ip', value: '10.0.5.22' },
        { kind: 'os', value: 'windows' },
        { kind: 'hostname', value: 'shared-name' },
      ],
    }],
    observation: obs({ biosUuid: BIOS_B, hostname: 'shared-name', os: 'Windows 11 Pro', ips: ['10.0.5.22'] }),
    expect: {
      decision: 'new_asset', created: true, score: 0, needsReview: false,
      identityConfidence: 100, vetoes: ['bios_uuid_conflict'],
    },
    check: (_db, result) => {
      const candidate = result.reason.candidates.find((c: CandidateScore) => c.assetUuid === 'A1');
      assert.ok(candidate, 'the vetoed candidate is still recorded, for audit');
      assert.strictEqual(
        candidate.score, 55,
        'the candidate scored well (hostname 40 + os 10 + ip 5) and was vetoed anyway',
      );
      assert.deepStrictEqual(candidate.vetoedBy, ['bios_uuid_conflict']);
    },
  },
  {
    name: 'the same bios_uuid on both sides is not a conflict',
    assets: [{
      assetUuid: 'A1',
      identities: [{ kind: 'bios_uuid', value: BIOS_A }, { kind: 'ip', value: '10.0.5.99' }],
    }],
    observation: obs({ biosUuid: BIOS_A, ips: ['10.0.5.22'] }),
    expect: { decision: 'attached', assetUuid: 'A1', score: 100, vetoes: [] },
  },
  {
    name: 'a candidate with no bios_uuid of its own cannot conflict',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'mac', value: MAC_A }] }],
    observation: obs({ biosUuid: BIOS_B, macs: [MAC_A] }),
    expect: { decision: 'attached_needs_review', assetUuid: 'A1', score: 80, vetoes: [] },
  },

  // ── Veto: os family conflict ───────────────────────────────────────────
  {
    name: 'os family conflict with no hardware anchor vetoes the candidate',
    assets: [{
      assetUuid: 'A1',
      identities: [
        { kind: 'os', value: 'windows' },
        { kind: 'hostname', value: 'shared-name' },
        { kind: 'ip', value: '10.0.5.22' },
      ],
    }],
    observation: obs({ hostname: 'shared-name', os: 'Ubuntu 22.04', ips: ['10.0.5.22'] }),
    expect: { decision: 'new_asset', created: true, vetoes: ['os_family_conflict'], identityConfidence: 40 },
  },
  {
    name: 'os family conflict is NOT a veto when the MAC matches (a reimaged machine)',
    assets: [{
      assetUuid: 'A1',
      identities: [{ kind: 'mac', value: MAC_A }, { kind: 'os', value: 'windows' }],
    }],
    observation: obs({ macs: [MAC_A], os: 'Ubuntu 22.04' }),
    expect: { decision: 'attached_needs_review', assetUuid: 'A1', score: 80, vetoes: [] },
  },
  {
    name: 'os family conflict is NOT a veto when the bios_uuid matches',
    assets: [{
      assetUuid: 'A1',
      identities: [{ kind: 'bios_uuid', value: BIOS_A }, { kind: 'os', value: 'windows' }],
    }],
    observation: obs({ biosUuid: BIOS_A, os: 'Linux 5.15' }),
    expect: { decision: 'attached', assetUuid: 'A1', score: 100, vetoes: [] },
  },

  // ── Veto: mac conflict ─────────────────────────────────────────────────
  // The production bug this veto exists to fix: a second, physically
  // different Linux host on the network happened to share the exact same
  // hostname ("vajra") as an existing asset. hostname (40) + os (10) = 50
  // clears REVIEW_THRESHOLD, so without this veto the two machines silently
  // merged into one asset even though the MAC addresses -- real hardware
  // evidence -- shared nothing at all.
  {
    name: 'mac conflict vetoes a shared-hostname match between two different physical machines',
    assets: [{
      assetUuid: 'A1',
      identities: [
        { kind: 'mac', value: MAC_C },
        { kind: 'hostname', value: 'vajra' },
        { kind: 'os', value: 'linux' },
      ],
    }],
    observation: obs({ macs: [MAC_A], hostname: 'vajra', os: 'Ubuntu 24.04 LTS' }),
    expect: {
      decision: 'new_asset', created: true, score: 0, needsReview: false,
      identityConfidence: 80, vetoes: ['mac_conflict'],
    },
    check: (_db, result) => {
      const candidate = result.reason.candidates.find((c: CandidateScore) => c.assetUuid === 'A1');
      assert.ok(candidate, 'the vetoed candidate is still recorded, for audit');
      assert.strictEqual(candidate.score, 50, 'hostname 40 + os 10 -- scored well and vetoed anyway');
      assert.deepStrictEqual(candidate.vetoedBy, ['mac_conflict']);
    },
  },
  {
    name: 'a partial mac overlap (one shared NIC among several) is not a conflict',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'mac', value: MAC_A }, { kind: 'mac', value: MAC_B }] }],
    // Shares MAC_A, carries an unrelated MAC_C the candidate has never seen --
    // per-kind scoring already treats this as one shared mac, and the overlap
    // means it is not the disjoint-sets case the veto targets.
    observation: obs({ macs: [MAC_A, MAC_C] }),
    expect: { decision: 'attached_needs_review', assetUuid: 'A1', score: 80, vetoes: [] },
  },
  {
    name: 'mac conflict is NOT a veto when the bios_uuid matches (a new NIC on known hardware)',
    assets: [{
      assetUuid: 'A1',
      identities: [{ kind: 'bios_uuid', value: BIOS_A }, { kind: 'mac', value: MAC_A }],
    }],
    observation: obs({ biosUuid: BIOS_A, macs: [MAC_B] }),
    expect: { decision: 'attached', assetUuid: 'A1', score: 100, vetoes: [] },
  },
  {
    name: 'a candidate with no mac of its own cannot conflict',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'hostname', value: 'shared-name' }] }],
    observation: obs({ hostname: 'shared-name', macs: [MAC_A] }),
    expect: { decision: 'attached_needs_review', assetUuid: 'A1', score: 40, vetoes: [] },
  },

  // ── Veto: ambiguity ────────────────────────────────────────────────────
  {
    name: 'two candidates tied on hostname refuse to merge and mint instead',
    assets: [
      { assetUuid: 'A1', identities: [{ kind: 'hostname', value: 'shared-name' }] },
      { assetUuid: 'A2', identities: [{ kind: 'hostname', value: 'shared-name' }] },
    ],
    observation: obs({ hostname: 'shared-name' }),
    expect: {
      decision: 'ambiguous_new_asset', created: true, needsReview: true,
      identityConfidence: 40, vetoes: ['ambiguous_candidates'],
    },
    check: (_db, result) => {
      assert.strictEqual(result.reason.winnerScore, 40);
      assert.strictEqual(result.reason.runnerUpScore, 40);
      assert.strictEqual(result.assetUuid, 'minted-1', 'a fresh asset, not either candidate');
    },
  },
  {
    name: 'a 10-point gap is inside AMBIGUITY_MARGIN and refuses to pick',
    // A1 matches hostname (40) + os (10) = 50; A2 matches hostname (40) only.
    // 10 < AMBIGUITY_MARGIN, so the matcher will not choose between them.
    assets: [
      { assetUuid: 'A1', identities: [{ kind: 'hostname', value: 'shared-name' }, { kind: 'os', value: 'linux' }] },
      { assetUuid: 'A2', identities: [{ kind: 'hostname', value: 'shared-name' }] },
    ],
    observation: obs({ hostname: 'shared-name', os: 'ubuntu' }),
    expect: { decision: 'ambiguous_new_asset', created: true, vetoes: ['ambiguous_candidates'] },
  },
  {
    name: 'a clear winner (mac + hostname vs hostname) is not ambiguous',
    assets: [
      {
        assetUuid: 'A1',
        identities: [{ kind: 'mac', value: MAC_A }, { kind: 'hostname', value: 'shared-name' }],
      },
      { assetUuid: 'A2', identities: [{ kind: 'hostname', value: 'shared-name' }] },
    ],
    observation: obs({ macs: [MAC_A], hostname: 'shared-name' }),
    expect: { decision: 'attached', assetUuid: 'A1', score: 120, vetoes: [] },
  },
  {
    name: 'a vetoed candidate cannot create an ambiguity with the winner',
    assets: [
      { assetUuid: 'A1', identities: [{ kind: 'hostname', value: 'shared-name' }] },
      {
        assetUuid: 'A2',
        identities: [{ kind: 'hostname', value: 'shared-name' }, { kind: 'bios_uuid', value: BIOS_B }],
      },
    ],
    observation: obs({ hostname: 'shared-name', biosUuid: BIOS_A }),
    // A2 is out on bios_uuid_conflict, leaving A1 as the only eligible
    // candidate at 40 — attach for review rather than refuse. A1 does not own
    // a bios_uuid yet, so BIOS_A didn't match anything: it rode along on the
    // observation without being evidence FOR A1. identityConfidence must stay
    // at 40 (what the hostname match actually proved), not jump to 100 off an
    // unverified bios_uuid this match never confirmed belongs to A1.
    expect: {
      decision: 'attached_needs_review', assetUuid: 'A1', score: 40,
      needsReview: true, vetoes: ['bios_uuid_conflict'], identityConfidence: 40,
    },
  },

  // ── mintIfNoMatch ──────────────────────────────────────────────────────
  {
    name: 'nuclei-style low-information source never mints',
    assets: [],
    observation: obs({ ips: ['10.0.5.22'] }, { source: 'nuclei', mintIfNoMatch: false }),
    expect: {
      decision: 'skipped_no_mint', assetUuid: null, created: false,
      needsReview: false, identityConfidence: 0,
    },
    check: (db) => {
      assert.strictEqual(db.assetInserts.length, 0, 'skipped_no_mint must not create an asset');
      assert.strictEqual(db.observationInserts.length, 1, 'but the audit row is still written');
      assert.strictEqual(db.observationInserts[0].assetUuid, null);
    },
  },
  {
    name: 'ambiguity with mintIfNoMatch:false is skipped, not merged',
    assets: [
      { assetUuid: 'A1', identities: [{ kind: 'ip', value: '10.0.5.22' }] },
      { assetUuid: 'A2', identities: [{ kind: 'ip', value: '10.0.5.22' }] },
    ],
    observation: obs({ ips: ['10.0.5.22'] }, { source: 'nuclei', mintIfNoMatch: false }),
    expect: { decision: 'skipped_no_mint', assetUuid: null, created: false, vetoes: ['ambiguous_candidates'] },
  },
  {
    name: 'a low-information source that DOES match still attaches',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'ip', value: '10.0.5.22' }] }],
    observation: obs({ ips: ['10.0.5.22'] }, { source: 'nuclei', mintIfNoMatch: false }),
    expect: { decision: 'attached_needs_review', assetUuid: 'A1', score: 5, identityConfidence: 5 },
  },

  // ── Nothing survived normalization ─────────────────────────────────────
  {
    name: 'an observation where everything is dropped resolves to nothing but is still audited',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'mac', value: '00:00:00:00:00:00' }] }],
    observation: obs({
      biosUuid: '00000000-0000-0000-0000-000000000000',
      macs: ['00:00:00:00:00:00', '02:42:ac:11:00:02'],
      hostname: 'localhost',
      ips: ['127.0.0.1'],
    }),
    expect: {
      decision: 'skipped_no_identities', assetUuid: null, score: 0,
      created: false, needsReview: false, identityConfidence: 0,
    },
    check: (db, result) => {
      assert.strictEqual(db.candidateLookups.length, 0, 'the candidate query must not even run');
      assert.strictEqual(db.lockKeys.length, 0, 'no advisory lock is taken');
      assert.strictEqual(db.assetInserts.length, 0);
      assert.strictEqual(db.observationInserts.length, 1, 'the audit row explains why this host is not an asset');
      assert.strictEqual(result.reason.dropped.length, 5);
      assert.deepStrictEqual(
        result.reason.dropped.map((d) => d.reason).sort(),
        ['generic_hostname', 'locally_administered_mac', 'loopback_ip', 'zero_bios_uuid', 'zero_mac'],
      );
    },
  },
  {
    name: 'the zero MAC never reaches the candidate query, so 36 hosts cannot collapse into one asset',
    assets: [
      { assetUuid: 'A1', identities: [{ kind: 'mac', value: '00:00:00:00:00:00' }, { kind: 'hostname', value: 'host-a' }] },
      { assetUuid: 'A2', identities: [{ kind: 'mac', value: '00:00:00:00:00:00' }, { kind: 'hostname', value: 'host-b' }] },
    ],
    observation: obs({ macs: ['00:00:00:00:00:00'], hostname: 'host-c' }, { source: 'agent' }),
    expect: { decision: 'new_asset', created: true, score: 0, identityConfidence: 40 },
    check: (db) => {
      assert.ok(
        !db.candidateLookups.some((l) => l.kind === 'mac'),
        'no mac lookup may be issued for an observation whose only MAC is the zero MAC',
      );
      assert.ok(
        !db.identityWrites.some((w) => w.startsWith('mac=')),
        'the zero MAC must never be written back as an identity',
      );
    },
  },
  {
    name: 'a Docker 02:42:* MAC is dropped before it can merge two containers hosts',
    assets: [{ assetUuid: 'A1', identities: [{ kind: 'mac', value: '02:42:ac:11:00:02' }] }],
    observation: obs({ macs: ['02:42:AC:11:00:02'], hostname: 'container-host' }, { source: 'agent' }),
    expect: { decision: 'new_asset', created: true, score: 0, identityConfidence: 40 },
    check: (db, result) => {
      assert.ok(!db.candidateLookups.some((l) => l.kind === 'mac'));
      assert.ok(
        result.reason.dropped.some((d) => d.reason === 'locally_administered_mac'),
        'the drop is recorded so the decision stays auditable',
      );
    },
  },

  // ── Housekeeping the matcher owes its callers ──────────────────────────
  {
    name: 'a soft-merged candidate redirects to the surviving asset',
    assets: [
      { assetUuid: 'A1', identities: [{ kind: 'bios_uuid', value: BIOS_A }], mergedInto: 'A9' },
      { assetUuid: 'A9', identities: [] },
    ],
    observation: obs({ biosUuid: BIOS_A }, { source: 'agent' }),
    expect: { decision: 'attached', assetUuid: 'A9', score: 100 },
  },
  {
    name: 'osquery_uuid is never scored and never queried as a candidate',
    assets: [{
      assetUuid: 'A1',
      identities: [{ kind: 'osquery_uuid', value: 'C1D2E3F4-A5B6-4788-9900-AABBCCDDEEFF' }],
    }],
    observation: obs(
      { osqueryUuid: 'c1d2e3f4-a5b6-4788-9900-aabbccddeeff', hostname: 'linux-agent-01' },
      { source: 'agent' },
    ),
    expect: { decision: 'new_asset', created: true, score: 0, identityConfidence: 40 },
    check: (db) => {
      assert.ok(
        !db.candidateLookups.some((l) => l.kind === 'osquery_uuid'),
        'a weight-0 kind must never pull two hosts together',
      );
      assert.ok(
        db.identityWrites.includes('osquery_uuid=C1D2E3F4-A5B6-4788-9900-AABBCCDDEEFF'),
        'but it is still recorded as evidence for the audit trail',
      );
    },
  },
  {
    // Not just the strongest identity: every lookup-kind identity the
    // observation carries gets its own lock, in one fixed sort order
    // (bios_uuid < ip < mac alphabetically here) -- see lockKeysFor's
    // comment for why a single strongest-only lock left a duplicate-minting
    // race between two observations of the same machine via non-overlapping
    // strong identities.
    name: 'the advisory lock is taken on every lookup-kind identity, sorted',
    assets: [],
    observation: obs({ biosUuid: BIOS_A, macs: [MAC_A], ips: ['10.0.5.22'] }, { source: 'agent' }),
    expect: { decision: 'new_asset', created: true },
    check: (db) => {
      assert.deepStrictEqual(db.lockKeys, ['bios_uuid:' + BIOS_A, 'ip:10.0.5.22', 'mac:' + MAC_A]);
    },
  },
  {
    name: 'owner_group_id from an agent observation is carried onto a newly minted asset',
    assets: [],
    observation: obs({ macs: [MAC_A] }, { source: 'agent', ownerGroupId: 'group-7' }),
    expect: { decision: 'new_asset', created: true },
    check: (db) => {
      assert.strictEqual(db.assetInserts[0].ownerGroupId, 'group-7');
    },
  },
  {
    name: 'a strong identity already owned by another asset is not re-inserted (partial UNIQUE index)',
    assets: [
      { assetUuid: 'A1', identities: [{ kind: 'bios_uuid', value: BIOS_A }] },
      { assetUuid: 'A2', identities: [{ kind: 'mac', value: MAC_B }] },
    ],
    observation: obs({ biosUuid: BIOS_A, macs: [MAC_B] }, { source: 'agent' }),
    // A1 wins on the bios_uuid (100); A2 scores 80 on the MAC, a 20-point gap
    // that is exactly AMBIGUITY_MARGIN and therefore not ambiguous. The MAC
    // still belongs to A2, so writing it against A1 would violate
    // idx_asset_identities_strong_unique and roll the whole transaction back.
    expect: { decision: 'attached', assetUuid: 'A1', score: 100, vetoes: [] },
    check: (db) => {
      assert.ok(db.identityWrites.includes('bios_uuid=' + BIOS_A));
      assert.ok(
        !db.identityWrites.includes('mac=' + MAC_B),
        'a MAC owned by another asset must be skipped, not inserted',
      );
    },
  },
];

async function main() {
  for (const c of CASES) {
    const db = new FakeDb(c.assets);
    const result = await resolveAssetWithQuerier(db, c.observation);
    const label = 'case "' + c.name + '"';

    assert.strictEqual(result.decision, c.expect.decision, label + ': decision');
    if (c.expect.assetUuid !== undefined) {
      assert.strictEqual(result.assetUuid, c.expect.assetUuid, label + ': assetUuid');
    }
    if (c.expect.score !== undefined) assert.strictEqual(result.score, c.expect.score, label + ': score');
    if (c.expect.created !== undefined) {
      assert.strictEqual(result.created, c.expect.created, label + ': created');
    }
    if (c.expect.needsReview !== undefined) {
      assert.strictEqual(result.needsReview, c.expect.needsReview, label + ': needsReview');
    }
    if (c.expect.identityConfidence !== undefined) {
      assert.strictEqual(
        result.identityConfidence, c.expect.identityConfidence, label + ': identityConfidence',
      );
    }
    if (c.expect.vetoes !== undefined) {
      assert.deepStrictEqual([...result.reason.vetoes].sort(), [...c.expect.vetoes].sort(), label + ': vetoes');
    }

    // Invariants that hold for every case, checked everywhere rather than
    // spelled out per case.
    assert.strictEqual(
      result.assetUuid === null,
      c.expect.decision.startsWith('skipped_'),
      label + ': assetUuid is null exactly for the two skipped_* decisions',
    );
    assert.strictEqual(result.reason.decision, result.decision, label + ': reason mirrors the decision');
    assert.ok(
      db.observationInserts.length === 1,
      label + ': exactly one asset_observations row is written, whatever the decision',
    );
    assert.strictEqual(
      db.observationInserts[0].assetUuid, result.assetUuid,
      label + ': the observation row points at the asset the matcher chose',
    );
    assert.ok(result.observationId !== null, label + ': the observation id is returned');
    assert.ok(
      db.candidateLookups.filter((l) => l.kind === 'mac').every((l) => l.value !== '00:00:00:00:00:00'),
      label + ': the zero MAC is never used as a lookup key',
    );

    if (c.check) c.check(db, result);
  }

  // ── AMBIGUITY_MARGIN boundary ─────────────────────────────────────────
  // A gap of AMBIGUITY_MARGIN or more is a clear winner; only a smaller gap
  // refuses to pick.
  assert.strictEqual(AMBIGUITY_MARGIN, 20, 'these boundary cases assume the shipped margin');
  {
    // A1: hostname 40 + mac 80 = 120. A2: hostname 40 + os 10 + ... = 50.
    // Gap 70 -> not ambiguous.
    const db = new FakeDb([
      { assetUuid: 'A1', identities: [{ kind: 'hostname', value: 'h' }, { kind: 'mac', value: MAC_A }] },
      { assetUuid: 'A2', identities: [{ kind: 'hostname', value: 'h' }, { kind: 'os', value: 'linux' }] },
    ]);
    const r = await resolveAssetWithQuerier(
      db,
      obs({ hostname: 'h', macs: [MAC_A], os: 'ubuntu' }, { source: 'agent' }),
    );
    assert.strictEqual(r.decision, 'attached', 'a 80-point gap is a clear winner');
    assert.strictEqual(r.assetUuid, 'A1');
    assert.strictEqual(r.reason.runnerUpScore, 50);
  }
  {
    // A1: mac 80 + ip 5 = 85. A2: hostname 40 + os 10 + ip 5 = 55.
    // Gap 30 -> above the margin, so still a clear winner.
    const db = new FakeDb([
      { assetUuid: 'A1', identities: [{ kind: 'mac', value: MAC_A }, { kind: 'ip', value: '10.1.1.1' }] },
      {
        assetUuid: 'A2',
        identities: [
          { kind: 'hostname', value: 'h' }, { kind: 'os', value: 'linux' }, { kind: 'ip', value: '10.1.1.1' },
        ],
      },
    ]);
    const r = await resolveAssetWithQuerier(
      db,
      obs({ macs: [MAC_A], hostname: 'h', os: 'ubuntu', ips: ['10.1.1.1'] }, { source: 'agent' }),
    );
    assert.strictEqual(r.decision, 'attached_needs_review', '85 is inside the review band');
    assert.strictEqual(r.assetUuid, 'A1');
    assert.strictEqual(r.reason.winnerScore, 85);
    assert.strictEqual(r.reason.runnerUpScore, 55);
    assert.deepStrictEqual(r.reason.vetoes, [], 'a 30-point gap is not ambiguous');
  }

  // ── Per-kind scoring: four NICs are not 320 points ─────────────────────
  {
    const db = new FakeDb([{
      assetUuid: 'A1',
      identities: [
        { kind: 'mac', value: MAC_A },
        { kind: 'mac', value: MAC_B },
        { kind: 'mac', value: '54:bf:64:11:22:33' },
      ],
    }]);
    const r = await resolveAssetWithQuerier(
      db,
      obs({ macs: [MAC_A, MAC_B, '54:BF:64:11:22:33'] }, { source: 'agent' }),
    );
    assert.strictEqual(r.score, 80, 'scoring is per kind: three shared MACs are still 80, not 240');
    assert.strictEqual(r.decision, 'attached_needs_review');
  }

  // ── Idempotency guard: a replayed (source, sourceRef) mints nothing ────
  // The production bug this guard exists to fix: a running scan's report
  // polled repeatedly (each poll fire-and-forgetting its own feed call) fed
  // the SAME single host observation through the resolver 12 times. The
  // first resolution correctly (if ambiguously) minted an asset; each replay
  // still ran the full ladder, minted ANOTHER asset, and only then discovered
  // via insertObservation's ON CONFLICT DO NOTHING that the observation row
  // itself was a duplicate -- by which point the mint had already committed,
  // since a skipped INSERT is not an error. 11 of 18 assets in the live
  // fleet were exactly this debris from one such burst.
  {
    const priorReason: MatchReason = {
      decision: 'ambiguous_new_asset', winnerScore: 40, runnerUpScore: 40,
      candidates: [], vetoes: ['ambiguous_candidates'], matched: [], dropped: [],
    };
    const db = new FakeDb();
    db.existingObservation = {
      source: 'openvas', sourceRef: 'ovas:report1:10.1.1.1', assetUuid: 'minted-1',
      matchScore: 0, reason: priorReason, identityConfidence: 40, needsReview: true,
    };
    const r = await resolveAssetWithQuerier(
      db,
      obs({ hostname: 'shared-name' }, { source: 'openvas', sourceRef: 'ovas:report1:10.1.1.1' }),
    );
    assert.strictEqual(r.decision, 'ambiguous_new_asset', 'replay returns the FIRST resolution\'s decision');
    assert.strictEqual(r.assetUuid, 'minted-1', 'replay returns the FIRST resolution\'s asset, mints nothing new');
    assert.strictEqual(r.created, false);
    assert.strictEqual(r.needsReview, true);
    assert.strictEqual(r.identityConfidence, 40);
    assert.strictEqual(r.observationId, null, 'no new observation row was written');
    assert.deepStrictEqual(r.reason, priorReason);
    assert.strictEqual(db.assetInserts.length, 0, 'a replay must never mint a second asset');
    assert.strictEqual(db.assetUpdates.length, 0, 'a replay must not even touch the existing asset');
    assert.strictEqual(db.identityWrites.length, 0, 'a replay must never write identities again');
    assert.strictEqual(db.observationInserts.length, 0, 'a replay writes no observation row at all');
    assert.strictEqual(db.lockKeys.length, 0, 'the guard short-circuits before the advisory lock is even taken');
  }

  // ── match_reason capping ──────────────────────────────────────────────
  {
    const many: CandidateScore[] = [];
    for (let i = 0; i < 40; i++) {
      many.push({ assetUuid: 'cand-' + i, score: i, matched: [], vetoedBy: [] });
    }
    const capped = capMatchReason({
      decision: 'new_asset', winnerScore: 39, runnerUpScore: 38,
      candidates: many, vetoes: [], matched: [], dropped: [],
    });
    assert.strictEqual(capped.candidates.length, MATCH_REASON_MAX_CANDIDATES);
    assert.strictEqual(capped.candidates[0].score, 39, 'the top candidates are the ones kept');
    assert.strictEqual(capped.candidates[4].score, 35);
  }
  {
    // Pathological: enough dropped identities to blow MATCH_REASON_MAX_BYTES.
    // The reason is stripped down, never allowed to fail the insert.
    const dropped = [];
    for (let i = 0; i < 4000; i++) {
      dropped.push({ kind: 'mac' as const, raw: '02:42:' + i.toString(16).padStart(12, '0'), reason: 'locally_administered_mac' as const });
    }
    const capped = capMatchReason({
      decision: 'new_asset', winnerScore: 0, runnerUpScore: null,
      candidates: [], vetoes: [], matched: [], dropped,
    });
    assert.ok(
      Buffer.byteLength(JSON.stringify(capped), 'utf8') <= 64 * 1024,
      'an oversized match_reason is truncated rather than persisted whole',
    );
    assert.strictEqual(capped.decision, 'new_asset', 'the decision always survives truncation');
    assert.deepStrictEqual(capped.dropped, [], 'the unbounded part is what gets dropped');
  }

  console.log('assetIdentityResolve.selftest: all checks passed (' + CASES.length + ' table cases + boundary cases)');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
