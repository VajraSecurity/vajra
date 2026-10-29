/**
 * The matcher: turns one observation into an attachment to an existing asset,
 * or a new asset, and records exactly why.
 *
 * Identity is resolved by WEIGHTED MATCHING over `asset_identities`, never by
 * hashing attributes into an id -- a scanner sees only a subset of a machine's
 * attributes (an unauthenticated scan cannot read SMBIOS) and IP/hostname
 * change over time, so any derived id would fragment the same machine into
 * several.
 *
 * The db handle is ALWAYS injected. This module never calls
 * dbSourceConnection() itself: that is what keeps it unit-testable
 * (src/test/utils/assetIdentityResolve.selftest.ts drives the whole scoring
 * ladder against a fake query function) and what lets a feeder hand it either
 * the fleet DataSource or an EntityManager it is already inside.
 *
 * Two properties this file exists to guarantee:
 *
 *  - A WRONG MERGE IS WORSE THAN A DUPLICATE. Merges are reversible
 *    (assets.merged_into is a soft pointer); two machines' scan histories
 *    silently conflated are not detectable after the fact. So the vetoes
 *    DOMINATE the score, and near-ties refuse to pick at all.
 *  - RE-SCANNING A SUBNET MUST NOT MINT DUPLICATES. There are already 1630
 *    nmap scans in network_scan_history; without the ip-only attach rule in
 *    the ladder below, replaying them would create a fresh asset per IP per
 *    scan. The rule attaches, but refuses to let identity_confidence rise
 *    above 5, so such an asset never looks better-identified than the DHCP
 *    lease it actually is.
 *
 * @see backend/src/utils/assetIdentity/normalize.ts (pure, no DB)
 * @see backend/src/consts/assets.ts for weights and thresholds
 */

// Type-only: importing typeorm as a VALUE here would make this module -- and
// therefore its selftest -- pull in typeorm's driver factory, which requires
// optional peer drivers that are not installed. The matcher only ever needs
// `.query()`, so the concrete classes are never referenced at runtime.
import type { DataSource, EntityManager } from 'typeorm';

import {
  AMBIGUITY_MARGIN,
  ATTACH_THRESHOLD,
  ATTRS_MAX_BYTES,
  MATCH_REASON_MAX_BYTES,
  MATCH_REASON_MAX_CANDIDATES,
  REVIEW_THRESHOLD,
} from '../../consts/assets';
import type {
  CandidateScore,
  MatchReason,
  NormalizedIdentity,
  NormalizedObservation,
  Observation,
  ObservedAttrs,
  ResolveDecision,
  ResolveResult,
  VetoReason,
} from '../../types/assetIdentity';
import { getLogger } from '../logger';
import { normalizeObservation } from './normalize';

const logger = getLogger('utils.assetIdentity.resolve');

/**
 * The only database capability the matcher needs. Both TypeORM's DataSource
 * and EntityManager satisfy it, and so does the fake the selftest injects --
 * which is the point: every branch of the ladder below is reachable without a
 * Postgres server.
 */
export interface AssetIdentityQuerier {
  query(sql: string, parameters?: unknown[]): Promise<any>;
}

/** Identity kinds that participate in scoring. */
const SCOREABLE_KINDS = new Set(['bios_uuid', 'mac', 'hostname', 'os', 'ip']);

/**
 * Identity kinds that may be used to LOOK CANDIDATES UP. `os` is scored but is
 * deliberately NOT a lookup key, because it is the one kind whose value space
 * is three items wide: on the live fleet a single `os = 'linux'` row is held by
 * 505 assets, so including it in the candidate query dragged 500 score-10
 * candidates into every observation that mentioned an OS. With AMBIGUITY_MARGIN
 * at 20, any observation whose true winner scored under 30 -- and ip 5 + os 10
 * = 15 is the ordinary case for an nmap host with no MAC line -- fell inside
 * the margin of that crowd, was declared ambiguous, and minted a duplicate.
 * Measured on a full backfill of the 1,559 stored scans: 2,791 such mints, and
 * 188 separate assets all claiming 10.118.5.132.
 *
 * An OS family was never identifying evidence; it is corroborating evidence.
 * It is still scored -- but only against candidates that a genuinely
 * identifying kind already put on the table, using the osFamilies the meta
 * lookup already fetches.
 */
const LOOKUP_KINDS = new Set(['bios_uuid', 'mac', 'hostname', 'ip']);

interface CandidateRow {
  asset_uuid: string;
  kind: string;
  value_norm: string;
}

interface CandidateMetaRow {
  asset_uuid: string;
  kind: string | null;
  value_norm: string | null;
}

interface WorkingCandidate {
  assetUuid: string;
  /** Matched identities, de-duplicated per kind (see scoring note below). */
  matchedByKind: Map<string, NormalizedIdentity>;
  /** Every bios_uuid this candidate already owns -- the conflict veto's input. */
  biosUuids: Set<string>;
  /** Every os family this candidate already owns. */
  osFamilies: Set<string>;
  /** Every mac this candidate already owns -- the mac_conflict veto's input. */
  macs: Set<string>;
  vetoedBy: VetoReason[];
}

/**
 * Pick the values the advisory lock is taken on: EVERY lookup-kind identity
 * (bios_uuid/mac/hostname/ip) this observation carries, not just the
 * strongest one.
 *
 * A single lock on only the strongest identity left a real race: two
 * observations of the same physical machine that happen to carry
 * non-overlapping strong identities -- one has only a bios_uuid, the other
 * (a different feeder, or a re-scan that hasn't picked up the bios_uuid yet)
 * has only a mac -- would take two DIFFERENT locks, both miss the candidate
 * query concurrently, and both mint a fresh asset for the same machine. `os`
 * is deliberately excluded, same as LOOKUP_KINDS itself: it is never a lookup
 * key (see LOOKUP_KINDS's comment), so an os-only observation never finds a
 * candidate regardless of locking -- there is nothing here to serialize
 * against.
 *
 * Returned pre-sorted into ONE fixed (kind, value) order, not by weight: any
 * two observations that lock an overlapping set of keys must acquire them in
 * the same order, or two transactions each holding one of the other's locks
 * and waiting on the rest deadlock instead of serializing.
 */
function lockKeysFor(norm: NormalizedObservation): string[] {
  const lookupable = norm.identities.filter((i) => LOOKUP_KINDS.has(i.kind));
  const keys = new Set<string>();
  for (const i of lookupable) keys.add(i.kind + ':' + i.value);
  return [...keys].sort();
}

/**
 * Cap match_reason before it is persisted. `candidates` is truncated to the
 * top MATCH_REASON_MAX_CANDIDATES, then the whole serialized document is
 * checked against MATCH_REASON_MAX_BYTES and progressively stripped if it is
 * still too large. It is never allowed to fail the insert: an observation with
 * a thin explanation is far better than a lost observation.
 * Precedent: MAX_CHART_DATA_BYTES in controllers/network/nmapController.ts.
 */
export function capMatchReason(reason: MatchReason): MatchReason {
  const byTopScore = [...reason.candidates].sort((a, b) => b.score - a.score);
  let out: MatchReason = { ...reason, candidates: byTopScore.slice(0, MATCH_REASON_MAX_CANDIDATES) };
  if (Buffer.byteLength(JSON.stringify(out), 'utf8') <= MATCH_REASON_MAX_BYTES) return out;

  // Still oversized: keep the decision and the scores (which is what an
  // operator reads first) and drop the per-candidate and dropped-identity
  // detail, which is what grows without bound.
  out = {
    ...out,
    candidates: out.candidates.map((c) => ({ ...c, matched: [] })),
    dropped: [],
  };
  if (Buffer.byteLength(JSON.stringify(out), 'utf8') <= MATCH_REASON_MAX_BYTES) return out;

  return {
    decision: reason.decision,
    winnerScore: reason.winnerScore,
    runnerUpScore: reason.runnerUpScore,
    candidates: [],
    vetoes: reason.vetoes,
    matched: [],
    dropped: [],
  };
}

/** Truncate one string to a bound length, marking that it happened. */
function truncateString(value: string, maxChars: number): string {
  return value.length > maxChars ? value.slice(0, maxChars) + '…(truncated)' : value;
}

/**
 * Cap `attrs` before it is persisted to asset_observations.attrs. Unlike
 * match_reason's fields, attrs has no fixed shape known ahead of time worth
 * hand-cutting field by field — several of its string fields come straight out
 * of unbounded regex captures (see ATTRS_MAX_BYTES's comment in consts/assets)
 * and `extra` is explicitly free-form per feeder. So the cap is generic:
 * truncate every string (top-level and one level into arrays/`extra`) to a
 * bound length and cap array length, then fall back to dropping `extra`
 * entirely if it is still oversized. Never fails the insert -- a shortened or
 * thinned attrs row is far better than a lost observation, same philosophy as
 * capMatchReason above.
 */
export function capAttrs(attrs: ObservedAttrs): ObservedAttrs {
  const MAX_STRING_CHARS = 1000;
  const MAX_ARRAY_ITEMS = 50;

  if (Buffer.byteLength(JSON.stringify(attrs ?? {}), 'utf8') <= ATTRS_MAX_BYTES) return attrs ?? {};

  const shrinkValue = (value: unknown): unknown => {
    if (typeof value === 'string') return truncateString(value, MAX_STRING_CHARS);
    if (Array.isArray(value)) {
      return value.slice(0, MAX_ARRAY_ITEMS).map((v) => (typeof v === 'string' ? truncateString(v, MAX_STRING_CHARS) : v));
    }
    if (value !== null && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, shrinkValue(v)]));
    }
    return value;
  };

  const shrunk = shrinkValue(attrs ?? {}) as ObservedAttrs;
  if (Buffer.byteLength(JSON.stringify(shrunk), 'utf8') <= ATTRS_MAX_BYTES) return shrunk;

  // Still oversized -- `extra` is the one genuinely unbounded field (feeders
  // may put arbitrary keys in it). Drop it and keep the identity-bearing
  // fields, which is what actually matters for replay.
  const { extra: _dropped, ...withoutExtra } = shrunk;
  return { ...withoutExtra, extra: { truncated: true } };
}

/**
 * Resolve one observation using an already-open transactional handle.
 *
 * Exported so the selftest can drive it with a fake querier; feeders should
 * call resolveAsset()/resolveAssets(), which add the transaction the advisory
 * lock and the multi-statement write need to be correct.
 */
export async function resolveAssetWithQuerier(
  db: AssetIdentityQuerier,
  observation: Observation,
): Promise<ResolveResult> {
  const norm = normalizeObservation(observation.attrs);
  const mintIfNoMatch = observation.mintIfNoMatch !== false;
  const observedAt = observation.observedAt;
  const ownerGroupId = observation.ownerGroupId ?? null;

  // Idempotency guard. asset_observations has UNIQUE (source, source_ref) and
  // insertObservation's ON CONFLICT DO NOTHING already makes a replayed
  // observation a no-op for the OBSERVATION row -- but until this check
  // existed, that was the only thing it protected. A replay (a running scan's
  // report/status polled repeatedly and each poll fire-and-forgetting a feed
  // call, a cron tick overlapping a slow previous one, a manual backfill
  // re-run) would still run the FULL decision ladder again, MINT another
  // asset on a new_asset/ambiguous_new_asset decision, and only discover the
  // observation itself was a duplicate afterward -- by which point the mint
  // had already committed in this same transaction, since a skipped INSERT is
  // not an error and rolls nothing back. Checked first, before any candidate
  // lookup or write, so a true replay is a pure no-op that returns exactly
  // what the FIRST resolution of this (source, sourceRef) already decided,
  // rather than a duplicate asset built entirely from wasted work.
  const existing = await db.query(
    'SELECT o.asset_uuid, o.match_score, o.match_reason, a.identity_confidence, a.needs_review ' +
    'FROM asset_observations o LEFT JOIN assets a ON a.asset_uuid = o.asset_uuid ' +
    'WHERE o.source = $1 AND o.source_ref = $2',
    [observation.source, observation.sourceRef],
  );
  if (existing.length > 0) {
    const row = existing[0];
    const reason = row.match_reason as MatchReason;
    return {
      assetUuid: row.asset_uuid,
      score: row.match_score,
      created: false,
      needsReview: row.needs_review ?? false,
      identityConfidence: row.identity_confidence ?? 0,
      decision: reason.decision,
      reason,
      observationId: null, // nothing new was written -- and nothing needed to be.
    };
  }

  // Everything the normalizer would have scored was rejected. Still write the
  // audit row (asset_observations.asset_uuid is nullable by design): "why is
  // this host not in Assets?" is answered entirely by match_reason.dropped.
  const scoreable = norm.identities.filter((i) => SCOREABLE_KINDS.has(i.kind));
  if (scoreable.length === 0) {
    const reason = capMatchReason({
      decision: 'skipped_no_identities',
      winnerScore: 0,
      runnerUpScore: null,
      candidates: [],
      vetoes: [],
      matched: [],
      dropped: norm.dropped,
    });
    const observationId = await insertObservation(db, observation, null, 0, reason);
    return {
      assetUuid: null, score: 0, created: false, needsReview: false,
      identityConfidence: 0, decision: 'skipped_no_identities', reason, observationId,
    };
  }

  // Serialize concurrent resolution of the same machine. hashtextextended is
  // stable across sessions, and _xact_ means the lock is released by COMMIT or
  // ROLLBACK with no unlock call to leak. The partial UNIQUE index on
  // (kind, value_norm) WHERE kind IN ('bios_uuid','mac') remains the actual
  // correctness backstop -- this lock only avoids the duplicate-minting race
  // in the common case. Locks are acquired one at a time in lockKeysFor's
  // fixed sort order (never Promise.all/concurrently), which is what makes
  // that order deadlock-free.
  for (const lockKey of lockKeysFor(norm)) {
    await db.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
  }

  // ONE indexed candidate lookup, never a query per identity. The row-value IN
  // list is served by idx_asset_identities_kind_value. Candidates that have
  // been soft-merged away are redirected to the survivor here (one hop), so an
  // observation never attaches to a row that is already a known duplicate.
  const lookupIdentities = scoreable.filter((i) => LOOKUP_KINDS.has(i.kind));
  const pairParams: unknown[] = [];
  const tuples: string[] = [];
  for (const id of lookupIdentities) {
    tuples.push('($' + (pairParams.length + 1) + ', $' + (pairParams.length + 2) + ')');
    pairParams.push(id.kind, id.value);
  }
  const candidateRows: CandidateRow[] = lookupIdentities.length === 0 ? [] : await db.query(
    'SELECT COALESCE(a.merged_into, i.asset_uuid) AS asset_uuid, i.kind, i.value_norm ' +
    'FROM asset_identities i ' +
    'LEFT JOIN assets a ON a.asset_uuid = i.asset_uuid ' +
    'WHERE (i.kind, i.value_norm) IN (' + tuples.join(', ') + ')',
    pairParams,
  );

  const byValue = new Map<string, NormalizedIdentity>();
  for (const id of lookupIdentities) byValue.set(id.kind + ' ' + id.value, id);

  const candidates = new Map<string, WorkingCandidate>();
  for (const row of candidateRows ?? []) {
    const matched = byValue.get(row.kind + ' ' + row.value_norm);
    if (!matched) continue;
    let c = candidates.get(row.asset_uuid);
    if (!c) {
      c = {
        assetUuid: row.asset_uuid,
        matchedByKind: new Map(),
        biosUuids: new Set(),
        osFamilies: new Set(),
        macs: new Set(),
        vetoedBy: [],
      };
      candidates.set(row.asset_uuid, c);
    }
    // Scoring is PER KIND, not per value: a host with four NICs that shares
    // all four MACs with a candidate scores 80 for `mac`, not 320. Otherwise
    // the number of NICs, rather than the strength of the evidence, would
    // decide the ladder.
    if (!c.matchedByKind.has(matched.kind)) c.matchedByKind.set(matched.kind, matched);
  }

  // Second lookup, keyed on the candidate PKs: the bios_uuid, os and mac
  // identities the candidates ALREADY own. The candidate query above only
  // returns the values that matched, so without this the conflict vetoes --
  // which are about values that DIFFER -- have no input at all. mac is
  // included here (not just in the initial lookup) so a candidate found via
  // hostname/ip that owns macs sharing NO overlap with this observation's
  // macs can be vetoed even though none of its macs happened to be a lookup hit.
  if (candidates.size > 0) {
    const metaRows: CandidateMetaRow[] = await db.query(
      'SELECT a.asset_uuid, i.kind, i.value_norm ' +
      'FROM assets a ' +
      "LEFT JOIN asset_identities i ON i.asset_uuid = a.asset_uuid AND i.kind IN ('bios_uuid', 'os', 'mac') " +
      'WHERE a.asset_uuid = ANY($1::uuid[])',
      [[...candidates.keys()]],
    );
    for (const row of metaRows ?? []) {
      const c = candidates.get(row.asset_uuid);
      if (!c || row.kind === null || row.value_norm === null) continue;
      if (row.kind === 'bios_uuid') c.biosUuids.add(row.value_norm);
      else if (row.kind === 'os') c.osFamilies.add(row.value_norm);
      else if (row.kind === 'mac') c.macs.add(row.value_norm);
    }
  }

  // Score the observation's os family against the candidates the identifying
  // kinds surfaced. This is where `os` earns its 10 points: as corroboration of
  // a candidate something else nominated, never as the nomination itself.
  const osIdentity = scoreable.find((i) => i.kind === 'os') ?? null;
  if (osIdentity !== null) {
    for (const c of candidates.values()) {
      if (c.osFamilies.has(osIdentity.value)) c.matchedByKind.set('os', osIdentity);
    }
  }

  // Vetoes. These DOMINATE the score -- a candidate carrying one is removed
  // from consideration no matter how high it scored.
  for (const c of candidates.values()) {
    const matchedBios = c.matchedByKind.has('bios_uuid');
    const matchedMac = c.matchedByKind.has('mac');

    // Both sides hold a valid BIOS UUID and they differ. This is the rule that
    // stops a reused DHCP lease from merging two different machines: the IP
    // matches, the OS matches, but the hardware says no.
    if (norm.biosUuid !== null && c.biosUuids.size > 0 && !c.biosUuids.has(norm.biosUuid)) {
      c.vetoedBy.push('bios_uuid_conflict');
    }

    // Both sides have at least one MAC on record and share NONE of them. A
    // MAC is nearly-unique hardware evidence (weight 80): a candidate that
    // already owns different MACs and now shows up with a completely
    // disjoint set is very likely a different machine that happens to share
    // some weaker signal (hostname, os) with this one -- exactly the case a
    // shared/templated hostname produces (two hosts both named "vajra"). A
    // matching bios_uuid overrides this: confirmed identical hardware can
    // legitimately grow a new NIC (or lose an old one), so that is not a
    // contradiction the way a bare hostname+os match sharing no MAC is.
    if (norm.macs.length > 0 && c.macs.size > 0 && !matchedMac && !matchedBios) {
      c.vetoedBy.push('mac_conflict');
    }

    // A different OS family, with no hardware anchor to explain it. With a
    // matching bios_uuid or MAC this is a reimaged machine and the OS change
    // is the news, not a contradiction -- so the veto only fires without one.
    if (
      norm.osFamily !== null &&
      c.osFamilies.size > 0 &&
      !c.osFamilies.has(norm.osFamily) &&
      !matchedBios &&
      !matchedMac
    ) {
      c.vetoedBy.push('os_family_conflict');
    }
  }

  const scored: CandidateScore[] = [...candidates.values()].map((c) => {
    const matched = [...c.matchedByKind.values()];
    return {
      assetUuid: c.assetUuid,
      score: matched.reduce((sum, m) => sum + m.weight, 0),
      matched,
      vetoedBy: c.vetoedBy,
    };
  });

  const eligible = scored
    .filter((c) => c.vetoedBy.length === 0)
    .sort((a, b) => b.score - a.score || (a.assetUuid < b.assetUuid ? -1 : 1));

  const vetoes: VetoReason[] = [];
  for (const c of scored) for (const v of c.vetoedBy) if (!vetoes.includes(v)) vetoes.push(v);

  const winner = eligible[0] ?? null;
  const runnerUp = eligible[1] ?? null;

  // Ambiguity veto: two candidates this close are not distinguishable by the
  // evidence in hand, so the matcher refuses to choose. Minting a duplicate
  // and flagging it for review is recoverable; picking the wrong one is not.
  const ambiguous =
    winner !== null && runnerUp !== null && winner.score - runnerUp.score < AMBIGUITY_MARGIN;
  if (ambiguous && !vetoes.includes('ambiguous_candidates')) vetoes.push('ambiguous_candidates');

  // The strongest anchor this observation itself carries -- used ONLY for a
  // freshly-minted asset, where "everything on this observation" and
  // "everything proven about the asset" are the same thing.
  const observationConfidence = scoreable.reduce((max, i) => Math.max(max, i.weight), 0);

  // What this observation actually PROVED about the WINNING candidate --
  // i.e. the strongest kind that took part in the match, not the strongest
  // kind the observation happens to carry. An observation that matches an
  // existing asset only on hostname (weight 40) may also carry a brand-new,
  // never-before-seen bios_uuid (weight 100): that value didn't match
  // anything (nothing owned it yet), so it must not promote confidence to
  // 100 on the strength of a hostname-only match -- that is exactly the
  // hostname-collision failure mode this module's vetoes exist to prevent,
  // just arriving through identity_confidence instead of through a wrong
  // attach.
  const matchedConfidence = (c: CandidateScore) =>
    c.matched.reduce((max, m) => Math.max(max, m.weight), 0);

  let decision: ResolveDecision;
  let chosen: CandidateScore | null = null;
  let confidence = observationConfidence;

  if (winner === null || ambiguous) {
    decision = mintIfNoMatch ? (ambiguous ? 'ambiguous_new_asset' : 'new_asset') : 'skipped_no_mint';
  } else if (winner.score >= ATTACH_THRESHOLD) {
    decision = 'attached';
    chosen = winner;
    confidence = matchedConfidence(chosen);
  } else if (winner.score >= REVIEW_THRESHOLD) {
    decision = 'attached_needs_review';
    chosen = winner;
    confidence = matchedConfidence(chosen);
  } else if (eligible.length === 1 && winner.matched.every((m) => m.kind === 'ip' || m.kind === 'os')) {
    // The anti-duplicate rule. Exactly one asset holds this IP, nothing
    // vetoed, and an IP is all we have. Attaching is right -- re-scanning a
    // subnet must not mint a fresh asset per IP per scan across 1630 stored
    // nmap runs -- but the asset must not come out of it looking any better
    // identified, so confidence is pinned to the ip weight.
    //
    // An `os` match rides along here rather than disqualifying the rule. A
    // matching OS family is CORROBORATION of the IP, so "this IP, and the OS
    // agrees" is strictly stronger evidence than "this IP" -- yet with `os`
    // treated as disqualifying, the ip+os observation scored 15, missed both
    // thresholds, failed this test and fell through to `new_asset`, minting a
    // duplicate on every single re-scan. Confidence is still pinned to 5:
    // an OS family does not identify a machine, so the asset must not come out
    // of this looking better identified than the DHCP lease it actually is.
    decision = 'attached_needs_review';
    chosen = winner;
    confidence = Math.min(confidence, 5);
  } else {
    decision = mintIfNoMatch ? 'new_asset' : 'skipped_no_mint';
  }

  const matchedIdentities: NormalizedIdentity[] = chosen ? chosen.matched : [];
  const score = chosen ? chosen.score : 0;
  const needsReview = decision === 'attached_needs_review' || decision === 'ambiguous_new_asset';

  const reason = capMatchReason({
    decision,
    winnerScore: winner ? winner.score : 0,
    runnerUpScore: runnerUp ? runnerUp.score : null,
    candidates: scored,
    vetoes,
    matched: matchedIdentities,
    dropped: norm.dropped,
  });

  if (decision === 'skipped_no_mint') {
    // A low-information source (nuclei) that matched nothing. Record the audit
    // row so the target is still explainable, but never create an asset from it.
    const observationId = await insertObservation(db, observation, null, score, reason);
    return {
      assetUuid: null, score, created: false, needsReview: false,
      identityConfidence: 0, decision, reason, observationId,
    };
  }

  let assetUuid: string;
  let created = false;
  if (chosen !== null) {
    assetUuid = chosen.assetUuid;
    await db.query(
      'UPDATE assets SET last_seen = GREATEST(last_seen, $2), ' +
      'identity_confidence = GREATEST(identity_confidence, $3), ' +
      'needs_review = needs_review OR $4, ' +
      'owner_group_id = COALESCE(owner_group_id, $5) ' +
      'WHERE asset_uuid = $1',
      [assetUuid, observedAt, confidence, needsReview, ownerGroupId],
    );
  } else {
    const minted = await db.query(
      'INSERT INTO assets (first_seen, last_seen, identity_confidence, needs_review, owner_group_id) ' +
      'VALUES ($1, $1, $2, $3, $4) RETURNING asset_uuid',
      [observedAt, confidence, needsReview, ownerGroupId],
    );
    assetUuid = minted[0].asset_uuid;
    created = true;
  }

  await upsertIdentities(db, assetUuid, norm, observedAt);
  const observationId = await insertObservation(db, observation, assetUuid, score, reason);

  return {
    assetUuid, score, created, needsReview,
    identityConfidence: confidence, decision, reason, observationId,
  };
}

/**
 * Record every surviving identity against the asset, bumping last_seen on the
 * ones already there. Identities ACCUMULATE and are never overwritten, so
 * last_seen per value doubles as that value's history (which IP this machine
 * held, and when).
 *
 * The NOT EXISTS guard skips a bios_uuid/mac already owned by a DIFFERENT
 * asset. That is not a hypothetical race: an observation can legitimately
 * match asset A on its BIOS UUID while carrying a MAC that asset B already
 * claims (a NIC moved between machines). Inserting it would violate the
 * partial UNIQUE index and abort the whole transaction, losing an observation
 * that resolved perfectly well. Skipping keeps the strong identity with its
 * first owner and leaves the discrepancy visible in match_reason.
 */
async function upsertIdentities(
  db: AssetIdentityQuerier,
  assetUuid: string,
  norm: NormalizedObservation,
  observedAt: Date,
): Promise<void> {
  if (norm.identities.length === 0) return;
  const kinds = norm.identities.map((i) => i.kind);
  const values = norm.identities.map((i) => i.value);
  const weights = norm.identities.map((i) => i.weight);
  await db.query(
    'INSERT INTO asset_identities (asset_uuid, kind, value_norm, weight, first_seen, last_seen) ' +
    'SELECT $1, t.kind, t.value_norm, t.weight, $5, $5 ' +
    'FROM unnest($2::text[], $3::text[], $4::int[]) AS t(kind, value_norm, weight) ' +
    "WHERE t.kind NOT IN ('bios_uuid', 'mac') OR NOT EXISTS (" +
    '  SELECT 1 FROM asset_identities x ' +
    '  WHERE x.kind = t.kind AND x.value_norm = t.value_norm AND x.asset_uuid <> $1' +
    ') ' +
    'ON CONFLICT (asset_uuid, kind, value_norm) DO UPDATE ' +
    'SET last_seen = GREATEST(asset_identities.last_seen, EXCLUDED.last_seen)',
    [assetUuid, kinds, values, weights, observedAt],
  );
}

/**
 * One append-only observation row per (source, source_ref). ON CONFLICT DO
 * NOTHING is what makes a replayed feed a no-op: re-reading an nmap scan after
 * a watermark reset returns no id and changes nothing.
 */
async function insertObservation(
  db: AssetIdentityQuerier,
  observation: Observation,
  assetUuid: string | null,
  matchScore: number,
  reason: MatchReason,
): Promise<string | null> {
  const rows = await db.query(
    'INSERT INTO asset_observations ' +
    '(asset_uuid, source, source_ref, observed_at, attrs, match_score, match_reason) ' +
    'VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb) ' +
    'ON CONFLICT (source, source_ref) DO NOTHING RETURNING id',
    [
      assetUuid,
      observation.source,
      observation.sourceRef,
      observation.observedAt,
      JSON.stringify(capAttrs(observation.attrs)),
      matchScore,
      JSON.stringify(reason),
    ],
  );
  // bigserial comes back from node-postgres as a string; keep it one.
  return rows && rows.length > 0 ? String(rows[0].id) : null;
}

/**
 * Resolve one observation inside its own transaction.
 *
 * The db handle is injected -- pass either the fleet DataSource
 * (dbSourceConnection()[1]) or an EntityManager the caller is already inside.
 * If the manager is already transactional the existing transaction is reused,
 * because pg_advisory_xact_lock must be held by the same transaction that does
 * the writes.
 */
export async function resolveAsset(
  db: DataSource | EntityManager,
  observation: Observation,
): Promise<ResolveResult> {
  // Duck-typed rather than `instanceof DataSource`, because the import above
  // is type-only: a DataSource exposes `.manager`, an EntityManager does not.
  const manager: EntityManager = 'manager' in db ? (db as DataSource).manager : (db as EntityManager);
  if (manager.queryRunner && manager.queryRunner.isTransactionActive) {
    return resolveAssetWithQuerier(manager, observation);
  }
  return manager.transaction((txManager) => resolveAssetWithQuerier(txManager, observation));
}

/**
 * Batch helper the feeders call. ONE TRANSACTION PER OBSERVATION, deliberately:
 * a single poisoned row (an identity that trips the partial UNIQUE index under
 * a concurrent writer, a value too long for value_norm) must not roll back an
 * entire scan's worth of resolutions. Failures are logged and skipped, and the
 * returned array is therefore SHORTER than the input when something failed.
 */
export async function resolveAssets(
  db: DataSource,
  observations: Observation[],
): Promise<ResolveResult[]> {
  const results: ResolveResult[] = [];
  for (const observation of observations) {
    try {
      results.push(await resolveAsset(db, observation));
    } catch (err) {
      logger.error(
        { err, source: observation.source, sourceRef: observation.sourceRef },
        'Asset identity resolution failed for one observation; continuing with the rest',
      );
    }
  }
  return results;
}
