import { describe, expect, it } from 'vitest';
import { driftChanged, expectedOf, expectedOfAlerts, needsReview, summarizeBulk } from '@/features/FileIntegrity/driftSafety';

describe('expectedOf (drift approve guard is content-based)', () => {
  it('sends only the reviewed contentHash per drift id', () => {
    const items = [
      { id: 7, contentHash: 'c7', newSha256: 'aa', changeType: 'modified', lastSeenAt: 100, occurrences: 3 },
      { id: 9, contentHash: 'c9', newSha256: null, changeType: 'removed', lastSeenAt: 200, occurrences: 1 },
    ];
    const out = expectedOf(items);
    expect(out).toEqual({ 7: { contentHash: 'c7' }, 9: { contentHash: 'c9' } });
    // Occurrences / last-seen / hash / change type must not be part of the approval guard any more.
    for (const v of Object.values(out!)) {
      expect(Object.keys(v)).toEqual(['contentHash']);
      expect(v).not.toHaveProperty('lastSeenAt');
      expect(v).not.toHaveProperty('newSha256');
      expect(v).not.toHaveProperty('changeType');
    }
  });

  it('is null when a drift carries no contentHash (approve needs a reload first)', () => {
    expect(expectedOf([{ id: 1, contentHash: 'c1' }, { id: 2, contentHash: null }])).toBeNull();
    expect(expectedOf([{ id: 1, contentHash: '' }])).toBeNull();
  });
});

describe('expectedOfAlerts', () => {
  it('keys by driftId, sends only contentHash and excludes alerts without linked drift', () => {
    const alerts = [
      { alertId: 1, driftId: 11, contentHash: 'h11', newSha256: 'x', changeType: 'modified', driftLastSeenAt: 5 },
      { alertId: 2, driftId: null, contentHash: null },
      { alertId: 3, driftId: 13, contentHash: 'h13', driftLastSeenAt: null },
    ];
    expect(expectedOfAlerts(alerts)).toEqual({ 11: { contentHash: 'h11' }, 13: { contentHash: 'h13' } });
  });

  it('does not require the linked drift lastSeenAt any more', () => {
    expect(expectedOfAlerts([{ driftId: 4, contentHash: 'h4' }])).toEqual({ 4: { contentHash: 'h4' } });
  });

  it('is null when a linked drift has no contentHash', () => {
    expect(expectedOfAlerts([{ driftId: 4, contentHash: null }])).toBeNull();
  });

  it('is empty (not null) when no alert has linked drift', () => {
    expect(expectedOfAlerts([{ driftId: null, contentHash: null }])).toEqual({});
  });
});

describe('summarizeBulk (multi-id per-item results)', () => {
  it('lists the drift items that were NOT resolved, with the reason', () => {
    const s = summarizeBulk([1, 2, 3, 4], {
      results: [
        { id: 1, outcome: 'resolved' },
        { id: 2, outcome: 'drift_changed', current: { contentHash: 'n', newSha256: 'b', changeType: 'modified', lastSeenAt: 9 } },
        { id: 3, outcome: 'awaiting_confirmation' },
      ],
    }, 'resolved');
    expect(s.done).toEqual([1]);
    expect(s.unknown).toBe(false);
    expect(s.refused.map((r) => [r.id, r.reason])).toEqual([[2, 'drift_changed'], [3, 'awaiting_confirmation'], [4, 'skipped']]);
    expect(s.refused[0].current?.newSha256).toBe('b');
    expect(needsReview(s).map((r) => r.id)).toEqual([2, 3]);
  });

  it('maps alert results to their linked drift', () => {
    const s = summarizeBulk([10, 11], { results: [{ id: 10, driftId: 100, outcome: 'closed' }, { id: 11, driftId: 101, outcome: 'awaiting_confirmation' }] }, 'closed');
    expect(s.done).toEqual([10]);
    expect(s.refused).toEqual([{ id: 11, driftId: 101, reason: 'awaiting_confirmation' }]);
  });

  it('flags a response without per-item results as unknown', () => {
    expect(summarizeBulk([1, 2], { ids: [1] }, 'resolved')).toEqual({ done: [1], refused: [], unknown: true });
  });
});

describe('driftChanged 409 still parses (now with contentHash)', () => {
  it('reads the current values', () => {
    const e = { response: { status: 409, data: { message: 'changed', errors: ['drift_changed', JSON.stringify({ id: 3, contentHash: 'new', newSha256: 'ff', changeType: 'modified', lastSeenAt: 4 })] } } };
    expect(driftChanged(e)?.items).toEqual([{ id: 3, contentHash: 'new', newSha256: 'ff', changeType: 'modified', lastSeenAt: 4, newAttrs: null }]);
  });
});
