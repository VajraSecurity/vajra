import { describe, expect, it } from 'vitest';
import { csvCell, hasInvisible, safeText } from '@/features/FileIntegrity/safeText';
import { validateRegKeyPattern, validateValueName } from '@/features/FileIntegrity/RegistryCoverage/regValidation';
import { awaitingConfirmation, driftChanged, isProtectedCoverage, isUnconfirmed, riskCounts } from '@/features/FileIntegrity/driftSafety';
import { protectedCoverageEntry } from '@/features/FileIntegrity/RegistryCoverage/regModel';

const ch = (cp: number) => String.fromCodePoint(cp);
const label = (cp: number) => `⟨U+${cp.toString(16).toUpperCase().padStart(4, '0')}⟩`;

describe('safeText', () => {
  const visible: [string, number][] = [
    ['NUL (Cc)', 0x0000], ['TAB (Cc)', 0x0009], ['DEL (Cc)', 0x007f], ['C1 (Cc)', 0x0085],
    ['RLO bidi override (Cf)', 0x202e], ['LRI isolate (Cf)', 0x2066], ['zero-width space (Cf)', 0x200b],
    ['ZWJ (Cf)', 0x200d], ['word joiner (Cf)', 0x2060], ['BOM (Cf)', 0xfeff], ['Arabic letter mark (Cf)', 0x061c],
    ['soft hyphen', 0x00ad], ['Mongolian vowel separator', 0x180e], ['combining grapheme joiner', 0x034f],
    ['Hangul choseong filler', 0x115f], ['Hangul jungseong filler', 0x1160], ['Hangul filler', 0x3164], ['halfwidth Hangul filler', 0xffa0],
    ['line separator', 0x2028], ['paragraph separator', 0x2029],
    ['tag U+E0000 (unassigned)', 0xe0000], ['language tag', 0xe0001], ['tag latin a', 0xe0061], ['cancel tag', 0xe007f],
  ];
  for (const [name, cp] of visible) {
    it(`makes ${name} visible`, () => {
      const s = `a${ch(cp)}b`;
      expect(hasInvisible(s)).toBe(true);
      expect(safeText(s)).toBe(`a${label(cp)}b`);
    });
  }

  it('renders an astral tag character as one code point token', () => {
    expect(safeText(`x${ch(0xe0041)}${ch(0xe0042)}`)).toBe('x⟨U+E0041⟩⟨U+E0042⟩');
  });

  it('spoofed extension via RLO is exposed', () => {
    expect(safeText(`Run\\evil${ch(0x202e)}exe.lld`)).toBe('Run\\evil⟨U+202E⟩exe.lld');
  });

  it('leaves ordinary text, accents and non-Latin scripts alone', () => {
    for (const s of ['HKEY_LOCAL_MACHINE\\SOFTWARE\\Run', 'café', '日本語', 'Ελληνικά', 'emoji 😀']) {
      expect(hasInvisible(s)).toBe(false);
      expect(safeText(s)).toBe(s);
    }
  });

  it('handles null, undefined and non-strings', () => {
    expect(safeText(null)).toBe('');
    expect(safeText(undefined)).toBe('');
    expect(safeText(42)).toBe('42');
    expect(hasInvisible(null)).toBe(false);
  });

  it('is stable across repeated calls (no global-regex lastIndex state)', () => {
    const s = `a${ch(0x200b)}`;
    expect(hasInvisible(s)).toBe(true);
    expect(hasInvisible(s)).toBe(true);
  });
});

describe('csvCell', () => {
  it('quotes, escapes and neutralises formulas', () => {
    expect(csvCell('=SUM(A1)')).toBe(`"'=SUM(A1)"`);
    expect(csvCell('+1')).toBe(`"'+1"`);
    expect(csvCell('-1')).toBe(`"'-1"`);
    expect(csvCell('@x')).toBe(`"'@x"`);
    expect(csvCell('a"b')).toBe('"a""b"');
    expect(csvCell(`a${ch(0x202e)}`)).toBe('"a⟨U+202E⟩"');
    expect(csvCell('\t=1+1')).toBe(`"'⟨U+0009⟩=1+1"`);
    expect(csvCell('\rcmd')).toBe(`"'⟨U+000D⟩cmd"`);
    expect(csvCell('plain')).toBe('"plain"');
  });
});

describe('registry validator refuses invisible characters', () => {
  const base = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Vendor\\Agent';
  for (const cp of [0x0000, 0x007f, 0x202e, 0x200b, 0x00ad, 0x180e, 0x034f, 0x115f, 0x3164, 0xffa0, 0xe0001, 0xe0000, 0x2028]) {
    it(`refuses U+${cp.toString(16).toUpperCase()} in a key and a value name`, () => {
      expect(validateRegKeyPattern(`${base}${ch(cp)}x`, { allowRecursive: false })).not.toBeNull();
      expect(validateValueName(`Val${ch(cp)}ue`)).not.toBeNull();
    });
  }
  it('refuses non-ASCII printable characters', () => {
    expect(validateRegKeyPattern(`${base}é`, { allowRecursive: false })).toMatch(/printable ASCII/);
    expect(validateValueName('Valué')).toMatch(/printable ASCII/);
  });
  it("allows '/' in value names but not in key patterns", () => {
    expect(validateValueName('a/b')).toBeNull();
    expect(validateRegKeyPattern(`${base}/x`, { allowRecursive: false })).not.toBeNull();
  });
  it('accepts a normal key', () => {
    expect(validateRegKeyPattern(base, { allowRecursive: false })).toBeNull();
  });
});

describe('drift approval guards', () => {
  const d = { path: 'registry|HKEY_LOCAL_MACHINE\\X', kind: 'item' as const, policyName: 'Registry coverage: host1', source: 'realtime', reverted: true, confirmedAt: null, severity: 'critical' as const };
  it('classifies protected / unconfirmed / reverted / critical', () => {
    expect(isProtectedCoverage(d)).toBe(true);
    expect(isUnconfirmed(d)).toBe(true);
    expect(isUnconfirmed({ ...d, confirmedAt: 5 })).toBe(false);
    expect(isUnconfirmed({ ...d, source: 'scan' })).toBe(false);
    expect(riskCounts([d, { ...d, path: '/etc/passwd', kind: 'file', reverted: false, severity: 'low' }])).toEqual({ critical: 1, protectedCov: 1, reverted: 1, unconfirmed: 1 });
  });
  it('parses the awaiting_confirmation 409', () => {
    const e = { response: { status: 409, data: { message: 'Awaiting confirmation scan for 2 item(s)', errors: ['awaiting_confirmation', '12', '13'] } } };
    expect(awaitingConfirmation(e)).toEqual({ message: 'Awaiting confirmation scan for 2 item(s)', ids: [12, 13] });
    expect(awaitingConfirmation({ response: { status: 409, data: { errors: ['other'] } } })).toBeNull();
    expect(awaitingConfirmation({ response: { status: 400, data: { errors: ['awaiting_confirmation'] } } })).toBeNull();
  });
  it('parses the drift_changed 409', () => {
    const e = { response: { status: 409, data: { message: 'The drift changed since it was reviewed', errors: ['drift_changed', JSON.stringify({ id: 7, newSha256: 'ab', changeType: 'modified', lastSeenAt: 10, newAttrs: { a: 1 } }), 'not json'] } } };
    const r = driftChanged(e);
    expect(r?.items).toEqual([{ id: 7, contentHash: null, newSha256: 'ab', changeType: 'modified', lastSeenAt: 10, newAttrs: { a: 1 } }]);
  });
  it('extracts the protected catalog id from a 422 message', () => {
    expect(protectedCoverageEntry('protected coverage: hklm-run overlaps the custom key')).toBe('hklm-run');
    expect(protectedCoverageEntry('something else')).toBeNull();
  });
});
