/**
 * Rendering helpers for UNTRUSTED text in every File Integrity view (paths, item keys, value names
 * and data, attributes, process / user / host names, notes, alert codes and remarks, server error
 * text). React already escapes HTML; these helpers additionally make invisible, blank-looking or
 * direction-changing characters visible, so a value such as `Run<U+202E>exe.lld` cannot visually
 * masquerade as something else and a hidden character cannot disappear from view.
 *
 * Made visible as `⟨U+XXXX⟩` (by code point, so astral characters are one token; rendered by
 * UntrustedText as a distinct styled element built from safeTokens()):
 *  - HIDDEN (reported by hasInvisible):
 *    - Unicode Cc (C0/C1 controls, DEL) and Cf (bidi marks / embeddings / overrides / isolates,
 *      zero-width space and joiners, word joiner, BOM, soft hyphen, interlinear annotation
 *      U+FFF9-U+FFFB, tag characters, ...);
 *    - every separator \p{Z} except the ASCII space U+0020 (NBSP, U+1680, U+2000-U+200A, U+2028,
 *      U+2029, U+202F, U+205F, U+3000, ...);
 *    - variation selectors U+FE00-U+FE0F and U+E0100-U+E01EF, Mongolian free variation selectors
 *      U+180B-U+180F, combining grapheme joiner U+034F;
 *    - blank-looking letters / symbols: Hangul fillers U+115F U+1160 U+3164 U+FFA0, Braille blank
 *      U+2800, Khmer inherent vowels U+17B4 U+17B5, object replacement U+FFFC, musical null
 *      notehead U+1D159;
 *    - the whole tag block U+E0000-U+E007F and lone (unpaired) surrogates.
 *  - LOOK-ALIKE (escaped, not reported as hidden): the marker's own bracket U+27E8 / U+27E9 and its
 *    look-alikes (U+2329/U+232A, U+3008-U+300B, U+27EA/U+27EB, U+2039/U+203A, ...), so data such
 *    as `⟨U+202E⟩` or `〈U+202E〉` can never imitate a real escape in a plain-text copy.
 *  - DECOMPOSED: in text that is not in Unicode NFC form, every combining mark (so `cafe` + U+0301
 *    is distinguishable from `café`); the text itself is never normalised. See isNotNfc().
 * Source contains no literal invisible characters: everything is written as escapes.
 */

// Hidden characters. Separators are matched as \p{Z} minus the ASCII space (lookahead); variation
// selectors (U+FE00-FE0F, U+E0100-E01EF, U+180B-180D, U+180F) via \p{Variation_Selector}.
// Combining marks (variation selectors, Khmer inherent vowels, CGJ) are kept OUT of the character
// class (each as its own alternative) so no class mixes base and combining characters.
const HIDDEN_SRC = '(?:(?! )\\p{Z}|\\p{Variation_Selector}|[\\p{Cc}\\p{Cf}\\p{Cs}\\u00AD\\u115F\\u1160\\u180E\\u2800\\u3164\\uFFA0\\uFFF9-\\uFFFC\\u{1D159}\\u{E0000}-\\u{E007F}]|\\u17B4|\\u17B5|\\u034F)';

/** Non-global (safe for .test()): matches one hidden character that safeText() rewrites. */
export const INVISIBLE_CHAR_RX = new RegExp(HIDDEN_SRC, 'u');

/** The marker's bracket and characters that look like it (escaped so data cannot imitate an escape). */
const BRACKETS_SRC = '[\\u2039\\u203A\\u2329\\u232A\\u276C-\\u2771\\u27E8-\\u27EB\\u2991\\u2992\\u29FC\\u29FD\\u3008-\\u300B\\uFE3D-\\uFE40\\uFF1C\\uFF1E]';
const MARKER_OPEN = '⟨';
const HIDDEN_RX_1 = new RegExp(`^${HIDDEN_SRC}$`, 'u');
const BRACKET_RX_1 = new RegExp(`^${BRACKETS_SRC}$`, 'u');
const ESCAPE_RX_G = new RegExp(`${HIDDEN_SRC}|${BRACKETS_SRC}`, 'gu');
const ESCAPE_NFD_RX_G = new RegExp(`${HIDDEN_SRC}|${BRACKETS_SRC}|\\p{M}`, 'gu');

/** Names for the characters most likely to be used for spoofing (title / aria-label of an escape). */
const CHAR_NAMES: Record<number, string> = {
  0x0000: 'NULL', 0x0009: 'CHARACTER TABULATION', 0x000a: 'LINE FEED', 0x000d: 'CARRIAGE RETURN', 0x001b: 'ESCAPE', 0x007f: 'DELETE',
  0x00a0: 'NO-BREAK SPACE', 0x00ad: 'SOFT HYPHEN', 0x034f: 'COMBINING GRAPHEME JOINER', 0x061c: 'ARABIC LETTER MARK', 0x115f: 'HANGUL CHOSEONG FILLER',
  0x1160: 'HANGUL JUNGSEONG FILLER', 0x1680: 'OGHAM SPACE MARK', 0x17b4: 'KHMER VOWEL INHERENT AQ', 0x17b5: 'KHMER VOWEL INHERENT AA',
  0x180e: 'MONGOLIAN VOWEL SEPARATOR', 0x2007: 'FIGURE SPACE', 0x200b: 'ZERO WIDTH SPACE', 0x200c: 'ZERO WIDTH NON-JOINER',
  0x200d: 'ZERO WIDTH JOINER', 0x200e: 'LEFT-TO-RIGHT MARK', 0x200f: 'RIGHT-TO-LEFT MARK', 0x2028: 'LINE SEPARATOR', 0x2029: 'PARAGRAPH SEPARATOR',
  0x202a: 'LEFT-TO-RIGHT EMBEDDING', 0x202b: 'RIGHT-TO-LEFT EMBEDDING', 0x202c: 'POP DIRECTIONAL FORMATTING', 0x202d: 'LEFT-TO-RIGHT OVERRIDE',
  0x202e: 'RIGHT-TO-LEFT OVERRIDE', 0x202f: 'NARROW NO-BREAK SPACE', 0x205f: 'MEDIUM MATHEMATICAL SPACE', 0x2060: 'WORD JOINER',
  0x2066: 'LEFT-TO-RIGHT ISOLATE', 0x2067: 'RIGHT-TO-LEFT ISOLATE', 0x2068: 'FIRST STRONG ISOLATE', 0x2069: 'POP DIRECTIONAL ISOLATE',
  0x2800: 'BRAILLE PATTERN BLANK', 0x27e8: 'MATHEMATICAL LEFT ANGLE BRACKET', 0x27e9: 'MATHEMATICAL RIGHT ANGLE BRACKET', 0x2329: 'LEFT-POINTING ANGLE BRACKET',
  0x232a: 'RIGHT-POINTING ANGLE BRACKET', 0x3000: 'IDEOGRAPHIC SPACE', 0x3008: 'LEFT ANGLE BRACKET', 0x3009: 'RIGHT ANGLE BRACKET', 0x3164: 'HANGUL FILLER',
  0xfeff: 'ZERO WIDTH NO-BREAK SPACE (BOM)', 0xffa0: 'HALFWIDTH HANGUL FILLER', 0xfffc: 'OBJECT REPLACEMENT CHARACTER', 0x1d159: 'MUSICAL SYMBOL NULL NOTEHEAD',
};

/** `U+XXXX` for one code point (no brackets). */
function codePointHex(c: string): string {
  return `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`;
}

/** `⟨U+XXXX⟩` for one code point. */
export function codePointLabel(c: string): string {
  return `${MARKER_OPEN}${codePointHex(c)}⟩`;
}

function charName(cp: number, c: string): string {
  if (CHAR_NAMES[cp]) return CHAR_NAMES[cp];
  if (cp >= 0xd800 && cp <= 0xdfff) return 'LONE SURROGATE (invalid UTF-16)';
  if (cp >= 0xe0000 && cp <= 0xe007f) return 'TAG CHARACTER';
  if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) return 'VARIATION SELECTOR';
  if (cp >= 0x180b && cp <= 0x180f) return 'MONGOLIAN FREE VARIATION SELECTOR';
  if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) return 'CONTROL CHARACTER';
  if (/\p{Z}/u.test(c)) return 'SPACE / SEPARATOR CHARACTER';
  if (BRACKET_RX_1.test(c)) return 'ANGLE BRACKET LOOK-ALIKE';
  if (/\p{M}/u.test(c)) return 'COMBINING MARK';
  return 'FORMAT CHARACTER';
}

/** Why a code point was escaped. */
export type EscapeReason = 'hidden' | 'lookalike' | 'decomposed';

/** One piece of rendered untrusted text: literal text, or one escaped code point. */
export type SafeToken =
  | { kind: 'text'; text: string }
  | {
    kind: 'escape';
    /** The code point that was escaped. */
    codePoint: number;
    /** Plain-text form, `⟨U+XXXX⟩` (what a copy / export contains). */
    label: string;
    /** `U+XXXX`. */
    hex: string;
    /** Unicode name or a category description. */
    name: string;
    /** true for a real invisible / bidi / control / blank character (what hasInvisible reports). */
    hidden: boolean;
    reason: EscapeReason;
    /** Human description for title / aria-label. */
    description: string;
  };

/** True when the text is not in Unicode NFC form (e.g. decomposed accents): it is shown with its combining marks escaped, never normalised. */
export function isNotNfc(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  const s = typeof value === 'string' ? value : String(value);
  try { return s.normalize('NFC') !== s; } catch { return false; }
}

/**
 * Structured form of safeText(): literal text runs and escape tokens. UntrustedText renders each
 * escape as a distinct styled element (not as plain characters), so data can never imitate one.
 */
export function safeTokens(value: unknown): SafeToken[] {
  if (value === null || value === undefined) return [];
  const s = typeof value === 'string' ? value : String(value);
  const rx = isNotNfc(s) ? ESCAPE_NFD_RX_G : ESCAPE_RX_G;
  const out: SafeToken[] = [];
  let last = 0;
  for (const m of s.matchAll(rx)) {
    const i = m.index ?? 0;
    if (i > last) out.push({ kind: 'text', text: s.slice(last, i) });
    const c = m[0];
    const cp = c.codePointAt(0) ?? 0;
    const hex = codePointHex(c);
    const name = charName(cp, c);
    const reason: EscapeReason = HIDDEN_RX_1.test(c) ? 'hidden' : BRACKET_RX_1.test(c) ? 'lookalike' : 'decomposed';
    out.push({
      kind: 'escape', codePoint: cp, label: codePointLabel(c), hex, name, hidden: reason === 'hidden', reason,
      description: reason === 'hidden' ? `Hidden character ${hex} (${name})`
        : reason === 'lookalike' ? `Literal character ${hex} (${name}) from the data, escaped so it cannot imitate a hidden-character marker`
          : `Combining mark ${hex} (${name}) in text that is not in Unicode NFC form; shown separately so look-alike text can be told apart`,
    });
    last = i + c.length;
  }
  if (last < s.length) out.push({ kind: 'text', text: s.slice(last) });
  return out;
}

/**
 * Plain-text form: every hidden character, every marker look-alike bracket and (in non-NFC text)
 * every combining mark replaced by `⟨U+XXXX⟩`. Use for attributes, toasts, CSV and other
 * text-only sinks.
 */
export function safeText(value: unknown): string {
  return safeTokens(value).map((t) => (t.kind === 'text' ? t.text : t.label)).join('');
}

/**
 * True when the text contains a real hidden character (see the list above), including lone
 * surrogates and non-ASCII spaces. Escaped look-alike brackets (e.g. a literal `⟨U+202E⟩` string)
 * and NFC differences are NOT reported here (see isNotNfc).
 */
export function hasInvisible(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  return INVISIBLE_CHAR_RX.test(typeof value === 'string' ? value : String(value));
}

/**
 * CSV cell for any export: formula-injection safe and quoted. A cell whose raw value starts with
 * = + - @ TAB or CR (or whose rendered form starts with = + - @) gets a leading '; hidden
 * characters are escaped by safeText.
 */
export function csvCell(value: unknown): string {
  const raw = value === null || value === undefined ? '' : typeof value === 'string' ? value : String(value);
  let s = safeText(value);
  if (/^[=+\-@\t\r]/.test(raw) || /^[=+\-@]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

export function fmtCount(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '-';
  return Math.round(n).toLocaleString();
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '-';
  if (Math.abs(n) < 1024) return `${Math.round(n)} B`;
  if (Math.abs(n) < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function fmtSigned(n: number, fmt: (v: number) => string): string {
  if (n === 0) return '±0';
  return `${n > 0 ? '+' : '-'}${fmt(Math.abs(n))}`;
}
