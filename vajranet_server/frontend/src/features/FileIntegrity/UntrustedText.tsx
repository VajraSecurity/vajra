import { AlertTriangle } from 'lucide-react';
import { hasInvisible, isNotNfc, safeText, safeTokens, type SafeToken } from './safeText';

type EscapeToken = Extract<SafeToken, { kind: 'escape' }>;

/**
 * One escaped code point, rendered as a distinct element (dashed box, own colours, title and
 * aria-label) built from a structured token, never from the data's own characters. Its text
 * content is the plain-text marker `⟨U+XXXX⟩` (what a copy contains); a literal `⟨` in the data is
 * itself escaped, so a plain-text copy is unambiguous as well.
 */
export function EscapeMark({ token }: { token: EscapeToken }) {
  return (
    <span
      role="img"
      data-fim-escape={token.hex}
      data-fim-hidden={token.hidden ? 'true' : 'false'}
      data-fim-reason={token.reason}
      title={token.description}
      aria-label={token.description}
      className={`fim-escape mx-px inline-block whitespace-nowrap rounded border border-dashed px-0.5 align-baseline font-mono text-[0.8em] font-semibold leading-tight ${token.reason === 'hidden'
        ? 'border-red-500 bg-red-100 text-red-800 dark:border-red-400 dark:bg-red-500/20 dark:text-red-200'
        : token.reason === 'decomposed'
          ? 'border-violet-400 bg-violet-100 text-violet-800 dark:border-violet-400 dark:bg-violet-500/20 dark:text-violet-200'
          : 'border-slate-400 bg-slate-100 text-slate-700 dark:border-slate-500 dark:bg-white/10 dark:text-slate-200'}`}
    >
      {token.label}
    </span>
  );
}

/**
 * Untrusted text: hidden characters, marker look-alikes and (in non-NFC text) combining marks are
 * shown as distinct escape marks; flagged when hidden characters exist or the text is not NFC.
 * Spaces are preserved (white-space: pre-wrap, or `pre` with `nowrap` for single-line cells), so
 * double and trailing spaces stay visible.
 */
export function RegText({ value, mono, className = '', title, nowrap }: { value: unknown; mono?: boolean; className?: string; title?: boolean; nowrap?: boolean }) {
  const tokens = safeTokens(value);
  const flagged = hasInvisible(value);
  const notNfc = isNotNfc(value);
  return (
    <span className={`${mono ? 'font-mono' : ''} ${nowrap ? 'whitespace-pre' : 'whitespace-pre-wrap break-all'} ${className}`} title={title ? safeText(value) : undefined}>
      {tokens.map((t, i) => (t.kind === 'text' ? t.text : <EscapeMark key={i} token={t} />))}
      {flagged && (
        <span title="Contains invisible, bidi-control, format or control characters (shown as boxed U+XXXX marks)" className="ml-1 inline-flex items-center rounded bg-amber-100 px-1 text-[10px] font-bold text-amber-800 dark:bg-amber-500/20 dark:text-amber-300">
          <AlertTriangle aria-hidden className="mr-0.5 h-3 w-3" />hidden chars
        </span>
      )}
      {notNfc && (
        <span data-testid="fim-not-nfc" title="Not in Unicode NFC form: this text can look identical to different text (e.g. a decomposed accent). Its combining marks are shown as boxed U+XXXX marks; the text was not normalised." className="ml-1 inline-flex items-center rounded bg-violet-100 px-1 text-[10px] font-bold text-violet-800 dark:bg-violet-500/20 dark:text-violet-300">
          not NFC
        </span>
      )}
    </span>
  );
}

/** Same component under a feature-neutral name. */
export const SafeText = RegText;
