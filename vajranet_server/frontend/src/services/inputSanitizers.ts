export type SanitizeAsciiOptions = {
  /**
   * Allow line breaks (\n and \r). Use for <textarea>.
   * Defaults to false.
   */
  allowNewlines?: boolean;
  /** Allow tab (\t). Defaults to false. */
  allowTabs?: boolean;
  /**
   * Max length after sanitization. If omitted, no extra truncation is applied.
   * (You should still enforce backend limits.)
   */
  maxLen?: number;
  /** Trim leading/trailing whitespace after sanitization. Defaults to false. */
  trim?: boolean;
};

/**
 * Keep only ASCII characters and optionally \n/\r/\t.
 * This rejects emojis and all other non-ASCII Unicode characters.
 *
 * Allowed (default):
 * - space (0x20) through tilde (0x7E)
 * Optional:
 * - \n (0x0A), \r (0x0D) when allowNewlines
 * - \t (0x09) when allowTabs
 */
export function sanitizeAscii(input: string, opts: SanitizeAsciiOptions = {}): string {
  const allowNewlines = opts.allowNewlines === true;
  const allowTabs = opts.allowTabs === true;

  let out = '';
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code >= 0x20 && code <= 0x7e) {
      out += input[i];
      continue;
    }
    if (allowNewlines && (code === 0x0a || code === 0x0d)) {
      out += input[i];
      continue;
    }
    if (allowTabs && code === 0x09) {
      out += input[i];
      continue;
    }
    // drop everything else (including emojis / non-ASCII)
  }

  if (opts.trim) out = out.trim();
  if (typeof opts.maxLen === 'number' && opts.maxLen >= 0) out = out.slice(0, opts.maxLen);
  return out;
}

export function sanitizeAsciiSingleLine(input: string, maxLen?: number, trim: boolean = false): string {
  return sanitizeAscii(input, { maxLen, trim, allowNewlines: false, allowTabs: false });
}

export function sanitizeAsciiMultiLine(input: string, maxLen?: number, trim: boolean = false): string {
  return sanitizeAscii(input, { maxLen, trim, allowNewlines: true, allowTabs: true });
}

