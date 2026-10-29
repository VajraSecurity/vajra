import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// crypto.randomUUID() is restricted to secure contexts (HTTPS/localhost) and
// is simply undefined everywhere else — throwing TypeError the moment it's
// called on a plain-HTTP deployment. crypto.getRandomValues() has no such
// restriction (only randomUUID() and subtle do), so it's used here to build
// an equivalent RFC 4122 v4 UUID from the same CSPRNG when randomUUID isn't
// available. This is not a weaker fallback — Math.random() (what this
// replaced project-wide per the Aug 8 2026 CWE-330 fix) would be, since it's
// not cryptographically secure and a predictable id here is a live WS
// routing key the backend trusts to deliver a response to the right socket.
export function secureUUID(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10xx
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// Hoisted out of formatUnixTimestamp: date.toLocaleString(locale, options)
// builds a fresh Intl.DateTimeFormat (the expensive part — locale + pattern
// resolution) on every single call, and this formatter runs once per row in
// the devices and nodes tables. Date.prototype.toLocaleString derives its
// formatter with ToDateTimeOptions(options, "any", "all") while the
// Intl.DateTimeFormat constructor uses ("any", "date"); the two differ only
// when no date/time component is requested, and every component below is
// explicit, so the resolved options — and therefore the output string — are
// byte-identical.
const UNIX_TIMESTAMP_FORMATTER = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
})

export function formatUnixTimestamp(timestamp: string | number) {
  if (!timestamp) return 'N/A'
  const date = new Date(parseInt(timestamp.toString()) * 1000)
  // NOT interchangeable on an invalid date: toLocaleString() returns the
  // literal string 'Invalid Date', whereas Intl.DateTimeFormat#format()
  // throws RangeError. Guard explicitly so hoisting stays behaviour-preserving
  // for non-numeric/out-of-range input (e.g. parseInt('abc') -> NaN).
  if (Number.isNaN(date.getTime())) return 'Invalid Date'
  return UNIX_TIMESTAMP_FORMATTER.format(date)
}
