/**
 * Presentational primitives local to the Burp Suite Assets feature — plays
 * the same small role features/Assets/ui.tsx plays for OpenVAS's Assets tab,
 * but there is far less to it: Burp Suite has only three severity tiers (no
 * "log"/"info" bucket at this level), no identity-confidence concept, and
 * nothing to merge across sources — a "Burp asset" is just a website Burp
 * Suite has scanned.
 */
import { Info } from 'lucide-react';
import type { Tone } from '../VulnerabilityScanner/scannerTokens';
import { SimpleTip } from '../VulnerabilityScanner/scannerUI';

/**
 * Status -> Tone. Duplicated from (not imported off of) BurpsuiteView.tsx's
 * own module-private STATUS_TONE: it's a tiny six-entry map with no shared
 * export to reach into, and this feature's whole point is to look like Burp
 * Suite's own sibling views rather than depend on one of them internally.
 * Keep in sync with BurpsuiteView.tsx's STATUS_TONE if Burp ever reports a
 * new status string.
 */
const STATUS_TONE: Record<string, Tone> = {
  succeeded: 'success',
  running: 'info',
  crawling: 'info',
  auditing: 'info',
  paused: 'warning',
  failed: 'danger',
};

// eslint-disable-next-line react-refresh/only-export-components
export const burpStatusTone = (status: string): Tone => STATUS_TONE[status] ?? 'neutral';

/** Same statuses BurpsuiteView.tsx animates with StatusPill's `pulse`. */
// eslint-disable-next-line react-refresh/only-export-components
export const isBurpStatusActive = (status: string): boolean => (
  status === 'running' || status === 'crawling' || status === 'auditing'
);

/**
 * The exact "shadow-sm ring-1 bg-white" chip look BurpsuiteView.tsx's own
 * scan table already uses for its High/Med/Low pills — reproduced verbatim
 * (rather than scannerUI.tsx's generic SeverityBadge/SeverityPill) so this
 * feature's severity chips read as identical to its sibling's, not merely similar.
 */
export function IssueSeverityChips({ high, medium, low }: { high: number; medium: number; low: number }) {
  if (high === 0 && medium === 0 && low === 0) {
    return <span className="text-slate-400">None</span>;
  }
  return (
    <div className="flex flex-wrap gap-1.5 text-xs">
      {high > 0 && (
        <span className="px-2 py-0.5 bg-white ring-1 ring-red-200 text-red-700 rounded-md font-semibold shadow-sm">High {high}</span>
      )}
      {medium > 0 && (
        <span className="px-2 py-0.5 bg-white ring-1 ring-orange-200 text-orange-700 rounded-md font-semibold shadow-sm">Med {medium}</span>
      )}
      {low > 0 && (
        <span className="px-2 py-0.5 bg-white ring-1 ring-yellow-200 text-yellow-700 rounded-md font-semibold shadow-sm">Low {low}</span>
      )}
    </div>
  );
}

/**
 * Plain locale date+time string, exactly `new Date(iso).toLocaleString()` —
 * matching what BurpsuiteView.tsx and BurpsuiteSettings.tsx already call
 * inline for every one of their own timestamps, rather than Assets/ui.tsx's
 * `Intl.DateTimeFormat(dateStyle: 'medium', timeStyle: 'short')` convention,
 * which belongs to OpenVAS's Assets tab. Kept as a one-line helper purely to
 * avoid repeating the null/invalid-date guard at every call site.
 */
// eslint-disable-next-line react-refresh/only-export-components
export const formatBurpTimestamp = (iso: string | null | undefined): string => {
  if (!iso) return '—';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
};

/**
 * Header-level "what is this and how is it computed" explainer for the Burp
 * Suite Assets list — the sibling of features/Assets/ui.tsx's AssetsHelpTip,
 * but for a much simpler model: no identity matching, no confidence score,
 * nothing to merge. Uses the same shared SimpleTip (scannerUI.tsx) as OpenVAS
 * Assets' own header tooltip, not the Base UI Tooltip primitive — see
 * SimpleTip's own comment for why.
 */
export function BurpsuiteAssetsHelpTip() {
  return (
    <SimpleTip
      align="right"
      panelClassName="w-80"
      trigger={
        <button
          type="button"
          aria-label="How the Burp Suite Assets list works"
          className="inline-flex size-6 shrink-0 items-center justify-center rounded-full text-white/80 transition-colors hover:bg-white/15 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40"
        >
          <Info className="size-4" />
        </button>
      }
    >
      <p>
        Groups every Burp Suite scan by the website it targeted, so re-scanning the same site
        shows up as one row with its full history, not a new one each time.
      </p>
      <p className="mt-2.5 font-semibold text-white">How a website is identified:</p>
      <p className="mt-1">
        The scanned URL is reduced to just its host (and port, if not the default for
        http/https) — scheme, a leading &ldquo;www.&rdquo;, and any path or query string are
        stripped. <span className="font-semibold">https://www.example.com/login?x=1</span> and{' '}
        <span className="font-semibold">http://example.com/</span> are the same asset,
        {' '}<span className="font-semibold">example.com</span>; a different subdomain or port
        (<span className="font-semibold">etender.example.com</span>,{' '}
        <span className="font-semibold">example.com:8080</span>) is a different one.
      </p>
      <p className="mt-2.5 text-white/70">
        High/Medium/Low counts shown are from that site&rsquo;s most recent scan, not summed
        across every scan it&rsquo;s ever had. Click any row for its full scan history.
      </p>
    </SimpleTip>
  );
}
