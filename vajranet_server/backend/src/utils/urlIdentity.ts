/**
 * Pure URL -> asset-identity normalization.
 *
 * Burp Suite Enterprise scans one URL at a time (burpsuite_scan_history.target
 * is the raw target string a caller passed to launchBurpsuiteScan), but the
 * same logical web application is very often scanned repeatedly under
 * cosmetically different URLs -- with and without a `www.` label, with and
 * without an explicit default port, over http vs. https, with a different
 * path/query each run. Grouping raw targets into "Burp assets" (see
 * controllers/burpsuiteAssets/) requires collapsing all of those down to one
 * stable key per host, the same way asset identity resolution collapses
 * multiple observations of one machine (see utils/assetIdentity/normalize.ts)
 * -- except here the identity is a hostname[:port], not a device.
 *
 * No database imports, no dependency on anything else in this codebase: this
 * module must stay safely importable from a standalone script (see
 * test/utils/urlIdentity.selftest.ts) with zero risk of transitively pulling
 * in src/index.ts's server-bootstrap IIFE.
 */

/**
 * Normalizes a raw Burp Suite scan target URL down to a stable grouping key:
 * lowercased hostname, a single leading `www.` label stripped, and `:port`
 * included only when it is both present and non-default for the URL's scheme.
 * Scheme, path, query string and fragment are always dropped.
 *
 * Returns `null` for a URL `new URL()` cannot parse, rather than throwing.
 * `launchBurpsuiteScan` already validates target URLs at creation time (see
 * assertAllowedBurpUrl / the scheme check in burpsuiteController.ts), so a
 * malformed value in burpsuite_scan_history.target should be rare in
 * practice -- but the column is free text, not a constrained type, and this
 * function backs a list endpoint that must never 500 because of one bad row.
 *
 * Examples:
 *   https://www.example.com/login?x=1  -> "example.com"
 *   http://example.com:8080/           -> "example.com:8080"
 *   https://EXAMPLE.com:443/           -> "example.com"
 *   https://www2.example.com/          -> "www2.example.com" (not a www label)
 *   https://wwwexample.com/            -> "wwwexample.com"   (not a www label)
 */
export function normalizeBurpTarget(rawUrl: string): string | null {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }

  let host = url.hostname.toLowerCase();

  // Strip exactly one leading "www." label. The length check excludes a bare
  // "www." host with nothing after it (host.slice(4) === '' there) -- that is
  // not "www.example.com" with the label stripped, it is a host that IS
  // literally "www." and stripping would turn it into an empty string.
  if (host.startsWith('www.') && host.length > 'www.'.length) {
    host = host.slice('www.'.length);
  }

  // url.port is '' when the URL had no explicit port (browsers/WHATWG URL
  // also normalize an explicit default port, e.g. ":443" on https, to '' on
  // parse) -- but a caller could still construct one that survives (rare
  // edge cases in some URL implementations), so the default-port check below
  // is a second, explicit guard rather than trusting url.port alone.
  const defaultPort = url.protocol === 'https:' ? '443' : url.protocol === 'http:' ? '80' : null;
  const portSuffix = url.port && url.port !== defaultPort ? `:${url.port}` : '';

  return `${host}${portSuffix}`;
}
