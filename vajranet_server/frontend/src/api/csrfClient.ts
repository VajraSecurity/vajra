/**
 * Browser half of double-submit CSRF used with:
 * - Token cookie: setCsrfTokenCookie / renewCSRFToken (backend)
 * - Validation: checkCsrf in checkCSRFToken.ts (backend)
 *
 * Keep VITE_CSRF_COOKIE_NAME and VITE_CSRF_HEADER_NAME aligned with backend
 * CSRF_COOKIE_NAME and CSRF_HEADER_NAME (.env).
 */
const CSRF_COOKIE_NAME =
  (import.meta.env.VITE_CSRF_COOKIE_NAME as string | undefined) || 'XSRF-TOKEN';
const CSRF_HEADER_NAME =
  (import.meta.env.VITE_CSRF_HEADER_NAME as string | undefined) || 'X-XSRF-TOKEN';

function readCookie(name: string): string | null {
  const row = document.cookie
    .split('; ')
    .find((r) => r.startsWith(`${encodeURIComponent(name)}=`) || r.startsWith(`${name}=`));
  if (!row) return null;
  const idx = row.indexOf('=');
  if (idx < 0) return null;
  const v = row.slice(idx + 1);
  try {
    return decodeURIComponent(v) || null;
  } catch {
    return v || null;
  }
}

export function getCsrfTokenFromCookie(): string | null {
  return (
    readCookie(CSRF_COOKIE_NAME) ||
    readCookie('XSRF-TOKEN') ||
    readCookie('CSRF-TOKEN') ||
    readCookie('csrf_token')
  );
}

/** For fetch() POST/PUT/PATCH/DELETE with credentials — same contract as axios interceptor. */
export function csrfHeadersJson(): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const t = getCsrfTokenFromCookie();
  if (t) headers[CSRF_HEADER_NAME] = t;
  return headers;
}

export function isCsrfFailureMessage(message: unknown): boolean {
  return typeof message === 'string' && message.toLowerCase().startsWith('csrf validation failed');
}

/**
 * fetch() wrapper for mutating requests. The backend silently rotates the
 * CSRF cookie whenever it renews a near-expiry access token or a refresh
 * token (see checkJwt.ts tryRenewTokens / rotateRefreshToken) — on
 * whichever request happens to trigger that renewal, not necessarily this
 * one. A sibling request in flight at the same time can read the old CSRF
 * cookie value into its header just before the rotation lands, then get
 * rejected with a 403 once the server compares it against the now-rotated
 * cookie. Retrying once — after the rotated cookie has already been
 * written to document.cookie — self-heals that race instead of surfacing
 * it to the user. A genuine CSRF failure (no session, tampered token) will
 * fail identically on the retry and still propagate.
 */
export async function fetchWithCsrf(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const response = await fetch(input, init);
  if (response.status !== 403) return response;

  let isCsrfFailure = false;
  try {
    const body = await response.clone().json();
    isCsrfFailure = isCsrfFailureMessage(body?.message);
  } catch {
    // Non-JSON or unreadable 403 body — not a CSRF failure we can identify/retry.
  }
  if (!isCsrfFailure) return response;

  return fetch(input, {
    ...init,
    // Fresh values must win over whatever stale headers the caller built
    // this call's init with — they hold the CSRF token that just failed.
    headers: { ...(init.headers as Record<string, string> | undefined), ...csrfHeadersJson() },
  });
}

export { CSRF_COOKIE_NAME, CSRF_HEADER_NAME };
