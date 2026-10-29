/**
 * Strips a caught error down to only the fields safe to write to logs.
 *
 * Several outbound integrations in this codebase (Burp Suite Enterprise,
 * AbuseIPDB, VirusTotal, the manual reputation server, Nessus, OpenVAS/GMP)
 * authenticate with an API key/token/username+password embedded in a request
 * header, URL query string, or POST body. Axios attaches the full request
 * config — including `config.headers`, `config.url`, and `config.data` — to
 * every AxiosError it throws, and the raw `ClientRequest`/socket under
 * `err.request` even carries the literal outgoing header string. pino's
 * default (unconfigured) serializer walks the *entire* object handed to it,
 * so logging a raw caught error via `logger.x({ err }, ...)` leaks whatever
 * plaintext credential that request carried: the value is printed verbatim
 * inside `err.config.headers`, and again inside `err.request._header`.
 *
 * pino's path-based `redact` option (see utils/logger.ts's REDACT_PATHS)
 * can't cover this case generically: the sensitive value's location shifts
 * per integration (header name, URL query param, or POST body field all
 * differ per provider), so there is no fixed path to redact.
 *
 * This allowlists only the fields that carry real diagnostic value and never
 * carry credentials: the error message, a network/HTTP error code, and the
 * upstream HTTP status/statusText when the error came from a response.
 *
 * Only ever change what gets logged with this — never what gets thrown,
 * returned to a caller, or sent to a client; those must keep seeing the
 * original error.
 */
export function sanitizeAxiosError(
  err: unknown,
): { message?: string; code?: string; status?: number; statusText?: string } | unknown {
  if (!err || typeof err !== 'object') return err;
  const e = err as { message?: string; code?: string; response?: { status?: number; statusText?: string } };
  return { message: e.message, code: e.code, status: e.response?.status, statusText: e.response?.statusText };
}
