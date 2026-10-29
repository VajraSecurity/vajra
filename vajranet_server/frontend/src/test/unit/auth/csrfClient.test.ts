import { describe, it, expect, afterEach } from 'vitest';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME, csrfHeadersJson, getCsrfTokenFromCookie } from '@/api/csrfClient';

// document.cookie assignments in jsdom add/update individual cookies rather than
// replacing the whole cookie jar, so we track and expire every cookie a test sets.
const cookiesSetInTest: string[] = [];

function setCookie(name: string, value: string) {
  cookiesSetInTest.push(name);
  document.cookie = `${name}=${value}`;
}

afterEach(() => {
  while (cookiesSetInTest.length) {
    const name = cookiesSetInTest.pop() as string;
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  }
});

describe('csrfClient', () => {
  describe('header/cookie name resolution', () => {
    it('resolves the default CSRF cookie name to XSRF-TOKEN', () => {
      expect(CSRF_COOKIE_NAME).toBe('XSRF-TOKEN');
    });

    it('resolves the default CSRF header name to X-XSRF-TOKEN', () => {
      expect(CSRF_HEADER_NAME).toBe('X-XSRF-TOKEN');
    });
  });

  describe('getCsrfTokenFromCookie', () => {
    it('returns null when no CSRF cookie is present', () => {
      expect(getCsrfTokenFromCookie()).toBeNull();
    });

    it('extracts the token when the XSRF-TOKEN cookie is present among other cookies', () => {
      setCookie('foo', 'bar');
      setCookie('XSRF-TOKEN', 'my-csrf-token');
      setCookie('baz', 'qux');

      expect(getCsrfTokenFromCookie()).toBe('my-csrf-token');
    });

    it('falls back to the CSRF-TOKEN cookie when XSRF-TOKEN is absent', () => {
      setCookie('CSRF-TOKEN', 'fallback-token');

      expect(getCsrfTokenFromCookie()).toBe('fallback-token');
    });

    it('falls back to the csrf_token cookie when higher-priority names are absent', () => {
      setCookie('csrf_token', 'lowest-priority-token');

      expect(getCsrfTokenFromCookie()).toBe('lowest-priority-token');
    });

    it('decodes a URL-encoded cookie value', () => {
      setCookie('XSRF-TOKEN', encodeURIComponent('token with spaces & symbols'));

      expect(getCsrfTokenFromCookie()).toBe('token with spaces & symbols');
    });

    it('returns null when the cookie is present but has an empty value', () => {
      setCookie('XSRF-TOKEN', '');

      expect(getCsrfTokenFromCookie()).toBeNull();
    });
  });

  describe('csrfHeadersJson', () => {
    it('always includes a JSON Content-Type header', () => {
      const headers = csrfHeadersJson();

      expect(headers['Content-Type']).toBe('application/json');
    });

    it('includes the CSRF header when a token cookie is present', () => {
      setCookie('XSRF-TOKEN', 'header-json-token');

      const headers = csrfHeadersJson();

      expect(headers[CSRF_HEADER_NAME]).toBe('header-json-token');
    });

    it('omits the CSRF header when no token cookie is present', () => {
      const headers = csrfHeadersJson();

      expect(headers[CSRF_HEADER_NAME]).toBeUndefined();
    });
  });
});
