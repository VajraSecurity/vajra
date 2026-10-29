import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';

// axiosInstance.ts imports `clearAuthData` from '../services/auth' (relative from src/api/).
// `@/services/auth` resolves to the same physical module (src/services/auth.ts), so mocking
// via the alias intercepts the same import the source under test uses.
const clearAuthDataMock = vi.fn();
vi.mock('@/services/auth', () => ({
  clearAuthData: (...args: unknown[]) => clearAuthDataMock(...args),
}));

// Imported after the mock so the mocked `clearAuthData` is wired into the interceptor.
const { default: api } = await import('@/api/axiosInstance');

function setCookie(name: string, value: string) {
  document.cookie = `${name}=${value}; path=/`;
}

function expireCookie(name: string) {
  document.cookie = `${name}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

describe('axiosInstance', () => {
  beforeEach(() => {
    clearAuthDataMock.mockClear();
    expireCookie('XSRF-TOKEN');
    // jsdom's `window.location` properties are non-configurable, so `vi.spyOn(window.location,
    // 'assign')` throws "Cannot redefine property". Replace the whole `location` object instead.
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, assign: vi.fn() },
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('CSRF request interceptor', () => {
    it('adds the CSRF header on a POST request when the CSRF cookie is present', async () => {
      setCookie('XSRF-TOKEN', 'csrf-token-abc');
      let capturedHeader: string | null = null;
      server.use(
        http.post(`*/api/csrf-echo`, ({ request }) => {
          capturedHeader = request.headers.get('x-xsrf-token');
          return HttpResponse.json({ ok: true });
        }),
      );

      await api.post('/csrf-echo', {});

      expect(capturedHeader).toBe('csrf-token-abc');
    });

    it.each(['put', 'patch', 'delete'] as const)(
      'adds the CSRF header on a %s request when the CSRF cookie is present',
      async (method) => {
        setCookie('XSRF-TOKEN', 'csrf-token-xyz');
        let capturedHeader: string | null = null;
        server.use(
          http[method](`*/api/csrf-echo-${method}`, ({ request }) => {
            capturedHeader = request.headers.get('x-xsrf-token');
            return HttpResponse.json({ ok: true });
          }),
        );

        await api[method]('/csrf-echo-' + method, {});

        expect(capturedHeader).toBe('csrf-token-xyz');
      },
    );

    it('does not add the CSRF header on a GET request even when the CSRF cookie is present', async () => {
      setCookie('XSRF-TOKEN', 'csrf-token-abc');
      let capturedHeader: string | null | undefined;
      server.use(
        http.get(`*/api/csrf-echo-get`, ({ request }) => {
          capturedHeader = request.headers.get('x-xsrf-token');
          return HttpResponse.json({ ok: true });
        }),
      );

      await api.get('/csrf-echo-get');

      expect(capturedHeader).toBeNull();
    });

    it('does not add the CSRF header on a POST request when no CSRF cookie is present', async () => {
      let capturedHeader: string | null | undefined;
      server.use(
        http.post(`*/api/csrf-echo-nocookie`, ({ request }) => {
          capturedHeader = request.headers.get('x-xsrf-token');
          return HttpResponse.json({ ok: true });
        }),
      );

      await api.post('/csrf-echo-nocookie', {});

      expect(capturedHeader).toBeNull();
    });
  });

  describe('response interceptor: forced logout signal', () => {
    it('clears auth data and redirects to /login on a 401 whose message includes "session invalidated"', async () => {
      server.use(
        http.get(`*/api/protected-a`, () =>
          HttpResponse.json({ message: 'Session invalidated' }, { status: 401 }),
        ),
      );

      vi.useFakeTimers();
      await expect(api.get('/protected-a')).rejects.toBeTruthy();

      expect(clearAuthDataMock).toHaveBeenCalledTimes(1);
      // The redirect is deliberately deferred (window.setTimeout, 300ms) so a
      // toast notification has a moment to mount before navigation tears
      // down the page — advance past that before asserting.
      await vi.advanceTimersByTimeAsync(350);
      expect(window.location.assign).toHaveBeenCalledWith('/login');
    });

    it('clears auth data and redirects to /login on a 403 whose message includes "suspend"', async () => {
      server.use(
        http.get(`*/api/protected-b`, () =>
          HttpResponse.json({ message: 'Your account has been suspended' }, { status: 403 }),
        ),
      );

      vi.useFakeTimers();
      await expect(api.get('/protected-b')).rejects.toBeTruthy();

      expect(clearAuthDataMock).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(350);
      expect(window.location.assign).toHaveBeenCalledWith('/login');
    });

    it('does not clear auth data or redirect on a plain 401 without a suspend/session-invalidated message', async () => {
      server.use(
        http.get(`*/api/protected-c`, () =>
          HttpResponse.json({ message: 'Unauthorized' }, { status: 401 }),
        ),
      );

      vi.useFakeTimers();
      await expect(api.get('/protected-c')).rejects.toBeTruthy();

      expect(clearAuthDataMock).not.toHaveBeenCalled();
      expect(window.location.assign).not.toHaveBeenCalled();
      // A plain 401 still schedules the module-level auth-change debounce
      // timer internally. Flush it before the test ends so it fires (and
      // resets that internal state) here under fake time instead of leaking
      // a live real-timer callback into a later test.
      await vi.advanceTimersByTimeAsync(100);
    });
  });

  describe('response interceptor: auth-change dispatch on generic 401', () => {
    it('dispatches a (debounced) auth-change event for a 401 on a non-boundary endpoint', async () => {
      server.use(
        http.get(`*/api/some-protected-resource`, () =>
          HttpResponse.json({ message: 'Unauthorized' }, { status: 401 }),
        ),
      );
      const authChangeHandler = vi.fn();
      window.addEventListener('auth-change', authChangeHandler);

      vi.useFakeTimers();
      await expect(api.get('/some-protected-resource')).rejects.toBeTruthy();
      // The handler coalesces bursts of 401s into one event fired after 80ms.
      await vi.advanceTimersByTimeAsync(200);

      expect(authChangeHandler).toHaveBeenCalledTimes(1);
      window.removeEventListener('auth-change', authChangeHandler);
    });

    it.each([
      ['/auth/status', '/api/auth/status'],
      ['/auth/login', '/api/auth/login'],
      ['/auth/logout', '/api/auth/logout'],
      ['/auth/profile/verify-password', '/api/auth/profile/verify-password'],
      ['/auth/mfa/verify', '/api/auth/mfa/verify'],
    ])(
      'does not dispatch auth-change for a 401 on the auth-boundary endpoint %s',
      async (requestPath, mswPath) => {
        server.use(
          http.get(`*${mswPath}`, () =>
            HttpResponse.json({ message: 'Unauthorized' }, { status: 401 }),
          ),
        );
        const authChangeHandler = vi.fn();
        window.addEventListener('auth-change', authChangeHandler);

        vi.useFakeTimers();
        await expect(api.get(requestPath)).rejects.toBeTruthy();
        await vi.advanceTimersByTimeAsync(200);

        expect(authChangeHandler).not.toHaveBeenCalled();
        window.removeEventListener('auth-change', authChangeHandler);
      },
    );
  });
});
