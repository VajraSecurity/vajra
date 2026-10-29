import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { act, cleanup, renderHook } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { ReactNode } from 'react';
import { server } from '../../msw/server';
import { AuthStatusProvider } from '@/context/AuthStatusContext';
import { useAuthStatus } from '@/context/useAuthStatus';
import { ToastProvider } from '@/context/ToastContext';

// Matched with a wildcard origin (rather than a hardcoded `http://localhost:4000`)
// so the test is independent of whatever VITE_API_BASE_URL resolves to locally.
const STATUS_URL = '*/api/auth/status';

function makeWrapper(pollIntervalMs: number) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <ToastProvider>
        <AuthStatusProvider pollIntervalMs={pollIntervalMs}>{children}</AuthStatusProvider>
      </ToastProvider>
    );
  };
}

// Lets pending microtasks (the mocked network round trip through axios/MSW)
// drain under fake timers without asserting on any particular real delay.
async function flush() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
}

async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

describe('AuthStatusContext', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it('fetches auth status on mount and exposes the resolved isValid/loading state', async () => {
    server.use(
      http.get(STATUS_URL, () =>
        HttpResponse.json({ isValid: true, forcePasswordChange: false }),
      ),
    );

    const { result } = renderHook(() => useAuthStatus(), { wrapper: makeWrapper(30000) });

    expect(result.current.loading).toBe(true);

    await flush();

    expect(result.current.isValid).toBe(true);
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('exposes forcePasswordChange as reported by the status endpoint', async () => {
    server.use(
      http.get(STATUS_URL, () =>
        HttpResponse.json({ isValid: true, forcePasswordChange: true }),
      ),
    );

    const { result } = renderHook(() => useAuthStatus(), { wrapper: makeWrapper(30000) });
    await flush();

    expect(result.current.forcePasswordChange).toBe(true);
  });

  it('polls the status endpoint again once pollIntervalMs elapses and updates state from the new response', async () => {
    let callCount = 0;
    server.use(
      http.get(STATUS_URL, () => {
        callCount += 1;
        return HttpResponse.json({ isValid: callCount === 1, forcePasswordChange: false });
      }),
    );

    const { result } = renderHook(() => useAuthStatus(), { wrapper: makeWrapper(1000) });
    await flush();

    expect(callCount).toBe(1);
    expect(result.current.isValid).toBe(true);

    await advance(1000);

    expect(callCount).toBe(2);
    expect(result.current.isValid).toBe(false);
  });

  it('does not re-fetch before pollIntervalMs has elapsed', async () => {
    let callCount = 0;
    server.use(
      http.get(STATUS_URL, () => {
        callCount += 1;
        return HttpResponse.json({ isValid: true, forcePasswordChange: false });
      }),
    );

    renderHook(() => useAuthStatus(), { wrapper: makeWrapper(5000) });
    await flush();
    expect(callCount).toBe(1);

    await advance(4999);

    expect(callCount).toBe(1);
  });

  it('delays the next poll past a full pollIntervalMs (rather than firing immediately) after a 429 response', async () => {
    let callCount = 0;
    server.use(
      http.get(STATUS_URL, () => {
        callCount += 1;
        // First call (initial mount) succeeds; second call (first poll tick) is rate limited.
        if (callCount === 2) {
          return new HttpResponse(null, { status: 429 });
        }
        return HttpResponse.json({ isValid: true, forcePasswordChange: false });
      }),
    );

    const { result } = renderHook(() => useAuthStatus(), { wrapper: makeWrapper(1000) });
    await flush();
    expect(callCount).toBe(1);

    // t=1000: interval tick fires the poll, which is rate limited.
    await advance(1000);
    expect(callCount).toBe(2);
    expect(result.current.error).toBe('Rate limited while checking session');
    // A 429 must not flip a previously-valid session to invalid.
    expect(result.current.isValid).toBe(true);

    // t=2000: this is exactly one more normal interval after the 429 (the cadence
    // a healthy poll would use), but backoff must suppress firing here.
    await advance(1000);
    expect(callCount).toBe(2);

    // Backoff for a first 429 is 2000ms, scheduled from the t=2000 interval tick,
    // so the retry should not have fired yet at t=3000.
    await advance(1000);
    expect(callCount).toBe(2);

    // t=4000: the 2000ms backoff timer (armed at t=2000) elapses and retries.
    await advance(1000);
    expect(callCount).toBe(3);
  });

  it('re-polls immediately when an "auth-change" window event is dispatched', async () => {
    let callCount = 0;
    server.use(
      http.get(STATUS_URL, () => {
        callCount += 1;
        return HttpResponse.json({
          isValid: true,
          forcePasswordChange: callCount >= 2,
        });
      }),
    );

    const { result } = renderHook(() => useAuthStatus(), { wrapper: makeWrapper(30000) });
    await flush();

    expect(callCount).toBe(1);
    expect(result.current.forcePasswordChange).toBe(false);

    await act(async () => {
      window.dispatchEvent(new Event('auth-change'));
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(callCount).toBe(2);
    expect(result.current.forcePasswordChange).toBe(true);
  });
});
