import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { isAxiosError } from 'axios';
import { checkAuthStatus } from '../api/api';
import { clearAuthData } from '../services/auth';
import { useToast } from './useToast';
import { AuthStatusContext } from './useAuthStatus';
import type { AuthStatusContextType, AuthStatusState } from './useAuthStatus';

const DEFAULT_STATE: AuthStatusState = {
  isValid: false,
  forcePasswordChange: false,
  loading: true,
  error: null,
};

/**
 * Structural reuse for the auth-status poll — same idea as `reuseUnchanged` in
 * hooks/useLiveWebSocket.ts, applied to the /auth/status tick.
 *
 * The poll below runs every `pollIntervalMs` (30s) for the whole session and
 * its overwhelmingly common outcome is "still logged in, nothing changed".
 * React's bailout compares with Object.is, which a fresh object literal never
 * satisfies, so handing `setState` one on every tick re-renders this provider,
 * invalidates the `value` useMemo keyed on `state`, and re-renders every
 * useAuthStatus() consumer — including the Alerts page, which rebuilds its
 * whole table and detail panel.
 *
 * Returning the previous object when all four fields are equal makes the
 * bailout hold. Purely an identity optimisation: the state value is the same
 * either way, and a tick carrying a real change still produces a new object.
 */
const sameAuthState = (a: AuthStatusState, b: AuthStatusState): boolean =>
  a.isValid === b.isValid &&
  a.forcePasswordChange === b.forcePasswordChange &&
  a.loading === b.loading &&
  a.error === b.error;

const MANUAL_LOGOUT_INTENT_KEY = 'manual_logout_intent_ts';
const MANUAL_LOGOUT_INTENT_WINDOW_MS = 2 * 60 * 1000; // 2 minutes

export const AuthStatusProvider: React.FC<{ children: ReactNode; pollIntervalMs?: number }> = ({
  children,
  pollIntervalMs = 30000,
}) => {
  const [state, setState] = useState<AuthStatusState>(DEFAULT_STATE);
  const { showToast } = useToast();

  const inFlightRef = useRef<Promise<void> | null>(null);
  const backoffMsRef = useRef<number>(0);
  const backoffTimerRef = useRef<number | null>(null);
  const prevIsValidRef = useRef<boolean>(false);
  const sessionEndedToastLockRef = useRef<number>(0);
  const lastAuthChangeRefetchAtRef = useRef<number>(0);

  const applyBackoff = useCallback((ms: number) => {
    backoffMsRef.current = ms;
    if (backoffTimerRef.current != null) {
      window.clearTimeout(backoffTimerRef.current);
    }
  }, []);

  const maybeToastSessionEnded = useCallback(() => {
    // If the user intentionally logged out, don't show a confusing
    // "Session expired" message.
    try {
      const tsStr = sessionStorage.getItem(MANUAL_LOGOUT_INTENT_KEY);
      const ts = tsStr ? Number(tsStr) : NaN;
      if (Number.isFinite(ts) && Date.now() - ts < MANUAL_LOGOUT_INTENT_WINDOW_MS) {
        sessionStorage.removeItem(MANUAL_LOGOUT_INTENT_KEY);
        return;
      }
      if (Number.isFinite(ts)) {
        sessionStorage.removeItem(MANUAL_LOGOUT_INTENT_KEY);
      }
    } catch {
      // ignore (e.g. storage disabled)
    }

    // Prevent toast spam if multiple checks fail close together.
    const now = Date.now();
    if (now - sessionEndedToastLockRef.current < 10_000) return;
    sessionEndedToastLockRef.current = now;
    showToast('Session expired. Please login again.', 'warning');
  }, [showToast]);

  const refetch = useCallback(async (opts?: { silent?: boolean }) => {
    const silent = Boolean(opts?.silent);
    if (inFlightRef.current) return inFlightRef.current;

    const run = (async () => {
      try {
        if (!silent) {
          // Important: set loading during user-triggered auth changes (logout/login)
          // so route guards don't redirect based on stale `isValid`.
          setState((prev) => {
            const next = { ...prev, loading: true, error: null };
            return sameAuthState(prev, next) ? prev : next;
          });
        }

        const res = await checkAuthStatus();
        const nextIsValid = Boolean(res?.isValid);
        const wasValid = prevIsValidRef.current;
        prevIsValidRef.current = nextIsValid;

        if (wasValid && !nextIsValid) {
          maybeToastSessionEnded();
        }

        setState((prev) => {
          const next: AuthStatusState = {
            isValid: nextIsValid,
            forcePasswordChange: Boolean(res?.forcePasswordChange),
            loading: false,
            error: null,
          };
          return sameAuthState(prev, next) ? prev : next;
        });
        applyBackoff(0);
      } catch (err) {
        const status = isAxiosError(err) ? err.response?.status : undefined;

        // Hard unauth: only for explicit auth failures.
        if (status === 401 || status === 403) {
          const wasValid = prevIsValidRef.current;
          prevIsValidRef.current = false;
          if (wasValid) {
            maybeToastSessionEnded();
            // This is the source-of-truth path for a routine session expiry
            // (axiosInstance.ts deliberately skips its own force-logout
            // handling for /auth/status — see isAuthBoundaryEndpoint — so it
            // never clears this cache either). Without this, the cached
            // `user`/`userSettings` profile fields sit in localStorage
            // indefinitely after an idle timeout, readable by the next
            // person on a shared/kiosk machine before anyone logs back in.
            clearAuthData();
          }
          setState((prev) => {
            const next: AuthStatusState = {
              isValid: false,
              forcePasswordChange: false,
              loading: false,
              error: null,
            };
            return sameAuthState(prev, next) ? prev : next;
          });
          applyBackoff(0);
          return;
        }

        // Rate limit / transient failures: do not flip auth to false.
        if (status === 429) {
          setState((prev) => {
            const next = {
              ...prev,
              // Keep loading=true when we don't yet know auth status to avoid
              // `ProtectedRoute` redirecting to `/login` during initial checks.
              loading: prev.isValid ? false : true,
              error: 'Rate limited while checking session',
            };
            return sameAuthState(prev, next) ? prev : next;
          });
          const nextBackoff = Math.min(Math.max(backoffMsRef.current || 1000, 1000) * 2, 60000);
          applyBackoff(nextBackoff);
          return;
        }

        setState((prev) => {
          const next = {
            ...prev,
            loading: false,
            error: err instanceof Error ? err.message : 'Auth status check failed',
          };
          return sameAuthState(prev, next) ? prev : next;
        });
      } finally {
        inFlightRef.current = null;
      }
    })();

    inFlightRef.current = run;
    return run;
  }, [applyBackoff, maybeToastSessionEnded]);

  useEffect(() => {
    // Initial check on mount.
    refetch();
  }, [refetch]);

  useEffect(() => {
    const handleAuthChange = () => {
      const now = Date.now();
      // Ignore accidental event bursts from many listeners firing at once.
      if (now - lastAuthChangeRefetchAtRef.current < 250) return;
      lastAuthChangeRefetchAtRef.current = now;
      // Avoid storms by deduping in-flight calls.
      refetch();
    };
    window.addEventListener('auth-change', handleAuthChange);
    return () => window.removeEventListener('auth-change', handleAuthChange);
  }, [refetch]);

  useEffect(() => {
    const tick = () => {
      // Poll silently to avoid spinners/flicker in route guards.
      refetch({ silent: true });
    };

    const id = window.setInterval(() => {
      if (backoffMsRef.current > 0) {
        // During backoff, schedule a one-off retry and skip interval tick.
        if (backoffTimerRef.current == null) {
          backoffTimerRef.current = window.setTimeout(() => {
            backoffTimerRef.current = null;
            tick();
          }, backoffMsRef.current);
        }
        return;
      }
      tick();
    }, pollIntervalMs);

    return () => {
      window.clearInterval(id);
      if (backoffTimerRef.current != null) {
        window.clearTimeout(backoffTimerRef.current);
        backoffTimerRef.current = null;
      }
    };
  }, [pollIntervalMs, refetch]);

  const value = useMemo<AuthStatusContextType>(
    () => ({
      ...state,
      refetch,
    }),
    [state, refetch],
  );

  return <AuthStatusContext.Provider value={value}>{children}</AuthStatusContext.Provider>;
};
