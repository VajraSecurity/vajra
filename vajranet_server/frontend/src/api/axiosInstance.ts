import axios from 'axios';
import { CSRF_HEADER_NAME, getCsrfTokenFromCookie, isCsrfFailureMessage } from './csrfClient';
import { clearAuthData } from '../services/auth';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000';

const api = axios.create({
    baseURL: `${API_BASE_URL}/api`,
    withCredentials: true,
});

// Request interceptor: header must match cookie set by backend (renewCSRFToken / checkCSRFToken)
api.interceptors.request.use(
    (config) => {
        if (['post', 'put', 'patch', 'delete'].includes(config.method?.toLowerCase() || '')) {
            const xsrfToken = getCsrfTokenFromCookie();
            if (xsrfToken) {
                // Axios may provide `headers` as undefined depending on call-site.
                // Ensure it's always an object before assignment.
                config.headers = config.headers ?? {};
                config.headers[CSRF_HEADER_NAME] = xsrfToken;
            }
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// Coalesce many parallel 401s (e.g. rate limits or session transitions) into one auth-change.
let authChangeFlushTimer: ReturnType<typeof setTimeout> | null = null;
const scheduleAuthChangeFromUnauthorized = () => {
    if (authChangeFlushTimer != null) return;
    authChangeFlushTimer = window.setTimeout(() => {
        authChangeFlushTimer = null;
        window.dispatchEvent(new Event('auth-change'));
    }, 80);
};

// This module is plain (not a React component/hook), so it can't call
// useToast() directly. Mirror the 'auth-change' pattern above: dispatch a
// DOM CustomEvent that ToastProvider (mounted near the app root) listens for
// and turns into a real toast.
export const APP_TOAST_EVENT_NAME = 'app-toast';

export interface AppToastEventDetail {
    message: string;
    type?: 'success' | 'error' | 'info' | 'warning';
}

const dispatchAppToast = (detail: AppToastEventDetail) => {
    window.dispatchEvent(new CustomEvent<AppToastEventDetail>(APP_TOAST_EVENT_NAME, { detail }));
};

// Rate limiting (see backend/src/middleware/rateLimiters.ts) is applied
// per-user/IP across the whole API, not per page, so this has to be
// surfaced the same way regardless of which screen triggered it. Same
// cross-module-notification pattern as APP_TOAST_EVENT_NAME above:
// RateLimitProvider (mounted once near the app root) listens for this and
// every page picks up the resulting banner/countdown for free.
export const RATE_LIMIT_EVENT_NAME = 'app-rate-limited';

export interface RateLimitEventDetail {
    /** Seconds until the backend will accept requests again (from the Retry-After header). */
    retryAfterSeconds: number;
}

// Every rate limiter in rateLimiters.ts sets standardHeaders (draft-6), which
// includes Retry-After in seconds whenever a request is actually over limit.
// Fall back to the shortest configured window (60s) on the rare chance it's missing.
const DEFAULT_RATE_LIMIT_RETRY_SECONDS = 60;

const dispatchRateLimited = (error: unknown) => {
    const err = error as ResponseErrorLike & { response?: { headers?: Record<string, string> } };
    const header = err?.response?.headers?.['retry-after'] ?? err?.response?.headers?.['Retry-After'];
    const parsed = header ? parseInt(header, 10) : NaN;
    const retryAfterSeconds = Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_RATE_LIMIT_RETRY_SECONDS;
    window.dispatchEvent(new CustomEvent<RateLimitEventDetail>(RATE_LIMIT_EVENT_NAME, { detail: { retryAfterSeconds } }));
};

const normalizeRequestUrl = (rawUrl: unknown): string => {
    if (typeof rawUrl !== 'string') return '';
    try {
        return new URL(rawUrl, API_BASE_URL).pathname.toLowerCase();
    } catch {
        return rawUrl.toLowerCase();
    }
};

const isAuthBoundaryEndpoint = (path: string): boolean => {
    // These endpoints are already the source of truth for auth transitions.
    // Emitting auth-change from their own 401 responses creates self-triggering loops.
    return (
        path.endsWith('/api/auth/status') || path.endsWith('/auth/status') ||
        path.endsWith('/api/auth/login') || path.endsWith('/auth/login') ||
        path.endsWith('/api/auth/logout') || path.endsWith('/auth/logout') ||
        path.endsWith('/api/auth/profile/verify-password') || path.endsWith('/auth/profile/verify-password') ||
        path.includes('/auth/mfa')
    );
};

interface ResponseErrorLike {
    response?: {
        status?: number;
        data?: { message?: string };
    };
}

const shouldForceLogoutAndRedirect = (error: unknown): boolean => {
    const err = error as ResponseErrorLike;
    const status = Number(err?.response?.status);
    if (status !== 401 && status !== 403) return false;

    const message = String(err?.response?.data?.message || '').toLowerCase();
    return message.includes('suspend') || message.includes('session invalidated');
};

// Backend now grants a short grace window on its own (see checkJwt.ts /
// checkCSRFToken.ts) that absorbs most instances of this race server-side.
// This retry stays as a second line of defense: it also covers the rare
// case of a genuinely expired grace window (e.g. an unusually long queuing
// delay), and callers that reach this interceptor either way get a seamless
// retry instead of a surfaced error.
const isCsrfMismatch = (error: unknown): boolean => {
    const err = error as ResponseErrorLike;
    return Number(err?.response?.status) === 403 && isCsrfFailureMessage(err?.response?.data?.message);
};

// Response interceptor for error handling
api.interceptors.response.use(
    (response) => response,
    (error) => {
        const config = error?.config as (typeof error.config & { _csrfRetried?: boolean }) | undefined;
        if (config && !config._csrfRetried && isCsrfMismatch(error)) {
            const freshToken = getCsrfTokenFromCookie();
            if (freshToken) {
                config._csrfRetried = true;
                config.headers = { ...(config.headers ?? {}), [CSRF_HEADER_NAME]: freshToken };
                return api(config);
            }
        }

        if (shouldForceLogoutAndRedirect(error)) {
            clearAuthData();
            const reqPath = normalizeRequestUrl(error?.config?.url);
            // Auth-boundary endpoints (esp. /auth/status, polled every 30s) are
            // already the source of truth for auth transitions — AuthStatusContext's
            // own catch handles the toast + state-driven redirect for their 401s.
            // Forcing a second toast+redirect here would duplicate it with different copy.
            if (!isAuthBoundaryEndpoint(reqPath) && window.location.pathname !== '/login') {
                // Let the user know why they're being bounced before the hard
                // redirect wipes the page — otherwise this looks like a bug.
                dispatchAppToast({
                    message: 'Your session has ended. Please log in again.',
                    type: 'warning',
                });
                // Brief delay so the toast has a moment to mount/render before
                // navigation tears down the page. Kept short so the
                // security-relevant redirect isn't meaningfully delayed.
                window.setTimeout(() => {
                    window.location.assign('/login');
                }, 300);
            }
            return Promise.reject(error);
        }

        if (error.response?.status === 401) {
            const reqPath = normalizeRequestUrl(error?.config?.url);
            if (isAuthBoundaryEndpoint(reqPath)) {
                return Promise.reject(error);
            }
            // Never try to clear httpOnly cookies client-side.
            // Avoid hard redirects on arbitrary 401s (can happen during background fetches),
            // and let route guards + session status checks decide navigation.
            scheduleAuthChangeFromUnauthorized();
        }

        if (error.response?.status === 429) {
            dispatchRateLimited(error);
        }

        return Promise.reject(error);
    }
);

export default api;