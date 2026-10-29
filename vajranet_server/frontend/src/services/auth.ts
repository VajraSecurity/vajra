// Utility functions for authentication.
// Important: backend auth is cookie-based; the frontend must not store tokens
// or treat localStorage flags as authentication authority.

// Shape of the client-side cache of the logged-in user's profile, stored in
// localStorage. Mirrors (a subset of) the backend profile response — kept
// loose via the index signature since the cached object is spread/round-
// tripped as-is by several call sites.
export interface StoredUser {
  name?: string;
  email?: string;
  role?: string;
  avatar_id?: number;
  avatar_image?: string | null;
  [key: string]: unknown;
}

// getStoredUser() sits on hot render paths — twice per Sidebar render via
// useAvatar()'s useSyncExternalStore snapshot, plus once per render of
// MobileNavbar, the AI console, the policy library and the CERT-In compliance
// view — and the cached object carries avatar_image, a base64 data URL of up
// to 200KB (updateAvatar MAX_IMAGE_LENGTH). So the parse is worth caching.
//
// Memoised on the raw localStorage string, deliberately not on a change
// event: six writers of the 'user' key dispatch no event at all
// (Sidebar.syncProfileRole, ProtectedRoute.maybeHydrateUser,
// SuperAdminRoute.hydrateRole, MyTeam's ownership transfer,
// Settings.syncProfileMfaState, UpdateProfile's submit), so an
// event-invalidated cache would serve a stale profile after any of them.
// Re-reading the raw string keeps localStorage as the source of truth and
// skips only the parse, so this cannot go stale.
//
// The returned object is shared between callers while the raw string is
// unchanged, so treat it as read-only; no call site mutates it. That stable
// identity is also what lets Sidebar's setUser(getStoredUser()) bail out of a
// redundant re-render.
let cachedUserRaw: string | null = null;
let cachedUser: StoredUser | null = null;

export const getStoredUser = (): StoredUser | null => {
  const userData = localStorage.getItem('user');
  if (!userData) {
    cachedUserRaw = null;
    cachedUser = null;
    return null;
  }
  if (userData === cachedUserRaw) return cachedUser;

  try {
    const parsed = JSON.parse(userData) as StoredUser;
    cachedUserRaw = userData;
    cachedUser = parsed;
    return parsed;
  } catch (error) {
    if (import.meta.env.DEV) {
      console.error('Error parsing user data:', error);
    }
    cachedUserRaw = null;
    cachedUser = null;
    localStorage.removeItem('user');
    return null;
  }
};

// Fields the UI actually reads back out of the cached 'user' object (sidebar
// chrome, role-gated routes/menus, avatar). Everything else on the profile —
// mobile, address, bio, website, linkedin, twitter, company, mfa_enabled — is
// always re-fetched from the cookie-authenticated /auth/profile endpoint by
// whatever screen needs it (Settings, UpdateProfile, MyTeam) and was never
// read back from this cache. Caching it anyway just left real PII sitting in
// plaintext localStorage, readable by any XSS for the life of the session
// (Coverity LOCALSTORAGE_WRITE / CWE-922). Route every write through this so
// the cache can't silently regain fields we've deliberately excluded.
const CACHEABLE_USER_FIELDS = ['id', 'name', 'email', 'role', 'avatar_id', 'avatar_image'] as const;

// Accepts `object` rather than `Record<string, unknown>` so callers can pass
// typed API response shapes (e.g. UserProfile) directly, without those
// interfaces needing an index signature just to satisfy this helper.
export const sanitizeUserForCache = (profile: object | null | undefined): Record<string, unknown> | null | undefined => {
  if (!profile || typeof profile !== 'object') return profile as Record<string, unknown> | null | undefined;
  const source = profile as Record<string, unknown>;
  const picked: Record<string, unknown> = {};
  for (const field of CACHEABLE_USER_FIELDS) {
    if (field in source) picked[field] = source[field];
  }
  return picked;
};

const MANUAL_LOGOUT_INTENT_KEY = 'manual_logout_intent_ts';

/**
 * Mark that the next auth status change is due to an intentional user logout.
 * Used to suppress "Session expired" toasts on manual logout.
 */
export const markManualLogout = (): void => {
  try {
    sessionStorage.setItem(MANUAL_LOGOUT_INTENT_KEY, String(Date.now()));
  } catch {
    // ignore (e.g. storage disabled)
  }
};

export const clearAuthData = (): void => {
  localStorage.removeItem('user');
  localStorage.removeItem('forcePasswordChange');
  localStorage.removeItem('isLoggedIn');
  // Account-scoped cache, not a device preference (mirrors backend MFA state
  // plus notification toggles) — must not survive onto the next user's
  // session on a shared/kiosk machine. See Settings.tsx.
  localStorage.removeItem('userSettings');
  window.dispatchEvent(new Event('auth-change'));
};
