/**
 * Auth / session / profile / MFA API functions
 */

import api from '../axiosInstance';

export interface LoginRequest {
  email: string;
  password: string;
  captcha?: string;
  captchaId?: string;
}

export interface LoginResponse {
  status: 'Success' | 'CaptchaRequired' | 'Fail' | 'MfaRequired' | 'MfaSetupRequired';
  message?: string;
  // Present on some backend responses but never read by any caller today —
  // kept untyped rather than guessing at (and potentially misdocumenting) a shape.
  user?: unknown;
  captcha?: string;
  captchaId?: string;
  mfaToken?: string;
}

export interface RegisterRequest {
  name: string;
  email: string;
  password: string;
  passwordConfirm: string;
  mobile: string;
  role: 'Super Administrator' | 'Group Admin' | 'Viewer';
  countryCode?: string;
}

export interface RegisterResponse {
  status?: 'Success' | 'Fail';
  message?: string;

  // Backend CustomError fields
  errorType?: string;
  errorMessage?: string;
  errorsValidation?: Array<Record<string, string>>;

  // Never read by any caller today — kept untyped rather than guessing at a shape.
  user?: unknown;
}

export interface ProfileRequest {
  company?: string;
  address?: string;
  mobile?: string;
  name?: string;
  email?: string;
}

export interface AuthStatusResponse {
  status?: string;
  isValid: boolean;
  forcePasswordChange?: boolean;
  // Never read by any caller today — kept untyped rather than guessing at a shape.
  user?: unknown;
  message?: string;
  errorType?: string;
}

export interface UserProfile {
  name: string;
  email: string;
  role?: 'Super Administrator' | 'Group Admin' | 'Viewer';
  company?: string;
  mobile?: string;
  address?: string;
  bio?: string;
  website?: string;
  linkedin?: string;
  twitter?: string;
  mfa_enabled?: boolean;
}

export interface ProfileResponse {
  status?: string;
  message?: string;
  errors?: Array<{ [key: string]: string }>;
  // Legacy fallback shape some callers check alongside `data` — same shape as `data`.
  user?: UserProfile;
  success?: boolean;
  data?: UserProfile;
}

/** Minimal shape of an Axios-style rejection, as accessed by this module's
 * catch blocks (`error.response?.data`, `error.message`). */
interface ApiErrorLike {
  response?: { data?: unknown };
  message?: string;
}

/**
 * Login user
 */
export const login = async (data: LoginRequest): Promise<LoginResponse> => {
  try {
    const response = await api.post('/auth/login', data);
    return response.data;
  } catch (error) {
    const err = error as ApiErrorLike;
    // If the server returned a response with error data, return it
    if (err.response?.data) {
      return err.response.data as LoginResponse;
    }
    // Otherwise, throw a generic error
    throw new Error(err.message || 'Network error occurred');
  }
};

export interface MfaBasicResponse {
  status: string;
  message?: string;
}

export interface MfaSetupResponse extends MfaBasicResponse {
  qrCode?: string;
  secret?: string;
  recoveryCodes?: string[];
}

export const setupMfa = async (mfaToken: string): Promise<MfaSetupResponse> => {
  const response = await api.post('/auth/mfa/setup', { mfaToken });
  return response.data;
};

export const verifyMfa = async (mfaToken: string, token: string): Promise<LoginResponse> => {
  try {
    const response = await api.post('/auth/mfa/verify', { mfaToken, token });
    return response.data;
  } catch (error) {
    const err = error as ApiErrorLike;
    if (err.response?.data) return err.response.data as LoginResponse;
    throw new Error(err.message || 'Network error occurred');
  }
};

export const setupMfaSettings = async (): Promise<MfaSetupResponse> => {
  try {
    const response = await api.post('/auth/mfa/setup');
    return response.data;
  } catch (error) {
    const err = error as ApiErrorLike;
    if (err.response?.data) return err.response.data as MfaSetupResponse;
    throw new Error(err.message || 'Network error occurred');
  }
};

export const disableMfaSettings = async (password: string): Promise<MfaBasicResponse> => {
  try {
    const response = await api.post('/auth/mfa/disable', { password });
    return response.data;
  } catch (error) {
    const err = error as ApiErrorLike;
    if (err.response?.data) return err.response.data as MfaBasicResponse;
    throw new Error(err.message || 'Network error occurred');
  }
};

export interface VerifyMfaSettingsRequest {
  token: string;
  securityQuestion1: string;
  securityAnswer1: string;
  securityQuestion2: string;
  securityAnswer2: string;
}

export const verifyMfaSettings = async (data: VerifyMfaSettingsRequest): Promise<MfaBasicResponse> => {
  try {
    const response = await api.post('/auth/mfa/verify-setup', data);
    return response.data;
  } catch (error) {
    const err = error as ApiErrorLike;
    if (err.response?.data) return err.response.data as MfaBasicResponse;
    throw new Error(err.message || 'Network error occurred');
  }
};

export const recoverMfa = async (mfaToken: string, recoveryCode: string): Promise<LoginResponse> => {
  try {
    const response = await api.post('/auth/mfa/recover', { mfaToken, recoveryCode });
    return response.data;
  } catch (error) {
    const err = error as ApiErrorLike;
    if (err.response?.data) return err.response.data as LoginResponse;
    throw new Error(err.message || 'Network error occurred');
  }
};

/**
 * Register new user
 */
export const register = async (data: RegisterRequest): Promise<RegisterResponse> => {
  const response = await api.post('/auth/user_register', data);
  return response.data;
};

/**
 * Check authentication status
 */
export const checkAuthStatus = async (): Promise<AuthStatusResponse> => {
  const response = await api.get('/auth/status');
  return response.data;
};

/**
 * Logout user
 */
export const logout = async (): Promise<void> => {
  await api.post('/auth/logout');
};

/**
 * Logout all devices
 */
export const logoutAllDevices = async (): Promise<void> => {
  await api.post('/auth/logout-all');
};

/**
 * Get user profile
 *
 * In-flight deduped. Loading any authenticated route mounts ProtectedRoute ->
 * SuperAdminRoute -> Layout -> Sidebar in a single commit, and three of those
 * hydrate the cached user from /auth/profile in their mount effect
 * (ProtectedRoute.maybeHydrateUser, SuperAdminRoute.hydrateRole,
 * Sidebar.syncProfileRole); the dashboard route adds a fourth. Without the
 * dedupe that is 2-4 concurrent identical GETs, each returning the whole
 * profile including avatar_image (a base64 data URL of up to 200KB) and each
 * writing the same value back to localStorage.
 *
 * Only the in-flight request is shared: overlapping callers get one promise and
 * the slot is released the moment it settles, so the next call still issues a
 * fresh request. Freshness is therefore unchanged, which matters because
 * SuperAdminRoute depends on a live fetch to notice server-side role
 * revocation. No caller mutates the resolved object, so sharing it is safe, and
 * a rejection propagates to each waiter.
 */
let inFlightProfile: Promise<ProfileResponse> | null = null;

export const getProfile = async (): Promise<ProfileResponse> => {
  if (inFlightProfile) return inFlightProfile;
  const request = api
    .get('/auth/profile')
    .then((response) => response.data as ProfileResponse)
    .finally(() => {
      inFlightProfile = null;
    });
  inFlightProfile = request;
  return request;
};

export const invalidateSessions = async (sessionIds: number[]) => {
  const response = await api.post('/users/sessions/invalidate', { sessionIds });
  return response.data;
};

export const invalidateUserSessions = async (email: string) => {
  const response = await api.post('/users/sessions/invalidate-user', { email });
  return response.data;
};

/**
 * Update user profile
 */
export const updateProfile = async (data: ProfileRequest): Promise<ProfileResponse> => {
  const response = await api.post('/auth/profile/update', data);
  return response.data;
};

/**
 * Update user avatar — built-in avatar id, or 999 plus an image data URL for
 * a custom uploaded photo. Stored on the user profile (works across devices).
 */
export const updateAvatar = async (data: {
  avatarId: number;
  avatarImage?: string;
}): Promise<{ status: string; message: string; data?: { avatar_id: number; avatar_image: string | null } }> => {
  const response = await api.post('/auth/profile/avatar', data);
  return response.data;
};

/**
 * Update user password
 */
export interface UpdatePasswordRequest {
  currentPassword: string;
  newPassword: string;
  newPasswordConfirm: string;
}

export interface UpdatePasswordResponse {
  status: string;
  message: string;
}

export const updatePassword = async (data: UpdatePasswordRequest): Promise<UpdatePasswordResponse> => {
  const response = await api.post('/auth/profile/password-update', data);
  return response.data;
};

export const verifyPassword = async (password: string): Promise<{ status: string; message: string; shell_token?: string }> => {
  const response = await api.post('/auth/profile/verify-password', { password });
  return response.data;
};
