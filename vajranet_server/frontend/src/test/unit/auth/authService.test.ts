import { describe, it, expect, beforeEach, vi } from 'vitest';
import { clearAuthData, getStoredUser, markManualLogout } from '@/services/auth';

describe('services/auth', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  describe('getStoredUser', () => {
    it('returns null when no user is stored', () => {
      expect(getStoredUser()).toBeNull();
    });

    it('returns the parsed user object when valid JSON is stored', () => {
      const user = { id: 1, email: 'user1@example.com', role: 'Viewer' };
      localStorage.setItem('user', JSON.stringify(user));

      expect(getStoredUser()).toEqual(user);
    });

    it('returns null and clears the stored value when the stored JSON is corrupted', () => {
      const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      localStorage.setItem('user', '{not valid json');

      const result = getStoredUser();

      expect(result).toBeNull();
      expect(localStorage.getItem('user')).toBeNull();
      errorSpy.mockRestore();
    });
  });

  describe('markManualLogout', () => {
    it('sets a numeric manual-logout-intent timestamp in sessionStorage', () => {
      const before = Date.now();
      markManualLogout();
      const after = Date.now();

      const stored = sessionStorage.getItem('manual_logout_intent_ts');
      expect(stored).not.toBeNull();
      const ts = Number(stored);
      expect(ts).toBeGreaterThanOrEqual(before);
      expect(ts).toBeLessThanOrEqual(after);
    });
  });

  describe('clearAuthData', () => {
    it('removes the user, forcePasswordChange, and isLoggedIn keys from localStorage', () => {
      localStorage.setItem('user', JSON.stringify({ id: 1 }));
      localStorage.setItem('forcePasswordChange', 'true');
      localStorage.setItem('isLoggedIn', 'true');
      localStorage.setItem('unrelated-key', 'keep-me');

      clearAuthData();

      expect(localStorage.getItem('user')).toBeNull();
      expect(localStorage.getItem('forcePasswordChange')).toBeNull();
      expect(localStorage.getItem('isLoggedIn')).toBeNull();
      expect(localStorage.getItem('unrelated-key')).toBe('keep-me');
    });

    it('dispatches an auth-change event on the window', () => {
      const handler = vi.fn();
      window.addEventListener('auth-change', handler);

      clearAuthData();

      expect(handler).toHaveBeenCalledTimes(1);
      window.removeEventListener('auth-change', handler);
    });
  });
});
