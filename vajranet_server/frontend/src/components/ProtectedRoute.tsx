import React, { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { getProfile } from '../api/api';
import { sanitizeUserForCache } from '../services/auth';
import { useAuthStatus } from '../context/useAuthStatus';
import { ForcePasswordChangeModal } from './ForcePasswordChangeModal';
import { useForcePasswordChange } from '../context/useForcePasswordChange';
import { LoadingScreen } from '@/components/ui/loading';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  
  // Continuously check session status including forcePasswordChange
  const { isValid, loading, forcePasswordChange, refetch: refetchSessionStatus } = useAuthStatus();
  const { setForcePasswordChange } = useForcePasswordChange();
  const [blockedLocation, setBlockedLocation] = useState<string | null>(null);

  // Block navigation when forcePasswordChange is true
  useEffect(() => {
    if (forcePasswordChange) {
      // Store the current location when blocking starts
      const currentPath = location.pathname;
      setBlockedLocation(currentPath);

      // Prevent browser back/forward navigation
      const handlePopState = () => {
        // Push current path back to prevent navigation
        window.history.pushState(null, '', currentPath);
        if (import.meta.env.DEV) {
          console.warn('Navigation blocked: Password change required');
        }
      };

      // Add a history entry to prevent back navigation
      window.history.pushState(null, '', currentPath);
      window.addEventListener('popstate', handlePopState);

      // Intercept link clicks that would navigate away
      const handleClick = (e: MouseEvent) => {
        const target = e.target as HTMLElement;
        const link = target.closest('a[href]');
        if (link && link.getAttribute('href')?.startsWith('/')) {
          const href = link.getAttribute('href');
          if (href && href !== currentPath) {
            e.preventDefault();
            e.stopPropagation();
            if (import.meta.env.DEV) {
              console.warn('Link navigation blocked: Password change required');
            }
            return false;
          }
        }
      };

      document.addEventListener('click', handleClick, true);

      return () => {
        window.removeEventListener('popstate', handlePopState);
        document.removeEventListener('click', handleClick, true);
      };
    } else {
      setBlockedLocation(null);
    }
  }, [forcePasswordChange, location.pathname]);

  // Intercept React Router navigation attempts
  useEffect(() => {
    if (forcePasswordChange && blockedLocation) {
      // If location changed (user tried to navigate), redirect back
      if (location.pathname !== blockedLocation) {
        navigate(blockedLocation, { replace: true });
        if (import.meta.env.DEV) {
          console.warn('Route navigation blocked: Password change required. Redirecting back to', blockedLocation);
        }
      }
    }
  }, [forcePasswordChange, blockedLocation, location.pathname, navigate]);

  useEffect(() => {
    // Keep force-password-change context in sync with server status.
    setForcePasswordChange(Boolean(forcePasswordChange));
  }, [forcePasswordChange, setForcePasswordChange]);

  useEffect(() => {
    // Ensure user cache exists for UI chrome (sidebar/menu).
    // We do not use this for auth decisions.
    const maybeHydrateUser = async () => {
      if (!isValid) return;
      const storedUser = localStorage.getItem('user');
      if (storedUser) return;
      try {
        const profile = await getProfile();
        if (profile?.data) {
          localStorage.setItem('user', JSON.stringify(sanitizeUserForCache(profile.data)));
        }
      } catch {
        // ignore: non-fatal
      }
    };

    void maybeHydrateUser();
  }, [isValid, forcePasswordChange]);

  // --- Loading state ---
  if (loading) {
    return <LoadingScreen size="md" title="Verifying authentication..." />;
  }

  // --- Not authenticated: redirect to login ---
  if (!isValid) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  // --- Must change password: do not mount the dashboard shell (no Outlet, no polling, no data fetches) ---
  if (forcePasswordChange) {
    return (
      <ForcePasswordChangeModal
        isOpen
        onPasswordChanged={() => {
          void refetchSessionStatus();
        }}
      />
    );
  }

  return <>{children}</>;
};

export default ProtectedRoute;
