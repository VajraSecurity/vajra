import React, { useEffect, useMemo, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { getProfile } from '../api/api';
import { getStoredUser, sanitizeUserForCache } from '../services/auth';
import { LoadingScreen } from '@/components/ui/loading';

type UserRole = 'Super Administrator' | 'Group Admin' | 'Viewer';

const normalizeRole = (role: unknown): UserRole => {
  if (role === 'Super Administrator' || role === 'Group Admin' || role === 'Viewer') {
    return role;
  }
  return 'Viewer';
};

interface SuperAdminRouteProps {
  children: React.ReactNode;
  /** Roles allowed through, in addition to Super Administrator (always allowed). */
  allowedRoles?: readonly UserRole[];
}

// A `= []` default parameter allocates a fresh array on every render, leaving
// `allowedRoles` referentially unstable and the useMemo below recomputing every
// time. A shared frozen constant makes the default stable. Callers passing an
// inline array literal still miss, but the common no-argument case hits.
const NO_EXTRA_ROLES: readonly UserRole[] = Object.freeze([]);

const SuperAdminRoute: React.FC<SuperAdminRouteProps> = ({ children, allowedRoles = NO_EXTRA_ROLES }) => {
  const [loading, setLoading] = useState(true);
  const [role, setRole] = useState<UserRole>('Viewer');

  const canAccess = useMemo(
    () => role === 'Super Administrator' || allowedRoles.includes(role),
    [role, allowedRoles],
  );

  useEffect(() => {
    let cancelled = false;

    const hydrateRole = async () => {
      const stored = getStoredUser();
      const cachedRole = normalizeRole(stored?.role);
      setRole(cachedRole);

      try {
        const profile = await getProfile();
        const fetchedRole = normalizeRole(profile?.data?.role);
        if (profile?.data) {
          localStorage.setItem('user', JSON.stringify(sanitizeUserForCache({ ...profile.data, role: fetchedRole })));
        }
        if (!cancelled) {
          setRole(fetchedRole);
        }
      } catch {
        // Keep cached/default role on fetch failure.
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void hydrateRole();
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return <LoadingScreen size="md" title="Checking permissions..." />;
  }

  if (!canAccess) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
};

export default SuperAdminRoute;

