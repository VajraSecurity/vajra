import React, { useRef } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuthStatus } from '../context/useAuthStatus';
import { LoadingScreen } from '@/components/ui/loading';

interface PublicRouteProps {
  children: React.ReactNode;
}

/**
 * PublicRoute - Redirects authenticated users away from public pages (login/signup)
 * If user is already logged in, they should not be able to access login/signup pages
 */
const PublicRoute: React.FC<PublicRouteProps> = ({ children }) => {
  const { isValid, loading } = useAuthStatus();
  const hasShownChildren = useRef(false);

  // Track when we've reached the "show form" state for the first time.
  // Once true, subsequent loading flashes (e.g. the auth-change event that fires
  // right after a successful login) will not unmount the form.
  if (!loading && !isValid) {
    hasShownChildren.current = true;
  }

  // Only show the spinner on the initial load before we know auth state.
  // After we've shown the form once, suppress the spinner so re-checks
  // (triggered by dispatching auth-change on login) don't unmount the form.
  if (loading && !hasShownChildren.current) {
    return <LoadingScreen size="md" />;
  }

  // If authenticated, redirect to My Devices
  if (isValid) {
    return <Navigate to="/my-devices" replace />;
  }

  // If not authenticated, show the public page (login/signup)
  return <>{children}</>;
};

export default PublicRoute;
