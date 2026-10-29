import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';
import { authUser } from '../../msw/handlers';
import ProtectedRoute from '@/components/ProtectedRoute';
import { AuthStatusProvider } from '@/context/AuthStatusContext';
import { ForcePasswordChangeProvider } from '@/context/ForcePasswordChangeContext';
import { ToastProvider } from '@/context/ToastContext';


function renderProtectedRoute(initialPath = '/dashboard') {
  return render(
    <ToastProvider>
      <AuthStatusProvider pollIntervalMs={1_000_000}>
        <ForcePasswordChangeProvider>
          <MemoryRouter initialEntries={[initialPath]}>
            <Routes>
              <Route path="/login" element={<div>Login Page Marker</div>} />
              <Route
                path="/dashboard"
                element={
                  <ProtectedRoute>
                    <div>Protected Content</div>
                  </ProtectedRoute>
                }
              />
            </Routes>
          </MemoryRouter>
        </ForcePasswordChangeProvider>
      </AuthStatusProvider>
    </ToastProvider>,
  );
}

describe('ProtectedRoute', () => {
  afterEach(() => {
    cleanup();
  });

  it('redirects to /login when the user is not authenticated', async () => {
    server.use(
      http.get(`*/api/auth/status`, () =>
        HttpResponse.json({ isValid: false, forcePasswordChange: false }),
      ),
    );

    renderProtectedRoute();

    await waitFor(() => expect(screen.getByText('Login Page Marker')).toBeInTheDocument());
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
  });

  it('renders the protected children when the user is authenticated', async () => {
    server.use(
      http.get(`*/api/auth/status`, () =>
        HttpResponse.json({ isValid: true, forcePasswordChange: false, user: authUser }),
      ),
    );

    renderProtectedRoute();

    await waitFor(() => expect(screen.getByText('Protected Content')).toBeInTheDocument());
    expect(screen.queryByText('Login Page Marker')).not.toBeInTheDocument();
  });

  it('renders the force-password-change modal instead of children when forcePasswordChange is true', async () => {
    server.use(
      http.get(`*/api/auth/status`, () =>
        HttpResponse.json({ isValid: true, forcePasswordChange: true, user: authUser }),
      ),
    );

    renderProtectedRoute();

    await waitFor(() => expect(screen.getByText('Current Password')).toBeInTheDocument());
    expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    expect(screen.queryByText('Login Page Marker')).not.toBeInTheDocument();
  });
});
