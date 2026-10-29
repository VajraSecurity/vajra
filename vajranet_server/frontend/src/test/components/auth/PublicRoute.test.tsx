import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';
import { authUser } from '../../msw/handlers';
import PublicRoute from '@/components/PublicRoute';
import { AuthStatusProvider } from '@/context/AuthStatusContext';
import { ToastProvider } from '@/context/ToastContext';


function renderPublicRoute(initialPath = '/login') {
  return render(
    <ToastProvider>
      <AuthStatusProvider pollIntervalMs={1_000_000}>
        <MemoryRouter initialEntries={[initialPath]}>
          <Routes>
            <Route
              path="/login"
              element={
                <PublicRoute>
                  <div>Login Form Marker</div>
                </PublicRoute>
              }
            />
            <Route path="/my-devices" element={<div>My Devices Marker</div>} />
          </Routes>
        </MemoryRouter>
      </AuthStatusProvider>
    </ToastProvider>,
  );
}

describe('PublicRoute', () => {
  afterEach(() => {
    cleanup();
  });

  it('renders the public children when the user is not authenticated', async () => {
    server.use(
      http.get(`*/api/auth/status`, () =>
        HttpResponse.json({ isValid: false, forcePasswordChange: false }),
      ),
    );

    renderPublicRoute();

    await waitFor(() => expect(screen.getByText('Login Form Marker')).toBeInTheDocument());
    expect(screen.queryByText('My Devices Marker')).not.toBeInTheDocument();
  });

  it('redirects to /my-devices when the user is already authenticated', async () => {
    server.use(
      http.get(`*/api/auth/status`, () =>
        HttpResponse.json({ isValid: true, forcePasswordChange: false, user: authUser }),
      ),
    );

    renderPublicRoute();

    await waitFor(() => expect(screen.getByText('My Devices Marker')).toBeInTheDocument());
    expect(screen.queryByText('Login Form Marker')).not.toBeInTheDocument();
  });
});
