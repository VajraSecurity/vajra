import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';
import SuperAdminRoute from '@/components/SuperAdminRoute';


function renderSuperAdminRoute(initialPath = '/superadmin') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/dashboard" element={<div>Dashboard Marker</div>} />
        <Route
          path="/superadmin"
          element={
            <SuperAdminRoute>
              <div>Super Admin Content</div>
            </SuperAdminRoute>
          }
        />
      </Routes>
    </MemoryRouter>,
  );
}

describe('SuperAdminRoute', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    cleanup();
  });

  it('redirects to /dashboard when the authenticated user does not have the Super Administrator role', async () => {
    server.use(
      http.get(`*/api/auth/profile`, () =>
        HttpResponse.json({
          status: 'Success',
          data: { name: 'Viewer User', email: 'viewer@example.com', role: 'Viewer' },
        }),
      ),
    );

    renderSuperAdminRoute();

    await waitFor(() => expect(screen.getByText('Dashboard Marker')).toBeInTheDocument());
    expect(screen.queryByText('Super Admin Content')).not.toBeInTheDocument();
  });

  it('renders the children when the authenticated user has the Super Administrator role', async () => {
    server.use(
      http.get(`*/api/auth/profile`, () =>
        HttpResponse.json({
          status: 'Success',
          data: { name: 'Admin User', email: 'admin@example.com', role: 'Super Administrator' },
        }),
      ),
    );

    renderSuperAdminRoute();

    await waitFor(() => expect(screen.getByText('Super Admin Content')).toBeInTheDocument());
    expect(screen.queryByText('Dashboard Marker')).not.toBeInTheDocument();
  });

  it('shows a permissions-checking state before the profile role is resolved', () => {
    server.use(
      http.get(
        `*/api/auth/profile`,
        () => new Promise(() => {}), // never resolves during this test
      ),
    );

    renderSuperAdminRoute();

    expect(screen.getByText('Checking permissions...')).toBeInTheDocument();
    expect(screen.queryByText('Super Admin Content')).not.toBeInTheDocument();
    expect(screen.queryByText('Dashboard Marker')).not.toBeInTheDocument();
  });
});
