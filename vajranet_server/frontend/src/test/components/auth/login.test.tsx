import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { http, HttpResponse } from 'msw';
import { server } from '../../msw/server';

// SideRays renders a WebGL canvas via `ogl` and relies on IntersectionObserver,
// neither of which exist in jsdom. It's a purely decorative side panel unrelated
// to auth behavior, so it's replaced with an inert stand-in for these tests.
vi.mock('@/components/SideRays/SideRays', () => ({
  default: () => <div data-testid="side-rays-mock" />,
}));

const { default: LoginForm } = await import('@/pages/login/index');


function renderLogin(initialPath = '/login') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/login" element={<LoginForm />} />
        <Route path="/my-devices" element={<div>My Devices Marker</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

async function fillCredentials(
  user: ReturnType<typeof userEvent.setup>,
  email = 'user1@example.com',
  password = 'Password123!',
) {
  await user.type(screen.getByPlaceholderText('hi@vajra.io'), email);
  await user.type(screen.getByPlaceholderText('••••••••••'), password);
}

describe('LoginForm', () => {
  afterEach(() => {
    cleanup();
  });

  it('reaches the success state when valid credentials are submitted', async () => {
    const user = userEvent.setup();
    renderLogin();

    await fillCredentials(user);
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() =>
      expect(screen.getByText('Login successful! Redirecting...')).toBeInTheDocument(),
    );
  });

  it('transitions to the MFA code form when the server responds with MfaRequired', async () => {
    server.use(
      http.post(`*/api/auth/login`, () =>
        HttpResponse.json({ status: 'MfaRequired', mfaToken: 'mfa-token-123' }),
      ),
    );
    const user = userEvent.setup();
    renderLogin();

    await fillCredentials(user);
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => expect(screen.getByText('Authenticator Code')).toBeInTheDocument());
    expect(
      screen.getByText('Enter the 6-digit code from your Google Authenticator app.'),
    ).toBeInTheDocument();
    expect(screen.queryByPlaceholderText('hi@vajra.io')).not.toBeInTheDocument();
  });

  it('reaches the success state after submitting a valid TOTP code', async () => {
    server.use(
      http.post(`*/api/auth/login`, () =>
        HttpResponse.json({ status: 'MfaRequired', mfaToken: 'mfa-token-123' }),
      ),
    );
    const user = userEvent.setup();
    renderLogin();

    await fillCredentials(user);
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(screen.getByText('Authenticator Code')).toBeInTheDocument());

    await user.type(screen.getByPlaceholderText('123456'), '654321');
    await user.click(screen.getByRole('button', { name: /verify & sign in/i }));

    await waitFor(() =>
      expect(screen.getByText('Login successful! Redirecting...')).toBeInTheDocument(),
    );
  });

  it('reaches the success state after submitting a recovery code', async () => {
    server.use(
      http.post(`*/api/auth/login`, () =>
        HttpResponse.json({ status: 'MfaRequired', mfaToken: 'mfa-token-123' }),
      ),
    );
    const user = userEvent.setup();
    renderLogin();

    await fillCredentials(user);
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(screen.getByText('Authenticator Code')).toBeInTheDocument());

    await user.click(screen.getByRole('button', { name: /use a recovery code instead/i }));
    expect(screen.getByText('Recovery Code')).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText('abcdef12'), 'abcdef12');
    await user.click(screen.getByRole('button', { name: /verify & sign in/i }));

    await waitFor(() =>
      expect(screen.getByText('Login successful! Redirecting...')).toBeInTheDocument(),
    );
  });

  it('shows an error and stays on the credentials form when the login fails', async () => {
    server.use(
      http.post(`*/api/auth/login`, () => HttpResponse.json({ status: 'Fail' })),
    );
    const user = userEvent.setup();
    renderLogin();

    await fillCredentials(user);
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() =>
      expect(screen.getByText('Invalid email or password.')).toBeInTheDocument(),
    );
    expect(screen.queryByText('Authenticator Code')).not.toBeInTheDocument();
    expect(screen.queryByText('Login successful! Redirecting...')).not.toBeInTheDocument();
  });
});
