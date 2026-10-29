import { http, HttpResponse } from 'msw';

// Wildcard origin ('*/api/...') rather than a hardcoded host: axiosInstance reads
// VITE_API_BASE_URL from the environment, and a local .env (gitignored, not committed)
// can point it somewhere other than localhost:4000. Wildcards keep these handlers correct
// regardless of what a given machine's .env sets, without depending on any particular value.

export const authUser = {
  id: 1,
  name: 'Test User',
  email: 'user1@example.com',
  role: 'Viewer' as const,
  mfa_enabled: false,
};

export const handlers = [
  http.post('*/api/auth/login', () => HttpResponse.json({ status: 'Success', user: authUser })),

  http.post('*/api/auth/mfa/verify', () =>
    HttpResponse.json({ status: 'Success', user: authUser }),
  ),

  http.post('*/api/auth/mfa/recover', () =>
    HttpResponse.json({ status: 'Success', user: authUser }),
  ),

  http.post('*/api/auth/logout', () => HttpResponse.json({ status: 'Success' })),

  http.get('*/api/auth/status', () => HttpResponse.json({ isValid: true, user: authUser })),

  http.get('*/api/auth/profile', () =>
    HttpResponse.json({
      status: 'Success',
      data: { name: authUser.name, email: authUser.email, role: authUser.role },
    }),
  ),
];
