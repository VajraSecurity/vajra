// Loaded before every test file (see `test.setupFiles` in vite.config.ts).
// Extends Vitest's `expect` with jest-dom's DOM matchers (toBeInTheDocument,
// toHaveClass, etc.) so component tests can assert against rendered markup
// without hand-rolling those checks.
import '@testing-library/jest-dom/vitest';

// Wires the MSW (Mock Service Worker) server used by the auth-subsystem
// tests under src/test/{unit,component}/auth/ — listen before the suite,
// reset per-test handler overrides after each test, close after the suite.
// Tests outside auth that don't use `server.use(...)` are unaffected.
import { beforeAll, afterEach, afterAll } from 'vitest';
import { server } from './msw/server';

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
