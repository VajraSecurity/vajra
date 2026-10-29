import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    // Only the vitest-based unit suite — NOT the *.selftest.ts scripts under
    // src/test/{mcp,middleware,utils,services}/, which are self-contained
    // (assert + process.exit) and run individually via `npm run test:mtls`
    // etc., chained together under `npm run test:selftest`.
    include: ['src/test/unit/**/*.test.ts'],
    setupFiles: ['./src/test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/test/**'],
    },
  },
});
