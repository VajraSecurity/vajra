import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import { defineConfig, globalIgnores } from 'eslint/config';

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.ts'],
    extends: [js.configs.recommended, tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.node,
    },
    rules: {
      // The codebase leans on `any` at API/DB/third-party boundaries
      // throughout — ratchet this on file-by-file as those boundaries get
      // typed properly rather than blocking CI on ~700 pre-existing uses.
      '@typescript-eslint/no-explicit-any': 'off',
      // tsc's noUnusedLocals/noUnusedParameters (tsconfig.json) already gate
      // unused bindings at build time.
      '@typescript-eslint/no-unused-vars': 'off',
    },
  },
  {
    // Self-contained *.selftest.ts scripts intentionally use require() +
    // require.cache busting to re-load a module under different env vars
    // mid-test (see agentCertProvisioning.selftest.ts) — a static import
    // can't do that.
    files: ['**/*.selftest.ts'],
    rules: {
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
]);
