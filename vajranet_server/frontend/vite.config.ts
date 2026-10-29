// `vitest/config` re-exports Vite's `defineConfig` with the `test` option's
// types layered on top, so this one config drives both `vite build`/`vite
// dev` and `vitest run` — no separate vitest.config.ts (and no risk of it
// drifting from the plugins/aliases below).
import { defineConfig } from 'vitest/config'
import type { ViteDevServer, Connect } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'
import http from 'http'

// Dev-only stand-in for nginx's `auth_request /auth/grafana` gate (see
// deploy/nginx/nginx-https.conf.example + backend/src/controllers/auth/validateGrafana.ts). In
// production, nginx calls that endpoint and forwards the identity it returns
// to Grafana as X-WEBAUTH-* headers, which is what lets Grafana's
// `${__user.email}` resolve to the real signed-in user for group-scoped
// dashboard queries. Vite's built-in dev proxy is a bare passthrough with no
// equivalent, so without this, every local dev request reaches Grafana as
// anonymous — which the CVE Analysis dashboard's group-scoping SQL correctly
// (but unhelpfully, for testing) treats as "sees nothing" rather than
// "sees everything". This middleware replicates the same header injection so
// group scoping can actually be exercised through the browser in dev.
function grafanaAuthProxyDevMiddleware() {
  return {
    name: 'grafana-auth-proxy-dev',
    configureServer(server: ViteDevServer) {
      const grafanaAuthMiddleware: Connect.NextHandleFunction = (req, _res, next) => {
        const validateReq = http.request(
          { host: 'localhost', port: 4000, path: '/api/auth/validate', method: 'GET', headers: { cookie: req.headers.cookie || '' } },
          (validateRes) => {
            if (validateRes.statusCode === 200) {
              const email = validateRes.headers['x-user-email'];
              const name = validateRes.headers['x-user-name'];
              const role = validateRes.headers['x-user-role'];
              if (email) req.headers['x-webauth-user'] = email;
              if (name) req.headers['x-webauth-user-name'] = name;
              if (role) req.headers['x-webauth-role'] = role;
            }
            validateRes.resume(); // drain, we only need the headers
            next();
          },
        );
        // Same fail-closed behavior as nginx's auth_request: on any error just
        // proceed unauthenticated (anonymous) rather than blocking the request.
        validateReq.on('error', () => next());
        validateReq.end();
      };
      server.middlewares.use('/grafana', grafanaAuthMiddleware);
    },
  };
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), grafanaAuthProxyDevMiddleware()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/grafana': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/test/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test/setup.ts'],
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          // Only split node_modules code into vendor chunks; keep app code
          // in its normal (route-based) chunks.
          if (!id.includes('node_modules')) return undefined;
          // Separate React and React DOM
          if (
            id.includes('node_modules/react/') ||
            id.includes('node_modules/react-dom/') ||
            id.includes('node_modules/react-router-dom/')
          ) {
            return 'react-vendor';
          }
          // Separate UI / animation libraries
          if (id.includes('node_modules/motion/') || id.includes('node_modules/@heroicons/react/')) {
            return 'ui-vendor';
          }
          // clsx / tailwind-merge / class-variance-authority back cn() in
          // src/lib/utils.ts, which the eagerly-loaded shell (Toast,
          // ConfirmDialog, LoadingScreen) uses. Left unassigned they return
          // undefined here, so Rollup co-locates them with their largest
          // consumer — recharts — and the entry chunk then statically imports
          // the whole 430KB chart-vendor just to reach clsx. Verified in the
          // shipped build: index-*.js contains `import{c as At}from
          // "./chart-vendor-*.js"` and index.html modulepreloads it, so /login
          // downloads a charting library it can never render. Pinning them to
          // the already-eager utils-vendor removes that edge.
          if (
            id.includes('node_modules/clsx/') ||
            id.includes('node_modules/tailwind-merge/') ||
            id.includes('node_modules/class-variance-authority/') ||
            // Same failure mode as clsx above, recurring with two more modules.
            // manualChunks returns undefined for these, so Rollup parks them with
            // their largest consumer -- recharts -- and Layout-*.js (which loads
            // on EVERY authenticated page) then statically imports the whole
            // 405KB chart-vendor to reach them. MUI's createSvgIcon needs
            // react-is; base-ui's useScrollLock needs use-sync-external-store.
            // Settings, RemoteShell, ThreatHunting, PolicyManagement, MyTeam and
            // Help all pay for a charting library they never render.
            id.includes('node_modules/react-is/') ||
            id.includes('node_modules/use-sync-external-store/')
          ) {
            return 'utils-vendor';
          }
          // Separate chart libraries. recharts is only ever imported from
          // lazy route chunks (Dashboard/Nodes/Compliance/Network pages),
          // never eagerly. Using the function form (vs. the previous
          // object-form manualChunks) lets Rollup correctly determine
          // chart-vendor is reachable only via those dynamic imports, so
          // it's no longer force-preloaded via <link rel="modulepreload">
          // on every page load (e.g. /login, which never renders a chart) —
          // provided nothing eager is chunked in alongside it, which is what
          // the clsx branch above now guarantees.
          if (id.includes('node_modules/recharts/')) {
            return 'chart-vendor';
          }
          // Separate utility libraries
          if (id.includes('node_modules/axios/')) {
            return 'utils-vendor';
          }
          return undefined;
        },
      },
    },
    // Increase chunk size warning limit to 1000kb
    chunkSizeWarningLimit: 1000,
    // Use esbuild minification (faster and no additional dependencies)
    minify: 'esbuild',
  },
})
