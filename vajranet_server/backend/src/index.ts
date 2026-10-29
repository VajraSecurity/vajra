// src/index.ts

import 'dotenv/config';
import express, { Express, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import fs from 'fs';
import path from 'path';
import http from 'http';
import https from 'https';
import * as httpolyglot from '@httptoolkit/httpolyglot';
import type { Server as PolyglotServer } from '@httptoolkit/httpolyglot';
import { randomUUID } from 'crypto';
import pinoHttp from 'pino-http';
import { logger, getLogger, runWithRequestId } from './utils/logger';
const log = getLogger('server');

// Validate environment variables before starting the server
import { validateEnvironmentVariables } from './utils/validateEnv';
validateEnvironmentVariables();

// Redis
import { initializeRedis, disconnectRedis, getRedisClient, isTokenBlacklisted } from './utils/redisClient';
import { isTokenBlacklistedMemory } from './utils/memoryStore';

// DB
import { dbCreateConnection } from './orm/dbCreateConnection';
import { getRawPgClient, getRawPgClientSecondary } from './orm/rawPgClient';
import databaseConfig, { databaseConfig2, databaseConfigHunt } from './orm/config/ormconfig';
import { DataSource } from 'typeorm';

// Routes
import routes from './routes/api';
import { errorHandler } from './middleware/errorHandler';

// WebSocket
import { WebSocketServer, WebSocket as WsWebSocket } from 'ws';
import { parseCookies } from './utils/cookieUtils';
import { verifyAgentMtls, agentInfoHostId, agentMtlsMode } from './utils/agentMtls';
import { caCertAvailable, getAgentCaCertPem } from './utils/agentCertProvisioning';
import {
  nodeUi, nodeExt, liveWeb, startLiveWeb, stopLiveWeb, ridCleanupInterval, jobDrainInterval,
} from './websocket';
import type { WsLike, ReqLike, LiveWebWsLike } from './websocket';
import type { JwtPayload } from './types/JwtPayload';
import jwt, { TokenExpiredError } from 'jsonwebtoken';
import { isMfaChallengeToken } from './middleware/checkJwt';
import { normalizeBurpTarget } from './utils/urlIdentity';

import {
  DEFAULT_PORT,
  REQUEST_TIMEOUT_MS,
  COMPRESSION_LEVEL,
  COMPRESSION_THRESHOLD_BYTES,
  BODY_LIMIT,
  AI_CHAT_BODY_LIMIT,
  PATCH_BUNDLE_BODY_LIMIT,
  AVATAR_UPLOAD_BODY_LIMIT,
  CORS_DEFAULT_ORIGIN,

  STATUS_OK,
  STATUS_SERVICE_UNAVAILABLE,
  WS_MAX_PAYLOAD_BYTES,
  ACCESS_TOKEN_COOKIE,
  REFRESH_TOKEN_COOKIE,
  WS_REDIS_EXT_PREFIX,
  JWT_ALGORITHM,
  SCAN_OUTPUT_DIR_DEFAULT,
  WS_HEARTBEAT_INTERVAL_MS,
} from './consts';

// PORT
const PORT = process.env.PORT || DEFAULT_PORT;

// This port is deliberately reachable on all interfaces, not just loopback: Go
// agent extensions dial this host:port directly over the public internet (see
// extension.conf's tls_hostname), bypassing nginx entirely, so this is the
// fleet's real connectivity path. Binding it to 127.0.0.1 disconnects every
// agent. The consequence is that agentMtls.ts cannot trust X-SSL-Client-*
// headers on reachability alone; it gates them on a shared secret only nginx
// sets. Any fix here must preserve that gate rather than narrow the bind.

// True whenever this deployment has TLS material configured at all
// (SSL_KEY_PATH/SSL_CERT_PATH — see the dual-protocol server built below).
// Read directly from env rather than derived from any per-connection state,
// since it answers a different question ("can this deployment do TLS at
// all?") from what a given connection actually used. Used both by the
// plaintext-transport guard below (Express routes) and by the WS upgrade
// router further down (browser-only paths) to decide whether plaintext is
// ever tolerated here, versus a local-dev deployment with no TLS capability
// at all, where plaintext is simply the only thing that can ever work.
const deploymentHasTls = !!(process.env.SSL_KEY_PATH && process.env.SSL_CERT_PATH);

// Create Express app
const app: Express = express();

// ========================================
// 0. SECURITY HEADERS & CONFIGURATION
// ========================================
// Disable X-Powered-By header (prevents fingerprinting)
app.disable('x-powered-by');

// Trust the first proxy (nginx). Required for express-rate-limit to read the
// real client IP from X-Forwarded-For instead of the nginx loopback address.
app.set('trust proxy', 1);

// ========================================
// 0b. SECURITY RESPONSE HEADERS
// ========================================
// Baseline hardening headers applied to every response. Deliberately does NOT
// set a restrictive `default-src` CSP: this server also serves the SPA's
// index.html (see the SPA fallback below), and a strict resource CSP would
// break it. `frame-ancestors 'none'` (plus X-Frame-Options) covers the real
// clickjacking risk without restricting resource loading. HSTS is only emitted
// in production, where nginx terminates TLS.
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// ========================================
// REQUEST LOGGING
// ========================================
// One structured log line per API request/response (method, url, status,
// duration, request ID) — level auto-picked by status so this stays quiet
// on the happy path (info) and loud on failures (warn/error). WS upgrades
// don't go through here; they're logged separately in the upgrade handler.
app.use(
  pinoHttp({
    logger,
    genReqId: (req, res) => {
      const existing = req.headers['x-request-id'];
      const id = typeof existing === 'string' && existing ? existing : randomUUID();
      res.setHeader('X-Request-Id', id);
      return id;
    },
    customLogLevel: (_req, res, err) => {
      if (err || res.statusCode >= 500) return 'error';
      if (res.statusCode >= 400) return 'warn';
      return 'info';
    },
    customSuccessMessage: (req, res) => `${req.method} ${req.url} ${res.statusCode}`,
    customErrorMessage: (req, res, err) => `${req.method} ${req.url} ${res.statusCode} - ${err.message}`,
    autoLogging: {
      ignore: (req) => req.url === '/health',
    },
    serializers: {
      req: (req) => ({ method: req.method, url: req.url, remoteAddress: req.remoteAddress }),
      res: (res) => ({ statusCode: res.statusCode }),
    },
  })
);

// Propagate this request's ID (set by pino-http just above) to every log line
// emitted anywhere during its lifecycle — controllers, services, DB calls —
// so a business log ("Alerts list retrieved") can be correlated with its
// HTTP access log line even under concurrent requests. Must run after
// pino-http (needs req.id) and wrap everything downstream (next()) so the
// AsyncLocalStorage context covers the whole request, including awaited work.
app.use((req: Request, _res: Response, next: NextFunction) => {
  runWithRequestId(req.id as string, () => next());
});

// Set request timeout
app.use((req: any, res: Response, next: NextFunction) => {
  let didTimeout = false;

  // Convert socket/request timeouts into a structured JSON error via the
  // global `errorHandler` (so the frontend receives a usable 504 body).
  req.setTimeout(REQUEST_TIMEOUT_MS, () => {
    if (didTimeout) return;
    didTimeout = true;
    if (res.headersSent || (res as any).writableEnded) return;

    // Logged here (not left to the downstream errorHandler/pino-http request log)
    // because both of those only ever see a generic 5xx — without this, a watchdog
    // timeout is indistinguishable from any other error that happens to produce the
    // same status code.
    log.warn({ method: req.method, url: req.originalUrl || req.url, reqId: req.id }, `Request exceeded timeout of ${REQUEST_TIMEOUT_MS}ms`);

    const timeoutErr: any = new Error(`Request timed out after ${REQUEST_TIMEOUT_MS}ms`);
    timeoutErr.errorType = 'timeout';
    next(timeoutErr);
  });

  next();
});

// ========================================
// 1. COMPRESSION
// ========================================
// Compress responses with gzip/brotli — exclude SSE (text/event-stream) to avoid buffering
app.use(compression({
  filter: (req, res) => {
    const ct = res.getHeader('Content-Type');
    if (typeof ct === 'string' && ct.includes('text/event-stream')) return false;
    return compression.filter(req, res);
  },
  level: COMPRESSION_LEVEL,
  threshold: COMPRESSION_THRESHOLD_BYTES,
}));

// ========================================
// 2. CORS
// ========================================
// Validate and configure CORS
const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(',').map(origin => origin.trim())
  : [CORS_DEFAULT_ORIGIN];

// Logged once at boot so a wave of CORS rejections can be checked against what
// was actually configured at the time, without needing a redeploy to find out.
log.info({ allowedOrigins, usingDefault: !process.env.FRONTEND_URL }, 'CORS allowed origins configured');

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);
      
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        log.warn({ origin }, 'CORS blocked request: origin not in allowlist');
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    // Retry-After is set by express-rate-limit on a 429 (see rateLimiters.ts) so the
    // frontend's RateLimitBanner can honour the server's actual configured window
    // instead of falling back to its hardcoded default. Browsers strip any response
    // header not explicitly exposed on a cross-origin request — without this, the
    // header is silently unreadable whenever FRONTEND_URL is a different origin
    // than the API, which is exactly the deployment this CORS config exists for.
    exposedHeaders: ['Retry-After'],
  })
);

// ========================================
// 3. BODY PARSERS
// ========================================
// Increase limit for AI routes since messages can be large (M5 Fix)
app.use('/api/ai', express.json({ limit: AI_CHAT_BODY_LIMIT, strict: true }));
// Patch Bundle manifests carry a per-package list (name/version/arch/
// filename/sha256) that can run to tens of thousands of entries for a full
// deb/rpm mirror snapshot — well over the default BODY_LIMIT. The signed
// wrapper's own MAX_PACKAGES_PER_BUNDLE cap (see utils/patchBundle.ts) is
// the substantive defense; this is just enough headroom for a legitimate
// upload to fit.
app.use('/api/patch/bundles', express.json({ limit: PATCH_BUNDLE_BODY_LIMIT, strict: true }));
// Avatar upload carries a small base64 image (max ~200KB validated in the controller)
app.use('/api/auth/profile/avatar', express.json({ limit: AVATAR_UPLOAD_BODY_LIMIT, strict: true }));
app.use(express.json({ limit: BODY_LIMIT, strict: true }));
app.use(express.urlencoded({ extended: true, limit: BODY_LIMIT }));
app.use(cookieParser());

// ========================================
// 3.5. PLAINTEXT TRANSPORT GUARD
// ========================================
// PORT accepts both plain HTTP and HTTPS on the same listener whenever TLS
// material is configured (see the dual-protocol server built further down) —
// deliberately, so Go agent extensions (which dial PORT directly, bypassing
// nginx — see the NOTE above PORT's definition — and each decide ws/wss for
// themselves from local config) never need that config kept in sync with
// this deployment's TLS mode. That tolerance is NOT meant to extend to the
// browser/session-facing surface: before the dual-protocol listener existed,
// a deployment with TLS configured served ONLY HTTPS on PORT, so nginx's TLS
// termination was structurally the only way in, even for a client hitting
// PORT directly. Without this guard, that same direct-PORT reachability
// would let anyone complete a login, refresh a session, or open a browser WS
// in cleartext, bypassing nginx's TLS entirely. Only the small, documented
// set of no-JWT endpoints agents call directly (see
// routes/api/agent.ts's header comment) — plus /health, which carries no secrets — are
// exempt. Checked on req.socket.encrypted, never req.secure/X-Forwarded-Proto
// (this app has 'trust proxy' enabled for real nginx-proxied traffic, but
// agents — and anyone else — can hit PORT directly and self-supply that
// header); nginx's own proxy_pass to Node is itself real HTTPS on loopback
// (see deploy/nginx/nginx-https.conf.example), so genuine nginx-proxied requests still read encrypted
// here with no special-casing needed.
const PLAINTEXT_ALLOWED_PATHS = new Set<string>([
  '/health',
  '/api/agent/manifest',
  '/api/agent/provision-cert',
]);
const isPlaintextAllowedPath = (path: string): boolean =>
  PLAINTEXT_ALLOWED_PATHS.has(path) || path.startsWith('/api/agent/patch-archives/');

app.use((req: Request, res: Response, next: NextFunction) => {
  if (!deploymentHasTls) return next(); // no TLS material anywhere on this deployment (e.g. local dev) — unchanged behaviour
  if ((req.socket as any)?.encrypted) return next();
  if (isPlaintextAllowedPath(req.path)) return next();
  log.warn({ path: req.path, remoteAddress: req.socket?.remoteAddress }, 'Rejected plaintext request to a non-agent route on a TLS-configured deployment');
  return res.status(403).json({ status: 'Fail', message: 'HTTPS required' });
});

// ========================================
// 4. API ROUTES
// ========================================
app.use('/api', routes);

// ========================================
// 5. HEALTH CHECK
// ========================================
// Probes both datasources. The fleet DB holds nodes, alerts, policies and all
// telemetry, so a check covering only the primary reports healthy while product
// function is entirely unavailable. Per-subsystem fields let a reader tell which
// half is down; `ok` remains the overall boolean for existing callers.
app.get('/health', async (_req: Request, res: Response) => {
  const checkDataSource = async (index: number, label: string): Promise<'ok' | 'down'> => {
    try {
      if (!dataSource || dataSource.length <= index || !dataSource[index].isInitialized) {
        log.warn({ datasource: label }, 'Health check failed: datasource not initialized');
        return 'down';
      }
      await dataSource[index].query('SELECT 1');
      return 'ok';
    } catch (error) {
      log.warn({ err: error, datasource: label }, 'Health check failed: datasource query error');
      return 'down';
    }
  };

  const [primary, fleet] = await Promise.all([
    checkDataSource(0, 'primary'),
    checkDataSource(1, 'fleet'),
  ]);

  const health = {
    ok: primary === 'ok' && fleet === 'ok',
    primary,
    fleet,
    timestamp: new Date().toISOString(),
  };

  res.status(health.ok ? STATUS_OK : STATUS_SERVICE_UNAVAILABLE).json(health);
});

// ========================================
// 6. 404 HANDLER
// ========================================
// ========================================
// 5.1. FRONTEND (SPA FALLBACK)
// ========================================
// If the frontend build exists, serve it and let React Router handle unknown routes
// (so `/random` shows the frontend 404 page instead of returning JSON).
const frontendDistDir = path.resolve(process.cwd(), '..', 'frontend', 'dist');
const frontendIndexHtml = path.join(frontendDistDir, 'index.html');
if (fs.existsSync(frontendIndexHtml)) {
  log.info({ frontendDistDir }, 'Frontend build found — SPA fallback enabled for non-API routes');
  app.use(express.static(frontendDistDir));

  // Catch-all for non-API routes (GET only). Exclude `/api` and `/ws` so API clients
  // still receive JSON 404s.
  // Note: Express 5 uses `path-to-regexp` and does not accept bare '*' patterns
  // (it crashes on startup). Using a RegExp route avoids that.
  app.get(/.*/, (req, res, next) => {
    const reqPath = req.path || '';
    if (reqPath.startsWith('/api') || reqPath.startsWith('/ws')) return next();
    res.status(404).sendFile(frontendIndexHtml);
  });
} else {
  log.info({ frontendDistDir }, 'Frontend build not found — SPA fallback disabled, unmatched non-API routes will return JSON 404');
}

app.use((_req: Request, res: Response) => {
  res.status(404).json({
    status: 'Error',
    message: `Cannot ${_req.method} ${_req.path}`,
  });
});

// ========================================
// 7. GLOBAL ERROR HANDLER
// ========================================
app.use(errorHandler);

// ========================================
// 8. DATABASE INITIALIZATION + SERVER START
// ========================================

// Returns the table name of every entity registered on ds that does not
// currently exist in the database — a read-only diagnostic, never a repair.
// Deliberately does not call ds.synchronize(): see the call site for why.
async function findMissingEntityTables(ds: DataSource): Promise<string[]> {
  const tableNames = [...new Set(ds.entityMetadatas.map((m) => m.tableName))];
  if (tableNames.length === 0) return [];
  const rows: { name: string }[] = await ds.query(
    `SELECT t.name FROM unnest($1::text[]) AS t(name)
      WHERE NOT EXISTS (
        SELECT 1 FROM information_schema.tables
         WHERE table_schema = 'public' AND table_name = t.name
      )`,
    [tableNames],
  );
  return rows.map((r) => r.name);
}

// Read-only existence check for one index, used to turn a "migration skipped"
// warning into a verified statement about the schema.
//
// DB_STATEMENT_TIMEOUT_MS (consts/database.ts) applies pool-wide, including to
// the boot-time DDL below. Most of that DDL is unguarded, so a timeout reaches
// the outer catch, logs fatal and exits — impossible to miss. But the few
// statements wrapped in try/catch so a deployment lacking a privilege still
// boots would swallow a timeout as a `warn` indistinguishable from the routine
// "no superuser, carry on" case. On an existing schema every statement is a
// cheap catalog lookup, so this only bites on the first boot after an upgrade
// adds a new index over a table that has since grown large — exactly when the
// missing index matters most and a warn line will not surface it.
async function indexExists(ds: DataSource, indexName: string): Promise<boolean> {
  const rows: unknown[] = await ds.query(
    `SELECT 1 FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind IN ('i', 'I') AND c.relname = $1 AND n.nspname = 'public'`,
    [indexName],
  );
  return rows.length > 0;
}

let dataSource: DataSource[] | null = null;
let server: http.Server | https.Server | PolyglotServer | null = null;
let wssNodeUi:      InstanceType<typeof WebSocketServer> | null = null;
let wssNodeExt:     InstanceType<typeof WebSocketServer> | null = null;
let wssLive:        InstanceType<typeof WebSocketServer> | null = null;
let hbLive:         ReturnType<typeof setInterval> | null = null;
let hbNodeUi:       ReturnType<typeof setInterval> | null = null;
let hbNodeExt:      ReturnType<typeof setInterval> | null = null;

export const dbSourceConnection = () => dataSource;
export const dbRawSourceConnection = getRawPgClient;
export const dbRawSourceConnectionSecondary = getRawPgClientSecondary;

/**
 * Graceful shutdown handler
 */
const gracefulShutdown = async (signal: string) => {
  log.info(`Received ${signal}, shutting down gracefully`);

  // Tracks which shutdown stage is in flight, mirroring `startupStep` in the
  // startup IIFE below — without it, a failure anywhere in this multi-step
  // teardown (DB close, Redis close, raw pg client close, etc.) would all
  // produce the same generic "Error during graceful shutdown" log line.
  let shutdownStep = 'http-server-close';
  try {
    // Stop accepting new connections
    if (server) {
      server.close(() => {
        log.info('HTTP server closed');
      });
    }

    // Stop live-dashboard timers and disconnect all WS clients before tearing
    // down the DB — prevents in-flight polls from hitting a closed connection.
    shutdownStep = 'stop-live-web';
    stopLiveWeb();

    // Stop WebSocket heartbeat intervals.
    shutdownStep = 'clear-heartbeat-intervals';
    if (hbLive)        clearInterval(hbLive);
    if (hbNodeUi)      clearInterval(hbNodeUi);
    if (hbNodeExt)     clearInterval(hbNodeExt);

    // Stop background intervals: rid sweep, job-queue drain.
    shutdownStep = 'clear-background-intervals';
    clearInterval(ridCleanupInterval);
    clearInterval(jobDrainInterval);

    // Close all WSS instances (terminates remaining WS connections).
    shutdownStep = 'close-wss-instances';
    // Batch op (3 WSS pools, each with an arbitrary number of live sockets) with
    // no prior outcome summary — logged so a report of "clients disconnected
    // unexpectedly" during a deploy can be checked against how many sockets this
    // shutdown actually held open, instead of just inferring it from silence.
    log.info(
      {
        nodeUi: wssNodeUi?.clients?.size ?? 0,
        nodeExt: wssNodeExt?.clients?.size ?? 0,
        live: wssLive?.clients?.size ?? 0,
      },
      'Closing WebSocket server instances',
    );
    wssNodeUi?.close();
    wssNodeExt?.close();
    wssLive?.close();

    // Close database connections
    shutdownStep = 'close-database-connections';
    if (dataSource && dataSource.length > 0) {
      for (let i = 0; i < dataSource.length; i++) {
        if (dataSource[i].isInitialized) {
          // Pins down exactly which connection's destroy() call threw — without
          // the index, the generic 'close-database-connections' step above
          // can't tell connection 1's failure apart from connection 2's or 3's
          // in the catch-all "Error during graceful shutdown" log below.
          shutdownStep = `close-database-connection-${i + 1}`;
          await dataSource[i].destroy();
          log.info(`Database connection ${i + 1} closed`);
        }
      }
    }

    // Close Redis connection
    shutdownStep = 'disconnect-redis';
    await disconnectRedis();

    // Close raw pg client (LISTEN/NOTIFY)
    shutdownStep = 'close-raw-pg-client';
    const { closeRawPgClient } = await import('./orm/rawPgClient');
    await closeRawPgClient();

    log.info('Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    log.error({ err: error, step: shutdownStep }, 'Error during graceful shutdown');
    process.exit(1);
  }
};

(async () => {
  // Tracks which startup stage is in flight so the catch-all below can report
  // *where* startup failed — most of the schema-bootstrap queries below run
  // unguarded (by design: any of them failing should abort startup), so
  // without this every one of them would produce the exact same generic
  // "Error during startup" log line, indistinguishable from each other.
  let startupStep = 'redis-init';
  try {
    // Initialize Redis (optional - falls back to in-memory if unavailable)
    await initializeRedis();

    // Initialize both databases
    startupStep = 'db-connect';
    dataSource = await dbCreateConnection(databaseConfig, databaseConfig2);

    if (!dataSource || dataSource.length === 0) {
      log.error('Failed to initialize databases. Exiting.');
      process.exit(1);
    }

    log.info(`${dataSource.length} database(s) initialized successfully.`);

    // Optional third connection: group-scoped historical hunting.
    // Authenticates as vajra_hunt, a role that does not own the fleet tables,
    // so the Row-Level Security policies set up by setupHuntRole() actually
    // apply to it — unlike the databaseConfig2 connection above, which
    // authenticates as the table owner and bypasses RLS entirely. This is why
    // adding this connection changes nothing for any existing code path: only
    // callers explicitly routed onto ds[2] (group-scoped hunts) are affected.
    //
    // Initialized independently of the two connections above so a deployment
    // that hasn't provisioned vajra_hunt yet (or never will) still starts
    // normally with two connections; scoped historical hunting just reports
    // itself unavailable until the role exists (see setupHuntRole() in
    // ormconfig-setup.ts).
    if (process.env.POSTGRES_HUNT_USER && process.env.POSTGRES_HUNT_PASSWORD) {
      try {
        const huntDataSource = await new DataSource(databaseConfigHunt).initialize();
        dataSource.push(huntDataSource);
        log.info('Group-scoped historical hunting connection (vajra_hunt) initialized.');
      } catch (huntErr) {
        log.warn(
          { err: huntErr },
          'Could not connect as vajra_hunt — group-scoped historical hunting will be unavailable ' +
          'until the role is provisioned (run setupFleetDatabase with an elevated-privilege DB user)',
        );
      }
    } else {
      log.info('POSTGRES_HUNT_USER/PASSWORD not set — group-scoped historical hunting is disabled.');
    }

    // Production schema bootstrap.
    // In development, synchronize:true (ormconfig) creates tables automatically.
    // In production, synchronize:false. dataSource.synchronize() diffs the entire
    // entity set against the live schema, so on a database that has drifted at
    // all — a column renamed in code but never migrated, an index dropped, a
    // primary key reshaped — "missing table" and "drifted column" are the same
    // diff: it cannot create one without being willing to apply the other, which
    // means dropping and recreating unrelated keys and constraints. Never call it
    // unattended here. Detect and log loudly instead, so a human adds the
    // specific reviewed CREATE TABLE for whatever is actually missing, the way
    // patch_jobs and the agent-release tables below were added.
    startupStep = 'schema-drift-check';
    if (process.env.NODE_ENV === 'production') {
      const missingPrimary = await findMissingEntityTables(dataSource[0]);
      if (missingPrimary.length > 0) {
        log.error(
          `Primary schema (vajra_db) is missing ${missingPrimary.length} table(s) its entities expect: ` +
            `${missingPrimary.join(', ')}. These must be created with a reviewed, additive migration — ` +
            'this bootstrap will NOT call synchronize() in production.',
        );
      }

      let missingSecondaryCount = 0;
      if (dataSource[1]?.isInitialized) {
        const missingSecondary = await findMissingEntityTables(dataSource[1]);
        missingSecondaryCount = missingSecondary.length;
        if (missingSecondary.length > 0) {
          log.error(
            `Secondary schema (fleet) is missing ${missingSecondary.length} table(s) its entities expect: ` +
              `${missingSecondary.join(', ')}. These must be created with a reviewed, additive migration — ` +
              'this bootstrap will NOT call synchronize() in production.',
          );
        }
      }

      // Confirms the check ran and passed: otherwise "no drift found" and "this
      // step never ran" are indistinguishable in the logs.
      if (missingPrimary.length === 0 && missingSecondaryCount === 0) {
        log.info('Schema drift check passed: no missing entity tables');
      }
    } else {
      // Silent no-op otherwise: synchronize:true (ormconfig, non-production) creates
      // tables automatically, so this diagnostic never runs outside production. Logged
      // so a deployment with NODE_ENV unset/misconfigured doesn't silently skip the
      // one check that would have caught schema drift before anything else broke.
      log.info({ nodeEnv: process.env.NODE_ENV }, 'Schema drift check skipped (NODE_ENV is not production)');
    }

    // Ensure vajra_users avatar columns exist on upgraded deployments (idempotent).
    startupStep = 'avatar-columns-migration';
    try {
      await dataSource[0].query(`
        ALTER TABLE vajra_users ADD COLUMN IF NOT EXISTS avatar_id    INTEGER NOT NULL DEFAULT 1;
        ALTER TABLE vajra_users ADD COLUMN IF NOT EXISTS avatar_image TEXT;
      `);
      log.info('vajra_users avatar columns ready');
    } catch (err) {
      log.warn({ err }, 'vajra_users avatar schema migration skipped');
    }

    // Reset stale agent_online state: on server restart the in-memory extension
    // WS slots are gone, but the DB still has agent_online=true for previously
    // connected agents. Clear it so the live broadcast reflects reality and the
    // UI doesn't allow sending commands to agents that aren't connected.
    if (dataSource.length >= 2 && dataSource[1].isInitialized) {
      startupStep = 'agent-online-reset';
      // `WHERE agent_online IS DISTINCT FROM false`, not an unqualified UPDATE:
      // the end state is identical, but only the already-true rows are
      // rewritten, so a restart leaves dead tuples proportional to the number of
      // connected agents rather than to the whole fleet. `nodes` has no triggers
      // or rules and nothing reads the row count, so the narrower predicate is
      // unobservable. IS DISTINCT FROM rather than a bare `WHERE agent_online`
      // because the column is nullable and a bare predicate would skip NULLs.
      await dataSource[1].query('UPDATE nodes SET agent_online = false WHERE agent_online IS DISTINCT FROM false');
      log.info('Reset agent_online to false for all nodes');

      // Ensure wifi_events table exists (idempotent — safe to run on every start).
      startupStep = 'wifi-events-table';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS wifi_events (
          id                  SERIAL       PRIMARY KEY,
          host_identifier     TEXT         NOT NULL,
          event_type          TEXT         NOT NULL DEFAULT 'initial',
          connected_ssid      TEXT,
          connected_bssid     TEXT,
          connected_interface TEXT,
          connected_signal    TEXT,
          connected_frequency TEXT,
          connected_channel   TEXT,
          connected_bitrate   TEXT,
          connected_security  TEXT,
          connected_ip        TEXT,
          is_connected        BOOLEAN      NOT NULL DEFAULT FALSE,
          saved_profiles      JSONB        NOT NULL DEFAULT '[]',
          wifi_timestamp      TIMESTAMPTZ,
          recorded_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_wifi_events_host
          ON wifi_events(host_identifier, recorded_at DESC)
      `);
      log.info('wifi_events table ready');

      // usb_events is the destination of the `usb_device_push` handler in
      // websocket/node.ts. That handler swallows insert failures in its own
      // .catch(), so if this table is missing every USB insertion/removal event
      // is discarded silently while the sibling alert insert still lands.
      //
      // Every agent-supplied column is TEXT, deliberately. node.ts binds
      // size_gb and detected_at straight off the agent payload and the two
      // platforms disagree about their shape: detected_at arrives as either an
      // epoch number or a date string (hence the parseUnixTime call below the
      // insert), which TIMESTAMPTZ rejects, and size_gb arrives as '' or a
      // non-numeric string, which NUMERIC rejects. Either rejection loses the
      // event the same way a missing table does. recorded_at is the one column
      // node.ts does not supply: server-side receipt time, and the only
      // trustworthy ordering key given detected_at is unvalidated agent text.
      //
      // The insert's `ON CONFLICT DO NOTHING` has no unique constraint to act
      // on, so nothing is deduplicated and duplicates are stored. Do not add the
      // obvious key — (host_identifier, serial_number, pnp_device_id,
      // event_type, detected_at) with NULLS NOT DISTINCT. When the agent omits
      // detected_at, every later event for that device collides with the first
      // and is dropped, which is the silent-data-loss failure this table exists
      // to end. The constraint only becomes safe once detected_at is mandatory;
      // note a column DEFAULT cannot make it so, because node.ts binds the
      // parameter explicitly and an explicit NULL beats a DEFAULT.
      //
      // Unguarded, like the wifi_events block above: a failure propagates to the
      // startup catch, which logs fatal and exits, so a restart loop makes it
      // impossible to miss. A local try/catch would let the server boot with the
      // table still missing and the inserts still failing. It is the same DDL,
      // user and connection that creates wifi_events, so it needs no additional
      // privilege.
      startupStep = 'usb-events-table';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS usb_events (
          id               BIGSERIAL    PRIMARY KEY,
          host_identifier  TEXT         NOT NULL,
          caption          TEXT,
          pnp_device_id    TEXT,
          serial_number    TEXT,
          size_gb          TEXT,
          event_type       TEXT,
          detected_at      TEXT,
          recorded_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      // Single index, mirroring wifi_events: the per-host, most-recent-first
      // read is the only access pattern the UI has today. A cross-host
      // (serial_number) index — the "where else has this stick been plugged
      // in" forensic query — is the obvious second one, but nothing reads this
      // table yet and an unused index is pure write cost on a path agents push
      // to, so it waits for an actual caller.
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_usb_events_host
          ON usb_events(host_identifier, recorded_at DESC)
      `);
      log.info('usb_events table ready');

      startupStep = 'clamav-status-table';
      // Ensure clamav_status table exists (idempotent — safe to run on every start).
      // One row per host, upserted on every clamav_status_push from the Linux agent.
      // daemon_running reflects whether clamd answered PING — distinct from the
      // agent itself being online.
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS clamav_status (
          host_identifier  TEXT         PRIMARY KEY,
          daemon_running   BOOLEAN      NOT NULL DEFAULT FALSE,
          engine_version   TEXT,
          db_version       TEXT,
          db_date          TEXT,
          version_raw      TEXT,
          last_error       TEXT,
          freshclam_result TEXT,
          updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      log.info('clamav_status table ready');

      startupStep = 'packages-snapshot-table';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS packages_snapshot (
          id               BIGSERIAL    PRIMARY KEY,
          host_identifier  TEXT         NOT NULL,
          source           TEXT         NOT NULL,
          name             TEXT         NOT NULL,
          version          TEXT,
          revision         TEXT,
          channel          TEXT,
          publisher        TEXT,
          confinement      TEXT,
          snap_type        TEXT,
          app_id           TEXT,
          branch           TEXT,
          origin           TEXT,
          arch             TEXT,
          install_dir      TEXT,
          size             TEXT,
          updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_packages_snapshot_host
          ON packages_snapshot (host_identifier);
        CREATE INDEX IF NOT EXISTS idx_packages_snapshot_host_source
          ON packages_snapshot (host_identifier, source);
      `);
      log.info('packages_snapshot table ready');

      // Patch Management tables (patch_jobs, patch_job_nodes,
      // pending_patch_commands, patch_available_updates) are NOT bootstrapped
      // here anymore — like agent_cert_provisioning_tokens, they're created by a reviewed, additive migration
      // (backend/migrations/005_add_patch_management_tables.sql) plus TypeORM
      // entities under orm/entities/fleet/ (PatchJob, PatchJobNode,
      // PendingPatchCommand, PatchAvailableUpdate) so findMissingEntityTables()
      // above can detect drift instead of this file silently recreating them.

      startupStep = 'nodes-columns-migration';
      // Ensure nodes columns added after the fleet server's base schema (idempotent).
      await dataSource[1].query(`
        ALTER TABLE nodes ADD COLUMN IF NOT EXISTS critical           BOOLEAN     DEFAULT false;
        ALTER TABLE nodes ADD COLUMN IF NOT EXISTS critical_reason    TEXT;
        ALTER TABLE nodes ADD COLUMN IF NOT EXISTS critical_marked_at TIMESTAMPTZ;
        ALTER TABLE nodes ADD COLUMN IF NOT EXISTS owner_group_id     TEXT;
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_nodes_owner_group_id ON nodes(owner_group_id);
      `);
      log.info('nodes schema up to date');

      startupStep = 'alerts-columns-migration';
      // Ensure alerts columns added (idempotent).
      // group_id: soft reference to nodes_groups.group_id (see nodeScope.ts).
      // Only populated for alert types whose triggering entity actually
      // carries a group — currently just the Scan Scheduler's consolidated
      // "Unmanaged Hosts Detected" alert (stamped from ScanSchedule.groupId in
      // createRunAlert, scanSchedulerService.ts), since that alert's
      // host_identifier is a synthetic per-run id with no matching `nodes` row,
      // so the usual host_identifier -> nodes.owner_group_id scoping used by
      // every other alert type can't apply to it. NULL for every other alert
      // type (still scoped via nodes.owner_group_id as before), and NULL for a
      // Super Administrator's own fleet-wide schedule.
      await dataSource[1].query(`
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assign             TEXT;
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS assignee_id        INTEGER;
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mark_type          TEXT;
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS group_id           VARCHAR(255);
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_alerts_assignee_open ON alerts(assignee_id, is_open);
        CREATE INDEX IF NOT EXISTS idx_alerts_mark_type ON alerts(mark_type);
        CREATE INDEX IF NOT EXISTS idx_alerts_group_id ON alerts(group_id);
      `);
      log.info('alerts schema up to date');

      // Ensure compliance snapshot tables have the node-list columns added after initial schema.
      startupStep = 'compliance-snapshot-migration';
      try {
        await dataSource[1].query(`
          ALTER TABLE historical_compliance        ADD COLUMN IF NOT EXISTS fully_compliant_nodes_list  JSONB DEFAULT NULL;
          ALTER TABLE historical_compliance        ADD COLUMN IF NOT EXISTS non_compliant_nodes_list    JSONB DEFAULT NULL;
          ALTER TABLE sebi_historical_compliance   ADD COLUMN IF NOT EXISTS fully_compliant_nodes_list  JSONB DEFAULT NULL;
          ALTER TABLE sebi_historical_compliance   ADD COLUMN IF NOT EXISTS non_compliant_nodes_list    JSONB DEFAULT NULL;
          ALTER TABLE irdai_historical_compliance  ADD COLUMN IF NOT EXISTS fully_compliant_nodes_list  JSONB DEFAULT NULL;
          ALTER TABLE irdai_historical_compliance  ADD COLUMN IF NOT EXISTS non_compliant_nodes_list    JSONB DEFAULT NULL;
          ALTER TABLE certin_historical_compliance ADD COLUMN IF NOT EXISTS fully_compliant_nodes_list  JSONB DEFAULT NULL;
          ALTER TABLE certin_historical_compliance ADD COLUMN IF NOT EXISTS non_compliant_nodes_list    JSONB DEFAULT NULL;
        `);
        log.info('compliance snapshot schemas up to date');
      } catch (err) {
        log.warn({ err }, 'compliance snapshot schema migration skipped (may need superuser)');
      }

      // Ensure network_scan_history schema is up to date (idempotent).
      startupStep = 'network-scan-history-table';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS network_scan_history (
          id                  BIGSERIAL    PRIMARY KEY,
          status              VARCHAR(50)  NOT NULL DEFAULT 'PENDING',
          progress            INTEGER      NOT NULL DEFAULT 0,
          target              TEXT         NOT NULL DEFAULT '',
          scan_type           VARCHAR(50)  NOT NULL DEFAULT '',
          reason              VARCHAR(500) NOT NULL DEFAULT '',
          command             TEXT         NOT NULL DEFAULT '',
          output              TEXT         NOT NULL DEFAULT '',
          pid                 INTEGER,
          created_by_user_id  BIGINT,
          created_by_name     VARCHAR(255),
          created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_nsh_created_by ON network_scan_history(created_by_user_id);
      `);
      await dataSource[1].query(`
        ALTER TABLE network_scan_history ADD COLUMN IF NOT EXISTS pid INTEGER DEFAULT NULL;
        ALTER TABLE network_scan_history ALTER COLUMN target TYPE TEXT;
      `).catch((err) => {
        log.warn({ err }, 'network_scan_history pid/target column migration skipped');
      });
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_nsh_status_created_at ON network_scan_history(status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_nsh_target ON network_scan_history(target);
      `);
      log.info('network_scan_history schema up to date');

      // Ensure scan_schedules table + network_scan_history.schedule_id are up to date (idempotent).
      startupStep = 'scan-schedules-table';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS scan_schedules (
          id                    SERIAL       PRIMARY KEY,
          name                  VARCHAR(255) NOT NULL,
          enabled               BOOLEAN      NOT NULL DEFAULT true,
          target                VARCHAR(20)  NOT NULL,
          frequency_preset      VARCHAR(20)  NOT NULL,
          cron_expression       VARCHAR(100) NOT NULL,
          reason                VARCHAR(500) NOT NULL DEFAULT '',
          known_ips             JSONB        NOT NULL DEFAULT '[]',
          created_by_user_id    INTEGER,
          created_by_name       VARCHAR(255),
          last_run_at           TIMESTAMPTZ,
          last_run_status       VARCHAR(20),
          last_run_history_id   BIGINT,
          last_new_ip_count     INTEGER,
          last_pending_ip_count INTEGER,
          last_reused_ip_count  INTEGER,
          created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      await dataSource[1].query(`
        ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS last_pending_ip_count INTEGER;
        ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS last_reused_ip_count INTEGER;
        ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS known_ips JSONB NOT NULL DEFAULT '[]';
        ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_scan_schedules_group ON scan_schedules(group_id);
      `);
      await dataSource[1].query(`
        ALTER TABLE network_scan_history ADD COLUMN IF NOT EXISTS schedule_id BIGINT;
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_nsh_schedule_id ON network_scan_history(schedule_id);
      `);
      try {
        // Supports ScanSchedulerService's per-tick "already notified" dedup lookup
        // (WHERE metadata::jsonb->>'schedule_id' = $1), which otherwise sequential-scans alerts.
        await dataSource[1].query(`
          CREATE INDEX IF NOT EXISTS idx_alerts_schedule_id
            ON alerts ((metadata::jsonb->>'schedule_id'));
        `);
      } catch (err) {
        log.warn({ err }, 'alerts schedule_id index skipped (may need superuser)');
      }
      // This is the one guarded index build whose silent failure is expensive,
      // so it is verified rather than assumed. Two very different failures land
      // in the catch above and log identically: the privilege error it was
      // written for, where the index simply will not exist, and a
      // DB_STATEMENT_TIMEOUT_MS abort while building over a large `alerts` —
      // the shape of a first boot after an upgrade. In the second case the
      // scheduler sequential-scans `alerts` on every tick from then on.
      //
      // Do not fix this by raising statement_timeout here. A non-CONCURRENT
      // CREATE INDEX holds a SHARE lock on `alerts`, the table the agent event
      // pipeline writes to, so a longer ceiling trades a missing index for a
      // fleet-wide alert-ingestion stall on every deploy. Keep the timeout, keep
      // booting — a missing index degrades the scheduler rather than breaking
      // it — and report the outcome with the remediation that avoids the lock.
      try {
        if (!(await indexExists(dataSource[1], 'idx_alerts_schedule_id'))) {
          log.error(
            { index: 'idx_alerts_schedule_id', table: 'alerts' },
            'idx_alerts_schedule_id is MISSING after the bootstrap attempt above — ScanSchedulerService\'s ' +
            "per-tick dedup lookup (WHERE metadata::jsonb->>'schedule_id' = $1) will sequential-scan alerts " +
            'on every tick until this is created by hand, out of band, with: ' +
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_schedule_id ON alerts ((metadata::jsonb->>'schedule_id'));",
          );
        }
      } catch (verifyErr) {
        // The verification query itself failing is not a reason to fail the
        // boot, but it must not be mistaken for "the index is present" —
        // logged separately from the two cases above so the three are
        // distinguishable.
        log.warn({ err: verifyErr }, 'Could not verify whether idx_alerts_schedule_id exists');
      }
      log.info('scan_schedules schema up to date');

      // Ensure nuclei_scan_history table exists (idempotent).
      startupStep = 'nuclei-scan-history-table';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS nuclei_scan_history (
          id                  BIGSERIAL    PRIMARY KEY,
          status              VARCHAR(50)  NOT NULL DEFAULT 'PENDING',
          progress            INTEGER      NOT NULL DEFAULT 0,
          target              TEXT         NOT NULL,
          scan_type           VARCHAR(50)  NOT NULL,
          reason              VARCHAR(500) NOT NULL,
          command             TEXT         NOT NULL,
          raw_output          TEXT         NOT NULL DEFAULT '',
          findings            JSONB,
          summary             JSONB,
          pid                 INTEGER,
          network_scan_id     BIGINT,
          created_by_user_id  BIGINT,
          created_by_name     VARCHAR(255),
          created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_nuclei_created_by ON nuclei_scan_history(created_by_user_id);
        CREATE INDEX IF NOT EXISTS idx_nuclei_status     ON nuclei_scan_history(status);
        CREATE INDEX IF NOT EXISTS idx_nuclei_created_at ON nuclei_scan_history(created_at DESC);
      `);
      log.info('nuclei_scan_history table ready');

      // Ensure the asset identity resolution tables exist (idempotent).
      // Documentation mirror: backend/migrations/029_add_asset_identity_tables.sql.
      // Keep the two in sync — nothing executes migrations/*.sql automatically,
      // so THIS block is the real DDL on every boot including production, where
      // TypeORM synchronize is disabled.
      startupStep = 'asset-identity-tables';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS assets (
          asset_uuid           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
          first_seen           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          last_seen            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          identity_confidence  SMALLINT     NOT NULL DEFAULT 0,
          needs_review         BOOLEAN      NOT NULL DEFAULT FALSE,
          merged_into          UUID,
          owner_group_id       VARCHAR(255)
        )
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_assets_needs_review ON assets (needs_review) WHERE needs_review;
        CREATE INDEX IF NOT EXISTS idx_assets_owner_group  ON assets (owner_group_id);
        CREATE INDEX IF NOT EXISTS idx_assets_merged_into  ON assets (merged_into);
        CREATE INDEX IF NOT EXISTS idx_assets_last_seen    ON assets (last_seen);
      `);
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS asset_identities (
          asset_uuid   UUID          NOT NULL,
          kind         VARCHAR(32)   NOT NULL,
          value_norm   VARCHAR(255)  NOT NULL,
          weight       SMALLINT      NOT NULL DEFAULT 0,
          first_seen   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
          last_seen    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
          PRIMARY KEY (asset_uuid, kind, value_norm)
        )
      `);
      // FK backstop for the "asset rows are never deleted" invariant (rows are
      // only ever soft-merged via merged_into) -- a future DELETE FROM assets
      // would otherwise silently orphan identity rows. Added via a guarded
      // ALTER rather than inline on the CREATE TABLE, because CREATE TABLE IF
      // NOT EXISTS is a no-op on a DB where this table predates the FK.
      await dataSource[1].query(`
        DO $$ BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_asset_identities_asset') THEN
            ALTER TABLE asset_identities
              ADD CONSTRAINT fk_asset_identities_asset
              FOREIGN KEY (asset_uuid) REFERENCES assets(asset_uuid) ON DELETE CASCADE;
          END IF;
        END $$;
      `);
      // idx_asset_identities_kind_value IS the matcher: resolveAsset() issues
      // exactly one indexed lookup per observation, WHERE (kind, value_norm)
      // IN (...), which the asset-first PK cannot serve. The partial UNIQUE
      // index is the concurrency backstop that turns a duplicate-minting race
      // on a bios_uuid/mac into a loud failure instead of a silent duplicate.
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_asset_identities_kind_value
          ON asset_identities (kind, value_norm);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_identities_strong_unique
          ON asset_identities (kind, value_norm)
          WHERE kind IN ('bios_uuid', 'mac');
      `);
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS asset_observations (
          id            BIGSERIAL     PRIMARY KEY,
          asset_uuid    UUID,
          source        VARCHAR(32)   NOT NULL,
          source_ref    VARCHAR(512)  NOT NULL,
          observed_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
          attrs         JSONB         NOT NULL DEFAULT '{}'::jsonb,
          match_score   SMALLINT      NOT NULL DEFAULT 0,
          match_reason  JSONB
        )
      `);
      // Same FK backstop as asset_identities above; NULL asset_uuid rows
      // (observations the matcher declined to resolve) are exempt from a FK
      // by definition, so this does not affect skipped_no_identities/no_mint.
      await dataSource[1].query(`
        DO $$ BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_asset_observations_asset') THEN
            ALTER TABLE asset_observations
              ADD CONSTRAINT fk_asset_observations_asset
              FOREIGN KEY (asset_uuid) REFERENCES assets(asset_uuid) ON DELETE CASCADE;
          END IF;
        END $$;
      `);
      // The UNIQUE index is what makes a replayed feed a no-op: feeders insert
      // ON CONFLICT DO NOTHING, so zeroing a watermark in asset_feed_state
      // re-ingests without duplicating.
      await dataSource[1].query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_obs_source_ref
          ON asset_observations (source, source_ref);
        CREATE INDEX IF NOT EXISTS idx_asset_obs_asset_observed
          ON asset_observations (asset_uuid, observed_at);
        CREATE INDEX IF NOT EXISTS idx_asset_obs_source_observed
          ON asset_observations (source, observed_at);
      `);
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS asset_feed_state (
          source          VARCHAR(32)  PRIMARY KEY,
          last_source_id  BIGINT,
          last_run_at     TIMESTAMPTZ,
          last_error      TEXT
        )
      `);
      log.info('asset_identity schema up to date');

      // File Integrity Monitoring tables (idempotent). Documentation mirror:
      // backend/migrations/030_add_fim_tables.sql (canonical: vajra_server
      // sql/migrations/0004_fim.sql). Keep in sync — this block is the real DDL.
      startupStep = 'fim-tables';
      // FIM schema (0004 base tables, 0005-0008 registry/verify/worker/perf): applied through
      // bootFimSchema - hash skip (no locks on a no-op boot), shared DDL lock, lock timeout +
      // retries, conditional ALTERs, invariant check + repair, history key check. NEVER fatal: on
      // failure only the FIM registry features are disabled (503 + banner + critical alert) and the
      // step is retried in the background every 5 minutes.
      {
        const regSvc = await import('./services/fimRegistryService');
        const ddl = await import('./utils/fim/fimRegistryDdl');
        const blocks: [string, string][] = [['0004_fim_base', ddl.FIM_BASE_DDL], ['0005_fim_registry', ddl.FIM_REGISTRY_DDL], ['0006_fim_verify', ddl.FIM_VERIFY_DDL],
          ['0007_fim_worker_schema', ddl.FIM_WORKER_DDL], ['0008_fim_perf', ddl.FIM_PERF_DDL]];
        const fleet = dataSource[1] as never;
        const boot = await regSvc.bootFimSchema(fleet, blocks, (m, e) => log.warn({ ...e }, m));
        if (!boot.ok) {
          const retry = setInterval(() => {
            regSvc.bootFimSchema(fleet, blocks, (m, e) => log.warn({ ...e }, m))
              .then((r) => { if (r.ok) { clearInterval(retry); log.info('FIM schema applied on retry; registry features re-enabled'); } })
              .catch((err) => log.error({ err }, 'FIM schema retry failed'));
          }, 5 * 60_000);
          retry.unref();
        }
        // 0008a performance indexes: built CONCURRENTLY in the background on ONE dedicated
        // connection, outside any transaction (never inline in the boot DDL). Retried daily.
        const buildPerf = async () => {
          const runner = dataSource![1].createQueryRunner();
          try {
            await runner.connect();
            await regSvc.ensurePerfIndexes({ query: (sql: string, params?: any[]) => runner.query(sql, params) }, (m, e) => log.warn({ ...e }, m));
          } catch (err) { log.error({ err }, 'FIM perf index build failed'); } finally { await runner.release().catch(() => undefined); }
        };
        setTimeout(() => { void buildPerf(); }, 30_000).unref();
        setInterval(() => { void buildPerf(); }, 24 * 3600_000).unref();
        log.info('fim schema step done');
      }

      // Ensure nessus_configs table exists (idempotent).
      startupStep = 'nessus-configs-table';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS nessus_configs (
          id                     BIGSERIAL    PRIMARY KEY,
          nessus_url             VARCHAR(500) NOT NULL,
          access_key_encrypted   TEXT         NOT NULL,
          access_key_iv          VARCHAR(64)  NOT NULL,
          access_key_auth_tag    VARCHAR(64)  NOT NULL,
          secret_key_encrypted   TEXT         NOT NULL,
          secret_key_iv          VARCHAR(64)  NOT NULL,
          secret_key_auth_tag    VARCHAR(64)  NOT NULL,
          access_key_suffix      VARCHAR(8)   NOT NULL DEFAULT '',
          secret_key_suffix      VARCHAR(8)   NOT NULL DEFAULT '',
          is_active              BOOLEAN      NOT NULL DEFAULT TRUE,
          created_by_user_id     BIGINT,
          created_by_name        VARCHAR(255),
          created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      // group_id: soft reference to nodes_groups.group_id, null = the Super
      // Administrator's own config (see NessusConfig.ts). The existing single
      // shared row (if any) keeps group_id = NULL on this ALTER, so it
      // becomes the Super Admin's own config rather than disappearing —
      // deliberate, per product decision, not a side effect.
      await dataSource[1].query(`
        ALTER TABLE nessus_configs ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_nessus_config_active ON nessus_configs(is_active);
        CREATE INDEX IF NOT EXISTS idx_nessus_config_group ON nessus_configs(group_id);
      `);
      // At most one active config per group (including the NULL/Super-Admin
      // bucket, via COALESCE) — enforces the "one config per scope" invariant
      // the save/delete controllers rely on. A plain UNIQUE(group_id) can't
      // express this because Postgres treats every NULL as distinct.
      await dataSource[1].query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_nessus_config_active_group_unique
          ON nessus_configs (COALESCE(group_id, ''))
          WHERE is_active;
      `);
      log.info('nessus_configs table ready');

      // Ensure ai_provider_configs table exists (idempotent). Lives on the
      // primary DataSource (dataSource[0]) alongside AiConversation, not the
      // fleet/secondary one used by the scanner integrations above.
      startupStep = 'ai-provider-configs-table';
      await dataSource[0].query(`
        CREATE TABLE IF NOT EXISTS ai_provider_configs (
          id                     BIGSERIAL    PRIMARY KEY,
          provider               VARCHAR(20)  NOT NULL,
          api_key_encrypted      TEXT         NOT NULL,
          api_key_iv             VARCHAR(64)  NOT NULL,
          api_key_auth_tag       VARCHAR(64)  NOT NULL,
          api_key_suffix         VARCHAR(8)   NOT NULL DEFAULT '',
          model                  VARCHAR(100),
          base_url               VARCHAR(500),
          organization           VARCHAR(255),
          max_output_tokens      INTEGER,
          is_active              BOOLEAN      NOT NULL DEFAULT TRUE,
          created_by_user_id     BIGINT,
          created_by_name        VARCHAR(255),
          created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      await dataSource[0].query(`
        CREATE INDEX IF NOT EXISTS idx_ai_provider_config_active ON ai_provider_configs(is_active);
      `);
      log.info('ai_provider_configs table ready');

      // Ensure openvas_configs table exists (idempotent).
      startupStep = 'openvas-configs-table';
      // Drop old table if schema changed (safe — configs are re-entered).
      const legacyOpenvasSchema: unknown[] = await dataSource[1].query(
        `SELECT 1 FROM information_schema.columns WHERE table_name='openvas_configs' AND column_name='connection_type'`,
      );
      if (legacyOpenvasSchema.length > 0) {
        log.warn('openvas_configs has legacy connection_type column — dropping and recreating table; existing OpenVAS config will need to be re-entered');
      }
      await dataSource[1].query(`
        DO $$ BEGIN
          IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='openvas_configs' AND column_name='connection_type') THEN
            DROP TABLE openvas_configs;
          END IF;
        END $$
      `);
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS openvas_configs (
          id                       BIGSERIAL    PRIMARY KEY,
          nessus_url               VARCHAR(500) NOT NULL,
          gmp_username             VARCHAR(255) NOT NULL,
          gmp_password_encrypted   TEXT         NOT NULL,
          gmp_password_iv          VARCHAR(64)  NOT NULL,
          gmp_password_auth_tag    VARCHAR(64)  NOT NULL,
          is_active                BOOLEAN      NOT NULL DEFAULT TRUE,
          created_by_user_id       BIGINT,
          created_by_name          VARCHAR(255),
          created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      // See the equivalent nessus_configs block above for the full rationale
      // (group_id semantics, why COALESCE is needed for the unique index).
      await dataSource[1].query(`
        ALTER TABLE openvas_configs ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_openvas_config_active ON openvas_configs(is_active);
        CREATE INDEX IF NOT EXISTS idx_openvas_config_group ON openvas_configs(group_id);
      `);
      await dataSource[1].query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_openvas_config_active_group_unique
          ON openvas_configs (COALESCE(group_id, ''))
          WHERE is_active;
      `);
      log.info('openvas_configs table ready');

      // Ensure burpsuite_configs table exists (idempotent).
      startupStep = 'burpsuite-configs-table';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS burpsuite_configs (
          id                     BIGSERIAL    PRIMARY KEY,
          api_url                VARCHAR(500) NOT NULL,
          api_key_encrypted      TEXT         NOT NULL,
          api_key_iv             VARCHAR(64)  NOT NULL,
          api_key_auth_tag       VARCHAR(64)  NOT NULL,
          api_key_suffix         VARCHAR(16)  DEFAULT '',
          is_active              BOOLEAN      NOT NULL DEFAULT TRUE,
          created_by_user_id     BIGINT,
          created_by_name        VARCHAR(255),
          created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      
      // Migration: Rename enterprise_url to api_url if it exists
      try {
        await dataSource[1].query(`
          ALTER TABLE burpsuite_configs RENAME COLUMN enterprise_url TO api_url;
        `);
        log.info('burpsuite_configs.enterprise_url renamed to api_url');
      } catch (e) {
        // Expected on every start after the first successful rename (column no
        // longer named enterprise_url) — logged so a genuinely unexpected
        // failure (permissions, lock timeout) is still traceable instead of
        // being silently swallowed on every restart.
        log.warn({ err: e }, 'burpsuite_configs.enterprise_url rename skipped (already renamed or column not present)');
      }

      // See the equivalent nessus_configs block above for the full rationale
      // (group_id semantics, why COALESCE is needed for the unique index).
      await dataSource[1].query(`
        ALTER TABLE burpsuite_configs ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_burpsuite_config_active ON burpsuite_configs(is_active);
        CREATE INDEX IF NOT EXISTS idx_burpsuite_config_group ON burpsuite_configs(group_id);
      `);
      await dataSource[1].query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_burpsuite_config_active_group_unique
          ON burpsuite_configs (COALESCE(group_id, ''))
          WHERE is_active;
      `);
      log.info('burpsuite_configs table ready');

      // Ensure burpsuite_scan_history table exists
      startupStep = 'burpsuite-scan-history-table';
      await dataSource[1].query(`
        CREATE TABLE IF NOT EXISTS burpsuite_scan_history (
          id                     BIGSERIAL    PRIMARY KEY,
          task_id                VARCHAR(255) NOT NULL,
          target                 VARCHAR(500) NOT NULL,
          status                 VARCHAR(50)  NOT NULL DEFAULT 'running',
          issues_total           INT          DEFAULT 0,
          issues_high            INT          DEFAULT 0,
          issues_medium          INT          DEFAULT 0,
          issues_low             INT          DEFAULT 0,
          created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      await dataSource[1].query(`
        ALTER TABLE burpsuite_scan_history ADD COLUMN IF NOT EXISTS results_json TEXT DEFAULT NULL;
        ALTER TABLE burpsuite_scan_history ADD COLUMN IF NOT EXISTS metrics_json TEXT DEFAULT NULL;
        ALTER TABLE burpsuite_scan_history ADD COLUMN IF NOT EXISTS group_id VARCHAR(255);
        ALTER TABLE burpsuite_scan_history ADD COLUMN IF NOT EXISTS normalized_target VARCHAR(255);
      `);
      await dataSource[1].query(`
        CREATE INDEX IF NOT EXISTS idx_burpsuite_history_group ON burpsuite_scan_history(group_id);
        CREATE INDEX IF NOT EXISTS idx_burpsuite_history_normalized_target ON burpsuite_scan_history(normalized_target);
      `);
      log.info('burpsuite_scan_history table ready');

      // Backfill normalized_target for rows written before this column existed
      // (Burp Suite Assets feature -- see utils/urlIdentity.ts). Idempotent:
      // only rows still NULL are touched, so once a deployment's history is
      // fully backfilled this is a single no-op SELECT on every subsequent
      // boot. New rows get normalized_target at insert time
      // (launchBurpsuiteScan in controllers/burpsuite/burpsuiteController.ts),
      // so this only ever has real work to do exactly once per pre-existing
      // row.
      startupStep = 'burpsuite-scan-history-normalized-target-backfill';
      const burpRowsNeedingBackfill = await dataSource[1].query(
        'SELECT id, target FROM burpsuite_scan_history WHERE normalized_target IS NULL',
      );
      if (burpRowsNeedingBackfill.length > 0) {
        let burpBackfilled = 0;
        for (const row of burpRowsNeedingBackfill) {
          const normalized = normalizeBurpTarget(row.target);
          // A target that fails to parse stays NULL, same as a fresh insert of
          // that same bad value would -- it is excluded from the Assets view
          // either way, not an error worth failing startup over.
          if (normalized === null) continue;
          await dataSource[1].query(
            'UPDATE burpsuite_scan_history SET normalized_target = $1 WHERE id = $2',
            [normalized, row.id],
          );
          burpBackfilled++;
        }
        log.info(
          { total: burpRowsNeedingBackfill.length, backfilled: burpBackfilled },
          'burpsuite_scan_history.normalized_target backfill complete',
        );
      }

      // Ensure scan output directory exists for file-backed scan persistence.
      startupStep = 'scan-dir-mkdir';
      const scanDir = process.env.VAJRA_SCAN_DIR || path.join(process.cwd(), SCAN_OUTPUT_DIR_DEFAULT);
      fs.mkdirSync(scanDir, { recursive: true });
      log.info({ scanDir }, 'Scan output directory ready');

      // Recover or finalize orphaned scans from a previous server run.
      startupStep = 'orphan-scan-cleanup';
      // If a scan process is still alive, resume tracking it via polling.
      // If it's dead, recover results from the output file.
      if (process.env.ON_PREM === 'true') {
        let orphanCleanupStep: 'nmap' | 'nuclei' = 'nmap';
        try {
          const { cleanupOrphanedScans } = await import('./controllers/network/nmapController');
          await cleanupOrphanedScans();
          orphanCleanupStep = 'nuclei';
          const { cleanupOrphanedNucleiScans } = await import('./controllers/network/nucleiController');
          await cleanupOrphanedNucleiScans();
          // Confirms both cleanup passes actually ran and completed — without this,
          // "cleanup ran clean" and "ON_PREM check never reached this branch" look
          // identical from logs alone, same reasoning as the schema-drift-check
          // clean-path log above.
          log.info('Orphaned scan cleanup completed (nmap + nuclei)');
        } catch (err) {
          log.error({ err, step: orphanCleanupStep }, 'Failed to cleanup orphaned scans');
        }
      } else {
        log.info('ON_PREM is not "true" — orphaned scan cleanup skipped');
      }

      // Initialize Data Retention Cron Jobs
      try {
        const { DataRetentionService, setDataRetentionServiceInstance } = await import('./services/dataRetentionService');
        const dataRetentionService = new DataRetentionService(dataSource[0], dataSource[1]);
        // Register before scheduling: if initializeJobs() fails wholesale the
        // controller must still reach the instance, or policy edits do nothing
        // until a restart that fails the same way.
        setDataRetentionServiceInstance(dataRetentionService);
        await dataRetentionService.initializeJobs();
        log.info('Data retention background jobs initialized');
      } catch (err) {
        log.error({ err }, 'Failed to initialize data retention background jobs');
      }

      // Expired CERT-In drafts and their storage are only reclaimed here; no
      // route triggers this cleanup.
      try {
        const cron = await import('node-cron');
        const { runCleanupExpiredDraftsJob } = await import('./controllers/alerts/certin_draft');
        cron.schedule('0 3 * * *', () => {
          runCleanupExpiredDraftsJob();
        });
        log.info('Expired CERT-In draft cleanup scheduled (daily at 03:00)');
      } catch (err) {
        log.error({ err }, 'Failed to schedule expired CERT-In draft cleanup');
      }

      // Initialize Node Auto-Assignment scheduler (IP -> group rules)
      try {
        const { NodeAutoAssignService, setNodeAutoAssignServiceInstance } = await import('./services/nodeAutoAssignService');
        const nodeAutoAssignService = new NodeAutoAssignService(dataSource[1]);
        setNodeAutoAssignServiceInstance(nodeAutoAssignService);
        nodeAutoAssignService.start();
        log.info('Node auto-assignment background job initialized');
      } catch (err) {
        log.error({ err }, 'Failed to initialize node auto-assignment background job');
      }

      // FIM: periodically re-apply published policies' scope to nodes.config_id so
      // late-enrolling / re-enrolled / newly grouped nodes get monitored without a
      // manual republish (re-enroll resets config_id to the server default list).
      try {
        const { reconcileAllPublishedPolicies } = await import('./services/fimService');
        const fleetDb = dataSource[1] as unknown as import('./services/fimService').FimDb;
        let fimReconcileInFlight = false;
        const fimTimer = setInterval(() => {
          if (fimReconcileInFlight) return;
          fimReconcileInFlight = true;
          reconcileAllPublishedPolicies(fleetDb, (err, policyId) => log.error({ err, policyId }, 'FIM reconcile failed for policy'))
            .catch((err) => log.error({ err }, 'FIM reconcile sweep failed'))
            // Per-node registry coverage: new nodes, group moves, waiver expiry, soft-retire purge,
            // removed nodes, invalid/needs-init alerts, daily history-chain verification.
            .then(() => import('./services/fimRegistryService'))
            .then(async (reg) => { await reg.resumeRegistryJobs(fleetDb, (msg, extra) => log.info({ ...extra }, msg)).catch((err) => log.error({ err }, 'FIM registry job resume failed')); return reg; })
            .then((reg) => reg.reconcileRegistryNodes(fleetDb, (msg, extra) => {
              if (msg === 'FIM_REG_AUTO_REPUBLISH') {
                log.info({ ...extra }, 'FIM registry automatic republish');
                import('./utils/auditTrailLogger').then(({ logAuditTrail }) => logAuditTrail({
                  action: 'FIM_REG_AUTO_REPUBLISH', status: 'success', userId: null, email: 'system', details: extra ?? null,
                })).catch(() => undefined);
              } else {
                log.error({ ...extra }, msg);
              }
            }, {
              anchor: async () => (await import('./controllers/fim/fim_registry')).historyAnchor(),
              anchorWrite: async (h) => (await import('./controllers/fim/fim_registry')).historyAnchorWriter(h),
            }))
            .catch((err) => log.error({ err }, 'FIM registry reconcile sweep failed'))
            .finally(() => { fimReconcileInFlight = false; });
        }, 60_000);
        fimTimer.unref();
        log.info('FIM config reconcile job scheduled (every 60s)');
      } catch (err) {
        log.error({ err }, 'Failed to schedule FIM config reconcile job');
      }

      // Initialize Scan Scheduler (recurring subnet discovery scans)
      try {
        const { ScanSchedulerService, setScanSchedulerServiceInstance } = await import('./services/scanSchedulerService');
        const scanSchedulerService = new ScanSchedulerService(dataSource[1]);
        setScanSchedulerServiceInstance(scanSchedulerService);
        await scanSchedulerService.initializeJobs();
        log.info('Scan scheduler background jobs initialized');
      } catch (err) {
        log.error({ err }, 'Failed to initialize scan scheduler background jobs');
      }

      // Initialize Domain Reputation scheduled-watchlist cron jobs
      try {
        const { DomainReputationSchedulerService, setDomainReputationSchedulerInstance } = await import('./services/domainReputation/scheduler');
        const domainReputationScheduler = new DomainReputationSchedulerService(dataSource[1]);
        setDomainReputationSchedulerInstance(domainReputationScheduler);
        await domainReputationScheduler.initializeJobs();
        log.info('Domain reputation background jobs initialized');
      } catch (err) {
        log.error({ err }, 'Failed to initialize domain reputation background jobs');
      }

      // Initialize Asset Identity Resolution (agent/arp/nmap/openvas/nuclei feeders)
      try {
        const { AssetResolutionService, setAssetResolutionServiceInstance } = await import('./services/assetIdentity/assetResolutionService');
        const assetResolutionService = new AssetResolutionService(dataSource[1]);
        // Registered before start() so a controller can still reach the
        // instance (runNow) even if scheduling itself throws.
        setAssetResolutionServiceInstance(assetResolutionService);
        assetResolutionService.start();
        log.info('Asset identity resolution background job initialized');
      } catch (err) {
        log.error({ err }, 'Failed to initialize asset identity resolution background job');
      }
    } else {
      log.warn(
        { dataSourceCount: dataSource.length, secondaryInitialized: dataSource[1]?.isInitialized ?? false },
        'Secondary (fleet) datasource unavailable — fleet schema bootstrap/migrations and all fleet-dependent ' +
        'background jobs (data retention, node auto-assignment, scan scheduler, domain reputation scheduler, ' +
        'asset identity resolution, orphaned scan cleanup) were skipped for this run',
      );
    }

    // Clear stale ws:ext:* keys from Redis.
    // EXTENSIONS[] is reset to null on every server start, so any Redis keys
    // from a previous run now point to stale slot indices.  If we didn't clear
    // them, a UI command arriving before the agent reconnects would find a
    // slot in Redis, check EXTENSIONS[slot]=null, and return "Agent not
    // connected" even if agent_online is already true (race window).
    const redisForCleanup = getRedisClient();
    if (redisForCleanup) {
      try {
        const staleExtKeys = await redisForCleanup.keys(`${WS_REDIS_EXT_PREFIX}*`);
        if (staleExtKeys.length > 0) {
          await redisForCleanup.del(staleExtKeys);
          log.info(`Cleared ${staleExtKeys.length} stale ws:ext:* key(s) from Redis`);
        } else {
          log.debug('No stale ws:ext:* keys found in Redis');
        }
      } catch (err) {
        log.warn({ err }, 'Could not clear stale ws:ext:* keys from Redis');
      }
    } else {
      log.warn('Redis client unavailable at startup — skipped clearing stale ws:ext:* keys (agents may briefly hit the stale-slot race until they reconnect)');
    }

    // Start live-web polling & notification timers now that the DB is available.
    // (In the original Vajra-UI these fired at module-load; starting them here
    //  ensures the first poll hits a live DB instead of retrying for seconds.)
    startupStep = 'live-web-start';
    startLiveWeb();

    startupStep = 'https-credentials-load';
    // Agents dial PORT directly (see the NOTE at PORT's definition) and each
    // agent decides ws/http vs wss/https for itself from its own local
    // extension.conf — there is no live signal telling this process which
    // scheme any given agent is about to use, and deployments (e.g. a local
    // dev box with no TLS material at all) may not be able to run HTTPS in
    // the first place. Rather than this process committing to exactly one
    // scheme and requiring every agent's config to be kept in sync with it,
    // build a single listener that accepts both plaintext and TLS on PORT
    // whenever TLS material is available, sniffing which one a given
    // connection is using from its first byte (see httpolyglot). When no
    // certs are configured at all, this degrades to a plain HTTP-only
    // listener — identical to the previous non-production behaviour.
    const keyPath  = process.env.SSL_KEY_PATH;
    const certPath = process.env.SSL_CERT_PATH;
    if (process.env.NODE_ENV === 'production' && (!keyPath || !certPath)) {
      throw new Error('SSL_KEY_PATH and SSL_CERT_PATH must be set in production');
    }

    let credentials: https.ServerOptions | undefined;
    if (keyPath && certPath) {
      credentials = {
        key:  fs.readFileSync(keyPath,  'utf8'),
        cert: fs.readFileSync(certPath, 'utf8'),
      };
      // Request (never require, at the TLS layer) an agent client cert signed
      // by the Agent CA on THIS listener directly. PORT is deliberately
      // reachable on all interfaces (see the note at PORT's definition) because
      // Go agent extensions dial it directly, bypassing nginx, so nginx's own
      // ssl_verify_client never sees real agent traffic and agentMtls.ts's
      // header check can only be a fallback. requestCert with
      // rejectUnauthorized:false mirrors nginx's `ssl_verify_client optional` at
      // this layer: browsers and API clients presenting no cert for this private
      // CA complete the handshake unaffected, while a genuine agent cert is
      // verified by Node's TLS stack and exposed on req.socket.authorized and
      // getPeerCertificate() for agentMtls.ts. Enforcement itself remains staged
      // through AGENT_MTLS_MODE.
      if (caCertAvailable()) {
        credentials.ca = getAgentCaCertPem();
        credentials.requestCert = true;
        credentials.rejectUnauthorized = false;
        log.info('Agent CA loaded — requesting client certs on the TLS branch of the dual-protocol listener');
      } else {
        log.warn('Agent CA not provisioned — agent client certificates can never be verified at the TLS layer (see AGENT_CA_DIR in .env.example)');
      }
      server = httpolyglot.createServer({ tls: credentials }, app);
      log.info('Dual-protocol server created — accepting both plain HTTP/WS and HTTPS/WSS on the same port');
    } else {
      // No TLS material configured anywhere — e.g. a local dev box with no
      // HTTPS capability at all. Plaintext-only, same as before.
      server = httpolyglot.createServer(app);
      log.warn('No SSL_KEY_PATH/SSL_CERT_PATH configured — serving plain HTTP only (no TLS capability on this deployment)');
    }

    startupStep = 'server-listen';
    server.listen(PORT, () => {
      log.info(`Server running at ${PORT}`);
    });

    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        log.error(`Port ${PORT} is already in use. Kill the existing process and retry.`);
        process.exit(1);
      } else {
        log.error({ err }, `HTTP server failed to start (${err.code})`);
        throw err;
      }
    });

    // ========================================
    // 9. WEBSOCKET SERVER
    // ========================================
    startupStep = 'websocket-server-setup';
    // Create separate WSS instances (noServer mode) for path-based routing.
    // Assigned to module-level vars so gracefulShutdown can call .close() on them.
    wssNodeUi      = new WebSocketServer({ noServer: true, maxPayload: WS_MAX_PAYLOAD_BYTES });
    wssNodeExt     = new WebSocketServer({ noServer: true, maxPayload: WS_MAX_PAYLOAD_BYTES });
    wssLive        = new WebSocketServer({ noServer: true, maxPayload: WS_MAX_PAYLOAD_BYTES });
    // ── WebSocket heartbeat (ping/pong) ──────────────────────────────────────
    // NAT devices and firewalls silently drop idle TCP connections (typically
    // after 60–120 s).  Without pings the server never detects the dead socket;
    // the browser eventually reconnects, accumulating stale "live" entries in
    // DevTools.  A 25-second ping interval keeps every connection alive through
    // even the most aggressive NAT and lets us terminate truly dead sockets fast.
    //
    // /ws/ext is heartbeated deliberately. Agent extensions answer PING at the
    // protocol layer, and the heartbeat does two jobs for them: it detects
    // zombie agent sockets, where power loss or a kernel kill means no FIN ever
    // arrives, and the resulting pongs drive refreshExtRouting() in
    // websocket/node.ts, which keeps the ws:ext:{hostId} Redis routing key's 24h
    // TTL from expiring under a long-lived connection. Do not remove it without
    // replacing both functions.
    const HEARTBEAT_MS = WS_HEARTBEAT_INTERVAL_MS;

    function startHeartbeat(wss: WebSocketServer, label: string): ReturnType<typeof setInterval> {
      return setInterval(() => {
        const totalClients = (wss.clients as Set<WsWebSocket>).size;
        let deadCount = 0;
        (wss.clients as Set<WsWebSocket>).forEach((ws: WsWebSocket) => {
          const socket = ws as WsWebSocket & { _hbAlive?: boolean };
          if (socket._hbAlive === false) {
            // No pong since the last ping, so terminate. Not logged per
            // connection: there is no per-socket identifier here, so N lines
            // would be indistinguishable from each other and the batch summary
            // below already reports how many of the pool died this tick.
            deadCount++;
            ws.terminate();
            return;
          }
          socket._hbAlive = false;
          ws.ping();
        });
        // Batch outcome summary — a mass NAT/network drop can terminate dozens of
        // sockets in the same 25s tick; this reports exactly how many of the pool
        // it took out, which a single flaky client would not.
        if (deadCount > 0) {
          log.warn({ wss: label, deadCount, totalClients }, 'heartbeat: tick summary, dead connections terminated');
        }
      }, HEARTBEAT_MS);
    }

    hbLive        = startHeartbeat(wssLive!, 'live');
    hbNodeUi      = startHeartbeat(wssNodeUi!, 'node-ui');
    hbNodeExt     = startHeartbeat(wssNodeExt!, 'node-ext');

    /**
     * Attach a socket-level 'error' listener.
     *
     * On an EventEmitter, an 'error' event with no listener is re-thrown. For a
     * WebSocket that means a routine per-connection fault — an ECONNRESET mid-send,
     * a TLS reset, a protocol violation — surfaces as an uncaught exception, and
     * the process.on('uncaughtException') handler below responds by calling
     * gracefulShutdown(). One flaky or hostile connection would therefore drop
     * every agent connection, dashboard session on the server.
     *
     * Attached synchronously in each 'connection' handler rather than inside the
     * per-channel modules: nodeUi/liveWeb are async, so a listener they
     * add themselves leaves a window between the socket opening and the first
     * await resolving in which an error is still fatal. (liveWeb.ts also attaches
     * its own for cleanup; both run, which is fine.)
     */
    const guardWsErrors = (ws: WsWebSocket, req: unknown, channel: string) => {
      ws.on('error', (err: Error) => {
        log.warn({ err, channel, remoteAddress: (req as any)?.socket?.remoteAddress }, 'WS socket error — connection dropped, server continues');
      });
    };

    // Wire up connection handlers
    wssNodeUi!.on('connection', (ws: WsWebSocket, req) => {
      guardWsErrors(ws, req, 'node-ui');
      (ws as WsWebSocket & { _hbAlive?: boolean })._hbAlive = true;
      ws.on('pong', () => { (ws as WsWebSocket & { _hbAlive?: boolean })._hbAlive = true; });
      nodeUi(ws as unknown as WsLike, req as unknown as ReqLike);
    });
    wssNodeExt!.on('connection', (ws: WsWebSocket, req) => {
      guardWsErrors(ws, req, 'node-ext');
      (ws as WsWebSocket & { _hbAlive?: boolean })._hbAlive = true;
      ws.on('pong', () => { (ws as WsWebSocket & { _hbAlive?: boolean })._hbAlive = true; });
      nodeExt(ws as unknown as WsLike, req as unknown as ReqLike);
    });
    wssLive!.on('connection', (ws: WsWebSocket, req) => {
      guardWsErrors(ws, req, 'live');
      (ws as WsWebSocket & { _hbAlive?: boolean })._hbAlive = true;
      ws.on('pong', () => { (ws as WsWebSocket & { _hbAlive?: boolean })._hbAlive = true; });
      liveWeb(ws as unknown as LiveWebWsLike, req as unknown as ReqLike).catch((err) => {
        // remoteAddress included because wssLive can hold many concurrent
        // connections and liveWeb.ts itself has no internal logging — without
        // an identifier here, two different clients' failures are indistinguishable.
        log.error({ err, remoteAddress: (req as any)?.socket?.remoteAddress }, 'liveWeb connection error');
      });
    });
    /**
     * Verifies the JWT cookies presented on a WebSocket upgrade. This is the auth
     * gate for /ws/ui and /ws/live.
     *
     * Mirrors checkAccessWithRefreshFallback:
     * 1. Blacklist check on both tokens, so logged-out users are rejected.
     * 2. Try the access token; if expired, fall through to the refresh token.
     * 3. Validate session_version against the database, so tokens issued before
     *    a password change are rejected as they are on HTTP routes.
     *
     * Fails closed: any database error, missing row or unexpected throw returns
     * false and the upgrade is refused, matching validateSessionVersion in
     * middleware/checkJwt.ts.
     */
    async function verifyWsJwt(request: any, wsPath: string): Promise<boolean> {
      // Tracks which stage of the multi-step auth check is in flight, mirroring
      // startupStep/shutdownStep above — the refresh-token jwt.verify() call in
      // step 4 below isn't individually try/caught, so without this, a rejected/
      // expired/malformed refresh token and a genuinely unexpected bug elsewhere
      // in this function both fall into the same generic catch-all log line.
      //
      // wsPath is threaded through every log line below because this function is
      // shared by two endpoints (/ws/ui, /ws/live) — without it,
      // concurrent auth failures on different endpoints interleave in the log
      // stream as identical "WS auth: ..." lines with no way to tell which
      // upgrade request each one belongs to.
      let authStep = 'cookie-parse';
      try {
        const cookieHeader = request.headers.cookie;
        if (!cookieHeader) {
          log.info({ path: wsPath }, 'WS auth: no cookie header present, failing closed');
          return false;
        }

        const cookies = parseCookies(cookieHeader);

        const accessToken  = cookies[ACCESS_TOKEN_COOKIE];
        const refreshToken = cookies[REFRESH_TOKEN_COOKIE];

        // 1. Upfront blacklist check: reject immediately if either token is revoked
        //    (mirrors checkAccessWithRefreshFallback — don't fall through to refresh
        //    when the access token was deliberately invalidated at logout).
        const redis = getRedisClient();
        authStep = 'access-token-blacklist-check';
        if (accessToken) {
          if (isTokenBlacklistedMemory(accessToken) || (redis && await isTokenBlacklisted(accessToken))) {
            log.info({ path: wsPath }, 'WS auth: access token is blacklisted (logged out), failing closed');
            return false;
          }
        }
        authStep = 'refresh-token-blacklist-check';
        if (refreshToken) {
          if (isTokenBlacklistedMemory(refreshToken) || (redis && await isTokenBlacklisted(refreshToken))) {
            log.info({ path: wsPath }, 'WS auth: refresh token is blacklisted (logged out), failing closed');
            return false;
          }
        }

        // 2. Helper: validate session_version to reject post-password-change tokens
        async function validateSession(payload: JwtPayload): Promise<boolean> {
          if (!dataSource || dataSource.length === 0 || !dataSource[0].isInitialized) {
            log.warn({ userId: payload.id, path: wsPath }, 'WS auth: primary datasource unavailable, failing closed');
            return false; // fail-closed when DB unavailable
          }
          try {
            const rows: { session_version: number; suspended: boolean }[] = await dataSource[0].query(
              'SELECT session_version, suspended FROM vajra_users WHERE id = $1',
              [payload.id],
            );
            if (!rows || rows.length === 0) {
              log.warn({ userId: payload.id, path: wsPath }, 'WS auth: token references a deleted user, failing closed');
              return false; // user deleted
            }
            if (rows[0].suspended) {
              log.warn({ userId: payload.id, path: wsPath }, 'WS auth: token belongs to a suspended user, failing closed');
              return false;
            }
            const sessionMatches = rows[0].session_version === (payload.session_version ?? 0);
            if (!sessionMatches) {
              log.info({ userId: payload.id, path: wsPath }, 'WS auth: session_version mismatch (stale token from before a password change), failing closed');
            } else {
              // Every rejection branch above and below logs; without this, a
              // successful WS auth is silent and indistinguishable from "no
              // upgrade attempt happened at all" — the only other signal for
              // this path is the eventual downstream WS 'connection' handler
              // (websocket/*.ts), which does not log either.
              log.info({ userId: payload.id, path: wsPath }, 'WS auth: session validated, upgrade allowed');
            }
            return sessionMatches;
          } catch (err) {
            log.warn({ err, userId: payload.id, path: wsPath }, 'WS auth: session_version lookup failed, failing closed');
            return false; // fail-closed on transient DB error
          }
        }

        // 3. Try access token first (fast path)
        authStep = 'access-token-verify';
        if (accessToken) {
          try {
            const payload = jwt.verify(accessToken, process.env.ACCESS_JWT_SECRET as string, { algorithms: [JWT_ALGORITHM] }) as JwtPayload;
            authStep = 'access-token-session-validate';
            // Reject the interim MFA-challenge token (see isMfaChallengeToken
            // in middleware/checkJwt.ts): it verifies against this same
            // secret but represents a password-only session.
            if (isMfaChallengeToken(payload)) return false;
            return await validateSession(payload);
          } catch (err) {
            if (!(err instanceof TokenExpiredError)) {
              log.warn({ err, path: wsPath }, 'WS auth: access token verification failed (not simple expiry), failing closed');
              return false; // bad signature etc.
            }
            // Access token expired — fall through to refresh token. Logged (rather
            // than left as a comment-only branch) because from logs alone this is
            // otherwise indistinguishable from "no access token cookie was sent at
            // all", which takes the same step-4 fallback path below.
            log.debug({ path: wsPath }, 'WS auth: access token expired, falling back to refresh token');
          }
        }

        // 4. Fallback: try refresh token (matches HTTP middleware behaviour)
        authStep = 'refresh-token-verify';
        if (refreshToken) {
          const payload = jwt.verify(refreshToken, process.env.REFRESH_JWT_SECRET as string, { algorithms: [JWT_ALGORITHM] }) as JwtPayload;
          authStep = 'refresh-token-session-validate';
          return await validateSession(payload);
        }

        log.info(
          { hadAccessToken: Boolean(accessToken), hadRefreshToken: Boolean(refreshToken), path: wsPath },
          'WS auth: no usable access or refresh token cookie found, failing closed',
        );
        return false;
      } catch (err) {
        // Catches, among other things, a rejected/expired/malformed refresh
        // token from step 4 above (that jwt.verify call isn't individually
        // try/caught) — authStep pins down which stage actually threw, since
        // otherwise every one of these produces the exact same generic log line.
        log.warn({ err, step: authStep, path: wsPath }, 'WS auth: unexpected error verifying session, failing closed');
        return false;
      }
    }

    // Browser-facing WS endpoints (/ws/ui, /ws/live) authenticate purely via
    // cookie + JWT, with no per-message CSRF token the way REST POSTs have —
    // so the upgrade itself must reject a foreign Origin rather than relying
    // solely on SameSite cookie behavior, which varies by browser/version.
    // Reuses the same allowlist the CORS middleware above already computed.
    const isAllowedWsOrigin = (request: any): boolean => {
      const origin = request.headers.origin;
      if (!origin) return true; // non-browser clients (agents, CLI) send no Origin
      return allowedOrigins.includes(origin);
    };

    // PORT now accepts both plaintext and TLS connections on the same
    // listener (see the dual-protocol server created above) so that no agent
    // ever needs its local websocket_secure config kept in sync with this
    // server's TLS mode. That is deliberate for the default AGENT_MTLS_MODE
    // ('off'/'optional'), but a connection with no TLS at all can never carry
    // a client certificate — so under 'required' mode it is rejected here,
    // before even calling verifyAgentMtls(), so the log reason says "no TLS"
    // instead of being indistinguishable from "no cert presented". Every
    // plaintext agent connection is logged regardless of mode: on a
    // deployment that does have TLS material configured, a plaintext agent
    // connection is unusual enough to be worth an operator's attention, while
    // on a deployment with no TLS material at all (e.g. local dev) it is
    // simply the expected, only-possible path.
    const rejectPlaintextIfMtlsRequired = (request: any, socket: any, label: string): boolean => {
      const encrypted = !!request.socket?.encrypted;
      if (encrypted) return false;
      log.info({ hostId: agentInfoHostId(request), remoteAddress: request.socket?.remoteAddress }, `${label} connected over plaintext (no TLS)`);
      if (agentMtlsMode() === 'required') {
        log.warn({ hostId: agentInfoHostId(request) }, `${label} upgrade rejected: AGENT_MTLS_MODE=required but connection has no TLS (a client certificate cannot be presented over plaintext)`);
        if (!socket.destroyed) {
          socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
          socket.destroy();
        }
        return true;
      }
      return false;
    };

    // /ws/ui and /ws/live are
    // strictly browser-facing — unlike the agent paths above, there is no
    // reason a legitimate browser session should ever reach PORT in
    // plaintext on a deployment that has TLS configured (nginx always
    // terminates real HTTPS for browsers and proxies to PORT over HTTPS
    // itself — see deploy/nginx/nginx-https.conf.example — so a plaintext connection here means someone
    // is hitting PORT directly, bypassing nginx's TLS entirely). Reject
    // outright rather than merely logging, mirroring the REST equivalent
    // (the plaintext transport guard registered as Express middleware
    // above/earlier in this file). A deployment with no TLS material
    // configured at all (e.g. local dev) is unaffected — plaintext is simply
    // the only thing that can ever work there.
    const rejectPlaintextBrowserWs = (request: any, socket: any, label: string): boolean => {
      if (!deploymentHasTls) return false;
      if (request.socket?.encrypted) return false;
      log.warn({ remoteAddress: request.socket?.remoteAddress }, `${label} upgrade rejected: plaintext connection on a TLS-configured deployment`);
      if (!socket.destroyed) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
      }
      return true;
    };

    // Route HTTP upgrade requests to the correct WSS by pathname
    server.on('upgrade', async (request: any, socket: any, head: any) => {
      try {
        const { pathname } = new URL(request.url || '/', `http://${request.headers.host}`);

        if (pathname === '/ws/ui') {
          if (rejectPlaintextBrowserWs(request, socket, '/ws/ui')) return;
          if (!isAllowedWsOrigin(request)) {
            log.warn({ origin: request.headers.origin }, '/ws/ui upgrade rejected: origin not allowed');
            if (!socket.destroyed) {
              socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
              socket.destroy();
            }
            return;
          }
          // Authenticate UI clients via JWT cookie (blacklist + session_version checked)
          if (!(await verifyWsJwt(request, pathname))) {
            log.warn('/ws/ui upgrade rejected: missing or invalid session');
            if (!socket.destroyed) {
              socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
              socket.destroy();
            }
            return;
          }
          wssNodeUi!.handleUpgrade(request, socket, head, (ws) => {
            wssNodeUi!.emit('connection', ws, request);
          });
        } else if (pathname === '/ws/ext') {
          // Agent connections authenticate by mTLS client certificate (CN =
          // host_identifier), verified at nginx and passed via headers. Gated by
          // AGENT_MTLS_MODE (off|optional|required) so enabling it never locks
          // out a fleet that is still enrolling; 'off' is a no-op.
          if (rejectPlaintextIfMtlsRequired(request, socket, '/ws/ext')) return;
          const mtlsReject = verifyAgentMtls(request, agentInfoHostId(request));
          if (mtlsReject) {
            log.warn({ hostId: agentInfoHostId(request), mode: agentMtlsMode(), reason: mtlsReject }, '/ws/ext mTLS rejected');
            if (!socket.destroyed) {
              socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
              socket.destroy();
            }
            return;
          }
          // In the default AGENT_MTLS_MODE='off', verifyAgentMtls() above returns
          // null (allowed) without logging anything — so without this line, an
          // agent's successful /ws/ext connection is completely silent and
          // indistinguishable from "no agent ever tried to connect".
          log.info({ hostId: agentInfoHostId(request) }, '/ws/ext upgrade accepted');
          wssNodeExt!.handleUpgrade(request, socket, head, (ws) => {
            wssNodeExt!.emit('connection', ws, request);
          });
        } else if (pathname === '/ws/live') {
          if (rejectPlaintextBrowserWs(request, socket, '/ws/live')) return;
          if (!isAllowedWsOrigin(request)) {
            log.warn({ origin: request.headers.origin }, '/ws/live upgrade rejected: origin not allowed');
            if (!socket.destroyed) {
              socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
              socket.destroy();
            }
            return;
          }
          // Authenticate live dashboard clients via JWT cookie (blacklist + session_version checked)
          if (!(await verifyWsJwt(request, pathname))) {
            log.warn('/ws/live upgrade rejected: missing or invalid session');
            if (!socket.destroyed) {
              socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
              socket.destroy();
            }
            return;
          }
          wssLive!.handleUpgrade(request, socket, head, (ws) => {
            wssLive!.emit('connection', ws, request);
          });
        } else {
          // Unknown WS path – reject
          log.warn({ pathname }, 'WS upgrade rejected: unknown path');
          if (!socket.destroyed) socket.destroy();
        }
      } catch (err) {
        log.error({ err, url: request.url }, 'WS upgrade error');
        if (!socket.destroyed) {
          socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
          socket.destroy();
        }
      }
    });

    log.info('WebSocket server mounted on /ws/ui, /ws/ext, /ws/live');

    // Graceful shutdown handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason: any, _promise: Promise<any>) => {
      log.error({ err: reason }, 'Unhandled Rejection');
      // Log but don't exit - allow the application to continue
    });

    // Handle uncaught exceptions
    process.on('uncaughtException', (error: Error) => {
      // WS max-payload errors are per-connection, not fatal — log at warn and
      // continue. Checked before the fatal log below (not after) so this routine,
      // fully-handled, non-fatal condition is never reported at 'fatal' severity —
      // that level is reserved for exceptions that actually trigger a shutdown, and
      // misreporting a handled per-connection error as fatal would misdirect anyone
      // paging off the log level as if the process were about to go down.
      if (error instanceof RangeError && error.message?.includes('Max payload size exceeded')) {
        log.warn({ err: error }, 'WS max payload exceeded — connection will be dropped, server continues.');
        return;
      }

      log.fatal({ err: error }, 'Uncaught Exception');

      // Trigger graceful shutdown on truly fatal exceptions
      gracefulShutdown('UNCAUGHT_EXCEPTION');
    });
    
  } catch (error) {
    log.fatal({ err: error, step: startupStep }, 'Error during startup');
    process.exit(1);
  }
})();
