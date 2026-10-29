/** Server and Express app literal constants (no env). */

import path from 'path';

export const DEFAULT_PORT = 4000;
export const REQUEST_TIMEOUT_MS = 30000;
export const COMPRESSION_LEVEL = 6;
export const COMPRESSION_THRESHOLD_BYTES = 1024;
export const BODY_LIMIT = '10kb';

// Route-specific body-parser overrides (default BODY_LIMIT above is too small for these).
export const AI_CHAT_BODY_LIMIT = '5mb';
export const PATCH_BUNDLE_BODY_LIMIT = '25mb';
export const AVATAR_UPLOAD_BODY_LIMIT = '256kb';

export const CORS_DEFAULT_ORIGIN = 'http://localhost:5173';

// Route path (mounted under /api/agent) where built Patch Bundle archives are
// served from — used both to construct archive_url in the build response and
// to register the download route.
export const PATCH_ARCHIVE_ROUTE_PATH = '/api/agent/patch-archives/';

// Default directory for locally-generated signing/verification keypairs
// (patch-bundle/update verify keys, agent CA)
// when no env override is set. All consumers live directly under src/<dir>/,
// so __dirname here resolves the same backend/keys path they each compute.
export const DEFAULT_KEYS_DIR = path.join(__dirname, '..', '..', 'keys');

// Locale used to format all user-facing dates/timestamps server-side.
export const DEFAULT_LOCALE = 'en-IN';
// IANA timezone explicitly applied where display must be pinned to India
// Standard Time regardless of the server process's own local timezone.
export const DEFAULT_DISPLAY_TIMEZONE = 'Asia/Kolkata';

// Directory holding server-rendered EJS report templates (framework/org
// compliance PDFs), resolved relative to the process's working directory —
// same base dir generateFrameworkReport.ts and reports.ts each build their
// template path from.
export const TEMPLATES_DIR = path.resolve(process.cwd(), '..', 'templates');

export const HEALTH_STATUS_UNKNOWN = 'unknown';
export const HEALTH_STATUS_CONNECTED = 'connected';
export const HEALTH_STATUS_DISCONNECTED = 'disconnected';
export const HEALTH_STATUS_ERROR = 'error';

// Poll cadence for the node auto-assignment scheduler (Super Admin managed IP -> group rules).
export const NODE_AUTO_ASSIGN_CRON_EXPRESSION = '*/5 * * * *';
