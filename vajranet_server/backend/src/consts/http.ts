/** HTTP status code constants. */

export const STATUS_OK = 200;
export const STATUS_BAD_REQUEST = 400;
export const STATUS_UNAUTHORIZED = 401;
export const STATUS_FORBIDDEN = 403;
export const STATUS_NOT_FOUND = 404;
export const STATUS_CONFLICT = 409;
export const STATUS_UNPROCESSABLE_ENTITY = 422;
export const STATUS_TOO_MANY_REQUESTS = 429;
export const STATUS_FAILED_DEPENDENCY = 424;
export const STATUS_INTERNAL_SERVER_ERROR = 500;
export const STATUS_SERVICE_UNAVAILABLE = 503;
export const STATUS_GATEWAY_TIMEOUT = 504;

// Shared error response strings used by the Windows telemetry read endpoints
// (bios_info, firewall_rules, secureboot, tpm_info, system_info, etc.) that
// all validate host_identifier / DB connection / node scope / query failure
// the same way.
export const ERROR_MISSING_HOST_IDENTIFIER = "Missing or invalid host_identifier";
export const ERROR_DATABASE_CONNECTION = "Database connection error";
export const ERROR_NODE_NOT_FOUND = "Node not found";
export const ERROR_DATABASE_FETCH_FAILED = "Database fetch failed.";

// Matches an https:// URL prefix (case-sensitive). Used to reject non-https
// artifact/archive URLs before they're trusted by an agent or fetched by the
// server.
export const HTTPS_URL_PATTERN = /^https:\/\//;
