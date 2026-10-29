/** Pagination literal constants for data-query endpoints (no env). */

/** Default number of rows returned per page. */
export const PAGINATION_DEFAULT_ROWS = 100;

/** Maximum rows per page for alert endpoints. */
export const PAGINATION_MAX_ROWS_ALERTS = 500;

/** Maximum rows per page for domain-reputation check-history endpoints. */
export const PAGINATION_MAX_ROWS_DOMAIN_REPUTATION = 500;

/** Maximum rows per page for vulnerability listing endpoints. */
export const PAGINATION_MAX_ROWS_VULNERABILITIES = 500;

/** Maximum rows per page for node list endpoints. */
export const PAGINATION_MAX_ROWS_NODES = 1000;

/** Maximum rows returned by token listing endpoints (uninstall/cert-provisioning tokens). */
export const TOKEN_LIST_MAX_ROWS = 100;

/** Maximum rows returned by org-level compliance history endpoints (certin/irdai/sebi/org). */
export const COMPLIANCE_ORG_HISTORY_MAX_ROWS = 50;

/** Maximum rows returned by per-node compliance history endpoints (certin/irdai/sebi/generic). */
export const NODE_COMPLIANCE_HISTORY_MAX_ROWS = 30;

/** Default/max rows for patch bundle and patch job list endpoints. */
export const PATCH_LIST_DEFAULT_ROWS = 200;

/** Max length (chars) a patch job reason/failure_reason string is truncated to before storage. */
export const PATCH_REASON_MAX_LENGTH = 500;

/**
 * Defense-in-depth cap on fleet-wide (no host filter) patch-related row
 * responses — a single-host query is naturally bounded by that host's own
 * row count and is never capped. Shared by patch_management.ts's
 * available-updates listing and patch_gap.ts's software-inventory gap query.
 */
export const PATCH_FLEETWIDE_ROW_LIMIT = 10_000;

/** Default rows per page (when no `limit` query param is given) for audit-trail, session-history, and alert-audit-trail listing endpoints. */
export const PAGINATION_DEFAULT_ROWS_AUDIT = 20;

/** Maximum rows per page for basic audit-trail and session-history listing endpoints. */
export const PAGINATION_MAX_ROWS_AUDIT_TRAIL = 100;

/** Maximum rows per page for admin-activity listing endpoints (alert audit trail, session actions, policy management). */
export const PAGINATION_MAX_ROWS_ADMIN_ACTIVITY = 200;
