/**
 * API Endpoint URLs Configuration
 * Centralized location for all API endpoints
 * 
 * This file contains all API endpoint URLs used throughout the application.
 * URLs are constructed using environment variables from .env file.
 */

// Get API base URL from environment variables
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000';
const API_PREFIX = '/api';

/**
 * Authentication API Endpoints
 */
// Instance & deployment endpoints removed — frontend now only uses auth APIs

/**
 * Nodes / Node sheet API paths (relative to api baseURL).
 * Used by NodesView and sub-pages (Details, Graph, etc.)
 */
export const NODES_URLS = {
  RENAME: `${API_BASE_URL}${API_PREFIX}/nodes/rename`,
  CRITICAL: `${API_BASE_URL}${API_PREFIX}/nodes/critical`,
  UNCRITICAL: `${API_BASE_URL}${API_PREFIX}/nodes/uncritical`,
  NODE: `${API_BASE_URL}${API_PREFIX}/nodes/details/`,
  NODES_LIST: `${API_BASE_URL}${API_PREFIX}/nodes/list`,
  NODES_IDENTIFIERS: `${API_BASE_URL}${API_PREFIX}/nodes/identifiers`,
  // Caller's own group memberships with per-group role (Group Admin vs
  // view-only Group Viewer) — used to disable act-level UI (e.g. Remote
  // Shell's Connect) for nodes the caller can only view, not act on.
  MY_GROUP_ROLES: `${API_BASE_URL}${API_PREFIX}/nodes/my-group-roles`,
  NODES_EXPORT: `${API_BASE_URL}${API_PREFIX}/nodes/export`,
  // Group names in the caller's node-group scope (empty for a Super Admin's
  // "no groups assigned to filter by" case as well as an unrestricted/all view).
  GROUPS: `${API_BASE_URL}${API_PREFIX}/nodes/groups`,
  IP_LIST: `${API_BASE_URL}${API_PREFIX}/nodes/ip`,
  PROGRAMS_LIST: `${API_BASE_URL}${API_PREFIX}/nodes/programs`,
  CONFIG_LIST: `${API_BASE_URL}${API_PREFIX}/nodes/config`,
  CONFIG_UPDATE: `${API_BASE_URL}${API_PREFIX}/nodes/config`,
  EVENTS_COUNT: `${API_BASE_URL}${API_PREFIX}/nodes/events/count`,
  ALERT_COUNT: `${API_BASE_URL}${API_PREFIX}/nodes/alerts/count`,
  WEEKLY_ALERTS_COUNT: `${API_BASE_URL}${API_PREFIX}/nodes/alerts/weekly`,
  MITRE_ANALYSIS: `${API_BASE_URL}${API_PREFIX}/nodes/mitre`,
  SEVERITY_COUNT: `${API_BASE_URL}${API_PREFIX}/nodes/severity/count`,
  // Compliance — append host_identifier directly: COMPLIANCE_LATEST + hostId
  COMPLIANCE_LATEST:  `${API_BASE_URL}${API_PREFIX}/nodes/compliance/latest/`,
  COMPLIANCE_HISTORY: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/history/`,
  // Org-level compliance snapshots (historical_compliance table)
  ORG_COMPLIANCE_HISTORY:  `${API_BASE_URL}${API_PREFIX}/nodes/compliance/org/history`,
  ORG_COMPLIANCE_SNAPSHOT: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/org/snapshot`,
  // SEBI compliance snapshots
  SEBI_COMPLIANCE_HISTORY:  `${API_BASE_URL}${API_PREFIX}/nodes/compliance/sebi/history`,
  SEBI_COMPLIANCE_SNAPSHOT: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/sebi/snapshot`,
  // IRDAI compliance snapshots
  IRDAI_COMPLIANCE_HISTORY:  `${API_BASE_URL}${API_PREFIX}/nodes/compliance/irdai/history`,
  IRDAI_COMPLIANCE_SNAPSHOT: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/irdai/snapshot`,
  // CERT-IN compliance snapshots
  CERTIN_COMPLIANCE_HISTORY:  `${API_BASE_URL}${API_PREFIX}/nodes/compliance/certin/history`,
  CERTIN_COMPLIANCE_SNAPSHOT: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/certin/snapshot`,
  // SEBI compliance for individual node (append host_identifier directly)
  SEBI_NODE_COMPLIANCE_LATEST:  `${API_BASE_URL}${API_PREFIX}/nodes/compliance/sebi/latest/`,
  SEBI_NODE_COMPLIANCE_HISTORY: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/sebi/history/`,
  SEBI_NODE_COMPLIANCE_SNAPSHOT: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/sebi/node-snapshot/`,
  // IRDAI compliance for individual node (append host_identifier directly)
  IRDAI_NODE_COMPLIANCE_LATEST:  `${API_BASE_URL}${API_PREFIX}/nodes/compliance/irdai/latest/`,
  IRDAI_NODE_COMPLIANCE_HISTORY: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/irdai/history/`,
  IRDAI_NODE_COMPLIANCE_SNAPSHOT: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/irdai/node-snapshot/`,
  // CERT-IN compliance for individual node (append host_identifier directly)
  CERTIN_NODE_COMPLIANCE_LATEST:  `${API_BASE_URL}${API_PREFIX}/nodes/compliance/certin/latest/`,
  CERTIN_NODE_COMPLIANCE_HISTORY: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/certin/history/`,
  CERTIN_NODE_COMPLIANCE_SNAPSHOT: `${API_BASE_URL}${API_PREFIX}/nodes/compliance/certin/node-snapshot/`,
  // WiFi telemetry — append host_identifier directly: WIFI_LATEST + hostId
  WIFI_LATEST: `${API_BASE_URL}${API_PREFIX}/nodes/wifi/`,
  STORAGE: `${API_BASE_URL}${API_PREFIX}/nodes/storage/`,
  // Linux firewall status (ufw / firewalld) — all nodes
  FIREWALL_STATUS: `${API_BASE_URL}${API_PREFIX}/nodes/firewall-status`,
  // Network posture — append host_identifier directly (listening ports also takes ?limit=&offset=)
  NETWORK_LISTENING_PORTS: `${API_BASE_URL}${API_PREFIX}/nodes/network/listening-ports/`,
  NETWORK_UPTIME: `${API_BASE_URL}${API_PREFIX}/nodes/network/uptime/`,
} as const;

/** WebSocket base URL for node agent/real-time (when backend provides WS) */
export const NODES_WS_BASE =
  import.meta.env.VITE_WS_BASE_URL || (API_BASE_URL.replace(/^http/, 'ws') + '/ws');

/**
 * Users API (audit trail, etc.)
 */
export const USERS_URLS = {
  AUDIT_TRAIL: `${API_BASE_URL}${API_PREFIX}/users/audit-trail`,
  LIST: `${API_BASE_URL}${API_PREFIX}/users/list`,
} as const;

/**
 * Alerts / Alert sheet API paths (relative to api baseURL).
 * Used by AlertsView and sub-pages (Metadata, Graph, Signal Table, etc.)
 */
export const ALERTS_URLS = {
  ALERTS_LIST: `${API_BASE_URL}${API_PREFIX}/alerts/list`,
  CLAMAV_SUMMARY: `${API_BASE_URL}${API_PREFIX}/alerts/clamav-summary`,
  CLAMAV_SCAN_LATEST: `${API_BASE_URL}${API_PREFIX}/alerts/clamav-scan-latest`,
  BY_ID: '/alerts/by-id',
  QUERY: '/alerts/query',
  ASSIGNEE: '/alerts/assignee',
  UPDATE: '/alerts/update',
  STATUS: '/alerts/status',
  EXPORT: '/alerts/export',
} as const;

/**
 * Windows-specific API endpoints
 * Used for Windows node security and system information
 */
export const WINDOWS_URLS = {
  PROFILE_INFO: `${API_BASE_URL}${API_PREFIX}/windows/profile_info`,
  FIREWALL_RULES: `${API_BASE_URL}${API_PREFIX}/windows/firewall_rules`,
  FIREWALL_RULES_DIFF: `${API_BASE_URL}${API_PREFIX}/windows/firewall_rules_diff`,
  TPM_INFO: `${API_BASE_URL}${API_PREFIX}/windows/tpm_info`,
  SECUREBOOT_INFO: `${API_BASE_URL}${API_PREFIX}/windows/secureboot`,
  BIOS_INFO: `${API_BASE_URL}${API_PREFIX}/windows/bios_info`,
  UPDATE_HISTORY: `${API_BASE_URL}${API_PREFIX}/windows/update_history`,
  LATEST_UPDATE: `${API_BASE_URL}${API_PREFIX}/windows/latest_update`,
} as const;

/**
 * Graph API endpoints
 * Used for dashboard and analytics visualizations
 */
export const GRAPH_URLS = {
  SEVERITY: `${API_BASE_URL}${API_PREFIX}/graph/severity`,
  WEEKLY_ALERTS: `${API_BASE_URL}${API_PREFIX}/graph/weekly_alerts`,
  ALERT_STATUS: `${API_BASE_URL}${API_PREFIX}/graph/alert_status`,
  OS_COUNT: `${API_BASE_URL}${API_PREFIX}/graph/os_count`,
  DEFENDER_COUNT: `${API_BASE_URL}${API_PREFIX}/graph/defender_count`,
  TOP5_MACHINE_ALERTS: `${API_BASE_URL}${API_PREFIX}/graph/top5_machine_alerts`,
  TOP5_MACHINE_USB: `${API_BASE_URL}${API_PREFIX}/graph/top5_machine_usb`,
  MEMORY_GRAPH: `${API_BASE_URL}${API_PREFIX}/graph/memory_graph`,
  FIREWALL_DIFF: `${API_BASE_URL}${API_PREFIX}/graph/firewall_diff`,
  NODE_COMPLIANCE_LATEST: `${API_BASE_URL}${API_PREFIX}/graph/node_compliance_latest`,
} as const;

/**
 * Export base URL and prefix for direct use if needed
 */
export { API_BASE_URL, API_PREFIX };

/**
 * AI Assistant endpoints
 */
export const AI_URLS = {
  CHAT:           `${API_BASE_URL}${API_PREFIX}/ai/chat`,
  SESSIONS:       `${API_BASE_URL}${API_PREFIX}/ai/sessions`,
  SESSION:        (id: number) => `${API_BASE_URL}${API_PREFIX}/ai/sessions/${id}`,
  PENDING:        `${API_BASE_URL}${API_PREFIX}/ai/pending`,
  CONFIRM_ACTION: `${API_BASE_URL}${API_PREFIX}/ai/confirm`,
  CANCEL_ACTION:  `${API_BASE_URL}${API_PREFIX}/ai/pending`,
} as const;

/**
 * Threat Hunting API endpoints
 * Run ad-hoc SELECT queries against the fleet DB and manage saved queries.
 */
export const THREAT_HUNTING_URLS = {
  RUN:     `${API_BASE_URL}${API_PREFIX}/threat-hunting/run`,
  QUERIES: `${API_BASE_URL}${API_PREFIX}/threat-hunting/queries`,
  QUERY:   (id: number) => `${API_BASE_URL}${API_PREFIX}/threat-hunting/queries/${id}`,
  POPULATE_DEFAULT_QUERIES: `${API_BASE_URL}${API_PREFIX}/threat-hunting/queries/populate-saved-queries`,
} as const;

/**
 * Uninstall Token API endpoints
 * MFA-protected token generation / revocation for supervised agent removal.
 */


/**
 * Helper function to get full API URL
 * @param endpoint - API endpoint path (e.g., '/auth/login')
 * @returns Full URL string
 */
export const getApiUrl = (endpoint: string): string => {
  return `${API_BASE_URL}${API_PREFIX}${endpoint}`;
};
