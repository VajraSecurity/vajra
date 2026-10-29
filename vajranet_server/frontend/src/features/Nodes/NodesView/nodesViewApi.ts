/**
 * NodesView API helpers.
 * Centralized node-related API calls for use by NodesView and tab components.
 * Backend endpoints can be wired here as they become available.
 */

import api from '../../../api/axiosInstance';
import { ALERTS_URLS, NODES_URLS, WINDOWS_URLS } from '../../../api/urls';

const withHost = (path: string, hostIdentifier: string) =>
  `${path}?host_identifier=${encodeURIComponent(hostIdentifier)}`;

export const nodesViewApi = {
  /** Fetch config list for node configuration tab */
  getConfigList: () => api.get(NODES_URLS.CONFIG_LIST),

  /** Update node config (selected config IDs) */
  updateConfig: (hostIdentifier: string, configId: number[]) =>
    api.put(NODES_URLS.CONFIG_UPDATE, { host_identifier: hostIdentifier, config_id: configId }),

  /** Events count */
  getEventsCount: (hostIdentifier: string) =>
    api.get(withHost(NODES_URLS.EVENTS_COUNT, hostIdentifier)),

  /** Alert count */
  getAlertCount: (hostIdentifier: string) =>
    api.get(withHost(NODES_URLS.ALERT_COUNT, hostIdentifier)),

  /** Weekly alerts count */
  getWeeklyAlertsCount: (hostIdentifier: string) =>
    api.get(withHost(NODES_URLS.WEEKLY_ALERTS_COUNT, hostIdentifier)),

  /** MITRE analysis */
  getMitreAnalysis: (hostIdentifier: string) =>
    api.get(withHost(NODES_URLS.MITRE_ANALYSIS, hostIdentifier)),

  /** Severity count */
  getSeverityCount: (hostIdentifier: string) =>
    api.get(withHost(NODES_URLS.SEVERITY_COUNT, hostIdentifier)),

  /** Programs list (packages) */
  getProgramsList: (hostIdentifier: string, osName?: string) =>
    api.post(NODES_URLS.PROGRAMS_LIST, {
      host_identifier: hostIdentifier,
      os_name: osName,
    }),

  /** Fetch Windows security profile information */
  getSecurityProfileInfo: (hostIdentifier: string) =>
    api.post(WINDOWS_URLS.PROFILE_INFO, { host_identifier: hostIdentifier }),

  /** Fetch Windows firewall rules */
  getFirewallRules: (hostIdentifier: string) =>
    api.post(WINDOWS_URLS.FIREWALL_RULES, { host_identifier: hostIdentifier }),
  /** Fetch Windows firewall rules diff */
  getFirewallRulesDiff: (hostId: string, startTime: string, endTime: string) =>
    api.post(WINDOWS_URLS.FIREWALL_RULES_DIFF, { host_identifier: hostId, start_time: startTime, end_time: endTime }),

  /** Fetch Windows TPM information */
  getTpmInfo: (hostIdentifier: string) =>
    api.post(WINDOWS_URLS.TPM_INFO, { host_identifier: hostIdentifier }),

  /** Fetch Windows Secure Boot information */
  getSecureBootInfo: (hostIdentifier: string) =>
    api.post(WINDOWS_URLS.SECUREBOOT_INFO, { host_identifier: hostIdentifier }),

  /** Fetch Windows BIOS information */
  getBiosInfo: (hostIdentifier: string) =>
    api.post(WINDOWS_URLS.BIOS_INFO, { host_identifier: hostIdentifier }),

  /** Fetch Windows Update History */
  getUpdateHistory: (hostIdentifier: string) =>
    api.post(WINDOWS_URLS.UPDATE_HISTORY, { host_identifier: hostIdentifier }),

  /** Fetch Latest Windows Update */
  getLatestUpdate: (hostIdentifier: string) =>
    api.post(WINDOWS_URLS.LATEST_UPDATE, { host_identifier: hostIdentifier }),

  /** Fetch node IP addresses */
  getNodeIps: (hostIdentifier: string) =>
    api.post(NODES_URLS.IP_LIST, { host_identifier: hostIdentifier }),

  /** Fetch node storage and memory telemetry */
  getStorage: (hostIdentifier: string) =>
    api.get(`${NODES_URLS.STORAGE}${encodeURIComponent(hostIdentifier)}`),

  /** Poll for latest completed ClamAV scan result since a given unix timestamp. */
  getClamavScanLatest: (hostIdentifier: string, sinceTs: number) =>
    api.get(`${ALERTS_URLS.CLAMAV_SCAN_LATEST}?host_identifier=${encodeURIComponent(hostIdentifier)}&since=${sinceTs}`),

  /** Fetch a node's currently-listening ports (paginated, default 200/max 500 per page). */
  getListeningPorts: (hostIdentifier: string, limit?: number, offset?: number) => {
    const params = new URLSearchParams();
    if (limit !== undefined) params.set('limit', String(limit));
    if (offset !== undefined) params.set('offset', String(offset));
    const qs = params.toString();
    return api.get(
      `${NODES_URLS.NETWORK_LISTENING_PORTS}${encodeURIComponent(hostIdentifier)}${qs ? `?${qs}` : ''}`,
    );
  },

  /** Fetch a node's last-boot/uptime tracking data (derived from win_socket_events). */
  getNetworkUptime: (hostIdentifier: string) =>
    api.get(`${NODES_URLS.NETWORK_UPTIME}${encodeURIComponent(hostIdentifier)}`),
};
