/**
 * Dashboard API helpers
 * Centralized API calls for dashboard and graph visualizations
 */

import api from '../../../api/axiosInstance';
import { GRAPH_URLS } from '../../../api/urls';
import { debugLog } from '@/lib/debugLog';

// Type definitions
export interface OsCountItem {
  name: string;
  count: number;
}

export interface DefenderCountResponse {
  status: string;
  message: string;
  data: {
    on: number;
    off: number;
    total_hosts: number;
  };
}

export interface AlertStatusItem {
  name: string;
  count: number;
}

export interface AlertTypeData {
  [alertType: string]: number;
}

export interface WeeklyAlertsData {
  [date: string]: AlertTypeData;
}

export interface TopMachineAlert {
  host_identifier: string;
  hostname: string;
  total_alerts: number;
  critical: string | number;
  high: string | number;
  medium: string | number;
  low: string | number;
  information: string | number;
}

export interface TopMachineAlertResponse {
  success: boolean;
  data: TopMachineAlert[];
}

export interface TopMachineUsb {
  host_identifier: string;
  hostname: string;
  usb_alert_count: number;
}

export interface TopMachineUsbResponse {
  success: boolean;
  data: TopMachineUsb[];
}

export interface SeverityCountItem {
  name: string;
  value: number;
}

export interface FirewallDiffResponse {
  status: string;
  message: string;
  data: {
    host_identifier: string;
    summary: {
      added: number;
      deleted: number;
      modified: number;
      unmodified?: number;
      unchanged: number;
      total_events?: number;
      total: number;
    };
  };
}

export interface MemoryHealthResponse {
  status: string;
  message: string;
  data: Array<{
    memory_total: number;
    memory_usage: number;
    time: number;
  }>;
}

export interface ComplianceResultItem {
  command_key: string;
  output: string;
}

export interface NodeComplianceLatestGraphResponse {
  success: boolean;
  exists: boolean;
  data: {
    id: number;
    host_identifier: string;
    unixtime: number;
    compliance_data: ComplianceResultItem[];
  } | null;
}

const isNoDataSuccessPayload = (value: unknown): boolean => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as { status?: unknown; message?: unknown };
  return v.status === 'Success' && typeof v.message === 'string' && v.message.toLowerCase().includes('no data');
};

export const dashboardApi = {
  /**
   * Fetch OS distribution count
   * @returns Array of OS types with their machine counts
   */
  getOsCount: async (): Promise<OsCountItem[]> => {
    const response = await api.get<OsCountItem[]>(GRAPH_URLS.OS_COUNT);
    return response.data;
  },

  /**
   * Fetch Windows Defender firewall statistics
   * @returns Defender on/off counts and total hosts
   */
  getDefenderCount: async (): Promise<DefenderCountResponse> => {
    const response = await api.get<DefenderCountResponse>(GRAPH_URLS.DEFENDER_COUNT);
    return response.data;
  },

  /**
   * Fetch alert status (open vs closed)
   * @parameter hostIdentifier - Optional host identifier for specific host data
   * @returns Alert status counts
   */
  getAlertStatus: async (hostIdentifier?: string): Promise<AlertStatusItem[]> => {
    const response = await api.post<unknown>(GRAPH_URLS.ALERT_STATUS, {
      host_identifier: hostIdentifier,
    });
    const data = response.data;
    if (Array.isArray(data)) return data as AlertStatusItem[];
    if (isNoDataSuccessPayload(data)) return [];
    debugLog('dashboardApi.getAlertStatus: unexpected payload shape', data);
    return [];
  },

  /**
   * Fetch weekly alerts data by alert type and date
   * @parameter hostIdentifier - Optional host identifier for specific host data
   * @returns Weekly alerts grouped by date and alert type
   */
  getWeeklyAlerts: async (hostIdentifier?: string): Promise<WeeklyAlertsData> => {
    const response = await api.post<unknown>(GRAPH_URLS.WEEKLY_ALERTS, {
      host_identifier: hostIdentifier,
    });
    const data = response.data;
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      if (isNoDataSuccessPayload(data)) return {};
      return data as WeeklyAlertsData;
    }
    debugLog('dashboardApi.getWeeklyAlerts: unexpected payload shape', data);
    return {};
  },

  /**
   * Fetch top 5 machines by total alert count
   * @returns Top 5 machines with highest alert volumes
   */
  getTop5MachineAlerts: async (): Promise<TopMachineAlertResponse> => {
    const response = await api.get<TopMachineAlertResponse>(GRAPH_URLS.TOP5_MACHINE_ALERTS);
    return response.data;
  },

  /**
   * Fetch top 5 machines by USB alert count
   * @returns Top 5 machines with highest USB alert volumes
   */
  getTop5MachineUsb: async (): Promise<TopMachineUsbResponse> => {
    const response = await api.get<TopMachineUsbResponse>(GRAPH_URLS.TOP5_MACHINE_USB);
    return response.data;
  },

  /**
   * Fetch severity count for a specific host
   * @parameter hostIdentifier - Host identifier for severity data
   * @returns Severity distribution counts
   */
  getSeverityCount: async (hostIdentifier: string): Promise<SeverityCountItem[]> => {
    const response = await api.post<unknown>(GRAPH_URLS.SEVERITY, {
      host_identifier: hostIdentifier,
    });
    const data = response.data;
    if (Array.isArray(data)) return data as SeverityCountItem[];
    if (isNoDataSuccessPayload(data)) return [];
    debugLog('dashboardApi.getSeverityCount: unexpected payload shape', data);
    return [];
  },

  /**
   * Fetch memory graph data for a specific host
   * @parameter hostIdentifier - Host identifier for memory data
   * @returns Memory health time series data
   */
  getMemoryGraph: async (hostIdentifier: string): Promise<MemoryHealthResponse> => {
    const response = await api.post<MemoryHealthResponse>(GRAPH_URLS.MEMORY_GRAPH, {
      host_identifier: hostIdentifier,
    });
    return response.data;
  },

  /**
   * Fetch firewall rules diff summary for a specific host
   * @parameter hostIdentifier - Host identifier for firewall diff data
   * @returns Firewall rule changes summary (added, deleted, modified, unchanged)
   */
  getFirewallDiff: async (hostIdentifier: string): Promise<FirewallDiffResponse> => {
    const response = await api.post<FirewallDiffResponse>(GRAPH_URLS.FIREWALL_DIFF, {
      host_identifier: hostIdentifier,
    });
    return response.data;
  },

  /**
   * Fetch latest compliance record for a specific host from compliance history table
   * @parameter hostIdentifier - Host identifier for compliance data
   */
  getNodeComplianceLatest: async (hostIdentifier: string): Promise<NodeComplianceLatestGraphResponse> => {
    const response = await api.post<NodeComplianceLatestGraphResponse>(GRAPH_URLS.NODE_COMPLIANCE_LATEST, {
      host_identifier: hostIdentifier,
    });
    return response.data;
  },
};
