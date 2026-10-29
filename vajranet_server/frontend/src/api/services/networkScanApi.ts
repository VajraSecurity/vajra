/**
 * Network scanning (Nmap) + scan scheduler API functions
 */

import api from '../axiosInstance';
import type { NucleiScanResult } from './nucleiApi';

export interface NmapScanRequest {
  target: string;
  scanType: 'quick' | 'full' | 'os' | 'discovery' | 'advanced';
  reason: string;
  sessionId?: number;
}

export interface NmapScanResponse {
  success: boolean;
  data?: {
    output?: string;
    command?: string;
    knownIps?: string[];
    unknownIps?: string[];
    staleManagedIps?: string[];
    newIps?: string[];
    disappearedIps?: string[];
    historyId?: number;
    message?: string;
    status?: string;
    progress?: number;
    id?: number;
  };
}

export const getScanStatus = async (id: number, signal?: AbortSignal): Promise<NmapScanResponse> => {
  const response = await api.get(`/network/scan/${id}`, { signal });
  return response.data;
};

export const cancelScanApi = async (id: number): Promise<NmapScanResponse> => {
  const response = await api.post(`/network/scan/${id}/cancel`);
  return response.data;
};

export const getActiveScan = async (): Promise<{ success: boolean; data: { historyId: number; progress: number; status: string } | null }> => {
  const response = await api.get('/network/scan/active');
  return response.data;
};

export const runNmapScan = async (data: NmapScanRequest, signal?: AbortSignal): Promise<NmapScanResponse> => {
  const response = await api.post('/network/scan', data, { signal });
  return response.data;
};

export interface NetworkScanHistory {
  id: number;
  target: string;
  scanType: string;
  reason: string;
  command: string;
  output: string;
  created_by_user_id: number | null;
  created_by_name: string | null;
  created_at: string;
  chart_data?: { portData: unknown[]; serviceData: unknown[]; hasData: boolean } | null;
  childScans?: NetworkScanHistory[];
  vulnScans?: (NucleiScanResult & { target: string; status?: string })[];
}

export interface NetworkScanHistoryResponse {
  success: boolean;
  data?: NetworkScanHistory[];
}

export const getNetworkScanHistory = async (): Promise<NetworkScanHistoryResponse> => {
  const response = await api.get('/network/scan/history');
  return response.data;
};

export const updateScanCharts = async (
  historyId: number,
  chartData: { portData: unknown[]; serviceData: unknown[]; hasData: boolean }
): Promise<{success: boolean; message: string}> => {
  const response = await api.put(`/network/scan/${historyId}/charts`, { chartData });
  return response.data;
};

export const getKnownIps = async (): Promise<{ success: boolean, data: string[] }> => {
  const response = await api.get('/network/known-ips');
  return response.data;
};

/**
 * Scan Scheduler: recurring subnet discovery scans (Super Admin only, on-prem).
 * A schedule re-scans a single /16 CIDR on a cron cadence; any IP with no
 * matching Vajra agent triggers an automatic advanced scan + an alert.
 */
export interface ScanSchedule {
  id: number;
  // Owning group — null means a Super Administrator's own/"fleet-wide"
  // schedule (visible only to Super Admins); a group id string means it
  // belongs to that group. See backend/src/utils/scannerScope.ts.
  groupId: string | null;
  name: string;
  enabled: boolean;
  target: string;
  frequencyPreset: '5min' | '1h' | '1d' | 'custom';
  cronExpression: string;
  reason: string;
  knownIps: string[];
  createdByUserId: number | null;
  createdByName: string | null;
  lastRunAt: string | null;
  lastRunStatus: 'running' | 'success' | 'failed' | null;
  lastRunHistoryId: number | null;
  lastNewIpCount: number | null;
  lastPendingIpCount: number | null;
  lastReusedIpCount: number | null;
  createdAt: string;
  updatedAt: string;
}

export interface ScanScheduleRequest {
  name: string;
  target: string;
  frequencyPreset: ScanSchedule['frequencyPreset'];
  cronExpression?: string;
  reason: string;
  knownIps?: string[];
  enabled?: boolean;
  // Create: which group this schedule belongs to (null = the Super
  // Administrator's own scope). Update: ignored by the server for
  // reassignment purposes — group_id never changes on update — but still
  // worth sending (the schedule's own current groupId) so the server can
  // disambiguate scope for a caller who acts on more than one group.
  groupId?: string | null;
}

/** 'self' is the wire form of `groupId: null` (see scannerScope.ts's
 *  readRequestedGroupId) — query/body params can't carry a literal null. */
function groupIdParam(groupId: string | null | undefined): string | undefined {
  if (groupId === undefined) return undefined;
  return groupId === null ? 'self' : groupId;
}

export const getScanSchedules = async (): Promise<{ success: boolean; schedules: ScanSchedule[] }> => {
  const response = await api.get('/network/schedules');
  return response.data;
};

export const createScanSchedule = async (data: ScanScheduleRequest): Promise<{ success: boolean; schedule?: ScanSchedule; message?: string }> => {
  const response = await api.post('/network/schedules', data);
  return response.data;
};

export const updateScanSchedule = async (id: number, data: ScanScheduleRequest): Promise<{ success: boolean; schedule?: ScanSchedule; message?: string }> => {
  const response = await api.put(`/network/schedules/${id}`, data);
  return response.data;
};

export const deleteScanSchedule = async (id: number, groupId?: string | null): Promise<{ success: boolean; message?: string }> => {
  const response = await api.delete(`/network/schedules/${id}`, { params: { groupId: groupIdParam(groupId) } });
  return response.data;
};

export const runScanScheduleNow = async (id: number, groupId?: string | null): Promise<{ success: boolean; message?: string }> => {
  const response = await api.post(`/network/schedules/${id}/run-now`, undefined, { params: { groupId: groupIdParam(groupId) } });
  return response.data;
};

export const getScanScheduleRuns = async (id: number, groupId?: string | null): Promise<{ success: boolean; runs: NetworkScanHistory[] }> => {
  const response = await api.get(`/network/schedules/${id}/runs`, { params: { groupId: groupIdParam(groupId) } });
  return response.data;
};
