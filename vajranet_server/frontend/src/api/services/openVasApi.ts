/**
 * OpenVAS / Greenbone Vulnerability Manager API functions
 */

import api from '../axiosInstance';

export interface OpenVASConfigData {
  id: number;
  /** null = the Super Administrator's own config, not tied to any group — mirrors
   *  the backend's groupId semantics in backend/src/utils/scannerScope.ts. */
  group_id: string | null;
  gsa_url: string;
  gmp_username: string;
  is_active: boolean;
  created_by_name: string | null;
  created_at: string;
  updated_at: string;
}

export interface SaveOpenVASConfigRequest {
  gsa_url: string;
  gmp_username: string;
  gmp_password: string;
  /** Target scope for the write — see scannerScope.ts's groupId semantics. Omit
   *  for "my own" (a Group Admin's own group, or a Super Administrator's own
   *  global config). */
  groupId?: string | null;
}

export interface OpenVASScanConfig {
  id: string;
  name: string;
  comment: string;
  type: string;
  usage_type: string;
  family_count: number;
  nvt_count: number;
}

export interface OpenVASTarget {
  id: string;
  name: string;
  hosts: string;
  comment: string;
  in_use: string;
  max_hosts: string;
  port_list: { id: string; name: string } | null;
  ssh_credential: { id: string } | null;
  smb_credential: { id: string } | null;
}

export interface OpenVASTask {
  id: string;
  name: string;
  comment: string;
  status: string;
  progress: string;
  trend: string;
  target: { id: string; name: string } | null;
  scanner: { id: string; name: string } | null;
  config: { id: string; name: string } | null;
  last_report: { id: string; timestamp: string; severity: string } | null;
  report_count: number;
  creation_time: string;
  modification_time: string;
}

export interface OpenVASScanner {
  id: string;
  name: string;
  type: string;
  host: string;
  port: string;
}

export interface OpenVASPortList {
  id: string;
  name: string;
  comment: string;
  port_count: number;
}

export interface OpenVASReportResult {
  id: string;
  name: string;
  host: string;
  port: string;
  severity: string;
  threat: string;
  description: string;
  nvt: {
    oid: string;
    name: string;
    family: string;
    cvss_base: string;
    cve: string;
    tags: string;
  } | null;
}

// --- Config ---

export const getOpenVASConfig = async (groupId?: string | null): Promise<{ success: boolean; data: OpenVASConfigData | null }> => {
  const response = await api.get('/openvas/config', { params: { groupId } });
  return response.data;
};

export const saveOpenVASConfig = async (data: SaveOpenVASConfigRequest): Promise<{ success: boolean; message: string }> => {
  const response = await api.post('/openvas/config', data);
  return response.data;
};

export const testOpenVASConnection = async (data: SaveOpenVASConfigRequest): Promise<{ success: boolean; message?: string; data?: { version?: string } }> => {
  const response = await api.post('/openvas/config/test', data);
  return response.data;
};

export const testStoredOpenVASConnection = async (groupId?: string | null): Promise<{ success: boolean; message?: string; data?: { version?: string } }> => {
  const response = await api.get('/openvas/config/test', { params: { groupId } });
  return response.data;
};

export const deleteOpenVASConfig = async (groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete('/openvas/config', { data: { groupId } });
  return response.data;
};

// --- Server ---

export const getGvmVersion = async (groupId?: string | null): Promise<{ success: boolean; data: { version: string } }> => {
  const response = await api.get('/openvas/version', { params: { groupId } });
  return response.data;
};

// Feed metadata payload has no discoverable fixed shape and is never
// destructured by any caller — kept as `unknown` rather than `any`.
export const getGvmFeeds = async (groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.get('/openvas/feeds', { params: { groupId } });
  return response.data;
};

// --- Scan Configs ---

export const listOpenVASScanConfigs = async (groupId?: string | null): Promise<{ success: boolean; data: { configs: OpenVASScanConfig[] } }> => {
  const response = await api.get('/openvas/configs', { params: { groupId } });
  return response.data;
};

// --- Scanners ---

export const listOpenVASScanners = async (groupId?: string | null): Promise<{ success: boolean; data: { scanners: OpenVASScanner[] } }> => {
  const response = await api.get('/openvas/scanners', { params: { groupId } });
  return response.data;
};

// --- Targets ---

export const listOpenVASTargets = async (groupId?: string | null): Promise<{ success: boolean; data: { targets: OpenVASTarget[] } }> => {
  const response = await api.get('/openvas/targets', { params: { groupId } });
  return response.data;
};

export const createOpenVASTarget = async (data: { name: string; hosts: string; port_list_id?: string; comment?: string }, groupId?: string | null): Promise<{ success: boolean; data: { id: string } }> => {
  const response = await api.post('/openvas/targets', { ...data, groupId });
  return response.data;
};

// Every field is optional — GVM's modify_target only touches what's supplied
// (mirrors the backend's updateTarget). An empty-string ssh_credential_id/
// smb_credential_id means "clear this credential" — the backend maps that to
// GVM's own '0' convention for "no credential".
export const updateOpenVASTarget = async (id: string, data: { name?: string; hosts?: string; ssh_credential_id?: string; smb_credential_id?: string; comment?: string }, groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.put(`/openvas/targets/${id}`, { ...data, groupId });
  return response.data;
};

export const deleteOpenVASTarget = async (id: string, groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete(`/openvas/targets/${id}`, { data: { groupId } });
  return response.data;
};

// --- Tasks (Scans) ---

export const listOpenVASTasks = async (groupId?: string | null): Promise<{ success: boolean; data: { tasks: OpenVASTask[] } }> => {
  const response = await api.get('/openvas/tasks', { params: { groupId } });
  return response.data;
};

export const createOpenVASTask = async (data: { name: string; target_id: string; config_id: string; scanner_id?: string; comment?: string }, groupId?: string | null): Promise<{ success: boolean; data: { id: string } }> => {
  const response = await api.post('/openvas/tasks', { ...data, groupId });
  return response.data;
};

export const getOpenVASTaskDetails = async (id: string, groupId?: string | null): Promise<{ success: boolean; data: OpenVASTask }> => {
  const response = await api.get(`/openvas/tasks/${id}`, { params: { groupId } });
  return response.data;
};

// Every field is optional — GVM's modify_task only touches what's supplied, so
// callers only send what actually changed (mirrors the backend's updateTask).
export const updateOpenVASTask = async (id: string, data: { name?: string; target_id?: string; config_id?: string; scanner_id?: string; comment?: string }, groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.put(`/openvas/tasks/${id}`, { ...data, groupId });
  return response.data;
};

export const startOpenVASTask = async (id: string, groupId?: string | null): Promise<{ success: boolean; data: { report_id: string } }> => {
  const response = await api.post(`/openvas/tasks/${id}/start`, { groupId });
  return response.data;
};

export const stopOpenVASTask = async (id: string, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.post(`/openvas/tasks/${id}/stop`, { groupId });
  return response.data;
};

export const resumeOpenVASTask = async (id: string, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.post(`/openvas/tasks/${id}/resume`, { groupId });
  return response.data;
};

export const deleteOpenVASTask = async (id: string, groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete(`/openvas/tasks/${id}`, { data: { groupId } });
  return response.data;
};

// --- Reports ---

export interface OpenVASReportData {
  results: OpenVASReportResult[];
  severity_counts: { high: number; medium: number; low: number; log: number };
}

export const getOpenVASReport = async (id: string, groupId?: string | null): Promise<{ success: boolean; data: OpenVASReportData }> => {
  const response = await api.get(`/openvas/reports/${id}`, { params: { groupId } });
  return response.data;
};

// --- Port Lists ---

export const listOpenVASPortLists = async (groupId?: string | null): Promise<{ success: boolean; data: { port_lists: OpenVASPortList[] } }> => {
  const response = await api.get('/openvas/port-lists', { params: { groupId } });
  return response.data;
};

// --- Report Formats ---

// Report-format descriptors have no discoverable fixed shape and are never
// destructured by any caller — kept as `unknown[]` rather than `any[]`.
export const listOpenVASReportFormats = async (groupId?: string | null): Promise<{ success: boolean; data: { formats: unknown[] } }> => {
  const response = await api.get('/openvas/report-formats', { params: { groupId } });
  return response.data;
};

// --- Credentials ---

export interface OpenVASCredential {
  id: string;
  name: string;
  type: string;
  login: string;
  comment: string;
  in_use: string;
}

export const listOpenVASCredentials = async (groupId?: string | null): Promise<{ success: boolean; data: { credentials: OpenVASCredential[] } }> => {
  const response = await api.get('/openvas/credentials', { params: { groupId } });
  return response.data;
};

export const createOpenVASCredential = async (data: { name: string; type: string; login: string; password: string; comment?: string }, groupId?: string | null): Promise<{ success: boolean; data: { id: string } }> => {
  const response = await api.post('/openvas/credentials', { ...data, groupId });
  return response.data;
};

export const updateOpenVASCredential = async (id: string, data: { name?: string; login?: string; password?: string; comment?: string }, groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.put(`/openvas/credentials/${id}`, { ...data, groupId });
  return response.data;
};

export const deleteOpenVASCredential = async (id: string, groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete(`/openvas/credentials/${id}`, { data: { groupId } });
  return response.data;
};

// --- Quick Scan ---

export const openVASQuickScan = async (data: { name: string; hosts: string; config_id: string; scanner_id?: string; port_list_id?: string; comment?: string; ssh_credential_id?: string; smb_credential_id?: string }, groupId?: string | null): Promise<{ success: boolean; data: { target_id: string; task_id: string; report_id: string } }> => {
  const response = await api.post('/openvas/quick-scan', { ...data, groupId });
  return response.data;
};
