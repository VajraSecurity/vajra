/**
 * Nessus Professional Vulnerability Scanner API functions
 */

import api from '../axiosInstance';

export interface NessusConfigData {
  id: number;
  /** null = the Super Administrator's own config, not tied to any group — mirrors
   *  the backend's groupId semantics in backend/src/utils/scannerScope.ts. */
  group_id: string | null;
  nessus_url: string;
  access_key_masked: string;
  secret_key_masked: string;
  is_active: boolean;
  created_by_name: string | null;
  created_at: string;
  updated_at: string;
}

export interface SaveNessusConfigRequest {
  nessus_url: string;
  access_key: string;
  secret_key: string;
  /** Target scope for the write — see NessusConfigData.group_id. Omit for "my own"
   *  (a Group Admin's own group, or a Super Administrator's own global config). */
  groupId?: string | null;
}

export interface NessusScan {
  id: number;
  uuid: string;
  name: string;
  status: string;
  folder_id: number;
  creation_date: number;
  last_modification_date: number;
}

export interface NessusScanTemplate {
  uuid: string;
  name: string;
  title: string;
  description: string;
}

export interface CreateNessusScanRequest {
  uuid: string;
  settings: {
    name: string;
    text_targets: string;
    policy_id?: number;
    folder_id?: number;
    description?: string;
  };
}

export interface NessusPolicy {
  id: number;
  name: string;
  description: string;
  owner: string;
  template_uuid: string;
  creation_date: number;
  last_modification_date: number;
}

export interface NessusExportRequest {
  format: 'nessus' | 'csv' | 'html';
  history_id?: number;
}

export interface NessusFolder {
  id: number;
  name: string;
  type: string;
  default_tag: number;
  custom: number;
}

// Config
export const getNessusConfig = async (groupId?: string | null): Promise<{ success: boolean; data: NessusConfigData | null }> => {
  const response = await api.get('/nessus/config', { params: { groupId } });
  return response.data;
};

export const saveNessusConfig = async (data: SaveNessusConfigRequest): Promise<{ success: boolean; message: string }> => {
  const response = await api.post('/nessus/config', data);
  return response.data;
};

export const testNessusConnection = async (data: SaveNessusConfigRequest): Promise<{ success: boolean; message?: string; data?: unknown }> => {
  const response = await api.post('/nessus/config/test', data);
  return response.data;
};

export const testStoredNessusConnection = async (groupId?: string | null): Promise<{ success: boolean; message?: string; data?: unknown }> => {
  const response = await api.get('/nessus/config/test', { params: { groupId } });
  return response.data;
};

export const deleteNessusConfig = async (groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete('/nessus/config', { data: { groupId } });
  return response.data;
};

// Server
// Nessus server status/properties payloads are vendor-defined diagnostic
// blobs with no fixed shape consumed by any caller — kept as `unknown`.
export const getNessusServerStatus = async (groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.get('/nessus/server/status', { params: { groupId } });
  return response.data;
};

export const getNessusServerProperties = async (groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.get('/nessus/server/properties', { params: { groupId } });
  return response.data;
};

// Templates
export const getNessusScanTemplates = async (groupId?: string | null): Promise<{ success: boolean; data: { templates: NessusScanTemplate[] } }> => {
  const response = await api.get('/nessus/templates/scan', { params: { groupId } });
  return response.data;
};

export const getNessusPolicyTemplates = async (groupId?: string | null): Promise<{ success: boolean; data: { templates: NessusScanTemplate[] } }> => {
  const response = await api.get('/nessus/templates/policy', { params: { groupId } });
  return response.data;
};

// Scans
export const listNessusScans = async (groupId?: string | null): Promise<{ success: boolean; data: { scans: NessusScan[] | null; folders: NessusFolder[] } }> => {
  const response = await api.get('/nessus/scans', { params: { groupId } });
  return response.data;
};

export const createNessusScan = async (data: CreateNessusScanRequest, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.post('/nessus/scans', { ...data, groupId });
  return response.data;
};

/** Fields read off GET /nessus/scans/:id by NessusScanDetail.tsx. */
export interface NessusScanHost {
  hostname?: string;
  host_id?: string | number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  progress?: string | number;
}

export interface NessusScanVulnerability {
  severity?: number;
  count?: number;
  plugin_name?: string;
  plugin_family?: string;
}

export interface NessusScanDetailData {
  info?: {
    name?: string;
    status?: string;
    targets?: string;
    hostcount?: number;
  };
  hosts?: NessusScanHost[];
  vulnerabilities?: NessusScanVulnerability[];
}

export const getNessusScanDetails = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: NessusScanDetailData }> => {
  const response = await api.get(`/nessus/scans/${id}`, { params: { groupId } });
  return response.data;
};

export const updateNessusScan = async (id: number, data: Record<string, unknown>, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.put(`/nessus/scans/${id}`, { ...data, groupId });
  return response.data;
};

export const deleteNessusScan = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.delete(`/nessus/scans/${id}`, { data: { groupId } });
  return response.data;
};

export const launchNessusScan = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.post(`/nessus/scans/${id}/launch`, { groupId });
  return response.data;
};

export const pauseNessusScan = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.post(`/nessus/scans/${id}/pause`, { groupId });
  return response.data;
};

export const resumeNessusScan = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.post(`/nessus/scans/${id}/resume`, { groupId });
  return response.data;
};

export const stopNessusScan = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.post(`/nessus/scans/${id}/stop`, { groupId });
  return response.data;
};

// Export
export const requestNessusExport = async (scanId: number, data: NessusExportRequest, groupId?: string | null): Promise<{ success: boolean; data: { file: number } }> => {
  const response = await api.post(`/nessus/scans/${scanId}/export`, { ...data, groupId });
  return response.data;
};

export const getNessusExportStatus = async (scanId: number, fileId: number, groupId?: string | null): Promise<{ success: boolean; data: { status: string } }> => {
  const response = await api.get(`/nessus/scans/${scanId}/export/${fileId}/status`, { params: { groupId } });
  return response.data;
};

export const downloadNessusExport = async (scanId: number, fileId: number, groupId?: string | null): Promise<Blob> => {
  const response = await api.get(`/nessus/scans/${scanId}/export/${fileId}/download`, { responseType: 'blob', params: { groupId } });
  return response.data;
};

// Policies
export const listNessusPolicies = async (groupId?: string | null): Promise<{ success: boolean; data: { policies: NessusPolicy[] | null } }> => {
  const response = await api.get('/nessus/policies', { params: { groupId } });
  return response.data;
};

export interface CreateNessusPolicyRequest {
  uuid: string;
  settings: { name: string; [key: string]: unknown };
}

export const createNessusPolicy = async (data: CreateNessusPolicyRequest, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.post('/nessus/policies', { ...data, groupId });
  return response.data;
};

export const getNessusPolicy = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.get(`/nessus/policies/${id}`, { params: { groupId } });
  return response.data;
};

export const updateNessusPolicy = async (id: number, data: Record<string, unknown>, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.put(`/nessus/policies/${id}`, { ...data, groupId });
  return response.data;
};

export const deleteNessusPolicy = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.delete(`/nessus/policies/${id}`, { data: { groupId } });
  return response.data;
};

// Folders
export const listNessusFolders = async (groupId?: string | null): Promise<{ success: boolean; data: { folders: NessusFolder[] } }> => {
  const response = await api.get('/nessus/folders', { params: { groupId } });
  return response.data;
};

export const createNessusFolder = async (name: string, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.post('/nessus/folders', { name, groupId });
  return response.data;
};

export const deleteNessusFolder = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.delete(`/nessus/folders/${id}`, { data: { groupId } });
  return response.data;
};

// Plugins
export const listNessusPluginFamilies = async (groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.get('/nessus/plugins/families', { params: { groupId } });
  return response.data;
};

export const getNessusPluginFamily = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.get(`/nessus/plugins/families/${id}`, { params: { groupId } });
  return response.data;
};

export const getNessusPlugin = async (id: number, groupId?: string | null): Promise<{ success: boolean; data: unknown }> => {
  const response = await api.get(`/nessus/plugins/${id}`, { params: { groupId } });
  return response.data;
};
