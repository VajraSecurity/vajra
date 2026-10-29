/**
 * Nuclei vulnerability scanning API functions
 */

import api from '../axiosInstance';

export type NucleiScanType = 'posture' | 'cve' | 'misconfig' | 'full';

export interface NucleiScanRequest {
  target: string;
  scanType: NucleiScanType;
  reason: string;
  networkScanId?: number;
}

export interface NucleiFinding {
  templateId: string;
  name: string;
  severity: string;
  type: string;
  host: string;
  matchedAt: string;
  ip: string;
  tags: string[];
  reference: string[];
  description: string;
  cveId: string[];
  cvssScore: number | null;
  timestamp: string;
}

export interface NucleiScanSummary {
  totalFindings: number;
  severity: { critical: number; high: number; medium: number; low: number; info: number };
  uniqueCves: string[];
  uniqueCveCount: number;
}

export interface NucleiScanResult {
  findings: NucleiFinding[];
  summary: NucleiScanSummary | null;
}

export interface NucleiScanStatusResponse {
  success: boolean;
  data?: {
    id: number;
    status: string;
    progress: number;
    target: string;
    scanType: string;
    findings: NucleiFinding[] | null;
    summary: NucleiScanSummary | null;
    rawOutput: string;
  };
}

export const runNucleiScan = async (data: NucleiScanRequest): Promise<{ success: boolean; data?: { historyId: number; message: string } }> => {
  const response = await api.post('/network/nuclei/scan', data);
  return response.data;
};

export const getNucleiScanStatus = async (id: number, signal?: AbortSignal): Promise<NucleiScanStatusResponse> => {
  const response = await api.get(`/network/nuclei/scan/${id}`, { signal });
  return response.data;
};

export const cancelNucleiScanApi = async (id: number): Promise<{ success: boolean; message: string }> => {
  const response = await api.post(`/network/nuclei/scan/${id}/cancel`);
  return response.data;
};

export const getActiveNucleiScan = async (): Promise<{ success: boolean; data: { historyId: number; progress: number; status: string } | null }> => {
  const response = await api.get('/network/nuclei/scan/active');
  return response.data;
};

export const checkNucleiInstalled = async (): Promise<{ success: boolean; data: { installed: boolean; version: string | null; templateCount: number } }> => {
  const response = await api.get('/network/nuclei/status');
  return response.data;
};

export const updateNucleiTemplates = async (): Promise<{ success: boolean; data: { message: string } }> => {
  const response = await api.post('/network/nuclei/templates/update');
  return response.data;
};
