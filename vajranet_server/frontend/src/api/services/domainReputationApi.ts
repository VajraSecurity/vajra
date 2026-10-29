/**
 * Domain Reputation
 */

import api from '../axiosInstance';

export type DomainReputationProviderName = 'manual' | 'virustotal' | 'abuseipdb';
export type DomainReputationTargetType = 'domain' | 'ip';
export type DomainReputationVerdict = 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'error';
export type DomainReputationAuthMode = 'none' | 'header' | 'bearer';

/** Vajra Reputation Engine — a single shared config, Super-Admin-only to edit. */
export interface DomainReputationGlobalProviderStatus {
  provider: 'manual';
  scope: 'global';
  configured: boolean;
  base_url?: string | null;
  auth_mode?: DomainReputationAuthMode;
  auth_header_name?: string;
  api_key_masked?: string | null;
  updated_at?: string;
  created_by_name?: string | null;
}

/** One config slot within a group-scoped provider: either a real group's config, or (group_id: null) the Super Admin org-wide default. */
export interface DomainReputationGroupConfigEntry {
  group_id: string | null;
  group_name: string | null;
  is_org_default: boolean;
  configured: boolean;
  api_key_masked: string | null;
  updated_at?: string | null;
  created_by_name?: string | null;
}

/** VirusTotal/AbuseIPDB — one independent config per group, plus the Super Admin org-wide default. */
export interface DomainReputationGroupScopedProviderStatus {
  provider: 'virustotal' | 'abuseipdb';
  scope: 'per_group';
  configs: DomainReputationGroupConfigEntry[];
}

export type DomainReputationProviderStatus = DomainReputationGlobalProviderStatus | DomainReputationGroupScopedProviderStatus;

export interface SaveManualServerConfigRequest {
  base_url: string;
  api_key?: string;
  auth_mode?: DomainReputationAuthMode;
  auth_header_name?: string;
}

export interface SaveApiKeyConfigRequest {
  api_key: string;
  /** Which group's config this saves/tests/deletes. Omit if you administer exactly one group; null targets the Super Admin org-wide default. */
  group_id?: string | null;
}

export interface DomainReputationResult {
  provider: DomainReputationProviderName;
  verdict: DomainReputationVerdict;
  score: number | null;
  summary: string;
  raw: unknown;
  /** Manual server only: the check completed on partial provider coverage — the summary says so too. */
  partial?: boolean;
  /** Manual server only: correlation ID for matching the check against that server's logs. */
  requestId?: string | null;
}

export interface DomainReputationCheckResultRow {
  id: number;
  target_id: number | null;
  value: string;
  type: DomainReputationTargetType;
  provider: DomainReputationProviderName;
  verdict: DomainReputationVerdict;
  score: number | null;
  summary: string | null;
  raw_response: unknown;
  triggered_by: 'manual' | 'schedule';
  checked_by_name: string | null;
  created_at: string;
}

export interface DomainReputationTarget {
  id: number;
  value: string;
  type: DomainReputationTargetType;
  providers: string[];
  cronExpression: string;
  isActive: boolean;
  lastVerdict: string | null;
  lastCheckedAt: string | null;
  created_by_name: string | null;
  created_at: string;
  updated_at: string;
  /** null = an org-wide (Super-Admin-managed) entry, visible read-only to every Group Admin. */
  group_id: string | null;
  group_name: string | null;
  /** Whether the caller may edit/delete/run this specific entry (false for another group's or an org-wide entry viewed by a Group Admin). */
  canManage: boolean;
}

/** The caller's own group memberships, for driving the group picker in Settings/Check Now/the watchlist modal. */
export interface DomainReputationMyGroups {
  unrestricted: boolean;
  groups: { group_id: string; name: string; role: 'Group Admin' | 'Group Viewer' }[];
}

export const getDomainReputationProviders = async (): Promise<{ success: boolean; data: DomainReputationProviderStatus[] }> => {
  const response = await api.get('/domain-reputation/providers');
  return response.data;
};

export const getMyDomainReputationGroups = async (): Promise<{ success: boolean; data: DomainReputationMyGroups }> => {
  const response = await api.get('/domain-reputation/my-groups');
  return response.data;
};

export const saveDomainReputationProviderConfig = async (
  provider: DomainReputationProviderName,
  data: SaveManualServerConfigRequest | SaveApiKeyConfigRequest,
): Promise<{ success: boolean; message: string }> => {
  const response = await api.post(`/domain-reputation/providers/${provider}/config`, data);
  return response.data;
};

export const testDomainReputationProviderConnection = async (
  provider: DomainReputationProviderName,
  data: (Partial<SaveManualServerConfigRequest> | Partial<SaveApiKeyConfigRequest>) & { group_id?: string | null },
): Promise<{ success: boolean; message: string; data?: unknown }> => {
  const response = await api.post(`/domain-reputation/providers/${provider}/test`, data);
  return response.data;
};

export const deleteDomainReputationProviderConfig = async (
  provider: DomainReputationProviderName,
  groupId?: string | null,
): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete(`/domain-reputation/providers/${provider}/config`, {
    params: groupId !== undefined ? { group_id: groupId ?? '' } : undefined,
  });
  return response.data;
};

export const checkDomainReputation = async (data: {
  value: string;
  type: DomainReputationTargetType;
  providers: DomainReputationProviderName[];
  /** Which group's VirusTotal/AbuseIPDB key to use. Omit if you administer exactly one group, or if only checking Vajra Reputation Engine. */
  group_id?: string;
}): Promise<{ success: boolean; data: DomainReputationResult[] }> => {
  const response = await api.post('/domain-reputation/check', data);
  return response.data;
};

export const getDomainReputationHistory = async (params: {
  rows?: number;
  pageno?: number;
  search?: string;
  provider?: DomainReputationProviderName | DomainReputationProviderName[];
  verdict?: DomainReputationVerdict;
  type?: DomainReputationTargetType;
}): Promise<{ success: boolean; total: number; count: number; page: number; rows: number; data: DomainReputationCheckResultRow[] }> => {
  const { provider, ...rest } = params;
  const response = await api.get('/domain-reputation/history', {
    params: { ...rest, provider: Array.isArray(provider) ? provider.join(',') : provider },
  });
  return response.data;
};

export const getDomainReputationTargets = async (): Promise<{ success: boolean; data: DomainReputationTarget[] }> => {
  const response = await api.get('/domain-reputation/targets');
  return response.data;
};

export const createDomainReputationTarget = async (data: {
  value: string;
  type: DomainReputationTargetType;
  providers: string[];
  cronExpression: string;
  /** Which group owns this watchlist entry. Omit if you administer exactly one group; null (or omitted, as Super Admin) creates an org-wide entry. */
  group_id?: string | null;
}): Promise<{ success: boolean; data: DomainReputationTarget }> => {
  const response = await api.post('/domain-reputation/targets', data);
  return response.data;
};

export const updateDomainReputationTarget = async (
  id: number,
  data: Partial<{ providers: string[]; cronExpression: string; isActive: boolean }>,
): Promise<{ success: boolean; data: DomainReputationTarget }> => {
  const response = await api.put(`/domain-reputation/targets/${id}`, data);
  return response.data;
};

export const deleteDomainReputationTarget = async (id: number): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete(`/domain-reputation/targets/${id}`);
  return response.data;
};

export const runDomainReputationTargetNow = async (id: number): Promise<{ success: boolean; data: DomainReputationResult[] }> => {
  const response = await api.post(`/domain-reputation/targets/${id}/run-now`);
  return response.data;
};

export const getDomainReputationInventorySuggestions = async (): Promise<{ success: boolean; data: string[] }> => {
  const response = await api.get('/domain-reputation/inventory-suggestions');
  return response.data;
};
