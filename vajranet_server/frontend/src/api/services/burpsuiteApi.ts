/**
 * Burp Suite API functions
 *
 * Group-scoped: pass `groupId` to target a specific group's Burp Suite
 * Enterprise config/scan history (or omit it for the caller's own default
 * scope). `groupId: null` (or omitted) means "my own scope" — mirrors the
 * backend's groupId semantics in backend/src/utils/scannerScope.ts exactly.
 *
 * `listBurpsuiteScans` is the one exception: for a Super Administrator,
 * omitting `groupId` entirely (passing `undefined`, i.e. simply not calling
 * with a groupId argument) returns a merged list across every group's scans
 * plus their own, since scan history is stored locally rather than proxied
 * from a remote server (unlike Nessus/OpenVAS). Passing `groupId: null`
 * explicitly narrows it to just the Super Admin's own scope, same as every
 * other endpoint here — see BurpsuiteView.tsx's group picker for how the two
 * are surfaced as distinct choices ("All groups" vs "My Own").
 */

import api from '../axiosInstance';

export interface BurpsuiteConfigResponse {
  success: boolean;
  data: {
    url: string;
    isConfigured: boolean;
    groupId: string | null;
    created_by_name?: string;
    updated_at?: string;
  } | null;
}

export const getBurpsuiteConfig = async (groupId?: string | null): Promise<BurpsuiteConfigResponse> => {
  const response = await api.get('/burpsuite/config', { params: groupId !== undefined ? { groupId: groupId ?? 'self' } : undefined });
  return response.data;
};

export const saveBurpsuiteConfig = async (data: { url: string; apiKey: string; groupId?: string | null }): Promise<{ success: boolean; message: string }> => {
  const response = await api.post('/burpsuite/config', data);
  return response.data;
};

export const deleteBurpsuiteConfig = async (groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete('/burpsuite/config', { data: groupId !== undefined ? { groupId: groupId ?? 'self' } : undefined });
  return response.data;
};

export const testStoredBurpsuiteConnection = async (groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.post('/burpsuite/test-stored', groupId !== undefined ? { groupId: groupId ?? 'self' } : undefined);
  return response.data;
};

export const testBurpsuiteConnection = async (data: { url: string; apiKey: string }): Promise<{ success: boolean; message: string }> => {
  const response = await api.post('/burpsuite/test', data);
  return response.data;
};

export interface BurpsuiteScan {
  id: number;
  groupId: string | null;
  target: string;
  status: string;
  issue_counts: { high: number; medium: number; low: number };
  /** Most recent activity on this scan (status/issue-count update) — a completed scan's `updated_at` is effectively its completion time. */
  updated_at?: string;
}

/**
 * `groupId` argument forms:
 *  - omitted (call with no args): for a Super Administrator, no groupId query
 *    param is sent at all — the backend's merged-list case (all groups + own).
 *    For a Group Admin, the backend forces their own group regardless.
 *  - `null`: explicitly "my own scope" (?groupId=self).
 *  - a group id string: that specific group's scans only.
 */
export const listBurpsuiteScans = async (groupId?: string | null): Promise<{ success: boolean; data: { scans: BurpsuiteScan[] } }> => {
  const response = await api.get('/burpsuite/scans', { params: groupId !== undefined ? { groupId: groupId ?? 'self' } : undefined });
  return response.data;
};

export interface BurpsuiteTaskDetail {
  id?: number | string;
  groupId?: string | null;
  target?: string;
  status?: string;
  created_at?: string;
  issuesHigh?: number;
  issuesMedium?: number;
  issuesLow?: number;
  issuesTotal?: number;
  metrics?: {
    crawl_requests_made?: number;
    audit_queue_items_waiting?: number;
    crawl_network_errors?: number;
  };
}

export interface BurpsuiteIssueDetail {
  name?: string;
  severity?: string;
  confidence?: string;
  path?: string;
  description?: string;
  remediation?: string;
}

export interface BurpsuiteIssueEntry {
  issue?: BurpsuiteIssueDetail;
}

export const getBurpsuiteScanDetails = async (taskId: string, groupId?: string | null): Promise<{ success: boolean; stale?: boolean; data: { task: BurpsuiteTaskDetail; issues: BurpsuiteIssueEntry[] } }> => {
  const response = await api.get(`/burpsuite/scans/${taskId}`, { params: groupId !== undefined ? { groupId: groupId ?? 'self' } : undefined });
  return response.data;
};

export const deleteBurpsuiteScanTask = async (taskId: string, groupId?: string | null): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete(`/burpsuite/scans/${taskId}`, { data: groupId !== undefined ? { groupId: groupId ?? 'self' } : undefined });
  return response.data;
};

export const launchBurpsuiteScan = async (data: { targetUrls: string[]; scanProfile?: string; groupId?: string | null }): Promise<{ success: boolean; message: string }> => {
  const response = await api.post('/burpsuite/scan', data);
  return response.data;
};
