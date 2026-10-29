/**
 * Policy Management API functions
 */

import api from '../axiosInstance';

export interface PolicyTarget {
  mode: 'all' | 'nodes' | 'groups' | 'mixed' | 'none';
  nodeIds: string[];
  /** nodes_groups.group_id (unique) — not the display name, which can collide across groups.
   *  Populate the picker via fetchEndpointGroups() (endpointGroupsApi.ts), which already
   *  hits GET /groups and returns {groupId, name, ...} — not listGroups() (name-only). */
  groupIds: string[];
}

export interface PolicyRecord {
  id: string;
  name: string;
  type: 'device-control' | 'network' | 'compliance' | 'custom';
  description: string;
  enabled: boolean;
  platforms: string[];
  portRules: {
    enabled: boolean;
    action: 'block' | 'allow';
    protocol: 'tcp' | 'udp' | 'both';
    ports: string[];
  };
  ipRules: {
    enabled: boolean;
    action: 'block' | 'allow';
    direction: 'inbound' | 'outbound' | 'both';
    ips: string[];
  };
  usb: {
    enabled: boolean;
    action: 'block' | 'allow';
    scope: 'all' | 'storage-only';
  };
  bluetooth: {
    enabled: boolean;
    action: 'block' | 'allow';
  };
  complianceChecks: string[];
  customQuery: string;
  target: PolicyTarget;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
  /** False for org-wide ("all") policies viewed by a Group Admin — read-only. */
  canManage: boolean;
}

export const listPolicies = async (
  params?: { page?: number; limit?: number },
): Promise<{ status: string; policies: PolicyRecord[]; total: number; page: number; limit: number }> => {
  const response = await api.get('/policies', { params });
  return response.data;
};

export const createPolicyRecord = async (
  body: Omit<PolicyRecord, 'id' | 'createdAt' | 'updatedAt' | 'createdBy' | 'canManage'>,
): Promise<{ status: string; policy: PolicyRecord }> => {
  const response = await api.post('/policies', body);
  return response.data;
};

export const updatePolicyRecord = async (
  id: string,
  body: Partial<Pick<PolicyRecord, 'enabled' | 'name' | 'description' | 'platforms' | 'portRules' | 'ipRules' | 'usb' | 'bluetooth' | 'complianceChecks' | 'customQuery'>>,
): Promise<{ status: string; policy: PolicyRecord }> => {
  const response = await api.patch(`/policies/${id}`, body);
  return response.data;
};

export const assignPolicyTargets = async (
  id: string,
  target: PolicyTarget,
): Promise<{ status: string; policy: PolicyRecord }> => {
  const response = await api.patch(`/policies/${id}/targets`, target);
  return response.data;
};

export const deletePolicyRecord = async (id: string): Promise<{ status: string; message: string }> => {
  const response = await api.delete(`/policies/${id}`);
  return response.data;
};
