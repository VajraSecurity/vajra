/**
 * Endpoint Group Management API (node groups + user access scoping)
 * Super Admin only for create/delete/assign.
 */

import api from '../axiosInstance';
import type { UserRole } from './teamApi';

export interface EndpointGroup {
  id: number;
  name: string;
  groupId: string;
  createdBy: string;
  organisation: string;
  manager: string;
  nodeCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface EndpointGroupUser {
  id: number;
  name: string;
  email: string;
  role: UserRole;
}

export const fetchEndpointGroups = async (): Promise<EndpointGroup[]> => {
  const response = await api.get('/groups');
  return (response.data.groups as EndpointGroup[]) ?? [];
};

export const createEndpointGroup = async (payload: {
  name: string;
  organisation?: string;
  manager?: string;
  createdBy?: string;
}): Promise<EndpointGroup> => {
  const response = await api.post('/groups', payload);
  return response.data.group as EndpointGroup;
};

export const deleteEndpointGroup = async (groupId: string): Promise<void> => {
  await api.delete(`/groups/${encodeURIComponent(groupId)}`);
};

export const assignNodesToGroup = async (groupId: string, nodeIdentifiers: string[]): Promise<void> => {
  await api.put(`/groups/${encodeURIComponent(groupId)}/nodes`, { nodeIdentifiers });
};

export const fetchGroupUsers = async (groupId: string): Promise<EndpointGroupUser[]> => {
  const response = await api.get(`/groups/${encodeURIComponent(groupId)}/users`);
  return (response.data.users as EndpointGroupUser[]) ?? [];
};

export const assignUsersToGroup = async (groupId: string, userIds: number[]): Promise<void> => {
  await api.put(`/groups/${encodeURIComponent(groupId)}/users`, { userIds });
};
