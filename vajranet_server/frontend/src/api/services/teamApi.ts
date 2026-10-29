/**
 * Super Admin: team / user management API functions
 */

import api from '../axiosInstance';

export type UserRole = 'Super Administrator' | 'Group Admin' | 'Viewer';

export interface TeamMember {
  id: number;
  name: string;
  email: string;
  mobile: string;
  company: string;
  forcePasswordChange: boolean;
  address: string;
  role: UserRole;
  suspended: boolean;
  groupIds?: string[];
  created_at: string;
  updated_at: string;
}

export interface TeamListResponse {
  status: 'Success' | 'Error';
  message?: string;
  data?: {
    users: TeamMember[];
  };
}

export interface TeamMemberUpdateRequest {
  id: number;
  name: string;
  email: string;
  mobile: string;
  company: string;
  address: string;
  role: UserRole;
  suspended: boolean;
  groupIds?: string[];
}

export interface TeamMemberUpdateResponse {
  status: 'Success' | 'Error';
  message?: string;
  data?: {
    user: TeamMember;
  };
}

export interface TeamTransferOwnershipRequest {
  targetUserId: number;
}

export interface TeamTransferOwnershipResponse {
  status: 'Success' | 'Error';
  message?: string;
  data?: {
    fromUser: {
      id: number;
      role: UserRole;
      session_version: number;
    };
    toUser: {
      id: number;
      role: UserRole;
      session_version: number;
    };
  };
}

export interface ForcePasswordChangeTeamRequest {
  id: number;
  reason: string;
}

export interface ForcePasswordChangeTeamResponse {
  status: 'Success' | 'Error';
  message?: string;
}

/**
 * Super admin: Get all team members and account details
 */
export const getTeamMembers = async (): Promise<TeamListResponse> => {
  const response = await api.get('/users/team');
  return response.data;
};

/**
 * Super admin: Update a team member's profile details and role
 */
export const updateTeamMember = async (
  data: TeamMemberUpdateRequest,
): Promise<TeamMemberUpdateResponse> => {
  const response = await api.post('/users/team/update', data);
  return response.data;
};

/**
 * Super admin: Transfer super admin ownership to another team member
 */
export const transferTeamOwnership = async (
  data: TeamTransferOwnershipRequest,
): Promise<TeamTransferOwnershipResponse> => {
  const response = await api.post('/users/team/transfer-ownership', data);
  return response.data;
};

/**
 * Super admin: Force password change for a team member
 */
export const forcePasswordChangeTeam = async (
  data: ForcePasswordChangeTeamRequest,
): Promise<ForcePasswordChangeTeamResponse> => {
  const response = await api.post('/users/team/force-password-change', data);
  return response.data;
};
