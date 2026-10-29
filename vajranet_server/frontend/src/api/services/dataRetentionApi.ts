/**
 * Data Retention API functions
 */

import api from '../axiosInstance';

export interface DataRetentionPolicyData {
  id: number;
  tableNames: string[];
  databaseName: string;
  timestampColumn: string;
  retentionType: 'time' | 'row_count';
  retentionDays: number | null;
  rowCountLimit: number | null;
  scheduleType: 'daily' | 'weekly' | 'monthly' | 'custom';
  cronExpression: string;
  cleanupTime: string;
}

export interface DataRetentionPoliciesResponse {
  success: boolean;
  data: DataRetentionPolicyData[];
}

export interface CreateDataRetentionRequest {
  tableNames: string[];
  databaseName: string;
  timestampColumn?: string;
  retentionType?: 'time' | 'row_count';
  retentionDays?: number | null;
  rowCountLimit?: number | null;
  scheduleType?: 'daily' | 'weekly' | 'monthly' | 'custom';
  cronExpression?: string;
  cleanupTime?: string;
}

export const getDataRetentionPolicies = async (): Promise<DataRetentionPoliciesResponse> => {
  const response = await api.get('/data-retention');
  return response.data;
};

export interface DataRetentionPolicyResponse {
  success: boolean;
  message?: string;
  data: DataRetentionPolicyData;
}

export const createDataRetentionPolicy = async (
  data: CreateDataRetentionRequest
): Promise<DataRetentionPolicyResponse> => {
  const response = await api.post(`/data-retention`, data);
  return response.data;
};

export const updateDataRetentionPolicy = async (
  id: number,
  data: CreateDataRetentionRequest
): Promise<DataRetentionPolicyResponse> => {
  const response = await api.put(`/data-retention/${id}`, data);
  return response.data;
};

export const deleteDataRetentionPolicy = async (id: number): Promise<{ success: boolean; message?: string }> => {
  const response = await api.delete(`/data-retention/${id}`);
  return response.data;
};

export const getDatabases = async (): Promise<{ success: boolean; data: string[] }> => {
  const response = await api.get('/data-retention/databases');
  return response.data;
};

export const getTables = async (db: string): Promise<{ success: boolean; data: string[] }> => {
  const response = await api.get(`/data-retention/tables/${db}`);
  return response.data;
};

export const getColumns = async (db: string, table: string): Promise<{ success: boolean; data: string[] }> => {
  const response = await api.get(`/data-retention/columns/${db}/${table}`);
  return response.data;
};
