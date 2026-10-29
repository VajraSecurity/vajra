/**
 * AI Assistant — provider configuration API functions
 */

import api from '../axiosInstance';

export type AiProvider = 'anthropic' | 'openai';

export interface AiProviderConfigData {
  provider: AiProvider;
  api_key_masked: string;
  model: string | null;
  base_url: string | null;
  organization: string | null;
  max_output_tokens: number | null;
  created_by_name: string | null;
  created_at: string;
  updated_at: string;
}

export interface SaveAiProviderConfigRequest {
  provider: AiProvider;
  api_key: string;
  model?: string;
  base_url?: string;
  organization?: string;
  max_output_tokens?: number;
}

export interface TestAiProviderConfigRequest {
  provider?: AiProvider;
  api_key?: string;
  model?: string;
  base_url?: string;
  organization?: string;
}

export const getAiProviderConfigStatus = async (): Promise<{ success: boolean; configured: boolean }> => {
  const response = await api.get('/ai/config/status');
  return response.data;
};

export const getAiProviderConfig = async (): Promise<{ success: boolean; data: AiProviderConfigData | null }> => {
  const response = await api.get('/ai/config');
  return response.data;
};

export const saveAiProviderConfig = async (data: SaveAiProviderConfigRequest): Promise<{ success: boolean; message: string }> => {
  const response = await api.post('/ai/config', data);
  return response.data;
};

export const testAiProviderConfig = async (data?: TestAiProviderConfigRequest): Promise<{ success: boolean; message: string }> => {
  const response = await api.post('/ai/config/test', data ?? {});
  return response.data;
};

export const deleteAiProviderConfig = async (): Promise<{ success: boolean; message: string }> => {
  const response = await api.delete('/ai/config');
  return response.data;
};
