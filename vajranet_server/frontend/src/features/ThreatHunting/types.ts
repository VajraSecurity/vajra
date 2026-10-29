export type PlatformChoice = 'linux' | 'windows' | 'macos';
export type Platform = 'all' | PlatformChoice;
export type PlatformSelection = Platform | PlatformChoice[];

export interface SavedQuery {
  id: number;
  name: string;
  description: string | null;
  query: string;
  platform: string;
  node_state?: string | null;
  defense_kit?: string[] | null;
  detection_subtypes?: string[] | null;
  created_by_user_id: number | null;
  created_by_name: string | null;
  created_at: string;
  updated_at: string;
}

export interface RunQueryResponse {
  success: boolean;
  data: Record<string, unknown>[];
  count: number;
  truncated: boolean;
  message?: string;
}

export const PLATFORM_LABELS: Record<Platform, string> = {
  all: 'All platforms',
  linux: 'Linux',
  windows: 'Windows',
  macos: 'macOS',
};

export const PLATFORM_COLORS: Record<Platform, string> = {
  all:     'bg-emerald-50 text-emerald-700 border-emerald-200',
  linux:   'bg-orange-50 text-orange-700 border-orange-200',
  windows: 'bg-blue-50 text-blue-700 border-blue-200',
  macos:   'bg-slate-100 text-slate-700 border-slate-200',
};
