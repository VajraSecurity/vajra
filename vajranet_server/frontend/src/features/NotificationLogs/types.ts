/**
 * Shared types for the NotificationLogs (audit trail) feature — extracted
 * verbatim, no content changes.
 */

export type AuditTrailEntry = {
  id: number;
  action: string;
  status: string;
  created_at: string;
  user_name?: string | null;
  user_email?: string | null;
  ip_address?: string | null;
  details?: Record<string, unknown> | null;
};

export type SessionEntry = {
  id: number;
  user_name?: string | null;
  user_email?: string | null;
  login_time: string;
  logout_time: string | null;
  duration_seconds: number | null;
  is_active: boolean;
  ip_address?: string | null;
  user_agent?: string | null;
  logout_reason?: string | null;
};

export type SortBy = 'created_at' | 'action' | 'status';
export type SessionSortBy = 'login_time' | 'logout_time';
export type SortOrder = 'asc' | 'desc';

export type AuditUserLite = { id?: number | string; name?: string | null; email?: string | null } | null;

export type UserByIdResponse = {
  status: string;
  data?: { user?: { id: number; name: string | null; email: string | null } };
};

export type TabId = 'user' | 'agent' | 'alerts' | 'sessions';

