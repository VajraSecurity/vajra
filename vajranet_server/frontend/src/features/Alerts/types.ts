/**
 * Shared types for the Alerts feature — extracted verbatim, no content changes.
 */

import type { CertinFormDataType } from './CertInTypes';

export type Tab = 'open' | 'closed' | 'my';
export type SeverityFilter = 'critical' | 'high' | 'medium' | 'low';
export type AssigneeFilter = 'assigned' | 'unassigned';
export type PositiveFilter = 'true_positive' | 'false_positive';
// Superset of PositiveFilter used for the mark action/modal — adds 'unmarked' to undo a TP/FP classification.
export type MarkAction = PositiveFilter | 'unmarked';
export type UserOption = { id: number; name: string; email: string };

export interface AlertItem {
  id: number | string;
  host_identifier: string;
  hostname: string;
  unixtime: string | number;
  event_code: string;
  metadata: Record<string, unknown> | null;
  is_alert: boolean;
  is_open: boolean;
  severity: string;
  alert_type: string;
  os_name: string;
  assignee_id?: number | string | null;
  assignee_name?: string | null;
  assignee_email?: string | null;
  mark_type?: string | null;
  action?: string | null;
}

export interface CertinDraft {
  id?: number | string;
  formData?: CertinFormDataType;
  selectedAlertIds?: string[];
  updated_at?: string;
  updatedAt?: string;
  created_at?: string;
  createdAt?: string;
  timestamp?: string;
  expiresAt?: string;
}

/** One entry of the CERT-In draft audit history (backend `certin-draft/history` endpoint). */
export interface CertinDraftHistoryEntry {
  formData?: CertinFormDataType;
  eventType?: string;
  actor?: { name?: string; email?: string; userId?: number | string };
  filename?: string;
  storedAt?: string;
}

export interface NodePrefillData {
  osquery_info?: { internal_ip?: string };
  host_ip_address?: string;
  os_name?: string;
  os_version?: string;
  system_info?: { hardware_model?: string };
}

