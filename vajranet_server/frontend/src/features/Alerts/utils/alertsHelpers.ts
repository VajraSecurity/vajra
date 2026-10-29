/**
 * Pure helpers, constants, and CERT-In draft utilities for the Alerts feature —
 * extracted verbatim, no logic changes.
 */

import { ALERTS_URLS, getApiUrl } from '../../../api/urls';
import type { CertinFormDataType } from '../CertInTypes';
import type { AlertItem, CertinDraft, MarkAction } from '../types';

// Kept in sync with CertInModal's own validateAndDownload() required-field list —
// this gates canDownloadDraft, so drifting from the modal's list would let a draft
// be flagged "complete" and downloaded as a final CERT-In submission while missing
// fields the modal itself would otherwise block on.
export const CERTIN_REQUIRED_FIELDS: Array<keyof CertinFormDataType> = [
  'iAm',
  'reporterRole',
  'reporterNameTitle',
  'reporterContactNo',
  'reporterEmail',
  'reporterAddress',
  'incidentTypes',
  'isCritical',
  'criticalBriefDetails',
  'affectedSystemDomainUrl',
  'affectedSystemIp',
  'affectedSystemOs',
  'affectedSystemMakeModelCloud',
  'affectedSystemLocation',
  'affectedSystemIsp',
  'incidentBriefDescription',
  'occurrenceDateTime',
  'detectionDateTime',
];

export function getDraftTimestampMs(draft: CertinDraft | null): number | null {
  const raw = draft?.updated_at ?? draft?.updatedAt ?? draft?.created_at ?? draft?.createdAt ?? draft?.timestamp;
  if (!raw) return null;
  const ts = new Date(raw).getTime();
  return Number.isFinite(ts) ? ts : null;
}

export function isDraftWithin24Hours(draft: CertinDraft | null): boolean {
  const draftTs = getDraftTimestampMs(draft);
  if (!draftTs) return false;
  return Date.now() - draftTs <= 24 * 60 * 60 * 1000;
}

export function isCertinDraftComplete(formData?: Partial<CertinFormDataType> | null): boolean {
  if (!formData) return false;
  return CERTIN_REQUIRED_FIELDS.every((field) => {
    const value = formData[field];
    if (Array.isArray(value)) return value.length > 0;
    return String(value ?? '').trim().length > 0;
  });
}

export function formatRelativeDuration(ms: number): string {
  if (ms <= 0) return '0m';
  const totalSeconds = Math.floor(ms / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

// Severity helpers

export function normalizeSev(s: string | number | undefined): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  const key = String(s ?? '').toLowerCase();
  if (key === 'critical' || key === 'severe' || key === '4' || key === '5') return 'critical';
  if (key === 'high' || key === '3') return 'high';
  if (key === 'medium' || key === 'moderate' || key === '2') return 'medium';
  if (key === 'low' || key === '1') return 'low';
  if (key === 'info' || key === '0' || key === 'informational' || key === 'information') return 'info';
  return 'info';
}

export const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' } as const;

export const MARK_ACTION_LABEL: Record<MarkAction, string> = {
  true_positive: 'True Positive',
  false_positive: 'False Positive',
  unmarked: 'Unmarked',
};

// High and medium must keep distinct text colors: on these near-identical
// backgrounds a shared color is indistinguishable at a glance, not only for
// colorblind users. Paired with getAlertIcon() so severity never relies on
// color alone.
export const SEV_BADGE_NEW: Record<string, string> = {
  critical: 'bg-[#FCEBEB] text-[#A32D2D] font-medium text-xs px-2.5 py-1.5 rounded-full',
  high: 'bg-[#FBE7D4] text-[#9A3412] font-medium text-xs px-2.5 py-1.5 rounded-full',
  medium: 'bg-[#FAF3D0] text-[#854F0B] font-medium text-xs px-2.5 py-1.5 rounded-full',
  low: 'bg-[#EAF3DE] text-[#3B6D11] font-medium text-xs px-2.5 py-1.5 rounded-full',
  info: 'bg-[#F1EFE8] text-[#5F5E5A] font-medium text-xs px-2.5 py-1.5 rounded-full',
};

export const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-400',
  low: 'bg-green-500',
  info: 'bg-gray-400',
};

export const SEV_ICON_COLOR: Record<string, string> = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#CA8A04',
  low: '#16A34A',
  info: '#6B7280',
};

export function getAlertIcon(sev: ReturnType<typeof normalizeSev>): string {
  switch (sev) {
    case 'critical': return 'fa fa-triangle-exclamation';
    case 'high': return 'fa fa-exclamation-triangle';
    case 'medium': return 'fa fa-exclamation-circle';
    case 'low': return 'fa fa-info-circle';
    default: return 'fa fa-bell';
  }
}
export const toolbarVariants = {
  hidden: { y: 80, opacity: 0, scale: 0.98 },
  visible: {
    y: 0,
    opacity: 1,
    scale: 1,
    transition: { type: "spring" as const, stiffness: 260, damping: 24 },
  },
  exit: { y: 80, opacity: 0, scale: 0.98, transition: { duration: 0.2 } },
} as const;

export function fmtTime(unixtime: string | number | undefined): string {
  if (!unixtime) return '—';
  const t = typeof unixtime === 'string' ? parseInt(unixtime, 10) : unixtime;
  if (isNaN(t)) return '—';
  return new Date(t * 1000).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

// Compact age ("5m", "3h", "2d") for an alert's unixtime. A missing or zero
// timestamp would otherwise measure from 1970 and render as "20755d".
export function fmtAlertAge(unixtime: string | number | null | undefined, nowMs: number = Date.now()): string {
  let t = typeof unixtime === 'string' ? Number(unixtime) : Number(unixtime ?? 0);
  if (!Number.isFinite(t) || t <= 0) return '—';
  if (t > 1e11) t = t / 1000; // millisecond epoch
  const mins = Math.max(0, Math.round((nowMs / 1000 - t) / 60));
  if (mins >= 1440) return `${Math.floor(mins / 1440)}d`;
  if (mins >= 60) return `${Math.floor(mins / 60)}h`;
  return `${mins}m`;
}

export function getAlertAssigneeId(a: AlertItem): number | null {
  const raw = a.assignee_id;
  if (raw == null) return null;
  const n = typeof raw === 'number' ? raw : Number(raw);
  return Number.isFinite(n) && n > 0 ? n : null;
}

export function getBulkAssignMode(alerts: AlertItem[]): 'assign' | 'reassign' {
  return alerts.some((x) => getAlertAssigneeId(x) != null) ? 'reassign' : 'assign';
}

// Metadata helpers

// Keys categorization for organized metadata display
export const META_SYSTEM_KEYS = new Set([
  'pid', 'ppid', 'gid', 'uid', 'process_id', 'parent_process_id',
  'target_user', 'privileged', 'integrity_level', 'session_id',
]);

export const META_FILE_KEYS = new Set([
  'path', 'file_path', 'module_path', 'image', 'md5', 'sha1', 'sha256', 'hash',
  'file_name', 'filename', 'file_description', 'company_name', 'product_name',
]);

export const META_PROCESS_KEYS = new Set([
  'cmdline', 'command_line', 'command', 'arguments', 'args',
  'parent_image', 'parent_command_line', 'process_name', 'executable',
]);

export const META_NETWORK_KEYS = new Set([
  'source_ip', 'sourceip', 'destination_ip', 'destinationip', 'remote_address',
  'local_address', 'port', 'source_port', 'destination_port', 'protocol',
  'connection', 'remote_port', 'local_port',
]);

export const META_PRIMARY_KEYS = new Set([
  'message', 'event_code', 'event_id', 'source', 'level',
  'category', 'severity', 'record_id', 'alert_type', 'type',
]);

export const META_TIMESTAMP_KEYS = new Set([
  'timestamp', 'initial_detection_time', 'last_threat_status_change',
  'detected', 'created_at', 'updated_at', 'event_time', 'time_created',
  'utc_time',
]);

export function classifyMetaKey(k: string): 'assignment' | 'system' | 'file' | 'process' | 'network' | 'primary' | 'timestamp' | 'empty' | 'other' {
  const lower = k.toLowerCase().replace(/\s+/g, '_');
  if (META_SYSTEM_KEYS.has(lower)) return 'system';
  if (META_FILE_KEYS.has(lower)) return 'file';
  if (META_PROCESS_KEYS.has(lower)) return 'process';
  if (META_NETWORK_KEYS.has(lower)) return 'network';
  if (META_PRIMARY_KEYS.has(lower)) return 'primary';
  if (META_TIMESTAMP_KEYS.has(lower)) return 'timestamp';
  return 'other';
}

export const ALERTS_UPDATE_URL = ALERTS_URLS.ALERTS_LIST.replace('/alerts/list', '/alerts/update');
export const ALERTS_MY_LIST_URL = ALERTS_URLS.ALERTS_LIST.replace('/alerts/list', '/alerts/list/my');
export const ALERTS_ASSIGN_URL = ALERTS_URLS.ALERTS_LIST.replace('/alerts/list', '/alerts/assign');
export const ALERTS_ASSIGNEE_URL = getApiUrl(ALERTS_URLS.ASSIGNEE);

export const ROWS_PER_PAGE = 10;

