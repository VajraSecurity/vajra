/**
 * Pure formatting/classification helpers for the NotificationLogs (audit
 * trail) feature — extracted verbatim, no logic changes.
 */

import type { AuditTrailEntry, AuditUserLite } from '../types';

export const ROWS_PER_PAGE = 20;
export const SEARCH_DEBOUNCE_MS = 300;

export function initialsFrom(nameOrEmail: string): string {
  const s = String(nameOrEmail || '').trim();
  if (!s) return '—';
  const parts = s
    .replace(/[^a-zA-Z0-9\s@._-]/g, '')
    .split(/\s+/)
    .filter(Boolean);
  const first = parts[0] ?? s;
  const second = parts[1] ?? '';
  const a = first[0] ?? '';
  const b = second[0] ?? '';
  const out = (a + b).toUpperCase();
  return out || s.slice(0, 2).toUpperCase();
}

export function timeAgo(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '—';
  const deltaSec = Math.floor((Date.now() - t) / 1000);
  const abs = Math.abs(deltaSec);
  const suffix = deltaSec >= 0 ? 'ago' : 'from now';
  if (abs < 60) return `${abs}s ${suffix}`;
  const min = Math.floor(abs / 60);
  if (min < 60) return `${min}m ${suffix}`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h ${suffix}`;
  const d = Math.floor(h / 24);
  return `${d}d ${suffix}`;
}

export function formatDuration(seconds: number | null): string {
  if (seconds == null) return '—';
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return s > 0 ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm > 0 ? `${h}h ${rm}m` : `${h}h`;
}

export function userLabelFromLite(user: AuditUserLite, fallbackId?: string): string {
  const name = typeof user?.name === 'string' ? user.name.trim() : '';
  const email = typeof user?.email === 'string' ? user.email.trim() : '';
  if (name && email) return `${name} <${email}>`;
  if (name) return name;
  if (email) return email;
  return fallbackId ? `user #${fallbackId}` : '—';
}

export function formatAuditAction(log: AuditTrailEntry): string {
  const statusLabel = log.status === 'success' ? 'Success' : 'Failed';
  const details = (log.details ?? null) as Record<string, unknown> | null | undefined;
  const reason =
    typeof details?.reason === 'string' ? details.reason.trim() : '';
  const hostLabel = (() => {
    const d = details;
    const hostname = typeof d?.hostname === 'string' ? (d.hostname as string) : '';
    const hostId =
      typeof d?.host_identifier === 'string'
        ? (d.host_identifier as string)
        : typeof d?.host_identifier === 'number'
          ? String(d.host_identifier)
          : '';
    const label = hostname || hostId ? [hostname || null, hostId ? `(${hostId})` : null].filter(Boolean).join(' ') : '';
    return label ? ` on ${label}` : '';
  })();

  switch (log.action) {
    case 'LOGIN': {
      const ip = log.ip_address?.replace(/^::ffff:/, '') || '';
      return `Login ${statusLabel}${ip ? ` from ${ip}` : ''}`;
    }
    case 'LOGOUT': {
      const ip = log.ip_address?.replace(/^::ffff:/, '') || '';
      const logoutReason = typeof details?.reason === 'string' ? details.reason : '';
      const isForced = logoutReason === 'invalidated_by_admin' || logoutReason === 'all_sessions_invalidated_by_admin';
      return `Logout ${statusLabel}${isForced ? ' (Forced by Admin)' : ''}${ip ? ` from ${ip}` : ''}`;
    }
    case 'USER_REGISTER': {
      const ip = log.ip_address?.replace(/^::ffff:/, '') || '';
      return `Registration ${statusLabel}${ip ? ` from ${ip}` : ''}`;
    }
    case 'PASSWORD_UPDATE':
      return `Password update ${statusLabel}`;
    case 'RENAME_NODE': {
      const oldName = typeof details?.old_hostname === 'string' && details.old_hostname ? details.old_hostname : '';
      const newName = typeof details?.new_hostname === 'string' && details.new_hostname ? details.new_hostname : '';
      if (oldName && newName) {
        return `Renamed node from "${oldName}" to "${newName}"${hostLabel}`;
      } else if (newName) {
        return `Renamed node to "${newName}"${hostLabel}`;
      }
      return `Node renamed${hostLabel}`;
    }
    case 'MARK_NODE_CRITICAL': {
      const actionType = typeof details?.action === 'string' ? details.action : 'marked';
      if (actionType === 'unmarked') {
        return `Unmarked node as critical${reason ? ` — ${reason}` : ''}${hostLabel}`;
      }
      return `Marked node as critical${reason ? ` — ${reason}` : ''}${hostLabel}`;
    }
    case 'CERTIN_DRAFT_DOWNLOAD':
      return `Downloaded CERT-In draft${hostLabel}`;
    case 'ISOLATE_NODE':
      return `Isolate node ${statusLabel}${reason ? ` — ${reason}` : ''}${hostLabel}`;
    case 'REENROLL_NODE':
      return `Re-enroll node ${statusLabel}${reason ? ` — ${reason}` : ''}${hostLabel}`;
    case 'ALERT_STATUS_UPDATE':
      return log.details?.is_open === true ? 'Opened alert(s)' : log.details?.is_open === false ? 'Closed alert(s)' : 'Updated alert(s)';
    case 'ALERT_ASSIGN_UPDATE': {
      const assignmentTypeRaw =
        typeof details?.assignment_type === 'string' ? details.assignment_type.toLowerCase() : '';
      const assigneeId =
        typeof details?.assignee_id === 'string' || typeof details?.assignee_id === 'number'
          ? String(details?.assignee_id)
          : '';
      const assignmentChanges = Array.isArray(details?.assignment_changes)
        ? (details?.assignment_changes as Array<Record<string, unknown>>)
        : [];
      const usersMap =
        details?.users && typeof details.users === 'object'
          ? (details.users as Record<string, { id?: number; name?: string | null; email?: string | null }>)
          : {};
      const singleChange = assignmentChanges.length === 1 ? assignmentChanges[0] : null;
      const fromAssigneeId =
        singleChange && (typeof singleChange.from_assignee_id === 'number' || typeof singleChange.from_assignee_id === 'string')
          ? String(singleChange.from_assignee_id)
          : '';
      const toAssigneeId =
        singleChange && (typeof singleChange.to_assignee_id === 'number' || typeof singleChange.to_assignee_id === 'string')
          ? String(singleChange.to_assignee_id)
          : assigneeId;
      const fromAssigneeLabel = userLabelFromLite(
        (singleChange?.from_assignee as AuditUserLite) ?? (fromAssigneeId ? usersMap[fromAssigneeId] : null),
        fromAssigneeId || undefined,
      );
      const toAssigneeLabel = userLabelFromLite(
        (singleChange?.to_assignee as AuditUserLite) ?? (toAssigneeId ? usersMap[toAssigneeId] : null),
        toAssigneeId || undefined,
      );
      const eventIds =
        Array.isArray(details?.event_ids) ? details?.event_ids.map((v) => String(v)).join(', ') : '';
      if (assignmentTypeRaw === 'reassigned' && fromAssigneeId && toAssigneeId) {
        return `Reassigned alert(s) from ${fromAssigneeLabel} to ${toAssigneeLabel}${eventIds ? ` (alerts: ${eventIds})` : ''}`;
      }
      if (assignmentTypeRaw === 'mixed') {
        return eventIds ? `Assigned/Reassigned alert(s) (${eventIds})` : 'Assigned/Reassigned alert(s)';
      }
      if (assignmentTypeRaw === 'unassigned') {
        return fromAssigneeId
          ? `Unassigned alert(s) from ${fromAssigneeLabel}${eventIds ? ` (alerts: ${eventIds})` : ''}`
          : eventIds
            ? `Unassigned alert(s) (${eventIds})`
            : 'Unassigned alert(s)';
      }
      return toAssigneeId
        ? `Assigned alert(s) to ${toAssigneeLabel}${eventIds ? ` (alerts: ${eventIds})` : ''}`
        : eventIds
          ? `Assigned alert(s) (${eventIds})`
          : 'Assigned alert(s)';
    }
    case 'ALERT_MARK_UPDATE': {
      const markRaw = typeof details?.mark === 'string' ? details.mark : '';
      const label =
        markRaw === 'true_positive'
          ? 'True Positive'
          : markRaw === 'false_positive'
            ? 'False Positive'
            : markRaw === 'unmarked'
              ? 'Unmarked'
              : 'Marked';
      return `${label} alert(s)${reason ? ` — ${reason}` : ''}`;
    }
    case 'PORT_BLOCK':
      return `${log.details?.sub_action === 'allow' ? 'Port allow' : 'Port block'}${hostLabel}${log.details?.port ? `: ${String(log.details.port)}` : ''
        }${log.details?.protocol ? `/${String(log.details.protocol)}` : ''}`;
    case 'IP_BLOCK':
      return `${log.details?.sub_action === 'allow' ? 'IP allow' : 'IP block'}${hostLabel}${log.details?.ip ? `: ${String(log.details.ip)}` : ''
        }${log.details?.port ? `:${String(log.details.port)}` : ''}`;
    case 'COMPLIANCE':
      return `Compliance check${hostLabel}`;
    case 'WIFI':
      return `WiFi status${hostLabel}`;
    case 'BLUETOOTH':
      return `${log.details?.sub_action ? `Bluetooth ${String(log.details.sub_action)}` : 'Bluetooth'}${hostLabel}`;
    case 'DEFENDER':
      return `Defender action${hostLabel}`;
    case 'USB':
      return `${log.details?.sub_action ? `USB ${String(log.details.sub_action)}` : 'USB'}${hostLabel}`;
    case 'CLAMAV':
      return `${log.details?.sub_action ? `ClamAV ${String(log.details.sub_action)}` : 'ClamAV'}${hostLabel}${
        log.details?.path ? `: ${String(log.details.path)}` : ''
      }`;
    default:
      return `${log.action} ${statusLabel}`;
  }
}

export const WEBSOCKET_ACTIONS = new Set<string>([
  'PORT_BLOCK',
  'IP_BLOCK',
  'COMPLIANCE',
  'WIFI',
  'BLUETOOTH',
  'DEFENDER',
  'USB',
  'CLAMAV',
]);
export const WEBSOCKET_ACTIONS_CSV = Array.from(WEBSOCKET_ACTIONS).join(',');
export const ALERT_ACTIONS_CSV = 'ALERT_STATUS_UPDATE,ALERT_ASSIGN_UPDATE,ALERT_MARK_UPDATE';

export function isWebsocketLog(log: AuditTrailEntry): boolean {
  return WEBSOCKET_ACTIONS.has(log.action);
}

export function isAlertLog(log: AuditTrailEntry): boolean {
  return log.action === 'ALERT_STATUS_UPDATE' || log.action === 'ALERT_ASSIGN_UPDATE' || log.action === 'ALERT_MARK_UPDATE';
}

