/**
 * AlertsView constants: tab config, severity levels, column names.
 */

import type { AlertsViewTabConfig } from './types';

export const ALERTS_VIEW_TABS: AlertsViewTabConfig[] = [
  { id: 'metadata', label: 'Metadata', icon: 'fa-info-circle' },
];

export const SEVERITY_LEVELS = {
  CRITICAL: '4',
  HIGH: '3',
  MEDIUM: '2',
  LOW: '1',
} as const;

export const WINDOWS_SIGNAL_COLUMNS = [
  'action', 'cmdline', 'event_type', 'owner_uid', 'parent_path', 'ppid', 'pid',
  'path', 'parent_process_guid', 'process_guid', 'uptime',
] as const;

export const LINUX_SIGNAL_COLUMNS = [
  'cwd', 'cmdline', 'event_type', 'pid', 'parent', 'tid', 'uid', 'guid', 'cid',
  'path', 'syscall', 'exit_code', 'probe_error', 'duration',
] as const;

export const REFERENCE_LOG_COLUMNS = [
  'is_container_process', 'pid', 'parent', 'syscall', 'unixTime', 'cid',
  'cmdline', 'cwd', 'path', 'exit_code',
] as const;

export const LOG_TYPES = ['Process', 'File', 'Socket'] as const;
