/**
 * AlertsView types. Used across AlertsView and tab components.
 * Compatible with mock alert shape (title, description, timestamp, source) and backend Event shape.
 */

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | string;

export interface AlertData {
  id: number | string;
  severity: AlertSeverity;
  /** Mock list page */
  title?: string;
  description?: string;
  timestamp?: string;
  source?: string;
  /** Backend / Event shape */
  event_code?: string;
  host_identifier?: string;
  hostname?: string;
  os_name?: string;
  unixtime?: string | number;
  is_open?: boolean;
  link?: string;
  technique?: string;
  [key: string]: unknown;
}

export type AlertsViewTabId =
  | 'metadata';

export interface AlertsViewTabConfig {
  id: AlertsViewTabId;
  label: string;
  icon: string;
}
