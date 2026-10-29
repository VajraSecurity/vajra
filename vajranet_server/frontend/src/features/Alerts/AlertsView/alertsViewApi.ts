/**
 * AlertsView API helpers.
 * Centralized alert-related API calls for use by AlertsView and tab components.
 */

import api from '../../../api/axiosInstance';
import { ALERTS_URLS } from '../../../api/urls';

const withParams = (path: string, params: Record<string, string | number>) => {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => q.set(k, String(v)));
  return `${path}?${q.toString()}`;
};

export const alertsViewApi = {
  /** Fetch alert extra data by event_id and host_identifier */
  getAlertQuery: (eventId: number | string, hostIdentifier: string) =>
    api.get(withParams(ALERTS_URLS.QUERY, { event_id: eventId, host_identifier: hostIdentifier })),

  /**
   * Fetch full alert record by id (no open/closed search heuristic).
   * Used for Audit Trail navigation where we may not have host metadata for list search.
   */
  getAlertFromById: (eventId: number | string) =>
    api.get(withParams(ALERTS_URLS.BY_ID, { id: eventId })),

  /** Fetch event assignee */
  getAssignee: (eventId: number | string) =>
    api.get(withParams(ALERTS_URLS.ASSIGNEE, { id: eventId })),

  /** Fetch current alert status (is_open, action) */
  getStatus: (eventIds: Array<number | string>) =>
    api.post(ALERTS_URLS.STATUS, { event_id: eventIds }),

  /** Update alert (e.g. assign, status) */
  updateAlert: (payload: Record<string, unknown>) =>
    api.post(ALERTS_URLS.UPDATE, payload),

  /** Export alerts (xls/csv/txt) */
  exportAlerts: (params: { format: string; event_ids?: string; start_time?: string; end_time?: string }) =>
    api.get(withParams(ALERTS_URLS.EXPORT, params as Record<string, string | number>), { responseType: 'blob' }),
};
