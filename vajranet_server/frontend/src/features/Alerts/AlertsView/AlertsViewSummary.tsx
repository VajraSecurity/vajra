/**
 * AlertsView: Summary row — severity/timestamp card, action controls, summary card.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { AlertData } from './types';
import AlertsViewActionControls from './AlertsViewActionControls';
import { alertsViewApi } from './alertsViewApi';
import { normalizeSev, SEV_BADGE_NEW, SEV_LABEL } from '../utils/alertsHelpers';

interface AlertsViewSummaryProps {
  alert: AlertData;
  onActionComplete?: () => void;
}

const formatUnixSeconds = (unixtime: string | number | undefined) => {
  if (unixtime == null) return null;
  const t = typeof unixtime === 'string' ? parseInt(unixtime, 10) : unixtime;
  if (!isFinite(t as number)) return null;
  const ms = (t as number) * 1000;
  if (!isFinite(ms)) return null;
  return new Date(ms).toLocaleString();
};

const formatTimeWithFallback = (alert: AlertData) => {
  if (alert.timestamp) {
    return {
      primary: alert.timestamp,
      secondary: alert.unixtime != null ? `Unix: ${String(alert.unixtime)}` : null,
    };
  }

  const unixFormatted = formatUnixSeconds(alert.unixtime);
  if (unixFormatted) {
    return {
      primary: unixFormatted,
      secondary: `Unix: ${String(alert.unixtime)}`,
    };
  }

  return {
    primary: 'Not available',
    secondary: null,
  };
};

const AlertsViewSummary = ({ alert, onActionComplete }: AlertsViewSummaryProps) => {
  const displayTitle = alert.title ?? alert.event_code ?? `Alert ${alert.id}`;
  const displayDesc = alert.description ?? '—';
  const displaySource = alert.source ?? alert.hostname ?? '—';

  const eventId = useMemo(() => {
    return typeof alert.id === 'number' ? alert.id : parseInt(String(alert.id), 10);
  }, [alert.id]);

  const [assignedMetaLoading, setAssignedMetaLoading] = useState(false);
  const [assignedMetaError, setAssignedMetaError] = useState<string | null>(null);
  const [assignedMeta, setAssignedMeta] = useState<{
    assignedBy: { name: string; email: string } | null;
    assignee: { name: string; email: string } | null;
    assignedAt: string | null;
    status: string | null;
  } | null>(null);

  // Extracted so it can be re-run both on mount/eventId change and on demand
  // after an Open/Close/Assign action completes (assignment data lives here,
  // not in the parent `alert` object, so a parent-level refetch alone can't
  // refresh it).
  const fetchAssignedMeta = useCallback(() => {
    if (!eventId || !Number.isFinite(eventId) || eventId <= 0) return undefined;

    let cancelled = false;
    setAssignedMetaLoading(true);
    setAssignedMetaError(null);

    void alertsViewApi
      .getAssignee(eventId)
      .then((res) => {
        if (cancelled) return;
        const data = res?.data?.data;
        const assignee =
          data?.assignee && (data.assignee.id != null || data.assignee.name != null || data.assignee.email != null)
            ? {
                name: String(
                  data.assignee.name ?? (data.assignee.id ? `User #${data.assignee.id}` : ''),
                ),
                email: String(data.assignee.email ?? ''),
              }
            : null;

        const assignedBy =
          data?.assignedBy && (data.assignedBy.id != null || data.assignedBy.name != null || data.assignedBy.email != null)
            ? {
                name: String(
                  data.assignedBy.name ?? (data.assignedBy.id ? `User #${data.assignedBy.id}` : ''),
                ),
                email: String(data.assignedBy.email ?? ''),
              }
            : null;
        const assignedAt = data?.assignedAt != null ? String(data.assignedAt) : null;
        const status = typeof data?.status === 'string' ? data.status : null;

        setAssignedMeta({
          assignedBy,
          assignee,
          assignedAt,
          status,
        });
      })
      .catch(() => {
        if (cancelled) return;
        setAssignedMetaError('Failed to load assignment details.');
      })
      .finally(() => {
        if (cancelled) return;
        setAssignedMetaLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [eventId]);

  useEffect(() => {
    setAssignedMeta(null);
    return fetchAssignedMeta();
  }, [fetchAssignedMeta]);

  // Refresh assignment details in place after an action succeeds, in addition
  // to bubbling the completion up so the parent can refetch the alert record.
  const handleActionComplete = useCallback(() => {
    fetchAssignedMeta();
    onActionComplete?.();
  }, [fetchAssignedMeta, onActionComplete]);

  const eventTime = formatTimeWithFallback(alert);

  return (
    <div className="grid grid-cols-1 md:grid-cols-[320px_260px_1fr] gap-4 mb-6 items-stretch min-h-[240px]">
      {/* Severity + metadata — top section, spacer, bottom section so height fills evenly */}
      <div className="bg-white rounded-xl border border-blue-100 shadow-sm p-5 w-full flex flex-col min-h-[240px]">
        <div className="shrink-0">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-gray-500 mb-1.5">Severity</p>
              <span className={`inline-block ${SEV_BADGE_NEW[normalizeSev(alert.severity)]}`}>
                {SEV_LABEL[normalizeSev(alert.severity)]}
              </span>
            </div>
            <div className="text-right shrink-0">
              <p className="text-xs font-medium uppercase tracking-wide text-gray-500 mb-1">Alert</p>
              <p className="text-sm font-semibold text-gray-900">#{alert.id}</p>
            </div>
          </div>

          <div className="mt-4">
            <p className="text-xs font-medium uppercase tracking-wide text-gray-500 mb-1.5">Event time</p>
            <p className="text-sm font-medium text-gray-900">{eventTime.primary}</p>
            {eventTime.secondary && (
              <p className="text-xs text-gray-400 mt-0.5">{eventTime.secondary}</p>
            )}
          </div>
        </div>

        <div className="flex-1 min-h-3" aria-hidden />

        <div className="shrink-0 pt-3 border-t border-blue-100 space-y-3">
          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-gray-500 mb-1">Host</p>
            <p className="text-sm font-medium text-gray-900 truncate">
              {alert.hostname ?? alert.host_identifier ?? '—'}
            </p>
          </div>
          <div className="grid grid-cols-2 gap-x-4 gap-y-2">
            <div>
              <p className="text-xs text-gray-500 mb-0.5">OS</p>
              <p className="text-sm text-gray-900 font-medium truncate">{alert.os_name ?? '—'}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 mb-0.5">Type</p>
              <p className="text-sm text-gray-900 font-medium truncate">{alert.technique ?? '—'}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Action controls */}
      <AlertsViewActionControls alert={alert} onActionComplete={handleActionComplete} />

      {/* Summary — top section, spacer, assignment block; divider aligns with Severity card */}
      <div className="min-w-0 bg-white rounded-xl border border-blue-100 shadow-sm p-5 w-full flex flex-col min-h-[240px]">
        <div className="shrink-0">
          <p className="text-xs font-medium uppercase tracking-wide text-gray-500 mb-2">Summary</p>
          <h3 className="font-semibold text-gray-900 text-base leading-tight mb-1.5">{displayTitle}</h3>
          <p className="text-sm text-gray-600 line-clamp-2" title={displayDesc}>{displayDesc}</p>
          <p className="text-xs text-gray-500 mt-2">Source: {displaySource}</p>
        </div>

        <div className="flex-1 min-h-3" aria-hidden />

        {(assignedMeta?.assignee != null || assignedMeta?.assignedBy != null) ? (
          <div className="shrink-0 pt-3 border-t border-blue-100">
            <p className="text-xs font-medium uppercase tracking-wide text-gray-500 mb-2">Assignment</p>
            <div className="grid grid-cols-2 gap-x-6 gap-y-3">
              <div className="min-w-0">
                <p className="text-xs text-gray-500 mb-0.5">Assigned by</p>
                <p className="text-sm font-medium text-gray-900 truncate">
                  {assignedMetaLoading
                    ? 'Loading…'
                    : assignedMetaError
                      ? '—'
                      : assignedMeta?.assignedBy
                        ? assignedMeta.assignedBy.email
                          ? `${assignedMeta.assignedBy.name} (${assignedMeta.assignedBy.email})`
                          : assignedMeta.assignedBy.name
                        : '—'}
                </p>
              </div>
              <div className="min-w-0">
                <p className="text-xs text-gray-500 mb-0.5">Assigned to</p>
                <p className="text-sm font-medium text-gray-900 truncate">
                  {assignedMetaLoading
                    ? 'Loading…'
                    : assignedMetaError
                      ? '—'
                      : assignedMeta?.assignee
                        ? assignedMeta.assignee.email
                          ? `${assignedMeta.assignee.name} (${assignedMeta.assignee.email})`
                          : assignedMeta.assignee.name
                        : '—'}
                </p>
              </div>
              <div className="min-w-0">
                <p className="text-xs text-gray-500 mb-0.5">Time of assignment</p>
                <p className="text-sm font-medium text-gray-900 truncate">
                  {assignedMetaLoading
                    ? '—'
                    : assignedMetaError
                      ? '—'
                      : assignedMeta?.assignedAt
                        ? new Date(assignedMeta.assignedAt).toLocaleString()
                        : eventTime.primary}
                </p>
              </div>
              <div className="min-w-0">
                <p className="text-xs text-gray-500 mb-0.5">Status</p>
                <p className="text-sm font-medium text-gray-900 truncate">
                  {assignedMetaLoading
                    ? '—'
                    : assignedMetaError
                      ? '—'
                      : assignedMeta?.status ?? (typeof alert.is_open === 'boolean' ? (alert.is_open ? 'Open' : 'Closed') : '—')}
                </p>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
};

export default AlertsViewSummary;
