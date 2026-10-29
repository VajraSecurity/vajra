/**
 * AlertsView: Main container for a single alert.
 * Opens from Alerts page "Investigate" button and from Audit Trail links.
 * If Audit Trail provides only partial state (e.g. just id), this view fetches
 * the full alert record so the UI is consistent.
 */

import { Link, useLocation } from 'react-router-dom';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { AlertData } from './types';
import AlertsViewNoData from './AlertsViewNoData';
import AlertsViewSummary from './AlertsViewSummary';
import AlertsViewMetadata from './AlertsViewMetadata';
import { alertsViewApi } from './alertsViewApi';
import { DuoSpinner } from '../../../components/ui/loading';

function toAlertData(state: unknown): AlertData | null {
  if (!state || typeof state !== 'object') return null;
  const o = state as Record<string, unknown>;
  return {
    id: o.id as number | string,
    severity: (o.severity as string) ?? 'info',
    title: o.title as string | undefined,
    description: o.description as string | undefined,
    timestamp: o.timestamp as string | undefined,
    source: o.source as string | undefined,
    event_code: o.event_code as string | undefined,
    host_identifier: o.host_identifier as string | undefined,
    hostname: o.hostname as string | undefined,
    os_name: o.os_name as string | undefined,
    unixtime: o.unixtime as string | number | undefined,
    is_open: o.is_open as boolean | undefined,
    link: o.link as string | undefined,
    technique: o.technique as string | undefined,
    ...o,
  };
}

export default function AlertsView() {
  const location = useLocation();
  const fromAuditTrail = Boolean((location.state as { fromAuditTrail?: unknown } | null)?.fromAuditTrail);
  const initialAlert = useMemo(() => toAlertData(location.state), [location.state]);
  const [resolvedAlert, setResolvedAlert] = useState<AlertData | null>(initialAlert);
  const [resolving, setResolving] = useState(false);
  // One resolve attempt per alert id. The effect below merges its result into
  // `resolvedAlert`, which is also its own dependency, so it always re-runs
  // afterwards — and `looksPartial` tests fields the server legitimately
  // returns as null (metadata and hostname both are, for e.g. unmanaged-host
  // alerts). Without this guard that pair turns into an unbounded
  // fetch → setState → fetch loop hammering GET /alerts/:id for as long as
  // the page is open.
  const resolveAttemptedIdRef = useRef<string | null>(null);

  // Keep local state in sync when navigation state changes.
  useEffect(() => {
    setResolvedAlert(initialAlert);
    // Navigation supplied a fresh (possibly partial) record, so allow the
    // resolver below to run again even for an id it already resolved once.
    // Without this, arriving back on an alert you are already viewing — e.g.
    // via the assignment toast's "View" action, which passes a partial state
    // lacking event_code — would replace the resolved record with the partial
    // one and then refuse to re-fetch, leaving the view permanently degraded.
    resolveAttemptedIdRef.current = null;
  }, [initialAlert]);

  useEffect(() => {
    const alert = resolvedAlert;
    if (!alert?.id) return;

    // Heuristic:
    // - Alerts list navigation already passes richer fields (metadata, unixtime, etc).
    // - Audit Trail often passes only a subset (sometimes includes hostname/host_identifier but misses unixtime/severity).
    // Fetch full record whenever key view fields are missing.
    const looksPartial =
      alert.unixtime == null ||
      alert.severity == null ||
      alert.event_code == null ||
      alert.metadata == null ||
      alert.host_identifier == null ||
      alert.hostname == null;

    if (!looksPartial) return;

    const idKey = String(alert.id);
    if (resolveAttemptedIdRef.current === idKey) return;
    resolveAttemptedIdRef.current = idKey;

    let cancelled = false;
    // Tracks whether the request actually settled, so the cleanup below can
    // tell "we already tried this id" apart from "our attempt was torn down
    // before it finished". React 19 StrictMode double-invokes effects in dev
    // (setup -> cleanup -> setup); without this the first setup claims the id,
    // the cleanup cancels its fetch, and the second setup is refused — leaving
    // the record unmerged and the "Loading..." chip stuck forever.
    let settled = false;
    setResolving(true);
    void alertsViewApi.getAlertFromById(alert.id).then((res) => {
      if (cancelled) return;
      const full = res?.data?.alert ?? res?.data ?? res;
      if (full && typeof full === 'object') {
        // Merge full record over the existing state (keep any extra fields already present).
        setResolvedAlert((prev) => ({ ...(prev ?? ({} as AlertData)), ...(full as Record<string, unknown>) } as AlertData));
      }
    }).finally(() => {
      settled = true;
      if (!cancelled) setResolving(false);
    });

    return () => {
      cancelled = true;
      // Release the claim only if the attempt never completed. Releasing it
      // unconditionally would reopen the unbounded refetch loop this guard
      // exists to close, because a successful merge re-runs this effect and
      // looksPartial is still true for legitimately-null server fields.
      if (!settled) resolveAttemptedIdRef.current = null;
    };
  }, [resolvedAlert]);

  // Re-fetch the full alert record on demand (e.g. after an Open/Close/Assign
  // action succeeds) so the Severity/Status card and Assignment panel reflect
  // the latest state instead of staying stale until a manual page reload.
  const reloadAlert = useCallback(() => {
    const id = resolvedAlert?.id;
    if (!id) return;
    setResolving(true);
    void alertsViewApi
      .getAlertFromById(id)
      .then((res) => {
        const full = res?.data?.alert ?? res?.data ?? res;
        if (full && typeof full === 'object') {
          setResolvedAlert((prev) => ({ ...(prev ?? ({} as AlertData)), ...(full as Record<string, unknown>) } as AlertData));
        }
      })
      .finally(() => {
        setResolving(false);
      });
  }, [resolvedAlert?.id]);

  const alert = resolvedAlert;

  if (!alert) {
    return <AlertsViewNoData />;
  }

  const displayCode = alert.event_code ?? alert.title ?? `Alert ${alert.id}`;
  const displayLink = alert.link && /^https?:\/\//i.test(alert.link) ? alert.link : undefined;

  return (
    <div className="min-h-screen bg-[#f8f9fb] bg-gradient-to-br from-blue-50 via-cyan-50 to-indigo-50">
      <div className="max-w-[100%] mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Header */}
        <div className="bg-white rounded-xl border border-blue-100 shadow-sm overflow-hidden mb-6">
          <div className="px-6 py-4 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 flex flex-wrap items-center justify-between gap-4">
            <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
              {displayLink ? (
                <a
                  href={displayLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:text-cyan-600 transition-colors"
                >
                  {displayCode}
                </a>
              ) : (
                displayCode
              )}
              {resolving && (
                <span className="ml-2 inline-flex items-center gap-2 text-sm font-medium text-slate-500">
                  <DuoSpinner size="xs" className="text-slate-300" />
                  Loading…
                </span>
              )}
            </h2>
            <Link
              to={fromAuditTrail ? '/audit-trail' : '/alerts'}
              className="inline-flex items-center gap-2 px-4 py-2 border border-blue-300 text-blue-700 rounded-lg font-medium hover:bg-blue-50"
            >
              <i className="fa fa-arrow-left" /> Back to {fromAuditTrail ? 'Audit Trail' : 'Alerts'}
            </Link>
          </div>
        </div>

        <AlertsViewSummary alert={alert} onActionComplete={reloadAlert} />

        <div className="bg-white rounded-xl border border-blue-100 shadow-sm overflow-hidden">
          <div className="min-h-[400px]">
            <AlertsViewMetadata alert={alert} />
          </div>
        </div>
      </div>
    </div>
  );
}
