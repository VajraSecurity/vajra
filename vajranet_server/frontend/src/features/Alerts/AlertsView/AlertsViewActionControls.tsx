/**
 * AlertsView: Action controls — Open/Close alert.
 * API: alertsViewApi.getStatus, alertsViewApi.updateAlert
 */

import { useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import type { AlertData } from './types';
import { alertsViewApi } from './alertsViewApi';
import { sanitizeAsciiMultiLine } from '../../../services/inputSanitizers';
import { ALERTS_URLS, USERS_URLS } from '../../../api/urls';
import { csrfHeadersJson, fetchWithCsrf } from '../../../api/csrfClient';

type UserOption = { id: number; name: string; email: string };

interface AlertsViewActionControlsProps {
  alert: AlertData;
  onActionComplete?: () => void;
}

const AlertsViewActionControls = ({ alert, onActionComplete }: AlertsViewActionControlsProps) => {
  const [loading, setLoading] = useState<'open' | 'close' | null>(null);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [isOpen, setIsOpen] = useState<boolean | null>(typeof alert.is_open === 'boolean' ? alert.is_open : null);
  const [reasonModal, setReasonModal] = useState<boolean | null>(null); // true = open, false = close
  const [reason, setReason] = useState('');
  const [reasonError, setReasonError] = useState<string | null>(null);
  const [reasonSubmitting, setReasonSubmitting] = useState(false);

  // Assign modal
  const [assignModalOpen, setAssignModalOpen] = useState(false);
  const [assignUsers, setAssignUsers] = useState<UserOption[]>([]);
  const [assignUsersLoading, setAssignUsersLoading] = useState(false);
  const [assignUsersError, setAssignUsersError] = useState<string | null>(null);
  const [selectedAssigneeId, setSelectedAssigneeId] = useState<number | null>(null);
  const [assignSubmitting, setAssignSubmitting] = useState(false);
  const [assignModalError, setAssignModalError] = useState<string | null>(null);
  const [assignSearch, setAssignSearch] = useState('');
  const [assignReason, setAssignReason] = useState('');
  const [assignReasonError, setAssignReasonError] = useState<string | null>(null);

  const eventId = typeof alert.id === 'number' ? alert.id : parseInt(String(alert.id), 10);
  const ALERTS_ASSIGN_URL = ALERTS_URLS.ALERTS_LIST.replace('/alerts/list', '/alerts/assign');

  const assigneeIdRaw = (alert as unknown as Record<string, unknown>).assignee_id;
  const assigneeIdNum =
    typeof assigneeIdRaw === 'number' ? assigneeIdRaw : typeof assigneeIdRaw === 'string' ? Number(assigneeIdRaw) : NaN;
  const initialHasAssignee = Number.isFinite(assigneeIdNum) && assigneeIdNum > 0;
  const [hasAssignee, setHasAssignee] = useState<boolean>(initialHasAssignee);
  const alreadyAssignedId = Number.isFinite(assigneeIdNum) && assigneeIdNum > 0 ? assigneeIdNum : null;

  const fetchStatus = async () => {
    try {
      const res = await alertsViewApi.getStatus([eventId]);
      const row = Array.isArray(res.data?.data) ? res.data.data[0] : null;
      if (row && typeof row.is_open === 'boolean') setIsOpen(row.is_open);
    } catch {
      // keep best-effort; fall back to current state
    }
  };

  useEffect(() => {
    fetchStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eventId]);

  // Audit-trail navigation state may not include `assignee_id`.
  // Always best-effort fetch assignment so the Assign/Reassign button stays consistent.
  useEffect(() => {
    if (!Number.isFinite(eventId) || eventId <= 0) return;
    let cancelled = false;
    void alertsViewApi
      .getAssignee(eventId)
      .then((res: unknown) => {
        if (cancelled) return;
        const data = (res as { data?: { data?: { assignee?: unknown } } } | undefined)?.data?.data;
        const nextHasAssignee = data?.assignee != null;
        setHasAssignee(Boolean(nextHasAssignee));
      })
      .catch(() => {
        // Keep current state best-effort.
      });
    return () => {
      cancelled = true;
    };
  }, [eventId]);

  const openReasonModal = (nextOpen: boolean) => {
    setReasonModal(nextOpen);
    setReason('');
    setReasonError(null);
  };

  const closeReasonModal = () => {
    setReasonModal(null);
    setReason('');
    setReasonError(null);
  };

  const closeAssignModal = () => {
    setAssignModalOpen(false);
    setSelectedAssigneeId(null);
    setAssignModalError(null);
    setAssignSearch('');
    setAssignReason('');
    setAssignReasonError(null);
  };

  const fetchAssignUsers = async () => {
    if (assignUsersLoading) return;
    if (assignUsers.length > 0) return;

    setAssignUsersLoading(true);
    setAssignUsersError(null);
    try {
      const res = await fetch(USERS_URLS.LIST, { credentials: 'include' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const users: UserOption[] = Array.isArray(data?.data?.users)
        ? data.data.users
        : Array.isArray(data?.users)
          ? data.users
          : [];
      setAssignUsers(users);
    } catch {
      setAssignUsersError('Failed to load users. Please try again.');
    } finally {
      setAssignUsersLoading(false);
    }
  };

  const openAssignModal = () => {
    setAssignModalOpen(true);
    setSelectedAssigneeId(null);
    setAssignModalError(null);
    setAssignSearch('');
    setAssignReason('');
    setAssignReasonError(null);
    void fetchAssignUsers();
  };

  const filteredAssignUsers = useMemo(() => {
    const q = assignSearch.trim().toLowerCase();
    if (!q) return assignUsers;
    return assignUsers.filter((u) => `${u.name} ${u.email}`.toLowerCase().includes(q));
  }, [assignUsers, assignSearch]);

  const handleAssignSubmit = async () => {
    if (selectedAssigneeId == null) {
      setAssignModalError('Please select a user to assign this alert.');
      return;
    }
    const trimmedReason = assignReason.trim();
    if (!trimmedReason) {
      setAssignReasonError('Reason is required.');
      return;
    }

    setAssignSubmitting(true);
    setAssignModalError(null);
    setAssignReasonError(null);
    setMessage(null);
    try {
      await fetchWithCsrf(ALERTS_ASSIGN_URL, {
        method: 'POST',
        credentials: 'include',
        headers: csrfHeadersJson(),
        body: JSON.stringify({
          event_id: [eventId],
          assignee_id: selectedAssigneeId,
          reason: trimmedReason,
        }),
      });

      setMessage({ type: 'success', text: 'Alert assigned successfully.' });
      closeAssignModal();
      onActionComplete?.();
    } catch {
      setAssignModalError('Failed to assign alert. Please try again.');
      setMessage({ type: 'error', text: 'Failed to assign alert.' });
    } finally {
      setAssignSubmitting(false);
    }
  };

  const handleSetOpen = async (nextOpen: boolean) => {
    const trimmedReason = reason.trim();
    if (!trimmedReason) {
      setReasonError('Reason is required.');
      return;
    }
    const action = nextOpen ? 'open' : 'close';
    setReasonSubmitting(true);
    setLoading(action);
    setMessage(null);
    try {
      await alertsViewApi.updateAlert({
        event_id: [eventId],
        is_open: nextOpen,
        reason: trimmedReason,
      });
      setIsOpen(nextOpen);
      setMessage({ type: 'success', text: nextOpen ? 'Alert opened.' : 'Alert closed.' });
      closeReasonModal();
      onActionComplete?.();
    } catch {
      setMessage({ type: 'error', text: `Failed to ${action} alert. Please try again.` });
    } finally {
      setLoading(null);
      setReasonSubmitting(false);
    }
  };

  return (
    <div className="bg-white rounded-xl border border-blue-100 shadow-sm p-4 min-w-[200px]">
      <p className="text-sm text-gray-500 mb-3">Actions</p>
      <div className="flex flex-col gap-2">
        <button
          type="button"
          onClick={() => openReasonModal(true)}
          disabled={!!loading || isOpen === true}
          className="w-full px-4 py-2 bg-emerald-100 text-emerald-800 rounded-lg font-medium hover:bg-emerald-200 disabled:opacity-50 text-sm"
        >
          {loading === 'open' ? 'Opening...' : 'Open Alert'}
        </button>
        <button
          type="button"
          onClick={() => openReasonModal(false)}
          disabled={!!loading || isOpen === false}
          className="w-full px-4 py-2 bg-slate-100 text-slate-700 rounded-lg font-medium hover:bg-slate-200 disabled:opacity-50 text-sm"
        >
          {loading === 'close' ? 'Closing...' : 'Close Alert'}
        </button>

        <button
          type="button"
          onClick={openAssignModal}
          disabled={!!loading || assignSubmitting}
          className="w-full px-4 py-2 bg-indigo-50 text-indigo-800 rounded-lg font-medium hover:bg-indigo-100 disabled:opacity-50 text-sm"
        >
          {assignSubmitting ? 'Assigning…' : hasAssignee ? 'Reassign Alert' : 'Assign Alert'}
        </button>
      </div>
      {message && (
        <p
          role="status"
          aria-live="polite"
          className={`mt-2 text-xs ${message.type === 'success' ? 'text-green-600' : 'text-red-600'}`}
        >
          {message.text}
        </p>
      )}

      {/* Reason modal for open/close */}
      {reasonModal !== null &&
        typeof document !== 'undefined' &&
        createPortal(
          <div
            className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50"
            role="dialog"
            aria-modal="true"
            onClick={closeReasonModal}
          >
            <div
              className="bg-white rounded-xl shadow-xl border border-gray-200 p-5 w-full max-w-md mx-4"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold text-gray-900 mb-2">
                {reasonModal ? 'Open alert' : 'Close alert'}
              </h3>
              <p className="text-sm text-gray-600 mb-3">
                Add a reason for {reasonModal ? 'opening' : 'closing'} this alert.
              </p>
              <textarea
                value={reason}
                onChange={(e) => {
                  setReason(sanitizeAsciiMultiLine(e.target.value, 300, false));
                  if (reasonError) setReasonError(null);
                }}
                placeholder={reasonModal ? 'e.g. Reopening for follow-up' : 'e.g. False positive, Resolved after patch'}
                className={`w-full min-h-[80px] px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-y ${
                  reasonError ? 'border-red-300' : 'border-gray-300'
                }`}
                autoFocus
              />
              {reasonError && <p className="mt-2 text-xs text-red-600">{reasonError}</p>}
              <div className="flex justify-end gap-2 mt-4">
                <button
                  type="button"
                  onClick={closeReasonModal}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => handleSetOpen(reasonModal)}
                  disabled={reasonSubmitting || !reason.trim()}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  {reasonSubmitting ? (reasonModal ? 'Opening…' : 'Closing…') : reasonModal ? 'Open' : 'Close'}
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}

      {/* Assign modal */}
      {assignModalOpen &&
        typeof document !== 'undefined' &&
        createPortal(
          <div
            className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50"
            role="dialog"
            aria-modal="true"
            onClick={closeAssignModal}
          >
            <div
              className="bg-white rounded-2xl shadow-xl border border-gray-200 p-5 w-full max-w-md mx-4"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-start justify-between gap-4 mb-3">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">Assign alert</h3>
                  <p className="text-sm text-gray-600 mt-1">
                    Choose who should close this alert.
                  </p>
                </div>
                <div className="shrink-0 w-10 h-10 rounded-2xl bg-blue-50 border border-blue-100 flex items-center justify-center">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path
                      d="M12 2C7.58 2 4 5.58 4 10c0 4.42 3.58 8 8 8s8-3.58 8-8c0-4.42-3.58-8-8-8Z"
                      stroke="#1D4ED8"
                      strokeWidth="1.8"
                    />
                    <path
                      d="M12 7v5l3 2"
                      stroke="#1D4ED8"
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>
              </div>

              {assignUsersError && (
                <div className="mb-3 px-3 py-2 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">
                  {assignUsersError}
                </div>
              )}

              {assignModalError && (
                <div className="mb-3 px-3 py-2 bg-red-50 border border-red-200 text-red-700 rounded-lg text-sm">
                  {assignModalError}
                </div>
              )}

              <div className="mb-4">
                <div className="flex items-center justify-between mb-2 gap-2">
                  <label className="block text-xs font-semibold text-gray-600 uppercase">Assignee</label>
                  {selectedAssigneeId != null && (
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedAssigneeId(null);
                        setAssignModalError(null);
                      }}
                      className="rounded-lg text-xs font-medium text-gray-600 hover:text-gray-900 hover:underline underline-offset-4"
                    >
                      Clear
                    </button>
                  )}
                </div>

                <input
                  type="text"
                  value={assignSearch}
                  onChange={(e) => {
                    setAssignSearch(e.target.value);
                    setAssignModalError(null);
                  }}
                  placeholder="Search by name or email"
                  autoFocus
                  disabled={assignUsersLoading || assignSubmitting}
                  className="w-full px-3 py-2.5 border border-gray-300 rounded-xl text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none disabled:opacity-50"
                />

                <div className="mt-3 rounded-2xl border border-gray-200 bg-gray-50 p-2">
                  {assignUsersLoading ? (
                    <div className="space-y-2 px-1">
                      {Array.from({ length: 5 }).map((_, i) => (
                        <div key={i} className="h-11 rounded-xl bg-gray-200/70 animate-pulse" />
                      ))}
                    </div>
                  ) : filteredAssignUsers.length === 0 ? (
                    <div className="py-10 px-2 text-center">
                      <p className="text-sm font-medium text-gray-900">No matching users</p>
                      <p className="text-xs text-gray-500 mt-1">Try a different name or email.</p>
                    </div>
                  ) : (
                    <div role="listbox" aria-label="Assignee options" className="max-h-52 overflow-y-auto pr-1">
                      {filteredAssignUsers.map((u) => {
                        const isActive = selectedAssigneeId === u.id;
                        const isAlreadyAssigned = alreadyAssignedId != null && u.id === alreadyAssignedId;
                        return (
                          <button
                            key={u.id}
                            type="button"
                            role="option"
                            aria-selected={isActive}
                            disabled={isAlreadyAssigned || assignSubmitting}
                            onClick={() => {
                              if (isAlreadyAssigned) return;
                              setSelectedAssigneeId(u.id);
                              setAssignModalError(null);
                            }}
                            className={[
                              'w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-xl border transition',
                              isActive
                                ? 'bg-blue-600 text-white border-blue-600'
                                : 'bg-white text-gray-900 border-transparent hover:border-blue-200 hover:bg-blue-50',
                              isAlreadyAssigned && !isActive
                                ? 'opacity-60 cursor-not-allowed bg-gray-100 text-gray-500 hover:bg-gray-100 hover:border-transparent'
                                : '',
                            ].join(' ')}
                          >
                            <div className="text-left min-w-0">
                              <p className="text-sm font-semibold truncate">{u.name}</p>
                              <p className={isActive ? 'text-xs text-blue-100' : 'text-xs text-gray-500 truncate'}>
                                {u.email}
                              </p>
                              {isAlreadyAssigned && !isActive && (
                                <p className={isActive ? 'text-xs text-blue-100' : 'text-xs text-gray-500 mt-0.5'}>
                                  Already assigned
                                </p>
                              )}
                            </div>
                            <div className="shrink-0">
                              {isActive ? (
                                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                                  <path
                                    d="M20 6 9 17l-5-5"
                                    stroke="currentColor"
                                    strokeWidth="2.2"
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                  />
                                </svg>
                              ) : (
                                <span className={isAlreadyAssigned ? 'text-gray-400' : 'text-gray-300'}>
                                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                                    <path
                                      d="M7 12h10"
                                      stroke="currentColor"
                                      strokeWidth="2.2"
                                      strokeLinecap="round"
                                    />
                                  </svg>
                                </span>
                              )}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              <div className="mb-4">
                <label className="block text-xs font-semibold text-gray-600 uppercase mb-2">Reason</label>
                <textarea
                  value={assignReason}
                  onChange={(e) => {
                    setAssignReason(sanitizeAsciiMultiLine(e.target.value, 300, false));
                    if (assignReasonError) setAssignReasonError(null);
                  }}
                  placeholder="Why are you assigning/reassigning this alert?"
                  disabled={assignSubmitting}
                  className={`w-full min-h-[80px] px-3 py-2 border rounded-xl text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 resize-y ${
                    assignReasonError ? 'border-red-300' : 'border-gray-300'
                  }`}
                />
                {assignReasonError && <p className="mt-2 text-xs text-red-600">{assignReasonError}</p>}
              </div>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={closeAssignModal}
                  className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-xl hover:bg-gray-200"
                  disabled={assignSubmitting}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleAssignSubmit}
                  disabled={assignSubmitting || assignUsersLoading || selectedAssigneeId == null || !assignReason.trim()}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-xl hover:bg-blue-700 disabled:opacity-50"
                >
                  {assignSubmitting ? 'Assigning…' : 'Assign'}
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}
    </div>
  );
};

export default AlertsViewActionControls;
