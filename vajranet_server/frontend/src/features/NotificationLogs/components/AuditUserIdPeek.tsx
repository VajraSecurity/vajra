/**
 * AuditUserIdPeek — clickable "user #id" chip that lazily loads name/email
 * from GET /users/by-id on click. Extracted verbatim, no logic changes.
 */

import { useRef, useState, useEffect, useLayoutEffect } from 'react';
import { createPortal } from 'react-dom';
import api from '../../../api/axiosInstance';
import type { UserByIdResponse } from '../types';

/** Clickable `user #id` that loads name/email from GET /users/by-id */
export function AuditUserIdPeek({ userId }: { userId: string }) {
  const anchorRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ top: 0, left: 0 });
  const [loading, setLoading] = useState(false);
  const [user, setUser] = useState<{ name: string | null; email: string | null } | null>(null);
  const [loadError, setLoadError] = useState(false);

  useLayoutEffect(() => {
    if (!open || !anchorRef.current) return;
    const updatePos = () => {
      if (!anchorRef.current) return;
      const r = anchorRef.current.getBoundingClientRect();
      setPos({ top: r.bottom + 6, left: r.left });
    };
    updatePos();
    // capture:true so ancestor scroll containers (e.g. the drawer body) are
    // caught even though `scroll` doesn't bubble to window.
    window.addEventListener('scroll', updatePos, true);
    window.addEventListener('resize', updatePos);
    return () => {
      window.removeEventListener('scroll', updatePos, true);
      window.removeEventListener('resize', updatePos);
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      const t = e.target as Node;
      if (anchorRef.current?.contains(t) || popoverRef.current?.contains(t)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const toggle = () => {
    setOpen((o) => !o);
  };

  useEffect(() => {
    if (!open) {
      setUser(null);
      setLoadError(false);
      setLoading(false);
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const idNum = parseInt(userId, 10);
    if (!Number.isFinite(idNum) || idNum <= 0) {
      setLoadError(true);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setLoadError(false);
    void api
      .get<UserByIdResponse>('/users/by-id', { params: { id: userId } })
      .then((res) => {
        if (cancelled) return;
        const u = res.data?.data?.user;
        if (u) setUser({ name: u.name, email: u.email });
        else setLoadError(true);
      })
      .catch(() => {
        if (!cancelled) setLoadError(true);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, userId]);

  return (
    <>
      <button
        type="button"
        ref={anchorRef}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          toggle();
        }}
        className="rounded-lg font-medium text-blue-600 underline decoration-blue-600/40 underline-offset-2 hover:text-blue-800"
      >
        user #{userId}
      </button>
      {open &&
        createPortal(
          <div
            ref={popoverRef}
            className="fixed z-[120] w-[min(280px,calc(100vw-24px))] rounded-xl border border-slate-200 bg-white p-3 text-left shadow-[0_16px_40px_rgba(15,23,42,0.14)]"
            style={{ top: pos.top, left: pos.left }}
            role="dialog"
            aria-label="User details"
          >
            {loading && <p className="text-sm text-slate-500">Loading…</p>}
            {!loading && user && (
              <div className="space-y-1">
                <p className="text-sm font-semibold text-slate-900">{user.name?.trim() || '—'}</p>
                <p className="break-all text-xs text-slate-600">{user.email?.trim() || '—'}</p>
              </div>
            )}
            {!loading && loadError && !user && (
              <p className="text-sm text-slate-500">Could not load this user.</p>
            )}
          </div>,
          document.body,
        )}
    </>
  );
}

