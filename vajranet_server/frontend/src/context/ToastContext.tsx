import React, { useState, useCallback, useEffect, useMemo } from 'react';
import type { ReactNode } from 'react';
import { ToastManager } from '../components/Toast';
import type { ToastType } from '../components/Toast';
import { ToastContext } from './useToast';
import { APP_TOAST_EVENT_NAME } from '../api/axiosInstance';
import type { AppToastEventDetail } from '../api/axiosInstance';
// eslint-disable-next-line react-refresh/only-export-components
export { useToast } from './useToast';

interface Toast {
  id: string;
  message: string;
  type?: ToastType;
  /** Visible duration in ms (default 4000 in Toast component). */
  duration?: number;
  action?: {
    label: string;
    onAction: () => void;
  };
}

export const ToastProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const showToast = useCallback(
    (
      message: string,
      type: ToastType = 'success',
      options?: {
        actionLabel?: string;
        onAction?: () => void;
        duration?: number;
      },
    ) => {
    const id = `toast-${Date.now()}-${Math.random()}`;
      const action =
        options?.onAction != null
          ? {
              label: options.actionLabel ?? 'View',
              onAction: options.onAction,
            }
          : undefined;

      setToasts((prev) => [
        ...prev,
        { id, message, type, duration: options?.duration, action },
      ]);
    },
    [],
  );

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  // Non-component modules (e.g. axiosInstance.ts) can't call useToast()
  // directly, so they dispatch this DOM event instead — same pattern as the
  // 'auth-change' event used elsewhere for cross-module notifications.
  useEffect(() => {
    const handleAppToast = (event: Event) => {
      const detail = (event as CustomEvent<AppToastEventDetail>).detail;
      if (!detail?.message) return;
      showToast(detail.message, detail.type ?? 'info');
    };
    window.addEventListener(APP_TOAST_EVENT_NAME, handleAppToast);
    return () => window.removeEventListener(APP_TOAST_EVENT_NAME, handleAppToast);
  }, [showToast]);

  // showToast is already useCallback-stable, but the object literal wrapping it
  // is not, and this provider re-renders whenever `toasts` changes — on every
  // toast shown and again when it auto-dismisses. Context propagation bypasses
  // React.memo, so without this memo every useToast() consumer re-renders twice
  // per toast for an unchanged value. This is the outermost provider in the
  // app, so that is the whole tree, including any open unvirtualized table.
  const value = useMemo(() => ({ showToast }), [showToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastManager toasts={toasts} onRemove={removeToast} />
    </ToastContext.Provider>
  );
};
