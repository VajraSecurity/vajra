import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';

export type ToastType = 'success' | 'error' | 'info' | 'warning';

interface ToastProps {
  id?: string;
  message: string;
  type?: ToastType;
  action?: {
    label: string;
    onAction: () => void;
  };
  duration?: number;
  onClose: () => void;
}

// Both maps are pure constants and only one entry of each is ever read, so they
// stay at module scope rather than allocating four object literals and four
// <svg> trees per toast render.
// Crisp, light-mode accent colors
const ACCENTS = {
  success: { text: 'text-emerald-600', bg: 'bg-emerald-50', border: 'border-emerald-100', progress: 'from-emerald-100 to-emerald-400' },
  error: { text: 'text-rose-600', bg: 'bg-rose-50', border: 'border-rose-100', progress: 'from-rose-100 to-rose-400' },
  info: { text: 'text-blue-600', bg: 'bg-blue-50', border: 'border-blue-100', progress: 'from-blue-100 to-blue-400' },
  warning: { text: 'text-amber-600', bg: 'bg-amber-50', border: 'border-amber-100', progress: 'from-amber-100 to-amber-400' },
};

const ICONS = {
  success: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  error: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  info: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2">
      <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  warning: (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2">
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  ),
};

export const Toast: React.FC<ToastProps> = ({ 
  message, 
  type = 'success', 
  action,
  duration = 4000,
  onClose 
}) => {
  useEffect(() => {
    const timer = setTimeout(() => onClose(), duration);
    return () => clearTimeout(timer);
  }, [duration, onClose]);

  const style = ACCENTS[type];
  const cardTone =
    type === 'info'
      ? 'border-blue-200 bg-blue-50/95'
      : type === 'warning'
        ? 'border-amber-200 bg-amber-50/95'
        : 'border-gray-100 bg-white';

  return (
    <motion.div
      layout
      // The exact physics for a snappy, clean slide-in from the right
      initial={{ opacity: 0, x: 100 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 100 }}
      transition={{ type: "spring", stiffness: 400, damping: 25 }}
      role={action ? 'button' : 'status'}
      aria-live="polite"
      tabIndex={action ? 0 : undefined}
      onKeyDown={(e) => {
        if (!action) return;
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        action.onAction();
        onClose();
      }}
      onClick={() => {
        if (!action) return;
        action.onAction();
        onClose();
      }}
      className={`pointer-events-auto relative flex w-full items-start gap-3 overflow-hidden rounded-xl border p-4 shadow-[0_8px_30px_rgb(0,0,0,0.08)] sm:w-[380px] ${cardTone} ${action ? 'cursor-pointer' : ''}`}
    >
      {/* Light theme icon container */}
      <div className={`flex-shrink-0 rounded-full p-1 ${style.bg} ${style.text} ${style.border} border`}>
        {ICONS[type]}
      </div>

      <div className="flex flex-1 flex-col justify-center pt-1.5 min-w-0">
        <p className="font-semibold text-sm text-gray-800 leading-snug tracking-tight break-words">
          {message}
        </p>
      </div>

      {action && (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            action.onAction();
            onClose();
          }}
          className="flex-shrink-0 text-xs font-semibold rounded-lg border border-gray-200 bg-white text-blue-700 hover:bg-blue-50 hover:border-blue-200 transition pt-1.5 px-3 py-1"
        >
          {action.label}
        </button>
      )}

      <button
        type="button"
        aria-label="Dismiss notification"
        onClick={(e) => {
          e.stopPropagation();
          onClose();
        }}
        className="flex-shrink-0 rounded-lg text-gray-400 transition-colors hover:text-gray-700 pt-1.5"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="2">
          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>

      {/* Progress Bar now matches the accent color */}
      <motion.div
        initial={{ scaleX: 1 }}
        animate={{ scaleX: 0 }}
        transition={{ duration: duration / 1000, ease: "linear" }}
        className={`absolute bottom-0 left-0 right-0 h-[3px] origin-left bg-gradient-to-r ${style.progress}`}
      />
    </motion.div>
  );
};

// Toast Manager Component
interface ToastManagerProps {
  toasts: Array<{
    id: string;
    message: string;
    type?: ToastType;
    duration?: number;
    action?: { label: string; onAction: () => void };
  }>;
  onRemove: (id: string) => void;
}

export const ToastManager: React.FC<ToastManagerProps> = ({ toasts, onRemove }) => {
  return (
    <div className="fixed top-4 right-4 left-4 sm:left-auto sm:top-6 sm:right-6 z-[9999] flex flex-col gap-3 pointer-events-none items-end overflow-visible">
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            message={toast.message}
            type={toast.type}
            duration={toast.duration}
            action={toast.action}
            onClose={() => onRemove(toast.id)}
          />
        ))}
      </AnimatePresence>
    </div>
  );
};