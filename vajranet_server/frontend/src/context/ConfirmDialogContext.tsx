import React, { useCallback, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { ConfirmDialogContext } from './useConfirm';
import type { ConfirmOptions } from './useConfirm';

interface ConfirmState extends ConfirmOptions {
  isOpen: boolean;
}

const initialState: ConfirmState = { isOpen: false, title: '' };

export const ConfirmDialogProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [state, setState] = useState<ConfirmState>(initialState);
  const resolverRef = useRef<((value: boolean) => void) | null>(null);

  const confirm = useCallback((options: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => {
      resolverRef.current = resolve;
      setState({ ...options, isOpen: true });
    });
  }, []);

  const handleResolve = useCallback((result: boolean) => {
    resolverRef.current?.(result);
    resolverRef.current = null;
    setState((prev) => ({ ...prev, isOpen: false }));
  }, []);

  // `confirm` is useCallback-stable, but the wrapper object is not, so without
  // this memo every dialog open and close re-renders every consumer of the
  // context for a value that has not changed.
  const value = useMemo(() => ({ confirm }), [confirm]);

  return (
    <ConfirmDialogContext.Provider value={value}>
      {children}
      <ConfirmDialog
        isOpen={state.isOpen}
        title={state.title}
        description={state.description}
        confirmLabel={state.confirmLabel}
        cancelLabel={state.cancelLabel}
        variant={state.variant}
        onConfirm={() => handleResolve(true)}
        onCancel={() => handleResolve(false)}
      />
    </ConfirmDialogContext.Provider>
  );
};
