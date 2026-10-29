import { createContext, useContext } from 'react';

export type AlertsPollingContextValue = {
  newAlertIds: Set<string>;
  newMyAlertIds: Set<string>;
  sidebarNewCount: number;
  clearSidebarNewCount: () => void;
  markAlertInteracted: (id: number | string) => void;
};

export const AlertsPollingContext = createContext<AlertsPollingContextValue | null>(null);

export function useAlertsPolling(): AlertsPollingContextValue {
  const ctx = useContext(AlertsPollingContext);
  if (ctx == null) {
    throw new Error('useAlertsPolling must be used within AlertsPollingProvider');
  }
  return ctx;
}
