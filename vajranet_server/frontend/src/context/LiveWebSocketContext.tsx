/**
 * LiveWebSocketContext
 *
 * Provides real-time node status and alert data to the entire app tree.
 * The WebSocket connection is established only when the user is
 * authenticated (cookie-based `/auth/status`).
 */

import React, { useMemo, useCallback } from 'react';
import type { ReactNode } from 'react';
import { useLiveWebSocket, ALERTS_PUSH_EVENT } from '../hooks/useLiveWebSocket';
import type { AlertsPushDetail } from '../hooks/useLiveWebSocket';
import { useAuthStatus } from './useAuthStatus';
import { LiveWebSocketContext } from './useLiveData';
import type { LiveWebSocketContextType } from './useLiveData';
// eslint-disable-next-line react-refresh/only-export-components
export { useLiveData } from './useLiveData';

export const LiveWebSocketProvider: React.FC<{ children: ReactNode }> = ({
  children,
}) => {
  const { isValid: isAuthenticated, forcePasswordChange } = useAuthStatus();

  // Called by useLiveWebSocket when the server rejects the WS upgrade with 401.
  const handleAuthFailed = useCallback(() => {
    // Ask session checker to re-evaluate auth; do not rely on localStorage flags.
    window.dispatchEvent(new Event('auth-change'));
  }, []);

  // Real-time new-alert signal from /ws/live, re-broadcast as a window event.
  //
  // Deliberately not surfaced through this context's value: doing so would
  // change the useMemo identity on every alert and re-render every
  // useLiveData() consumer in the app, which the reuseUnchanged() work in
  // useLiveWebSocket exists specifically to avoid. Only AlertsPollingContext
  // cares, and it already listens for window events ('auth-change') from here.
  const handleAlertsPush = useCallback((detail: AlertsPushDetail) => {
    window.dispatchEvent(new CustomEvent<AlertsPushDetail>(ALERTS_PUSH_EVENT, { detail }));
  }, []);

  const { connected, data, clamavAlertsByHost, firewallStatusPushByHost, osupdatePushByHost, windowsPatchPushByHost, disconnect, reconnect } = useLiveWebSocket(
    isAuthenticated && !forcePasswordChange,
    handleAuthFailed,
    handleAlertsPush,
  );

  const value = useMemo<LiveWebSocketContextType>(
    () => ({
      connected,
      liveData: data,
      nodeStatus: data?.nodeStatus ?? null,
      alertStatus: data?.alertStatus ?? null,
      clamavAlertsByHost,
      firewallStatusPushByHost,
      osupdatePushByHost,
      windowsPatchPushByHost,
      disconnect,
      reconnect,
    }),
    [connected, data, clamavAlertsByHost, firewallStatusPushByHost, osupdatePushByHost, windowsPatchPushByHost, disconnect, reconnect]
  );

  return (
    <LiveWebSocketContext.Provider value={value}>
      {children}
    </LiveWebSocketContext.Provider>
  );
};
