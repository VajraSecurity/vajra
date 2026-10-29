import { createContext, useContext } from 'react';
import type {
  LiveData,
  NodeStatus,
  AlertStatus,
  UseLiveWebSocketReturn,
  ClamavAlertEntry,
  FirewallStatusPushEntry,
  OsupdatePushEntry,
  WindowsPatchPushEntry,
} from '../hooks/useLiveWebSocket';

export interface LiveWebSocketContextType {
  /** Whether the live WebSocket is connected */
  connected: boolean;
  /** Full payload (null until first message arrives) */
  liveData: LiveData | null;
  /** Shorthand for liveData.nodeStatus */
  nodeStatus: NodeStatus | null;
  /** Shorthand for liveData.alertStatus */
  alertStatus: AlertStatus | null;
  /**
   * Live ClamAV alert accumulator keyed by host_identifier.
   * Populated in real-time from clamav_push messages forwarded through
   * the live-dashboard WebSocket channel. Empty Map until the first
   * clamav_push message arrives for a given host.
   */
  clamavAlertsByHost: Map<string, ClamavAlertEntry>;
  /**
   * Firewall status push signal keyed by host_identifier.
   * Reference changes when a firewall_status_push arrives — consumers
   * use this as a debounced refetch trigger (same pattern as clamavAlertsByHost).
   */
  firewallStatusPushByHost: Map<string, FirewallStatusPushEntry>;
  /**
   * Patch Management (osupdate_result) push signal keyed by host_identifier.
   */
  osupdatePushByHost: Map<string, OsupdatePushEntry>;
  /**
   * Windows maintained-app install/uninstall job completion (patch_job_push)
   * push signal keyed by host_identifier — unrelated to osupdatePushByHost
   * above (that's the pre-existing Linux osupdate feature).
   */
  windowsPatchPushByHost: Map<string, WindowsPatchPushEntry>;
  /** Imperatively disconnect */
  disconnect: UseLiveWebSocketReturn['disconnect'];
  /** Imperatively reconnect */
  reconnect: UseLiveWebSocketReturn['reconnect'];
}

export const LiveWebSocketContext = createContext<LiveWebSocketContextType | undefined>(
  undefined
);

/**
 * Access live node-status & alert data anywhere inside
 * `<LiveWebSocketProvider>`.
 *
 * ```tsx
 * const { nodeStatus, alertStatus, connected } = useLiveData();
 * ```
 */
export const useLiveData = (): LiveWebSocketContextType => {
  const ctx = useContext(LiveWebSocketContext);
  if (!ctx) {
    throw new Error('useLiveData must be used within <LiveWebSocketProvider>');
  }
  return ctx;
};
