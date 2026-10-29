/**
 * NodesViewWifiControl
 *
 * Displays WiFi telemetry for a node.
 *
 * Linux (full implementation):
 *   On-demand status:  { type:'agent', params:{ agent:'wifi', action:'status' } }
 *   Real-time push:    rid === 'wifi_push' from lastMessage
 *   Response schema (WifiEvent):
 *     { event_type, connected: ConnectedWifi|null, saved_profiles: SavedProfile[], timestamp }
 *
 * Windows:
 *   Full WiFi implementation: on-demand status via PowerShell (command keys 66/67)
 *   and real-time push via rid === 'wifi_push' from lastMessage.
 *   Profile schema differs from Linux — no uuid field; profiles are keyed by name.
 *
 * Security risk colour tiers:
 *   none     → green   (#22c55e)
 *   low      → blue    (#3b82f6)
 *   medium   → amber   (#f59e0b)
 *   high     → orange  (#ef4444)
 *   critical → red     (#dc2626)
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { DuoSpinner } from '@/components/ui/loading';
import type { NodeData } from './types';
import { NODES_URLS } from '../../../api/urls';

// Protocol types — must match the wifi agent's payload shape.

interface ConnectedWifi {
  ssid:       string;
  bssid:      string;
  interface:  string;
  signal:     string;
  frequency:  string;
  channel:    string;
  bitrate:    string;
  security:   string;
  ip_address: string;
}

interface SavedProfile {
  uuid:            string;
  name:            string;
  ssid:            string;
  security:        string;
  // 'unknown' is returned by the agent for unrecognised key-mgmt types (classifySecurity default case)
  security_risk:   'none' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  security_detail: string;
  auto_connect:    boolean;
  last_used:       string;
}

interface WifiEvent {
  event_type:     'initial' | 'change' | 'query';
  connected:      ConnectedWifi | null;
  saved_profiles: SavedProfile[];
  timestamp:      string;
}

/** Shape of the shared WS envelope pushed to lastMessage (see useNodeWebSocket). */
interface WsPushMessage {
  rid?: string;
  host_identifier?: string;
  response?: unknown;
}

interface NodesViewWifiControlProps {
  node:          NodeData;
  wsConnected:   boolean;
  wsSendMessage: (message: unknown) => Promise<{ status?: string; message?: string; response?: unknown }>;
  lastMessage:   WsPushMessage | null;
}

// Risk badge styling

const RISK_STYLES: Record<SavedProfile['security_risk'], string> = {
  none:     'bg-green-100  text-green-700  border-green-200',
  low:      'bg-blue-100   text-blue-700   border-blue-200',
  medium:   'bg-amber-100  text-amber-700  border-amber-200',
  high:     'bg-orange-100 text-orange-700 border-orange-200',
  critical: 'bg-red-100    text-red-700    border-red-200',
  unknown:  'bg-gray-100   text-gray-600   border-gray-200',
};

const RISK_ORDER: Record<SavedProfile['security_risk'], number> = {
  critical: 0, high: 1, medium: 2, low: 3, none: 4, unknown: 5,
};

// Sort profiles: worst risk first, then by SSID
function sortProfiles(profiles: SavedProfile[]): SavedProfile[] {
  return [...profiles].sort((a, b) => {
    const rd = RISK_ORDER[a.security_risk] - RISK_ORDER[b.security_risk];
    return rd !== 0 ? rd : a.ssid.localeCompare(b.ssid);
  });
}

// Relative time helper
function relativeTime(iso: string): string {
  if (!iso || iso === 'never') return 'Never';
  const diff = Date.now() - new Date(iso).getTime();
  if (isNaN(diff)) return iso;
  const s = Math.floor(diff / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

// Signal bar visual
function SignalBar({ value }: { value: string }) {
  const pct = parseInt(value, 10);
  if (isNaN(pct)) return <span className="text-gray-400 text-xs">—</span>;
  const color = pct >= 70 ? 'bg-green-500' : pct >= 40 ? 'bg-amber-500' : 'bg-red-500';
  const bars = [25, 50, 75, 100].map((threshold) => ({
    filled: pct >= threshold,
  }));
  return (
    <span className="inline-flex items-end gap-0.5" title={`${pct}%`}>
      {bars.map((bar, i) => (
        <span
          key={i}
          style={{ height: `${8 + i * 3}px`, width: '4px' }}
          className={`rounded-sm inline-block ${bar.filled ? color : 'bg-gray-200'}`}
        />
      ))}
      <span className="ml-1 text-xs text-gray-600">{pct}%</span>
    </span>
  );
}

// Main component

// Connection status badge
// Must stay at module scope: as an inline component it gets a new function identity
// every render, so React tears the badge down and rebuilds it instead of updating it —
// and this panel re-renders on every wifi_push WebSocket message.
const ConnectionBadge = ({ loadingStatus, wifiData }: { loadingStatus: boolean; wifiData: WifiEvent | null }) => {
  if (loadingStatus) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-500">
        <DuoSpinner size="xs" /> Fetching…
      </span>
    );
  }
  if (!wifiData) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-400">
        — Unknown
      </span>
    );
  }
  if (wifiData.connected) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700">
        ● Network: Connected
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-500">
      ● Network: Disconnected
    </span>
  );
};

// Worst-risk banner across saved profiles
// Hoisted for the same reason as ConnectionBadge above.
const RiskBanner = ({ savedProfiles }: { savedProfiles: SavedProfile[] }) => {
  if (!savedProfiles.length) return null;
  const criticalCount = savedProfiles.filter(p => p.security_risk === 'critical').length;
  const highCount     = savedProfiles.filter(p => p.security_risk === 'high').length;
  if (criticalCount > 0) {
    return (
      <div className="px-4 py-2 bg-red-50 border-b border-red-100 flex items-center gap-2 text-xs text-red-700">
        <i className="fa fa-triangle-exclamation" />
        <span>
          <span className="font-semibold">{criticalCount}</span> saved network{criticalCount > 1 ? 's have' : ' has'} no
          encryption — all traffic is exposed on that network.
        </span>
      </div>
    );
  }
  if (highCount > 0) {
    return (
      <div className="px-4 py-2 bg-orange-50 border-b border-orange-100 flex items-center gap-2 text-xs text-orange-700">
        <i className="fa fa-triangle-exclamation" />
        <span>
          <span className="font-semibold">{highCount}</span> saved network{highCount > 1 ? 's use' : ' uses'} WEP which is
          cryptographically broken.
        </span>
      </div>
    );
  }
  return (
    <div className="px-4 py-2 bg-green-50 border-b border-green-100 flex items-center gap-2 text-xs text-green-700">
      <i className="fa fa-shield-halved" />
      <span>All saved networks use acceptable security.</span>
    </div>
  );
};

const NodesViewWifiControl = ({
  node,
  wsConnected,
  wsSendMessage,
  lastMessage,
}: NodesViewWifiControlProps) => {
  const hostId  = node.host_identifier || String(node.id);
  const [wifiData,      setWifiData]      = useState<WifiEvent | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(false);
  const [lastEventType, setLastEventType] = useState<string | null>(null);

  // Saved profiles are fetched from the DB via HTTP so they are always
  // visible even when the agent is offline. They are also updated in real
  // time when a wifi_push arrives.
  const [savedProfiles, setSavedProfiles] = useState<SavedProfile[]>([]);
  const [loadingSaved,  setLoadingSaved]  = useState(false);

  // Fetch saved profiles from DB (HTTP, works regardless of WS state)
  const fetchSavedProfiles = useCallback(async () => {
    setLoadingSaved(true);
    try {
      const resp = await fetch(
        `${NODES_URLS.WIFI_LATEST}${encodeURIComponent(hostId)}`,
        { credentials: 'include' },
      );
      if (!resp.ok) return;
      const json = await resp.json();
      if (json?.success && json.data) {
        const raw = json.data.saved_profiles;
        const profiles: SavedProfile[] = Array.isArray(raw)
          ? raw
          : (typeof raw === 'string' ? JSON.parse(raw) : []);
        setSavedProfiles(profiles);
      }
    } catch {
      // best-effort — do not surface error
    } finally {
      setLoadingSaved(false);
    }
  }, [hostId]);

  // Sorted here rather than inline in the JSX: otherwise every wifi_push message
  // re-sorts the whole saved-profile list even when the profiles have not changed.
  const sortedProfiles = useMemo(() => sortProfiles(savedProfiles), [savedProfiles]);

  // Fetch WiFi status on demand
  const fetchWifiStatus = useCallback(async () => {
    if (!wsConnected) return;
    setLoadingStatus(true);
    try {
      const response = await wsSendMessage({
        type: 'agent',
        params: { agent: 'wifi', action: 'status' },
        host_identifier: hostId,
      });
      const raw = typeof response.response === 'string'
        ? JSON.parse(response.response)
        : response.response;
      if (raw && typeof raw === 'object' && 'saved_profiles' in raw) {
        setWifiData(raw as WifiEvent);
        setLastEventType(raw.event_type ?? 'query');
      }
    } catch {
      // best-effort; do not surface error
    } finally {
      setLoadingStatus(false);
    }
  }, [wsConnected, wsSendMessage, hostId]);

  // Fetch saved profiles from DB on mount — unconditional (no WS needed)
  const hasFetchedSavedRef = useRef(false);
  useEffect(() => {
    if (!hasFetchedSavedRef.current) {
      hasFetchedSavedRef.current = true;
      fetchSavedProfiles();
    }
  }, [fetchSavedProfiles]);

  // Fire WS status query once on WS connect (StrictMode-safe)
  const hasFetchedRef = useRef(false);
  useEffect(() => {
    if (wsConnected && !hasFetchedRef.current) {
      hasFetchedRef.current = true;
      fetchWifiStatus();
    }
    if (!wsConnected) hasFetchedRef.current = false;
  }, [wsConnected, fetchWifiStatus]);

  // Real-time wifi_push messages
  useEffect(() => {
    if (!lastMessage || lastMessage.rid !== 'wifi_push') return;
    if (lastMessage.host_identifier && lastMessage.host_identifier !== hostId) return;
    try {
      const raw = typeof lastMessage.response === 'string'
        ? JSON.parse(lastMessage.response)
        : lastMessage.response;
      if (raw && typeof raw === 'object' && 'saved_profiles' in raw) {
        setWifiData(raw as WifiEvent);
        setLastEventType(raw.event_type ?? 'change');
        // Keep saved profiles table in sync with live push
        if (Array.isArray(raw.saved_profiles)) {
          setSavedProfiles(raw.saved_profiles);
        }
      }
    } catch {
      // malformed push — ignore
    }
  }, [lastMessage, hostId]);


  return (
    <div className="p-4 flex flex-col gap-6">

      {/* Header card */}
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h6 className="font-semibold text-gray-800">WiFi Telemetry</h6>
              <ConnectionBadge loadingStatus={loadingStatus} wifiData={wifiData} />
              {lastEventType && (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-slate-100 text-slate-500 uppercase tracking-wide">
                  {lastEventType}
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500 mt-0.5">
              Real-time WiFi status — pushed by agent on connect / change.
            </p>
            <span className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full ${wsConnected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              {wsConnected ? 'Agent Connected' : 'Agent Disconnected'}
            </span>
          </div>
          <button
            type="button"
            onClick={() => { fetchSavedProfiles(); if (wsConnected) fetchWifiStatus(); }}
            disabled={loadingStatus || loadingSaved}
            className="text-xs text-blue-600 hover:text-blue-800 font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1 shrink-0 mt-1 rounded-lg"
          >
            <i className={`fa fa-sync-alt ${(loadingStatus || loadingSaved) ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {savedProfiles.length > 0 && <RiskBanner savedProfiles={savedProfiles} />}

        {/* No data yet */}
        {!wifiData && !loadingStatus && (
          <div className="p-8 text-center text-gray-500 text-sm">
            {wsConnected
              ? 'No WiFi data received yet. Click Refresh to query the agent.'
              : 'Agent is offline. WiFi data will appear when the agent reconnects.'}
          </div>
        )}
      </div>

      {/* Current connection card */}
      {wifiData && (
        <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
          <div className="px-4 py-3 bg-gray-50 border-b border-blue-100">
            <h6 className="font-semibold text-gray-800">Current Connection</h6>
          </div>

          {wifiData.connected ? (
            <div className="p-4 space-y-4">
              {/* SSID + security row */}
              <div className="flex items-center gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <div className="w-10 h-10 rounded-xl bg-blue-50 flex items-center justify-center">
                    <i className="fa fa-wifi text-blue-500 text-lg" />
                  </div>
                  <div>
                    <p className="font-semibold text-gray-900">
                      {wifiData.connected.ssid || <span className="text-gray-400 italic">Hidden SSID</span>}
                    </p>
                    <p className="text-xs text-gray-500">{wifiData.connected.bssid}</p>
                  </div>
                </div>
                {wifiData.connected.security && (
                  <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-50 text-blue-700 border border-blue-100">
                    {wifiData.connected.security}
                  </span>
                )}
              </div>

              {/* Details grid */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                {[
                  { label: 'Signal',    value: <SignalBar value={wifiData.connected.signal} /> },
                  { label: 'Band',      value: [wifiData.connected.frequency, wifiData.connected.channel ? `Ch ${wifiData.connected.channel}` : ''].filter(Boolean).join(' · ') || '—' },
                  { label: 'Bitrate',   value: wifiData.connected.bitrate || '—' },
                  { label: 'Interface', value: wifiData.connected.interface || '—' },
                  { label: 'IP Address',value: wifiData.connected.ip_address || '—' },
                ].map((item) => (
                  <div key={item.label} className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2">
                    <p className="text-[10px] font-semibold uppercase text-gray-400">{item.label}</p>
                    <div className="mt-1 font-medium text-gray-800 break-words">{item.value}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-8 text-center">
              <div className="mx-auto w-12 h-12 rounded-2xl bg-gray-100 flex items-center justify-center mb-3">
                <i className="fa fa-wifi-slash text-gray-400 text-xl" />
              </div>
              <p className="font-semibold text-gray-700">No active network connection</p>
              <p className="text-sm text-gray-500 mt-1">The node may be using a wired connection.</p>
            </div>
          )}
        </div>
      )}

      {/* Saved profiles table — always rendered, sourced from DB via HTTP */}
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
        <div className="px-4 py-3 bg-gray-50 border-b border-blue-100 flex items-center justify-between">
          <div>
            <h6 className="font-semibold text-gray-800">
              Saved WiFi Profiles
              {!loadingSaved && (
                <span className="ml-2 text-xs font-normal text-gray-500">
                  ({savedProfiles.length})
                </span>
              )}
            </h6>
            <p className="text-xs text-gray-500 mt-0.5">
              Sorted by security risk — worst first.
            </p>
          </div>
        </div>

        {loadingSaved ? (
          <div className="p-8 text-center text-gray-500 text-sm">
            <DuoSpinner size="xs" className="mr-2" />
            Loading saved profiles…
          </div>
        ) : savedProfiles.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">
            No saved WiFi profiles found on this node.
          </div>
        ) : (
          <div className="overflow-auto max-h-[480px]">
            <table className="w-full text-sm border-separate border-spacing-0">
              <thead>
                <tr className="text-left">
                  <th className="pb-2 pt-3 px-4 font-semibold text-gray-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Network (SSID)</th>
                  <th className="pb-2 pt-3 px-4 font-semibold text-gray-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Security</th>
                  <th className="pb-2 pt-3 px-4 font-semibold text-gray-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Risk</th>
                  <th className="pb-2 pt-3 px-4 font-semibold text-gray-700 whitespace-nowrap sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Last Used</th>
                  <th className="pb-2 pt-3 px-4 font-semibold text-gray-700 whitespace-nowrap text-center sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Auto-Connect</th>
                </tr>
              </thead>
              <tbody>
                {sortedProfiles.map((profile, idx) => (
                  <tr key={profile.uuid || profile.name || profile.ssid || idx} className="border-b last:border-0 hover:bg-gray-50">
                    <td className="py-3 px-4">
                      <p className={`font-medium ${profile.auto_connect ? 'text-gray-900' : 'text-gray-600'}`}>
                        {profile.ssid || <span className="italic text-gray-400">Hidden SSID</span>}
                      </p>
                      <p className="text-[11px] text-gray-400 mt-0.5 max-w-[220px] truncate" title={profile.security_detail}>
                        {profile.security_detail}
                      </p>
                    </td>
                    <td className="py-3 px-4 text-gray-600 whitespace-nowrap">
                      {profile.security || '—'}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${RISK_STYLES[profile.security_risk]}`}>
                        {profile.security_risk.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-gray-500 text-xs whitespace-nowrap">
                      {relativeTime(profile.last_used)}
                    </td>
                    <td className="py-3 px-4 text-center">
                      {profile.auto_connect
                        ? <i className="fa fa-check text-green-600" title="Auto-connects" />
                        : <i className="fa fa-xmark text-gray-400" title="Manual only" />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
};

export default NodesViewWifiControl;
