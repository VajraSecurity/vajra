/**
 * NodesViewFirewallStatusControl
 *
 * Read-only firewall status panel for Linux nodes.
 * Data arrives via firewall_status_push from the agent (ufw / firewalld / nftables / iptables).
 * On page load the latest row is fetched from GET /api/nodes/firewall-status;
 * any subsequent push on the per-node WS channel refreshes state in-place.
 */

import { useState, useEffect, useCallback } from 'react';
import { DuoSpinner } from '@/components/ui/loading';
import type { NodeData } from './types';
import { NODES_URLS } from '../../../api/urls';
import api from '../../../api/axiosInstance';

interface FirewallStatus {
  manager: string;
  active: boolean;
  enabled_on_boot: boolean;
  default_policy_in: string;
  default_policy_out: string;
  zone_or_profile: string | null;
  installed: string[];
  distro: string | null;
  init_system: string | null;
  details: string | null;
  updated_at: number | null;
}

interface NodesViewFirewallStatusControlProps {
  node: NodeData;
  wsConnected: boolean;
  lastMessage: unknown;
}

function toLocal(epoch: number | null): string {
  if (!epoch) return 'N/A';
  return new Date(epoch * 1000).toLocaleString();
}

const MANAGER_LABELS: Record<string, string> = {
  ufw: 'UFW',
  firewalld: 'firewalld',
  nftables: 'nftables',
  iptables: 'iptables',
  none: 'None',
};

const NodesViewFirewallStatusControl = ({
  node,
  wsConnected,
  lastMessage,
}: NodesViewFirewallStatusControlProps) => {
  const hostId = node.host_identifier || String(node.id);

  const [status, setStatus] = useState<FirewallStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await api.get(NODES_URLS.FIREWALL_STATUS);
      const body = res.data;
      const rows: Array<FirewallStatus & { host_identifier?: string }> = Array.isArray(body?.data) ? body.data : [];
      const row = rows.find((r) => String(r.host_identifier) === hostId);
      setStatus(row ?? null);
      setFetchError(null);
    } catch (err: unknown) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load firewall status');
    } finally {
      setLoading(false);
    }
  }, [hostId]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  // Live refresh: agent pushes firewall_status_push on connect and every 5 min.
  useEffect(() => {
    if (!lastMessage) return;
    try {
      const parsed = typeof lastMessage === 'string' ? JSON.parse(lastMessage) : lastMessage;
      if (parsed?.rid !== 'firewall_status_push') return;
      if (String(parsed?.host_identifier) !== hostId) return;
      const fw: FirewallStatus = typeof parsed.response === 'string'
        ? JSON.parse(parsed.response)
        : (parsed.response ?? {});
      setStatus((prev) => ({ ...(prev ?? {} as FirewallStatus), ...fw }));
      setFetchError(null);
    } catch { /* ignore malformed */ }
  }, [lastMessage, hostId]);

  const manager = status?.manager ?? 'none';
  const managerLabel = MANAGER_LABELS[manager] ?? manager;
  const active = status?.active ?? false;

  const statusColor = !status
    ? 'bg-slate-50 border-slate-200'
    : active
      ? 'bg-green-50 border-green-100'
      : 'bg-red-50 border-red-100';

  const dotColor = !status ? 'bg-slate-400' : active ? 'bg-green-500' : 'bg-red-500';
  const statusLabel = !status ? 'No data' : active ? 'Active' : 'Inactive';

  return (
    <div className="p-4 flex flex-col gap-6">
      <div className={`bg-white rounded-xl border overflow-hidden ${statusColor}`}>
        {/* Header */}
        <div className={`px-4 py-3 border-b ${statusColor} flex items-center justify-between gap-3`}>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h6 className="font-semibold text-gray-800 flex items-center gap-2">
                <i className="fa fa-shield-halved text-blue-600" /> Firewall Status
              </h6>
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                  active
                    ? 'bg-green-100 text-green-700'
                    : status
                      ? 'bg-red-100 text-red-700'
                      : 'bg-slate-100 text-slate-600'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
                {statusLabel}
              </span>
              {status && (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-700">
                  {managerLabel}
                </span>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={fetchStatus}
            className="text-xs text-blue-700 hover:text-blue-900 font-medium flex items-center gap-1 rounded-lg"
          >
            <i className="fa fa-sync-alt" /> Refresh
          </button>
        </div>

        <div className="p-4">
          {loading && (
            <div className="flex items-center gap-2 text-sm text-gray-500 py-4">
              <DuoSpinner size="sm" /> Loading firewall status…
            </div>
          )}

          {!loading && fetchError && (
            <div className="rounded-lg px-3 py-2 text-sm bg-red-50 border border-red-200 text-red-700">
              {fetchError}
            </div>
          )}

          {!loading && !fetchError && !status && (
            <div className="py-8 text-center text-sm text-gray-400">
              No firewall status reported yet.{' '}
              {wsConnected
                ? 'Status will appear when the agent pushes its next heartbeat.'
                : 'Connect the agent to receive firewall status.'}
            </div>
          )}

          {!loading && status && (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              {/* Status card */}
              <div className="rounded-lg border border-gray-200 overflow-hidden">
                <div className="px-3 py-2 bg-gray-50 border-b border-gray-200">
                  <h6 className="font-semibold text-gray-800">Firewall State</h6>
                </div>
                <div className="p-3">
                  <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
                    <dt className="text-gray-500">Manager</dt>
                    <dd className="text-gray-800 font-medium">{managerLabel}</dd>

                    <dt className="text-gray-500">Status</dt>
                    <dd>
                      <span className={`inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full ${
                        active ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-green-500' : 'bg-red-500'}`} />
                        {active ? 'Active' : 'Inactive'}
                      </span>
                    </dd>

                    <dt className="text-gray-500">Boot Persistent</dt>
                    <dd>
                      <span className={`inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full ${
                        status.enabled_on_boot ? 'bg-green-100 text-green-700' : 'bg-amber-100 text-amber-700'
                      }`}>
                        {status.enabled_on_boot ? 'Yes' : 'No'}
                      </span>
                    </dd>

                    {status.zone_or_profile && (
                      <>
                        <dt className="text-gray-500">Zone / Profile</dt>
                        <dd className="text-gray-800 font-mono text-xs">{status.zone_or_profile}</dd>
                      </>
                    )}

                    <dt className="text-gray-500">Last Updated</dt>
                    <dd className="text-gray-600 text-xs">{toLocal(status.updated_at)}</dd>
                  </dl>
                </div>
              </div>

              {/* Policy card */}
              <div className="rounded-lg border border-gray-200 overflow-hidden">
                <div className="px-3 py-2 bg-gray-50 border-b border-gray-200">
                  <h6 className="font-semibold text-gray-800">Default Policies</h6>
                </div>
                <div className="p-3">
                  <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
                    <dt className="text-gray-500">Inbound</dt>
                    <dd>
                      <span className={`inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded-full ${
                        (status.default_policy_in ?? '').toLowerCase() === 'deny' || (status.default_policy_in ?? '').toLowerCase() === 'drop'
                          ? 'bg-green-100 text-green-700'
                          : 'bg-amber-100 text-amber-700'
                      }`}>
                        {status.default_policy_in || 'unknown'}
                      </span>
                    </dd>

                    <dt className="text-gray-500">Outbound</dt>
                    <dd>
                      <span className={`inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded-full ${
                        (status.default_policy_out ?? '').toLowerCase() === 'allow'
                          ? 'bg-blue-100 text-blue-700'
                          : 'bg-amber-100 text-amber-700'
                      }`}>
                        {status.default_policy_out || 'unknown'}
                      </span>
                    </dd>

                    {status.distro && (
                      <>
                        <dt className="text-gray-500">Distro</dt>
                        <dd className="text-gray-700 text-xs">{status.distro}</dd>
                      </>
                    )}

                    {status.init_system && (
                      <>
                        <dt className="text-gray-500">Init</dt>
                        <dd className="text-gray-700 text-xs">{status.init_system}</dd>
                      </>
                    )}

                    {status.installed && status.installed.length > 0 && (
                      <>
                        <dt className="text-gray-500">Installed</dt>
                        <dd className="text-gray-700 text-xs">{status.installed.join(', ')}</dd>
                      </>
                    )}
                  </dl>
                </div>
              </div>

              {/* Raw details */}
              {status.details && (
                <div className="rounded-lg border border-gray-200 p-3 xl:col-span-2">
                  <h6 className="font-semibold text-gray-800 mb-2 text-sm">Details</h6>
                  <pre className="text-xs text-gray-700 bg-gray-50 rounded p-2 max-h-40 overflow-auto whitespace-pre-wrap break-all">
                    {status.details}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default NodesViewFirewallStatusControl;
