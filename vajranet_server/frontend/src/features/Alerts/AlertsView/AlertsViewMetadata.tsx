/**
 * AlertsView: Metadata tab — key-value and technique tags for the alert.
 * API: alertsViewApi.getAlertQuery for extra metadata when backend is ready.
 */

import { useState, useEffect } from 'react';
import type { AlertData } from './types';
import { alertsViewApi } from './alertsViewApi';
import { DuoSpinner } from '../../../components/ui/loading';
import { UnmanagedHostsAlertDetails } from '../UnmanagedHostsAlertDetails';
import type { UnmanagedHost } from '../UnmanagedHostsAlertDetails';

interface AlertsViewMetadataProps {
  alert: AlertData;
}

const AlertsViewMetadata = ({ alert }: AlertsViewMetadataProps) => {
  const [extra, setExtra] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);

  const eventId = typeof alert.id === 'number' ? alert.id : parseInt(String(alert.id), 10);
  const hostId = alert.host_identifier ?? '';

  useEffect(() => {
    if (!hostId) return;
    let cancelled = false;
    setLoading(true);
    alertsViewApi.getAlertQuery(eventId, hostId).then((res) => {
      if (!cancelled) setExtra((res.data as Record<string, unknown>) ?? null);
    }).catch(() => {
      if (!cancelled) setExtra(null);
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
  }, [eventId, hostId]);

  const displayCode = alert.event_code ?? alert.title ?? `Alert ${alert.id}`;
  const techniques = alert.technique ? String(alert.technique).split(',').map((t) => t.trim()) : [];

  const keyValues: { key: string; value: unknown }[] = [
    { key: 'Event code', value: displayCode },
    { key: 'Severity', value: alert.severity },
    { key: 'Host', value: alert.hostname ?? alert.source },
    { key: 'Host identifier', value: alert.host_identifier },
    { key: 'OS', value: alert.os_name },
    { key: 'Timestamp', value: alert.unixtime != null ? new Date(Number(alert.unixtime) * 1000).toLocaleString() : alert.timestamp },
    { key: 'Is open', value: alert.is_open },
  ].filter((r) => r.value !== undefined && r.value !== '');

  return (
    <div className="p-4 space-y-6">
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100">
          <h6 className="font-semibold text-gray-800">Metadata for {displayCode}</h6>
        </div>
        <div className="p-4">
          {loading && (
            <div className="flex justify-center py-4">
              <DuoSpinner size="lg" className="text-blue-500" />
            </div>
          )}
          {techniques.length > 0 && (
            <div className="mb-4">
              <p className="text-sm text-gray-500 mb-2">Techniques</p>
              <div className="flex flex-wrap gap-2">
                {techniques.map((t, i) => (
                  <span
                    key={i}
                    className="px-2 py-1 rounded-lg text-xs font-medium bg-blue-100 text-blue-800"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
          {alert.alert_type === 'Unmanaged Hosts Detected' && Array.isArray((alert.metadata as Record<string, unknown> | null)?.hosts) && (
            <div className="mb-4">
              <UnmanagedHostsAlertDetails hosts={(alert.metadata as Record<string, unknown>).hosts as UnmanagedHost[]} />
            </div>
          )}
          <div className="rounded-lg border border-gray-200 overflow-hidden">
            <table className="w-full text-sm">
              <tbody>
                {keyValues.map(({ key, value }) => (
                  <tr key={key} className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 px-3 text-gray-500 font-medium w-1/3">{key}</td>
                    <td className="py-2 px-3 text-gray-900">{String(value)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {/* Inline metadata from the alert record (USB Device / Defender fields) */}
          {(() => {
            const meta = alert.metadata;
            if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return null;
            const entries = Object.entries(meta as Record<string, unknown>).filter(([, v]) => v != null && v !== '');
            if (entries.length === 0) return null;
            return (
              <div className="mt-4">
                <p className="text-sm text-gray-500 mb-2">Alert Details</p>
                <div className="rounded-lg border border-gray-200 overflow-hidden">
                  <table className="w-full text-sm">
                    <tbody>
                      {entries.map(([k, v]) => (
                        <tr key={k} className="border-b border-gray-100 hover:bg-gray-50">
                          <td className="py-2 px-3 text-gray-500 font-medium w-1/3 capitalize">{k.replace(/_/g, ' ')}</td>
                          <td className="py-2 px-3 text-gray-900 break-all">{String(v)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            );
          })()}

          {extra && Object.keys(extra).length > 0 && (
            <div className="mt-4">
              <p className="text-sm text-gray-500 mb-2">Extra data</p>
              <pre className="p-3 bg-gray-50 rounded-lg text-xs overflow-auto max-h-48">
                {JSON.stringify(extra, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AlertsViewMetadata;
