/**
 * NodesViewClamavControl
 *
 * Linux ClamAV surface:
 * - Ping / daemon health check (auto on connect)
 * - Engine + signature database version card, with remote signature update
 * - On-demand scans (async: immediate ack, completion via clamav_scan_push)
 * - Real-time detection table driven by clamav_push WS messages
 *
 * Async protocol: the agent acknowledges scan/update commands immediately
 * (the server's rid routing expires after 60 s, so long-running work can
 * never respond synchronously). Outcomes arrive as agent pushes:
 *   clamav_scan_push   — scan completion summary
 *   clamav_status_push — daemon health + DB version (+ freshclam result)
 *   clamav_push        — individual detections (store-and-forward)
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { DuoSpinner } from '@/components/ui/loading';
import type { NodeData } from './types';
import { sanitizeAsciiSingleLine } from '../../../services/inputSanitizers';
import { nodesViewApi } from './nodesViewApi';
import { useToast } from '../../../context/useToast';

interface ClamavAlert {
  source?: string;
  scan_type?: string;
  path?: string;
  signature?: string;
  status?: string;
  /** SHA-256 computed by the agent from the file at detection time. */
  sha256?: string;
  /** MD5 from clamd's ExtendedDetectionInfo, when available. */
  md5?: string;
  size_bytes?: number;
  detected_at?: string;
}

interface ClamavScanResult {
  path?: string;
  status?: string;
  signature?: string;
  message?: string;
}

/** Matches the Go agent's CommandResponse (agent/clamav/main.go). */
interface ClamavResponse {
  source?: string;
  command?: string;
  target?: string;
  success?: boolean;
  async?: boolean;
  raw?: string;
  error?: string;
  results?: ClamavScanResult[];
  scanned?: number;
  infected?: number;
  errors?: number;
  timestamp?: string;
}

/** Matches the Go agent's Status (clamav_status_push). */
interface ClamavStatus {
  source?: string;
  daemon_running?: boolean;
  engine_version?: string;
  db_version?: string;
  db_date?: string;
  version_raw?: string;
  freshclam_result?: string;
  error?: string;
  timestamp?: string;
}

interface NodesViewClamavControlProps {
  node: NodeData;
  wsConnected: boolean;
  wsSendMessage: (message: unknown, options?: { timeoutMs?: number }) => Promise<{ status?: string; message?: string; response?: unknown }>;
  /** Raw WS envelope pushed by the server; narrowed inside the effect below (may arrive as a JSON string or object). */
  lastMessage: unknown;
}

const WS_TIMEOUT_MS = 60_000;

function toLocal(value: unknown): string {
  if (!value) return 'N/A';
  const n = Number(value);
  if (!Number.isNaN(n) && n > 1_000_000_000) return new Date(n * 1000).toLocaleString();
  const d = new Date(String(value));
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

const NodesViewClamavControl = ({
  node,
  wsConnected,
  wsSendMessage,
  lastMessage,
}: NodesViewClamavControlProps) => {
  const hostId = node.host_identifier || String(node.id);
  const { showToast } = useToast();

  const [pingStatus, setPingStatus] = useState<'unknown' | 'ok' | 'error'>('unknown');
  const [versionInfo, setVersionInfo] = useState<ClamavStatus | null>(null);
  const [scanPath, setScanPath] = useState('/home');
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [scanRunning, setScanRunning] = useState<{ command: string; path: string; startedAt: number } | null>(null);
  const [sigUpdating, setSigUpdating] = useState(false);
  const [freshclamResult, setFreshclamResult] = useState<string | null>(null);
  const [lastOutput, setLastOutput] = useState<string | null>(null);
  const [realtimeAlerts, setRealtimeAlerts] = useState<ClamavAlert[]>([]);

  // Poll the DB every 30 s while a scan is in progress to recover the result
  // when the live WS push is missed (dropped connection, page open during scan,
  // etc.). The server persists every completed scan to the alerts table so the
  // result is always retrievable via REST. Safety ceiling: 4 h for contscan
  // (matches agent scanTimeout), 35 min for a single-path scan.
  useEffect(() => {
    if (!scanRunning) return;

    const sinceTs = Math.floor(scanRunning.startedAt / 1000) - 5;
    const ceilMs = scanRunning.command === 'contscan'
      ? 4 * 60 * 60 * 1000
      : 35 * 60 * 1000;

    const ceil = setTimeout(() => {
      setScanRunning(null);
      showToast('Scan timed out — no result received after the maximum wait. The scan may still be running on the endpoint; check agent logs.', 'error');
    }, ceilMs);

    const poll = setInterval(async () => {
      try {
        const { data } = await nodesViewApi.getClamavScanLatest(hostId, sinceTs);
        if (data?.found && data.scan) {
          const scan: ClamavResponse = data.scan;
          setScanRunning(null);
          setLastOutput(scan.raw ?? scan.error ?? null);
          if (scan.error) {
            showToast(`Scan of ${scan.target ?? '?'} failed: ${scan.error}`, 'error');
          } else {
            const infected = scan.infected ?? 0;
            showToast(
              `Scan of ${scan.target ?? '?'} completed — ${scan.scanned ?? 0} result(s), ${infected} infected, ${scan.errors ?? 0} error(s).`,
              infected > 0 ? 'error' : 'success',
            );
          }
        }
      } catch { /* network hiccups don't mean the scan failed */ }
    }, 30_000);

    return () => {
      clearInterval(poll);
      clearTimeout(ceil);
    };
  }, [scanRunning, hostId, showToast]);

  // Agent pushes on the per-node nodeUi channel: detections, scan completions,
  // daemon status. All carry host_identifier (attached by the backend).
  useEffect(() => {
    if (!lastMessage) return;
    try {
      const parsed = typeof lastMessage === 'string' ? JSON.parse(lastMessage) : lastMessage;
      if (parsed?.host_identifier !== hostId) return;

      if (parsed?.rid === 'clamav_push') {
        const rows: ClamavAlert[] = typeof parsed.response === 'string'
          ? JSON.parse(parsed.response)
          : (parsed.response ?? []);
        if (Array.isArray(rows) && rows.length > 0) {
          setRealtimeAlerts((prev) => [...rows, ...prev].slice(0, 100));
        }
        return;
      }

      if (parsed?.rid === 'clamav_scan_push') {
        const res: ClamavResponse = typeof parsed.response === 'string'
          ? JSON.parse(parsed.response)
          : (parsed.response ?? {});
        setScanRunning(null);
        setLastOutput(res.raw ?? res.error ?? null);
        if (res.error) {
          showToast(`Scan of ${res.target ?? '?'} failed: ${res.error}`, 'error');
        } else {
          const infected = res.infected ?? 0;
          showToast(
            `Scan of ${res.target ?? '?'} completed — ${res.scanned ?? 0} result(s), ${infected} infected, ${res.errors ?? 0} error(s).`,
            infected > 0 ? 'error' : 'success',
          );
        }
        return;
      }

      if (parsed?.rid === 'clamav_status_push') {
        const st: ClamavStatus = typeof parsed.response === 'string'
          ? JSON.parse(parsed.response)
          : (parsed.response ?? {});
        setPingStatus(st.daemon_running ? 'ok' : 'error');
        if (st.daemon_running) setVersionInfo(st);
        // freshclam_result present ⇒ a signature update just finished.
        if (st.freshclam_result) {
          setSigUpdating(false);
          setFreshclamResult(st.freshclam_result);
          const failed = /failed|timed out/i.test(st.freshclam_result);
          showToast(
            failed
              ? 'Signature update finished with errors — see the freshclam output below.'
              : 'Signature database updated and reloaded.',
            failed ? 'error' : 'success',
          );
        }
        return;
      }
    } catch { /* ignore malformed messages */ }
  }, [lastMessage, hostId, showToast]);

  const sendClamav = useCallback(
    async (action: string, arg1?: string): Promise<ClamavResponse> => {
      const response = await wsSendMessage(
        {
          type: 'agent',
          params: {
            agent: 'clamav',
            action,
            ...(arg1 !== undefined ? { arg1 } : {}),
          },
          host_identifier: hostId,
        },
        { timeoutMs: WS_TIMEOUT_MS },
      );
      try {
        const parsed = JSON.parse(String(response?.response ?? '{}'));
        return parsed && typeof parsed === 'object' ? (parsed as ClamavResponse) : { raw: String(response?.response ?? '') };
      } catch {
        return { raw: String(response?.response ?? '') };
      }
    },
    [hostId, wsSendMessage],
  );

  const hasPingedRef = useRef(false);
  const handlePing = useCallback(async () => {
    if (!wsConnected) return;
    setActionLoading('ping');
    try {
      const res = await sendClamav('ping');
      const ok = res.success === true;
      setPingStatus(ok ? 'ok' : 'error');
      setLastOutput(res.raw ?? res.error ?? null);
      showToast(
        ok ? 'clamd is running (PONG received).' : `Ping failed: ${res.error ?? res.raw ?? 'no response'}`,
        ok ? 'success' : 'error',
      );
      // Daemon is up — fetch the engine/signature versions for the card.
      if (ok) {
        const ver = await sendClamav('version');
        if (ver.success && ver.raw) {
          const [engine, dbVersion, dbDate] = ver.raw.split('/').map((s) => s.trim());
          setVersionInfo({
            daemon_running: true,
            engine_version: engine,
            db_version: dbVersion,
            db_date: dbDate,
            version_raw: ver.raw,
          });
        }
      }
    } catch (err: unknown) {
      setPingStatus('error');
      showToast((err instanceof Error ? err.message : undefined) ?? 'Ping failed.', 'error');
    } finally {
      setActionLoading(null);
    }
  }, [sendClamav, showToast, wsConnected]);

  useEffect(() => {
    if (wsConnected && !hasPingedRef.current) {
      hasPingedRef.current = true;
      handlePing();
    }
    if (!wsConnected) hasPingedRef.current = false;
  }, [handlePing, wsConnected]);

  /** Quick synchronous actions: stats, reload. Respond well within 60 s. */
  const runAction = useCallback(
    async (actionId: string, label: string, action: string, arg1?: string) => {
      setActionLoading(actionId);
      try {
        const res = await sendClamav(action, arg1);
        setLastOutput(res.raw ?? res.error ?? null);
        if (res.error) {
          showToast(`${label}: ${res.error}`, 'error');
        } else {
          showToast(`${label} completed.`, 'success');
        }
      } catch (err: unknown) {
        showToast((err instanceof Error ? err.message : undefined) ?? `${label} failed.`, 'error');
      } finally {
        setActionLoading(null);
      }
    },
    [sendClamav, showToast],
  );

  /** Async scan: agent acks immediately, completion arrives as clamav_scan_push. */
  const startScan = useCallback(
    async (action: 'scan' | 'contscan', path: string) => {
      setActionLoading(action);
      try {
        const res = await sendClamav(action, path);
        if (res.error) {
          showToast(`Scan failed to start: ${res.error}`, 'error');
        } else {
          setScanRunning({ command: action, path, startedAt: Date.now() });
          showToast(
            `Scan of ${path} started — this can take a while. Detections stream in below; a summary arrives when it finishes.`,
            'success',
          );
        }
      } catch (err: unknown) {
        showToast((err instanceof Error ? err.message : undefined) ?? 'Scan failed to start.', 'error');
      } finally {
        setActionLoading(null);
      }
    },
    [sendClamav, showToast],
  );

  /** Async signature update: freshclam on the endpoint, result via status push. */
  const startSignatureUpdate = useCallback(async () => {
    setActionLoading('update');
    setFreshclamResult(null);
    try {
      const res = await sendClamav('update');
      if (res.error) {
        showToast(`Signature update failed to start: ${res.error}`, 'error');
      } else {
        setSigUpdating(true);
        showToast(
          'Signature update started (freshclam) — the version card refreshes when it completes.',
          'success',
        );
      }
    } catch (err: unknown) {
      showToast((err instanceof Error ? err.message : undefined) ?? 'Signature update failed to start.', 'error');
    } finally {
      setActionLoading(null);
    }
  }, [sendClamav, showToast]);

  const busy = !!actionLoading;

  const pingDot =
    pingStatus === 'ok'
      ? 'bg-green-500'
      : pingStatus === 'error'
        ? 'bg-red-500'
        : 'bg-gray-400';

  const pingLabel =
    pingStatus === 'ok' ? 'Running' : pingStatus === 'error' ? 'Unavailable' : 'Unknown';

  return (
    <div className="p-4 flex flex-col gap-6">
      <div className="bg-white rounded-xl border border-green-100 overflow-hidden">
        {/* Header */}
        <div className="px-4 py-3 bg-gradient-to-r from-green-50 to-emerald-50 border-b border-green-100 flex items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h6 className="font-semibold text-gray-800 flex items-center gap-2">
                <i className="fa fa-shield-virus text-green-600" /> ClamAV Controls
              </h6>
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                  pingStatus === 'ok'
                    ? 'bg-green-100 text-green-700'
                    : pingStatus === 'error'
                      ? 'bg-red-100 text-red-700'
                      : 'bg-gray-100 text-gray-600'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${pingDot}`} />
                {pingLabel}
              </span>
            </div>
            <span
              className={`inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded-full mt-1 ${
                wsConnected ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'}`} />
              {wsConnected ? 'Agent Connected' : 'Agent Disconnected'}
            </span>
          </div>
          <button
            type="button"
            onClick={handlePing}
            disabled={busy || !wsConnected}
            className="rounded-lg text-xs text-green-700 hover:text-green-900 font-medium disabled:opacity-50 flex items-center gap-1"
          >
            <i className={`fa fa-sync-alt ${actionLoading === 'ping' ? 'animate-spin' : ''}`} /> Ping
          </button>
        </div>

        {scanRunning && (
          <div className="mx-4 mt-4 rounded-lg px-3 py-2 text-sm bg-blue-50 border border-blue-200 text-blue-700 flex items-center gap-2">
            <DuoSpinner size="sm" />
            {scanRunning.command === 'contscan' ? 'ContScan' : 'Scan'} of{' '}
            <span className="font-mono">{scanRunning.path}</span> running since{' '}
            {new Date(scanRunning.startedAt).toLocaleTimeString()} — detections appear below in real time.
          </div>
        )}

        <div className="p-4 grid grid-cols-1 xl:grid-cols-2 gap-4">
          {/* Engine & Signature Database */}
          <div className="rounded-lg border border-gray-200 overflow-hidden">
            <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 flex items-center justify-between gap-3">
              <div>
                <h6 className="font-semibold text-gray-800">Engine &amp; Signatures</h6>
                <p className="text-xs text-gray-500 mt-0.5">
                  Virus definition database loaded by clamd.
                </p>
              </div>
              <button
                type="button"
                onClick={startSignatureUpdate}
                disabled={busy || sigUpdating || !wsConnected || pingStatus !== 'ok'}
                className="px-3 py-1.5 text-xs font-medium rounded-lg border border-green-200 text-green-700 hover:bg-green-50 disabled:opacity-50 whitespace-nowrap"
              >
                {sigUpdating || actionLoading === 'update' ? (
                  <>
                    <DuoSpinner size="xs" className="text-green-700" /> Updating…
                  </>
                ) : (
                  <>
                    <i className="fa fa-cloud-download-alt" /> Update Signatures
                  </>
                )}
              </button>
            </div>
            <div className="p-3">
              {versionInfo ? (
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
                  <dt className="text-gray-500">Engine</dt>
                  <dd className="text-gray-800 font-medium">{versionInfo.engine_version || '—'}</dd>
                  <dt className="text-gray-500">Signature DB</dt>
                  <dd className="text-gray-800 font-medium">
                    {versionInfo.db_version ? `Version ${versionInfo.db_version}` : 'Not loaded'}
                  </dd>
                  <dt className="text-gray-500">DB Published</dt>
                  <dd className="text-gray-800">{versionInfo.db_date || '—'}</dd>
                </dl>
              ) : (
                <p className="text-sm text-gray-400">
                  {pingStatus === 'error'
                    ? 'clamd is not reachable — version unavailable.'
                    : 'Version not loaded yet.'}
                </p>
              )}
              {freshclamResult && (
                <details className="mt-3">
                  <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-700">
                    Last freshclam output
                  </summary>
                  <pre className="mt-1 text-xs text-gray-700 bg-gray-50 rounded p-2 max-h-32 overflow-auto whitespace-pre-wrap break-all">
                    {freshclamResult}
                  </pre>
                </details>
              )}
            </div>
          </div>

          {/* Scan Actions */}
          <div className="rounded-lg border border-gray-200 overflow-hidden">
            <div className="px-3 py-2 bg-gray-50 border-b border-gray-200">
              <h6 className="font-semibold text-gray-800">Scan Operations</h6>
              <p className="text-xs text-gray-500 mt-0.5">
                Scans run asynchronously on the endpoint — start one and keep working.
              </p>
            </div>
            <div className="p-3 space-y-3">
              <div className="flex flex-wrap gap-2 items-center">
                <input
                  type="text"
                  value={scanPath}
                  onChange={(e) => setScanPath(sanitizeAsciiSingleLine(e.target.value, 512, false))}
                  placeholder="/path/to/scan"
                  className="min-w-[220px] px-2 py-1.5 text-xs border border-gray-300 rounded-lg"
                  disabled={busy || !!scanRunning}
                />
                <button
                  type="button"
                  onClick={() => startScan('scan', scanPath.trim())}
                  disabled={busy || !!scanRunning || !wsConnected || !scanPath.trim()}
                  aria-label="Scan"
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-green-200 text-green-700 hover:bg-green-50 disabled:opacity-50"
                >
                  {actionLoading === 'scan' ? <DuoSpinner size="xs" className="text-green-700" /> : 'Scan'}
                </button>
                <button
                  type="button"
                  onClick={() => startScan('contscan', scanPath.trim())}
                  disabled={busy || !!scanRunning || !wsConnected || !scanPath.trim()}
                  aria-label="ContScan"
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-green-200 text-green-700 hover:bg-green-50 disabled:opacity-50"
                >
                  {actionLoading === 'contscan' ? (
                    <DuoSpinner size="xs" className="text-green-700" />
                  ) : (
                    'ContScan'
                  )}
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => runAction('stats', 'Stats', 'stats')}
                  disabled={busy || !wsConnected}
                  aria-label="Stats"
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-200 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {actionLoading === 'stats' ? <DuoSpinner size="xs" className="text-gray-700" /> : 'Stats'}
                </button>
                <button
                  type="button"
                  onClick={() => runAction('reload', 'Reload Signatures', 'reload')}
                  disabled={busy || !wsConnected}
                  aria-label="Reload Signatures"
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-200 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                >
                  {actionLoading === 'reload' ? (
                    <DuoSpinner size="xs" className="text-gray-700" />
                  ) : (
                    'Reload Signatures'
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Last Command Output */}
          <div className="rounded-lg border border-gray-200 p-3 xl:col-span-2">
            <h6 className="font-semibold text-gray-800 mb-2">Last Command Output</h6>
            {lastOutput ? (
              <pre className="text-xs text-gray-700 bg-gray-50 rounded p-2 max-h-40 overflow-auto whitespace-pre-wrap break-all">
                {lastOutput}
              </pre>
            ) : (
              <p className="text-sm text-gray-400">No output yet.</p>
            )}
          </div>

          {/* Real-time Detection Table */}
          <div className="rounded-lg border border-gray-200 overflow-hidden xl:col-span-2">
            <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 flex items-center justify-between gap-3">
              <div>
                <h6 className="font-semibold text-gray-800">Real-time Detections</h6>
                <p className="text-xs text-gray-500 mt-0.5">
                  Alerts pushed live by the ClamAV agent. Newest first.
                </p>
              </div>
              {realtimeAlerts.length > 0 && (
                <button
                  type="button"
                  onClick={() => setRealtimeAlerts([])}
                  className="rounded-lg text-xs text-gray-400 hover:text-gray-600"
                >
                  Clear
                </button>
              )}
            </div>
            {realtimeAlerts.length === 0 ? (
              <div className="py-10 text-center text-sm text-gray-400">
                No detections received yet.{' '}
                {wsConnected ? 'Alerts will appear here in real-time.' : 'Connect agent to receive alerts.'}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs border-separate border-spacing-0">
                  <thead>
                    <tr>
                      {['Detected At', 'Path', 'Signature', 'SHA-256', 'Status', 'Type'].map((h) => (
                        <th
                          key={h}
                          className="px-3 py-2 text-left font-semibold text-gray-600 uppercase tracking-wide text-[10px] sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {realtimeAlerts.map((alert, idx) => {
                      const isMalware =
                        String(alert.status ?? '').toUpperCase().includes('FOUND') ||
                        String(alert.signature ?? '') !== '';
                      return (
                        <tr
                          key={idx}
                          className={isMalware ? 'bg-red-50' : ''}
                        >
                          <td className="px-3 py-2 whitespace-nowrap text-gray-700">
                            {toLocal(alert.detected_at)}
                          </td>
                          <td
                            className="px-3 py-2 max-w-[260px] truncate text-gray-800 font-mono"
                            title={alert.path}
                          >
                            {alert.path ?? 'N/A'}
                          </td>
                          <td
                            className={`px-3 py-2 font-medium ${isMalware ? 'text-red-700' : 'text-gray-600'}`}
                          >
                            {alert.signature || '—'}
                          </td>
                          <td className="px-3 py-2">
                            {alert.sha256 ? (
                              <button
                                type="button"
                                className="rounded-lg font-mono text-gray-600 hover:text-gray-900"
                                title={`${alert.sha256}\n(click to copy)`}
                                onClick={() => navigator.clipboard?.writeText(alert.sha256 ?? '')}
                              >
                                {alert.sha256.slice(0, 12)}…
                              </button>
                            ) : (
                              <span className="text-gray-400">—</span>
                            )}
                          </td>
                          <td className="px-3 py-2">
                            <span
                              className={`inline-flex items-center rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider border ${
                                isMalware
                                  ? 'bg-red-100 text-red-800 border-red-200'
                                  : 'bg-green-100 text-green-800 border-green-200'
                              }`}
                            >
                              {alert.status ?? 'OK'}
                            </span>
                          </td>
                          <td className="px-3 py-2 text-gray-500">{alert.scan_type ?? '—'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default NodesViewClamavControl;
