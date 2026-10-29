import React, { useState, useRef, useEffect } from 'react';
import type { ReactNode } from 'react';
import { isAxiosError } from 'axios';
import { runNmapScan, getScanStatus, cancelScanApi, getActiveScan, runNucleiScan, getNucleiScanStatus, cancelNucleiScanApi } from '../../../api/api';
import type { NmapScanRequest, NucleiScanType, NucleiScanResult } from '../../../api/api';
import { parseNmapOutput } from '../utils/parseNmapOutput';
import type { ParsedNmapResult } from '../utils/parseNmapOutput';
import { NetworkScanContext } from './useNetworkScan';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

export const NetworkScanProvider = ({ children }: { children: ReactNode }) => {
  const [target, setTarget] = useState('');
  const [cidr, setCidr] = useState('');
  const [reason, setReason] = useState('');
  const [scanType, setScanType] = useState<NmapScanRequest['scanType']>('discovery');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<string | null>(null);
  const [command, setCommand] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [knownIps, setKnownIps] = useState<string[]>([]);
  const [unknownIps, setUnknownIps] = useState<string[]>([]);
  const [staleManagedIps, setStaleManagedIps] = useState<string[]>([]);
  const [newIps, setNewIps] = useState<string[]>([]);
  const [disappearedIps, setDisappearedIps] = useState<string[]>([]);
  const [currentSessionId, setCurrentSessionId] = useState<number | null>(null);
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const [activeTab, setActiveTab] = useState<'known' | 'unknown'>('unknown');

  // Advanced Scan (nmap)
  const [isAdvancedScanModalOpen, setIsAdvancedScanModalOpen] = useState(false);
  const [advancedScanIp, setAdvancedScanIp] = useState<string | null>(null);
  const [advancedScanLoadingMap, setAdvancedScanLoadingMap] = useState<Record<string, boolean>>({});
  const [advancedScanProgressMap, setAdvancedScanProgressMap] = useState<Record<string, number>>({});
  const [advancedScanResult, setAdvancedScanResult] = useState<string | null>(null);
  const [advancedScanParsedResult, setAdvancedScanParsedResult] = useState<ParsedNmapResult | null>(null);
  const [advancedScanErrorMap, setAdvancedScanErrorMap] = useState<Record<string, string>>({});
  const [advancedScanResultsMap, setAdvancedScanResultsMap] = useState<Record<string, ParsedNmapResult>>({});
  const [advancedScanRawResultsMap, setAdvancedScanRawResultsMap] = useState<Record<string, string>>({});
  const [advancedScanTypeMap, setAdvancedScanTypeMap] = useState<Record<string, string>>({});
  const advPollIntervalsRef = useRef<Record<string, ReturnType<typeof setInterval>>>({});
  const advHistoryIdMap = useRef<Record<string, number>>({});

  // Vulnerability Scan (Nuclei)
  const [isVulnResultModalOpen, setIsVulnResultModalOpen] = useState(false);
  const [vulnScanIp, setVulnScanIp] = useState<string | null>(null);
  const [vulnScanLoadingMap, setVulnScanLoadingMap] = useState<Record<string, boolean>>({});
  const [vulnScanProgressMap, setVulnScanProgressMap] = useState<Record<string, number>>({});
  const [vulnScanResult, setVulnScanResult] = useState<NucleiScanResult | null>(null);
  const [vulnScanErrorMap, setVulnScanErrorMap] = useState<Record<string, string>>({});
  const [vulnScanResultsMap, setVulnScanResultsMap] = useState<Record<string, NucleiScanResult>>({});
  const [vulnScanTypeMap, setVulnScanTypeMap] = useState<Record<string, string>>({});
  const vulnPollIntervalsRef = useRef<Record<string, ReturnType<typeof setInterval>>>({});
  const vulnHistoryIdMap = useRef<Record<string, number>>({});

  useEffect(() => {
    // No frontend deployment-mode check is needed here: the whole /network
    // router is behind requireOnPrem (backend/src/routes/api/network.ts), so
    // this call already fails closed on a cloud deployment.
    const checkActive = async () => {
      try {
        const res = await getActiveScan();
        if (res.success && res.data) {
          setCurrentSessionId(res.data.historyId);
          setLoading(true);
          setProgress(res.data.progress || 0);
          pollMainScan(res.data.historyId);
        }
      } catch (err) {
        console.error("Failed to fetch active scan:", err);
      }
    };
    checkActive();

    const advPollIntervals = advPollIntervalsRef.current;
    const vulnPollIntervals = vulnPollIntervalsRef.current;
    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
      Object.values(advPollIntervals).forEach(clearInterval);
      Object.values(vulnPollIntervals).forEach(clearInterval);
    };
  }, []);

  // Main Nmap Scan

  const pollMainScan = (historyId: number) => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);

    pollIntervalRef.current = setInterval(async () => {
      try {
        const statusRes = await getScanStatus(historyId);
        if (statusRes.success && statusRes.data) {
          setProgress(statusRes.data.progress || 0);

          if (statusRes.data.status === 'COMPLETED' || statusRes.data.status === 'FAILED' || statusRes.data.status === 'CANCELLED') {
            if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
            setLoading(false);

            if (statusRes.data.status === 'COMPLETED') {
              setResult(statusRes.data.output || '');
              setKnownIps(statusRes.data.knownIps || []);
              setUnknownIps(statusRes.data.unknownIps || []);
              setStaleManagedIps(statusRes.data.staleManagedIps || []);
              setNewIps(statusRes.data.newIps || []);
              setDisappearedIps(statusRes.data.disappearedIps || []);
            } else if (statusRes.data.status === 'CANCELLED') {
              setError('Scan was cancelled by the user.');
            } else {
              setError('Scan failed. ' + (statusRes.data.message || ''));
            }
          }
        }
      } catch (err) {
        console.error("Polling error:", err);
      }
    }, 3000);
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!target || !reason) return;

    setLoading(true);
    setProgress(0);
    setError(null);
    setResult(null);
    setCommand(null);
    setKnownIps([]);
    setUnknownIps([]);
    setStaleManagedIps([]);
    setNewIps([]);
    setDisappearedIps([]);
    setCurrentSessionId(null);
    setAdvancedScanResultsMap({});
    setAdvancedScanTypeMap({});
    setVulnScanResultsMap({});
    setVulnScanTypeMap({});

    try {
      let finalTarget = target;
      if (cidr) {
        const cleanCidr = cidr.startsWith('/') ? cidr : `/${cidr}`;
        finalTarget = target
          .split(/[\s,]+/)
          .filter(t => t)
          .map(t => t.includes('/') ? t : `${t}${cleanCidr}`)
          .join(' ');
      }

      const response = await runNmapScan(
        { target: finalTarget, scanType, reason }
      );

      if (response.success && response.data?.historyId) {
        setCurrentSessionId(response.data.historyId);
        pollMainScan(response.data.historyId);
      } else {
        setError('Failed to initiate scan.');
        setLoading(false);
      }
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to execute Nmap scan'));
      setLoading(false);
    }
  };

  const cancelScan = async () => {
    if (currentSessionId) {
      try {
        await cancelScanApi(currentSessionId);
      } catch (e) {
        console.error("Failed to cancel API side", e);
      }
    }
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    setLoading(false);
    setError('Scan was cancelled by the user.');
  };

  // Advanced Nmap Scan (per-IP)

  const pollAdvancedScan = (ip: string, historyId: number) => {
    if (advPollIntervalsRef.current[ip]) clearInterval(advPollIntervalsRef.current[ip]);

    advPollIntervalsRef.current[ip] = setInterval(async () => {
      try {
        const statusRes = await getScanStatus(historyId);
        if (statusRes.success && statusRes.data) {
          setAdvancedScanProgressMap(prev => ({ ...prev, [ip]: statusRes.data?.progress || 0 }));

          if (statusRes.data.status === 'COMPLETED' || statusRes.data.status === 'FAILED' || statusRes.data.status === 'CANCELLED') {
            clearInterval(advPollIntervalsRef.current[ip]);
            delete advPollIntervalsRef.current[ip];
            delete advHistoryIdMap.current[ip];
            setAdvancedScanLoadingMap(prev => ({ ...prev, [ip]: false }));

            if (statusRes.data.status === 'COMPLETED') {
              const output = statusRes.data.output || '';
              const parsed = parseNmapOutput(output);

              setAdvancedScanIp((currentIp) => {
                if (currentIp === ip) {
                  setAdvancedScanResult(output);
                  setAdvancedScanParsedResult(parsed);
                }
                return currentIp;
              });

              setAdvancedScanResultsMap(prev => ({ ...prev, [ip]: parsed }));
              setAdvancedScanRawResultsMap(prev => ({ ...prev, [ip]: output }));
            } else if (statusRes.data.status === 'CANCELLED') {
              setAdvancedScanErrorMap(prev => ({ ...prev, [ip]: 'Scan was cancelled.' }));
            } else {
              setAdvancedScanErrorMap(prev => ({ ...prev, [ip]: 'Scan failed. ' + (statusRes.data?.message || '') }));
            }
          }
        }
      } catch (err) {
        console.error("Advanced scan poll error", err);
      }
    }, 3000);
  };

  const startAdvancedScan = async (ip: string, type: 'advanced' = 'advanced') => {
    if (!ip) return;

    setAdvancedScanLoadingMap(prev => ({ ...prev, [ip]: true }));
    setAdvancedScanProgressMap(prev => ({ ...prev, [ip]: 0 }));
    setAdvancedScanErrorMap(prev => ({ ...prev, [ip]: '' }));
    setAdvancedScanTypeMap(prev => ({ ...prev, [ip]: type }));

    try {
      const response = await runNmapScan(
        {
          target: ip,
          scanType: type,
          reason: 'Advanced deep scan on unknown IP',
          sessionId: currentSessionId || undefined
        }
      );

      if (response.success && response.data?.historyId) {
        advHistoryIdMap.current[ip] = response.data.historyId;
        pollAdvancedScan(ip, response.data.historyId);
      } else {
        setAdvancedScanErrorMap(prev => ({ ...prev, [ip]: 'Failed to start advanced scan.' }));
        setAdvancedScanLoadingMap(prev => ({ ...prev, [ip]: false }));
      }
    } catch (err) {
      setAdvancedScanErrorMap(prev => ({ ...prev, [ip]: getErrorMessage(err, 'Failed to execute advanced scan') }));
      setAdvancedScanLoadingMap(prev => ({ ...prev, [ip]: false }));
    }
  };

  const cancelAdvancedScan = async (ip: string) => {
    const historyId = advHistoryIdMap.current[ip];
    if (historyId) {
      try {
        await cancelScanApi(historyId);
      } catch (e) {
        console.error("Failed to cancel advanced scan:", e);
      }
      delete advHistoryIdMap.current[ip];
    }
    if (advPollIntervalsRef.current[ip]) {
      clearInterval(advPollIntervalsRef.current[ip]);
      delete advPollIntervalsRef.current[ip];
    }
    setAdvancedScanLoadingMap(prev => ({ ...prev, [ip]: false }));
  };

  const openAdvancedScanModal = (ip: string) => {
    setAdvancedScanIp(ip);
    setAdvancedScanResult(advancedScanRawResultsMap[ip] || null);
    setAdvancedScanParsedResult(advancedScanResultsMap[ip] || null);
    setIsAdvancedScanModalOpen(true);
  };

  // Vulnerability Scan (Nuclei, per-IP)

  const pollVulnScan = (ip: string, historyId: number) => {
    if (vulnPollIntervalsRef.current[ip]) clearInterval(vulnPollIntervalsRef.current[ip]);

    vulnPollIntervalsRef.current[ip] = setInterval(async () => {
      try {
        const statusRes = await getNucleiScanStatus(historyId);
        if (statusRes.success && statusRes.data) {
          setVulnScanProgressMap(prev => ({ ...prev, [ip]: statusRes.data?.progress || 0 }));

          if (statusRes.data.status === 'COMPLETED' || statusRes.data.status === 'FAILED' || statusRes.data.status === 'CANCELLED') {
            clearInterval(vulnPollIntervalsRef.current[ip]);
            delete vulnPollIntervalsRef.current[ip];
            delete vulnHistoryIdMap.current[ip];
            setVulnScanLoadingMap(prev => ({ ...prev, [ip]: false }));

            if (statusRes.data.status === 'COMPLETED') {
              const scanResult: NucleiScanResult = {
                findings: statusRes.data.findings || [],
                summary: statusRes.data.summary,
              };

              setVulnScanIp((currentIp) => {
                if (currentIp === ip) {
                  setVulnScanResult(scanResult);
                }
                return currentIp;
              });

              setVulnScanResultsMap(prev => ({ ...prev, [ip]: scanResult }));
            } else if (statusRes.data.status === 'FAILED') {
              setVulnScanErrorMap(prev => ({ ...prev, [ip]: 'Vulnerability scan failed.' }));
            } else if (statusRes.data.status === 'CANCELLED') {
              setVulnScanErrorMap(prev => ({ ...prev, [ip]: 'Scan was cancelled.' }));
            }
          }
        }
      } catch (err) {
        console.error("Vuln scan poll error", err);
      }
    }, 3000);
  };

  const startVulnScan = async (ip: string, type: NucleiScanType) => {
    if (!ip) return;

    setVulnScanLoadingMap(prev => ({ ...prev, [ip]: true }));
    setVulnScanProgressMap(prev => ({ ...prev, [ip]: 0 }));
    setVulnScanErrorMap(prev => ({ ...prev, [ip]: '' }));
    setVulnScanTypeMap(prev => ({ ...prev, [ip]: type }));

    try {
      const response = await runNucleiScan({
        target: ip,
        scanType: type,
        reason: `Vulnerability scan (${type})`,
        networkScanId: currentSessionId || undefined,
      });

      if (response.success && response.data?.historyId) {
        vulnHistoryIdMap.current[ip] = response.data.historyId;
        pollVulnScan(ip, response.data.historyId);
      } else {
        setVulnScanErrorMap(prev => ({ ...prev, [ip]: 'Failed to start vulnerability scan.' }));
        setVulnScanLoadingMap(prev => ({ ...prev, [ip]: false }));
      }
    } catch (err) {
      setVulnScanErrorMap(prev => ({ ...prev, [ip]: getErrorMessage(err, 'Failed to start vulnerability scan') }));
      setVulnScanLoadingMap(prev => ({ ...prev, [ip]: false }));
    }
  };

  const cancelVulnScan = async (ip: string) => {
    const historyId = vulnHistoryIdMap.current[ip];
    if (historyId) {
      try {
        await cancelNucleiScanApi(historyId);
      } catch (e) {
        console.error("Failed to cancel Nuclei scan:", e);
      }
      delete vulnHistoryIdMap.current[ip];
    }
    if (vulnPollIntervalsRef.current[ip]) {
      clearInterval(vulnPollIntervalsRef.current[ip]);
      delete vulnPollIntervalsRef.current[ip];
    }
    setVulnScanLoadingMap(prev => ({ ...prev, [ip]: false }));
  };

  const openVulnResultModal = (ip: string) => {
    setVulnScanIp(ip);
    setVulnScanResult(vulnScanResultsMap[ip] || null);
    setIsVulnResultModalOpen(true);
  };

  return (
    <NetworkScanContext.Provider value={{
      target, setTarget,
      cidr, setCidr,
      reason, setReason,
      scanType, setScanType,
      loading, progress, result, command, error,
      knownIps, unknownIps, staleManagedIps, newIps, disappearedIps,
      currentSessionId,
      handleScan, cancelScan,
      activeTab, setActiveTab,
      isAdvancedScanModalOpen, setIsAdvancedScanModalOpen,
      advancedScanIp, setAdvancedScanIp,
      advancedScanLoadingMap, advancedScanProgressMap,
      advancedScanResult,
      advancedScanParsedResult, advancedScanErrorMap,
      startAdvancedScan, cancelAdvancedScan,
      advancedScanResultsMap,
      advancedScanRawResultsMap,
      advancedScanTypeMap,
      openAdvancedScanModal,
      isVulnResultModalOpen, setIsVulnResultModalOpen,
      vulnScanIp, setVulnScanIp,
      vulnScanLoadingMap, vulnScanProgressMap,
      vulnScanResult,
      vulnScanErrorMap,
      startVulnScan, cancelVulnScan,
      vulnScanResultsMap,
      vulnScanTypeMap,
      openVulnResultModal
    }}>
      {children}
    </NetworkScanContext.Provider>
  );
};
