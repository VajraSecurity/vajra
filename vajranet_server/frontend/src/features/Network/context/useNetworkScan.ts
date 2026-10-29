import React, { createContext, useContext } from 'react';
import type { NmapScanRequest, NucleiScanType, NucleiScanResult } from '../../../api/api';
import type { ParsedNmapResult } from '../utils/parseNmapOutput';

export interface NetworkScanContextType {
  target: string;
  setTarget: (target: string) => void;
  cidr: string;
  setCidr: (cidr: string) => void;
  reason: string;
  setReason: (reason: string) => void;
  scanType: NmapScanRequest['scanType'];
  setScanType: (scanType: NmapScanRequest['scanType']) => void;
  loading: boolean;
  progress: number;
  result: string | null;
  command: string | null;
  error: string | null;
  knownIps: string[];
  unknownIps: string[];
  staleManagedIps: string[];
  newIps: string[];
  disappearedIps: string[];
  currentSessionId: number | null;
  handleScan: (e?: React.FormEvent) => Promise<void>;
  cancelScan: () => void;

  activeTab: 'known' | 'unknown';
  setActiveTab: (tab: 'known' | 'unknown') => void;

  // Advanced Scan (nmap)
  isAdvancedScanModalOpen: boolean;
  setIsAdvancedScanModalOpen: (isOpen: boolean) => void;
  advancedScanIp: string | null;
  setAdvancedScanIp: (ip: string | null) => void;
  advancedScanLoadingMap: Record<string, boolean>;
  advancedScanProgressMap: Record<string, number>;
  advancedScanResult: string | null;
  advancedScanParsedResult: ParsedNmapResult | null;
  advancedScanErrorMap: Record<string, string>;
  startAdvancedScan: (ip: string, type?: 'advanced') => Promise<void>;
  cancelAdvancedScan: (ip: string) => void;
  advancedScanResultsMap: Record<string, ParsedNmapResult>;
  advancedScanRawResultsMap: Record<string, string>;
  advancedScanTypeMap: Record<string, string>;
  openAdvancedScanModal: (ip: string) => void;

  // Vulnerability Scan (Nuclei)
  isVulnResultModalOpen: boolean;
  setIsVulnResultModalOpen: (isOpen: boolean) => void;
  vulnScanIp: string | null;
  setVulnScanIp: (ip: string | null) => void;
  vulnScanLoadingMap: Record<string, boolean>;
  vulnScanProgressMap: Record<string, number>;
  vulnScanResult: NucleiScanResult | null;
  vulnScanErrorMap: Record<string, string>;
  startVulnScan: (ip: string, type: NucleiScanType) => Promise<void>;
  cancelVulnScan: (ip: string) => void;
  vulnScanResultsMap: Record<string, NucleiScanResult>;
  vulnScanTypeMap: Record<string, string>;
  openVulnResultModal: (ip: string) => void;
}

export const NetworkScanContext = createContext<NetworkScanContextType | undefined>(undefined);

export const useNetworkScan = () => {
  const context = useContext(NetworkScanContext);
  if (context === undefined) {
    throw new Error('useNetworkScan must be used within a NetworkScanProvider');
  }
  return context;
};
