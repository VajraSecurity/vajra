/**
 * NodesView Details tab: Software/Hardware info and TPM information.
 * API: nodesViewApi.getTpmInfo
 */

import { useState, useEffect } from 'react';
import type { NodeData } from './types';
import {DuoSpinner} from '@/components/ui/loading';
import { nodesViewApi } from './nodesViewApi';

interface NodesViewDetailsProps {
  node: NodeData;
}

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
};

/** Hardware RAM from API (bytes as string); guards NaN / bad osquery values on Windows. */
const formatPhysicalMemory = (value: string | undefined) => {
  if (value === undefined || value === null) return 'N/A';
  const trimmed = String(value).trim();
  if (!trimmed) return 'N/A';
  const lower = trimmed.toLowerCase();
  if (lower === 'nan' || lower === 'null' || lower === 'undefined') return 'N/A';
  const bytes = parseInt(trimmed, 10);
  if (!Number.isFinite(bytes) || bytes < 0) return 'N/A';
  return formatBytes(bytes);
};

const formatTimestamp = (timestamp: string | number | undefined) => {
  if (!timestamp) return 'N/A';
  const ts = typeof timestamp === 'string' ? parseInt(timestamp, 10) : timestamp;
  if (isNaN(ts)) return 'N/A';
  return new Date(ts * 1000).toLocaleString();
};

interface TpmData {
  id: string;
  host_identifier: string;
  unixtime: string;
  activated: number;
  enabled: number;
  owned: number;
  manufacturer_version: string;
  manufacturer_id: number;
  manufacturer_name: string;
  product_name: string;
  physical_presence_version: string;
  spec_version: string;
}

interface SecureBootData {
  id: string;
  host_identifier: string;
  unixtime: string;
  secure_boot: number;
  setup_mode: number;
}

interface UpdateSummary {
  update_title: string;
  category: string;
  version_reference: string;
  install_status: string;
  timestamp: string;
  description_summary: string;
}

interface IpInterface {
  interface: string;
  address: string;
  mask: string;
  friendly_name: string;
  type: string;
  priority: number;
}

const NodesViewDetails = ({ node }: NodesViewDetailsProps) => {
  const [tpmData, setTpmData] = useState<TpmData | null>(null);
  const [secureBootData, setSecureBootData] = useState<SecureBootData | null>(null);
  const [latestUpdate, setLatestUpdate] = useState<UpdateSummary | null>(null);
  const [primaryIp, setPrimaryIp] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const hostId = node.host_identifier || String(node.id);
  const isUbuntu =
    node.os_platform?.toLowerCase().includes('ubuntu');
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const [tpmRes, secureBootRes, latestUpdateRes, ipRes] = await Promise.all([
          nodesViewApi.getTpmInfo(hostId).catch(() => ({ data: null })),
          nodesViewApi.getSecureBootInfo(hostId).catch(() => ({ data: null })),
          nodesViewApi.getLatestUpdate(hostId).catch(() => ({ data: null })),
          nodesViewApi.getNodeIps(hostId).catch(() => ({ data: null })),
        ]);
        if (!cancelled) {
          const tpmInfo = tpmRes.data as { status?: string; data?: TpmData[] } | null;
          const secureBootInfo = secureBootRes.data as { status?: string; data?: SecureBootData[] } | null;
          const updateInfo = latestUpdateRes.data as { status?: string; data?: { summary?: UpdateSummary } } | null;

          if (tpmInfo?.status === 'Success' && tpmInfo.data && tpmInfo.data.length > 0) {
            setTpmData(tpmInfo.data[0]);
          } else {
            setTpmData(null);
          }

          if (secureBootInfo?.status === 'Success' && secureBootInfo.data && secureBootInfo.data.length > 0) {
            setSecureBootData(secureBootInfo.data[0]);
          } else {
            setSecureBootData(null);
          }

          if (updateInfo?.status === 'Success' && updateInfo.data?.summary) {
            setLatestUpdate(updateInfo.data.summary);
          } else {
            setLatestUpdate(null);
          }

          const ipInfo = ipRes.data as { host_identifier?: string; interfaces?: IpInterface[] } | null;
          if (ipInfo && ipInfo.interfaces && ipInfo.interfaces.length > 0) {
            const priority1Interface = ipInfo.interfaces.find(iface => iface.priority === 1);
            setPrimaryIp(priority1Interface ? priority1Interface.address : ipInfo.interfaces[0].address);
          } else {
            setPrimaryIp(null);
          }
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [hostId]);



  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <DuoSpinner size="lg" className="text-blue-500" />
      </div>
    );
  }

  const cardShell = 'bg-white rounded-xl border border-blue-100 overflow-hidden flex flex-col min-h-0';

  const secureBootCard = (
    <div className={cardShell}>
      <div className="px-4 py-2.5 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 shrink-0">
        <h6 className="font-semibold text-gray-800 flex items-center gap-2 text-sm">
          <i className="fa fa-lock text-blue-600" /> Secure Boot
        </h6>
      </div>
      <div className="p-3 flex-1 min-h-0">
        {!secureBootData ? (
          <p className="text-gray-500 text-sm">No Secure Boot information available.</p>
        ) : (
          <div className="space-y-2">
            <div className={`rounded-lg p-3 border-l-4 ${secureBootData.secure_boot === 1 ? 'bg-green-50 border-green-500' : 'bg-gray-50 border-gray-400'}`}>
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs text-gray-600 font-medium">Secure Boot</span>
                  <p className={`font-semibold text-sm ${secureBootData.secure_boot === 1 ? 'text-green-700' : 'text-gray-700'}`}>
                    {secureBootData.secure_boot === 1 ? 'Enabled' : 'Disabled'}
                  </p>
                </div>
                <div className={`w-10 h-10 rounded-full flex items-center justify-center ${secureBootData.secure_boot === 1 ? 'bg-green-100' : 'bg-gray-200'}`}>
                  <i className={`fa ${secureBootData.secure_boot === 1 ? 'fa-shield-alt text-green-600' : 'fa-shield text-gray-500'} text-lg`} />
                </div>
              </div>
            </div>
            <div className={`rounded-lg p-3 border-l-4 ${secureBootData.setup_mode === 1 ? 'bg-blue-50 border-blue-500' : 'bg-gray-50 border-gray-400'}`}>
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs text-gray-600 font-medium">Setup Mode</span>
                  <p className={`font-semibold text-sm ${secureBootData.setup_mode === 1 ? 'text-blue-700' : 'text-gray-700'}`}>
                    {secureBootData.setup_mode === 1 ? 'Enabled' : 'Disabled'}
                  </p>
                </div>
                <div className={`w-10 h-10 rounded-full flex items-center justify-center ${secureBootData.setup_mode === 1 ? 'bg-blue-100' : 'bg-gray-200'}`}>
                  <i className={`fa ${secureBootData.setup_mode === 1 ? 'fa-cog text-blue-600' : 'fa-cog text-gray-500'} text-lg`} />
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );

  const softwareCard = (
    <div className={`${cardShell} overflow-hidden rounded-2xl border border-gray-200 bg-white shadow-sm`}>
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-blue-100 bg-gradient-to-r from-blue-50 to-cyan-50 px-4 py-3">
        <i className="fa fa-desktop text-sm text-blue-600" />
        <h6 className="text-sm font-semibold text-gray-800">Software</h6>
      </div>

      {/* Body */}
      <div className="flex h-full flex-col gap-4 p-4">
        {/* IP + OS */}
        <div className="grid grid-cols-2">
          <div>
            <p className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              IP Address
            </p>
            <p className="font-medium text-gray-900  text-sm">{primaryIp || node.address || 'N/A'}</p>
          </div>

          <div>
            <p className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              Operating System
            </p>

            <p className="font-medium text-gray-900 text-sm leading-tight"> {node.os_name || 'N/A'} {node.os_arch || ''} {node.os_major || ''}.{node.os_minor || ''}{node.os_build && node.os_build !== 'unknown' ? ` (${node.os_build})` : ''} </p>
          </div>
        </div>

        {/* Platform + Agent */}
        <div className="grid grid-cols-3 gap-4">
          <div>
            <p className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              Platform
            </p>

            <p className="font-medium text-gray-900 capitalize text-sm">{node.os_platform || 'N/A'}</p>
          </div>

          <div>
            <p className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              Agent Version
            </p>

            <p className="font-medium text-gray-900 text-sm">{node.osquery_version || 'N/A'}</p>
          </div>
          <div>
            <p className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              Device Group
            </p>

            <p className="font-medium text-gray-900 text-sm">{node.device_group ? node.device_group : 'N/A'}</p>
          </div>
        </div>

        {/* Divider */}
        <div className="border-t  border-gray-200" />

        {/* Dates */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              Enrolled On
            </p>

            <p className="font-medium text-gray-900 text-sm">{(node.enrolled_on)}</p>
         
            
          </div>

          <div>
            <p className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              Last Seen
            </p>

            <p className="font-medium text-gray-900 text-sm">{formatTimestamp(node.last_seen)}</p>
          </div>
        </div>
      </div>
    </div>
  );

  const hardwareCard = (
    <div className={cardShell}>
      <div className="px-4 py-2.5 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 shrink-0">
        <h6 className="font-semibold text-gray-800 flex items-center gap-2 text-sm">
          <i className="fa fa-microchip text-blue-600" /> Hardware
        </h6>
      </div>
      <div className="p-3 space-y-2.5 flex-1 min-h-0">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Vendor</span>
            <p className="font-medium text-gray-900 text-sm">{node.hardware_vendor || 'N/A'}</p>
          </div>
          <div>
            <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Model</span>
            <p className="font-medium text-gray-900 text-sm">{node.hardware_model || 'N/A'}</p>
          </div>
          <div>
            <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">CPU Type</span>
            <p className="font-medium text-gray-900 text-sm leading-tight">{node.hardware_cpu_type || 'N/A'}</p>
          </div>
        </div>
        {/* Divider */}
        <div className="border-t mt-5 border-gray-200" />

        <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-4">
          <div>
            <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-gray-500">
              Physical Memory
            </span>

            <p className="text-sm font-medium text-gray-900">
              {formatPhysicalMemory(node.hardware_physical_memory)}
            </p>
          </div>

          <div>
            <span className="mb-1 block text-xs font-medium uppercase tracking-wide text-gray-500">
              Logical Cores
            </span>

            <p className="text-sm font-medium text-gray-900">
              {node.hardware_cpu_logical_core || 'N/A'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );

  const tpmCard = (
    <div className={cardShell}>
      <div className="px-4 py-2.5 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100 shrink-0">
        <h6 className="font-semibold text-gray-800 flex items-center gap-2 text-sm">
          <i className="fa fa-shield-alt text-blue-600" /> TPM
        </h6>
      </div>
      <div className="p-3 flex-1 min-h-0">
        {!tpmData ? (
          <p className="text-gray-500 text-xs">No TPM information available.</p>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Status</span>
                <p className="font-medium text-gray-900">
                  {tpmData.activated === 1 && tpmData.enabled === 1 ? (
                    <span className="text-green-600 flex items-center gap-1 text-sm">
                      <i className="fa fa-check-circle" /> Active & Enabled
                    </span>
                  ) : (
                    <span className="text-yellow-600 flex items-center gap-1 text-xs">
                      <i className="fa fa-exclamation-circle" /> {tpmData.activated === 1 ? 'Activated' : 'Not Active'}
                    </span>
                  )}
                </p>
              </div>
              <div>
                <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Owned</span>
                <p className={`font-medium text-sm ${tpmData.owned === 1 ? 'text-green-600' : 'text-gray-600'}`}>
                  {tpmData.owned === 1 ? 'Yes' : 'No'}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-2">

                <div>
                  <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Spec Version</span>
                  <p className="font-medium text-gray-900 text-sm">{tpmData.spec_version || 'N/A'}</p>
                </div>
              </div>
              <div>
                <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Manufacturer</span>
                <p className="font-medium text-gray-900 text-sm">{tpmData.manufacturer_name || 'N/A'}</p>
              </div>
            </div>
                   {/* Divider */}
        <div className="border-t mt-6 border-gray-200" />
             <div className="grid grid-cols-2 gap-2">
            <div>
              <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Product Name</span>
              <p className="text-sm font-medium text-gray-900">{tpmData.product_name || 'N/A'}</p>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Mfr ID</span>
                <p className="text-sm font-medium text-gray-900 font-mono">{tpmData.manufacturer_id || 'N/A'}</p>
              </div>
              <div>
                <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Mfr Version</span>
                <p className="text-sm font-medium text-gray-900">{tpmData.manufacturer_version || 'N/A'}</p>
              </div>
            </div>
            </div>

          </>
        )}
      </div>
    </div>
  );

  if (isUbuntu) {
    return (
      <div className="p-4">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-stretch">
          {softwareCard}
          {hardwareCard}
          {secureBootCard}
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 space-y-4">
      {/* Row 1: Latest Update (2/3) + Secure Boot (1/3) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-white rounded-xl border border-blue-100 overflow-hidden">
          <div className="px-4 py-2.5 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100">
            <h6 className="font-semibold text-gray-800 flex items-center gap-2 text-sm">
              <i className="fa fa-history text-blue-600" /> Latest Update
            </h6>
          </div>
          <div className="p-3">
            {!latestUpdate ? (
              <p className="text-gray-500 text-sm">No update information available for this device.</p>
            ) : (
              <>
                <div className="md:col-span-2">
                  <p className="font-medium text-gray-900 text-sm">{latestUpdate.update_title || 'N/A'}</p>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 py-4">
                  <div>
                    <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Category</span>
                    <p className="font-medium text-gray-900">
                      <span className="inline-block px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800">
                        {latestUpdate.category || 'N/A'}
                      </span>
                    </p>
                  </div>
                  <div>
                    <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Install Status</span>
                    <p className="font-medium text-gray-900">
                      {latestUpdate.install_status === 'Succeeded' ? (
                        <span className="text-green-600 flex items-center gap-1 text-sm">
                          <i className="fa fa-check-circle" /> {latestUpdate.install_status}
                        </span>
                      ) : latestUpdate.install_status === 'Failed' ? (
                        <span className="text-red-600 flex items-center gap-1 text-sm">
                          <i className="fa fa-times-circle" /> {latestUpdate.install_status}
                        </span>
                      ) : (
                        <span className="text-gray-600 text-sm">{latestUpdate.install_status || 'N/A'}</span>
                      )}
                    </p>
                  </div>
                  <div>
                    <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Version</span>
                    <p className="font-medium text-gray-900  text-sm">{latestUpdate.version_reference || 'N/A'}</p>
                  </div>
                  <div>
                    <span className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Timestamp</span>
                    <p className="font-medium text-gray-900 text-sm">{latestUpdate.timestamp || 'N/A'}</p>
                  </div>

                  <div className="md:col-span-2">
                    <div className="border-t border-gray-200 my-2 w-[60rem]" />
                    <p className="mb-1 font-medium text-gray-900 text-sm line-clamp-2">{latestUpdate.description_summary || 'N/A'}</p>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>

        {secureBootCard}
      </div>

      {/* Row 2: Software, Hardware, TPM */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {softwareCard}
        {hardwareCard}
        {tpmCard}
      </div>
    </div>
  );
};

export default NodesViewDetails;
