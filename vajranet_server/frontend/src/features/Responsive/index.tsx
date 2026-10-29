import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { motion } from 'motion/react';

import { Meteors } from '@/components/ui/meteors';
import LiveConnectionBadge from '@/components/ui/LiveConnectionBadge';
import { useLiveData } from '../../context/useLiveData';
import { fetchNodesList } from './responsiveNodeUtils';
import ResponsivePortTab from './ResponsivePortTab';
import ResponsiveIpTab from './ResponsiveIpTab';
import ResponsiveUsbTab from './ResponsiveUsbTab';
import ResponsiveBluetoothTab from './ResponsiveBluetoothTab';
import ResponsiveSendMessageTab from './ResponsiveSendMessageTab';

const TABS = [
  { id: 'port', label: 'Port' },
  { id: 'ip', label: 'IP' },
  { id: 'usb', label: 'USB' },
  { id: 'bluetooth', label: 'Bluetooth' },
  { id: 'send-message', label: 'Send Message' },
] as const;

type TabId = (typeof TABS)[number]['id'];
const TAB_IDS: readonly string[] = TABS.map((t) => t.id);

const Responsive = () => {
  const navigate = useNavigate();
  // Active tab lives in the URL (?tab=...) rather than plain component state so
  // that a browser refresh (or a shared link) lands back on the same tab instead
  // of always resetting to the default "port" view.
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get('tab');
  const activeTab: TabId = TAB_IDS.includes(tabParam ?? '') ? (tabParam as TabId) : 'port';

  const setActiveTab = (tab: TabId) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set('tab', tab);
        return next;
      },
      { replace: true },
    );
  };

  const { nodeStatus } = useLiveData();
  const onlineCount = nodeStatus?.agentOnline?.length ?? 0;

  const [totalNodes, setTotalNodes] = useState<number>(0);
  useEffect(() => {
    fetchNodesList().then(res => setTotalNodes(res.nodes.length));
  }, []);

  return (
    <div className="min-h-screen bg-[#f8f9fb] pb-8 md:pb-6">
      <div className="max-w-[100%] mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <header className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 mb-5 text-white" style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}>
          <Meteors number={30} className="!bg-white before:!from-white before:!to-transparent" />
          <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <div className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 backdrop-blur-sm px-3 py-1 mb-2 shadow-sm">
                <span className="text-[11px] font-semibold uppercase tracking-[0.24em] text-blue-50">Super admin</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white">Remote Actions</h1>
              <p className="mt-1 text-sm text-blue-100">
                Bulk port, network, peripheral, and messaging controls.
              </p>
            </div>

            <div className="flex flex-col sm:items-end gap-3 shrink-0">
              <div className="flex items-center gap-3 text-xs font-semibold">
                <div className="flex items-center gap-2 rounded-lg bg-white/10 backdrop-blur-sm border border-white/20 px-3 py-1.5 text-blue-50 shadow-sm transition-all cursor-default">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                  Online: <span className="font-bold text-white">{onlineCount}</span>
                </div>
                <div className="flex items-center gap-2 rounded-lg bg-white/10 backdrop-blur-sm border border-white/20 px-3 py-1.5 text-blue-50 shadow-sm transition-all cursor-default">
                  Total nodes: <span className="font-bold text-white">{totalNodes}</span>
                </div>
                <LiveConnectionBadge label="Live node status offline" />
              </div>
              <button
                type="button"
                onClick={() => navigate('/dashboard')}
                className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/20 bg-white/10 backdrop-blur-sm px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-all hover:bg-white/20"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                </svg>
                Back to Dashboard
              </button>
            </div>
          </div>
        </header>

        <div className="flex flex-col md:flex-row rounded-2xl border border-slate-200 bg-white shadow-[0_14px_34px_rgba(15,23,42,0.06)] overflow-hidden">
          <div
            role="tablist"
            aria-label="Responsive sections"
            className="flex md:flex-col gap-2 overflow-x-auto md:overflow-x-visible md:overflow-y-auto border-b md:border-b-0 md:border-r border-slate-200 bg-slate-50/80 p-2 md:p-4 md:w-56 shrink-0"
          >
            {TABS.map((t) => {
              const selected = activeTab === t.id;
              return (
                <button
                  key={t.id}
                  type="button"
                  role="tab"
                  aria-selected={selected}
                  id={`responsive-tab-${t.id}`}
                  aria-controls={`responsive-panel-${t.id}`}
                  onClick={() => setActiveTab(t.id)}
                  className={`relative shrink-0 text-left rounded-lg px-4 py-2.5 text-sm font-semibold transition-all ${selected

                    ? 'bg-white text-blue-700 shadow-sm ring-1 ring-slate-200/80'
                    : 'text-slate-600 hover:bg-white/70 hover:text-slate-900'
                    }`}
                >
                  {t.label}
                  {selected && (
                    <motion.div
                      layoutId="verticalSidebarIndicator"
                      className="absolute top-0 bottom-0 left-[-1px] w-[2px] bg-blue-700"
                      transition={{ type: "spring", bounce: 0.2, duration: 0.6 }}
                    />
                  )}
                </button>
              );
            })}
          </div>

          <div className="p-5 sm:p-6 flex-1 min-w-0">
            {activeTab === 'port' ? (
              <ResponsivePortTab />
            ) : activeTab === 'ip' ? (
              <ResponsiveIpTab />
            ) : activeTab === 'usb' ? (
              <ResponsiveUsbTab />
            ) : activeTab === 'bluetooth' ? (
              <ResponsiveBluetoothTab />
            ) : (
              <ResponsiveSendMessageTab />
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Responsive;
