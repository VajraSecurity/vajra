import { useSearchParams } from 'react-router-dom';
import { motion } from 'motion/react';
import { Radar, Bug, CalendarClock } from 'lucide-react';
import { Meteors } from '@/components/ui/meteors';
import { NetworkSecurityIcon } from '@/components/icons/navIcons';
import NetworkScanning from './NetworkScanning';
import VulnerabilityScanner from '../VulnerabilityScanner/index';
import ScanScheduler from './ScanScheduler';
import { NetworkScanProvider } from './context/NetworkScanContext';
import { SegmentedControlOnDark } from './ui';

// Note: Assets does NOT live here. An earlier pass added it as a fourth tab
// in this outer bar; the user rejected that placement after seeing it built
// and asked for it inside the Vulnerability Scanner tab's OpenVAS sub-view
// instead, between that view's own "Scans" and "Settings" tabs (asset
// identity resolution is OpenVAS-only — see features/VulnerabilityScanner/
// index.tsx's OpenVASTab/OPENVAS_TABS and features/Assets/index.tsx).
const TABS = [
  { value: 'network', title: 'Network Scanning', icon: <Radar className="h-3.5 w-3.5" /> },
  { value: 'vuln', title: 'Vulnerability Scanner', icon: <Bug className="h-3.5 w-3.5" /> },
  { value: 'scheduler', title: 'Scan Scheduler', icon: <CalendarClock className="h-3.5 w-3.5" /> },
] as const;

type TabValue = (typeof TABS)[number]['value'];
const TAB_VALUES: readonly string[] = TABS.map((tab) => tab.value);

const NetworkHub = () => {
  // Active sub-tab lives in the URL (?tab=...) rather than plain component state so
  // that a browser refresh (or a shared link) lands back on the same sub-tab instead
  // of always resetting to the default "network" view.
  const [searchParams, setSearchParams] = useSearchParams();
  const tabParam = searchParams.get('tab');
  const activeTab: TabValue = TAB_VALUES.includes(tabParam ?? '') ? (tabParam as TabValue) : 'network';

  const setActiveTab = (tab: TabValue) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set('tab', tab);
        return next;
      },
      { replace: true },
    );
  };

  return (
    <NetworkScanProvider>
      <div className="min-h-screen bg-[#f8f9fb] pb-8">
        <div className="max-w-full mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5">

        {/* Hero Header */}
        <motion.header
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-2xl shadow-lg shadow-blue-950/20 ring-1 ring-white/10 p-5 sm:p-6 mb-5 text-white"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
        >
          <Meteors number={30} className="!bg-white before:!from-white before:!to-transparent" />
        
          <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
                <NetworkSecurityIcon className="w-6 h-6 mr-2" />
                Network Security
              </h1>
              <p className="mt-1 text-sm text-blue-100/90 max-w-xl">
                Network discovery, port scanning, and vulnerability assessment
              </p>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <SegmentedControlOnDark
                value={activeTab}
                onChange={setActiveTab}
                layoutId="activeNetworkTab"
                options={TABS.map(tab => ({ value: tab.value, label: tab.title, icon: tab.icon }))}
              />
            </div>
          </div>
        </motion.header>

        {/* Tab Content */}
        {activeTab === 'network' && <NetworkScanning />}
        {activeTab === 'vuln' && <VulnerabilityScanner />}
        {activeTab === 'scheduler' && <ScanScheduler />}
      </div>
    </div>
    </NetworkScanProvider>
  );
};

export default NetworkHub;
