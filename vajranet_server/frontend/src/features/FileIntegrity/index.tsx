import { useState } from 'react';
import { Bell, LayoutDashboard, GitCompareArrows, ListChecks, Database, KeyRound } from 'lucide-react';
import { FileIntegrityIcon } from '@/components/icons/navIcons';
import { SegmentedControl } from './ui';
import OverviewTab from './OverviewTab';
import DriftTab, { type DriftPreset } from './DriftTab';
import PoliciesTab from './PoliciesTab';
import BaselineTab from './BaselineTab';
import AlertsTab, { type AlertsPreset } from './AlertsTab';
import RegistryTab from './RegistryTab';
import { useFimOpenAlerts } from './useFimOpenAlerts';

type Tab = 'overview' | 'alerts' | 'drift' | 'policies' | 'baseline' | 'registry';

const TABS: { value: Tab; label: string; icon: React.ReactNode }[] = [
  { value: 'overview', label: 'Overview', icon: <LayoutDashboard className="h-3.5 w-3.5" /> },
  { value: 'alerts', label: 'Alerts', icon: <Bell className="h-3.5 w-3.5" /> },
  { value: 'drift', label: 'Drift', icon: <GitCompareArrows className="h-3.5 w-3.5" /> },
  { value: 'policies', label: 'Policies', icon: <ListChecks className="h-3.5 w-3.5" /> },
  { value: 'baseline', label: 'Baseline', icon: <Database className="h-3.5 w-3.5" /> },
  { value: 'registry', label: 'Registry', icon: <KeyRound className="h-3.5 w-3.5" /> },
];

/** File Integrity Monitoring hub: thin shell + one component per tab (same shape as RuleEngine/index.tsx). */
export default function FileIntegrityHub() {
  const [tab, setTab] = useState<Tab>('overview');
  const [preset, setPreset] = useState<DriftPreset | undefined>();
  const [driftKey, setDriftKey] = useState(0);
  const [alertPreset, setAlertPreset] = useState<AlertsPreset | undefined>();
  const [alertsKey, setAlertsKey] = useState(0);
  const { count: openAlerts, refresh: refreshOpenAlerts } = useFimOpenAlerts();

  return (
    <div className="h-screen overflow-hidden bg-[#f8f9fb] dark:bg-slate-950 flex flex-col">
      <div className="max-w-full mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5 flex-1 flex flex-col min-h-0 w-full">
        <header className="relative overflow-hidden rounded-2xl shadow-lg shadow-blue-950/20 ring-1 ring-white/10 p-5 sm:p-6 mb-5 text-white shrink-0"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}>
          <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
            <FileIntegrityIcon className="w-6 h-6 mr-2" />
            File Integrity
          </h1>
          <p className="mt-1 text-sm text-blue-100/90 max-w-2xl">
            Initialize a baseline of what your critical files look like, then get told when they change. Baselines only change when you re-initialize or approve a drift.
          </p>
        </header>

        <div className="mb-4 shrink-0 overflow-x-auto">
          <SegmentedControl value={tab} onChange={setTab} size="sm" options={TABS.map((t) => ({ value: t.value, label: <span className="flex items-center gap-1.5">{t.icon}{t.label}{t.value === 'alerts' && openAlerts > 0 && <span className={`ml-1 min-w-5 rounded-full px-1.5 text-[10px] font-bold ${tab === 'alerts' ? 'bg-white text-indigo-700' : 'bg-red-500 text-white'}`}>{openAlerts}</span>}</span> }))} />
        </div>

        <div className="flex-1 min-h-0">
          {tab === 'overview' && <OverviewTab onOpenAlerts={(f) => { setAlertPreset({ ...f, status: 'open' }); setAlertsKey((k) => k + 1); setTab('alerts'); }} onOpenDrift={(f) => { setPreset({ ...f, status: 'open' }); setDriftKey((k) => k + 1); setTab('drift'); }} />}
          {tab === 'alerts' && <AlertsTab key={alertsKey} preset={alertPreset} onChanged={refreshOpenAlerts} />}
          {tab === 'drift' && <DriftTab key={driftKey} preset={preset} />}
          {tab === 'policies' && <PoliciesTab />}
          {tab === 'baseline' && <BaselineTab />}
          {tab === 'registry' && <RegistryTab />}
        </div>
      </div>
    </div>
  );
}
