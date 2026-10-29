import { useSearchParams } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import { Meteors } from '@/components/ui/meteors';
import LiveConnectionBadge from '@/components/ui/LiveConnectionBadge';
import { useLiveData } from '../../context/useLiveData';
import { PolicyManagementIcon } from '@/components/icons/navIcons';

import ResponsivePortTab from '../Responsive/ResponsivePortTab';
import ResponsiveIpTab from '../Responsive/ResponsiveIpTab';
import ResponsiveUsbTab from '../Responsive/ResponsiveUsbTab';
import ResponsiveBluetoothTab from '../Responsive/ResponsiveBluetoothTab';
import ResponsiveSendMessageTab from '../Responsive/ResponsiveSendMessageTab';
import PolicyLibrary from './sections/PolicyLibrary';

type SectionId =
  | 'port'
  | 'ip'
  | 'usb'
  | 'bluetooth'
  | 'send-message'
  | 'policy-library';

const SECTION_IDS: readonly string[] = [
  'port',
  'ip',
  'usb',
  'bluetooth',
  'send-message',
  'policy-library',
];

const ENFORCEMENT_ITEMS: { id: SectionId; label: string; icon: React.ReactNode }[] = [
  {
    id: 'port',
    label: 'Port Control',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M12 5l7 7-7 7" />
      </svg>
    ),
  },
  {
    id: 'ip',
    label: 'IP Control',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
      </svg>
    ),
  },
  {
    id: 'usb',
    label: 'USB Control',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
      </svg>
    ),
  },
  {
    id: 'bluetooth',
    label: 'Bluetooth Control',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
  },
  {
    id: 'send-message',
    label: 'Send Message',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
      </svg>
    ),
  },
];

const POLICY_ITEMS: { id: SectionId; label: string; icon: React.ReactNode }[] = [
  {
    id: 'policy-library',
    label: 'Policy Library',
    icon: (
      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 6H7a2 2 0 01-2-2V4a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
    ),
  },
];

const PolicyManagement = () => {
  // Active section lives in the URL (?section=...) rather than plain component state so
  // that a browser refresh (or a shared link) lands back on the same section instead
  // of always resetting to the default "port" view.
  const [searchParams, setSearchParams] = useSearchParams();
  const sectionParam = searchParams.get('section');
  const activeSection: SectionId = SECTION_IDS.includes(sectionParam ?? '')
    ? (sectionParam as SectionId)
    : 'port';

  const setActiveSection = (section: SectionId) => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set('section', section);
        return next;
      },
      { replace: true },
    );
  };

  const { nodeStatus } = useLiveData();
  const onlineCount = nodeStatus?.agentOnline?.length ?? 0;
  const totalNodes = nodeStatus?.total ?? 0;

  const renderContent = () => {
    switch (activeSection) {
      case 'port':        return <ResponsivePortTab />;
      case 'ip':          return <ResponsiveIpTab />;
      case 'usb':         return <ResponsiveUsbTab />;
      case 'bluetooth':   return <ResponsiveBluetoothTab />;
      case 'send-message':return <ResponsiveSendMessageTab />;
      case 'policy-library':   return <PolicyLibrary />;
    }
  };

  return (
    <div className="min-h-screen bg-[#f8f9fb] pb-8">
      <div className="max-w-full mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5">

        {/* Header — same gradient + Meteors as Remote Actions */}
        <header
          className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 mb-5 text-white"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
        >
          <Meteors number={30} className="!bg-white before:!from-white before:!to-transparent" />
          <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
                <PolicyManagementIcon className="w-6 h-6 mr-2" />
                Policy Management
              </h1>
              <p className="mt-1 text-sm text-blue-100">
                {activeSection in { port: 1, ip: 1, usb: 1, bluetooth: 1, 'send-message': 1 }
                  ? 'Bulk port, network, peripheral, and messaging controls.'
                  : 'Create and manage enforcement policies and uninstall tokens.'}
              </p>
            </div>

            <div className="flex flex-col sm:items-end gap-3 shrink-0">
              <div className="flex items-center gap-3 text-xs font-semibold">
                <div className="flex items-center gap-2 rounded-lg bg-white/10 backdrop-blur-sm border border-white/20 px-3 py-1.5 text-blue-50 shadow-sm transition-all cursor-default">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
                  </span>
                  Online: <span className="font-bold text-white">{onlineCount}</span>
                </div>
                <div className="flex items-center gap-2 rounded-lg bg-white/10 backdrop-blur-sm border border-white/20 px-3 py-1.5 text-blue-50 shadow-sm transition-all cursor-default">
                  Total nodes: <span className="font-bold text-white">{totalNodes}</span>
                </div>
                <LiveConnectionBadge label="Live node status offline" />
              </div>

            </div>
          </div>
        </header>

        {/* Two-panel body */}
        <div className="flex flex-col md:flex-row rounded-2xl border border-slate-200 bg-white shadow-[0_14px_34px_rgba(15,23,42,0.06)] overflow-hidden">

          {/* Left nav rail */}
          <nav
            aria-label="Policy management sections"
            className="flex md:flex-col gap-1 overflow-x-auto md:overflow-x-visible md:overflow-y-auto border-b md:border-b-0 md:border-r border-slate-200 bg-slate-50/80 p-2 md:p-4 md:w-56 shrink-0"
          >
            {/* Enforcement group */}
            <div className="hidden md:block mb-1">
              <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-400 px-2 mb-1.5">
                Enforcement
              </p>
              {ENFORCEMENT_ITEMS.map((item) => (
                <NavButton
                  key={item.id}
                  item={item}
                  active={activeSection === item.id}
                  onClick={() => setActiveSection(item.id)}
                />
              ))}
            </div>

            {/* Mobile: enforcement items flat */}
            <div className="flex md:hidden gap-1">
              {ENFORCEMENT_ITEMS.map((item) => (
                <NavButton
                  key={item.id}
                  item={item}
                  active={activeSection === item.id}
                  onClick={() => setActiveSection(item.id)}
                  compact
                />
              ))}
            </div>

            {/* Policies group */}
            <div className="hidden md:block mt-3">
              <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-400 px-2 mb-1.5">
                Policies
              </p>
              {POLICY_ITEMS.map((item) => (
                <NavButton
                  key={item.id}
                  item={item}
                  active={activeSection === item.id}
                  onClick={() => setActiveSection(item.id)}
                />
              ))}
            </div>

            {/* Mobile: divider between enforcement and policies */}
            <div className="md:hidden h-10 w-px bg-slate-200 mx-1 shrink-0 self-center" />

            {/* Mobile: policy items flat */}
            <div className="flex md:hidden gap-1">
              {POLICY_ITEMS.map((item) => (
                <NavButton
                  key={item.id}
                  item={item}
                  active={activeSection === item.id}
                  onClick={() => setActiveSection(item.id)}
                  compact
                />
              ))}
            </div>
          </nav>

          {/* Right content panel */}
          <div className="p-5 sm:p-6 flex-1 min-w-0">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeSection}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.15 }}
              >
                {renderContent()}
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
};

interface NavButtonProps {
  item: { id: SectionId; label: string; icon: React.ReactNode };
  active: boolean;
  onClick: () => void;
  compact?: boolean;
}

const NavButton = ({ item, active, onClick, compact }: NavButtonProps) => (
  <button
    type="button"
    role="tab"
    aria-selected={active}
    onClick={onClick}
    title={item.label}
    className={`shrink-0 flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm font-semibold transition-all w-full text-left ${
      compact ? 'justify-center px-2.5' : ''
    } ${
      active
        ? 'bg-white text-blue-700 shadow-sm ring-1 ring-slate-200/80'
        : 'text-slate-600 hover:bg-white/70 hover:text-slate-900'
    }`}
  >
    <span className={active ? 'text-blue-600' : 'text-slate-400'}>{item.icon}</span>
    {!compact && <span>{item.label}</span>}
  </button>
);

export default PolicyManagement;
