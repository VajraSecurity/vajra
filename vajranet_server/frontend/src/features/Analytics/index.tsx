import { useEffect, useRef, useState } from 'react';
import { motion } from 'motion/react';
import { Meteors } from '../../components/ui/meteors';
import { useTheme } from '../../context/useTheme';

const DASHBOARDS = [
  { id: 'cve-analysis', name: 'CVE Analysis' },
  ...(import.meta.env.VITE_DEPLOYMENT_MODE === 'on_prem' ? [{ id: 'network-analysis', name: 'Network Analysis' }] : []),
  { id: 'custom-template', name: 'Custom Template' },
];

// Only ever set `active` to a dashboard id we actually provisioned — an
// unvalidated `?dashboard=` value would let it double as a bypass for
// whatever dashboard-level access control exists (or gets added later),
// not just a UI nicety.
function getInitialDashboard(): string {
  const requested = new URLSearchParams(window.location.search).get('dashboard');
  return DASHBOARDS.some((d) => d.id === requested) ? (requested as string) : DASHBOARDS[0].id;
}

const Analytics = () => {
  const { theme } = useTheme();
  const [active, setActive] = useState(getInitialDashboard);
  const [status, setStatus] = useState<'loading' | 'loaded' | 'error'>('loading');
  // Bumped by Retry so the effect below (and the iframe's key) re-run even
  // when `active` hasn't changed — otherwise a retry on the same dashboard
  // never re-arms the timeout or forces the iframe to re-navigate.
  const [attempt, setAttempt] = useState(0);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  useEffect(() => {
    setStatus('loading');
    // onLoad fires even for an nginx auth-rejection or Grafana error page (the
    // browser still loaded *a* document), so this timeout only catches the
    // "nothing responded at all" case — not a true error detector, but better
    // than an indefinite blank frame with zero feedback.
    const timeout = setTimeout(() => setStatus((s) => (s === 'loading' ? 'error' : s)), 15000);
    return () => clearTimeout(timeout);
  }, [active, attempt]);

  const dashboardUrl = `/grafana/d/${active}?orgId=1&theme=${theme}&kiosk`;
  const openInNewTabUrl = `/grafana/d/${active}?orgId=1&theme=${theme}`;

  // WAI-ARIA APG tabs pattern (automatic activation): Left/Right move focus
  // between tabs and switch the active dashboard; a single roving tabIndex
  // stop is kept in sync via the tabIndex prop below.
  const handleTabKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
    event.preventDefault();
    const nextIndex =
      event.key === 'ArrowRight' ? (index + 1) % DASHBOARDS.length : (index - 1 + DASHBOARDS.length) % DASHBOARDS.length;
    setActive(DASHBOARDS[nextIndex].id);
    tabRefs.current[nextIndex]?.focus();
  };

  return (
    <div className="h-[calc(100vh)] flex flex-col overflow-hidden bg-[#f8f9fb] pt-16 md:pt-0">
      <div className="px-2 sm:px-4 lg:px-8 pt-3 sm:pt-4 lg:pt-5 shrink-0">
        {/* Page Header — same gradient + Meteors treatment used across the dashboard */}
        <motion.header
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 mb-5 text-white"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
        >
          <Meteors number={25} className="!bg-white before:!from-white before:!to-transparent" />
          <div className="relative z-10 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="min-w-0 shrink-0">
              <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
                <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2H7a2 2 0 01-2-2z" />
                </svg>
                Analytics
              </h1>
              <p className="mt-1 text-sm text-blue-100">Explore CVE trends and custom reporting dashboards.</p>
            </div>

            <div className="flex flex-wrap items-center gap-2 lg:justify-end">
              {/* Tab switcher — same pill-nav treatment used on Compliance */}
              <div
                role="tablist"
                aria-label="Analytics dashboards"
                className="relative inline-flex items-center gap-0.5 rounded-full border border-white/20 bg-white/10 backdrop-blur-sm p-1 overflow-x-auto scrollbar-hide max-w-full"
              >
                {DASHBOARDS.map((d, index) => {
                  const isActive = active === d.id;
                  return (
                    <button
                      key={d.id}
                      ref={(el) => {
                        tabRefs.current[index] = el;
                      }}
                      role="tab"
                      aria-selected={isActive}
                      tabIndex={isActive ? 0 : -1}
                      onClick={() => setActive(d.id)}
                      onKeyDown={(e) => handleTabKeyDown(e, index)}
                      className={`relative z-10 inline-flex items-center rounded-full font-semibold transition-colors duration-150 px-3 py-1.5 text-sm whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300 ${
                        isActive ? 'text-[rgb(4,34,119)]' : 'text-blue-100 hover:text-white'
                      }`}
                      style={{ transformStyle: 'preserve-3d' }}
                    >
                      {isActive && (
                        <motion.div
                          layoutId="analyticsTabBackground"
                          transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }}
                          className="absolute inset-0 bg-white rounded-full shadow-sm"
                          style={{ zIndex: -1 }}
                        />
                      )}
                      <span>{d.name}</span>
                    </button>
                  );
                })}
              </div>

              <a
                href={openInNewTabUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex h-10 items-center gap-1.5 rounded-xl border border-white/20 bg-white/10 backdrop-blur-sm px-4 text-sm font-semibold text-white shadow-sm transition-all hover:bg-white/20"
              >
                Open in New Tab
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
              </a>
            </div>
          </div>
        </motion.header>
      </div>
      <div className="relative flex-1">
        {status === 'loading' && (
          <div role="status" aria-live="polite" className="absolute inset-0 flex items-center justify-center bg-slate-50">
            <span className="sr-only">Loading dashboard…</span>
            <div className="h-8 w-8 rounded-full border-2 border-blue-600 border-t-transparent animate-spin" aria-hidden="true" />
          </div>
        )}
        {status === 'error' && (
          <div role="alert" className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-slate-50 text-gray-600">
            <p>Dashboard unavailable — contact your administrator.</p>
            <button
              onClick={() => setAttempt((a) => a + 1)}
              className="text-sm font-medium text-blue-600 hover:text-blue-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded px-2 py-1"
            >
              Retry
            </button>
          </div>
        )}
        <iframe
          key={`${active}-${attempt}`}
          src={dashboardUrl}
          onLoad={() => setStatus('loaded')}
          className={`h-full w-full border-0 bg-slate-50 ${status === 'loaded' ? '' : 'invisible'}`}
          title="Vajra Analytics Dashboard"
          sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
        />
      </div>
    </div>
  );
};

export default Analytics;
