import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import MobileNavbar from './MobileNavbar';
import { AlertsPollingProvider } from '../../context/AlertsPollingContext';
import { ThemeProvider as ThemProvider } from '../../context/ThemeContext';
import { Suspense } from 'react';
import { LoadingScreen } from '@/components/ui/loading';
import ErrorBoundary from '../ErrorBoundary';
import { FloatingChatProvider } from '../../features/AI/FloatingChatContext';
import FloatingChatWidget from '../../features/AI/FloatingChatWidget';

const DashboardContentLoader = ({ isAI }: { isAI: boolean }) => (
  <LoadingScreen size="full" fullScreen={false} dark={isAI} className="min-h-screen" />
);

const DashboardLayout = () => {
  const location = useLocation();
  const isAI = location.pathname === '/ai';

  return (
    <ThemProvider>
    <AlertsPollingProvider>
    <FloatingChatProvider>
      <div className={isAI ? 'h-screen bg-[#08080f] overflow-hidden' : 'min-h-screen bg-[#f8f9fb]'}>
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-white focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-gray-900 focus:shadow-lg"
        >
          Skip to main content
        </a>
        <Sidebar />
        <main
          id="main-content"
          tabIndex={-1}
          className={`dashboard-content md:ml-59 transition-all duration-300 overflow-x-hidden pb-16 md:pb-0 ${isAI ? 'h-screen overflow-hidden' : 'min-h-screen'}`}
        >
          <Suspense fallback={<DashboardContentLoader isAI={isAI} />}>
            <ErrorBoundary resetKey={`${location.pathname}${location.search}`}>
              <Outlet />
            </ErrorBoundary>
          </Suspense>
        </main>
        <MobileNavbar />
        {/* The dedicated /ai page IS this same assistant, full-page — a
            floating copy on top of it would be redundant. Every other
            authenticated page gets it. */}
        {!isAI && <FloatingChatWidget />}
      </div>
    </FloatingChatProvider>
    </AlertsPollingProvider>
    </ThemProvider>
  );
}
  

export default DashboardLayout;
