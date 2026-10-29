import React, { useState, useCallback, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  MoreHorizontal,
  ShieldCheck,
  ShieldAlert,
  ClipboardList,
  FileSearch,
  Network,
  Globe,
  Search,
  Sparkles,
  Settings as SettingsIcon,
  HelpCircle,
  History,
  Users,
  LogOut,
  Download,
} from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { getStoredUser, clearAuthData, markManualLogout } from '../../services/auth';
import { logout, logoutAllDevices } from '../../api/api';
import { useAlertsPolling } from '../../context/useAlertsPolling';
import { useConfirm } from '../../context/useConfirm';
import { useToast } from '../../context/useToast';

type UserRole = 'Super Administrator' | 'Group Admin' | 'Viewer';

const normalizeRole = (role: unknown): UserRole => {
  if (role === 'Super Administrator' || role === 'Group Admin' || role === 'Viewer') {
    return role;
  }
  return 'Viewer';
};

const MobileNavbar = () => {
  const [moreOpen, setMoreOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const isAI = location.pathname === '/ai';
  const { sidebarNewCount } = useAlertsPolling();

  const user = getStoredUser();
  const userRole = normalizeRole(user?.role);
  const isSuperAdmin = userRole === 'Super Administrator';
  const canManagePolicies = isSuperAdmin || userRole === 'Group Admin';
  const canAccessDomainReputation = isSuperAdmin || userRole === 'Group Admin';
  // Mirrors Sidebar.tsx — backend/src/routes/api/network.ts allows Group Admin
  // (requireAdmin), though nothing under /network is group-scoped.
  const canAccessNetworkSecurity = isSuperAdmin || userRole === 'Group Admin';
  const isOnPrem = import.meta.env.VITE_DEPLOYMENT_MODE !== 'cloud';
  const confirm = useConfirm();
  const { showToast } = useToast();

  const goTo = (path: string) => {
    setMoreOpen(false);
    navigate(path);
  };

  const handleLogout = useCallback(async () => {
    setMoreOpen(false);
    const confirmed = await confirm({
      title: 'Log out?',
      description: 'You will need to sign in again to access this device.',
      confirmLabel: 'Log out',
      variant: 'danger',
    });
    if (!confirmed) return;
    try {
      markManualLogout();
      await logout();
    } catch {
      // Still treat this as an intentional logout; fall through to clearing local state.
    }
    clearAuthData();
    navigate('/');
  }, [confirm, navigate]);

  const handleDownloadAgent = useCallback(() => {
    setMoreOpen(false);
    const userAgent = window.navigator.userAgent.toLowerCase();
    const downloadUrl = userAgent.includes('win')
      ? import.meta.env.VITE_WINDOWS_AGENT_INSTALLER_URL
      : userAgent.includes('linux') && !userAgent.includes('android')
        ? import.meta.env.VITE_LINUX_AGENT_INSTALLER_URL
        : null;
    if (!downloadUrl) {
      showToast('Agent download is not available for this device. Please use a Windows or Linux desktop.', 'error');
      return;
    }
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = '';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }, [showToast]);

  const handleLogoutAllDevices = useCallback(async () => {
    setMoreOpen(false);
    const confirmed = await confirm({
      title: 'Log out of all sessions?',
      description: 'This will end every active session for your account on all devices, not just this one.',
      confirmLabel: 'Logout all sessions',
      variant: 'danger',
    });
    if (!confirmed) return;
    try {
      markManualLogout();
      await logoutAllDevices();
    } catch {
      // Still treat this as an intentional logout; fall through to clearing local state.
    }
    clearAuthData();
    navigate('/');
  }, [confirm, navigate]);

  // This component consumes useAlertsPolling(), so it re-renders on every poll
  // tick. Memoising keeps the row array and its Lucide icon elements
  // referentially stable across ticks, which matters while the More sheet is
  // open: fresh icon identities would make every row's <svg> subtree reconcile.
  // The handler deps close over react-router's `navigate`, which BrowserRouter
  // rebuilds on navigation, so the memo holds across ticks but not across route
  // changes. Sidebar.tsx memoises its menuItems for the same reason.
  const moreItems: Array<{ label: string; path?: string; icon: React.ReactNode; action?: () => void; danger?: boolean }> = useMemo(() => [
    { label: 'Compliance', path: '/compliance', icon: <ShieldCheck className="size-5" /> },
    ...(canManagePolicies
      ? [
          { label: 'Policy Management', path: '/policy-management', icon: <ClipboardList className="size-5" /> },
          { label: 'File Integrity', path: '/file-integrity', icon: <FileSearch className="size-5" /> },
        ]
      : []),
    ...(canAccessNetworkSecurity && isOnPrem
      ? [{ label: 'Network Security', path: '/network', icon: <Network className="size-5" /> }]
      : []),
    ...(isSuperAdmin
      ? [{ label: 'Patch Management', path: '/vulnerability-management', icon: <ShieldAlert className="size-5" /> }]
      : []),
    ...(canAccessDomainReputation
      ? [{ label: 'Domain Reputation', path: '/domain-reputation', icon: <Globe className="size-5" /> }]
      : []),
    { label: 'Threat Hunting', path: '/threat-hunting', icon: <Search className="size-5" /> },
    { label: 'AI Assistant', path: '/ai', icon: <Sparkles className="size-5" /> },
    ...(isSuperAdmin
      ? [{ label: 'Audit Trail', path: '/audit-trail', icon: <History className="size-5" /> }]
      : []),
    ...(isSuperAdmin
      ? [{ label: 'Management', path: '/management', icon: <Users className="size-5" /> }]
      : []),
    { label: 'Download Agent', action: handleDownloadAgent, icon: <Download className="size-5" /> },
    { label: 'Settings', path: '/settings', icon: <SettingsIcon className="size-5" /> },
    { label: 'Help', path: '/help', icon: <HelpCircle className="size-5" /> },
    { label: 'Logout', action: handleLogout, icon: <LogOut className="size-5" />, danger: true },
    { label: 'Logout all sessions', action: handleLogoutAllDevices, icon: <LogOut className="size-5" />, danger: true },
  ], [
    canManagePolicies,
    canAccessNetworkSecurity,
    isOnPrem,
    isSuperAdmin,
    canAccessDomainReputation,
    handleDownloadAgent,
    handleLogout,
    handleLogoutAllDevices,
  ]);

  return (
    <>
      <nav aria-label="Primary" className={`fixed bottom-0 left-0 right-0 z-50 flex justify-around items-center border-t shadow-[0_-4px_10px_-2px_rgba(15,23,42,0.08)] md:hidden h-16 ${isAI ? 'bg-[#0d0d1a] border-white/10' : 'bg-white border-slate-200'}`}>
        <NavLinkItem to="/dashboard" label="Dashboard" isAI={isAI}>
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" /></svg>
        </NavLinkItem>
        <NavLinkItem to="/my-devices" label="Devices" isAI={isAI}>
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
        </NavLinkItem>
        <NavLinkItem to="/alerts" label="Alerts" badge={sidebarNewCount} isAI={isAI}>
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0018 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" /></svg>
        </NavLinkItem>
        <NavLinkItem to="/update-profile" label="User" isAI={isAI}>
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A9 9 0 1112 21a9 9 0 01-6.879-3.196z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
        </NavLinkItem>
        <button
          className={`flex flex-col items-center justify-center px-2 pt-1 text-xs font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-lg ${isAI ? 'text-white/60' : 'text-slate-500'}`}
          onClick={() => setMoreOpen(true)}
          aria-label="More"
          aria-haspopup="dialog"
          aria-expanded={moreOpen}
        >
          <MoreHorizontal className="w-6 h-6" />
          <span className="mt-0.5">More</span>
        </button>
      </nav>

      <Dialog open={moreOpen} onOpenChange={setMoreOpen}>
        <DialogContent className={`max-w-sm md:hidden ${isAI ? 'bg-[#0d0d1a] text-white' : ''}`}>
          <DialogHeader>
            <DialogTitle className={isAI ? 'text-white' : ''}>More</DialogTitle>
          </DialogHeader>
          <div className="grid grid-cols-3 gap-2 px-4 pb-6 pt-2">
            {moreItems.map((item) => {
              const isActive = !!item.path && (location.pathname === item.path || location.pathname.startsWith(item.path + '/'));
              return (
                <button
                  key={item.label}
                  onClick={item.action ?? (() => goTo(item.path!))}
                  aria-current={isActive ? 'page' : undefined}
                  className={`flex flex-col items-center gap-1.5 rounded-xl px-2 py-3 text-xs font-medium transition-colors ${
                    item.danger
                      ? isAI ? 'text-red-400 hover:bg-red-500/10' : 'text-red-600 hover:bg-red-50'
                      : isActive
                        ? isAI ? 'bg-white/10 text-white' : 'bg-blue-50 text-blue-600'
                        : isAI ? 'text-white/70 hover:bg-white/8' : 'text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  {item.icon}
                  <span className="text-center leading-tight">{item.label}</span>
                </button>
              );
            })}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
};

const NavLinkItem = ({ to, label, badge, isAI, children }: { to: string, label: string, badge?: number, isAI?: boolean, children: React.ReactNode }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const isActive = location.pathname === to || (to !== '/dashboard' && location.pathname.startsWith(to + '/'));
  const inactiveColor = isAI ? 'text-white/50' : 'text-slate-500';
  const activeColor = isAI ? 'text-blue-400' : 'text-blue-600';
  return (
    <button
      className={`relative flex flex-col items-center justify-center px-2 pt-1 text-xs font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-lg ${isActive ? activeColor : inactiveColor}`}
      onClick={() => navigate(to)}
      aria-label={label}
      aria-current={isActive ? 'page' : undefined}
    >
      {children}
      {!!badge && (
        <span className="absolute top-0 right-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white">
          {badge > 99 ? '99+' : badge}
        </span>
      )}
      <span className="mt-0.5">{label}</span>
    </button>
  );
};

export default MobileNavbar;
