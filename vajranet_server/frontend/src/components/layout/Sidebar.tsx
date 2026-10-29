import { useEffect, useState, useRef, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { motion, AnimatePresence, useReducedMotion } from 'motion/react';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft';
import ChevronRightIcon from '@mui/icons-material/ChevronRight';
import vajraLogoCollapsed from '../../assets/vajra/vajralogo.svg';
import { getStoredUser, clearAuthData, markManualLogout, sanitizeUserForCache } from '../../services/auth';
import type { StoredUser } from '../../services/auth';
import { getProfile, logout, logoutAllDevices } from '../../api/api';
import { useAlertsPolling } from '../../context/useAlertsPolling';
import { useFimOpenAlerts } from '../../features/FileIntegrity/useFimOpenAlerts';
import ShimmerText from '../../components/kokonutui/shimmer-text';
import { NoiseBackground } from '../../components/ui/noise-background';
import { avatars } from '../../components/kokonutui/avatar-picker';
import { CUSTOM_AVATAR_ID, useAvatar } from '../../lib/avatarStorage';
import { useToast } from '../../context/useToast';
import { useConfirm } from '../../context/useConfirm';
import {
    DashboardIcon,
    DevicesIcon,
    AlertsIcon,
    ComplianceIcon,
    PolicyManagementIcon,
    FileIntegrityIcon,
    NetworkSecurityIcon,
    PatchManagementIcon,
    DomainReputationIcon,
    ThreatHuntingIcon,
    AiAssistantIcon,
    HelpIcon,
    RuleEngineIcon,
} from '../icons/navIcons';
import { RULE_ENGINE_ENABLED } from '../../lib/featureFlags';

type UserRole = 'Super Administrator' | 'Group Admin' | 'Viewer';

const normalizeRole = (role: unknown): UserRole => {
    if (role === 'Super Administrator' || role === 'Group Admin' || role === 'Viewer') {
        return role;
    }
    return 'Viewer';
};

// The render body calls OSName() once per download-menu branch, and each call
// lowercases the full UA string and runs several substring scans. The UA cannot
// change for the life of the document, so resolve it once and cache it.
let cachedOSName: string | null = null;
const OSName = (): string => {
    if (cachedOSName !== null) return cachedOSName;
    const userAgent = window.navigator.userAgent.toLowerCase();
    if (userAgent.includes('win')) {
        cachedOSName = 'Windows';
    }
    else if (userAgent.includes('mac')) {
        cachedOSName = 'MacOS';
    }
    else if (userAgent.includes('linux')) {
        cachedOSName = userAgent.includes('cros') ? 'Chrome OS' : 'Linux';
    }
    else if (userAgent.includes('android')) {
        cachedOSName = 'Android';
    }
    else if (userAgent.includes('iphone') || userAgent.includes('ipad') || userAgent.includes('ipod')) {
        cachedOSName = 'iOS';
    }
    else {
        cachedOSName = 'Unknown';
    }
    return cachedOSName;
};

// Module scope, not an inline array literal in the JSX: otherwise
// NoiseBackground's gradientColors prop gets a new identity on every Sidebar
// render (i.e. every alerts-polling tick), defeating memoisation on its side.
const DOWNLOAD_BUTTON_GRADIENT = ['rgb(147,197,253)', 'rgb(191,219,254)', 'rgb(96,165,250)'];

const Sidebar = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const prefersReducedMotion = useReducedMotion();
    const { sidebarNewCount } = useAlertsPolling();
    const [isCollapsed, setIsCollapsed] = useState(() => localStorage.getItem('sidebar-collapsed') === 'true');
    const [showExpandedContent, setShowExpandedContent] = useState(() => localStorage.getItem('sidebar-collapsed') !== 'true');
    // Lazy initializer: the non-lazy form evaluated getStoredUser() — a
    // synchronous localStorage read plus a JSON.parse — on every single render
    // and threw the result away, since React only uses it on the first one.
    // Sidebar re-renders on every alerts-polling tick and every route change.
    const [user, setUser] = useState<StoredUser | null>(() => getStoredUser());
    const [menuOpen, setMenuOpen] = useState(false);
    const [downloadOpen, setDownloadOpen] = useState(false);
    const [downloadPopupOpen, setDownloadPopupOpen] = useState(false);
    const { id: avatarId, image: customAvatarImage } = useAvatar();
    const { showToast } = useToast();
    const confirmDialog = useConfirm();
    const downloadRef = useRef<HTMLDivElement | null>(null);
    const userMenuRef = useRef<HTMLDivElement | null>(null);
    const downloadMenuPanelRef = useRef<HTMLDivElement | null>(null);
    const userMenuPanelRef = useRef<HTMLDivElement | null>(null);
    const chooseAgentDialogRef = useRef<HTMLDivElement | null>(null);
    const chooseAgentTriggerRef = useRef<HTMLButtonElement | null>(null);
    const userRole = normalizeRole(user?.role);
    const isSuperAdmin = userRole === 'Super Administrator';
    // Remote Shell and Policy Management are both scoped server-side to let
    // Group Admin act only within their own group(s) (backend/src/websocket/
    // terminal.ts, backend/src/controllers/policies/policy_management.ts) —
    // unlike Audit Trail / Team Management, which the backend restricts to
    // Super Administrator on every route.
    //
    // Network Security is open to Group Admin too (backend/src/routes/api/
    // network.ts uses requireAdmin), but note it is not group-scoped: scan
    // targets are operator-supplied addresses rather than nodes from the
    // caller's group, and scan history/schedules are fleet-wide. See the note
    // on that router.use() call.
    const canManagePolicies = isSuperAdmin || userRole === 'Group Admin';
    // Open FIM alert count for the File Integrity badge (60 s poll, silent on failure).
    const { count: fimOpenAlerts } = useFimOpenAlerts(canManagePolicies);
    const canAccessDomainReputation = isSuperAdmin || userRole === 'Group Admin';
    // Same bar as Domain Reputation / Policy Management — detection/correlation
    // rules are a "changes detection/enforcement behavior" class of sensitive
    // config, per docs/RULE_ENGINE_UI_SPEC.md. GET-level backend routes are a
    // lower bar server-side, but this app has no plain-Viewer UI path to any
    // of these three.
    const canAccessRuleEngine = RULE_ENGINE_ENABLED && (isSuperAdmin || userRole === 'Group Admin');
    const canAccessNetworkSecurity = isSuperAdmin || userRole === 'Group Admin';
    const isOnPrem = import.meta.env.VITE_DEPLOYMENT_MODE !== 'cloud';
    const isAI = location.pathname === '/ai';

    useEffect(() => {
        if (!downloadOpen && !menuOpen) return;

        const onPointerDown = (e: MouseEvent | TouchEvent) => {
            const target = e.target as Node | null;
            if (!target) return;

            const clickedInside =
                downloadRef.current?.contains(target) ||
                userMenuRef.current?.contains(target);

            if (!clickedInside) {
                setDownloadOpen(false);
                setDownloadPopupOpen(false);
                setMenuOpen(false);
            }
        };

        const onKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                setDownloadOpen(false);
                setDownloadPopupOpen(false);
                setMenuOpen(false);
            }
        };

        document.addEventListener('mousedown', onPointerDown, true);
        document.addEventListener('touchstart', onPointerDown, true);
        document.addEventListener('keydown', onKeyDown);
        return () => {
            document.removeEventListener('mousedown', onPointerDown, true);
            document.removeEventListener('touchstart', onPointerDown, true);
            document.removeEventListener('keydown', onKeyDown);
        };
    }, [downloadOpen, menuOpen]);

    useEffect(() => {
        // "Choose a Different Agent" is a real modal dialog (role="dialog"
        // aria-modal="true"), so it must move focus in on open, trap Tab
        // inside it, and restore focus to the button that opened it on close.
        if (!downloadPopupOpen) return;

        const dialog = chooseAgentDialogRef.current;
        const triggerEl = chooseAgentTriggerRef.current;
        const focusableSelector = 'button:not([disabled]), [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
        const focusables = dialog ? Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector)) : [];
        focusables[0]?.focus();

        const trapTab = (e: KeyboardEvent) => {
            if (e.key !== 'Tab' || !dialog) return;
            const items = Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector));
            if (items.length === 0) return;
            const first = items[0];
            const last = items[items.length - 1];
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        };

        document.addEventListener('keydown', trapTab, true);
        return () => {
            document.removeEventListener('keydown', trapTab, true);
            triggerEl?.focus();
        };
    }, [downloadPopupOpen]);

    useEffect(() => {
        const refreshUser = () => setUser(getStoredUser());
        const onStorage = (e: StorageEvent) => {
            if (e.key === 'user') refreshUser();
        };
        window.addEventListener('auth-change', refreshUser);
        window.addEventListener('storage', onStorage);
        return () => {
            window.removeEventListener('auth-change', refreshUser);
            window.removeEventListener('storage', onStorage);
        };
    }, []);

    const hydrateProfileAttemptedRef = useRef(false);

    useEffect(() => {
        const syncProfileRole = async () => {
            // Always sync once per mount so role changes in DB are reflected without re-login.
            if (hydrateProfileAttemptedRef.current) return;
            hydrateProfileAttemptedRef.current = true;
            try {
                const profile = await getProfile();
                if (profile?.data) {
                    const nextUser = {
                        ...profile.data,
                        role: normalizeRole(profile.data.role),
                    };
                    localStorage.setItem('user', JSON.stringify(sanitizeUserForCache(nextUser)));
                    setUser(nextUser);
                }
            } catch {
                hydrateProfileAttemptedRef.current = false;
            }
        };

        syncProfileRole();
    }, []);

    useEffect(() => {
        document.documentElement.classList.toggle('sidebar-collapsed', isCollapsed);
        localStorage.setItem('sidebar-collapsed', String(isCollapsed));
    }, [isCollapsed]);

    useEffect(() => {
        // Hide labels immediately on collapse; reveal after width transition on expand.
        if (isCollapsed) setShowExpandedContent(false);
    }, [isCollapsed]);

    const handleLogout = async () => {
        try {
            markManualLogout();
            await logout();
            clearAuthData();
            navigate('/');
        } catch (error) {
            if (import.meta.env.DEV) {
                console.error('Logout error:', error);
            }
            // Still treat this as an intentional logout attempt; session checks
            // may run while cookies are being cleared.
            markManualLogout();
            clearAuthData();
            navigate('/login');
        }
    };

    const handleLogoutAllDevices = async () => {
        try {
            markManualLogout();
            await logoutAllDevices();
            clearAuthData();
            navigate('/');
        } catch (error) {
            if (import.meta.env.DEV) {
                console.error('Logout all devices error:', error);
            }
            markManualLogout();
            clearAuthData();
            navigate('/login');
        }
    };

    // "Logout all sessions" is far higher blast-radius than "Logout" (it kills
    // every other active device/session), so unlike plain Logout it requires
    // an explicit confirmation before firing.
    const handleLogoutAllSessionsClick = async () => {
        setMenuOpen(false);
        const confirmed = await confirmDialog({
            title: 'Logout all sessions?',
            description: 'This signs you out on every device currently logged in to your account, not just this browser.',
            confirmLabel: 'Logout all sessions',
            cancelLabel: 'Cancel',
            variant: 'danger',
        });
        if (confirmed) {
            handleLogoutAllDevices();
        }
    };

    // Roving arrow-key navigation for the hand-rolled menu panels below, to
    // back up their aria-haspopup="menu" contract on the trigger buttons.
    const handleMenuKeyDown = (
        e: React.KeyboardEvent<HTMLDivElement>,
        panelRef: React.RefObject<HTMLDivElement | null>,
    ) => {
        if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp' && e.key !== 'Home' && e.key !== 'End') return;
        // The "Choose a Different Agent" dialog is rendered as a nested DOM
        // child of this same menu panel (no portal), so its own keydowns
        // bubble up here. While that modal is open and focus is inside it,
        // defer entirely to its own Tab-trap instead of roving focus onto
        // the (now hidden-behind-overlay) menu trigger buttons.
        if (downloadPopupOpen && chooseAgentDialogRef.current?.contains(document.activeElement)) {
            return;
        }
        const panel = panelRef.current;
        if (!panel) return;
        const items = Array.from(panel.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not([disabled])'));
        if (items.length === 0) return;
        e.preventDefault();
        const currentIndex = items.indexOf(document.activeElement as HTMLButtonElement);
        let nextIndex = 0;
        if (e.key === 'ArrowDown') nextIndex = currentIndex < items.length - 1 ? currentIndex + 1 : 0;
        else if (e.key === 'ArrowUp') nextIndex = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
        else if (e.key === 'End') nextIndex = items.length - 1;
        items[nextIndex]?.focus();
    };


    const handleWindowsDownload = () => {
        setDownloadOpen(false);
        setDownloadPopupOpen(false);

        const downloadUrl = import.meta.env.VITE_WINDOWS_AGENT_INSTALLER_URL;

        if (!downloadUrl) {
            console.error('VITE_WINDOWS_AGENT_INSTALLER_URL not configured');
            showToast('Windows agent download is not available right now. Please contact your administrator.', 'error');
            return;
        }

        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = '';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const handleLinuxDownload = () => {
        setDownloadOpen(false);
        setDownloadPopupOpen(false);

        const downloadUrl = import.meta.env.VITE_LINUX_AGENT_INSTALLER_URL;

        if (!downloadUrl) {
            console.error('VITE_LINUX_AGENT_INSTALLER_URL not configured');
            showToast('Linux agent download is not available right now. Please contact your administrator.', 'error');
            return;
        }

        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = '';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const handleDownload = () => {
        const os = OSName();
        if (os === 'Windows') handleWindowsDownload();
        else if (os === 'Linux') handleLinuxDownload();
    };


    type MenuItem = {
        name: string;
        icon: React.ReactElement;
        path: string;
        badge?: number | string;
        category?: 'main' | 'help';
    };

    // Sidebar re-renders on every alerts-polling tick and every route change.
    // Memoising keeps the icon JSX elements referentially stable across those
    // renders; without it every nav row's icon subtree reconciles even when
    // nothing about the nav has changed.
    const menuItems: MenuItem[] = useMemo(() => [
        {
            name: 'Dashboard',
            category: 'main',
            icon: <DashboardIcon className="w-6 h-6" />,
            path: '/dashboard',
        },
        {
            name: 'Devices',
            category: 'main',
            icon: <DevicesIcon className="w-6 h-6" />,
            path: '/my-devices',
        },
        {
            name: 'Alerts',
            category: 'main',
            icon: <AlertsIcon className="w-6 h-6" />,
            path: '/alerts',
            badge: sidebarNewCount > 0 ? sidebarNewCount : undefined,
        },
        {
            name: 'Compliance',
            category: 'main',
            icon: <ComplianceIcon className="w-6 h-6" />,
            path: '/compliance',
        },
        ...(canManagePolicies
            ? [
                {
                    name: 'Policy Management',
                    category: 'main' as const,
                    icon: <PolicyManagementIcon className="w-6 h-6" />,
                    path: '/policy-management',
                },
                {
                    name: 'File Integrity',
                    category: 'main' as const,
                    icon: <FileIntegrityIcon className="w-6 h-6" />,
                    path: '/file-integrity',
                    badge: fimOpenAlerts > 0 ? fimOpenAlerts : undefined,
                },
            ]
            : []),
        ...(canAccessNetworkSecurity && isOnPrem
            ? [{
                name: 'Network Security',
                category: 'main' as const,
                icon: <NetworkSecurityIcon className="w-6 h-6" />,
                path: '/network',
            }]
            : []),
        // Single nav entry for the whole Vulnerability Management area; patch
        // application is an inline action on the Vulnerabilities/Software
        // Inventory lists rather than a page of its own (see
        // VulnerabilityManagement/index.tsx's header comment).
        //
        // Gated on isSuperAdmin alone, tighter than routes/api/vulnerabilities.ts
        // (checkAccessJwt + apiDataLimiter only, no admin gate — see App.tsx's
        // matching comment on the /vulnerability-management route). Deliberate,
        // pending an explicit decision on the intended audience; do not loosen
        // without it.
        ...(isSuperAdmin
            ? [{
                name: 'Patch Management',
                category: 'main' as const,
                icon: <PatchManagementIcon className="w-6 h-6" />,
                path: '/vulnerability-management',
            }]
            : []),
        ...(canAccessDomainReputation
            ? [{
                name: 'Domain Reputation',
                category: 'main' as const,
                icon: <DomainReputationIcon className="w-6 h-6" />,
                path: '/domain-reputation',
            }]
            : []),
        ...(canAccessRuleEngine
            ? [{
                name: 'Rule Engine',
                category: 'main' as const,
                icon: <RuleEngineIcon className="w-6 h-6" />,
                path: '/rule-engine',
            }]
            : []),
        {
            name: 'Threat Hunting',
            category: 'main',
            icon: <ThreatHuntingIcon className="w-6 h-6" />,
            path: '/threat-hunting',
        },
        {
            name: 'AI Assistant',
            category: 'main',
            icon: <AiAssistantIcon className="w-6 h-6" />,
            path: '/ai',
        },

        {
            name: 'Help',
            category: 'help',
            icon: <HelpIcon className="w-6 h-6" />,
            path: '/help',
        },
    ], [sidebarNewCount, fimOpenAlerts, canManagePolicies, canAccessNetworkSecurity, isOnPrem, isSuperAdmin, canAccessDomainReputation, canAccessRuleEngine]);

    // The memo above was immediately undone downstream: the render body filtered
    // menuItems twice (category !== 'help' for the main nav, category === 'help'
    // for the Support section), allocating two fresh arrays on every render —
    // and Sidebar re-renders on every alerts-polling tick. Partitioning once,
    // memoised on the same list, keeps both arrays referentially stable. Same
    // items, same order, same rows.
    const mainItems = useMemo(() => menuItems.filter(item => item.category !== 'help'), [menuItems]);
    const helpItems = useMemo(() => menuItems.filter(item => item.category === 'help'), [menuItems]);

    return (
        <aside
            aria-label="Sidebar"
            onTransitionEnd={(e) => {
                if (e.propertyName === 'width' && !isCollapsed) {
                    setShowExpandedContent(true);
                }
            }}
            className={`fixed left-0 top-0 h-screen hidden md:flex flex-col transition-all duration-300 z-10 ${isCollapsed ? 'w-20' : 'w-59'} ${isAI ? 'bg-[#0d0d1a] border-r border-white/8' : 'bg-gradient-to-b from-white to-slate-50 border-r border-slate-200'}`}
        >
            {/* Header Section */}
            <div
                className={`flex items-center px-4 py-5 ${showExpandedContent ? 'gap-2' : 'justify-center'} ${isAI ? 'border-b border-white/8 bg-transparent' : 'border-b border-slate-200 bg-white'}`}
            >
                {showExpandedContent && (
                    <div className="flex-1 flex justify-center">
                        <motion.button
                            onClick={() => navigate('/dashboard')}
                            className="flex items-center rounded-lg hover:bg-slate-100 transition-colors py-1.5 px-2"
                            title="Go to Dashboard"
                            whileHover={{ scale: 1.02 }}
                        >
                            <img
                                src={vajraLogoCollapsed}
                                alt="Vajra"
                                className="h-8 w-auto"
                            />
                        </motion.button>
                    </div>
                )}
                <motion.button
                    onClick={() => setIsCollapsed(!isCollapsed)}
                    className={`z-20 p-1.5 rounded-lg transition-all border ${isCollapsed
                        ? 'sidebar-active hover:opacity-90 text-white border-transparent'
                        : isAI
                            ? 'bg-white/5 hover:bg-white/10 text-white/60 border-white/10'
                            : 'bg-white hover:bg-slate-100 text-slate-700 border-slate-200'
                        }`}
                    aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                    title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                    whileHover={{ scale: 1.06 }}
                    whileTap={{ scale: 0.96 }}
                >
                    {isCollapsed ? (
                        <ChevronRightIcon sx={{ fontSize: 22 }} />
                    ) : (
                        <ChevronLeftIcon sx={{ fontSize: 22 }} />
                    )}
                </motion.button>
            </div>

            {/* Main Content */}
            <div className="flex-1 flex flex-col overflow-hidden relative">
                {/* Navigation Menu */}
                <nav aria-label="Primary" className={`${showExpandedContent ? 'px-3 py-4' : 'px-2 py-3'} overflow-y-auto flex-1 space-y-1`}>
                    {/* Help is kept out of the main nav so it sits in the dedicated
                        "Support" section at the same vertical position — see the
                        mainItems/helpItems partition above. */}
                    {mainItems
                        .map((item) => {
                            const isItemActive = location.pathname === item.path || (item.path !== '/dashboard' && location.pathname.startsWith(item.path + '/'));
                            return (
                            <button
                                key={item.path}
                                onClick={() => navigate(item.path)}
                                title={item.name}
                                aria-label={item.name}
                                aria-current={isItemActive ? 'page' : undefined}
                                className={`relative w-full group flex items-center ${showExpandedContent ? 'justify-between px-3.5' : 'justify-center px-2.5'} py-3 rounded-lg transition-colors duration-150 ${isItemActive
                                    ? isAI
                                        ? 'bg-white/10 text-white shadow-none border border-white/15'
                                        : 'sidebar-active text-white shadow-md'
                                    : isAI
                                        ? 'text-white/55 hover:bg-white/8 hover:text-white/90'
                                        : 'text-slate-700 hover:bg-blue-50'
                                    }`}
                            >
                                <div className={`flex items-center min-w-0 ${showExpandedContent ? 'gap-3' : 'justify-center w-full'}`}>
                                    <div className={`shrink-0 transition-colors ${isItemActive ? 'text-white' : isAI ? 'text-white/50 group-hover:text-white/90' : 'text-slate-600 group-hover:text-blue-600'}`}>
                                        {item.icon}
                                    </div>
                                    {showExpandedContent && (
                                        <span className="font-semibold text-sm truncate">{item.name}</span>
                                    )}
                                </div>
                                {showExpandedContent && item.badge && (
                                    <motion.span
                                        className={`inline-flex items-center justify-center min-w-6 h-6 px-2 text-sm font-bold rounded-full ${isItemActive
                                            ? 'bg-white text-blue-600'
                                            : 'bg-red-500 text-white'
                                            }`}
                                        animate={prefersReducedMotion ? undefined : { scale: [1, 1.05, 1] }}
                                        transition={prefersReducedMotion ? undefined : { duration: 2, repeat: Infinity }}
                                    >
                                        {item.badge}
                                    </motion.span>
                                )}
                                {isCollapsed && item.badge && (
                                    <motion.div className="absolute top-2 right-2 w-3 h-3 bg-red-500 rounded-full" />
                                )}
                            </button>
                            );
                        })}
                </nav>

                {/* Help Section */}
                <div className={`${showExpandedContent ? 'px-3 py-3' : 'px-2 py-3'} border-t ${isAI ? 'border-white/8 bg-transparent' : 'border-slate-200 bg-white'}`}>
                    {helpItems
                        .map((item) => (
                            <button
                                key={item.path}
                                onClick={() => navigate(item.path)}
                                title={item.name}
                                aria-label={item.name}
                                aria-current={location.pathname === item.path ? 'page' : undefined}
                                className={`w-full flex items-center min-w-0 ${showExpandedContent ? 'gap-3 px-3.5' : 'justify-center px-2.5'} py-3 rounded-lg transition-colors duration-150 ${location.pathname === item.path
                                    ? isAI ? 'bg-white/10 text-white border border-white/15' : 'sidebar-active text-white shadow-md'
                                    : isAI ? 'text-white/55 hover:bg-white/8 hover:text-white/90' : 'text-slate-700 hover:bg-slate-100'
                                    }`}
                            >
                                <div className={`shrink-0 ${location.pathname === item.path ? 'text-white' : isAI ? 'text-white/50' : 'text-slate-600'}`}>
                                    {item.icon}
                                </div>
                                {showExpandedContent && (
                                    <span className="font-semibold text-sm truncate">{item.name}</span>
                                )}
                            </button>
                        ))}
                </div>
            </div>

            {/* Bottom Actions Section */}
            <div className={`border-t space-y-1 ${showExpandedContent ? 'px-3 py-3' : 'px-2 py-2'} ${isAI ? 'border-white/8 bg-transparent' : 'border-slate-200 bg-white'}`}>
                {/* Download Agent */}
                <div ref={downloadRef} className="relative">
                    <motion.button
                        whileHover={{ scale: 1.02 }}
                        whileTap={{ scale: 0.97 }}
                        onClick={() => setDownloadOpen((prev) => !prev)}
                        title="Download Agent"
                        aria-label="Download Agent"
                        aria-haspopup="menu"
                        aria-expanded={downloadOpen}
                        className="w-full rounded-lg"
                    >
                        <NoiseBackground
                            containerClassName="rounded-xl p-0"
                            gradientColors={DOWNLOAD_BUTTON_GRADIENT}
                            noiseIntensity={0.12}
                            speed={0.08}
                            className={`flex items-center min-w-0 ${showExpandedContent ? 'justify-start gap-2 px-3' : 'justify-center px-2'} py-2.5`}
                        >
                            <svg className="w-5 h-5 shrink-0" style={{ color: 'rgb(4,34,119)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                            </svg>
                            {showExpandedContent && (
                                <ShimmerText
                                    text="Download Agent"
                                    className="text-sm font-bold truncate from-[rgb(4,34,119)] via-[rgb(37,99,235)] to-[rgb(4,34,119)]"
                                />
                            )}
                        </NoiseBackground>
                    </motion.button>

                    <AnimatePresence>
                        {downloadOpen && (
                            <motion.div
                                ref={downloadMenuPanelRef}
                                role="menu"
                                aria-orientation="vertical"
                                onKeyDown={(e) => handleMenuKeyDown(e, downloadMenuPanelRef)}
                                initial={{ scale: 0.92, opacity: 0, y: 8 }}
                                animate={{ scale: 1, opacity: 1, y: 0 }}
                                exit={{ scale: 0.92, opacity: 0, y: 8 }}
                                transition={{ duration: 0.15 }}
                                className={`absolute ${isCollapsed ? 'left-full ml-2 bottom-full mb-2' : 'left-full ml-2 bottom-0'} w-64 rounded-lg shadow-lg overflow-hidden z-50 py-1 ${isAI ? 'bg-[#1a1a2e] border border-white/10' : 'bg-white border border-slate-200'}`}
                            >
                                <div className={`px-4 py-3 border-b ${isAI ? 'border-white/10 bg-white/5' : 'border-slate-200 bg-white'}`}>
                                    {
                                        OSName() === 'Linux' && (
                                            <i className="fa-brands fa-linux w-4 text-center text-sm leading-none" aria-hidden />
                                        )
                                    }
                                    {
                                        OSName() === 'Windows' && (
                                            <i className="fa-brands fa-windows w-4 text-center text-sm leading-none" aria-hidden />
                                        )
                                    }
                                    {
                                        OSName() === 'MacOS' && (
                                            <i className="fa-brands fa-apple w-4 text-center text-sm leading-none" aria-hidden />
                                        )
                                    }
                                    {
                                        (OSName() === 'Windows' || OSName() === 'Linux') && (
                                            <p className={`text-sm font-semibold ${isAI ? 'text-white' : 'text-slate-900'}`}>Download for {OSName()}</p>
                                        )
                                    }
                                    {
                                        OSName() === 'MacOS' && (
                                            <p className={`text-sm font-semibold ${isAI ? 'text-white' : 'text-slate-900'}`}>Not Available for macOS (Coming Soon)</p>
                                        )
                                    }
                                    {
                                        (OSName() === 'Android' || OSName() === 'iOS' || OSName() === 'Chrome OS' || OSName() === 'Unknown') && (
                                            <p className={`text-sm font-semibold ${isAI ? 'text-white' : 'text-slate-900'}`}>Not Available for {OSName()}</p>
                                        )
                                    }
                                </div>
                                {
                                    (OSName() === 'Windows' || OSName() === 'Linux') && (
                                        <button
                                            role="menuitem"
                                            onClick={handleDownload}
                                            className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 rounded-lg ${isAI ? 'text-white/70 hover:bg-white/8 hover:text-white' : 'text-slate-700 hover:bg-blue-50 hover:text-blue-600'}`}
                                        >
                                            Confirm Download
                                        </button>
                                    )
                                }
                                <button
                                    ref={chooseAgentTriggerRef}
                                    role="menuitem"
                                    onClick={() => setDownloadPopupOpen(true)}
                                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 rounded-lg ${isAI ? 'text-white/70 hover:bg-white/8 hover:text-white' : 'text-slate-700 hover:bg-blue-50 hover:text-blue-600'}`}
                                >
                                    Choose a Different Agent
                                </button>
                                {
                                    downloadPopupOpen && (
                                        <div
                                            className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
                                            onClick={() => setDownloadPopupOpen(false)}
                                        >
                                            <div
                                                ref={chooseAgentDialogRef}
                                                role="dialog"
                                                aria-modal="true"
                                                aria-labelledby="choose-agent-title"
                                                onClick={(e) => e.stopPropagation()}
                                                className="w-full max-w-sm rounded-2xl bg-white p-6 shadow-xl"
                                            >
                                                <h2 id="choose-agent-title" className="text-lg font-semibold text-slate-900 mb-2">Choose a Different Agent</h2>
                                                <button
                                                    onClick={handleWindowsDownload}
                                                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 rounded-lg ${isAI ? 'text-white/70 hover:bg-white/8 hover:text-white' : 'text-slate-700 hover:bg-blue-50 hover:text-blue-600'}`}
                                                >
                                                    <i className="fa-brands fa-windows w-4 text-center text-sm leading-none" aria-hidden />
                                                    Download for Windows
                                                </button>
                                                <button
                                                    onClick={handleLinuxDownload}
                                                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 rounded-lg ${isAI ? 'text-white/70 hover:bg-white/8 hover:text-white' : 'text-slate-700 hover:bg-blue-50 hover:text-blue-600'}`}
                                                >
                                                    <i className="fa-brands fa-linux w-4 text-center text-sm leading-none" aria-hidden />
                                                    Download for Linux
                                                </button>
                                                <button
                                                    disabled
                                                    className={`w-full text-left px-4 py-2.5 text-sm cursor-not-allowed flex items-center gap-2 rounded-lg ${isAI ? 'text-white/25 bg-white/3' : 'text-slate-400 bg-slate-50'}`}
                                                >
                                                    <i className="fa-brands fa-apple w-4 text-center text-sm leading-none" aria-hidden />
                                                    macOS (Coming Soon)
                                                </button>
                                                <button
                                                    onClick={() => setDownloadPopupOpen(false)}
                                                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 rounded-lg ${isAI ? 'text-white/70 hover:bg-white/8 hover:text-white' : 'text-slate-700 hover:bg-blue-50 hover:text-red-600'}`}
                                                >
                                                    Cancel
                                                </button>

                                            </div>

                                        </div>
                                    )
                                }
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>

                {isSuperAdmin && (
                    <motion.button
                        whileHover={{ scale: 1.01 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => navigate('/audit-trail')}
                        className={`w-full flex items-center ${showExpandedContent ? 'justify-between' : 'justify-center'} rounded-lg px-3 py-3 transition-colors group ${location.pathname === '/audit-trail'
                            ? isAI ? 'bg-white/10 text-white border border-white/15' : 'sidebar-active text-white shadow-md'
                            : isAI ? 'text-white/55 hover:bg-white/8 hover:text-white/90' : 'text-slate-700 hover:bg-slate-100'
                            }`}
                        title="Audit Trail"
                        aria-label="Audit Trail"
                        aria-current={location.pathname === '/audit-trail' ? 'page' : undefined}
                    >
                        <div className={`flex items-center min-w-0 ${showExpandedContent ? 'gap-2' : ''}`}>
                            <svg
                                className="w-6 h-6 transition-colors shrink-0"
                                fill="none"
                                stroke="currentColor"
                                viewBox="0 0 24 24"
                            >
                                <path
                                    strokeLinecap="round"
                                    strokeLinejoin="round"
                                    strokeWidth={2}
                                    d="M9 12h6m-6 4h6m2 6H7a2 2 0 01-2-2V4a2 2 0 012-2h6l6 6v12a2 2 0 01-2 2z"
                                />
                            </svg>
                            {showExpandedContent && <span className="text-sm font-semibold truncate">Audit Trail</span>}
                        </div>
                    </motion.button>
                )}

                {/* User Profile */}
                <div ref={userMenuRef} className="relative">
                    <motion.button
                        whileHover={{ scale: 1.01 }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => setMenuOpen((prev) => !prev)}
                        className={`w-full flex items-center ${showExpandedContent ? 'justify-start gap-2' : 'justify-center'} rounded-lg px-3 py-3 transition-colors group border border-transparent ${isAI ? 'text-white/55 hover:bg-white/8 hover:text-white/90 hover:border-white/10' : 'text-slate-700 hover:bg-slate-100 hover:border-slate-200'}`}
                        title={user?.name || 'User profile'}
                        aria-label={user?.name || 'User profile'}
                        aria-haspopup="menu"
                        aria-expanded={menuOpen}
                    >
                        <div className="w-8 h-8 rounded-full overflow-hidden ring-2 ring-blue-300 group-hover:shadow-md transition-shadow flex items-center justify-center bg-gradient-to-br from-blue-500 to-blue-700 shrink-0">
                            {avatarId === CUSTOM_AVATAR_ID && customAvatarImage
                                ? <img alt="My avatar" className="h-full w-full object-cover" src={customAvatarImage} />
                                : avatars.find(a => a.id === avatarId)?.svg ?? <AccountCircleIcon sx={{ fontSize: 24, color: 'white' }} />}
                        </div>
                        {showExpandedContent && (
                            <span className="text-sm font-semibold truncate">{user?.name?.split(' ')[0] || 'User'}</span>
                        )}
                    </motion.button>

                    <AnimatePresence>
                        {menuOpen && (
                            <motion.div
                                ref={userMenuPanelRef}
                                role="menu"
                                aria-orientation="vertical"
                                onKeyDown={(e) => handleMenuKeyDown(e, userMenuPanelRef)}
                                initial={{ scale: 0.92, opacity: 0, y: 8 }}
                                animate={{ scale: 1, opacity: 1, y: 0 }}
                                exit={{ scale: 0.92, opacity: 0, y: 8 }}
                                transition={{ duration: 0.15 }}
                                className={`absolute left-full ml-2 bottom-0 w-64 rounded-lg shadow-lg overflow-hidden z-50 ${isAI ? 'bg-[#1a1a2e] border border-white/10' : 'bg-white border border-slate-200'}`}
                            >
                                <div className={`px-4 py-3 border-b ${isAI ? 'border-white/10 bg-white/5' : 'border-slate-200 bg-white'}`}>
                                    <p className={`text-sm font-semibold ${isAI ? 'text-white' : 'text-slate-900'}`}>{user?.name || 'User'}</p>
                                    <p className={`text-xs font-medium truncate ${isAI ? 'text-white/50' : 'text-slate-700'}`}>{user?.email || 'No email available'}</p>
                                </div>
                                <button
                                    role="menuitem"
                                    onClick={() => { setMenuOpen(false); navigate('/update-profile'); }}
                                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 rounded-lg ${isAI ? 'text-white/70 hover:bg-white/8 hover:text-white' : 'text-slate-700 hover:bg-blue-50 hover:text-blue-600'}`}
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                    </svg>
                                    Profile Settings
                                </button>
                                <button
                                    role="menuitem"
                                    onClick={() => { setMenuOpen(false); navigate('/settings'); }}
                                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 rounded-lg ${isAI ? 'text-white/70 hover:bg-white/8 hover:text-white' : 'text-slate-700 hover:bg-blue-50 hover:text-blue-600'}`}
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                                    </svg>
                                    Settings
                                </button>
                                {isSuperAdmin && (
                                    <button
                                        role="menuitem"
                                        onClick={() => { setMenuOpen(false); navigate('/management'); }}
                                        className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 border-b rounded-lg ${isAI ? 'text-white/70 hover:bg-white/8 hover:text-white border-white/10' : 'text-slate-700 hover:bg-blue-50 hover:text-blue-600 border-slate-200'}`}
                                    >
                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-1a4 4 0 00-5.9-3.5M17 20H7m10 0v-1c0-1.1-.37-2.11-1-2.93M7 20H2v-1a4 4 0 015.9-3.5M7 20v-1c0-1.1.37-2.11 1-2.93m0 0a5 5 0 018 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM5 10a2 2 0 11-4 0 2 2 0 014 0z" />
                                        </svg>
                                        Management
                                    </button>
                                )}
                                <button
                                    role="menuitem"
                                    onClick={() => { setMenuOpen(false); handleLogout(); }}
                                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 rounded-lg ${isAI ? 'text-rose-400 hover:bg-rose-500/10' : 'text-red-600 hover:bg-red-50'}`}
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                                    </svg>
                                    Logout
                                </button>
                                <button
                                    role="menuitem"
                                    onClick={handleLogoutAllSessionsClick}
                                    className={`w-full text-left px-4 py-2.5 text-sm transition-colors flex items-center gap-2 border-t rounded-lg ${isAI ? 'text-rose-400 hover:bg-rose-500/10 border-white/10' : 'text-red-600 hover:bg-red-50 border-slate-200'}`}
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                                    </svg>
                                    Logout all sessions
                                </button>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;