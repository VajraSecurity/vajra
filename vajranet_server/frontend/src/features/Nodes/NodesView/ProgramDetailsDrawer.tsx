import { useEffect, useRef, useState } from 'react';
import {
    Archive,
    ArrowLeft,
    Barcode,
    Box,
    Bug,
    CalendarDays,
    CheckCircle2,
    Clock,
    Code,
    Cpu,
    Download,
    Flame,
    FolderOpen,
    FolderTree,
    GitBranch,
    Globe,
    HardDrive,
    Hash,
    Info,
    Languages,
    Layers,
    Link2,
    Lock,
    Package,
    ShieldAlert,
    ShieldCheck,
    SortDesc,
    Terminal,
    Trash2,
    User,
    X,
    type LucideIcon,
} from 'lucide-react';
import type { BadgeProps } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import CveVulnerabilityList from './CveVulnerabilityList';
import { severityBadgeVariant } from './severityBadge';

export interface ProgramDetailsDrawerProps {
    isOpen: boolean;
    onClose: () => void;
    programData: Record<string, unknown> | null;
}

/** dpkg Installed-Size field is in kilobytes */
const formatDebInstalledSizeKb = (raw: unknown): string | null => {
    if (raw === null || raw === undefined || raw === '') return null;
    const kb = Number(raw);
    if (Number.isNaN(kb)) return String(raw);
    if (kb >= 1048576) return `${(kb / 1048576).toFixed(2)} GB`;
    if (kb >= 1024) return `${(kb / 1024).toFixed(1)} MB`;
    return `${kb} KB`;
};

// Helper to reliably parse YYYYMMDD or standard ISO dates and convert to IST
const formatToIST = (dateInput: unknown, includeTime = false) => {
    if (!dateInput) return null;
    const str = String(dateInput).trim();
    if (!str) return null;

    try {
        let dateObj: Date;

        // Handle specific YYYYMMDD format (e.g., "20240401" -> April 1, 2024)
        if (/^\d{8}$/.test(str)) {
            const year = parseInt(str.substring(0, 4), 10);
            const month = parseInt(str.substring(4, 6), 10) - 1; // Months are 0-indexed in JS
            const day = parseInt(str.substring(6, 8), 10);
            dateObj = new Date(year, month, day);
        } else {
            // Handle normal timestamps or ISO strings
            const num = Number(str);
            dateObj = !isNaN(num) && str.length >= 10
                ? new Date(num > 9999999999 ? num : num * 1000)
                : new Date(str);
        }

        // If it's an invalid date, fallback to returning the original string
        if (isNaN(dateObj.getTime())) return str;

        const options: Intl.DateTimeFormatOptions = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            timeZone: 'Asia/Kolkata',
        };

        // Only add time if requested AND it wasn't a plain YYYYMMDD date
        if (includeTime && !/^\d{8}$/.test(str)) {
            options.hour = '2-digit';
            options.minute = '2-digit';
        }

        return new Intl.DateTimeFormat('en-IN', options).format(dateObj);
    } catch {
        return str; // Fallback
    }
};

const ProgramDetailsDrawer = ({ isOpen, onClose, programData }: ProgramDetailsDrawerProps) => {
    const [activeCveId, setActiveCveId] = useState<string | null>(null);
    const dialogRef = useRef<HTMLDivElement>(null);
    const closeButtonRef = useRef<HTMLButtonElement>(null);
    const previouslyFocusedElementRef = useRef<HTMLElement | null>(null);
    // The dialog always renders both slides side-by-side (only a CSS
    // transform swaps which one is visible), so the Tab trap must be scoped
    // to whichever slide is actually on screen rather than the whole dialog
    // - otherwise it would include the other slide's off-canvas, clipped
    // controls (e.g. the "Back" button) as focusable.
    const slide1Ref = useRef<HTMLDivElement>(null);
    const slide2Ref = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!isOpen) {
            setTimeout(() => setActiveCveId(null), 300);
        }
    }, [isOpen, programData]);

    // Move focus into the drawer when it opens, and restore it to the
    // trigger element when it closes, so keyboard focus never gets stranded.
    useEffect(() => {
        if (isOpen) {
            previouslyFocusedElementRef.current = document.activeElement as HTMLElement | null;
            closeButtonRef.current?.focus();
        } else {
            previouslyFocusedElementRef.current?.focus();
            previouslyFocusedElementRef.current = null;
        }
    }, [isOpen]);

    useEffect(() => {
        const handleKeydown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                if (activeCveId) setActiveCveId(null);
                else onClose();
                return;
            }

            // Trap Tab/Shift+Tab within the dialog so focus can't leak into
            // the page behind the backdrop while the drawer is open. Scope
            // the query to the currently visible slide only - the other
            // slide is still in the DOM (just translated off-screen and
            // clipped) and must not contribute focusable elements.
            const activeSlide = activeCveId ? slide2Ref.current : slide1Ref.current;
            if (e.key === 'Tab' && activeSlide) {
                const focusable = activeSlide.querySelectorAll<HTMLElement>(
                    'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'
                );
                if (focusable.length === 0) return;

                const first = focusable[0];
                const last = focusable[focusable.length - 1];

                if (e.shiftKey && document.activeElement === first) {
                    e.preventDefault();
                    last.focus();
                } else if (!e.shiftKey && document.activeElement === last) {
                    e.preventDefault();
                    first.focus();
                }
            }
        };

        if (isOpen) {
            document.body.style.overflow = 'hidden';
            document.addEventListener('keydown', handleKeydown);
        } else {
            document.body.style.overflow = 'unset';
        }

        return () => {
            document.body.style.overflow = 'unset';
            document.removeEventListener('keydown', handleKeydown);
        };
    }, [isOpen, onClose, activeCveId]);

    if (!isOpen && !programData) return null;

    const isDebPackage =
        typeof programData?.admindir === 'string' && programData.admindir.includes('dpkg');
    const isRpmPackage =
        (typeof programData?.vendor === 'string' && programData.vendor.trim() !== '') ||
        (typeof programData?.release === 'string' && programData.release.trim() !== '') ||
        (programData?.install_time !== null && programData?.install_time !== undefined);
    const isSnapPackage = programData?.source === 'snap';

    const cveMatchObj: Record<string, Record<string, unknown>> =
        programData?.cve_match && typeof programData.cve_match === 'object' && !Array.isArray(programData.cve_match)
            ? (programData.cve_match as Record<string, Record<string, unknown>>)
            : {};
    const cveIds = Object.keys(cveMatchObj);
    const activeCveData: Record<string, unknown> | null = activeCveId ? (cveMatchObj[activeCveId] ?? null) : null;
    const cveCount = Number(programData?.cve_count) || 0;
    const severity = programData?.severity as string | undefined;
    const isKev = programData?.has_kev_cve === true || programData?.kev === true;
    const vendorAdvisories = Array.isArray(activeCveData?.vendor_advisories)
        ? (activeCveData.vendor_advisories as string[]).filter((ref) => /^https?:\/\//i.test(ref))
        : [];
    const exploitReferences = Array.isArray(activeCveData?.exploit_references)
        ? (activeCveData.exploit_references as string[]).filter((ref) => /^https?:\/\//i.test(ref))
        : [];

    return (
        <div
            className={`fixed inset-0 z-[100] flex justify-end transition-all duration-300 ${isOpen ? 'visible' : 'invisible pointer-events-none'
                }`}
        >
            <div
                className={`fixed inset-0 bg-slate-900/40 backdrop-blur-sm transition-opacity duration-300 ${isOpen ? 'opacity-100' : 'opacity-0'
                    }`}
                onClick={onClose}
                aria-hidden="true"
            />

            <div
                ref={dialogRef}
                className={`relative w-full sm:w-[480px] bg-white h-full shadow-2xl flex flex-col transform transition-transform duration-300 ease-in-out overflow-hidden ${isOpen ? 'translate-x-0' : 'translate-x-full'
                    }`}
                role="dialog"
                aria-modal="true"
                aria-label={programData?.name ? `${programData.name} details` : 'Program details'}
            >
                <div
                    className="flex w-[200%] h-full transition-transform duration-300 ease-in-out"
                    style={{ transform: activeCveId ? 'translateX(-50%)' : 'translateX(0)' }}
                >

                    {/* ---- SLIDE 1: MAIN PROGRAM DETAILS ---- */}
                    <div ref={slide1Ref} className="w-1/2 h-full flex flex-col relative">
                        <div className="flex items-start gap-3 px-5 py-4 border-b border-slate-100 bg-gradient-to-b from-slate-50/80 to-white">
                            <div className="flex size-10 shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-white text-slate-500 shadow-sm">
                                <Package className="size-5" />
                            </div>
                            <div className="min-w-0 flex-1 pr-2">
                                <h2 className="text-base font-bold text-slate-800 leading-tight break-words">
                                    {String(programData?.name ?? '') || 'Unknown Program'}
                                </h2>
                                {programData?.version ? (
                                    <p className="mt-0.5 font-mono text-xs text-slate-400">v{String(programData.version)}</p>
                                ) : null}
                            </div>
                            <button
                                ref={closeButtonRef}
                                onClick={onClose}
                                aria-label="Close program details"
                                className="flex size-8 shrink-0 items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 active:scale-95"
                            >
                                <X className="size-4" />
                            </button>
                        </div>

                        <div className="flex-1 overflow-y-auto p-5 space-y-5">
                            <div className="grid grid-cols-3 gap-3">
                                <StatTile
                                    label="CVE Count"
                                    value={cveCount}
                                    accent={cveCount > 0 ? 'destructive' : 'neutral'}
                                    icon={Bug}
                                />
                                <StatTile
                                    label="Severity"
                                    value={severity || 'None'}
                                    accent={severity ? severityBadgeVariant(severity) : 'neutral'}
                                    icon={ShieldAlert}
                                />
                                <StatTile
                                    label="CISA KEV"
                                    value={isKev ? 'Yes' : 'No'}
                                    accent={isKev ? 'destructive' : 'neutral'}
                                    icon={Flame}
                                />
                            </div>

                            <div className="space-y-2">
                                {isSnapPackage ? (
                                    <>
                                        <DetailItem label="Channel" value={programData?.channel} icon={GitBranch} />
                                        <DetailItem label="Publisher" value={programData?.publisher} icon={User} />
                                        <DetailItem label="Revision" value={programData?.revision} icon={Hash} />
                                        <DetailItem label="Confinement" value={programData?.confinement} icon={Lock} />
                                        <DetailItem label="Snap Type" value={programData?.snap_type} icon={Box} />
                                        <DetailItem label="Architecture" value={programData?.arch} icon={Cpu} />
                                        <DetailItem label="Origin" value={programData?.origin} icon={Globe} />
                                        <DetailItem label="Install Directory" value={programData?.install_dir} icon={FolderOpen} />
                                        <DetailItem label="Size" value={programData?.size} icon={HardDrive} />
                                        <DetailItem
                                            label="Last Updated"
                                            value={formatToIST(programData?.updated_at, true)}
                                            icon={Clock}
                                        />
                                    </>
                                ) : isDebPackage ? (
                                    <>
                                        <DetailItem label="Maintainer" value={programData?.maintainer} icon={User} />
                                        <DetailItem label="Source package" value={programData?.source} icon={Archive} />
                                        <DetailItem label="Architecture" value={programData?.arch} icon={Cpu} />
                                        <DetailItem label="Section" value={programData?.section} icon={Layers} />
                                        <DetailItem label="Priority" value={programData?.priority} icon={SortDesc} />
                                        <DetailItem label="Status" value={programData?.status} icon={CheckCircle2} />
                                        <DetailItem
                                            label="Installed size"
                                            value={formatDebInstalledSizeKb(programData?.size) ?? programData?.installed_size}
                                            icon={HardDrive}
                                        />
                                        <DetailItem label="Revision" value={programData?.revision} icon={GitBranch} />
                                        <DetailItem label="Admin dir" value={programData?.admindir} icon={FolderTree} />
                                        <DetailItem label="OS major release" value={programData?.major_release_version} icon={Terminal} />
                                        <DetailItem label="Sanitized name" value={programData?.sanitized_name} />
                                        <DetailItem label="Sanitized version" value={programData?.sanitized_version} />
                                        <DetailItem
                                            label="Last reported"
                                            value={formatToIST(programData?.unixtime, true)}
                                            icon={Clock}
                                        />
                                        <div className="grid grid-cols-2 gap-2.5">
                                            <DetailItem label="Is processed" value={programData?.is_processed} />
                                        </div>
                                    </>
                                ) : isRpmPackage ? (
                                    <>
                                        <DetailItem label="Publisher" value={programData?.publisher ?? programData?.vendor} icon={User} />
                                        <DetailItem label="Architecture" value={programData?.arch} icon={Cpu} />
                                        <DetailItem label="Source package" value={programData?.source} icon={Archive} />
                                        <DetailItem label="Release" value={programData?.release} icon={GitBranch} />
                                        <DetailItem label="Epoch" value={programData?.epoch} />
                                        <DetailItem
                                            label="Size"
                                            value={programData?.size ?? programData?.installed_size}
                                            icon={HardDrive}
                                        />
                                        <DetailItem
                                            label="Install Date"
                                            value={formatToIST(programData?.install_date ?? programData?.install_time, true)}
                                            icon={CalendarDays}
                                        />
                                        <DetailItem
                                            label="Last reported"
                                            value={formatToIST(programData?.first_reported_at ?? programData?.unixtime, true)}
                                            icon={Clock}
                                        />
                                        <div className="grid grid-cols-2 gap-2.5">
                                            <DetailItem label="Is Processed" value={programData?.is_processed} />
                                            <DetailItem label="Is CVE Processed" value={programData?.is_cve_processed} />
                                        </div>
                                    </>
                                ) : (
                                    <>
                                        <DetailItem label="Publisher" value={programData?.publisher} icon={User} />
                                        <DetailItem label="Install Date" value={formatToIST(programData?.install_date)} icon={CalendarDays} />
                                        <DetailItem label="First Reported At" value={programData?.first_reported_at} icon={Clock} />
                                        <DetailItem label="Install Location" value={programData?.install_location} icon={FolderOpen} />
                                        <DetailItem label="Install Source" value={programData?.install_source} icon={Download} />
                                        <DetailItem label="Uninstall String" value={programData?.uninstall_string} icon={Trash2} />
                                        <DetailItem label="Language" value={programData?.language} icon={Languages} />
                                        <DetailItem label="Identifying Number" value={programData?.identifying_number} icon={Hash} />
                                        <DetailItem label="CPE String" value={programData?.cpe_string} icon={Barcode} />

                                        <div className="grid grid-cols-2 gap-2.5">
                                            <DetailItem label="Is Processed" value={programData?.is_processed} />
                                            <DetailItem label="Is CVE Processed" value={programData?.is_cve_processed} />
                                        </div>

                                        <DetailItem label="Bundle Name" value={programData?.bundle_name} icon={Box} />
                                        <DetailItem label="Bundle Publisher" value={programData?.bundle_publisher} />
                                        <DetailItem label="Bundle Version" value={programData?.bundle_version} />
                                    </>
                                )}
                            </div>

                            {cveIds.length > 0 && (
                                <div className="pt-4 mt-2 border-t border-slate-100">
                                    <CveVulnerabilityList cveMatchObj={cveMatchObj} onSelectCve={setActiveCveId} />

                                </div>
                            )}
                        </div>
                    </div>

                    {/* ---- SLIDE 2: NESTED CVE DETAILS ---- */}
                    <div ref={slide2Ref} className="w-1/2 h-full flex flex-col relative bg-slate-50">
                        <div className="flex items-center px-4 py-3.5 border-b border-slate-200 bg-white shadow-sm z-10">
                            <button
                                onClick={() => setActiveCveId(null)}
                                className="text-slate-500 hover:text-blue-600 hover:bg-blue-50 px-3 py-1.5 rounded-lg transition-colors flex items-center gap-2 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40"
                            >
                                <ArrowLeft className="size-4" /> Back
                            </button>
                            <h3 className="ml-4 text-base font-bold text-slate-800 truncate">{activeCveId}</h3>
                        </div>

                        <div className="flex-1 overflow-y-auto p-5 space-y-5">
                            {activeCveData ? (
                                <>
                                    {(() => {
                                        const kev = activeCveData.kev as
                                            | {
                                                  in_kev?: boolean;
                                                  vulnerability_name?: string;
                                                  date_added?: string;
                                                  due_date?: string;
                                                  required_action?: string;
                                                  known_ransomware_use?: string;
                                              }
                                            | undefined;
                                        if (!kev?.in_kev) return null;
                                        return (
                                            <div className="rounded-xl border border-red-200 bg-red-50/70 p-3.5 space-y-2.5">
                                                <div className="flex items-center gap-2">
                                                    <div className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-red-600 text-white">
                                                        <Flame className="size-3.5" />
                                                    </div>
                                                    <div className="min-w-0">
                                                        <p className="text-[11px] font-bold uppercase tracking-wider text-red-700">
                                                            CISA Known Exploited Vulnerability
                                                        </p>
                                                        {kev.vulnerability_name && (
                                                            <p className="text-xs font-medium text-red-900 truncate">{kev.vulnerability_name}</p>
                                                        )}
                                                    </div>
                                                </div>
                                                <div className="grid grid-cols-2 gap-2">
                                                    <DetailItem label="Date Added" value={kev.date_added} icon={CalendarDays} />
                                                    <DetailItem label="Remediation Due" value={kev.due_date} icon={Clock} />
                                                </div>
                                                <DetailItem label="Required Action" value={kev.required_action} icon={ShieldAlert} />
                                                <DetailItem label="Known Ransomware Use" value={kev.known_ransomware_use} icon={Bug} />
                                            </div>
                                        );
                                    })()}

                                    <div className="grid grid-cols-2 gap-2.5">
                                        <DetailItem label="Severity" value={activeCveData.severity} />
                                        <DetailItem label="CVSS Score" value={activeCveData.cvss_score} />
                                        <DetailItem label="CVSS Version" value={activeCveData.cvss_version} />
                                        <DetailItem label="CWE" value={activeCveData.cwe} />
                                        <DetailItem label="Attack Vector" value={activeCveData.attack_vector} />
                                        <DetailItem label="Exploit Status" value={activeCveData.exploit_status} />
                                        <DetailItem label="Scope" value={activeCveData.scope} />
                                        <DetailItem label="Privileges Required" value={activeCveData.privileges_required} />
                                        <DetailItem label="User Interaction" value={activeCveData.user_interaction} />
                                        <DetailItem label="Reference Count" value={activeCveData.reference_count} />
                                    </div>

                                    <div>
                                        <h4 className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-1.5">
                                            Description
                                        </h4>
                                        <p className="text-sm text-slate-700 bg-white p-3 rounded-lg border border-slate-200 leading-relaxed whitespace-pre-wrap">
                                            {String(activeCveData.description ?? '') || 'No description available.'}
                                        </p>
                                    </div>

                                    <div className="grid grid-cols-2 gap-2.5">
                                        <DetailItem label="Published Date" value={formatToIST(activeCveData.published, true)} icon={CalendarDays} />
                                        <DetailItem label="Last Modified" value={formatToIST(activeCveData.last_modified, true)} icon={Clock} />
                                    </div>

                                    <DetailItem label="Vector String" value={activeCveData.vector} icon={Code} />

                                    {vendorAdvisories.length > 0 && (
                                        <div>
                                            <h4 className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                                <ShieldCheck className="size-3.5 text-slate-400" /> Vendor Advisories
                                            </h4>
                                            <ul className="space-y-1.5 bg-white p-3 rounded-lg border border-slate-200">
                                                {vendorAdvisories.map((ref: string, idx: number) => (
                                                    <li key={idx} className="text-sm truncate">
                                                        <a href={ref} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                                                            {ref}
                                                        </a>
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}

                                    {exploitReferences.length > 0 && (
                                        <div>
                                            <h4 className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                                <Link2 className="size-3.5 text-slate-400" /> Exploit References
                                            </h4>
                                            <ul className="space-y-1.5 bg-white p-3 rounded-lg border border-slate-200">
                                                {exploitReferences.map((ref: string, idx: number) => (
                                                    <li key={idx} className="text-sm truncate">
                                                        <a href={ref} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                                                            {ref}
                                                        </a>
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}
                                </>
                            ) : (
                                <div className="flex flex-col items-center justify-center h-full text-slate-400">
                                    <Info className="size-8 mb-2" />
                                    <p>No details found.</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

const StatTile = ({
    label,
    value,
    accent,
    icon: Icon,
}: {
    label: string;
    value: string | number;
    accent: NonNullable<BadgeProps['variant']>;
    icon: LucideIcon;
}) => {
    const accentColor: Record<string, string> = {
        destructive: 'text-red-500 bg-red-50 border-red-100',
        warning: 'text-amber-500 bg-amber-50 border-amber-100',
        success: 'text-emerald-500 bg-emerald-50 border-emerald-100',
        info: 'text-blue-500 bg-blue-50 border-blue-100',
        neutral: 'text-slate-400 bg-slate-100 border-slate-200',
    };

    return (
        <div className="rounded-xl border border-slate-100 bg-slate-50/60 p-3">
            <div className="flex items-center justify-between">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
                <div className={cn('flex size-6 items-center justify-center rounded-md border', accentColor[accent])}>
                    <Icon className="size-3.5" />
                </div>
            </div>
            <p className="mt-1.5 text-lg font-bold text-slate-800">{value}</p>
        </div>
    );
};

// Explicit render component for Data Null Handling
const DetailItem = ({ label, value, icon: Icon }: { label: string; value?: unknown; icon?: LucideIcon }) => {
    let displayValue;

    if (value === null || value === undefined || value === '') {
        displayValue = <span className="text-slate-400 italic">Not available</span>;
    } else if (typeof value === 'boolean') {
        displayValue = value ? 'Yes' : 'No';
    } else {
        displayValue = String(value);
    }

    return (
        <div className="flex items-start gap-3 rounded-lg border border-slate-100 bg-slate-50/60 p-2.5">
            {Icon && (
                <div className="flex size-7 shrink-0 items-center justify-center rounded-md border border-slate-200 bg-white text-slate-400">
                    <Icon className="size-3.5" />
                </div>
            )}
            <div className="min-w-0 flex-1">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-black-500">{label}</p>
                <p className="mt-0.5 text-xs font-medium text-slate-800 break-all">{displayValue}</p>
            </div>
        </div>
    );
};

export default ProgramDetailsDrawer;
