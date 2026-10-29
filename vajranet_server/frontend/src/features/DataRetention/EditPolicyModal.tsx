import { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { isAxiosError } from 'axios';
import { X, Save, AlertCircle, Database, ChevronDown, Check } from 'lucide-react';
import { createDataRetentionPolicy, updateDataRetentionPolicy, getTables } from '../../api/api';
import type { DataRetentionPolicyData, CreateDataRetentionRequest } from '../../api/api';
import { DuoSpinner } from '@/components/ui/loading';
import { useModalA11y } from '../../hooks/useModalA11y';
import { useConfirm } from '../../context/useConfirm';

// Rejects scientific notation (e.g. "1e3") that parseInt would silently read as 1,
// which for a retention/row-count field would purge far more data than intended.
function getErrorMessage(err: unknown, fallback: string): string {
    if (isAxiosError<{ message?: string }>(err)) {
        return err.response?.data?.message || fallback;
    }
    return err instanceof Error ? err.message : fallback;
}

const parseStrictInt = (v: string): number | null => {
    if (!/^\d+$/.test(v.trim())) return null;
    return parseInt(v, 10);
};

// Plain-language descriptions for the tables a compliance officer is most likely to
// encounter when building a retention policy, so the selector isn't just a list of
// bare internal table names. Sourced from this app's own ORM entity definitions
// (backend/src/orm/entities/fleet) -- not exhaustive, since getTables() reflects
// whatever tables exist in the target database, but covers the tables this app owns.
const TABLE_DESCRIPTIONS: Record<string, string> = {
    certin_compliance_results: 'Per-device CERT-In compliance check results',
    certin_historical_compliance: 'Historical CERT-In compliance score snapshots',
    irdai_compliance_results: 'Per-device IRDAI compliance check results',
    irdai_historical_compliance: 'Historical IRDAI compliance score snapshots',
    sebi_compliance_results: 'Per-device SEBI compliance check results',
    sebi_historical_compliance: 'Historical SEBI compliance score snapshots',
    compliance_results: 'General compliance check results',
    historical_compliance: 'Historical overall compliance score snapshots',
    burpsuite_configs: 'Burp Suite scanner configuration settings',
    burpsuite_scan_history: 'Burp Suite web application scan history',
    nessus_configs: 'Nessus scanner configuration settings',
    openvas_configs: 'OpenVAS scanner configuration settings',
    nuclei_scan_history: 'Nuclei vulnerability scan history',
    network_scan_history: 'Network vulnerability scan history and results',
    scan_schedules: 'Scheduled scan job definitions',
    domain_reputation_check_results: 'Domain reputation check results',
    domain_reputation_provider_configs: 'Domain reputation provider configuration',
    domain_reputation_targets: 'Monitored domains for reputation checks',
    agent_cert_provisioning_tokens: 'Agent certificate provisioning tokens',
    node_assignment_rules: 'Device group assignment rules',
    nodes_groups: 'Device group definitions',
    policies: 'Compliance/security policy definitions',
    patch_jobs: 'Patch deployment job records',
    patch_bundles: 'Patch bundle definitions',
    patch_job_nodes: 'Per-device patch job status records',
    patch_available_updates: 'Available software update records per device',
    pending_patch_commands: 'Patch commands queued for agents',
    saved_queries: 'Saved osquery query definitions',
};

interface PolicyBuilderModalProps {
    isOpen: boolean;
    onClose: () => void;
    onSuccess: (policy: DataRetentionPolicyData) => void;
    editPolicy?: DataRetentionPolicyData | null;
}

const PolicyBuilderModal = ({ isOpen, onClose, onSuccess, editPolicy }: PolicyBuilderModalProps) => {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Form State
    const [database, setDatabase] = useState<string>('fleet');
    const [tableNames, setTableNames] = useState<string[]>([]);
    const [timestampColumn, setTimestampColumn] = useState<string>('unixtime');
    const [retentionType, setRetentionType] = useState<'time' | 'row_count'>('time');
    const [retentionDays, setRetentionDays] = useState<string>('');
    const [rowCountLimit, setRowCountLimit] = useState<string>('');
    const [scheduleType, setScheduleType] = useState<'daily' | 'weekly' | 'monthly' | 'custom'>('daily');
    const [cleanupTime, setCleanupTime] = useState('00:00');
    const [cronExpression, setCronExpression] = useState('0 0 * * *');
    const [isTableDropdownOpen, setIsTableDropdownOpen] = useState(false);

    useEffect(() => {
        if (isOpen) {
            if (editPolicy) {
                setDatabase(editPolicy.databaseName);
                setTableNames(editPolicy.tableNames || []);
                setTimestampColumn(editPolicy.timestampColumn || 'unixtime');
                setRetentionType(editPolicy.retentionType || 'time');
                setRetentionDays(editPolicy.retentionDays != null ? editPolicy.retentionDays.toString() : '');
                setRowCountLimit(editPolicy.rowCountLimit != null ? editPolicy.rowCountLimit.toString() : '');
                setScheduleType(editPolicy.scheduleType || 'daily');
                setCleanupTime(editPolicy.cleanupTime || '00:00');
                setCronExpression(editPolicy.cronExpression || '0 0 * * *');
            } else {
                setDatabase('fleet');
                setTableNames([]);
                setTimestampColumn('unixtime');
                setRetentionType('time');
                setRetentionDays('');
                setRowCountLimit('');
                setScheduleType('daily');
                setCleanupTime('00:00');
                setCronExpression('0 0 * * *');
            }
        }
    }, [isOpen, editPolicy]);

    // Dynamic Lists
    const [tables, setTables] = useState<string[]>([]);

    // `tables` is the full reflected table list of the target database and can
    // run to hundreds of entries, while this dropdown re-renders on every
    // checkbox toggle. As an array, `tableNames` costs an includes() twice per
    // sort comparison plus once per row; a Set makes each lookup O(1), and the
    // useMemo keeps the sort to actual input changes. The comparator ends in a
    // localeCompare tiebreak, so the ordering is total and stable.
    const selectedTableNames = useMemo(() => new Set(tableNames), [tableNames]);
    const sortedTables = useMemo(
        () => [...tables].sort((a, b) => {
            const aSelected = selectedTableNames.has(a);
            const bSelected = selectedTableNames.has(b);
            if (aSelected && !bSelected) return -1;
            if (!aSelected && bSelected) return 1;
            return a.localeCompare(b);
        }),
        [tables, selectedTableNames],
    );

    // getTables() has no AbortSignal support, and this modal stays mounted (just
    // returns null) across open/close cycles, so a stale response for a previously
    // edited policy's database can otherwise arrive after and overwrite the table
    // list for the policy now being edited. Guard with a request sequence number.
    const tablesRequestSeq = useRef(0);

    useEffect(() => {
        if (database && isOpen) {
            const seq = ++tablesRequestSeq.current;
            getTables(database).then(res => {
                if (seq !== tablesRequestSeq.current) return; // stale response, a newer request is in flight
                setTables(res.data);
                if (res.data.length > 0 && !editPolicy) setTableNames([]); // Reset selection when DB changes only if not editing
            }).catch(console.error);
        }
    }, [database, isOpen, editPolicy]);

    useEffect(() => {
        // Auto-generate cron for standard types
        if (editPolicy && scheduleType === editPolicy.scheduleType && cleanupTime === editPolicy.cleanupTime) {
            return; // keep existing cron if not changed from edit
        }
        const [hh, mm] = cleanupTime.split(':');
        if (scheduleType === 'daily') setCronExpression(`${mm || '0'} ${hh || '0'} * * *`);
        else if (scheduleType === 'weekly') setCronExpression(`${mm || '0'} ${hh || '0'} * * 0`);
        else if (scheduleType === 'monthly') setCronExpression(`${mm || '0'} ${hh || '0'} 1 * *`);
    }, [scheduleType, cleanupTime, editPolicy]);

    // useModalA11y's Escape handler is registered on `document` in the capture
    // phase (see useModalA11y.ts), so it always fires before any bubble-phase
    // handler further down the tree (e.g. a keydown on the table dropdown's
    // wrapper div) ever gets a chance to run — that bubble handler is dead code.
    // To make Escape collapse just the table dropdown instead of closing the
    // whole modal, intercept at the onClose callback useModalA11y itself invokes.
    // isTableDropdownOpenRef mirrors isTableDropdownOpen so this always reads the
    // live value even though useModalA11y's effect (and the closure it captures)
    // only (re)runs when `isOpen` changes, not on every render.
    const isTableDropdownOpenRef = useRef(false);
    useEffect(() => {
        isTableDropdownOpenRef.current = isTableDropdownOpen;
    }, [isTableDropdownOpen]);

    const modalRef = useModalA11y<HTMLDivElement>(isOpen, () => {
        if (isTableDropdownOpenRef.current) {
            setIsTableDropdownOpen(false);
            return;
        }
        onClose();
    });
    const confirm = useConfirm();

    // Parsed live values, used both for the inline zero-value warning and for the
    // tightening/immediate-purge confirmation checks below. Recomputed on every
    // render from current form state, so both usages always agree.
    const parsedRetentionDays = retentionType === 'time' && retentionDays !== '' ? parseStrictInt(retentionDays) : null;
    const parsedRowCountLimit = retentionType === 'row_count' && rowCountLimit !== '' ? parseStrictInt(rowCountLimit) : null;

    if (!isOpen) return null;

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        if (retentionType === 'time' && retentionDays !== '' && parsedRetentionDays === null) {
            setError('Retention days must be a whole number.');
            return;
        }
        if (retentionType === 'row_count' && rowCountLimit !== '' && parsedRowCountLimit === null) {
            setError('Row count limit must be a whole number.');
            return;
        }

        // Shrinking retention (vs. the value already saved) purges more data on the
        // next scheduled run — confirm before submitting, same as the delete flow.
        const isTighteningRetention = !!editPolicy && (
            (retentionType === 'time' && editPolicy.retentionDays != null && parsedRetentionDays != null && parsedRetentionDays < editPolicy.retentionDays) ||
            (retentionType === 'row_count' && editPolicy.rowCountLimit != null && parsedRowCountLimit != null && parsedRowCountLimit < editPolicy.rowCountLimit) ||
            (retentionType === 'time' && editPolicy.retentionDays == null && parsedRetentionDays != null) ||
            (retentionType === 'row_count' && editPolicy.rowCountLimit == null && parsedRowCountLimit != null)
        );
        // A brand-new policy saved with a 0 value purges everything on its very first
        // run — just as dangerous as tightening an existing policy down to 0, so it
        // gets the same confirmation gate even though there's no prior value to compare against.
        const isImmediatePurge =
            (retentionType === 'time' && parsedRetentionDays === 0) ||
            (retentionType === 'row_count' && parsedRowCountLimit === 0);
        const needsConfirmation = isTighteningRetention || (!editPolicy && isImmediatePurge);
        if (needsConfirmation) {
            const confirmed = await confirm({
                title: editPolicy ? 'Reduce this retention policy?' : 'Create an immediate-purge policy?',
                description: editPolicy
                    ? 'Rows older than the new limit will be purged on the next scheduled cleanup run. This cannot be undone.'
                    : 'This policy keeps nothing — every matching row will be purged on the very first scheduled run. This cannot be undone.',
                confirmLabel: editPolicy ? 'Reduce & Save' : 'Create Policy',
                variant: 'danger',
            });
            if (!confirmed) return;
        }

        setLoading(true);
        try {
            const payload: CreateDataRetentionRequest = {
                databaseName: database,
                tableNames,
                timestampColumn,
                retentionType,
                retentionDays: parsedRetentionDays,
                rowCountLimit: parsedRowCountLimit,
                scheduleType,
                cronExpression,
                cleanupTime
            };
            const response = editPolicy
                ? await updateDataRetentionPolicy(editPolicy.id, payload)
                : await createDataRetentionPolicy(payload);

            if (response.success) {
                onSuccess(response.data);
            } else {
                setError(response.message || 'Failed to save policy');
            }
        } catch (err) {
            setError(getErrorMessage(err, 'Error creating policy'));
        } finally {
            setLoading(false);
        }
    };

    const toggleTableSelection = (table: string) => {
        setTableNames(prev =>
            prev.includes(table) ? prev.filter(t => t !== table) : [...prev, table]
        );
    };

    return (
        <AnimatePresence>
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
                <div className="absolute inset-0 bg-slate-900/60 backdrop-blur-sm" onClick={onClose} />
                <motion.div
                    ref={modalRef}
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="edit-policy-modal-title"
                    initial={{ opacity: 0, scale: 0.95, y: 10 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.95, y: 10 }}
                    className="relative w-full max-w-2xl bg-white rounded-2xl shadow-2xl border border-slate-200 overflow-hidden"
                >
                    {/* Header */}
                    <div className="px-6 py-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-blue-100 flex items-center justify-center text-blue-600">
                                <Database className="w-5 h-5" />
                            </div>
                            <div>
                                <h2 id="edit-policy-modal-title" className="text-lg font-bold text-slate-800">{editPolicy ? 'Edit Policy' : 'Create Policy'}</h2>
                                <p className="text-sm text-slate-500">Define dynamic data retention rules</p>
                            </div>
                        </div>
                        <button onClick={onClose} className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded-full transition-colors">
                            <X className="w-5 h-5" />
                        </button>
                    </div>

                    {/* Content */}
                    <form onSubmit={handleSubmit} className="p-6">
                        {error && (
                            <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 flex items-start gap-3">
                                <AlertCircle className="w-5 h-5 mt-0.5 flex-shrink-0" />
                                <p className="text-sm font-medium">{error}</p>
                            </div>
                        )}

                        <div className="grid grid-cols-2 gap-6 mb-6">
                            {/* DB & Table */}
                            <div className="relative col-span-2">
                                <label id="table-selector-label" htmlFor="table-selector-trigger" className="block text-sm font-semibold text-slate-700 mb-1">Table(s)</label>
                                <p className="text-xs text-slate-500 mb-1">Choose the tables this policy purges or retains data from. Descriptions are shown below each table name where available.</p>
                                <button
                                    type="button"
                                    id="table-selector-trigger"
                                    aria-haspopup="listbox"
                                    aria-expanded={isTableDropdownOpen}
                                    className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors bg-white cursor-pointer flex items-center justify-between min-h-[42px] text-left"
                                    onClick={() => setIsTableDropdownOpen(!isTableDropdownOpen)}
                                >
                                    <div className="flex-1 truncate pr-4 text-sm">
                                        {tableNames.length === 0
                                            ? <span className="text-slate-400">Select tables...</span>
                                            : <span className="text-slate-800">{tableNames.length} table{tableNames.length > 1 ? 's' : ''} selected</span>
                                        }
                                    </div>
                                    <ChevronDown className="w-4 h-4 text-slate-400 flex-shrink-0" />
                                </button>

                                <AnimatePresence>
                                    {isTableDropdownOpen && (
                                        <>
                                            <div className="fixed inset-0 z-40" onClick={() => setIsTableDropdownOpen(false)} />
                                            <motion.div
                                                initial={{ opacity: 0, y: -5 }}
                                                animate={{ opacity: 1, y: 0 }}
                                                exit={{ opacity: 0, y: -5 }}
                                                role="listbox"
                                                aria-multiselectable="true"
                                                aria-labelledby="table-selector-label"
                                                className="absolute z-50 w-full mt-1 bg-white border border-slate-200 rounded-lg shadow-xl max-h-60 overflow-y-auto"
                                            >
                                                {sortedTables.map(t => {
                                                    const isSelected = selectedTableNames.has(t);
                                                    return (
                                                        <button
                                                            key={t}
                                                            type="button"
                                                            role="option"
                                                            aria-selected={isSelected}
                                                            onClick={() => toggleTableSelection(t)}
                                                            className="w-full flex items-center gap-3 px-3 py-2 hover:bg-slate-50 cursor-pointer border-b border-slate-50 last:border-0 text-left focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500"
                                                        >
                                                            <div className={`w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 transition-colors ${isSelected ? 'bg-blue-600 border-blue-600' : 'border-slate-300'}`}>
                                                                {isSelected && <Check className="w-3 h-3 text-white" />}
                                                            </div>
                                                            <div className="min-w-0 flex-1">
                                                                <span className="block text-sm text-slate-700 font-mono truncate">{t}</span>
                                                                <span className="block text-xs text-slate-400 truncate">{TABLE_DESCRIPTIONS[t] || 'No description available'}</span>
                                                            </div>
                                                        </button>
                                                    );
                                                })}
                                                {tables.length === 0 && (
                                                    <div className="p-3 text-sm text-slate-500 text-center">No tables available</div>
                                                )}
                                            </motion.div>
                                        </>
                                    )}
                                </AnimatePresence>
                            </div>



                            {/* Retention Type & Limit */}
                            <div className="col-span-2 grid grid-cols-2 gap-6 p-4 bg-slate-50 border border-slate-200 rounded-xl">
                                <div>
                                    <label className="block text-sm font-semibold text-slate-700 mb-1">Retention Strategy</label>
                                    <div className="flex bg-white border border-slate-300 rounded-lg p-1">
                                        <button
                                            type="button"
                                            onClick={() => setRetentionType('time')}
                                            className={`flex-1 px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${retentionType === 'time' ? 'bg-blue-100 text-blue-700 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
                                        >
                                            Time Based
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => setRetentionType('row_count')}
                                            className={`flex-1 px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${retentionType === 'row_count' ? 'bg-blue-100 text-blue-700 shadow-sm' : 'text-slate-500 hover:text-slate-700'}`}
                                        >
                                            Row Count Limit
                                        </button>
                                    </div>
                                    <p className="text-xs text-slate-500 mt-2">
                                        {retentionType === 'time' 
                                            ? "Delete records older than X days." 
                                            : "Keep only the newest X records. Delete the rest."}
                                    </p>
                                </div>
                                
                                <div>
                                    {retentionType === 'time' ? (
                                        <>
                                            <label className="block text-sm font-semibold text-slate-700 mb-1">Retention Period (Days)</label>
                                            <input
                                                type="number"
                                                min="0"
                                                value={retentionDays}
                                                onChange={(e) => setRetentionDays(e.target.value)}
                                                placeholder="e.g. 180 (Empty = keep forever)"
                                                className="w-full px-3 py-2 border border-slate-300 bg-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                                            />
                                            {parsedRetentionDays === 0 && (
                                                <p className="mt-1 text-xs font-semibold text-red-600">
                                                    0 days means every row is purged immediately on each run — this is not the same as "keep forever."
                                                </p>
                                            )}
                                            {/* Advisory only: the server enforces the floor and can lower it per deployment. */}
                                            <p className="mt-1 text-xs text-slate-500">
                                                CERT-In 4.2/5.7 require logs of ICT systems to be retained for a minimum of 180 days
                                                unless the CISO has specified otherwise, so shorter periods are rejected.
                                            </p>
                                        </>
                                    ) : (
                                        <>
                                            <label className="block text-sm font-semibold text-slate-700 mb-1">Maximum Rows to Keep</label>
                                            <input
                                                type="number"
                                                min="0"
                                                value={rowCountLimit}
                                                onChange={(e) => setRowCountLimit(e.target.value)}
                                                placeholder="e.g. 100000 (Empty = keep forever)"
                                                className="w-full px-3 py-2 border border-slate-300 bg-white rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                                            />
                                            {parsedRowCountLimit === 0 && (
                                                <p className="mt-1 text-xs font-semibold text-red-600">
                                                    0 rows means every row is purged immediately on each run — this is not the same as "keep forever."
                                                </p>
                                            )}
                                        </>
                                    )}
                                </div>
                            </div>

                            {/* Schedule Type */}
                            <div>
                                <label className="block text-sm font-semibold text-slate-700 mb-1">Schedule Type</label>
                                <select 
                                    value={scheduleType} 
                                    onChange={e => setScheduleType(e.target.value as 'daily' | 'weekly' | 'monthly' | 'custom')}
                                    className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                                >
                                    <option value="daily">Daily</option>
                                    <option value="weekly">Weekly</option>
                                    <option value="monthly">Monthly</option>
                                    <option value="custom">Custom (Cron)</option>
                                </select>
                            </div>
                            
                            {/* Schedule Input */}
                            <div>
                                {scheduleType === 'custom' ? (
                                    <>
                                        <label className="block text-sm font-semibold text-slate-700 mb-1">Cron Expression</label>
                                        <input
                                            type="text"
                                            value={cronExpression}
                                            onChange={(e) => setCronExpression(e.target.value)}
                                            placeholder="* * * * *"
                                            className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors font-mono text-sm"
                                        />
                                    </>
                                ) : (
                                    <>
                                        <label className="block text-sm font-semibold text-slate-700 mb-1">Cleanup Time</label>
                                        <input
                                            type="time"
                                            value={cleanupTime}
                                            onChange={(e) => setCleanupTime(e.target.value)}
                                            className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                                        />
                                    </>
                                )}
                            </div>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-100">
                            <button
                                type="button"
                                onClick={onClose}
                                disabled={loading}
                                className="px-5 py-2.5 text-sm font-semibold text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-xl transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                type="submit"
                                disabled={loading || tableNames.length === 0 || !timestampColumn}
                                className="px-5 py-2.5 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition-colors flex items-center gap-2 disabled:opacity-50"
                            >
                                {loading ? (
                                    <DuoSpinner size="sm" className="text-white" />
                                ) : (
                                    <Save className="w-4 h-4" />
                                )}
                                Save Policy
                            </button>
                        </div>
                    </form>
                </motion.div>
            </div>
        </AnimatePresence>
    );
};

export default PolicyBuilderModal;
