import { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'motion/react';
import { HardDrive, Clock, RefreshCw, AlertTriangle, Plus, Trash2 } from 'lucide-react';
import { getDataRetentionPolicies, deleteDataRetentionPolicy } from '../../api/api';
import { DuoSpinner } from '@/components/ui/loading';
import type { DataRetentionPolicyData } from '../../api/api';
import PolicyBuilderModal from './EditPolicyModal';
import PasswordVerificationModal from '../../components/PasswordVerificationModal';
import { useToast } from '../../context/useToast';
import { useConfirm } from '../../context/useConfirm';

interface DataRetentionProps {
    headerActionsContainer?: HTMLDivElement | null;
}

const DataRetention = ({ headerActionsContainer }: DataRetentionProps) => {
    const { showToast } = useToast();
    const confirm = useConfirm();
    const [policies, setPolicies] = useState<DataRetentionPolicyData[]>([]);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Modal states
    const [isEditModalOpen, setIsEditModalOpen] = useState(false);
    const [policyToEdit, setPolicyToEdit] = useState<DataRetentionPolicyData | null>(null);


    // Authentication state
    const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
    const [isReAuthenticated, setIsReAuthenticated] = useState(false);
    const [pendingAction, setPendingAction] = useState<(() => void) | null>(null);

    const fetchPolicies = async () => {
        try {
            setIsLoading(true);
            const res = await getDataRetentionPolicies();
            if (res.success) {
                setPolicies(res.data);
            } else {
                setError('Failed to load policies.');
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Error loading policies.');
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchPolicies();
    }, []);

    const describeRetention = (policy: DataRetentionPolicyData) => {
        if (policy.retentionType === 'row_count') {
            return policy.rowCountLimit == null ? 'retain forever' : policy.rowCountLimit === 0 ? 'purges immediately' : `max ${policy.rowCountLimit.toLocaleString()} rows`;
        }
        return policy.retentionDays == null ? 'retain forever' : policy.retentionDays === 0 ? 'purges immediately' : `${policy.retentionDays} days`;
    };

    const handleDeleteClick = async (policy: DataRetentionPolicyData) => {
        const action = async () => {
            const tableList = policy.tableNames?.length ? policy.tableNames.join(', ') : 'no tables';
            const confirmed = await confirm({
                title: `Delete this retention policy?`,
                description: `Tables: ${tableList}. Current setting: ${describeRetention(policy)}. Scheduled cleanup for these tables will stop — this does not delete any existing data.`,
                confirmLabel: 'Delete',
                variant: 'danger',
            });
            if (!confirmed) return;
            try {
                await deleteDataRetentionPolicy(policy.id);
                showToast('Policy deleted successfully', 'success');
                fetchPolicies();
            } catch (err) {
                showToast(err instanceof Error ? err.message : 'Failed to delete policy', 'error');
            }
        };

        if (!isReAuthenticated) {
            setPendingAction(() => action);
            setIsAuthModalOpen(true);
        } else {
            action();
        }
    };

    const handleCreateClick = () => {
        setPolicyToEdit(null);
        if (!isReAuthenticated) {
            setPendingAction(() => () => setIsEditModalOpen(true));
            setIsAuthModalOpen(true);
        } else {
            setIsEditModalOpen(true);
        }
    };

    const handleEditClick = (policy: DataRetentionPolicyData) => {
        setPolicyToEdit(policy);
        if (!isReAuthenticated) {
            setPendingAction(() => () => setIsEditModalOpen(true));
            setIsAuthModalOpen(true);
        } else {
            setIsEditModalOpen(true);
        }
    };

    const handleAuthSuccess = () => {
        setIsAuthModalOpen(false);
        setIsReAuthenticated(true);
        showToast('Authentication verified.', 'success');
        
        if (pendingAction) {
            pendingAction();
            setPendingAction(null);
        }
        
        // Expire re-auth after 5 minutes
        setTimeout(() => setIsReAuthenticated(false), 5 * 60 * 1000);
    };

    const handlePolicyUpdateSuccess = () => {
        setIsEditModalOpen(false);
        fetchPolicies();
        showToast('Data retention policy updated successfully.', 'success');
    };

    const actionButtons = (
        <>
            <span className="bg-slate-100/10 text-white px-3 py-1.5 rounded-lg text-sm font-semibold border border-white/20">
                {policies.length} Configured
            </span>
            <button
                onClick={handleCreateClick}
                className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 transition-colors shadow-sm"
            >
                <Plus className="w-4 h-4" />
                Create Policy
            </button>
            <button
                onClick={fetchPolicies}
                className="inline-flex items-center gap-2 rounded-lg bg-white/10 border border-white/20 px-4 py-2 text-sm font-semibold text-white hover:bg-white/20 transition-colors shadow-sm"
            >
                <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
                Refresh
            </button>
        </>
    );

    return (
        <div className="flex-1 relative min-h-full">
            {headerActionsContainer && createPortal(actionButtons, headerActionsContainer)}

            {/* Content Area */}
            {isLoading ? (
                <div className="flex items-center justify-center py-20">
                    <DuoSpinner size="lg" className="text-blue-500" />
                </div>
            ) : error ? (
                <div className="bg-red-50 border border-red-100 rounded-xl p-8 text-center text-red-600 shadow-sm max-w-2xl mx-auto mt-10">
                    <AlertTriangle className="w-10 h-10 mx-auto mb-4 text-red-400" />
                    <h3 className="text-lg font-semibold mb-1">Failed to load policies</h3>
                    <p className="text-sm">{error}</p>
                </div>
            ) : (
                <motion.div 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.1 }}
                    className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm"
                >


                    {policies.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-24 text-center px-6">
                            <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mb-4 border border-slate-200">
                                <HardDrive className="w-8 h-8 text-slate-400" />
                            </div>
                            <h3 className="text-lg font-semibold text-slate-800 mb-2">No policies configured</h3>
                            <p className="text-slate-500 max-w-sm mb-6">
                                Data retention allows you to automatically purge old logs and history to keep your database lean.
                            </p>
                            <button
                                onClick={handleCreateClick}
                                className="inline-flex items-center gap-2 rounded-xl bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-blue-700 transition-colors shadow-sm"
                            >
                                <Plus className="w-4 h-4" />
                                Create First Policy
                            </button>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-separate border-spacing-0">
                            <thead>
                                <tr className="bg-white border-b border-slate-200">
                                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider w-[50%] sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Table Name</th>
                                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider w-[18%] sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Retention Period</th>
                                    <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider w-[18%] sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Schedule</th>
                                    <th className="px-6 py-4 text-xs font-semibold text-right text-slate-500 uppercase tracking-wider w-[14%] sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                <AnimatePresence>
                                    {policies.map((policy, idx) => (
                                        <motion.tr
                                            key={policy.id}
                                            initial={{ opacity: 0, y: 10 }}
                                            animate={{ opacity: 1, y: 0 }}
                                            transition={{ delay: idx * 0.05 }}
                                            className="hover:bg-blue-50/30 transition-colors group"
                                        >
                                            <td className="px-6 py-4">
                                                <div className="flex flex-wrap gap-1">
                                                    {policy.tableNames?.map(name => (
                                                        <span key={name} className="inline-flex items-center px-2 py-0.5 rounded bg-indigo-50 border border-indigo-100 text-indigo-700 text-xs font-mono font-medium">
                                                            {name}
                                                        </span>
                                                    ))}
                                                </div>
                                            </td>
                                            <td className="px-6 py-4">
                                                {policy.retentionType === 'row_count' ? (
                                                    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold ${
                                                        policy.rowCountLimit == null
                                                            ? 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                                                            : policy.rowCountLimit === 0
                                                                ? 'bg-red-100 text-red-700 border border-red-200'
                                                                : 'bg-indigo-100 text-indigo-700 border border-indigo-200'
                                                    }`}>
                                                        {policy.rowCountLimit == null ? 'Retain Forever' : policy.rowCountLimit === 0 ? 'Purges Immediately (0 rows kept)' : `Max ${policy.rowCountLimit.toLocaleString()} Rows`}
                                                    </span>
                                                ) : (
                                                    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold ${
                                                        policy.retentionDays == null
                                                            ? 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                                                            : policy.retentionDays === 0
                                                                ? 'bg-red-100 text-red-700 border border-red-200'
                                                                : 'bg-amber-100 text-amber-700 border border-amber-200'
                                                    }`}>
                                                        {policy.retentionDays == null ? 'Retain Forever' : policy.retentionDays === 0 ? 'Purges Immediately (0 days kept)' : `${policy.retentionDays} Days`}
                                                    </span>
                                                )}
                                            </td>
                                            <td className="px-6 py-4">
                                                <div className="flex flex-col gap-0.5 text-sm text-slate-600 font-medium">
                                                    <div className="flex items-center gap-2">
                                                        <Clock className="w-4 h-4 text-slate-400" />
                                                        <span className="capitalize">{policy.scheduleType}</span>
                                                    </div>
                                                    <span 
                                                        className="text-xs text-slate-400 font-mono ml-6 cursor-help" 
                                                        title="Standard Cron Expression (Minute, Hour, Day of Month, Month, Day of Week)"
                                                    >
                                                        {policy.cronExpression}
                                                    </span>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 text-right">
                                                <div className="flex justify-end gap-2">
                                                    <button
                                                        onClick={() => handleEditClick(policy)}
                                                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-600 hover:text-blue-600 rounded-lg transition-colors text-sm border border-slate-200 hover:border-blue-200 shadow-sm font-medium"
                                                    >
                                                        Edit
                                                    </button>
                                                    <button
                                                        onClick={() => handleDeleteClick(policy)}
                                                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white hover:bg-red-50 text-slate-600 hover:text-red-600 rounded-lg transition-colors text-sm border border-slate-200 hover:border-red-200 shadow-sm font-medium"
                                                    >
                                                        <Trash2 className="w-3.5 h-3.5" />
                                                        Delete
                                                    </button>
                                                </div>
                                            </td>
                                        </motion.tr>
                                    ))}
                                </AnimatePresence>
                            </tbody>
                        </table>
                    </div>
                )}
            </motion.div>
        )}

            {/* Modals */}
            <PasswordVerificationModal 
                isOpen={isAuthModalOpen} 
                onClose={() => setIsAuthModalOpen(false)} 
                onSuccess={handleAuthSuccess}
                title="Security Verification Required"
                description="Modifying data retention policies carries significant risk of data loss. Please re-authenticate to confirm your identity."
            />

            <PolicyBuilderModal
                isOpen={isEditModalOpen}
                onClose={() => setIsEditModalOpen(false)}
                onSuccess={handlePolicyUpdateSuccess}
                editPolicy={policyToEdit}
            />
        </div>
    );
};

export default DataRetention;
