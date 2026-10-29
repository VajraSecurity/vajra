import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { isAxiosError } from 'axios';
import { verifyPassword } from '../api/api';
import { InlineSpinner } from '@/components/ui/loading';

interface PasswordVerificationModalProps {
    isOpen: boolean;
    onClose: () => void;
    onSuccess: (token: string) => void;
    title?: string;
    description?: React.ReactNode;
}

const PasswordVerificationModal: React.FC<PasswordVerificationModalProps> = ({ 
    isOpen, 
    onClose, 
    onSuccess, 
    title = "Authentication Required", 
    description = "Please enter your password to proceed." 
}) => {
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    if (!isOpen) return null;

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!password) {
            setError('Password is required');
            return;
        }
        setLoading(true);
        setError(null);
        try {
            const res = await verifyPassword(password);
            onSuccess(res.shell_token || '');
            setPassword(''); // clear password on success
        } catch (err) {
            const message = isAxiosError<{ message?: string }>(err) ? err.response?.data?.message : undefined;
            setError(message || (err instanceof Error ? err.message : 'Invalid password'));
        } finally {
            setLoading(false);
        }
    };

    return (
        <AnimatePresence>
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95, y: 10 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.95, y: 10 }}
                    className="bg-white rounded-2xl shadow-xl border border-slate-200 w-full max-w-md overflow-hidden"
                >
                    <div className="p-6">
                        <div className="w-12 h-12 rounded-xl bg-blue-100 text-blue-600 flex items-center justify-center mb-4">
                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                            </svg>
                        </div>
                        <h2 className="text-xl font-bold text-slate-900">{title}</h2>
                        <div className="text-sm text-slate-500 mt-1">
                            {description}
                        </div>

                        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-slate-700 mb-1">Password</label>
                                <input
                                    type="password"
                                    autoFocus
                                    className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="Enter your password"
                                    disabled={loading}
                                />
                                {error && <p className="mt-1.5 text-sm text-red-600 font-medium">{error}</p>}
                            </div>

                            <div className="flex items-center justify-end gap-3 pt-2">
                                <button
                                    type="button"
                                    onClick={onClose}
                                    disabled={loading}
                                    className="px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 rounded-lg transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors flex items-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed"
                                >
                                    {loading ? (
                                        <InlineSpinner text="Verifying..." size="sm" />
                                    ) : (
                                        'Verify'
                                    )}
                                </button>
                            </div>
                        </form>
                    </div>
                </motion.div>
            </div>
        </AnimatePresence>
    );
};

export default PasswordVerificationModal;
