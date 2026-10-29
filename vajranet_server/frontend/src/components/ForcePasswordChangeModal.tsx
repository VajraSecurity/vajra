import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { isAxiosError } from 'axios';
import { updatePassword } from '../api/api';
import { useForcePasswordChange } from '../context/useForcePasswordChange';
import { useToast } from '../context/useToast';
import { sanitizeAsciiSingleLine } from '../services/inputSanitizers';

import { EyeIcon, EyeSlashIcon } from "@heroicons/react/24/outline";
import { DuoSpinner } from "@/components/ui/loading";


interface ForcePasswordChangeModalProps {
    isOpen: boolean;
    onPasswordChanged: () => void;
}

export const ForcePasswordChangeModal: React.FC<ForcePasswordChangeModalProps> = ({
    isOpen,
    onPasswordChanged,
}) => {
    const navigate = useNavigate();
    const { setForcePasswordChange } = useForcePasswordChange();
    const { showToast } = useToast();
    const [currentPassword, setCurrentPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [successMessage, setSuccessMessage] = useState<string | null>(null);
    const [showPasswords, setShowPasswords] = useState({
        current: false,
        new: false,
        confirm: false,
    });
    const redirectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    /** ✅ RESET MESSAGES WHEN MODAL OPENS */
    useEffect(() => {
        if (isOpen) {
            setErrorMessage(null);
            setSuccessMessage(null);
        }
    }, [isOpen]);

    /** ✅ CLEAR PENDING REDIRECT TIMER ON UNMOUNT */
    useEffect(() => {
        return () => {
            if (redirectTimeoutRef.current) {
                clearTimeout(redirectTimeoutRef.current);
            }
        };
    }, []);

    const showError = (message: string) => {
        setErrorMessage(message);
        setTimeout(() => setErrorMessage(null), 5000);
    };

    const showSuccess = (message: string) => {
        setSuccessMessage(message);
        setTimeout(() => setSuccessMessage(null), 5000);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        /** ✅ CLEAR OLD MESSAGES BEFORE VALIDATION */
        setErrorMessage(null);
        setSuccessMessage(null);

        // Validation
        if (!currentPassword.trim()) {
            showError('Current password is required');
            return;
        }

        if (!newPassword.trim()) {
            showError('New password is required');
            return;
        }

        if (newPassword.length < 8) {
            showError('New password must be at least 8 characters long');
            return;
        }

        if (newPassword !== confirmPassword) {
            showError('Passwords do not match');
            return;
        }

        if (currentPassword === newPassword) {
            showError('New password must be different from current password');
            return;
        }

        setIsLoading(true);

        try {
            const response = await updatePassword({
                currentPassword,
                newPassword,
                newPasswordConfirm: confirmPassword,
            });

            // Check for both 'Success' and 'success' status (backend returns 'Success')
            if (response.status === 'Success' || response.status === 'success') {
                const msg = response.message || 'Password updated successfully. Please log in again with your new password.';
                showSuccess(msg);
                showToast(msg, 'success');

                localStorage.removeItem('forcePasswordChange');
                setCurrentPassword('');
                setNewPassword('');
                setConfirmPassword('');

                setForcePasswordChange(false);
                try {
                    onPasswordChanged();
                } catch { /* no-op */ }

                // Navigate to /login to force the user to re-authenticate
                redirectTimeoutRef.current = setTimeout(() => {
                    navigate('/login', { replace: true });
                    window.location.reload();
                }, 1500);
            } else {
                showError(response.message || 'Failed to update password');
            }
        } catch (error) {
            if (import.meta.env.DEV) {
                console.error('Error updating password:', error);
            }
            const message = isAxiosError<{ message?: string }>(error) ? error.response?.data?.message : undefined;
            showError(message || 'Error updating password');
        } finally {
            setIsLoading(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4 p-6 md:p-8">

                {/* Error Message */}
                {errorMessage && (
                    <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-800 text-sm">
                        {errorMessage}
                    </div>
                )}

                {/* Success Message */}
                {successMessage && (
                    <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg text-green-800 text-sm">
                        ✅ {successMessage}
                    </div>
                )}

                {/* Form */}
                <form onSubmit={handleSubmit} className="space-y-4">
                    {/* Current Password */}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                            Current Password
                        </label>
                        <div className="relative">
                            <input
                                type={showPasswords.current ? 'text' : 'password'}
                                value={currentPassword}
                                onChange={(e) => setCurrentPassword(sanitizeAsciiSingleLine(e.target.value, 128, false))}
                                disabled={isLoading}
                                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
                                placeholder="Enter your current password"
                            />
                            <button
                                type="button"
                                onClick={() =>
                                    setShowPasswords((prev) => ({
                                        ...prev,
                                        current: !prev.current,
                                    }))
                                }
                                disabled={isLoading}
                                className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg text-gray-500 hover:text-gray-700 disabled:cursor-not-allowed"
                            >
                                {showPasswords.current ? <EyeIcon/> : <EyeSlashIcon/>}
                            </button>
                        </div>
                    </div>

                    {/* New Password */}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                            New Password
                        </label>
                        <div className="relative">
                            <input
                                type={showPasswords.new ? 'text' : 'password'}
                                value={newPassword}
                                onChange={(e) => setNewPassword(sanitizeAsciiSingleLine(e.target.value, 128, false))}
                                disabled={isLoading}
                                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
                                placeholder="Enter new password (min 8 characters)"
                            />
                            <button
                                type="button"
                                onClick={() =>
                                    setShowPasswords((prev) => ({ ...prev, new: !prev.new }))
                                }
                                disabled={isLoading}
                                className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg text-gray-500 hover:text-gray-700 disabled:cursor-not-allowed"
                            >
                                {showPasswords.new ? <EyeIcon/> : <EyeSlashIcon/>}
                            </button>
                        </div>
                    </div>

                    {/* Confirm Password */}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                            Confirm Password
                        </label>
                        <div className="relative">
                            <input
                                type={showPasswords.confirm ? 'text' : 'password'}
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(sanitizeAsciiSingleLine(e.target.value, 128, false))}
                                disabled={isLoading}
                                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
                                placeholder="Confirm new password"
                            />
                            <button
                                type="button"
                                onClick={() =>
                                    setShowPasswords((prev) => ({
                                        ...prev,
                                        confirm: !prev.confirm,
                                    }))
                                }
                                disabled={isLoading}
                                className="absolute right-3 top-1/2 -translate-y-1/2 rounded-lg text-gray-500 hover:text-gray-700 disabled:cursor-not-allowed"
                            >
                                {showPasswords.confirm ? <EyeIcon/> : <EyeSlashIcon/>}
                            </button>
                        </div>
                    </div>

                    {/* Info Box */}
                    <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-sm text-blue-800">
                        ℹ️ For security reasons, you must change your password to continue.
                    </div>

                    {/* Submit Button */}
                    <button
                        type="submit"
                        disabled={isLoading}
                        className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-semibold py-2 px-4 rounded-lg transition-colors duration-200 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                    >
                        {isLoading && <DuoSpinner size="md" />}
                        {isLoading ? 'Updating...' : 'Update Password'}
                    </button>
                </form>
            </div>
        </div>
    );
};