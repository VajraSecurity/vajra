import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { isAxiosError } from 'axios';
import { sanitizeUserForCache } from '../../services/auth';
import { updatePassword, disableMfaSettings, getProfile } from '../../api/api';
import { motion } from "motion/react";
import { EyeIcon, EyeSlashIcon } from "@heroicons/react/24/outline";
import { sanitizeAsciiSingleLine } from '../../services/inputSanitizers';
import { Meteors } from "@/components/ui/meteors";
import MfaSetupModal from "./mfa/MfaSetupModal";
import { useModalA11y } from "../../hooks/useModalA11y";

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ errorMessage?: string }>(err)) {
    return err.response?.data?.errorMessage || fallback;
  }
  return fallback;
}

interface SettingToggleProps {
  label: string;
  description: string;
  checked: boolean;
  onChange: () => void;
}

// Declared at module scope rather than inside Settings(): as a nested arrow it
// got a fresh function identity on every Settings render, so React treated each
// of the four toggles as a different component type and unmounted/remounted the
// whole row (and its <button>) on every keystroke in the profile forms above.
function SettingToggle({ label, description, checked, onChange }: SettingToggleProps) {
  return (
    <div className="flex items-center justify-between py-4">
      <div className="flex-1">
        <h4 className="text-sm font-medium text-gray-900">{label}</h4>
        <p className="text-sm text-gray-500">{description}</p>
      </div>
      <button
        onClick={onChange}
        role="switch"
        aria-checked={checked}
        aria-label={label}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${checked ? "bg-blue-600" : "bg-gray-200"
          }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${checked ? "translate-x-6" : "translate-x-1"
            }`}
        />
      </button>
    </div>
  );
}

function ChangePasswordModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const modalRef = useModalA11y<HTMLDivElement>(isOpen, onClose);
  const [showOldPwd, setShowOldPwd] = useState(false);
  const [showNewPwd, setShowNewPwd] = useState(false);
  const [showConfirmPwd, setShowConfirmPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [formData, setFormData] = useState({
    oldPassword: "",
    newPassword: "",
    confirmPassword: "",
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    const nextValue = sanitizeAsciiSingleLine(value, 128, false);
    setFormData((prev) => ({ ...prev, [name]: nextValue }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);

    if (formData.newPassword !== formData.confirmPassword) {
      setMessage({ type: 'error', text: "New passwords don't match." });
      setLoading(false);
      return;
    }

    try {
      const response = await updatePassword({
        currentPassword: formData.oldPassword,
        newPassword: formData.newPassword,
        newPasswordConfirm: formData.confirmPassword,
      });

      if (response.status === "Success" || response.status === "success") {
        setMessage({ type: 'success', text: "Password changed successfully. You will be logged out to re-authenticate." });
        setTimeout(() => {
          onClose();
          setFormData({ oldPassword: "", newPassword: "", confirmPassword: "" });
          setMessage(null);

          // Clear frontend auth state and force login
          window.location.href = '/login';
        }, 2000);
      } else {
        setMessage({ type: 'error', text: response.message || "Failed to update password" });
      }
    } catch (error) {
      setMessage({ type: 'error', text: getErrorMessage(error, "Failed to update password. Please try again.") });
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <motion.div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="change-password-title"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className="bg-white rounded-xl shadow-2xl p-6 max-w-md w-full"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 id="change-password-title" className="text-2xl font-bold text-gray-900">Change Password</h2>
          <button onClick={onClose} aria-label="Close" className="rounded-lg text-gray-400 hover:text-gray-600 transition-colors">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {message && (
          <div
            className={`text-center mb-4 font-medium p-3 rounded-lg ${message.type === 'success'
              ? "bg-green-100 text-green-700"
              : "bg-red-100 text-red-700"
              }`}
          >
            {message.text}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          {["oldPassword", "newPassword", "confirmPassword"].map((key) => (
            <div key={key} className="relative">
              <label htmlFor={key} className="block mb-2 text-sm font-medium text-gray-700">
                {key === "oldPassword"
                  ? "Old Password"
                  : key === "newPassword"
                    ? "New Password"
                    : "Confirm New Password"}
              </label>
              <input
                id={key}
                type={
                  (key === "oldPassword" && showOldPwd) ||
                    (key === "newPassword" && showNewPwd) ||
                    (key === "confirmPassword" && showConfirmPwd)
                    ? "text"
                    : "password"
                }
                name={key}
                value={formData[key as keyof typeof formData]}
                onChange={handleChange}
                placeholder="••••••••"
                required
                autoComplete={key === "oldPassword" ? "current-password" : "new-password"}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg pr-10 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 outline-none transition-all"
              />
              <button
                type="button"
                onClick={() =>
                  key === "oldPassword"
                    ? setShowOldPwd(!showOldPwd)
                    : key === "newPassword"
                      ? setShowNewPwd(!showNewPwd)
                      : setShowConfirmPwd(!showConfirmPwd)
                }
                aria-label={
                  (key === "oldPassword" && showOldPwd) ||
                    (key === "newPassword" && showNewPwd) ||
                    (key === "confirmPassword" && showConfirmPwd)
                    ? "Hide password"
                    : "Show password"
                }
                className="absolute right-3 top-9 rounded-lg text-gray-500 hover:text-gray-700"
              >
                {(key === "oldPassword" && showOldPwd) ||
                  (key === "newPassword" && showNewPwd) ||
                  (key === "confirmPassword" && showConfirmPwd) ? (
                  <EyeSlashIcon className="h-5 w-5" />
                ) : (
                  <EyeIcon className="h-5 w-5" />
                )}
              </button>
            </div>
          ))}

          <div className="flex space-x-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 bg-blue-600 text-white font-semibold py-2 rounded-lg hover:bg-blue-700 disabled:opacity-70 transition-all"
            >
              {loading ? "Updating..." : "Update Password"}
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
}

// Disable MFA modal
function DisableMfaModal({ isOpen, onClose, onSuccess }: { isOpen: boolean; onClose: () => void; onSuccess: () => void }) {
  const modalRef = useModalA11y<HTMLDivElement>(isOpen, onClose);
  const [showPwd, setShowPwd] = useState(false);
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage(null);

    try {
      const response = await disableMfaSettings(password);
      if (response.status === "Success" || response.status === "success") {
        setMessage({ type: 'success', text: "MFA disabled successfully." });
        setTimeout(() => {
          onSuccess();
          onClose();
          setPassword("");
          setMessage(null);
        }, 1500);
      } else {
        setMessage({ type: 'error', text: response.message || "Failed to disable MFA" });
      }
    } catch (error) {
      setMessage({ type: 'error', text: getErrorMessage(error, "Failed to disable MFA. Please try again.") });
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <motion.div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="disable-mfa-title"
        initial={{ scale: 0.9, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className="bg-white rounded-xl shadow-2xl p-6 max-w-md w-full"
      >
        <div className="flex items-center justify-between mb-6">
          <h2 id="disable-mfa-title" className="text-2xl font-bold text-gray-900">Disable Two-Factor Auth</h2>
          <button onClick={onClose} aria-label="Close" className="rounded-lg text-gray-400 hover:text-gray-600 transition-colors">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {message && (
          <div className={`text-center mb-4 font-medium p-3 rounded-lg ${message.type === 'success' ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
            {message.text}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <p className="text-sm text-gray-600">
            Please enter your password to confirm that you want to disable Two-Factor Authentication. All your backup codes will be invalidated.
          </p>

          <div className="relative">
            <label htmlFor="disable-mfa-password" className="block mb-2 text-sm font-medium text-gray-700">Password</label>
            <input
              id="disable-mfa-password"
              type={showPwd ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(sanitizeAsciiSingleLine(e.target.value, 128, false))}
              placeholder="••••••••"
              required
              autoComplete="current-password"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg pr-10 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 outline-none transition-all"
            />
            <button
              type="button"
              onClick={() => setShowPwd(!showPwd)}
              aria-label={showPwd ? "Hide password" : "Show password"}
              className="absolute right-3 top-9 text-gray-500 hover:text-gray-700"
            >
              {showPwd ? <EyeSlashIcon className="h-5 w-5" /> : <EyeIcon className="h-5 w-5" />}
            </button>
          </div>

          <div className="flex space-x-3 pt-2">
            <button type="button" onClick={onClose} className="flex-1 px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors font-medium">Cancel</button>
            <button type="submit" disabled={loading || !password} className="flex-1 bg-red-600 text-white font-semibold py-2 rounded-lg hover:bg-red-700 disabled:opacity-70 transition-all">
              {loading ? "Disabling..." : "Disable MFA"}
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
}

export default function Settings() {
  const navigate = useNavigate();
  const [settings, setSettings] = useState({
    emailNotifications: true,
    pushNotifications: false,
    twoFactorAuth: false,
    auditAlerts: true,
  });
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [showMfaModal, setShowMfaModal] = useState(false);
  const [showDisableMfaModal, setShowDisableMfaModal] = useState(false);

  useEffect(() => {
    // Load saved settings from localStorage if they exist
    const savedSettings = localStorage.getItem('userSettings');
    let parsedSettings = null;
    if (savedSettings) {
      try {
        parsedSettings = JSON.parse(savedSettings);
        setSettings(parsedSettings);
      } catch (err) {
        if (import.meta.env.DEV) {
          console.error('Invalid userSettings in localStorage, resetting.', err);
        }
        localStorage.removeItem('userSettings');
      }
    }

    // Force sync the MFA toggle state from the real backend profile
    const syncProfileMfaState = async () => {
      try {
        const response = await getProfile();
        if (response?.data && response.data.mfa_enabled !== undefined) {
          const mfaEnabled = response.data.mfa_enabled;
          setSettings(prev => {
            const updated = { ...prev, twoFactorAuth: mfaEnabled };
            localStorage.setItem("userSettings", JSON.stringify(updated));
            return updated;
          });
          localStorage.setItem("user", JSON.stringify(sanitizeUserForCache(response.data)));
        }
      } catch (err) {
        if (import.meta.env.DEV) {
          console.error("Failed to sync MFA profile state", err);
        }
      }
    };
    syncProfileMfaState();
  }, [navigate]);

  // Handle toggles
  const handleToggle = (key: string) => {
    if (key === 'twoFactorAuth') {
      if (!settings.twoFactorAuth) {
        setShowMfaModal(true);
      } else {
        setShowDisableMfaModal(true);
      }
      return;
    }
    const newSettings = { ...settings, [key]: !settings[key as keyof typeof settings] };
    setSettings(newSettings);
    localStorage.setItem("userSettings", JSON.stringify(newSettings));
  };

  const handleMfaSuccess = () => {
    const newSettings = { ...settings, twoFactorAuth: true };
    setSettings(newSettings);
    localStorage.setItem("userSettings", JSON.stringify(newSettings));
  };

  const handleMfaDisableSuccess = () => {
    const newSettings = { ...settings, twoFactorAuth: false };
    setSettings(newSettings);
    localStorage.setItem("userSettings", JSON.stringify(newSettings));
  };


  return (
    <div className="min-h-screen bg-[#f8f9fb]">
      {/* Password Change Modal */}
      <ChangePasswordModal isOpen={showPasswordModal} onClose={() => setShowPasswordModal(false)} />

      {/* MFA Setup Modal */}
      <MfaSetupModal isOpen={showMfaModal} onClose={() => setShowMfaModal(false)} onSuccess={handleMfaSuccess} />
      <DisableMfaModal isOpen={showDisableMfaModal} onClose={() => setShowDisableMfaModal(false)} onSuccess={handleMfaDisableSuccess} />

      {/* Header */}
      <div className="max-w-full mx-auto px-4 sm:px-6 lg:px-8 pt-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 mb-5"
          style={{
            background:
              "linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)",
          }}
        >
          <Meteors
            number={30}
            className="!bg-white before:!from-white before:!to-transparent"
          />

          <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white">Settings</h1>
              <p className="mt-1 text-sm text-blue-100">
                Manage your account security and alert preferences
              </p>
            </div>

            <button
              type="button"
              onClick={() => navigate('/dashboard')}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/20 bg-white/10 backdrop-blur-sm px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-all hover:bg-white/20"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              Back to Dashboard
            </button>
          </div>
        </motion.div>
      </div>

      {/* Main Content */}
      <div className="max-w-[100%] mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">

        {/* Row 1: Alert Notifications & Security */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Alert Notifications */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-white rounded-xl shadow-lg p-6 border border-blue-100"
          >
            <div className="flex items-center space-x-3 mb-6">
              <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
                </svg>
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900">Alert Notifications</h2>
                <p className="text-sm text-gray-500">Control how you receive security alerts</p>
              </div>
            </div>

            <p className="text-xs text-gray-400 mb-4">
              These preferences are saved to this browser only and are not yet synced to your account or organization.
            </p>

            <div className="divide-y divide-gray-200">
              <SettingToggle
                label="Email Threat Alerts"
                description="Receive email notifications when threats are detected on your endpoints"
                checked={settings.emailNotifications}
                onChange={() => handleToggle('emailNotifications')}
              />
              <SettingToggle
                label="Push Notifications"
                description="Get real-time push alerts on your device for critical security events"
                checked={settings.pushNotifications}
                onChange={() => handleToggle('pushNotifications')}
              />
              <SettingToggle
                label="Audit Event Alerts"
                description="Get notified when important audit events or policy violations are logged"
                checked={settings.auditAlerts}
                onChange={() => handleToggle('auditAlerts')}
              />
            </div>
          </motion.div>

          {/* Security Settings */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-white rounded-xl shadow-lg p-6 border border-blue-100"
          >
            <div className="flex items-center space-x-3 mb-6">
              <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <div>
                <h2 className="text-xl font-bold text-gray-900">Security</h2>
                <p className="text-sm text-gray-500">Harden your account access controls</p>
              </div>
            </div>

            <div className="divide-y divide-gray-200">
              <SettingToggle
                label="Two-Factor Authentication"
                description="Require a second verification step every time you sign in"
                checked={settings.twoFactorAuth}
                onChange={() => handleToggle('twoFactorAuth')}
              />
              <div className="py-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <h4 className="text-sm font-medium text-gray-900">Change Password</h4>
                    <p className="text-sm text-gray-500">Rotate your credentials regularly to stay secure</p>
                  </div>
                  <motion.button
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={() => setShowPasswordModal(true)}
                    className="px-4 py-2 bg-gradient-to-r from-blue-500 to-cyan-500 text-white rounded-lg hover:from-blue-600 hover:to-cyan-600 transition-colors text-sm font-medium shadow-md"
                  >
                    Change
                  </motion.button>
                </div>
              </div>
            </div>
          </motion.div>

        </div>

      </div>
    </div>
  );
}
