import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "motion/react";
import { isAxiosError } from 'axios';
import { getProfile, updateProfile } from '../../api/api';
import { sanitizeAsciiMultiLine, sanitizeAsciiSingleLine } from '../../services/inputSanitizers';
import { sanitizeUserForCache } from '../../services/auth';
import ProfileSetup from '../../components/kokonutui/avatar-picker';
import { Meteors } from '../../components/ui/meteors';
import { InlineSpinner } from '@/components/ui/loading';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || err.message || fallback;
  }
  return err instanceof Error ? err.message : fallback;
}

export default function UpdateProfile() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    company: "",
    mobile: "",
    address: "",
    bio: "",
    website: "",
    linkedin: "",
    twitter: "",
  });

  useEffect(() => {


    const fetchProfile = async () => {
      try {
        const res = await getProfile(); // Cookie-based GET
        if (import.meta.env.DEV) {
          console.log("Profile API response:", res);
        }


        if (res?.data) {
          const user = res.data;

          setFormData({
            name: user.name || "",
            email: user.email || "", // Optional if returned later
            company: user.company || "",
            mobile: user.mobile || "",
            address: user.address || "",
            bio: user.bio || "",
            website: user.website || "",
            linkedin: user.linkedin || "",
            twitter: user.twitter || "",
          });
        }
      } catch (err) {
        if (import.meta.env.DEV) {
          console.error("Error fetching profile:", err);
        }
        setError("Failed to load profile. Please try again.");
      }
    };

    fetchProfile();
  }, []); // Empty dependency array - only fetch on mount


  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    const nextValue = (() => {
      switch (name) {
        case 'email':
          return sanitizeAsciiSingleLine(value, 254, true);
        case 'name':
          return sanitizeAsciiSingleLine(value, 64, true);
        case 'company':
          return sanitizeAsciiSingleLine(value, 128, true);
        case 'mobile':
          // store strict E.164 in state (e.g. +14155552671). If you want formatting, normalize on submit instead.
          return sanitizeAsciiSingleLine(value, 16, true).replace(/[^0-9+]/g, '');
        case 'address':
          return sanitizeAsciiSingleLine(value, 256, true);
        case 'bio':
          return sanitizeAsciiMultiLine(value, 500, false);
        case 'website':
        case 'linkedin':
        case 'twitter':
          return sanitizeAsciiSingleLine(value, 300, true);
        default:
          return sanitizeAsciiSingleLine(value, 300, true);
      }
    })();
    setFormData({ ...formData, [name]: nextValue });
  };

  //Submit updated data
  const handleSubmit = async (e: { preventDefault: () => void }) => {
    e.preventDefault();
    setLoading(true);
    setSuccess(false);
    setError(null);

    try {
      const res = await updateProfile({
        name: formData.name.trim(),
        email: formData.email.trim(),
        company: formData.company.trim(),
        mobile: formData.mobile.trim(),
        address: formData.address.trim(),
      });

      // Merge into the cached user rather than replacing it: the update
      // response only carries the edited fields, not id/role/avatar.
      if (res?.data) {
        const storedUser = JSON.parse(localStorage.getItem("user") ?? "null");
        localStorage.setItem("user", JSON.stringify(sanitizeUserForCache({ ...storedUser, ...res.data })));

        setFormData((prev) => ({
          ...prev,
          ...res.data,
        }));
      }

      setSuccess(true);

      // Redirect after success
      setTimeout(() => navigate("/dashboard"), 1500);
    } catch (err) {
      setError(getErrorMessage(err, "Failed to update profile. Please try again."));
    } finally {
      setLoading(false);
      setTimeout(() => setSuccess(false), 3000);
    }
  };


  return (
    <div className="min-h-screen bg-[#f8f9fb]">
      {/* Header */}

      {/* Main Content */}
      <div className="max-w-[100%] mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Account Information — Meteors banner */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-xl shadow-lg p-6 text-white mb-6"
          style={{ background: "rgb(4 34 119)" }}
        >
          <Meteors number={25} className="!bg-white before:!from-white before:!to-transparent" />
          <div className="relative z-10">
            <h2 className="text-xl font-bold mb-4 flex items-center text-white">
              <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
              </svg>
              Account Information
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                <p className="text-blue-200 text-xs mb-1">Full Name</p>
                <p className="text-sm font-semibold text-white">{formData.name || 'Not set'}</p>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                <p className="text-blue-200 text-xs mb-1">Email Address</p>
                <p className="text-sm font-semibold text-white truncate">{formData.email || 'Not set'}</p>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                <p className="text-blue-200 text-xs mb-1">Company</p>
                <p className="text-sm font-semibold text-white">{formData.company || 'Not specified'}</p>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                <p className="text-blue-200 text-xs mb-1">Mobile</p>
                <p className="text-sm font-semibold text-white">{formData.mobile || 'Not specified'}</p>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                <p className="text-blue-200 text-xs mb-1">Address</p>
                <p className="text-sm font-semibold text-white truncate">{formData.address || 'Not specified'}</p>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                <p className="text-blue-200 text-xs mb-1">Member Since</p>
                {/* The profile endpoint doesn't return an account creation date, so
                    there's no real value to show here yet — a fixed date would be
                    fabricated for every user. Show an honest fallback instead. */}
                <p className="text-sm font-semibold text-white">Not available</p>
              </div>
            </div>
          </div>
        </motion.div>
        <motion.form
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          onSubmit={handleSubmit}
          className="space-y-6"
        >
          {/* Success Message */}
          {success && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              role="status"
              aria-live="polite"
              className="bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded-lg flex items-center space-x-2"
            >
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
              <span>Profile updated successfully!</span>
            </motion.div>
          )}

          {/* Error Message */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              role="status"
              aria-live="polite"
              className="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg flex items-center space-x-2"
            >
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              <span>{error}</span>
            </motion.div>
          )}

          {/* Basic Information & Social Links Side by Side */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Basic Information */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="bg-white rounded-xl shadow-lg p-6 border border-blue-100"
            >
              <div className="flex items-center space-x-3 mb-6">
                <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                  <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-gray-900">Basic Information</h2>
                  <p className="text-sm text-gray-500">Update your personal details</p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Full Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                    required
                    className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    placeholder="John Doe"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Email Address
                  </label>
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    placeholder="john@example.com"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Company
                  </label>
                  <input
                    type="text"
                    name="company"
                    value={formData.company}
                    onChange={handleChange}
                    className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    placeholder="Acme Inc."
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Mobile Number
                  </label>
                  <input
                    type="tel"
                    name="mobile"
                    value={formData.mobile}
                    onChange={handleChange}
                    className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    placeholder="+1 (555) 000-0000"
                  />
                </div>

                <div className="sm:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Address
                  </label>
                  <input
                    type="text"
                    name="address"
                    value={formData.address}
                    onChange={handleChange}
                    className="w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    placeholder="123 Main St, City, Country"
                  />
                </div>

                <div className="sm:col-span-2">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Bio
                  </label>
                  {/* Disabled: the backend profile endpoint has no bio column/field, so
                      anything typed here can never be persisted. Leaving it editable would
                      let users "save" an edit that is silently dropped. */}
                  <textarea
                    name="bio"
                    value={formData.bio}
                    onChange={handleChange}
                    disabled
                    rows={3}
                    className="w-full px-4 py-2.5 border border-gray-300 rounded-lg bg-gray-50 text-gray-500 cursor-not-allowed resize-none"
                    placeholder="Tell us about yourself..."
                  />
                  <p className="mt-1 text-xs text-gray-400">Bio isn't saved yet — coming soon.</p>
                </div>
              </div>
            </motion.div>

            {/* Avatar Picker — sized to its own content, not stretched to
                match the taller Basic Information card (that's what was
                pushing the picker down into a huge empty gap above it). */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="bg-white rounded-xl shadow-lg p-6 border border-blue-100 lg:self-start"
            >
              <div className="flex items-center space-x-3 mb-6">
                <div className="w-10 h-10 bg-indigo-100 rounded-lg flex items-center justify-center">
                  <svg className="w-6 h-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0z" />
                  </svg>
                </div>
                <div>
                  <h2 className="text-xl font-bold text-gray-900">Choose Avatar</h2>
                  <p className="text-sm text-gray-500">Pick one — updates instantly in the sidebar</p>
                </div>
              </div>
              {/* Persists selection itself (per-user, via lib/avatarStorage) */}
              <div className="flex justify-center">
                <ProfileSetup showUsername={false} />
              </div>
            </motion.div>

          </div>

          {/* Action Buttons */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4 }}
            className="flex items-center justify-end space-x-4"
          >
            <button
              type="button"
              onClick={() => navigate('/dashboard')}
              className="px-6 py-3 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors font-medium"
            >
              Cancel
            </button>
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              type="submit"
              disabled={loading}
              className="px-8 py-3 bg-gradient-to-r from-blue-500 to-cyan-500 text-white rounded-lg hover:from-blue-600 hover:to-cyan-600 transition-all font-medium shadow-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
            >
              {loading ? (
                <InlineSpinner text="Saving..." size="md" />
              ) : (
                <>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  <span>Save Changes</span>
                </>
              )}
            </motion.button>
          </motion.div>
        </motion.form>
      </div>
    </div>
  );
}
