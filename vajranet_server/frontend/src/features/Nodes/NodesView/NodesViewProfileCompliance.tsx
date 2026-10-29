/**
 * NodesView Profile Compliance tab: Windows security profile information.
 * API: nodesViewApi.getSecurityProfileInfo
 */

import { useState, useEffect } from 'react';
import { isAxiosError } from 'axios';
import type { NodeData } from './types';
import { DuoSpinner } from '@/components/ui/loading';
import { nodesViewApi } from './nodesViewApi';
import { motion } from 'motion/react';
import {Meteors} from '@/components/ui/meteors';
import { InfoTooltip } from './components/InfoTooltip';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

interface NodesViewProfileComplianceProps {
  node: NodeData;
}

interface SecurityProfileData {
  id: string;
  host_identifier: string;
  unixtime: string;
  minimum_password_age: number;
  maximum_password_age: number;
  minimum_password_length: number;
  password_complexity: number;
  password_history_size: number;
  lockout_bad_count: number;
  logon_to_change_password: number;
  force_logoff_when_expire: number;
  new_administrator_name: string;
  new_guest_name: string;
  clear_text_password: number;
  lsa_anonymous_name_lookup: number;
  enable_admin_account: number;
  enable_guest_account: number;
  audit_system_events: number;
  audit_logon_events: number;
  audit_object_access: number;
  audit_privilege_use: number;
  audit_policy_change: number;
  audit_account_manage: number;
  audit_process_tracking: number;
  audit_ds_access: number;
  audit_account_logon: number;
}

const NodesViewProfileCompliance = ({ node }: NodesViewProfileComplianceProps) => {
  const [profileData, setProfileData] = useState<SecurityProfileData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const hostId = node.host_identifier || String(node.id);

  useEffect(() => {
    let cancelled = false;
    const loadProfileInfo = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await nodesViewApi.getSecurityProfileInfo(hostId);
        if (!cancelled) {
          if (res.data.status === 'Success' && res.data.data && res.data.data.length > 0) {
            setProfileData(res.data.data[0]);
          } else {
            setError(res.data.message || 'No security profile information found');
          }
        }
      } catch (err: unknown) {
        if (!cancelled) {
          console.error('Failed to fetch security profile info:', err);
          setError(getErrorMessage(err, 'Failed to fetch security profile information'));
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };
    loadProfileInfo();
    return () => {
      cancelled = true;
    };
  }, [hostId]);

  const renderBooleanValue = (value: number) => {
    const isEnabled = value === 1 || value > 0;
    return (
      <span
        className={`px-2 py-1 rounded text-xs font-medium ${isEnabled ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
          }`}
      >
        {isEnabled ? 'Enabled' : 'Disabled'}
      </span>
    );
  };

  const renderNumericValue = (value: number | string) => {
    return <span className="font-mono text-gray-800">{value}</span>;
  };

  const formatTimestamp = (unixtime: string) => {
    try {
      const timestamp = parseInt(unixtime, 10);
      if (isNaN(timestamp)) return unixtime;
      const date = new Date(timestamp * 1000);
      return date.toLocaleString();
    } catch {
      return unixtime;
    }
  };

  if (loading) {
    return (
      <div className="p-4">
        <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
          <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100">
            <h6 className="font-semibold text-gray-800">Security Profile Information</h6>
          </div>
          <div className="flex items-center justify-center py-12">
            <DuoSpinner size="lg" className="text-blue-500" />
          </div>
        </div>
      </div>
    );
  }

  if (error || !profileData) {
    return (
      <div className="p-4">
        <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
          <div className="px-4 py-3 bg-gradient-to-r from-blue-50 to-cyan-50 border-b border-blue-100">
            <h6 className="font-semibold text-gray-800">Security Profile Information</h6>
          </div>
          <div className="p-4">
            <div className="text-sm p-3 rounded-lg bg-red-50 text-red-700 border border-red-200">
              {error || 'No security profile information available'}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="px-4 pb-4 space-y-4">
      {/* Metadata Card */}
      {/* Sebi Header Card */}
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
              Profile Metadata
            </h2>
            <div className="flex items-center justify-between">
              <div className="grid grid-cols-3 gap-4">
              {(
                  <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                    <p className="text-blue-200 text-xs mb-1">Device Name</p>
                    <p className="text-sm font-semibold text-white">{node.hostname || node.name || hostId}</p>
                  </div>
                )
              }
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                <p className="text-blue-200 text-xs mb-1">Host Identifier</p>
                <p className="text-sm font-semibold text-white">{profileData.host_identifier}</p>
              </div>
              <div className="bg-white/10 backdrop-blur-sm rounded-lg p-3 border border-white/10">
                <p className="text-blue-200 text-xs mb-1">Last Updated</p>
                <p className="text-sm font-semibold text-white">{formatTimestamp(profileData.unixtime)}</p>
              </div>
              </div>
              <div className="flex flex-col gap-2">
            </div>
            </div>
          </div>
        </motion.div>

      {/* Password Policy Card */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Password Policy Card */}
        <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
          <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-blue-200">
            <h6 className="font-semibold text-white">Password Policies</h6>
          </div>
          <div className="p-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm border-separate border-spacing-0">
                <thead>
                  <tr className="border-b border-gray-200 text-left text-gray-600 font-medium">
                    <th className="py-2 pr-4 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Policy</th>
                    <th className="py-2 pr-4 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Value</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Minimum Password Age
                      <InfoTooltip text="Minimum number of days a user must wait before changing their password again." />
                    </td>
                    <td className="py-2 pr-4">{renderNumericValue(profileData.minimum_password_age)} days</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Maximum Password Age
                      <InfoTooltip text="Maximum number of days a password can be used before Windows requires the user to change it." />
                    </td>
                    <td className="py-2 pr-4">{renderNumericValue(profileData.maximum_password_age)} days</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Minimum Password Length
                      <InfoTooltip text="Minimum number of characters required when a user sets a new password." />
                    </td>
                    <td className="py-2 pr-4">{renderNumericValue(profileData.minimum_password_length)} characters</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Password Complexity
                      <InfoTooltip text="Whether new passwords must mix uppercase, lowercase, numbers, and special characters." />
                    </td>
                    <td className="py-2 pr-4">{renderBooleanValue(profileData.password_complexity)}</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Password History Size
                      <InfoTooltip text="Number of previous passwords Windows remembers, to stop a user from reusing them." />
                    </td>
                    <td className="py-2 pr-4">{renderNumericValue(profileData.password_history_size)} passwords</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Lockout Bad Count
                      <InfoTooltip text="Number of failed login attempts allowed before the account is automatically locked out." />
                    </td>
                    <td className="py-2 pr-4">{renderNumericValue(profileData.lockout_bad_count)} attempts</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Logon to Change Password
                      <InfoTooltip text="Whether a user must be logged on locally before they are allowed to change their own password." />
                    </td>
                    <td className="py-2 pr-4">{renderBooleanValue(profileData.logon_to_change_password)}</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Force Logoff When Logon Hours Expire
                      <InfoTooltip text="Whether users are automatically disconnected once their allowed logon hours end (Windows Security Option: 'Force logoff when logon hours expire')." />
                    </td>
                    <td className="py-2 pr-4">{renderBooleanValue(profileData.force_logoff_when_expire)}</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Clear Text Password
                      <InfoTooltip text="Whether passwords are stored in a reversible, readable format instead of being securely hashed. Should normally be Disabled." />
                    </td>
                    <td className="py-2 pr-4">{renderBooleanValue(profileData.clear_text_password)}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Account Settings Card */}
        <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
          <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-blue-200">
            <h6 className="font-semibold text-white">Account Settings</h6>
          </div>
          <div className="p-4">
            <div className="overflow-x-auto">
              <table className="w-full text-sm border-separate border-spacing-0">
                <thead>
                  <tr className="border-b border-gray-200 text-left text-gray-600 font-medium">
                    <th className="py-2 pr-4 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Setting</th>
                    <th className="py-2 pr-4 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Value</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Administrator Name
                      <InfoTooltip text="Current name of the built-in Administrator account. Renaming it away from the default makes it harder for attackers to target." />
                    </td>
                    <td className="py-2 pr-4 font-mono text-gray-800">{profileData.new_administrator_name}</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Guest Name
                      <InfoTooltip text="Current name of the built-in Guest account." />
                    </td>
                    <td className="py-2 pr-4 font-mono text-gray-800">{profileData.new_guest_name}</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Enable Admin Account
                      <InfoTooltip text="Whether the built-in local Administrator account is active on this device." />
                    </td>
                    <td className="py-2 pr-4">{renderBooleanValue(profileData.enable_admin_account)}</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      Enable Guest Account
                      <InfoTooltip text="Whether the built-in Guest account is active on this device." />
                    </td>
                    <td className="py-2 pr-4">{renderBooleanValue(profileData.enable_guest_account)}</td>
                  </tr>
                  <tr className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-2 pr-4 text-gray-700">
                      LSA Anonymous Name Lookup
                      <InfoTooltip text="Whether anonymous, unauthenticated users can look up account and share names on this device (LSA = Windows Local Security Authority)." />
                    </td>
                    <td className="py-2 pr-4">{renderBooleanValue(profileData.lsa_anonymous_name_lookup)}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Audit Policies Card */}
      <div className="bg-white rounded-xl border border-blue-100 overflow-hidden">
        <div className="px-4 py-3 bg-gradient-to-br from-teal-700 to-teal-600 border-b border-blue-200">
          <h6 className="font-semibold text-white">Audit Policies</h6>
        </div>
        <div className="p-4">
          <div className="overflow-x-auto">
            <table className="w-full text-sm border-separate border-spacing-0">
              <thead>
                <tr className="border-b border-gray-200 text-left text-gray-600 font-medium">
                  <th className="py-2 pr-4 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Audit Category</th>
                  <th className="py-2 pr-4 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Status</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-700">
                    System Events
                    <InfoTooltip text="Whether Windows logs system startup, shutdown, and security log changes." />
                  </td>
                  <td className="py-2 pr-4">{renderBooleanValue(profileData.audit_system_events)}</td>
                </tr>
                <tr className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-700">
                    Logon Events
                    <InfoTooltip text="Whether Windows logs user logon and logoff activity on this device." />
                  </td>
                  <td className="py-2 pr-4">{renderBooleanValue(profileData.audit_logon_events)}</td>
                </tr>
                <tr className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-700">
                    Object Access
                    <InfoTooltip text="Whether Windows logs access to protected files, folders, and other securable objects." />
                  </td>
                  <td className="py-2 pr-4">{renderBooleanValue(profileData.audit_object_access)}</td>
                </tr>
                <tr className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-700">
                    Privilege Use
                    <InfoTooltip text="Whether Windows logs use of sensitive user rights, such as taking ownership of files." />
                  </td>
                  <td className="py-2 pr-4">{renderBooleanValue(profileData.audit_privilege_use)}</td>
                </tr>
                <tr className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-700">
                    Policy Change
                    <InfoTooltip text="Whether Windows logs changes to user rights, audit policies, and trust relationships." />
                  </td>
                  <td className="py-2 pr-4">{renderBooleanValue(profileData.audit_policy_change)}</td>
                </tr>
                <tr className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-700">
                    Account Management
                    <InfoTooltip text="Whether Windows logs creation, deletion, and changes to user and group accounts." />
                  </td>
                  <td className="py-2 pr-4">{renderBooleanValue(profileData.audit_account_manage)}</td>
                </tr>
                <tr className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-700">
                    Process Tracking
                    <InfoTooltip text="Whether Windows logs process creation and termination on this device." />
                  </td>
                  <td className="py-2 pr-4">{renderBooleanValue(profileData.audit_process_tracking)}</td>
                </tr>
                <tr className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-700">
                    Directory Service Access
                    <InfoTooltip text="Whether Windows logs access to Active Directory objects." />
                  </td>
                  <td className="py-2 pr-4">{renderBooleanValue(profileData.audit_ds_access)}</td>
                </tr>
                <tr className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-2 pr-4 text-gray-700">
                    Account Logon
                    <InfoTooltip text="Whether Windows logs authentication events processed by the domain controller." />
                  </td>
                  <td className="py-2 pr-4">{renderBooleanValue(profileData.audit_account_logon)}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NodesViewProfileCompliance;
