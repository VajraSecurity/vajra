import { useEffect, useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Link, useSearchParams } from 'react-router-dom';
import { isAxiosError } from 'axios';
import {
  getTeamMembers,
  transferTeamOwnership,
  updateTeamMember,
  forcePasswordChangeTeam,
  fetchEndpointGroups,
} from '../../api/api';
import type { FormEvent } from 'react';
import type { TeamMember, TeamMemberUpdateRequest, UserRole, EndpointGroup } from '../../api/api';
import { useToast } from '../../context/useToast';
import { getStoredUser, sanitizeUserForCache } from '../../services/auth';
import { useConfirm } from '../../context/useConfirm';
import DataRetention from '../DataRetention/index';
import EndpointManagementTab from '../Management/EndpointManagementTab';
import { Meteors } from '@/components/ui/meteors';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  if (err instanceof Error) return err.message || fallback;
  return fallback;
}

const ROLE_OPTIONS: UserRole[] = ['Super Administrator', 'Group Admin', 'Viewer'];
const ROLE_PRIORITY: Record<UserRole, number> = {
  'Super Administrator': 0,
  'Group Admin': 1,
  Viewer: 2,
};
const TEAM_CSS = `
.metallic-btn-blue {
  background: linear-gradient(135deg, rgba(37, 99, 235, 0.95) 0%, rgba(29, 78, 216, 1) 100%) !important;
  color: white !important;
  border-color: rgba(37, 99, 235, 0.4) !important;
  border-bottom-color: rgba(30, 58, 138, 0.6) !important;
  box-shadow: 
    0 2px 8px rgba(37, 99, 235, 0.25),
    inset 0 1px 1px rgba(255, 255, 255, 0.35),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2) !important;
  position: relative;
  overflow: hidden;
  transition: all 0.2s ease;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3) !important;
}

.metallic-btn-blue:hover:not(:disabled) {
  box-shadow: 
    0 4px 12px rgba(37, 99, 235, 0.4),
    inset 0 1px 1px rgba(255, 255, 255, 0.45),
    inset 0 -1px 1px rgba(0, 0, 0, 0.25) !important;
  background: linear-gradient(135deg, rgba(59, 130, 246, 1) 0%, rgba(37, 99, 235, 1) 100%) !important;
  transform: translateY(-1px);
}

.metallic-btn-blue:active:not(:disabled) {
  transform: translateY(1px) !important;
  box-shadow: 
    0 1px 2px rgba(0, 0, 0, 0.2),
    inset 0 2px 4px rgba(0, 0, 0, 0.3) !important;
}

.metallic-btn-blue:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none !important;
}

.metallic-btn-yellow {
  background: linear-gradient(135deg, rgba(245, 158, 11, 0.95) 0%, rgba(217, 119, 6, 1) 100%) !important;
  color: white !important;
  border-color: rgba(245, 158, 11, 0.4) !important;
  border-bottom-color: rgba(180, 83, 9, 0.6) !important;
  box-shadow: 
    0 2px 8px rgba(245, 158, 11, 0.25),
    inset 0 1px 1px rgba(255, 255, 255, 0.35),
    inset 0 -1px 1px rgba(0, 0, 0, 0.2) !important;
  position: relative;
  overflow: hidden;
  transition: all 0.2s ease;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3) !important;
}

.metallic-btn-yellow:hover:not(:disabled) {
  box-shadow: 
    0 4px 12px rgba(245, 158, 11, 0.4),
    inset 0 1px 1px rgba(255, 255, 255, 0.45),
    inset 0 -1px 1px rgba(0, 0, 0, 0.25) !important;
  background: linear-gradient(135deg, rgba(251, 191, 36, 1) 0%, rgba(245, 158, 11, 1) 100%) !important;
  transform: translateY(-1px);
}

.metallic-btn-yellow:active:not(:disabled) {
  transform: translateY(1px) !important;
  box-shadow: 
    0 1px 2px rgba(0, 0, 0, 0.2),
    inset 0 2px 4px rgba(0, 0, 0, 0.3) !important;
}

.metallic-btn-yellow:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none !important;
}
`;


const TeamManagementTab = () => {
  const [team, setTeam] = useState<TeamMember[]>([]);
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [form, setForm] = useState<TeamMemberUpdateRequest>({
    id: 0,
    name: '',
    email: '',
    mobile: '',
    company: '',
    address: '',
    role: 'Viewer',
    suspended: false,
    groupIds: [],
  });
  // Membership lookup for the group checkbox list. The list re-renders on
  // every keystroke in this form, and the previous `.includes()` was O(groups)
  // per checkbox, i.e. O(groups^2) per render.
  const selectedGroupIds = useMemo(() => new Set(form.groupIds ?? []), [form.groupIds]);
  const [availableGroups, setAvailableGroups] = useState<EndpointGroup[]>([]);

  const { showToast } = useToast();
  const confirmDialog = useConfirm();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [transferring, setTransferring] = useState(false);
  const [forcingPassword, setForcingPassword] = useState(false);
  const [isForcePasswordModalOpen, setIsForcePasswordModalOpen] = useState(false);
  const [forcePasswordReason, setForcePasswordReason] = useState('');
  const [error, setError] = useState<string>('');
  const currentUserId = useMemo(() => {
    try {
      return Number(JSON.parse(localStorage.getItem('user') || '{}')?.id);
    } catch {
      return NaN;
    }
  }, []);

  const sortedTeam = useMemo(
    () =>
      [...team].sort((a, b) => {
        const roleDelta = ROLE_PRIORITY[a.role] - ROLE_PRIORITY[b.role];
        if (roleDelta !== 0) return roleDelta;
        return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
      }),
    [team],
  );

  const selectedUser = useMemo(
    () => team.find((member) => member.id === selectedUserId) || null,
    [team, selectedUserId],
  );
  const existingSuperAdmin = useMemo(
    () => team.find((member) => member.role === 'Super Administrator') || null,
    [team],
  );
  const isCurrentUserSuperAdmin = useMemo(
    () => team.some((member) => member.id === currentUserId && member.role === 'Super Administrator'),
    [team, currentUserId],
  );
  const isEditingOwnSuperAdmin = useMemo(
    () =>
      selectedUser?.id === currentUserId &&
      selectedUser?.role === 'Super Administrator',
    [selectedUser, currentUserId],
  );
  const allowedRoleOptions = useMemo(() => {
    const selected = selectedUser;
    if (!selected) return ROLE_OPTIONS;
    const canKeepOrAssignSuperAdmin =
      selected.role === 'Super Administrator' || !existingSuperAdmin;
    return canKeepOrAssignSuperAdmin
      ? ROLE_OPTIONS
      : ROLE_OPTIONS.filter((role) => role !== 'Super Administrator');
  }, [existingSuperAdmin, selectedUser]);
  const canTransferOwnership = useMemo(
    () =>
      !!selectedUser &&
      selectedUser.id !== currentUserId &&
      selectedUser.role !== 'Super Administrator' &&
      isCurrentUserSuperAdmin,
    [selectedUser, currentUserId, isCurrentUserSuperAdmin],
  );

  const filteredTeam = useMemo(() => {
    const normalizedSearch = searchTerm.trim().toLowerCase();
    if (!normalizedSearch) return sortedTeam;

    return sortedTeam.filter((member) => {
      const nameMatch = (member.name || '').toLowerCase().includes(normalizedSearch);
      const emailMatch = (member.email || '').toLowerCase().includes(normalizedSearch);
      const roleMatch = (member.role || '').toLowerCase().includes(normalizedSearch);
      return nameMatch || emailMatch || roleMatch;
    });
  }, [searchTerm, sortedTeam]);

  const teamStats = useMemo(() => {
    const total = team.length;
    let admins = 0;
    let superAdmins = 0;
    let viewers = 0;
    let active = 0;
    let suspended = 0;

    team.forEach((user) => {
      if (user.role === 'Group Admin') admins++;
      if (user.role === 'Super Administrator') superAdmins++;
      if (user.role === 'Viewer') viewers++;
      if (!user.suspended) active++;
      if (user.suspended) suspended++;
    });

    return {
      total,
      admins,
      superAdmins,
      viewers,
      active,
      suspended,
    };
  }, [team]);

  const loadTeam = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await getTeamMembers();
      const users = response?.data?.users || [];
      setTeam(users);

      if (users.length > 0) {
        const orderedUsers = [...users].sort((a, b) => {
          const roleDelta = ROLE_PRIORITY[a.role] - ROLE_PRIORITY[b.role];
          if (roleDelta !== 0) return roleDelta;
          return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
        });
        const currentSelected = orderedUsers.find((u) => u.id === selectedUserId) || orderedUsers[0];
        setSelectedUserId(currentSelected.id);
        setForm({
          id: currentSelected.id,
          name: currentSelected.name,
          email: currentSelected.email,
          mobile: currentSelected.mobile,
          company: currentSelected.company ?? '',
          address: currentSelected.address ?? '',
          role: currentSelected.role,
          suspended: currentSelected.suspended,
          groupIds: currentSelected.groupIds ?? [],
        });
      } else {
        setSelectedUserId(null);
      }
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to load team members'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadTeam();
    fetchEndpointGroups().then(setAvailableGroups).catch(() => setAvailableGroups([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSelectUser = (user: TeamMember) => {
    setSelectedUserId(user.id);
    setError('');
    setForm({
      id: user.id,
      name: user.name,
      email: user.email,
      mobile: user.mobile,
      company: user.company ?? '',
      address: user.address ?? '',
      role: user.role,
      suspended: user.suspended,
      groupIds: user.groupIds ?? [],
    });
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedUserId) return;

    const isNewlySuspending = selectedUser && !selectedUser.suspended && form.suspended;
    if (isNewlySuspending) {
      const confirmed = await confirmDialog({
        title: `Suspend ${selectedUser.name}?`,
        description: 'This immediately blocks their login. They will not be able to access Vajra until account status is set back to Active.',
        confirmLabel: 'Suspend Account',
        variant: 'danger',
      });
      if (!confirmed) return;
    }

    const isRoleChanging = selectedUser && form.role !== selectedUser.role;
    if (isRoleChanging) {
      const confirmed = await confirmDialog({
        title: `Change ${selectedUser.name}'s role to ${form.role}?`,
        description: 'This immediately changes what they can see and do in Vajra.',
        confirmLabel: 'Change Role',
        variant: 'danger',
      });
      if (!confirmed) return;
    }

    setSaving(true);
    setError('');
    try {
      const payload: TeamMemberUpdateRequest = { ...form, id: selectedUserId };
      const response = await updateTeamMember(payload);
      const updated = response?.data?.user;
      if (!updated) {
        throw new Error(response?.message || 'Update failed');
      }

      setTeam((prev) => prev.map((member) => (member.id === updated.id ? updated : member)));
      showToast('User updated successfully!');
    } catch (err) {
      setError(getErrorMessage(err, 'Failed to update user'));
    } finally {
      setSaving(false);
    }
  };

  const onTransferOwnership = async () => {
    if (!selectedUser || !canTransferOwnership) return;

    const confirmed = await confirmDialog({
      title: `Transfer Super Administrator ownership to ${selectedUser.name}?`,
      description: 'Your role will change to Group Admin.',
      confirmLabel: 'Transfer',
      variant: 'danger',
    });
    if (!confirmed) return;

    setTransferring(true);
    setError('');

    try {
      await transferTeamOwnership({ targetUserId: selectedUser.id });

      setTeam((prev) =>
        prev.map((member) => {
          if (member.id === selectedUser.id) {
            return { ...member, role: 'Super Administrator' };
          }
          if (member.id === currentUserId) {
            return { ...member, role: 'Group Admin' };
          }
          return member;
        }),
      );
      setForm((prev) =>
        prev.id === selectedUser.id ? { ...prev, role: 'Super Administrator' } : prev,
      );

      try {
        const rawUser = localStorage.getItem('user');
        if (rawUser) {
          const parsed = JSON.parse(rawUser);
          if (parsed?.id === currentUserId) {
            parsed.role = 'Group Admin';
            localStorage.setItem('user', JSON.stringify(sanitizeUserForCache(parsed)));
          }
        }
      } catch {
        // Ignore local storage parsing issues.
      }

      showToast('Ownership transferred successfully. Your role is now Group Admin.');
    } catch (err) {
      const message = getErrorMessage(err, 'Failed to transfer ownership');
      setError(message);
      showToast(message, 'error');
    } finally {
      setTransferring(false);
    }
  };

  const onForcePasswordChange = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedUser || !forcePasswordReason.trim()) return;

    setForcingPassword(true);
    try {
      await forcePasswordChangeTeam({ id: selectedUser.id, reason: forcePasswordReason.trim() });
      setTeam((prev) =>
        prev.map((member) =>
          member.id === selectedUser.id ? { ...member, forcePasswordChange: true } : member
        ),
      );
      showToast('Force password change applied successfully.');
      setIsForcePasswordModalOpen(false);
      setForcePasswordReason('');
    } catch (err) {
      showToast(getErrorMessage(err, 'Failed to force password change'), 'error');
    } finally {
      setForcingPassword(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <style dangerouslySetInnerHTML={{ __html: TEAM_CSS }} />
      <div className="flex min-h-0 flex-1 flex-col">
        {error && (
          <div className="mb-4 shrink-0 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>
        )}

        <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-3">
          <section className="flex min-h-0 flex-col overflow-hidden bg-white rounded-2xl border border-slate-200 shadow-[0_14px_34px_rgba(15,23,42,0.06)] p-4 xl:col-span-1">
            <div className="flex items-center justify-between mb-3 shrink-0">
              <h2 className="text-sm font-bold text-slate-900">All Users</h2>
              <Link
                to="/new-user"
                className="p-1.5 text-blue-600 hover:bg-blue-50 rounded-lg transition"
                title="Add New User"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
                </svg>
              </Link>
            </div>
            {loading ? (
              <p className="text-sm text-slate-500">Loading users...</p>
            ) : sortedTeam.length === 0 ? (
              <p className="text-sm text-slate-500">No users found.</p>
            ) : (
              <div className="flex min-h-0 flex-1 flex-col gap-4">
                <div className="shrink-0">
                  <label htmlFor="team-search" className="sr-only">
                    Search team members
                  </label>
                  <input
                    id="team-search"
                    type="search"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Search by name, email, or role"
                    className="w-full rounded-xl border border-slate-300 bg-slate-50 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-100"
                  />
                </div>
                {filteredTeam.length === 0 ? (
                  <p className="text-sm text-slate-500">No users match your search.</p>
                ) : (
                  <div className="table-scrollbar min-h-0 flex-1 space-y-2 overflow-y-auto pr-1">
                    {filteredTeam.map((user) => (
                      <button
                        type="button"
                        key={user.id}
                        onClick={() => handleSelectUser(user)}
                        className={`w-full text-left rounded-xl border px-3 py-2 transition ${selectedUserId === user.id
                          ? 'border-blue-300 bg-blue-50'
                          : 'border-slate-200 bg-white hover:bg-slate-50'
                          }`}
                      >
                        <p className="text-sm font-semibold text-slate-900 truncate">{user.name}</p>
                        <p className="text-xs text-slate-600 truncate">{user.email}</p>
                        <p className="text-xs text-slate-500 mt-1">{user.role}</p>
                        <p className={`text-[11px] mt-1 font-semibold ${user.suspended ? 'text-red-600' : 'text-emerald-600'}`}>
                          {user.suspended ? 'Suspended' : 'Active'}
                        </p>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </section>



          <section className="flex min-h-0 flex-col overflow-hidden bg-white rounded-2xl border border-slate-200 shadow-[0_14px_34px_rgba(15,23,42,0.06)] p-5 xl:col-span-2">
            <div className="table-scrollbar min-h-0 flex-1 space-y-6 overflow-y-auto pr-1">
              <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl border border-blue-100 p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="p-2 bg-blue-100 rounded-lg">
                    <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-semibold text-slate-900">Team Overview</h3>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                  <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm text-center">
                    <p className="text-xs font-medium tracking-wide text-slate-500 uppercase mb-1">Total Members</p>
                    <p className="text-2xl font-bold text-slate-900">{teamStats.total}</p>
                  </div>
                  <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm text-center">
                    <p className="text-xs font-medium tracking-wide text-slate-500 uppercase mb-1">Active</p>
                    <p className="text-2xl font-bold text-emerald-600">{teamStats.active}</p>
                  </div>
                  <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm text-center">
                    <p className="text-xs font-medium tracking-wide text-slate-500 uppercase mb-1">Group Admins</p>
                    <p className="text-2xl font-bold text-blue-600">{teamStats.admins}</p>
                  </div>
                  <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm text-center">
                    <p className="text-xs font-medium tracking-wide text-slate-500 uppercase mb-1">Super Admin</p>
                    <p className="text-2xl font-bold text-indigo-600">{teamStats.superAdmins}</p>
                  </div>
                  <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm text-center md:col-span-2 lg:col-span-1">
                    <p className="text-xs font-medium tracking-wide text-slate-500 uppercase mb-1">Viewers</p>
                    <p className="text-2xl font-bold text-slate-700">{teamStats.viewers}</p>
                  </div>
                  <div className="bg-white rounded-lg p-4 border border-slate-200 shadow-sm text-center md:col-span-2 lg:col-span-1">
                    <p className="text-xs font-medium tracking-wide text-slate-500 uppercase mb-1">Suspended</p>
                    <p className="text-2xl font-bold text-amber-600">{teamStats.suspended}</p>
                  </div>

                </div>
              </div>
              <div className="rounded-xl border border-blue-100 p-6 py-8">
                <h2 className="text-sm font-bold text-slate-900 mb-3">Edit Account Details</h2>
                {!selectedUser ? (
                  <p className="text-sm text-slate-500">Select a user to view and edit profile details.</p>
                ) : (
                  <form onSubmit={onSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-semibold text-slate-600 mb-1">Name</label>
                      <input
                        value={form.name}
                        onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-600 mb-1">Email</label>
                      <input
                        type="email"
                        value={form.email}
                        onChange={(e) => setForm((prev) => ({ ...prev, email: e.target.value }))}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-600 mb-1">Mobile</label>
                      <input
                        value={form.mobile}
                        onChange={(e) => setForm((prev) => ({ ...prev, mobile: e.target.value }))}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                        required
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-600 mb-1">Role</label>
                      <select
                        value={form.role}
                        onChange={(e) => setForm((prev) => ({ ...prev, role: e.target.value as UserRole }))}
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                        disabled={isEditingOwnSuperAdmin}
                      >
                        {allowedRoleOptions.map((role) => (
                          <option key={role} value={role}>
                            {role}
                          </option>
                        ))}
                      </select>
                      {isEditingOwnSuperAdmin && (
                        <p className="mt-1 text-xs text-slate-500">
                          Super Administrator cannot change their own role.
                        </p>
                      )}
                    </div>
                    {form.role !== 'Super Administrator' && (
                      <div className="md:col-span-2">
                        <label className="block text-xs font-semibold text-slate-600 mb-1">
                          Group Access
                          <span className="ml-1 font-normal text-slate-400">
                            (limits this user to nodes in the selected group(s) — none selected means no node access)
                          </span>
                        </label>
                        {availableGroups.length === 0 ? (
                          <p className="text-xs text-slate-500">No groups exist yet. Create one under Group Management.</p>
                        ) : (
                          <div className="flex flex-wrap gap-2 rounded-lg border border-slate-300 p-3">
                            {availableGroups.map((group) => {
                              const checked = selectedGroupIds.has(group.groupId);
                              return (
                                <label
                                  key={group.groupId}
                                  className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium cursor-pointer transition ${checked
                                    ? 'border-blue-300 bg-blue-50 text-blue-700'
                                    : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50'
                                    }`}
                                >
                                  <input
                                    type="checkbox"
                                    className="sr-only"
                                    checked={checked}
                                    onChange={() =>
                                      setForm((prev) => {
                                        const current = prev.groupIds ?? [];
                                        const next = checked
                                          ? current.filter((g) => g !== group.groupId)
                                          : [...current, group.groupId];
                                        return { ...prev, groupIds: next };
                                      })
                                    }
                                  />
                                  {group.name}
                                </label>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    )}
                    <div>
                      <label className="block text-xs font-semibold text-slate-600 mb-1">Account Status</label>
                      <select
                        value={form.suspended ? 'suspended' : 'active'}
                        onChange={(e) =>
                          setForm((prev) => ({ ...prev, suspended: e.target.value === 'suspended' }))
                        }
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                      >
                        <option value="active">Active (Can login)</option>
                        <option
                          value="suspended"
                          disabled={isEditingOwnSuperAdmin && !form.suspended}
                        >
                          Suspended (Login blocked)
                        </option>
                      </select>
                      {isEditingOwnSuperAdmin && (
                        <p className="mt-1 text-xs text-slate-500">
                          Super Administrator cannot suspend their own account.
                          {form.suspended ? ' You can restore your account to Active.' : ''}
                        </p>
                      )}
                    </div>
                    <div className="md:col-span-2">
                      <div className="flex flex-wrap items-center gap-2 py-4">
                        <button
                          type="submit"
                          disabled={saving || transferring}
                          className="metallic-btn-blue inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-semibold border-transparent"
                        >
                          {saving ? 'Saving...' : 'Save Changes'}
                        </button>
                        <button
                          type="button"
                          onClick={onTransferOwnership}
                          disabled={!canTransferOwnership || transferring || saving}
                          className="metallic-btn-yellow inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-semibold border-transparent"
                        >
                          {transferring ? 'Transferring...' : 'Transfer Ownership'}
                        </button>
                        <button
                          type="button"
                          onClick={() => setIsForcePasswordModalOpen(true)}
                          disabled={!selectedUser || selectedUser.id === currentUserId || transferring || saving || selectedUser.forcePasswordChange}
                          className="inline-flex items-center justify-center rounded-xl border border-red-300 bg-red-50 px-4 py-2 text-sm font-semibold text-red-800 transition hover:bg-red-100 disabled:cursor-not-allowed disabled:opacity-60"
                          title={
                            selectedUser?.forcePasswordChange
                              ? 'Password change is already forced for this user'
                              : selectedUser?.id === currentUserId
                                ? 'Super Administrator cannot force a password change on their own account'
                                : transferring || saving
                                  ? 'Please wait for the current action to finish'
                                  : ''
                          }
                        >
                          {selectedUser?.forcePasswordChange ? 'Change Already Forced' : 'Force Password Change'}
                        </button>
                      </div>
                      {isCurrentUserSuperAdmin && (
                        <p className="mt-2 text-xs text-slate-500">
                          Select another team member and use Transfer Ownership to assign them as Super Administrator.
                        </p>
                      )}
                    </div>
                  </form>
                )}
              </div>
            </div>
          </section>
        </div>
      </div>
      {isForcePasswordModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm">
          <div className="bg-white rounded-2xl p-6 w-full max-w-md shadow-xl border border-slate-200">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 bg-red-100 rounded-lg">
                <svg className="w-5 h-5 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <h3 className="text-lg font-bold text-slate-900">Force Password Change</h3>
            </div>
            <p className="text-sm text-slate-500 mb-5 ml-12">
              This will invalidate the user's sessions and force them to change their password on the next login.
            </p>
            <form onSubmit={onForcePasswordChange}>
              <div className="mb-5">
                <label className="block text-xs font-semibold text-slate-600 mb-1">Reason for forcing change</label>
                <textarea
                  value={forcePasswordReason}
                  onChange={(e) => setForcePasswordReason(e.target.value)}
                  className="w-full rounded-xl border border-slate-300 bg-slate-50 px-3 py-2 text-sm text-slate-900 focus:border-red-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-red-100"
                  rows={3}
                  required
                  placeholder="E.g., Suspicious activity detected..."
                />
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsForcePasswordModalOpen(false)}
                  className="px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100 rounded-xl transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={forcingPassword || !forcePasswordReason.trim()}
                  className="px-4 py-2 text-sm font-semibold text-white bg-red-600 hover:bg-red-700 rounded-xl transition disabled:opacity-60"
                >
                  {forcingPassword ? 'Applying...' : 'Force Password Change'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

type ManagementTabId = 'team' | 'endpoint' | 'data';

const MANAGEMENT_TAB_IDS: ManagementTabId[] = ['team', 'endpoint', 'data'];

const Management = () => {
  const isSuperAdmin = getStoredUser()?.role === 'Super Administrator';
  // ?tab=<id> deep link.
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState<ManagementTabId>(() => {
    const requested = searchParams.get('tab');
    if (!requested || !MANAGEMENT_TAB_IDS.includes(requested as ManagementTabId)) return 'team';
    // Every tab but 'team' is super-admin-only (the page itself is already
    // <SuperAdminRoute>-gated, this is belt-and-braces for a hand-typed URL).
    if (requested !== 'team' && !isSuperAdmin) return 'team';
    return requested as ManagementTabId;
  });
  const [headerActionsContainer, setHeaderActionsContainer] = useState<HTMLDivElement | null>(null);

  // The reverse direction: adopt an externally-changed ?tab= into state. The
  // seed above only runs on mount, so without this a navigate('/management?tab=…')
  // would be a no-op for an admin who is ALREADY sitting on /management — the
  // component never remounts. Paired with
  // the effect below this converges rather than looping: whichever side is
  // stale is brought into line, after which both effects see a match and stop.
  useEffect(() => {
    const requested = searchParams.get('tab');
    if (!requested || !MANAGEMENT_TAB_IDS.includes(requested as ManagementTabId)) return;
    if (requested !== 'team' && !isSuperAdmin) return;
    setActiveTab((current) => (current === requested ? current : (requested as ManagementTabId)));
  }, [searchParams, isSuperAdmin]);

  // Keep the URL in step with the visible tab; the default 'team' tab drops the
  // param entirely so the plain /management URL stays clean.
  useEffect(() => {
    const current = searchParams.get('tab');
    const desired = activeTab === 'team' ? null : activeTab;
    if (current === desired) return;
    if (desired === null) {
      const next = new URLSearchParams(searchParams);
      next.delete('tab');
      setSearchParams(next, { replace: true });
    } else {
      setSearchParams({ tab: desired }, { replace: true });
    }
  }, [activeTab, searchParams, setSearchParams]);

  let title = 'Management';
  let description = 'Manage your team, configure endpoint groups, and set data retention policies.';

  if (activeTab === 'team') {
    title = 'Team Management';
    description = 'Manage your team members, roles, and access permissions.';
  } else if (activeTab === 'endpoint') {
    title = 'Endpoint Management';
    description = 'Configure endpoint groups, assign nodes, and manage configurations.';
  } else if (activeTab === 'data') {
    title = 'Data Management';
    description = 'Set data retention policies and manage system data storage.';
  }

  const managementTabs = useMemo(() => [
    { id: 'team' as const, label: 'Team Management', visible: true },
    { id: 'endpoint' as const, label: 'Group Management', visible: isSuperAdmin },
    { id: 'data' as const, label: 'Data Management', visible: isSuperAdmin },
  ].filter((t) => t.visible), [isSuperAdmin]);

  return (
    <div className="flex max-h-[calc(100vh-4rem)] flex-col overflow-hidden bg-[#f8f9fb] md:max-h-screen">
      <div className="mx-auto flex min-h-0 w-full max-w-full flex-1 flex-col px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5">
        <motion.header
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6 mb-5 text-white shrink-0"
          style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
        >
          <Meteors number={25} className="!bg-white before:!from-white before:!to-transparent" />
          <div className="relative z-10 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="min-w-0 shrink-0">
              <h1 className="flex items-center text-2xl font-bold tracking-tight text-white">
                <svg className="w-6 h-6 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-1a4 4 0 00-5.9-3.5M17 20H7m10 0v-1c0-1.1-.37-2.11-1-2.93M7 20H2v-1a4 4 0 015.9-3.5M7 20v-1c0-1.1.37-2.11 1-2.93m0 0a5 5 0 018 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM5 10a2 2 0 11-4 0 2 2 0 014 0z" />
                </svg>
                {title}
              </h1>
              <p className="mt-1 text-sm text-blue-100">{description}</p>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center lg:justify-end">
              {/* Tab switcher — same pill-nav treatment used on Compliance */}
              <div className="relative inline-flex items-center gap-0.5 rounded-full border border-white/20 bg-white/10 backdrop-blur-sm p-1 overflow-x-auto scrollbar-hide max-w-full" role="tablist">
                {managementTabs.map((t) => {
                  const active = activeTab === t.id;
                  return (
                    <button
                      key={t.id}
                      role="tab"
                      aria-selected={active}
                      onClick={() => setActiveTab(t.id)}
                      className={`relative z-10 inline-flex items-center rounded-full font-semibold transition-colors duration-150 px-3 py-1.5 text-sm whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300 ${active ? 'text-[rgb(4,34,119)]' : 'text-blue-100 hover:text-white'
                        }`}
                      style={{ transformStyle: 'preserve-3d' }}
                    >
                      {active && (
                        <motion.div
                          layoutId="teamManagementTabBackground"
                          transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }}
                          className="absolute inset-0 bg-white rounded-full shadow-sm"
                          style={{ zIndex: -1 }}
                        />
                      )}
                      <span>{t.label}</span>
                    </button>
                  );
                })}
              </div>

              <div ref={setHeaderActionsContainer} className="flex items-center gap-2"></div>
            </div>
          </div>
        </motion.header>

        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className={activeTab === 'team' ? 'flex min-h-0 flex-1 flex-col' : 'min-h-0 flex-1 overflow-y-auto'}

          >
            {activeTab === 'team' && <TeamManagementTab />}
            {activeTab === 'endpoint' && (
              <EndpointManagementTab headerActionsContainer={headerActionsContainer} />
            )}
            {activeTab === 'data' && (
              <div className="mt-6">
                <DataRetention headerActionsContainer={headerActionsContainer} />
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
};

export default Management;

