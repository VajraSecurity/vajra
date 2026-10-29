import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { isAxiosError } from 'axios';
import api from '../../api/axiosInstance';
import { useToast } from '../../context/useToast';
import { useConfirm } from '../../context/useConfirm';
import {
  getTeamMembers,
  fetchGroupUsers,
  assignUsersToGroup,
  fetchNodeAssignmentRules,
  createNodeAssignmentRule,
  updateNodeAssignmentRule,
  deleteNodeAssignmentRule,
  runNodeAssignmentRulesNow,
} from '../../api/api';
import type { TeamMember, NodeAssignmentRule, NodeAssignmentRuleInput } from '../../api/api';
import { Checkbox } from '../../components/ui/checkbox';

function getErrorMessage(err: unknown, fallback: string): string {
  if (isAxiosError<{ message?: string }>(err)) {
    return err.response?.data?.message || fallback;
  }
  return fallback;
}

interface Group {
  id: number;
  name: string;
  groupId: string;
  createdBy: string;
  organisation: string;
  createdAt: string;
  nodeCount: number;
}

interface Node {
  id: number;
  host_identifier: string;
  hostname: string;
  os_name: string;
  address: string;
  status: string;
  group_ids?: string[] | null;
}

interface EndpointManagementTabProps {
  headerActionsContainer?: HTMLDivElement | null;
}

// Matches the backend's PAGINATION_MAX_ROWS_NODES cap for /nodes/list — requesting more than
// this is silently clamped server-side, so we request the max and warn the admin if we hit it,
// since this modal doesn't paginate.
const NODE_LIST_FETCH_CAP = 1000;

// Hoisted out of the render body: a fresh `sx` literal per row means a new object identity for
// every one of the (up to NODE_LIST_FETCH_CAP) MUI Checkboxes on every re-render, which forces
// Emotion to re-serialise the same style block over and over. One shared frozen object instead.
const CHECKBOX_SX = {
  color: '#cbd5e1',
  '&.Mui-checked': {
    color: '#4f46e5',
  },
} as const;

// Shared empty array so groups with no rules keep a stable reference across renders.
const NO_RULES: NodeAssignmentRule[] = [];

const EndpointManagementTab = ({ headerActionsContainer }: EndpointManagementTabProps) => {
  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(false);
  const [nodes, setNodes] = useState<Node[]>([]);
  
  // Modals
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isAssignModalOpen, setIsAssignModalOpen] = useState(false);
  const [isAssignUsersModalOpen, setIsAssignUsersModalOpen] = useState(false);
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null);
  const [selectedUserIds, setSelectedUserIds] = useState<number[]>([]);
  const [assigningUsers, setAssigningUsers] = useState(false);
  const [assigningNodes, setAssigningNodes] = useState(false);

  const [newGroup, setNewGroup] = useState({ name: '', organisation: '' });
  const [selectedNodes, setSelectedNodes] = useState<string[]>([]);
  const [initialSelectedNodes, setInitialSelectedNodes] = useState<string[]>([]);
  const [showRemoveWarning, setShowRemoveWarning] = useState(false);
  const [nodeToRemove, setNodeToRemove] = useState<string | null>(null);
  const [dontShowRemoveWarning, setDontShowRemoveWarning] = useState<boolean>(() => {
    return localStorage.getItem('dontShowRemoveGroupWarning') === 'true';
  });
  const [tempDontShowChecked, setTempDontShowChecked] = useState(false);
  const [teamMembers, setTeamMembers] = useState<TeamMember[]>([]);

  // Auto-assignment rules (Task Scheduler)
  const [rules, setRules] = useState<NodeAssignmentRule[]>([]);
  const [expandedGroupId, setExpandedGroupId] = useState<string | null>(null);
  const [isRuleModalOpen, setIsRuleModalOpen] = useState(false);
  const [ruleGroup, setRuleGroup] = useState<Group | null>(null);
  const [ruleToEdit, setRuleToEdit] = useState<NodeAssignmentRule | null>(null);
  const [ruleForm, setRuleForm] = useState<NodeAssignmentRuleInput>({ name: '', conditionValue: '', groupId: '', priority: 100, enabled: true });
  const [savingRule, setSavingRule] = useState(false);
  const [runningScheduler, setRunningScheduler] = useState(false);

  const { showToast } = useToast();
  const confirm = useConfirm();

  // Bucket once per `rules` change rather than filtering and sorting inline per group in
  // the render body, which is O(groups x rules) plus a sort on every render, including
  // renders driven by unrelated state. Insertion order follows `rules` and
  // Array.prototype.sort is stable, so ties keep their original order.
  const rulesByGroupId = useMemo(() => {
    const byGroup = new Map<string, NodeAssignmentRule[]>();
    for (const rule of rules) {
      const bucket = byGroup.get(rule.groupId);
      if (bucket) bucket.push(rule);
      else byGroup.set(rule.groupId, [rule]);
    }
    for (const bucket of byGroup.values()) {
      bucket.sort((a, b) => a.priority - b.priority);
    }
    return byGroup;
  }, [rules]);

  // `selectedNodes` is a plain string[]; the assign-nodes list did an Array.includes() per row
  // *and* two more inside the sort comparator, so a single checkbox click cost O(n^2) string
  // comparisons at the 1000-node cap. A Set makes every membership test O(1).
  const selectedNodeSet = useMemo(() => new Set(selectedNodes), [selectedNodes]);
  const selectedUserIdSet = useMemo(() => new Set(selectedUserIds), [selectedUserIds]);

  // Selected nodes first; Array.prototype.sort is stable, so the original order is
  // preserved within each half. Memoised so it re-runs on input changes rather than on
  // every render of the modal.
  const nodesSelectedFirst = useMemo(
    () =>
      [...nodes].sort((a, b) => {
        const aSelected = selectedNodeSet.has(a.host_identifier);
        const bSelected = selectedNodeSet.has(b.host_identifier);
        if (aSelected && !bSelected) return -1;
        if (!aSelected && bSelected) return 1;
        return 0;
      }),
    [nodes, selectedNodeSet],
  );

  const fetchGroups = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.get(`/groups`);
      if (res.data.success) {
        setGroups(res.data.groups);
      }
    } catch (err) {
      console.error(err);
      showToast('Failed to load groups', 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast]);

  const fetchNodes = async () => {
    try {
      const res = await api.get(`/nodes/list?rows=${NODE_LIST_FETCH_CAP}&pageno=1`);
      if (res.data.success) {
        setNodes(res.data.nodes || []);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchTeamMembers = async () => {
    try {
      const res = await getTeamMembers();
      if (res.status === 'Success' && res.data) {
        setTeamMembers(res.data.users);
      }
    } catch (err) {
      console.error('Failed to load team members', err);
    }
  };

  const fetchRules = async () => {
    try {
      const data = await fetchNodeAssignmentRules();
      setRules(data);
    } catch (err) {
      console.error('Failed to load auto-assignment rules', err);
    }
  };

  useEffect(() => {
    fetchGroups();
    fetchNodes();
    fetchTeamMembers();
    fetchRules();
  }, [fetchGroups]);

  const toggleGroupExpansion = (groupId: string) => {
    setExpandedGroupId((prev) => (prev === groupId ? null : groupId));
  };

  const openCreateRuleModal = (group: Group) => {
    setRuleGroup(group);
    setRuleToEdit(null);
    setRuleForm({ name: '', conditionValue: '', groupId: group.groupId, priority: 100, enabled: true });
    setIsRuleModalOpen(true);
  };

  const openEditRuleModal = (group: Group, rule: NodeAssignmentRule) => {
    setRuleGroup(group);
    setRuleToEdit(rule);
    setRuleForm({
      name: rule.name,
      conditionValue: rule.conditionValue,
      groupId: rule.groupId,
      priority: rule.priority,
      enabled: rule.enabled,
    });
    setIsRuleModalOpen(true);
  };

  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingRule(true);
    try {
      if (ruleToEdit) {
        await updateNodeAssignmentRule(ruleToEdit.id, ruleForm);
        showToast('Rule updated successfully!');
      } else {
        await createNodeAssignmentRule(ruleForm);
        showToast('Rule created successfully!');
      }
      setIsRuleModalOpen(false);
      fetchRules();
    } catch (err) {
      showToast(getErrorMessage(err, 'Failed to save rule'), 'error');
    } finally {
      setSavingRule(false);
    }
  };

  const handleDeleteRule = async (rule: NodeAssignmentRule) => {
    const confirmed = await confirm({
      title: `Delete the rule "${rule.name}"?`,
      description: 'This will stop the rule from auto-assigning new matching nodes going forward. Nodes already assigned to the group by this rule will remain assigned.',
      confirmLabel: 'Delete',
      variant: 'danger',
    });
    if (!confirmed) return;
    try {
      await deleteNodeAssignmentRule(rule.id);
      showToast('Rule deleted successfully!');
      fetchRules();
    } catch {
      showToast('Failed to delete rule', 'error');
    }
  };

  const handleToggleRuleEnabled = async (rule: NodeAssignmentRule) => {
    try {
      await updateNodeAssignmentRule(rule.id, {
        name: rule.name,
        conditionValue: rule.conditionValue,
        groupId: rule.groupId,
        priority: rule.priority,
        enabled: !rule.enabled,
      });
      fetchRules();
    } catch {
      showToast('Failed to update rule', 'error');
    }
  };

  const handleRunSchedulerNow = async () => {
    setRunningScheduler(true);
    try {
      const result = await runNodeAssignmentRulesNow();
      showToast(`Scheduler run complete: ${result.totalAssigned} node(s) assigned.`);
      fetchRules();
      fetchGroups();
      fetchNodes();
    } catch {
      showToast('Failed to run scheduler', 'error');
    } finally {
      setRunningScheduler(false);
    }
  };

  const handleCreateGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await api.post(`/groups`, newGroup);
      if (res.data.success) {
        showToast('Group created successfully!');
        setIsCreateModalOpen(false);
        setNewGroup({ name: '', organisation: '' });
        fetchGroups();
      }
    } catch {
      showToast('Failed to create group', 'error');
    }
  };

  const handleAssignNodes = async () => {
    if (!selectedGroup) return;
    setAssigningNodes(true);
    try {
      const res = await api.put(`/groups/${selectedGroup.groupId}/nodes`, {
        nodeIdentifiers: selectedNodes
      });
      if (res.data.success) {
        showToast('Nodes assigned successfully!');
        setIsAssignModalOpen(false);
        setSelectedNodes([]);
        fetchGroups(); // refresh node counts
        fetchNodes(); // refresh nodes list with new group_ids
      }
    } catch {
      showToast('Failed to assign nodes', 'error');
    } finally {
      setAssigningNodes(false);
    }
  };

  const openAssignUsersModal = async (group: Group) => {
    setSelectedGroup(group);
    setIsAssignUsersModalOpen(true);
    try {
      const users = await fetchGroupUsers(group.groupId);
      setSelectedUserIds(users.map((u) => u.id));
    } catch (err) {
      console.error(err);
      showToast('Failed to load group members', 'error');
      setSelectedUserIds([]);
    }
  };

  const toggleUserSelection = (userId: number) => {
    setSelectedUserIds((prev) =>
      prev.includes(userId) ? prev.filter((id) => id !== userId) : [...prev, userId],
    );
  };

  const handleAssignUsers = async () => {
    if (!selectedGroup) return;
    setAssigningUsers(true);
    try {
      await assignUsersToGroup(selectedGroup.groupId, selectedUserIds);
      showToast('Users assigned successfully!');
      setIsAssignUsersModalOpen(false);
      setSelectedUserIds([]);
    } catch (err) {
      console.error(err);
      showToast('Failed to assign users', 'error');
    } finally {
      setAssigningUsers(false);
    }
  };

  const handleDeleteGroup = async (groupId: string) => {
    const group = groups.find((g) => g.groupId === groupId);
    const confirmed = await confirm({
      title: group ? `Delete group "${group.name}"?` : 'Delete this group?',
      description: 'This will unassign all nodes currently in this group, remove all user assignments to it, and delete any auto-assignment rules tied to it. This cannot be undone.',
      confirmLabel: 'Delete',
      variant: 'danger',
    });
    if (!confirmed) return;
    try {
      const res = await api.delete(`/groups/${groupId}`);
      if (res.data.success) {
        showToast('Group deleted successfully!');
        fetchGroups();
      }
    } catch {
      showToast('Failed to delete group', 'error');
    }
  };

  const toggleNodeSelection = (hostIdentifier: string) => {
    if (selectedNodes.includes(hostIdentifier)) {
      if (initialSelectedNodes.includes(hostIdentifier) && !dontShowRemoveWarning) {
        setNodeToRemove(hostIdentifier);
        setTempDontShowChecked(false);
        setShowRemoveWarning(true);
        return;
      }
      setSelectedNodes(prev => prev.filter(id => id !== hostIdentifier));
    } else {
      setSelectedNodes(prev => [...prev, hostIdentifier]);
    }
  };

  const handleConfirmRemove = () => {
    if (tempDontShowChecked) {
      setDontShowRemoveWarning(true);
      localStorage.setItem('dontShowRemoveGroupWarning', 'true');
    }
    if (nodeToRemove) {
      setSelectedNodes(prev => prev.filter(id => id !== nodeToRemove));
    }
    setShowRemoveWarning(false);
    setNodeToRemove(null);
  };

  const handleCancelRemove = () => {
    setShowRemoveWarning(false);
    setNodeToRemove(null);
  };

  const actionButtons = (
    <>
      <button
        onClick={handleRunSchedulerNow}
        disabled={runningScheduler}
        className="inline-flex items-center gap-2 rounded-lg bg-white border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50 transition-colors shadow-sm disabled:opacity-50"
        title="Evaluate auto-assignment rules against ungrouped nodes right now"
      >
        {runningScheduler ? 'Running...' : 'Run Scheduler Now'}
      </button>
      <button
        onClick={() => setIsCreateModalOpen(true)}
        className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 transition-colors shadow-sm"
      >
        + Create New Group
      </button>
    </>
  );

  return (
    <div className="mt-6">
      {headerActionsContainer && createPortal(actionButtons, headerActionsContainer)}

      <div className="bg-white rounded-2xl border border-slate-200 shadow-[0_14px_34px_rgba(15,23,42,0.06)] overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-slate-500">Loading groups...</div>
        ) : groups.length === 0 ? (
          <div className="p-8 text-center text-slate-500">No groups found. Create one to get started.</div>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left border-separate border-spacing-0">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200">
                <th className="w-10 px-3 py-4 sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]"></th>
                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Group Name</th>
                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Organization</th>
                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Nodes Count</th>
                <th className="px-6 py-4 text-xs font-semibold text-slate-500 uppercase tracking-wider text-right sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {groups.map((group) => {
                const groupRules = rulesByGroupId.get(group.groupId) ?? NO_RULES;
                const isExpanded = expandedGroupId === group.groupId;
                return (
                  <React.Fragment key={group.id}>
                    <tr className="hover:bg-slate-50 transition">
                      <td className="px-3 py-4 text-center">
                        <button
                          onClick={() => toggleGroupExpansion(group.groupId)}
                          className="rounded-lg text-slate-400 hover:text-slate-700 transition-transform"
                          style={{ transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)' }}
                          title="Toggle auto-assignment rules"
                          aria-label="Toggle auto-assignment rules"
                          aria-expanded={isExpanded}
                          aria-controls={`group-rules-${group.groupId}`}
                        >
                          &#9656;
                        </button>
                      </td>
                      <td className="px-6 py-4 text-sm font-medium text-slate-900">{group.name}</td>
                      <td className="px-6 py-4 text-sm text-slate-500">{group.organisation || '-'}</td>
                      <td className="px-6 py-4">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                          {group.nodeCount} nodes
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex justify-end gap-3">
                          <button
                            onClick={() => {
                              setSelectedGroup(group);
                              const assignedNodes = nodes
                                .filter(n => n.group_ids && n.group_ids.includes(group.groupId))
                                .map(n => n.host_identifier);
                              setSelectedNodes(assignedNodes);
                              setInitialSelectedNodes(assignedNodes);
                              setIsAssignModalOpen(true);
                            }}
                            className="rounded-lg text-sm text-blue-600 hover:text-blue-800 font-medium"
                          >
                            Assign Nodes
                          </button>
                          <button
                            onClick={() => openAssignUsersModal(group)}
                            className="rounded-lg text-sm text-blue-600 hover:text-blue-800 font-medium"
                          >
                            Assign Users
                          </button>
                          <button
                            onClick={() => handleDeleteGroup(group.groupId)}
                            className="rounded-lg text-sm text-red-600 hover:text-red-800 font-medium"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr id={`group-rules-${group.groupId}`} className="bg-slate-50/70">
                        <td colSpan={6} className="px-6 py-4">
                          <div className="flex items-center justify-between mb-3">
                            <h4 className="text-sm font-semibold text-slate-700">
                              Auto-Assignment Rules
                              <span className="ml-2 text-xs font-normal text-slate-400">
                                Nodes with no group yet are added here automatically when their IP matches.
                              </span>
                            </h4>
                            <button
                              onClick={() => openCreateRuleModal(group)}
                              className="inline-flex items-center gap-1 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-700 transition-colors"
                            >
                              + Add Rule
                            </button>
                          </div>
                          {groupRules.length === 0 ? (
                            <div className="text-sm text-slate-400 py-3">No auto-assignment rules for this group yet.</div>
                          ) : (
                            <div className="overflow-x-auto">
                            <table className="w-full min-w-[560px] text-left border-separate border-spacing-0 bg-white rounded-xl border border-slate-200 overflow-hidden">
                              <thead>
                                <tr className="bg-slate-100 border-b border-slate-200">
                                  <th className="px-4 py-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Name</th>
                                  <th className="px-4 py-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Condition (CIDR)</th>
                                  <th className="px-4 py-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Priority</th>
                                  <th className="px-4 py-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Enabled</th>
                                  <th className="px-4 py-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Last Run</th>
                                  <th className="px-4 py-2 text-[11px] font-semibold text-slate-500 uppercase tracking-wider text-right sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]">Actions</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-slate-100">
                                {groupRules
                                  .map((rule) => (
                                    <tr key={rule.id} className="hover:bg-slate-50">
                                      <td className="px-4 py-2 text-sm text-slate-800">{rule.name}</td>
                                      <td className="px-4 py-2 text-sm font-mono text-slate-600">{rule.conditionValue}</td>
                                      <td className="px-4 py-2 text-sm text-slate-500">{rule.priority}</td>
                                      <td className="px-4 py-2">
                                        <button onClick={() => handleToggleRuleEnabled(rule)} className="rounded-lg">
                                          <span
                                            className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                                              rule.enabled ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-200 text-slate-500'
                                            }`}
                                          >
                                            {rule.enabled ? 'Enabled' : 'Disabled'}
                                          </span>
                                        </button>
                                      </td>
                                      <td className="px-4 py-2 text-xs text-slate-500">
                                        {rule.lastRunAt
                                          ? `${new Date(rule.lastRunAt).toLocaleString()} (${rule.lastMatchedCount ?? 0} matched)`
                                          : 'Never run yet'}
                                      </td>
                                      <td className="px-4 py-2 text-right">
                                        <div className="flex justify-end gap-3">
                                          <button
                                            onClick={() => openEditRuleModal(group, rule)}
                                            className="rounded-lg text-xs text-blue-600 hover:text-blue-800 font-medium"
                                          >
                                            Edit
                                          </button>
                                          <button
                                            onClick={() => handleDeleteRule(rule)}
                                            className="rounded-lg text-xs text-red-600 hover:text-red-800 font-medium"
                                          >
                                            Delete
                                          </button>
                                        </div>
                                      </td>
                                    </tr>
                                  ))}
                              </tbody>
                            </table>
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
          </div>
        )}
      </div>

      {/* Create Group Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
          <div className="bg-white rounded-2xl p-6 w-full max-w-md shadow-xl border border-slate-200">
            <h3 className="text-lg font-bold text-slate-900 mb-4">Create Endpoint Group</h3>
            <form onSubmit={handleCreateGroup}>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">Group Name *</label>
                  <input
                    type="text"
                    required
                    value={newGroup.name}
                    onChange={(e) => setNewGroup({...newGroup, name: e.target.value})}
                    className="w-full rounded-xl border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
                    placeholder="e.g. Finance Servers"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">Organization</label>
                  <input
                    type="text"
                    value={newGroup.organisation}
                    onChange={(e) => setNewGroup({...newGroup, organisation: e.target.value})}
                    className="w-full rounded-xl border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
                    placeholder="e.g. Acme Corp"
                  />
                </div>
              </div>
              <div className="mt-6 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100 rounded-xl transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition"
                >
                  Create Group
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Assign Nodes Modal */}
      {isAssignModalOpen && selectedGroup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
          <div className="bg-white rounded-2xl p-6 w-full max-w-2xl shadow-xl border border-slate-200 max-h-[90vh] flex flex-col">
            <h3 className="text-lg font-bold text-slate-900 mb-2">
              Assign Nodes to <span className="text-blue-600">{selectedGroup.name}</span>
            </h3>
            <p className="text-sm text-slate-500 mb-4">
              Select the nodes you want to add to this group.
            </p>
            {nodes.length >= NODE_LIST_FETCH_CAP && (
              <p className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-4">
                Showing first {NODE_LIST_FETCH_CAP} nodes — there may be more in your fleet that aren't listed here. Contact support if you need to assign beyond this.
              </p>
            )}

            <div className="flex-1 overflow-y-auto border border-slate-200 rounded-xl mb-4">
              {nodes.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-sm">No nodes available.</div>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {nodesSelectedFirst.map(node => (
                    <li key={node.host_identifier} className="p-3 hover:bg-slate-50 flex items-center gap-3">
                      <Checkbox 
                        checked={selectedNodeSet.has(node.host_identifier)}
                        onChange={() => toggleNodeSelection(node.host_identifier)}
                        size="small"
                        sx={CHECKBOX_SX}
                      />
                      <div>
                        <div className="text-sm font-medium text-slate-900">{node.hostname || node.host_identifier}</div>
                        <div className="text-xs text-slate-500 flex gap-2">
                          <span>{node.os_name}</span>
                          <span className={node.status === 'Online' ? 'text-emerald-600' : 'text-slate-400'}>• {node.status}</span>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="flex justify-between items-center pt-2 border-t border-slate-100">
              <span className="text-sm text-slate-500">
                {selectedNodes.length} node(s) selected
              </span>
              <div className="flex gap-3">
                <button
                  onClick={() => {
                    setIsAssignModalOpen(false);
                    setSelectedNodes([]);
                    setInitialSelectedNodes([]);
                  }}
                  className="px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100 rounded-xl transition"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAssignNodes}
                  disabled={assigningNodes}
                  className="px-4 py-2 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {assigningNodes ? 'Saving...' : 'Confirm Assignment'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Assign Users Modal */}
      {isAssignUsersModalOpen && selectedGroup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
          <div className="bg-white rounded-2xl p-6 w-full max-w-2xl shadow-xl border border-slate-200 max-h-[90vh] flex flex-col">
            <h3 className="text-lg font-bold text-slate-900 mb-2">
              Assign Users to <span className="text-blue-600">{selectedGroup.name}</span>
            </h3>
            <p className="text-sm text-slate-500 mb-4">
              Users assigned here (Group Admin or Viewer role) can only see and act on nodes in this group.
            </p>

            <div className="flex-1 overflow-y-auto border border-slate-200 rounded-xl mb-4">
              {teamMembers.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-sm">No team members available.</div>
              ) : (
                <ul className="divide-y divide-slate-100">
                  {teamMembers
                    .filter((m) => m.role !== 'Super Administrator')
                    .map((member) => (
                      <li key={member.id} className="p-3 hover:bg-slate-50 flex items-center gap-3">
                        <Checkbox
                          checked={selectedUserIdSet.has(member.id)}
                          onChange={() => toggleUserSelection(member.id)}
                          size="small"
                          sx={CHECKBOX_SX}
                        />
                        <div>
                          <div className="text-sm font-medium text-slate-900">{member.name}</div>
                          <div className="text-xs text-slate-500 flex gap-2">
                            <span>{member.email}</span>
                            <span>• {member.role}</span>
                          </div>
                        </div>
                      </li>
                    ))}
                </ul>
              )}
            </div>

            <div className="flex justify-between items-center pt-2 border-t border-slate-100">
              <span className="text-sm text-slate-500">
                {selectedUserIds.length} user(s) selected
              </span>
              <div className="flex gap-3">
                <button
                  onClick={() => {
                    setIsAssignUsersModalOpen(false);
                    setSelectedUserIds([]);
                  }}
                  className="px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100 rounded-xl transition"
                >
                  Cancel
                </button>
                <button
                  onClick={handleAssignUsers}
                  disabled={assigningUsers}
                  className="px-4 py-2 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {assigningUsers ? 'Saving...' : 'Confirm Assignment'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Remove Node Warning Modal */}
      {showRemoveWarning && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
          <div className="bg-white rounded-2xl p-6 w-full max-w-sm shadow-xl border border-slate-200">
            <h3 className="text-lg font-bold text-slate-900 mb-2">Remove Node?</h3>
            <p className="text-sm text-slate-600 mb-4">
              Unselecting this node will remove it from the group when you confirm the assignment. Are you sure?
            </p>
            <label className="flex items-center gap-2 mb-6 cursor-pointer">
              <Checkbox
                checked={tempDontShowChecked}
                onChange={(e) => setTempDontShowChecked(e.target.checked)}
                size="small"
              />
              <span className="text-xs text-slate-600">Don't show this warning again</span>
            </label>
            <div className="flex justify-end gap-3">
              <button
                onClick={handleCancelRemove}
                className="px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100 rounded-xl transition"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmRemove}
                className="px-4 py-2 text-sm font-semibold text-white bg-red-600 hover:bg-red-700 rounded-xl transition"
              >
                Remove
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create/Edit Auto-Assignment Rule Modal */}
      {isRuleModalOpen && ruleGroup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
          <div className="bg-white rounded-2xl p-6 w-full max-w-md shadow-xl border border-slate-200">
            <h3 className="text-lg font-bold text-slate-900 mb-1">
              {ruleToEdit ? 'Edit' : 'Add'} Auto-Assignment Rule
            </h3>
            <p className="text-sm text-slate-500 mb-4">
              New nodes whose IP falls in this range are auto-added to <span className="font-semibold text-blue-600">{ruleGroup.name}</span>.
            </p>
            <form onSubmit={handleSaveRule}>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">Rule Name *</label>
                  <input
                    type="text"
                    required
                    value={ruleForm.name}
                    onChange={(e) => setRuleForm({ ...ruleForm, name: e.target.value })}
                    className="w-full rounded-xl border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
                    placeholder="e.g. Vajralab subnet"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">IP Condition (CIDR) *</label>
                  <input
                    type="text"
                    required
                    value={ruleForm.conditionValue}
                    onChange={(e) => setRuleForm({ ...ruleForm, conditionValue: e.target.value })}
                    className="w-full rounded-xl border border-slate-300 px-3 py-2 text-sm font-mono focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
                    placeholder="e.g. 10.0.5.0/24"
                  />
                  <p className="text-xs text-slate-400 mt-1">A node matches when its IP address falls inside this subnet.</p>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1">Priority</label>
                  <input
                    type="number"
                    value={ruleForm.priority ?? 100}
                    onChange={(e) => setRuleForm({ ...ruleForm, priority: parseInt(e.target.value, 10) || 0 })}
                    className="w-full rounded-xl border border-slate-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
                  />
                  <p className="text-xs text-slate-400 mt-1">Lower numbers are evaluated first when a node could match rules in multiple groups.</p>
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox
                    checked={ruleForm.enabled ?? true}
                    onChange={(e) => setRuleForm({ ...ruleForm, enabled: e.target.checked })}
                    size="small"
                  />
                  <span className="text-sm text-slate-600">Enabled</span>
                </label>
              </div>
              <div className="mt-6 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsRuleModalOpen(false)}
                  className="px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100 rounded-xl transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingRule}
                  className="px-4 py-2 text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition disabled:opacity-50"
                >
                  {savingRule ? 'Saving...' : ruleToEdit ? 'Save Changes' : 'Create Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default EndpointManagementTab;
