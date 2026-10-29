/**
 * Node Auto-Assignment Rules API (Task Scheduler: IP -> group rules)
 * Super Admin only. A node with no group yet is auto-added to a rule's group
 * when its IP falls inside the rule's CIDR; nodes that already have a group,
 * or match no rule, are left untouched.
 */

import api from '../axiosInstance';

export interface NodeAssignmentRule {
  id: number;
  name: string;
  priority: number;
  enabled: boolean;
  conditionType: 'ip_cidr';
  conditionValue: string;
  groupId: string;
  createdBy: string;
  lastRunAt: string | null;
  lastMatchedCount: number | null;
  createdAt: string;
  updatedAt: string;
}

export interface NodeAssignmentRuleInput {
  name: string;
  conditionValue: string;
  groupId: string;
  priority?: number;
  enabled?: boolean;
}

export const fetchNodeAssignmentRules = async (): Promise<NodeAssignmentRule[]> => {
  const response = await api.get('/node-assignment-rules');
  return (response.data.rules as NodeAssignmentRule[]) ?? [];
};

export const createNodeAssignmentRule = async (payload: NodeAssignmentRuleInput): Promise<NodeAssignmentRule> => {
  const response = await api.post('/node-assignment-rules', payload);
  return response.data.rule as NodeAssignmentRule;
};

export const updateNodeAssignmentRule = async (
  id: number,
  payload: NodeAssignmentRuleInput
): Promise<NodeAssignmentRule> => {
  const response = await api.put(`/node-assignment-rules/${id}`, payload);
  return response.data.rule as NodeAssignmentRule;
};

export const deleteNodeAssignmentRule = async (id: number): Promise<void> => {
  await api.delete(`/node-assignment-rules/${id}`);
};

export const runNodeAssignmentRulesNow = async (): Promise<{ rulesEvaluated: number; totalAssigned: number }> => {
  const response = await api.post('/node-assignment-rules/run');
  return response.data;
};
