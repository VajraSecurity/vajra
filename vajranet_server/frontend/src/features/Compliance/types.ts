/**
 * Shared types for the Compliance feature — extracted verbatim, no content
 * changes.
 */

import type { NodeData } from '../Nodes/NodesView/types';

export type ControlPassRate = {
  key: string;
  label: string;
  passRatePct: number | null;
  passHosts: number;
  failHosts: number;
  eligibleHosts: number;
};

/**
 * Which analytics widgets behind the overview failed to load. The overview is
 * assembled with Promise.allSettled, so a rejected call still yields a zero —
 * consumers must check the flag before printing the paired number, or an
 * unknown reads as a measured 0.
 */
export type ComplianceOverviewFailures = {
  /** Gates `defender`. */
  defender: boolean;
  /** Gates `alerts.openCount` / `alerts.closeCount`. */
  alerts: boolean;
  /** Gates `alerts.weeklyTotals`. */
  weeklyAlerts: boolean;
};

export type ComplianceOverview = {
  generatedAt: number;
  failed: ComplianceOverviewFailures;
  totalNodes: number;
  onlineNodes: number;
  offlineNodes: number;
  osBreakdown: Array<{ name: string; count: number }>;
  windowsHosts: number;

  alerts: {
    openCount: number;
    closeCount: number;
    weeklyTotals: Array<{ dateLabel: string; dateKey: string; total: number }>;
    topMachines: Array<{
      hostname: string;
      hostIdentifier: string;
      totalAlerts: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      information: number;
    }>;
  };

  defender: {
    on: number;
    off: number;
    total: number;
  };
};

export type OrgSnapshot = {
  id: number;
  snapshot_at: number;
  total_nodes: number | null;
  windows_hosts: number | null;
  windows_with_results: number | null;
  fully_compliant_nodes: number | null;
  avg_compliance_percent: number | null;
  strong_count: number | null;
  moderate_count: number | null;
  needs_attention_count: number | null;
  control_pass_rates: ControlPassRate[];
  source: string;
  // Present once the group-scoping migration lands; null = fleet-wide/legacy snapshot.
  owner_group_ids?: string[] | null;
  fully_compliant_nodes_list?: string[] | null;
  non_compliant_nodes_list?: string[] | null;
};

export type ComplianceType = 'overview' | 'sebi' | 'irdai' | 'certin' | 'iso27001' | 'soc2';

export type ComplianceRouteState = {
  node?: NodeData;
} | null;

