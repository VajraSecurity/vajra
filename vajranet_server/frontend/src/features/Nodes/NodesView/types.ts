/**
 * Node and NodesView related types.
 * Used across NodesView container and tab components.
 */

export type NodeStatus = 'online' | 'offline' | 'warning' | 'reconnecting';

export interface SecurityProduct {
  name: string;
  state: string;
}

export interface NodeData {
  id: number;
  name: string;
  status: NodeStatus;
  cpu?: number;
  memory?: number;
  location?: string;
  lastSeen?: string;
  /** Backend host identifier when integrated with API */
  host_identifier?: string;
  hostname?: string;
  original_hostname?: string;
  address?: string;
  os_platform?: string;
  os_name?: string;
  os_arch?: string;
  os_major?: string;
  os_minor?: string;
  os_build?: string;
  osquery_version?: string;
  kernel_version?: string;
  hardware_vendor?: string;
  hardware_version?: string;
  hardware_model?: string;
  hardware_physical_memory?: string;
  /** Set when server cannot read memory_info (e.g. table not migrated). */
  memory_metrics_unavailable_reason?: string;
  hardware_cpu_logical_core?: string;
  hardware_cpu_type?: string;
  enrolled_on?: string;
  last_seen?: number;
  device_group?: string;
  security_products?: SecurityProduct[];
  isolated?: boolean;
  view?: 'details' | 'progarms';
  agent_online?: boolean; // New field to directly reflect agent online status from backend
}

export type NodesViewTabId =
  | 'details'
  | 'responsive-actions'
  | 'port-control'
  | 'ip-control'
  | 'usb-control'
  | 'bluetooth-control'
  | 'defender-control'
  | 'wifi'
  | 'programs'
  | 'compliance'
  | 'sebi-compliance'
  | 'profile-compliance'
  | 'firewall-rules'
  | 'bios-info'
  | 'storage'
  | 'update-history'
  | 'send-message'
  | 'container-list'
  | 'container-query'
  | 'clamav-control';

export interface NodesViewTabConfig {
  id: NodesViewTabId;
  label: string;
  icon: string;
  /** Hide on Windows (e.g. container list/query) */
  hideOnWindows?: boolean;
  hideOnLinux?: boolean;
  /** Disable when node is offline */
  requireOnline?: boolean;
}

export interface PortControlState {
  protocol: string;
  port: string;
  action: 'Allow' | 'Block';
  trafficType: string;
  manualEntry: boolean;
}

export interface IpControlState {
  ip: string;
  action: 'Allow' | 'Block';
  trafficType: string;
}
