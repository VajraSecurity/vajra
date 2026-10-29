/**
 * NodesView constants: tab config, error/success messages, storage keys.
 */

import type { NodesViewTabConfig } from './types';

export const NODES_VIEW_TABS: NodesViewTabConfig[] = [
  { id: 'details', label: 'Details', icon: 'fa-info-circle', requireOnline: false },
  { id: 'responsive-actions', label: 'Device Controls', icon: 'fa-bolt', requireOnline: false },
  { id: 'wifi', label: 'Wireless', icon: 'fa-wifi', requireOnline: false },
  // Compliance now contains subtabs: Machine/SEBI/Profile.
  // Keep SEBI/Profile supported via deep-link query param, but don't show as top-level tabs.
  { id: 'compliance', label: 'Compliance', icon: 'fa-check-circle', requireOnline: false, hideOnLinux: true },
  { id: 'firewall-rules', label: 'Firewall Rules', icon: 'fa-fire', requireOnline: false, hideOnLinux: true },
  { id: 'bios-info', label: 'BIOS Info', icon: 'fa-microchip', requireOnline: false, hideOnLinux: true },
  { id: 'storage', label: 'Storage', icon: 'fa-hard-drive', requireOnline: false },
  { id: 'update-history', label: 'Update History', icon: 'fa-history', requireOnline: false, hideOnLinux: true },
  { id: 'programs', label: 'Programs', icon: 'fa-th-list', requireOnline: false },
  { id: 'send-message', label: 'Send Message', icon: 'fa-paper-plane', requireOnline: false },
];

export const ERROR_MESSAGES = {
  NODE_DATA_NOT_AVAILABLE: 'Node data not available',
  EMPTY_MESSAGE: 'Please enter a message',
  INVALID_MESSAGE: 'Invalid message content',
  EMPTY_PORT: 'Please enter or select a port',
  INVALID_PORT: 'Invalid port number',
  EMPTY_IP: 'Please enter an IP address',
  INVALID_IP: 'Invalid IP address',
  AGENT_INSTALLER_MISSING: 'Agent installer URL is not configured',
  FAILED_UPGRADE: 'Failed to upgrade agent',
} as const;

export const SUCCESS_MESSAGES = {
  MESSAGE_SENT: 'Message sent successfully',
  PORT_UPDATED: 'Port rule updated',
  IP_ACTION_SUCCESS: 'IP rule updated successfully',
} as const;
