import type { NodeUiOutbound } from '../../services/nodeUiBulkSend';
import { isLinuxNode, type NodeRow } from './responsiveNodeUtils';

export function usbStorageMessage(host: string, action: 'enable' | 'disable', reason: string): NodeUiOutbound {
  return {
    type: 'agent',
    host_identifier: host,
    params: {
      agent: 'removableDevice',
      action,
      arg1: reason,
      reason,
    },
  };
}

export function bluetoothRadioMessage(
  host: string,
  isLinux: boolean,
  action: 'enable' | 'disable',
  reason: string,
): NodeUiOutbound {
  if (isLinux) {
    return {
      type: 'agent',
      host_identifier: host,
      params: {
        agent: 'bluetooth',
        action,
        arg1: reason,
        reason,
      },
    };
  }
  const commandKey = action === 'enable' ? '48' : '47';
  return {
    type: 'agent',
    host_identifier: host,
    params: {
      agent: 'powershell',
      command_keys: [commandKey],
      arg1: reason,
      reason,
    },
  };
}

export function buildUsbCommands(rows: NodeRow[], action: 'enable' | 'disable', reason: string): NodeUiOutbound[] {
  return rows.map((r) => usbStorageMessage(r.host_identifier, action, reason));
}

export function buildBluetoothCommands(rows: NodeRow[], action: 'enable' | 'disable', reason: string): NodeUiOutbound[] {
  return rows.map((r) => bluetoothRadioMessage(r.host_identifier, isLinuxNode(r), action, reason));
}
