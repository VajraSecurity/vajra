import { memo } from 'react';
import type { ReactNode } from 'react';
import { Checkbox } from '../../../components/ui/checkbox';
import { GroupCell } from './GroupCell';
import { StatusBadge } from './StatusBadge';
import { RowActionsMenu } from './RowActionsMenu';
import { getDeviceIcon, getRelativeTime } from '../utils/deviceFormatters';
import type { Device } from '../types';

/** Memoized mobile card — same reference-preservation benefit as `DeviceTableRow` above. */
export const DeviceMobileCard = memo(function DeviceMobileCard({
  device,
  isSelected,
  isExtConnected,
  isWindowsDevice,
  groupsMap,
  onSelectRow,
  onToggleSelect,
  onQuickView,
  onRename,
  onToggleCritical,
  renderSecurityTools,
}: {
  device: Device;
  isSelected: boolean;
  isExtConnected: boolean;
  isWindowsDevice: boolean;
  groupsMap: Record<string, string>;
  onSelectRow: (id: string) => void;
  onToggleSelect: (id: string) => void;
  onQuickView: (deviceId: string) => void;
  onRename: (device: Device) => void;
  onToggleCritical: (device: Device) => void;
  renderSecurityTools: (device: Device, isWindowsDevice: boolean, isExtConnected: boolean) => ReactNode;
}) {
  return (
    <div
      onClick={() => onSelectRow(device.id)}
      className={`cursor-pointer rounded-xl border p-4 shadow-sm transition active:scale-[0.99] ${isSelected ? 'border-blue-300 bg-blue-50/50 ring-1 ring-blue-200' : 'border-slate-200 bg-white'
        } ${device.critical ? 'border-l-4 border-l-purple-500' : ''}`}
    >
      <div className="flex items-start gap-3">
        <div onClick={(e) => e.stopPropagation()} className="pt-1.5">
          <Checkbox
            size="small"
            checked={isSelected}
            onChange={() => onToggleSelect(String(device.id))}
            sx={{ padding: '10px', '&.Mui-checked': { color: '#2563eb' } }}
          />
        </div>
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-700">
          {getDeviceIcon(device.type)}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-slate-900">{device.name}</div>
              <div className="truncate text-xs text-slate-500">{device.os}</div>
            </div>
            <RowActionsMenu
              device={device}
              triggerAriaLabel={`Actions for ${device.name}`}
              triggerClassName="shrink-0 p-3"
              onQuickView={onQuickView}
              onRename={onRename}
              onToggleCritical={onToggleCritical}
            />
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <StatusBadge status={device.displayStatus} />
            {device.critical && (
              <span className="inline-flex items-center gap-1 rounded-full border border-purple-200 bg-purple-50 px-2 py-0.5 text-[10px] font-semibold text-purple-800">
                <i className="fa fa-star text-[9px]" aria-hidden="true" /> Critical
              </span>
            )}
            {device.isolated && (
              <span className="inline-flex items-center gap-1 rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-[10px] font-semibold text-blue-800">
                <i className="fa fa-lock text-[9px]" aria-hidden="true" /> Isolated
              </span>
            )}
          </div>

          <div className="mt-2.5 flex items-center justify-between text-xs text-slate-500">
            <span>Last seen {device.lastSeen} <span className="text-slate-400">({getRelativeTime(device.last_seen)})</span></span>
            <GroupCell groupIds={device.groupIds} groupsMap={groupsMap} />
          </div>
          <div className="mt-1 text-xs text-slate-400">Enrolled {device.enrolledDate}</div>

          <div className="mt-2 flex flex-wrap gap-1">{renderSecurityTools(device, isWindowsDevice, isExtConnected)}</div>
        </div>
      </div>
    </div>
  );
});
