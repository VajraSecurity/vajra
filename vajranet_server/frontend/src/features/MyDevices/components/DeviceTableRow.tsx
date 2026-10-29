import { useState, memo } from 'react';
import type { ReactNode } from 'react';
import { motion } from 'motion/react';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { Checkbox } from '../../../components/ui/checkbox';
import { GroupCell } from './GroupCell';
import { StatusBadge } from './StatusBadge';
import { getDeviceIcon } from '../utils/deviceFormatters';
import type { Device, SecurityProductChange } from '../types';

/**
 * Memoized desktop table row. Polling only replaces the object reference for
 * devices whose data actually changed (see `areNodesEquivalent`/`nodesData`
 * in the parent), so `memo`'s default shallow prop comparison lets untouched
 * rows skip re-rendering entirely when e.g. one device's security_products
 * flips state.
 */
export const DeviceTableRow = memo(function DeviceTableRow({
  device,
  index,
  isSelected,
  isExtConnected,
  isWindowsDevice,
  openUpward,
  groupsMap,
  pendingChange,
  onSelectRow,
  onToggleSelect,
  onAcknowledge,
  onRename,
  renderSecurityTools,
}: {
  device: Device;
  index: number;
  isSelected: boolean;
  isExtConnected: boolean;
  isWindowsDevice: boolean;
  openUpward: boolean;
  groupsMap: Record<string, string>;
  pendingChange?: { changes: SecurityProductChange[]; detectedAt: number };
  onSelectRow: (id: string) => void;
  onToggleSelect: (id: string) => void;
  onAcknowledge: (id: string) => void;
  onRename: (device: Device) => void;
  onToggleCritical: (device: Device) => void;
  renderSecurityTools: (device: Device, isWindowsDevice: boolean, isExtConnected: boolean) => ReactNode;
}) {
  const [pendingPopoverOpen, setPendingPopoverOpen] = useState(false);
  return (
    <motion.tr
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: Math.min(index, 12) * 0.02 }}
      onClick={() => onSelectRow(device.id)}
      className={`cursor-pointer transition-colors ${isSelected
        ? 'bg-blue-50/70 ring-1 ring-inset ring-blue-200'
        : device.critical
          ? 'bg-purple-50/40 hover:bg-purple-50/70'
          : device.isolated
            ? 'bg-blue-50/30 hover:bg-blue-50/60'
            : 'hover:bg-slate-50'
        } ${device.critical ? 'border-l-4 border-l-purple-500' : ''} ${pendingChange ? 'ring-2 ring-amber-400' : ''}`}
    >
      <td className="px-4 py-4" onClick={(e) => e.stopPropagation()}>
        <Checkbox
          size="small"
          checked={isSelected}
          onChange={() => onToggleSelect(String(device.id))}
          sx={{ padding: '2px', '&.Mui-checked': { color: '#2563eb' } }}
        />
      </td>

      <td className="px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-700">
            {getDeviceIcon(device.type)}
          </div>
          <div className="relative min-w-0 group">
            <div className="flex items-center gap-2">
              <span
                role="button"
                tabIndex={0}
                onClick={(e) => {
                  e.stopPropagation();
                  onRename(device);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    e.stopPropagation();
                    onRename(device);
                  }
                }}
                className="truncate text-sm font-semibold text-slate-900 cursor-pointer"
                aria-label={`Rename ${device.name}`}
              >
                {device.name}
              </span>
              {device.critical && (
                <span className="inline-flex items-center gap-1 rounded-full border border-purple-200 bg-purple-50 px-2 py-0.5 text-[10px] font-semibold text-purple-800">
                  <i className="fa fa-star text-[9px]" aria-hidden="true" />
                  Critical
                </span>
              )}
              {device.isolated && (
                <span className="inline-flex items-center gap-1 rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-[10px] font-semibold text-blue-800">
                  <i className="fa fa-lock text-[9px]" aria-hidden="true" />
                  Isolated
                </span>
              )}
              {pendingChange && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setPendingPopoverOpen((v) => !v);
                  }}
                  className="inline-flex items-center gap-1 rounded-full border border-amber-300 bg-amber-50 px-2 py-0.5 text-[10px] font-semibold text-amber-800 hover:bg-amber-100"
                  aria-expanded={pendingPopoverOpen}
                  aria-label="View security status changes"
                >
                  <i className="fa fa-triangle-exclamation text-[9px]" aria-hidden="true" />
                  Changed
                </button>
              )}
            </div>
            <div className="truncate text-xs text-slate-500">{device.os}</div>

            {pendingChange && (
              <div
                onClick={(e) => e.stopPropagation()}
                className={`pointer-events-none absolute left-0 top-full z-20 mt-2 w-[min(360px,calc(100vw-2rem))] rounded-xl border border-amber-200 bg-white/95 p-3 text-xs text-slate-800 shadow-xl backdrop-blur group-hover:block ${pendingPopoverOpen ? 'block' : 'hidden'}`}
              >
                <div className="mb-2 flex items-center justify-between gap-2">
                  <div className="font-semibold text-amber-800">Security status changed</div>
                  <div className="text-[10px] text-slate-400">
                    {new Date(pendingChange.detectedAt).toLocaleTimeString()}
                  </div>
                </div>
                <ul className="list-disc space-y-1 pl-4 text-[11px]">
                  {pendingChange.changes.map((c, i) => (
                    <li key={`${c.name}-${i}`}>
                      <span className="font-semibold">{c.name}</span>: {c.from} → {c.to}
                    </li>
                  ))}
                </ul>
                <div className="mt-3 flex justify-end">
                  <button
                    className="pointer-events-auto inline-flex items-center justify-center rounded-lg bg-amber-600 px-3 py-1.5 text-[11px] font-semibold text-white hover:bg-amber-700"
                    onClick={(e) => {
                      e.stopPropagation();
                      onAcknowledge(String(device.id));
                    }}
                  >
                    OK
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </td>

      <td className="px-4 py-4 lg:table-cell">
        <GroupCell
          groupIds={device.groupIds}
          groupsMap={groupsMap}
          openUpward={openUpward}
        />
      </td>

      <td className="whitespace-nowrap px-4 py-4 text-sm text-slate-600">
        {device.enrolledDate}
      </td>

      <td className="whitespace-nowrap px-4 py-4 text-sm text-slate-600">
        <div>{device.lastSeen}</div>
      </td>

      <td className="px-4 py-4">
        <StatusBadge status={device.displayStatus} />
      </td>

      <td className="hidden whitespace-nowrap px-4 py-4 xl:table-cell">
        <div className="flex max-w-[220px] flex-wrap items-start gap-1">
          {renderSecurityTools(device, isWindowsDevice, isExtConnected)}
        </div>
      </td>

      <td className="px-2 py-4 text-right" onClick={(e) => e.stopPropagation()}>
        <div className=" flex items-center justify-end gap-1.5">
          <button
            onClick={() => onSelectRow(device.id)}
            className="metallic-btn-blue whitespace-nowrap flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md border-transparent"
          >
            <VisibilityIcon sx={{ fontSize: 10 }} /> Quick view
          </button>
        </div>
      </td>

    </motion.tr>
  );
});
