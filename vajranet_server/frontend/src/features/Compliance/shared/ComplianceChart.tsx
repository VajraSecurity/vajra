/**
 * Shared pie-chart pieces for the compliance views (Sebi/CertIn/IRDAI per-node
 * tabs and the org-wide Compliance overview) — was copy-pasted verbatim
 * across all 4 files.
 */

import { Sector } from 'recharts';

// eslint-disable-next-line react-refresh/only-export-components
export const PIE_COLORS = ['#136f63', '#ab3428'];

interface ActiveShapeProps {
  cx?: number;
  cy?: number;
  innerRadius?: number;
  outerRadius?: number;
  startAngle?: number;
  endAngle?: number;
  fill?: string;
  cornerRadius?: number;
}

// eslint-disable-next-line react-refresh/only-export-components
export const renderActiveShape = (props: ActiveShapeProps) => {
  const {
    cx,
    cy,
    innerRadius,
    outerRadius = 0,
    startAngle = 0,
    endAngle = 0,
    fill,
    cornerRadius,
  } = props;

  return (
    <Sector
      cx={cx}
      cy={cy}
      innerRadius={innerRadius}
      outerRadius={outerRadius + 4}
      startAngle={startAngle + 1.5}
      endAngle={endAngle - 1.5}
      fill={fill}
      style={{
        filter: 'drop-shadow(0 4px 12px rgba(0,0,0,0.12))'
      }}
      cornerRadius={cornerRadius}
    />
  );
};

interface TooltipPayloadItem {
  name?: string;
  value?: number | string;
  color?: string;
  payload?: { hosts?: string[] };
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: TooltipPayloadItem[];
}

/** Simple tooltip — used by CertIn and IRDAI compliance views. */
export function CustomTooltip({
  active,
  payload,
}: CustomTooltipProps) {
  if (!active || !payload?.length) return null;

  const item = payload[0];

  return (
    <div className="bg-white rounded-lg shadow-lg border border-slate-200 px-3 py-2">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <div
            className="w-2 h-2 rounded-full"
            style={{
              backgroundColor: item.color,
            }}
          />
          <span className="text-sm text-slate-600">
            {item.name}
          </span>
        </div>

        <span className="font-semibold text-slate-900">
          {item.value}
        </span>
      </div>
    </div>
  );
}

/** Tooltip variant with a "which hosts" breakdown — used by Sebi and the Compliance overview. */
export function CustomTooltipWithHosts({
  active,
  payload,
}: CustomTooltipProps) {
  if (!active || !payload?.length) return null;

  const item = payload[0];

  // Defensively coerce: older saved snapshots stored { host_identifier, failed_checks }
  // objects here instead of plain host_identifier strings.
  const hosts: string[] = (Array.isArray(item.payload?.hosts) ? item.payload.hosts : [])
    .map((h: unknown) => (typeof h === 'string' ? h : (h as Record<string, unknown> | null)?.host_identifier))
    .filter((h: unknown): h is string => typeof h === 'string' && h.length > 0);

  return (
    <div className="bg-white rounded-lg shadow-lg border border-slate-200 px-3 py-2">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <div
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: item.color }}
          />
          <span className="text-sm text-slate-600">
            {item.name}
          </span>
        </div>

        <span className="font-semibold text-slate-900 gap-2">
          {item.value}
        </span>
      </div>

      <div className="border-t border-slate-200 mt-2 pt-2">
        <div className="text-xs text-slate-500">
          {hosts.length} Nodes (Host ID)
        </div>

        <div className="mt-1 space-y-1">
          {hosts.slice(0, 3).map((host: string) => (
            <div
              key={host}
              className="text-xs font-mono text-slate-700 break-all"
              title={host}
            >
              {host}
            </div>
          ))}

          {hosts.length > 3 && (
            <div className="text-xs text-slate-500">
              +{hosts.length - 3} more
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
