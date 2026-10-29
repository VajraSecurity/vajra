import { ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import CellValue from './CellValue';
import { PRIMARY_COLUMN } from './formatters';
import type { DataRow } from './types';

interface MobileRowCardProps {
    row: DataRow;
    columns: string[];
    fallbackValue: string;
    onRowClick?: (row: DataRow) => void;
    selected: boolean;
}

const MobileRowCard = ({ row, columns, fallbackValue, onRowClick, selected }: MobileRowCardProps) => {
    const primaryCol = columns.includes(PRIMARY_COLUMN) ? PRIMARY_COLUMN : columns[0];
    const secondaryCols = columns.filter((c) => c !== primaryCol);

    return (
        <div
            role={onRowClick ? 'button' : undefined}
            tabIndex={onRowClick ? 0 : undefined}
            onClick={() => onRowClick?.(row)}
            onKeyDown={(e) => {
                if (onRowClick && (e.key === 'Enter' || e.key === ' ')) {
                    e.preventDefault();
                    onRowClick(row);
                }
            }}
            className={cn(
                'rounded-xl border border-slate-100 bg-white p-4 shadow-sm transition-colors',
                onRowClick && 'cursor-pointer active:bg-slate-50',
                selected && 'border-blue-200 bg-blue-50/40 ring-1 ring-blue-100'
            )}
        >
            <div className="flex items-start justify-between gap-3">
                <p className="min-w-0 flex-1 truncate text-sm font-semibold text-slate-800">
                    <CellValue row={row} column={primaryCol} fallbackValue={fallbackValue} />
                </p>
                {onRowClick && <ChevronRight className="mt-0.5 size-4 shrink-0 text-slate-300" />}
            </div>

            <dl className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2">
                {secondaryCols.map((col) => (
                    <div key={col} className="min-w-0">
                        <dt className="truncate text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                            {col.replace(/_/g, ' ')}
                        </dt>
                        <dd className="mt-0.5 truncate text-xs font-medium text-slate-600">
                            <CellValue row={row} column={col} fallbackValue={fallbackValue} />
                        </dd>
                    </div>
                ))}
            </dl>
        </div>
    );
};

export default MobileRowCard;
