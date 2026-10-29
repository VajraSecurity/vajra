import { Badge } from '@/components/ui/badge';
import { CVE_COUNT_COLUMN, KEV_COLUMN, SEVERITY_COLUMN, STATUS_COLUMN, severityBadgeVariant, statusBadgeVariant } from './formatters';
import type { DataRow } from './types';

interface CellValueProps {
    row: DataRow;
    column: string;
    fallbackValue: string;
}

const CellValue = ({ row, column, fallbackValue }: CellValueProps) => {
    const value = row[column];

    // Checked before the general null/empty guard below: `false` (not a
    // known exploited CVE) is a real, falsy value for this column, not a
    // missing one — it renders "No" rather than the shared fallback dash.
    if (column === KEV_COLUMN) {
        return value === true
            ? <span className="font-semibold text-red-600">Yes</span>
            : <span className="text-slate-400">No</span>;
    }

    if (value == null || value === '') {
        return <span className="text-slate-400">{fallbackValue}</span>;
    }

    if (column === CVE_COUNT_COLUMN && typeof value === 'number') {
        // Deliberately neutral, not red: severity already carries the risk signal below —
        // a second red badge next to it just competes for attention instead of adding information.
        return value > 0 ? (
            <span className="inline-flex items-center rounded-md bg-slate-100 px-2 py-0.5 text-xs font-semibold tabular-nums text-slate-600">
                {value} CVE{value === 1 ? '' : 's'}
            </span>
        ) : (
            <span className="text-slate-400">0</span>
        );
    }

    if (column === SEVERITY_COLUMN && typeof value === 'string') {
        return <Badge variant={severityBadgeVariant(value)}>{value.toUpperCase()}</Badge>;
    }

    if (column === STATUS_COLUMN && typeof value === 'string') {
        return <Badge variant={statusBadgeVariant(value)}>{value}</Badge>;
    }

    if (typeof value === 'boolean') return <span>{value ? 'Yes' : 'No'}</span>;

    if (typeof value === 'object') {
        try {
            return <span>{JSON.stringify(value)}</span>;
        } catch {
            return <span className="text-slate-400">{fallbackValue}</span>;
        }
    }

    return <span>{String(value)}</span>;
};

export default CellValue;
