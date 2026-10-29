import type { LucideIcon } from 'lucide-react';

export type DataRow = Record<string, unknown>;

export type SortDirection = 'asc' | 'desc';

export interface SortState {
    column: string | null;
    direction: SortDirection;
}

export interface EmptyStateConfig {
    icon?: LucideIcon;
    title?: string;
    description?: string;
}

export interface DynamicDataTableProps {
    columns: string[];
    data: DataRow[];
    rowsPerPage?: number;
    fallbackValue?: string;
    onRowClick?: (row: DataRow) => void;
    /** Shows the skeleton loader instead of table rows/toolbar results. */
    loading?: boolean;
    /** Enables the refresh button in the toolbar. */
    onRefresh?: () => void;
    /** Copy shown when there is no data at all (before any filtering). */
    emptyState?: EmptyStateConfig;
    searchPlaceholder?: string;
}
