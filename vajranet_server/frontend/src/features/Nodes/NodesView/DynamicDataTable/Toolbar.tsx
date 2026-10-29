import { RefreshCw, Search, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

interface ToolbarProps {
    search: string;
    onSearchChange: (value: string) => void;
    searchPlaceholder: string;
    severityOptions: string[];
    severityFilter: string;
    onSeverityFilterChange: (value: string) => void;
    isFiltering: boolean;
    onClearFilters: () => void;
    totalFiltered: number;
    totalAll: number;
    onRefresh?: () => void;
}

const Toolbar = ({
    search,
    onSearchChange,
    searchPlaceholder,
    severityOptions,
    severityFilter,
    onSeverityFilterChange,
    isFiltering,
    onClearFilters,
    totalFiltered,
    totalAll,
    onRefresh,
}: ToolbarProps) => {
    return (
        <div className="flex flex-col gap-3 border-b border-slate-100 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-5">
            <div className="flex flex-1 flex-col gap-2 sm:flex-row sm:items-center">
                <div className="relative w-full sm:max-w-xs">
                    <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
                    <input
                        type="text"
                        value={search}
                        onChange={(e) => onSearchChange(e.target.value)}
                        placeholder={searchPlaceholder}
                        aria-label="Search table"
                        className="h-9 w-full rounded-lg border border-slate-200 bg-slate-50/60 pl-9 pr-8 text-sm text-slate-700 outline-none transition-colors placeholder:text-slate-400 focus:border-blue-300 focus:bg-white focus:ring-3 focus:ring-blue-500/10"
                    />
                    {search && (
                        <button
                            type="button"
                            onClick={() => onSearchChange('')}
                            aria-label="Clear search"
                            className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-0.5 text-slate-400 transition-colors hover:bg-slate-200/70 hover:text-slate-600"
                        >
                            <X className="size-3.5" />
                        </button>
                    )}
                </div>

                {severityOptions.length > 0 && (
                    <Select value={severityFilter} onValueChange={(value) => onSeverityFilterChange(value as string)}>
                        <SelectTrigger size="sm" className="min-w-[130px] bg-slate-50/60 font-medium" aria-label="Filter by severity">
                            <SelectValue placeholder="All severities">
                                {(value: string) =>
                                    value === 'all' ? 'All severities' : value.charAt(0) + value.slice(1).toLowerCase()
                                }
                            </SelectValue>
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value="all">All severities</SelectItem>
                            {severityOptions.map((opt) => (
                                <SelectItem key={opt} value={opt}>
                                    {opt.charAt(0) + opt.slice(1).toLowerCase()}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                )}

                {isFiltering && (
                    <button
                        type="button"
                        onClick={onClearFilters}
                        className="inline-flex h-9 items-center gap-1 rounded-lg px-2 text-sm font-medium text-blue-600 transition-colors hover:bg-blue-50"
                    >
                        <X className="size-3.5" /> Clear filters
                    </button>
                )}
            </div>

            <div className="flex items-center gap-3">
                <p className="whitespace-nowrap text-xs font-medium text-slate-400">
                    {isFiltering ? (
                        <>
                            <span className="text-slate-600">{totalFiltered.toLocaleString()}</span> of{' '}
                            {totalAll.toLocaleString()}
                        </>
                    ) : (
                        <>
                            <span className="text-slate-600">{totalAll.toLocaleString()}</span> total
                        </>
                    )}
                </p>
                {onRefresh && (
                    <button
                        type="button"
                        onClick={onRefresh}
                        aria-label="Refresh data"
                        className={cn(
                            'inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-500',
                            'transition-all hover:border-slate-300 hover:bg-slate-50 hover:text-slate-700 active:scale-95',
                            'focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-blue-500/20'
                        )}
                    >
                        <RefreshCw className="size-4" />
                    </button>
                )}
            </div>
        </div>
    );
};

export default Toolbar;
