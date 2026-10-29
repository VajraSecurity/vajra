import { Inbox, SearchX } from 'lucide-react';
import type { EmptyStateConfig } from './types';

interface EmptyStateProps {
    isFiltering: boolean;
    onClearFilters: () => void;
    config?: EmptyStateConfig;
}

const EmptyState = ({ isFiltering, onClearFilters, config }: EmptyStateProps) => {
    if (isFiltering) {
        return (
            <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
                <div className="mb-4 flex size-12 items-center justify-center rounded-full bg-slate-50 text-slate-300">
                    <SearchX className="size-6" />
                </div>
                <p className="text-sm font-semibold text-slate-700">No matching results</p>
                <p className="mt-1 max-w-xs text-sm text-slate-400">
                    Try a different search term or clear your filters to see all rows.
                </p>
                <button
                    type="button"
                    onClick={onClearFilters}
                    className="mt-4 inline-flex h-8 items-center rounded-lg border border-slate-200 px-3 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-50"
                >
                    Clear filters
                </button>
            </div>
        );
    }

    const Icon = config?.icon ?? Inbox;

    return (
        <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
            <div className="mb-4 flex size-12 items-center justify-center rounded-full bg-slate-50 text-slate-300">
                <Icon className="size-6" />
            </div>
            <p className="text-sm font-semibold text-slate-700">{config?.title ?? 'No data yet'}</p>
            <p className="mt-1 max-w-xs text-sm text-slate-400">
                {config?.description ?? 'Nothing has been reported for this view yet.'}
            </p>
        </div>
    );
};

export default EmptyState;
