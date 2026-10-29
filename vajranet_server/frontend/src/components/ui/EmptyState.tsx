import { Inbox, type LucideIcon } from 'lucide-react';

export interface EmptyStateAction {
    label: string;
    onClick: () => void;
}

export interface EmptyStateProps {
    icon?: LucideIcon;
    title: string;
    description?: string;
    action?: EmptyStateAction;
}

const EmptyState = ({ icon: Icon = Inbox, title, description, action }: EmptyStateProps) => {
    return (
        <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
            <div className="mb-4 flex size-12 items-center justify-center rounded-full bg-slate-50 text-slate-300">
                <Icon className="size-6" />
            </div>
            <p className="text-sm font-semibold text-slate-700">{title}</p>
            {description && (
                <p className="mt-1 max-w-xs text-sm text-slate-400">{description}</p>
            )}
            {action && (
                <button
                    type="button"
                    onClick={action.onClick}
                    className="mt-4 inline-flex h-8 items-center rounded-lg border border-slate-200 px-3 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-50"
                >
                    {action.label}
                </button>
            )}
        </div>
    );
};

export default EmptyState;
