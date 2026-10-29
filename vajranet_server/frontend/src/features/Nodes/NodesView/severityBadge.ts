import type { BadgeProps } from '@/components/ui/badge';

export const severityBadgeVariant = (value?: string): NonNullable<BadgeProps['variant']> => {
    const v = (value || '').toLowerCase();
    if (v.includes('critical')) return 'destructive';
    if (v.includes('high')) return 'high';
    if (v.includes('medium')) return 'warning';
    return 'neutral';
};

export const SEVERITY_RANK: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
};
