import type { BadgeProps } from '@/components/ui/badge';
import type { DataRow } from './types';

export const SEVERITY_COLUMN = 'severity';
export const STATUS_COLUMN = 'status';
export const CVE_COUNT_COLUMN = 'cve_count';
export const PRIMARY_COLUMN = 'name';
/** CISA Known Exploited Vulnerabilities flag — set by the vulnexus pipeline's
 * KEV enrichment on programs/deb_packages/rpm_packages (has_kev_cve column).
 * Renamed to the shorter `kev` here purely for a clean column header. */
export const KEV_COLUMN = 'kev';

/** Columns whose values are always short (badges/codes) — they should take less table width than free text. */
export const COMPACT_COLUMNS = new Set([
    'severity',
    'cve_count',
    'status',
    'arch',
    'revision',
    'confinement',
    'snap_type',
    'priority',
    'epoch',
    'installed_size',
    'is_processed',
    'is_cve_processed',
    'kev',
]);

/** Columns rendered in a monospace face — version strings, sizes, ids read better tabular. */
export const MONO_COLUMNS = new Set(['version', 'revision', 'installed_size', 'size', 'cvss_score']);

/**
 * Fixed pixel width for a column. Explicit (not percentage) widths keep the table-fixed layout
 * deterministic — long values truncate with an ellipsis instead of overflowing into neighboring
 * cells, and the pinned severity/action table can size its columns predictably.
 */
export const columnMinWidth = (col: string): number => {
    if (col === PRIMARY_COLUMN) return 220;
    if (col === SEVERITY_COLUMN) return 130;
    if (COMPACT_COLUMNS.has(col)) return 110;
    if (MONO_COLUMNS.has(col)) return 140;
    return 190;
};

export const severityBadgeVariant = (value: string): BadgeProps['variant'] => {
    const v = value.toLowerCase();
    if (v.includes('critical')) return 'destructive';
    if (v.includes('high')) return 'high';
    if (v.includes('medium')) return 'warning';
    if (v.includes('low')) return 'success';
    return 'neutral';
};

export const statusBadgeVariant = (value: string): BadgeProps['variant'] => {
    const v = value.toLowerCase();
    if (v.includes('install ok') || v.includes('active') || v.includes('installed') || v.includes('ok')) return 'success';
    if (v.includes('pending') || v.includes('config')) return 'warning';
    if (v.includes('remove') || v.includes('delete') || v.includes('archiv') || v.includes('uninstall')) return 'destructive';
    return 'neutral';
};

/** Shared severity ranking — lower is more severe. Unrecognized values sort last. */
const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const severityRank = (value: unknown): number => SEVERITY_RANK[String(value ?? '').toUpperCase()] ?? 99;

/** Distinct, sorted severity values present in the current dataset — powers the toolbar filter. */
export const collectSeverityOptions = (data: DataRow[]): string[] => {
    const values = new Set<string>();
    for (const row of data) {
        const raw = row[SEVERITY_COLUMN];
        if (typeof raw === 'string' && raw.trim() && raw !== '—') {
            values.add(raw.toUpperCase());
        }
    }
    return Array.from(values).sort((a, b) => severityRank(a) - severityRank(b));
};

/** Best-effort stable identity for a row, used to preserve selection across re-sorts/re-filters. */
export const rowIdentity = (row: DataRow, fallbackIndex: number): string => {
    const candidateKeys = ['id', 'name', 'sanitized_name'];
    for (const key of candidateKeys) {
        const val = row[key];
        if (typeof val === 'string' || typeof val === 'number') {
            return `${key}:${val}:${row['version'] ?? ''}`;
        }
    }
    return `idx:${fallbackIndex}`;
};

export const compareValues = (a: unknown, b: unknown): number => {
    const aNum = typeof a === 'number' ? a : Number(a);
    const bNum = typeof b === 'number' ? b : Number(b);
    if (!Number.isNaN(aNum) && !Number.isNaN(bNum) && a !== '' && b !== '' && a != null && b != null) {
        return aNum - bNum;
    }
    const aStr = String(a ?? '').toLowerCase();
    const bStr = String(b ?? '').toLowerCase();
    return aStr.localeCompare(bStr);
};

/** Default ordering when the user hasn't chosen a column to sort by: most severe rows surface
 *  first (Critical > High > Medium > Low), CVE count only breaks ties within the same severity —
 *  otherwise a Medium row with many CVEs could outrank a Critical row with few. */
export const defaultSortComparator = (a: DataRow, b: DataRow): number => {
    const severityDiff = severityRank(a[SEVERITY_COLUMN]) - severityRank(b[SEVERITY_COLUMN]);
    if (severityDiff !== 0) return severityDiff;
    const aVal = Number(a.cve_count ?? 0);
    const bVal = Number(b.cve_count ?? 0);
    if (aVal > 0 && bVal === 0) return -1;
    if (aVal === 0 && bVal > 0) return 1;
    return bVal - aVal;
};

export const matchesSearch = (row: DataRow, columns: string[], query: string): boolean => {
    if (!query.trim()) return true;
    const needle = query.trim().toLowerCase();
    return columns.some((col) => {
        const val = row[col];
        if (val == null) return false;
        return String(val).toLowerCase().includes(needle);
    });
};
