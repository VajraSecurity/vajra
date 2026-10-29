import { ChevronDown, ChevronUp, ChevronsUpDown, Eye } from 'lucide-react';
import { cn } from '@/lib/utils';
import Pagination from '@/components/ui/pagination';
import CellValue from './CellValue';
import EmptyState from './EmptyState';
import MobileRowCard from './MobileRowCard';
import { TableSkeleton } from '@/components/ui/table-skeleton';
import Toolbar from './Toolbar';
import { MONO_COLUMNS, PRIMARY_COLUMN, SEVERITY_COLUMN, columnMinWidth } from './formatters';
import { useTableState } from './useTableState';
import type { DynamicDataTableProps } from './types';

const PAGE_SIZE_OPTIONS = [10, 25, 50];

const DynamicDataTable = ({
    columns,
    data,
    rowsPerPage = 10,
    fallbackValue = '—',
    onRowClick,
    loading = false,
    onRefresh,
    emptyState,
    searchPlaceholder = 'Search…',
}: DynamicDataTableProps) => {
    const {
        search,
        setSearch,
        severityFilter,
        setSeverityFilter,
        severityOptions,
        sort,
        toggleSort,
        currentPage,
        setCurrentPage,
        rowsPerPage: pageSize,
        setRowsPerPage,
        totalPages,
        paginatedRows,
        totalFiltered,
        isFiltering,
        clearFilters,
        selectedRowKey,
        setSelectedRowKey,
        rowIdentity,
    } = useTableState(columns, data, rowsPerPage);

    const showPagination = !loading && totalFiltered > pageSize;
    const hasRows = paginatedRows.length > 0;

    const handleRowClick = (row: Record<string, unknown>, key: string) => {
        setSelectedRowKey(key);
        onRowClick?.(row);
    };

    // Severity + row-actions read best pinned to the right so they stay visible while scrolling wide tables.
    // Backgrounds here must be fully opaque (no alpha) — sticky cells render on top of whatever
    // column content is scrolling underneath them, so any transparency lets it ghost through.
    const severityStickyOffset = onRowClick ? 'right-14' : 'right-0';
    const stickyCellBg = (rowIndex: number, isSelected: boolean) =>
        isSelected ? 'bg-blue-100' : rowIndex % 2 === 0 ? 'bg-slate-50' : 'bg-white';

    return (
        <div className="flex w-full flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm">
            {!loading && (
                <Toolbar
                    search={search}
                    onSearchChange={setSearch}
                    searchPlaceholder={searchPlaceholder}
                    severityOptions={severityOptions}
                    severityFilter={severityFilter}
                    onSeverityFilterChange={setSeverityFilter}
                    isFiltering={isFiltering}
                    onClearFilters={clearFilters}
                    totalFiltered={totalFiltered}
                    totalAll={data.length}
                    onRefresh={onRefresh}
                />
            )}

            {loading ? (
                <TableSkeleton columns={columns.length + (onRowClick ? 1 : 0)} rows={8} />
            ) : !hasRows ? (
                <EmptyState isFiltering={isFiltering} onClearFilters={clearFilters} config={emptyState} />
            ) : (
                <>
                    {/* Desktop / tablet: full table, scrolls both ways within a capped height so the page doesn't stretch as rows/page-size grow */}
                    <div className="table-scrollbar hidden sm:block max-h-[65vh] overflow-auto">
                        <table className="min-w-full table-fixed border-separate border-spacing-0 text-left text-sm">
                            <colgroup>
                                {columns.map((col) => (
                                    <col key={col} style={{ width: `${columnMinWidth(col)}px` }} />
                                ))}
                                {onRowClick && <col style={{ width: '56px' }} />}
                            </colgroup>
                            <thead>
                                <tr>
                                    {columns.map((col) => {
                                        const isSorted = sort.column === col;
                                        const isSeverityCol = col === SEVERITY_COLUMN;
                                        return (
                                            <th
                                                key={col}
                                                scope="col"
                                                aria-sort={isSorted ? (sort.direction === 'asc' ? 'ascending' : 'descending') : 'none'}
                                                className={cn(
                                                    'border-b border-slate-200 py-3 px-4 text-xs font-semibold tracking-wide text-slate-500 uppercase sticky top-0 z-10 bg-slate-100/95 backdrop-blur-sm dark:bg-slate-800/95 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)]',
                                                    isSeverityCol &&
                                                        cn(
                                                            'sticky z-20 border-l bg-slate-100 dark:bg-slate-800',
                                                            severityStickyOffset
                                                        )
                                                )}
                                            >
                                                <button
                                                    type="button"
                                                    onClick={() => toggleSort(col)}
                                                    title={col.replace(/_/g, ' ')}
                                                    className="group flex w-full min-w-0 items-center gap-1 rounded transition-colors hover:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40"
                                                >
                                                    <span className="min-w-0 truncate">{col.replace(/_/g, ' ').toUpperCase()}</span>
                                                    {isSorted ? (
                                                        sort.direction === 'asc' ? (
                                                            <ChevronUp className="size-3.5 shrink-0 text-slate-500" />
                                                        ) : (
                                                            <ChevronDown className="size-3.5 shrink-0 text-slate-500" />
                                                        )
                                                    ) : (
                                                        <ChevronsUpDown className="size-3.5 shrink-0 text-slate-300 opacity-0 transition-opacity group-hover:opacity-100" />
                                                    )}
                                                </button>
                                            </th>
                                        );
                                    })}
                                    {onRowClick && (
                                        <th
                                            scope="col"
                                            className="sticky top-0 right-0 z-20 w-14 border-b-2 border-slate-300 dark:border-slate-600 shadow-[0_1px_2px_rgba(15,23,42,0.06)] bg-slate-100 px-2 py-3 text-right text-xs font-semibold tracking-wide text-slate-400 uppercase dark:bg-slate-800"
                                        >
                                            <span className="sr-only">Actions</span>
                                        </th>
                                    )}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {paginatedRows.map((row, rowIndex) => {
                                    const key = rowIdentity(row, (currentPage - 1) * pageSize + rowIndex);
                                    const isSelected = selectedRowKey === key;
                                    return (
                                        <tr
                                            key={key}
                                            onClick={() => onRowClick && handleRowClick(row, key)}
                                            className={cn(
                                                'group/row relative bg-white transition-colors duration-150 odd:bg-slate-50/40',
                                                onRowClick && 'cursor-pointer hover:bg-blue-50/50',
                                                isSelected && 'bg-blue-50/70 hover:bg-blue-50/70'
                                            )}
                                        >
                                            {columns.map((col, colIdx) => {
                                                const rawValue = row[col];
                                                const titleAttr =
                                                    typeof rawValue === 'string' || typeof rawValue === 'number'
                                                        ? String(rawValue)
                                                        : undefined;
                                                const isSeverityCol = col === SEVERITY_COLUMN;
                                                return (
                                                    <td
                                                        key={col}
                                                        title={titleAttr}
                                                        className={cn(
                                                            'relative truncate py-4 px-4 text-sm',
                                                            col === PRIMARY_COLUMN
                                                                ? 'font-semibold text-slate-800'
                                                                : 'font-normal text-slate-600',
                                                            MONO_COLUMNS.has(col) && 'font-mono text-[13px] text-slate-500',
                                                            isSeverityCol &&
                                                                cn(
                                                                    'sticky z-[5] border-l border-slate-100',
                                                                    severityStickyOffset,
                                                                    stickyCellBg(rowIndex, isSelected),
                                                                    onRowClick && !isSelected && 'group-hover/row:bg-blue-50'
                                                                )
                                                        )}
                                                    >
                                                        {colIdx === 0 && (
                                                            <span
                                                                aria-hidden="true"
                                                                className={cn(
                                                                    'absolute left-0 top-0 bottom-0 w-[3px] origin-center scale-y-0 bg-blue-600 transition-transform duration-200',
                                                                    (isSelected) && 'scale-y-100',
                                                                    'group-hover/row:scale-y-100'
                                                                )}
                                                            />
                                                        )}
                                                        <CellValue row={row} column={col} fallbackValue={fallbackValue} />
                                                    </td>
                                                );
                                            })}

                                            {onRowClick && (
                                                <td
                                                    className={cn(
                                                        'sticky right-0 z-[5] w-14 px-3 text-right',
                                                        stickyCellBg(rowIndex, isSelected),
                                                        !isSelected && 'group-hover/row:bg-blue-50'
                                                    )}
                                                >
                                                    <button
                                                        type="button"
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            handleRowClick(row, key);
                                                        }}
                                                        aria-label={`View details for ${String(row[PRIMARY_COLUMN] ?? 'row')}`}
                                                        className="inline-flex size-8 items-center justify-center rounded-lg text-slate-400 opacity-70 transition-all hover:bg-blue-50 hover:text-blue-600 focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40 group-hover/row:opacity-100"
                                                    >
                                                        <Eye className="size-4" />
                                                    </button>
                                                </td>
                                            )}
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>

                    {/* Mobile: stacked cards, all data + actions preserved */}
                    <div className="table-scrollbar flex flex-col gap-2.5 p-3 max-h-[65vh] overflow-y-auto sm:hidden">
                        {paginatedRows.map((row, rowIndex) => {
                            const key = rowIdentity(row, (currentPage - 1) * pageSize + rowIndex);
                            return (
                                <MobileRowCard
                                    key={key}
                                    row={row}
                                    columns={columns}
                                    fallbackValue={fallbackValue}
                                    selected={selectedRowKey === key}
                                    onRowClick={onRowClick ? (r) => handleRowClick(r, key) : undefined}
                                />
                            );
                        })}
                    </div>
                </>
            )}

            {showPagination && (
                <Pagination
                    page={currentPage}
                    totalPages={totalPages}
                    total={totalFiltered}
                    pageSize={pageSize}
                    onPageChange={setCurrentPage}
                    onPageSizeChange={setRowsPerPage}
                    pageSizeOptions={PAGE_SIZE_OPTIONS}
                />
            )}
        </div>
    );
};

export default DynamicDataTable;
