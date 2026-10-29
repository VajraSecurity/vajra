import { useEffect, useMemo, useState } from 'react';
import {
    SEVERITY_COLUMN,
    collectSeverityOptions,
    compareValues,
    defaultSortComparator,
    matchesSearch,
    rowIdentity,
} from './formatters';
import type { DataRow, SortState } from './types';

export const useTableState = (columns: string[], data: DataRow[], initialRowsPerPage: number) => {
    const [search, setSearch] = useState('');
    const [severityFilter, setSeverityFilter] = useState<string>('all');
    const [sort, setSort] = useState<SortState>({ column: null, direction: 'desc' });
    const [currentPage, setCurrentPage] = useState(1);
    const [rowsPerPage, setRowsPerPage] = useState(initialRowsPerPage);
    const [selectedRowKey, setSelectedRowKey] = useState<string | null>(null);

    const hasSeverityColumn = columns.includes(SEVERITY_COLUMN);
    const severityOptions = useMemo(
        () => (hasSeverityColumn ? collectSeverityOptions(data) : []),
        [data, hasSeverityColumn]
    );

    // Reset transient view state whenever the dataset shape changes (e.g. switching package-type tabs).
    useEffect(() => {
        setSearch('');
        setSeverityFilter('all');
        setSort({ column: null, direction: 'desc' });
        setCurrentPage(1);
        setSelectedRowKey(null);
    }, [columns]);

    const filteredData = useMemo(() => {
        return data.filter((row) => {
            if (severityFilter !== 'all') {
                const rowSeverity = String(row[SEVERITY_COLUMN] ?? '').toUpperCase();
                if (rowSeverity !== severityFilter) return false;
            }
            return matchesSearch(row, columns, search);
        });
    }, [data, columns, search, severityFilter]);

    const sortedData = useMemo(() => {
        if (!sort.column) return [...filteredData].sort(defaultSortComparator);
        const dir = sort.direction === 'asc' ? 1 : -1;
        const col = sort.column;
        return [...filteredData].sort((a, b) => dir * compareValues(a[col], b[col]));
    }, [filteredData, sort]);

    const totalPages = Math.max(1, Math.ceil(sortedData.length / rowsPerPage));

    useEffect(() => {
        if (currentPage > totalPages) setCurrentPage(totalPages);
    }, [currentPage, totalPages]);

    const paginatedRows = useMemo(() => {
        const start = (currentPage - 1) * rowsPerPage;
        return sortedData.slice(start, start + rowsPerPage);
    }, [currentPage, sortedData, rowsPerPage]);

    const toggleSort = (column: string) => {
        setCurrentPage(1);
        setSort((prev) => {
            if (prev.column !== column) return { column, direction: 'asc' };
            return { column, direction: prev.direction === 'asc' ? 'desc' : 'asc' };
        });
    };

    const isFiltering = search.trim() !== '' || severityFilter !== 'all';

    const clearFilters = () => {
        setSearch('');
        setSeverityFilter('all');
        setCurrentPage(1);
    };

    return {
        search,
        setSearch: (value: string) => {
            setSearch(value);
            setCurrentPage(1);
        },
        severityFilter,
        setSeverityFilter: (value: string) => {
            setSeverityFilter(value);
            setCurrentPage(1);
        },
        severityOptions,
        hasSeverityColumn,
        sort,
        toggleSort,
        currentPage,
        setCurrentPage,
        rowsPerPage,
        setRowsPerPage: (size: number) => {
            setRowsPerPage(size);
            setCurrentPage(1);
        },
        totalPages,
        paginatedRows,
        totalFiltered: sortedData.length,
        isFiltering,
        clearFilters,
        selectedRowKey,
        setSelectedRowKey,
        rowIdentity,
    };
};
