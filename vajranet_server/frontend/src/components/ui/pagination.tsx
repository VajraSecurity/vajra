import { cn } from "@/lib/utils";
import { DEFAULT_PAGE_SIZE_OPTIONS } from "./pagination.constants";

export interface PaginationProps {
  page: number;
  totalPages: number;
  total: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  pageSizeOptions?: number[];
  itemLabel?: string;
  className?: string;
}

export function Pagination({
  page,
  totalPages,
  total,
  pageSize,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = DEFAULT_PAGE_SIZE_OPTIONS,
  itemLabel = "",
  className,
}: PaginationProps) {
  if (totalPages <= 0) return null;

  const start = total === 0 ? 0 : Math.min((page - 1) * pageSize + 1, total);
  const end = Math.min(page * pageSize, total);

  // Only five page numbers can ever survive the predicate (first, last, and the
  // three around the current page), so build the kept set directly instead of
  // materialising and filtering a full 1..totalPages array — that array is
  // thousands of elements for a large result set, reallocated on every render of
  // every paginated list in the app.
  const kept = [...new Set([1, totalPages, page - 1, page, page + 1])]
    .filter((p) => p >= 1 && p <= totalPages)
    .sort((a, b) => a - b);

  const pages = kept.reduce<(number | "…")[]>((acc, p, i, arr) => {
    if (i > 0 && (p as number) - (arr[i - 1] as number) > 1) acc.push("…");
    acc.push(p);
    return acc;
  }, []);

  return (
    <div
      className={cn(
        "flex flex-wrap items-center justify-between gap-3 px-5 py-3 border-t border-gray-100 dark:border-gray-700 flex-shrink-0",
        className
      )}
    >
      <p className="text-sm text-gray-400 dark:text-gray-500">
        Showing <span className="font-semibold text-gray-600 dark:text-gray-300">{start}</span> to{" "}
        <span className="font-semibold text-gray-600 dark:text-gray-300">{end}</span> of{" "}
        <span className="font-semibold text-gray-600 dark:text-gray-300">{total.toLocaleString()}</span>
        {itemLabel ? ` ${itemLabel}` : ""}
      </p>
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          onClick={() => onPageChange(Math.max(1, page - 1))}
          disabled={page === 1}
          aria-label="Previous page"
          className="w-8 h-8 flex items-center justify-center rounded-lg border border-gray-200 dark:border-gray-600 text-gray-400 dark:text-gray-500 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors duration-150 text-sm"
        >
          ‹
        </button>

        {pages.map((p, i) =>
          p === "…" ? (
            <span key={`e-${i}`} className="px-1 text-gray-300 dark:text-gray-600 text-sm">
              …
            </span>
          ) : (
            <button
              key={p}
              type="button"
              onClick={() => onPageChange(p as number)}
              aria-label={`Page ${p}`}
              aria-current={page === p ? "page" : undefined}
              className={`w-8 h-8 flex items-center justify-center rounded-lg text-sm font-semibold transition-colors duration-150 ${
                page === p
                  ? "bg-blue-600 text-white shadow-sm"
                  : "text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700"
              }`}
            >
              {p}
            </button>
          )
        )}

        <button
          type="button"
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
          disabled={page === totalPages}
          aria-label="Next page"
          className="w-8 h-8 flex items-center justify-center rounded-lg border border-gray-200 dark:border-gray-600 text-gray-400 dark:text-gray-500 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors duration-150 text-sm"
        >
          ›
        </button>

        {onPageSizeChange && pageSizeOptions && pageSizeOptions.length > 0 && (
          <select
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            aria-label="Rows per page"
            className="h-8 text-sm border border-gray-200 dark:border-gray-600 rounded-lg px-2 text-gray-500 dark:text-gray-400 dark:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
          >
            {pageSizeOptions.map((size) => (
              <option key={size} value={size}>
                {size} / page
              </option>
            ))}
          </select>
        )}
      </div>
    </div>
  );
}

export default Pagination;
