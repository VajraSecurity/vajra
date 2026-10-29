import { Skeleton } from "@/components/ui/skeleton";

/**
 * Shared table-loading skeletons.
 * - `TableSkeleton`: rows of shimmering cells, used by DynamicDataTable and
 *   the VulnerabilityScanner (Nessus/OpenVAS/Burpsuite) panels.
 * - `HeaderSkeleton` / `StatGridSkeleton`: matching header + stat-tile
 *   placeholders used alongside `TableSkeleton` in the scanner panels.
 */

export function TableSkeleton({ columns, rows = 6 }: { columns: number; rows?: number }) {
  return (
    <div className="divide-y divide-slate-100" role="status" aria-label="Loading table data">
      {Array.from({ length: rows }).map((_, rowIdx) => (
        <div key={rowIdx} className="flex items-center gap-6 px-5 py-4">
          {Array.from({ length: columns }).map((_, colIdx) => (
            <Skeleton
              key={colIdx}
              className="h-4 flex-1"
              style={{ animationDelay: `${(rowIdx * columns + colIdx) * 20}ms`, maxWidth: colIdx === 0 ? '30%' : undefined }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

export function HeaderSkeleton() {
  return (
    <div className="px-5 py-4 border-b border-slate-200 flex items-center gap-3">
      <Skeleton className="size-8 rounded-lg" />
      <div className="space-y-1.5">
        <Skeleton className="h-4 w-40" />
        <Skeleton className="h-3 w-24" />
      </div>
    </div>
  );
}

export function StatGridSkeleton() {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm space-y-2">
          <Skeleton className="h-3 w-16" />
          <Skeleton className="h-7 w-10" />
        </div>
      ))}
    </div>
  );
}
