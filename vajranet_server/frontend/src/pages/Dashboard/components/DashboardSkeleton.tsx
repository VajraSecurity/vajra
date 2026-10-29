import { Skeleton } from '@/components/ui/skeleton';
import { COLORS } from '../constants';

const DonutMetricCardSkeleton = () => (
  <div
    className="bg-white rounded-2xl border p-5 md:p-6 h-full"
    style={{ borderColor: COLORS.border, boxShadow: '0 12px 28px rgba(15, 23, 42, 0.06)' }}
  >
    <div className="flex items-start justify-between gap-3">
      <div className="space-y-2">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-3 w-40" />
      </div>
      <Skeleton className="h-6 w-16 rounded-full" />
    </div>
    <div className="mt-4 grid grid-cols-1 sm:grid-cols-[168px_1fr] gap-4 items-center">
      <Skeleton className="w-[168px] h-[168px] rounded-full mx-auto" />
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="space-y-1.5">
            <div className="flex items-center justify-between gap-3">
              <Skeleton className="h-3.5 w-24" />
              <Skeleton className="h-3.5 w-10" />
            </div>
            <Skeleton className="h-1.5 w-full rounded-full" />
          </div>
        ))}
      </div>
    </div>
  </div>
);

const MachineTableSkeleton = ({ columns, rows = 5 }: { columns: number; rows?: number }) => (
  <table className="w-full text-sm">
    <thead style={{ backgroundColor: COLORS.light }}>
      <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
        {Array.from({ length: columns }).map((_, i) => (
          <th key={i} className="px-4 py-3">
            <Skeleton className="h-3 w-12 mx-auto" />
          </th>
        ))}
      </tr>
    </thead>
    <tbody>
      {Array.from({ length: rows }).map((_, r) => (
        <tr key={r} style={{ borderBottom: `1px solid ${COLORS.border}`, backgroundColor: r % 2 === 0 ? COLORS.surface : COLORS.light }}>
          {Array.from({ length: columns }).map((_, c) => (
            <td key={c} className="px-4 py-4">
              <Skeleton className="h-4 w-full max-w-[80px] mx-auto" />
            </td>
          ))}
        </tr>
      ))}
    </tbody>
  </table>
);

const DashboardSkeleton = () => (
  <div className="min-h-screen bg-gradient-to-b from-white to-slate-50" role="status" aria-live="polite" aria-busy="true">
    <span className="sr-only">Loading dashboard…</span>
    <main className="mx-auto px-2 sm:px-4 lg:px-8 py-3 sm:py-4 lg:py-5 space-y-8" aria-hidden="true">
      {/* Hero header — same gradient card the loaded page renders, just pulsing placeholders inside */}
      <div
        className="relative overflow-hidden rounded-2xl shadow-lg p-5 sm:p-6"
        style={{ background: 'linear-gradient(135deg, rgb(4, 34, 119) 0%, rgb(10, 50, 150) 100%)' }}
      >
        <div className="relative z-10 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 space-y-2">
            <Skeleton className="h-7 w-72 bg-white/15" />
            <Skeleton className="h-4 w-96 max-w-full bg-white/10" />
          </div>
          <div className="flex flex-col sm:items-end gap-3 shrink-0">
            <Skeleton className="h-10 w-56 rounded-xl bg-white/10" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="bg-white rounded-xl shadow-lg p-4 border border-slate-200 space-y-2">
            <Skeleton className="h-3 w-24" />
            <Skeleton className="h-6 w-16" />
            <Skeleton className="h-3 w-32" />
          </div>
        ))}
      </div>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <DonutMetricCardSkeleton />
        <DonutMetricCardSkeleton />
        <DonutMetricCardSkeleton />
      </section>

      <section className="grid grid-cols-1 xl:grid-cols-9 gap-6">
        <div
          className="xl:col-span-5 bg-white rounded-2xl border overflow-hidden"
          style={{ borderColor: COLORS.border, boxShadow: '0 8px 24px rgba(15, 23, 42, 0.05)' }}
        >
          <div className="px-6 py-5 border-b flex items-center gap-4" style={{ borderColor: COLORS.border, backgroundColor: COLORS.light }}>
            <Skeleton className="h-9 w-9 rounded-lg" />
            <div className="space-y-2">
              <Skeleton className="h-4 w-36" />
              <Skeleton className="h-3 w-48" />
            </div>
          </div>
          <div className="overflow-x-auto">
            <MachineTableSkeleton columns={8} />
          </div>
        </div>

        <div
          className="xl:col-span-4 bg-white rounded-2xl border overflow-hidden"
          style={{ borderColor: COLORS.border, boxShadow: '0 8px 24px rgba(15, 23, 42, 0.05)' }}
        >
          <div className="px-6 py-5 border-b flex items-center gap-4" style={{ borderColor: COLORS.border, backgroundColor: COLORS.light }}>
            <Skeleton className="h-9 w-9 rounded-lg" />
            <div className="space-y-2">
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-3 w-40" />
            </div>
          </div>
          <div className="overflow-x-auto">
            <MachineTableSkeleton columns={4} />
          </div>
        </div>
      </section>
    </main>
  </div>
);

export default DashboardSkeleton;
