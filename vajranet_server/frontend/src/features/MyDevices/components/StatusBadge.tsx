export const StatusBadge = ({ status }: { status: 'Online' | 'Active' | 'Offline' }) => {
  const config =
    status === 'Online'
      ? {
          dot: 'bg-emerald-500',
          text: 'text-emerald-700',
          bg: 'bg-emerald-50',
          border: 'border-emerald-200',
          title: 'Online — agent and browser extension both connected',
        }
      : status === 'Active'
        ? {
            dot: 'bg-amber-500',
            text: 'text-amber-700',
            bg: 'bg-amber-50',
            border: 'border-amber-200',
            title: 'Active — agent connected, browser extension not connected',
          }
        : {
            dot: 'bg-slate-400',
            text: 'text-slate-600',
            bg: 'bg-slate-50',
            border: 'border-slate-200',
            title: 'Offline — agent not reporting',
          };
  return (
    <span
      title={config.title}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-medium ${config.bg} ${config.text} ${config.border}`}
    >

      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${config.dot}`} />
      {status}
    </span>
  );
};
