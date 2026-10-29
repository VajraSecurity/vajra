export const getRelativeTime = (unixSeconds: unknown): string => {
  const n = typeof unixSeconds === 'number' ? unixSeconds : parseInt(String(unixSeconds ?? ''), 10);
  if (!Number.isFinite(n) || n <= 0) return 'Never';
  const diffMs = Date.now() - n * 1000;
  if (diffMs < 45_000) return 'Just now';
  const diffMin = Math.floor(diffMs / 60_000);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 30) return `${diffDay}d ago`;
  const diffMonth = Math.floor(diffDay / 30);
  if (diffMonth < 12) return `${diffMonth}mo ago`;
  return `${Math.floor(diffMonth / 12)}y ago`;
};

export const getDeviceIcon = (type: string) => {
  const normalized = String(type ?? '').toLowerCase();

  switch (normalized) {
    case 'laptop':
      return (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
      );
    case 'desktop':
      return <i className="fa-brands fa-windows text-xl" aria-hidden="true"></i>;
    case 'server':
      return <i className="fa-brands fa-linux text-xl" aria-hidden="true"></i>;
    case 'mac':
    case 'macos':
    case 'darwin':
    case 'os x':
    case 'osx':
    case 'macbook':
    case 'macbook air':
    case 'macbook pro':
    case 'imac':
      return <i className="fa-brands fa-apple text-xl" aria-hidden="true"></i>;
    default:
      return (
        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
        </svg>
      );
  }
};
