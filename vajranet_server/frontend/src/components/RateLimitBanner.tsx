import AccessTimeIcon from '@mui/icons-material/AccessTime';
import { useRateLimit } from '../context/useRateLimit';

const formatCountdown = (totalSeconds: number) => {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes}:${seconds.toString().padStart(2, '0')}` : `${seconds}s`;
};

/**
 * App-wide notice for when the backend's per-user/IP rate limiter
 * (backend/src/middleware/rateLimiters.ts) starts rejecting this browser's
 * requests with 429s. Rendered once near the app root so it shows above
 * whichever page is open, rather than each page inventing its own
 * "no data" message for what is really a shared, global condition.
 */
const RateLimitBanner = () => {
  const { isRateLimited, secondsLeft } = useRateLimit();

  if (!isRateLimited || secondsLeft === null) return null;

  return (
    <div
      role="alert"
      className="sticky top-0 z-[60] flex items-center justify-center gap-2 px-4 py-2 text-xs sm:text-sm font-medium text-center"
      style={{ backgroundColor: '#fef3c7', color: '#92400e', borderBottom: '1px solid #fde68a' }}
    >
      <AccessTimeIcon sx={{ fontSize: 16 }} />
      <span>
        Too many requests were sent from this browser — the server is temporarily rate-limiting this session.
        Retrying automatically in <strong>{formatCountdown(secondsLeft)}</strong>.
      </span>
    </div>
  );
};

export default RateLimitBanner;
