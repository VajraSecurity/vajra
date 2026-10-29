import React, { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { RateLimitContext } from './useRateLimit';
import { RATE_LIMIT_EVENT_NAME } from '../api/axiosInstance';
import type { RateLimitEventDetail } from '../api/axiosInstance';

// eslint-disable-next-line react-refresh/only-export-components
export { useRateLimit } from './useRateLimit';

export const RateLimitProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  // null = not rate limited. Any page/request can push this up (it always
  // wins, since a fresh 429 mid-countdown means the window slid further out).
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null);

  // axiosInstance.ts is a plain module, not a component, so it can't call
  // this provider's setter directly — same cross-module pattern as
  // APP_TOAST_EVENT_NAME/ToastProvider.
  useEffect(() => {
    const handleRateLimited = (event: Event) => {
      const detail = (event as CustomEvent<RateLimitEventDetail>).detail;
      if (!detail || !Number.isFinite(detail.retryAfterSeconds)) return;
      setSecondsLeft((prev) => (prev === null ? detail.retryAfterSeconds : Math.max(prev, detail.retryAfterSeconds)));
    };
    window.addEventListener(RATE_LIMIT_EVENT_NAME, handleRateLimited);
    return () => window.removeEventListener(RATE_LIMIT_EVENT_NAME, handleRateLimited);
  }, []);

  // Tick the countdown down once a second while active.
  useEffect(() => {
    if (secondsLeft === null || secondsLeft <= 0) return;
    const tick = setInterval(() => {
      setSecondsLeft((prev) => (prev !== null && prev > 1 ? prev - 1 : null));
    }, 1000);
    return () => clearInterval(tick);
  }, [secondsLeft !== null]); // eslint-disable-line react-hooks/exhaustive-deps

  const value = useMemo(
    () => ({ isRateLimited: secondsLeft !== null && secondsLeft > 0, secondsLeft }),
    [secondsLeft],
  );

  return <RateLimitContext.Provider value={value}>{children}</RateLimitContext.Provider>;
};
