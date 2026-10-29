import { createContext, useContext } from 'react';

export interface RateLimitContextType {
  /** True while the API is rejecting requests from this browser with 429s. */
  isRateLimited: boolean;
  /** Seconds remaining until requests are expected to succeed again, or null when not rate limited. */
  secondsLeft: number | null;
}

export const RateLimitContext = createContext<RateLimitContextType | undefined>(undefined);

export const useRateLimit = (): RateLimitContextType => {
  const context = useContext(RateLimitContext);
  if (!context) {
    throw new Error('useRateLimit must be used within RateLimitProvider');
  }
  return context;
};
