/**
 * Shared in-process sliding-window throttle. node-cron fires each scheduled
 * watchlist target independently, so without a shared throttle a handful of
 * targets on overlapping schedules (plus ad-hoc "Check Now" calls sharing the
 * same API key) can burst past a provider's rate limit and start getting
 * 429s. This queues every outbound call through one window so callers wait
 * instead of getting rejected.
 */
import { getLogger } from '../../utils/logger';

const logger = getLogger('services.domainReputation.rateLimiter');

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createThrottle(provider: string, windowMs: number, maxPerWindow: number) {
  const callTimestamps: number[] = [];
  let queue: Promise<void> = Promise.resolve();

  return function throttle<T>(fn: () => Promise<T>): Promise<T> {
    const turn = queue.then(async () => {
      const now = Date.now();
      while (callTimestamps.length && now - callTimestamps[0] >= windowMs) callTimestamps.shift();
      if (callTimestamps.length >= maxPerWindow) {
        const waitMs = windowMs - (now - callTimestamps[0]) + 50;
        if (waitMs > 0) {
          // Without this, a check that takes far longer than the provider's own
          // response time looks identical to one that never queued.
          logger.info({ provider, waitMs, maxPerWindow, windowMs }, 'Outbound request throttled to stay under provider rate limit');
          await sleep(waitMs);
        }
      }
      callTimestamps.push(Date.now());
    });
    queue = turn.catch(() => {});
    return turn.then(fn);
  };
}

// VirusTotal's free tier caps at 4 requests/minute.
export const throttleVirusTotal = createThrottle('virustotal', 60_000, 4);

// AbuseIPDB publishes only a daily cap, not a per-minute burst limit. This
// window queues concurrent manual and scheduled bursts instead of letting them
// 429; the daily cap is still enforced only by the 429 handling in abuseipdb.ts.
// The per-minute figure is a conservative guess, not a documented limit.
export const throttleAbuseIPDB = createThrottle('abuseipdb', 60_000, 30);
