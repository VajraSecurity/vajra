import { useCallback, useRef, useState } from "react";

/**
 * Return this from a `run()` fetcher to leave `data` exactly as it is —
 * useful when a response comes back "ok" but doesn't actually carry a usable
 * payload (e.g. `{ success: false }`), where keeping the last-known value
 * beats erroring or clobbering it with `undefined`.
 */
export const SKIP = Symbol("useSafeFetch.skip");

type FetchFn<T> = (signal: AbortSignal) => Promise<T | typeof SKIP>;

export interface UseSafeFetchResult<T> {
  data: T;
  loading: boolean;
  /** True if the most recent (non-superseded, non-aborted) run() threw. */
  error: boolean;
  /**
   * Runs `fetchFn`, aborting any still-in-flight call started by a previous
   * `run()` first. A sequence number guards state updates so a slow response
   * from a superseded call can never overwrite state written by a newer one
   * — even if it resolves after the newer call already finished.
   */
  run: (fetchFn: FetchFn<T>) => Promise<void>;
}

/**
 * Generalizes the abort-controller + sequence-number race guard used
 * throughout this codebase's hand-rolled fetch effects (see `fetchPage` and
 * its abortRef/fetchSeqRef pair in features/Alerts/index.tsx) into a small
 * reusable hook, so each new fetch site doesn't have to hand-roll it again.
 *
 * Not a general data-fetching library: no caching, retries, or
 * revalidation — just the discard-if-stale guarantee.
 */
export function useSafeFetch<T>(initialData: T): UseSafeFetchResult<T> {
  const [data, setData] = useState<T>(initialData);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);

  const abortRef = useRef<AbortController | null>(null);
  const seqRef = useRef(0);

  const run = useCallback(async (fetchFn: FetchFn<T>) => {
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const seq = ++seqRef.current;

    setLoading(true);
    setError(false);

    try {
      const result = await fetchFn(ctrl.signal);
      if (seq !== seqRef.current) return; // superseded by a newer run()
      if (result !== SKIP) setData(result);
    } catch (e: unknown) {
      if (seq !== seqRef.current) return;
      const name = typeof e === "object" && e !== null && "name" in e ? (e as { name?: unknown }).name : undefined;
      if (name !== "AbortError") setError(true);
    } finally {
      if (seq === seqRef.current && !ctrl.signal.aborted) setLoading(false);
    }
  }, []);

  return { data, loading, error, run };
}
