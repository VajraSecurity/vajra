import { useCallback, useEffect, useState } from 'react';
import { getFimSummary } from '../../api/services/fimApi';

/** Open FIM alert count (summary endpoint), fetched on mount and every 60 s; failures are silent. */
export function useFimOpenAlerts(enabled = true): { count: number; refresh: () => void } {
  const [n, setN] = useState(0);
  const [tick, setTick] = useState(0);
  const refresh = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    if (!enabled) return;
    let cancel = false;
    const run = () => { getFimSummary().then((s) => { if (!cancel) setN(s.openAlerts ?? 0); }).catch(() => undefined); };
    run();
    const t = setInterval(run, 60_000);
    return () => { cancel = true; clearInterval(t); };
  }, [enabled, tick]);
  return { count: n, refresh };
}
