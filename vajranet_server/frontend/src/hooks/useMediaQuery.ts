import { useEffect, useState } from 'react';

/**
 * Tracks a CSS media query via matchMedia's change event, not a one-shot
 * check — so the value stays correct across resize/orientation-change
 * (e.g. rotating a tablet, resizing a desktop window) instead of freezing
 * at whatever matched on mount.
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() =>
    typeof window !== 'undefined' ? window.matchMedia(query).matches : false
  );

  useEffect(() => {
    const mql = window.matchMedia(query);
    const onChange = () => setMatches(mql.matches);
    onChange();
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, [query]);

  return matches;
}
