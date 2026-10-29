import { useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { useLiveData } from '../../context/useLiveData';

/**
 * Staleness indicator for screens driven by the live WebSocket (`/ws/live`).
 * Without it a frozen live view is indistinguishable from a working one — the
 * last-known counts simply stop moving.
 *
 * Renders nothing while connected, and subscribes to the context here rather
 * than taking a prop so the subscription stays in this leaf.
 */

/** Grace period so a normal mount or reconnect gap doesn't flash a warning. */
const DISCONNECTED_GRACE_MS = 3_000;

export interface LiveConnectionBadgeProps {
  className?: string;
  /** Overrides the default label, e.g. to name what has stopped updating. */
  label?: string;
}

const LiveConnectionBadge = ({ className, label = 'Live updates offline' }: LiveConnectionBadgeProps) => {
  const { connected } = useLiveData();
  const [show, setShow] = useState(false);

  useEffect(() => {
    if (connected) {
      setShow(false);
      return;
    }
    const timer = setTimeout(() => setShow(true), DISCONNECTED_GRACE_MS);
    return () => clearTimeout(timer);
  }, [connected]);

  if (!show) return null;

  return (
    <Badge
      variant="warning"
      dot
      role="status"
      title="The live connection is down — the values on this screen are the last ones received and may be out of date. Reconnection is retried automatically; refresh if it persists."
      className={cn('shrink-0', className)}
    >
      {label}
    </Badge>
  );
};

export default LiveConnectionBadge;
