import { useEffect, useRef } from 'react';

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Minimal accessibility contract for hand-rolled modal overlays that don't go
 * through components/ui/dialog.tsx (which gets this for free from @base-ui/react):
 * traps Tab/Shift+Tab inside the modal, closes on Escape, and returns focus to
 * whatever triggered the modal when it unmounts.
 *
 * Usage: const containerRef = useModalA11y(isOpen, onClose); then attach
 * containerRef to the modal's outermost element. Safe to call unconditionally
 * (before any early `if (!isOpen) return null`) — it only attaches listeners
 * while `active` is true.
 */
export function useModalA11y<T extends HTMLElement>(active: boolean, onClose: () => void) {
  const containerRef = useRef<T | null>(null);
  const triggerRef = useRef<Element | null>(null);

  useEffect(() => {
    if (!active) return;
    triggerRef.current = document.activeElement;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== 'Tab' || !containerRef.current) return;

      const focusable = Array.from(
        containerRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
      ).filter((el) => el.offsetParent !== null);
      if (focusable.length === 0) return;

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;

      if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown, true);
    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      if (triggerRef.current instanceof HTMLElement) {
        triggerRef.current.focus();
      }
    };
    // onClose is intentionally excluded — re-running this effect on every
    // render of a parent that passes an inline `() => ...` would move focus
    // back to the trigger on every keystroke inside the modal.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  return containerRef;
}
