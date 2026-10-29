/**
 * InfoTooltip — hover/click info icon used by NodesViewSebiHotCompliance's
 * guideline and status columns. Extracted verbatim, no logic changes.
 */

import { useState, useEffect, useRef, useId } from 'react';
import { createPortal } from 'react-dom';

export const InfoTooltip = ({ text, description, withDescription = false }: { text: string, description?: string, align?: 'right' | 'top' | 'left', withDescription?: boolean }) => {
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState({ top: 0, left: 0 });
  const iconRef = useRef<HTMLElement>(null);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tooltipId = useId();

  const show = () => {
    if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null; }
    if (iconRef.current) {
      const rect = iconRef.current.getBoundingClientRect();
      const tooltipWidth = 240; // 15rem
      const left = Math.min(rect.right + 8 + window.scrollX, window.scrollX + window.innerWidth - tooltipWidth - 16);
      setCoords({
        top: rect.top + rect.height / 2 + window.scrollY,
        left: Math.max(left, window.scrollX + 8),
      });
    }
    setOpen(true);
  };

  const scheduleHide = () => {
    hideTimer.current = setTimeout(() => { setOpen(false); hideTimer.current = null; }, 120);
  };

  useEffect(() => () => { if (hideTimer.current) clearTimeout(hideTimer.current); }, []);

  const points = text.split(/\n|,/).map(s => s.trim()).filter(Boolean);

  const renderPoints = () => {
    if (points.length > 1) {
      return (
        <ul className="list-disc pl-4 m-0">
          {points.map((p, i) => <li key={i}>{p}</li>)}
        </ul>
      );
    }
    return <span>{points[0]}</span>;
  };

  return (
    <span
      className="relative ml-1.5 inline-flex items-center align-middle"
      onMouseEnter={show}
      onMouseLeave={scheduleHide}
    >
      <i
        ref={iconRef}
        className="fa fa-circle-info text-gray-400 hover:text-rose-500 text-[10px] cursor-help transition-colors"
        role="button"
        tabIndex={0}
        aria-label="More info"
        aria-expanded={open}
        aria-describedby={open ? tooltipId : undefined}
        onClick={() => { if (open) scheduleHide(); else show(); }}
        onFocus={show}
        onBlur={scheduleHide}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            if (open) scheduleHide(); else show();
          }
        }}
      />
      {open && createPortal(
        <span
          id={tooltipId}
          role="tooltip"
          onMouseEnter={() => { if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null; } }}
          onMouseLeave={scheduleHide}
          style={{
            position: 'absolute',
            top: coords.top,
            left: coords.left,
            transform: 'translateY(-50%)',
            width: '15rem',
            zIndex: 9999,
          }}
          className="flex flex-col items-start pointer-events-auto"
        >
          <span className="rounded-lg bg-gray-900 text-[11px] leading-relaxed text-white shadow-2xl flex flex-col w-full">
            {withDescription ? (
              <div className="px-3 py-2.5 flex flex-col gap-1.5">
                <span className="text-white font-semibold text-[11px] leading-snug whitespace-normal">{description}</span>
                <div className="text-white/70 text-[10px] leading-relaxed whitespace-normal">{renderPoints()}</div>
              </div>
            ) : (
              <div className="px-3 py-2.5 whitespace-normal">
                {renderPoints()}
              </div>
            )}
          </span>
        </span>,
        document.body
      )}
    </span>
  );
};
