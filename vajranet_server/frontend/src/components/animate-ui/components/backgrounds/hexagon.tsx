'use client';

import * as React from 'react';

import { cn } from '@/lib/utils';

// Every hexagon in the grid resolves to the exact same utility-class string;
// only hexagonProps?.className can vary between them. Hoisting the constant
// part keeps cn() (clsx + twMerge over ~700 characters of Tailwind) to one
// call per render instead of one per cell — several hundred cells on a desktop
// viewport. Login and signup both wrap their whole form in this background and
// keep every controlled input in one component, so the grid re-renders on
// every keystroke.
const HEXAGON_CELL_CLASSES = [
  'relative',
  '[clip-path:polygon(50%_0%,_100%_25%,_100%_75%,_50%_100%,_0%_75%,_0%_25%)]',
  "before:content-[''] before:absolute before:top-0 before:left-0 before:w-full before:h-full dark:before:bg-neutral-950 before:bg-white before:opacity-100 before:transition-all before:duration-1000",
  "after:content-[''] after:absolute after:inset-[var(--hexagon-margin)] dark:after:bg-neutral-950 after:bg-white",
  'after:[clip-path:polygon(50%_0%,_100%_25%,_100%_75%,_50%_100%,_0%_75%,_0%_25%)]',
  'hover:before:bg-neutral-200 dark:hover:before:bg-neutral-800 hover:before:opacity-100 hover:before:duration-0 dark:hover:after:bg-neutral-900 hover:after:bg-neutral-100 hover:after:opacity-100 hover:after:duration-0',
] as const;

type HexagonBackgroundProps = React.ComponentProps<'div'> & {
  hexagonProps?: React.ComponentProps<'div'>;
  hexagonSize?: number; // value greater than 50
  hexagonMargin?: number;
};

function HexagonBackground({
  className,
  children,
  hexagonProps,
  hexagonSize = 75,
  hexagonMargin = 3,
  ...props
}: HexagonBackgroundProps) {
  const hexagonWidth = hexagonSize;
  const hexagonHeight = hexagonSize * 1.1;
  const rowSpacing = hexagonSize * 0.8;
  const baseMarginTop = -36 - 0.275 * (hexagonSize - 100);
  const computedMarginTop = baseMarginTop + hexagonMargin;
  const oddRowMarginLeft = -(hexagonSize / 2);
  const evenRowMarginLeft = hexagonMargin / 2;

  const [gridDimensions, setGridDimensions] = React.useState({
    rows: 0,
    columns: 0,
  });

  const updateGridDimensions = React.useCallback(() => {
    const rows = Math.ceil(window.innerHeight / rowSpacing);
    const columns = Math.ceil(window.innerWidth / hexagonWidth) + 1;
    setGridDimensions({ rows, columns });
  }, [rowSpacing, hexagonWidth]);

  React.useEffect(() => {
    updateGridDimensions();
    window.addEventListener('resize', updateGridDimensions);
    return () => window.removeEventListener('resize', updateGridDimensions);
  }, [updateGridDimensions]);

  // One merged class string and one style object for the whole grid instead of
  // one of each per hexagon. Sharing a single style object across every cell is
  // safe - React only ever reads the style prop - and it additionally lets
  // React skip style diffing for those nodes, since the reference is unchanged
  // between renders. The emitted class attribute and inline styles are
  // byte-for-byte what the per-cell version produced.
  const hexagonClassName = React.useMemo(
    () => cn(...HEXAGON_CELL_CLASSES, hexagonProps?.className),
    [hexagonProps?.className],
  );

  const hexagonStyle = React.useMemo(
    () => ({
      width: hexagonWidth,
      height: hexagonHeight,
      marginLeft: hexagonMargin,
      ...hexagonProps?.style,
    }),
    [hexagonWidth, hexagonHeight, hexagonMargin, hexagonProps?.style],
  );

  // Row offsets alternate between exactly two values, so there are only ever
  // two distinct row style objects rather than one per row.
  const oddRowStyle = React.useMemo(
    () => ({ marginTop: computedMarginTop, marginLeft: oddRowMarginLeft - 10 }),
    [computedMarginTop, oddRowMarginLeft],
  );
  const evenRowStyle = React.useMemo(
    () => ({ marginTop: computedMarginTop, marginLeft: evenRowMarginLeft - 10 }),
    [computedMarginTop, evenRowMarginLeft],
  );

  return (
    <div
      data-slot="hexagon-background"
      className={cn(
        'relative size-full overflow-hidden dark:bg-neutral-900 bg-neutral-100',
        className,
      )}
      {...props}
    >
      <style>{`:root { --hexagon-margin: ${hexagonMargin}px; }`}</style>
      <div className="absolute top-0 -left-0 size-full overflow-hidden">
        {Array.from({ length: gridDimensions.rows }).map((_, rowIndex) => (
          <div
            key={`row-${rowIndex}`}
            style={(rowIndex + 1) % 2 === 0 ? evenRowStyle : oddRowStyle}
            className="inline-flex"
          >
            {Array.from({ length: gridDimensions.columns }).map(
              (_, colIndex) => (
                <div
                  key={`hexagon-${rowIndex}-${colIndex}`}
                  {...hexagonProps}
                  style={hexagonStyle}
                  className={hexagonClassName}
                />
              ),
            )}
          </div>
        ))}
      </div>
      {children}
    </div>
  );
}

export { HexagonBackground, type HexagonBackgroundProps };
