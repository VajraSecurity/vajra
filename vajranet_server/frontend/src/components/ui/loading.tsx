import * as React from "react";
import { cn } from "@/lib/utils";
import loadingImage from "@/assets/vajra/loading.svg";

/**
 * Single source of truth for every loading indicator in the app.
 * - `LoadingScreen`: full-page / section loader using the branded loading.svg mark.
 * - `Spinner`: small inline spinner (buttons, table cells, form actions) that
 *   inherits `currentColor`, so it always matches the surrounding text/button color.
 */

type SpinnerSize = "xs" | "sm" | "md" | "lg";

const spinnerSizeClasses: Record<SpinnerSize, string> = {
  xs: "size-3.5",
  sm: "size-4",
  md: "size-5",
  lg: "size-6",
};

export interface SpinnerProps extends React.SVGAttributes<SVGSVGElement> {
  size?: SpinnerSize;
  label?: string;
}

export function Spinner({ size = "sm", label = "Loading", className, ...props }: SpinnerProps) {
  return (
    <svg
      role="status"
      aria-label={label}
      className={cn("animate-spin", spinnerSizeClasses[size], className)}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      {...props}
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8v8H4z"
      />
    </svg>
  );
}

const duoSpinnerSizeClasses: Record<SpinnerSize, string> = {
  xs: "size-4 border-2",
  sm: "size-6 border-2",
  md: "size-8 border-[3px]",
  lg: "size-10 border-[3px]",
};

export interface DuoSpinnerProps {
  size?: SpinnerSize;
  label?: string;
  className?: string;
}

/** Two-tone rotating ring (red top arc / blue bottom arc) for brand-styled loading states. */
export function DuoSpinner({ size = "md", label = "Loading", className }: DuoSpinnerProps) {
  return (
    <span
      role="status"
      aria-label={label}
      className={cn(
        "inline-block animate-spin rounded-full border-solid border-t-[#8F407F] border-b-[#8F407F] border-x-transparent",
        duoSpinnerSizeClasses[size],
        className
      )}
    />
  );
}

export interface InlineSpinnerProps {
  text?: string;
  size?: SpinnerSize;
  className?: string;
  spinnerClassName?: string;
}

/** Spinner + label, for inline "Loading…" rows (table cells, empty states, select options). */
export function InlineSpinner({
  text = "Loading...",
  size = "sm",
  className,
  spinnerClassName,
}: InlineSpinnerProps) {
  return (
    <span className={cn("inline-flex items-center gap-2", className)}>
      <Spinner size={size} className={spinnerClassName} />
      {text}
    </span>
  );
}

type LoadingScreenSize = "sm" | "md" | "lg" | "full";

const loadingImageSizeClasses: Record<LoadingScreenSize, string> = {
  sm: "h-16 w-auto",
  md: "h-24 w-auto",
  lg: "h-32 w-auto",
  full: "h-100 w-auto",
};

export interface LoadingScreenProps {
  /** Optional heading shown under the mark. */
  title?: string;
  /** Optional supporting copy shown under the title. */
  subtitle?: string;
  /** Controls the size of the loading mark. Use "full" for top-level route/page loaders. */
  size?: LoadingScreenSize;
  /** min-h-screen vs fill the parent container. */
  fullScreen?: boolean;
  /** Use the dark AI-workspace background instead of the default light one. */
  dark?: boolean;
  className?: string;
}

export function LoadingScreen({
  title,
  subtitle,
  size = "full",
  fullScreen = true,
  dark = false,
  className,
}: LoadingScreenProps) {
  return (
    <div
      className={cn(
        "flex items-center justify-center",
        fullScreen ? "min-h-screen" : "h-full min-h-60",
        dark ? "bg-[#08080f]" : "bg-[#f8f9fb]",
        className
      )}
    >
      <div className="text-center">
        <img src={loadingImage} alt="Loading" className={cn("mx-auto", loadingImageSizeClasses[size])} />
        {title && (
          <p className={cn("mt-3 text-base font-medium", dark ? "text-white/90" : "text-gray-800")}>
            {title}
          </p>
        )}
        {subtitle && (
          <p className={cn("mt-1 text-sm", dark ? "text-white/60" : "text-gray-500")}>{subtitle}</p>
        )}
      </div>
    </div>
  );
}
