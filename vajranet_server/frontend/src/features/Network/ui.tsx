import type { ReactNode } from 'react';
import { motion } from 'motion/react';
import { Select as SelectPrimitive } from '@base-ui/react/select';
import { Checkbox as CheckboxPrimitive } from '@base-ui/react/checkbox';
import { Check, ChevronDown, Minus } from 'lucide-react';
import { cn } from '@/lib/utils';

/* Shared CIDR option list — used by both the ad-hoc scanner and the scheduler */

// eslint-disable-next-line react-refresh/only-export-components
export const CIDR_OPTIONS = [
  { value: '', label: 'No CIDR' },
  { value: '/32', label: '/32 — Single host' },
  { value: '/30', label: '/30 — 4 hosts' },
  { value: '/28', label: '/28 — 16 hosts' },
  { value: '/27', label: '/27 — 32 hosts' },
  { value: '/26', label: '/26 — 64 hosts' },
  { value: '/25', label: '/25 — 128 hosts' },
  { value: '/24', label: '/24 — 256 hosts' },
  { value: '/22', label: '/22 — 1,024 hosts' },
  { value: '/20', label: '/20 — 4,096 hosts' },
  { value: '/16', label: '/16 — 65,536 hosts' },
];

/* Segmented control — pill tab-switcher shared across the Network Security tabs */

interface SegmentOption<T extends string> {
  value: T;
  label: ReactNode;
  icon?: ReactNode;
}

interface SegmentedControlProps<T extends string> {
  options: SegmentOption<T>[];
  value: T;
  onChange: (value: T) => void;
  layoutId: string;
  accent?: string;
  activeTextClassName?: string;
  idleTextClassName?: string;
  size?: 'sm' | 'md';
  className?: string;
}

export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  size = 'md',
  className,
}: SegmentedControlProps<T>) {
  return (
    <div
      className={cn(
        'inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-100 p-1',
        className
      )}
      role="tablist"
    >
      {options.map((option) => {
        const active = option.value === value

        return (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            className={cn(
              'relative inline-flex items-center justify-center gap-1.5 rounded-full border border-transparent font-medium transition-all duration-200',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 focus-visible:ring-offset-2',
              size === 'md' ? 'px-4 py-2 text-sm' : 'px-3 py-1.5 text-xs',
              active
                ? 'text-slate-900 shadow-sm'
                : 'text-slate-600 hover:text-slate-900 hover:bg-white/60'
            )}
            role="tab"
            aria-selected={active}
          >
            {active && (
              <span
                className="absolute inset-0 rounded-full bg-white border border-slate-200 shadow-sm"
                aria-hidden="true"
              />
            )}

            <span className="relative z-10 inline-flex items-center gap-1.5">
              {option.icon}
              {option.label}
            </span>
          </button>
        )
      })}
    </div>
  )
}

/* Frosted variant — same control, tuned for use on top of a dark gradient hero */

export function SegmentedControlOnDark<T extends string>({
  options, value, onChange, layoutId, size = 'md', className,
}: Omit<SegmentedControlProps<T>, 'accent' | 'activeTextClassName' | 'idleTextClassName'>) {
  return (
    <div className={cn('relative inline-flex items-center gap-0.5 rounded-full  border border-white/20 bg-white/10 backdrop-blur-sm p-1', className)}>
      {options.map((opt) => {
        const active = value === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            onClick={() => onChange(opt.value)}
            className={cn(
              'relative z-10 inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg font-semibold transition-colors duration-150',
              size === 'sm' ? 'px-3 py-1.5 text-xs' : 'px-3 py-1.5 text-sm',
              active ? 'text-[rgb(4,34,119)]' : 'text-blue-100 hover:text-white',
            )}
          >
            {active && (
              <motion.div
                layoutId={layoutId}
                transition={{ type: 'spring', bounce: 0.2, duration: 0.5 }}
                className="absolute inset-0 rounded-full bg-white shadow-sm"
                style={{ zIndex: -1 }}
              />
            )}
            {opt.icon}
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

/* Select — styled dropdown built on Base UI, replaces the native <select> everywhere */

interface SelectItemDef<T extends string> {
  value: T;
  label: ReactNode;
  adornment?: ReactNode;
}

interface FancySelectProps<T extends string> {
  value: T;
  onChange: (value: T) => void;
  items: SelectItemDef<T>[];
  placeholder?: string;
  disabled?: boolean;
  size?: 'sm' | 'default';
  /** Use tabular monospace for the value + item text — for numeric/IP-like values (e.g. CIDR). */
  mono?: boolean;
  className?: string;
}

/**
 * Same visual language as the shadcn `components/ui/select.tsx` primitive (rounded-xl
 * trigger, blue focus ring, blue-highlighted items) — reimplemented locally so the popup
 * can sit at a z-index above this feature's modals (z-[100]) and pick up the shared
 * table-scrollbar treatment, neither of which the shared component's Positioner exposes.
 */
export function FancySelect<T extends string>({
  value, onChange, items, placeholder, disabled, size = 'sm', mono = false, className,
}: FancySelectProps<T>) {
  const current = items.find((i) => i.value === value);

  return (
    <SelectPrimitive.Root
      value={value}
      onValueChange={(v) => onChange(v as T)}
      disabled={disabled}
      items={items.map((i) => ({ value: i.value, label: i.label as string }))}
    >
      <SelectPrimitive.Trigger
        className={cn(
          'flex w-full items-center justify-between gap-2 rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-700 shadow-sm outline-none transition',
          size === 'default' ? 'h-11' : 'h-9',
          'hover:border-slate-300',
          'focus:border-blue-500 focus:ring-4 focus:ring-blue-100',
          'data-[popup-open]:border-blue-500 data-[popup-open]:ring-4 data-[popup-open]:ring-blue-100',
          'data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50',
          className,
        )}
      >
        <span className={cn('flex min-w-0 items-center gap-2 truncate', mono && 'font-mono')}>
          {current?.adornment}
          <SelectPrimitive.Value placeholder={placeholder}>
            {() => current?.label ?? placeholder}
          </SelectPrimitive.Value>
        </span>
        <SelectPrimitive.Icon className="flex shrink-0 items-center text-slate-500 transition-transform duration-200 data-[popup-open]:rotate-180">
          <ChevronDown className="h-4 w-4" />
        </SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>

      <SelectPrimitive.Portal>
        <SelectPrimitive.Positioner
          className="z-[500] outline-none"
          sideOffset={6}
          side="bottom"
          align="start"
          alignItemWithTrigger={false}
          collisionAvoidance={{ side: 'shift', align: 'shift' }}
        >
          <SelectPrimitive.Popup
            className={cn(
              'table-scrollbar max-h-[min(24rem,var(--available-height,24rem))] min-w-[var(--anchor-width)] max-w-[min(26rem,90vw)] origin-(--transform-origin) overflow-y-auto rounded-lg border border-slate-200 bg-white p-1 shadow-lg outline-none',
              'transition-[transform,opacity] duration-150 ease-out',
              'data-[starting-style]:scale-95 data-[starting-style]:opacity-0 data-[ending-style]:scale-95 data-[ending-style]:opacity-0',
            )}
          >
            <SelectPrimitive.List>
              {items.map((item) => (
                <SelectPrimitive.Item
                  key={item.value}
                  value={item.value}
                  className={cn(
                    'relative flex w-full cursor-pointer select-none items-center gap-2 rounded-md py-1.5 pl-2 pr-8 text-sm font-medium text-slate-700 outline-none',
                    mono && 'font-mono',
                    'data-[highlighted]:bg-blue-50 data-[highlighted]:text-blue-900',
                    'data-[selected]:font-semibold data-[selected]:text-slate-900',
                    'data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
                  )}
                >
                  {item.adornment}
                  <SelectPrimitive.ItemText className="flex-1 truncate">{item.label}</SelectPrimitive.ItemText>
                  <SelectPrimitive.ItemIndicator className="absolute right-2 flex items-center justify-center text-blue-600">
                    <Check className="h-4 w-4" />
                  </SelectPrimitive.ItemIndicator>
                </SelectPrimitive.Item>
              ))}
            </SelectPrimitive.List>
          </SelectPrimitive.Popup>
        </SelectPrimitive.Positioner>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  );
}

/* Checkbox — Base UI primitive styled to replace bare MUI checkboxes in tables */

interface CheckboxProps {
  checked: boolean;
  indeterminate?: boolean;
  disabled?: boolean;
  onChange: () => void;
  accent?: string;
  'aria-label'?: string;
}

export function Checkbox({ checked, indeterminate, disabled, onChange, accent = 'rgb(4, 34, 119)', ...rest }: CheckboxProps) {
  return (
    <CheckboxPrimitive.Root
      checked={checked}
      indeterminate={indeterminate}
      disabled={disabled}
      onCheckedChange={onChange}
      aria-label={rest['aria-label']}
      className={cn(
        'flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors',
        disabled
          ? 'cursor-not-allowed border-slate-200 bg-slate-100'
          : checked || indeterminate
            ? 'cursor-pointer border-transparent shadow-sm'
            : 'cursor-pointer border-slate-300 bg-white hover:border-slate-400',
      )}
      style={!disabled && (checked || indeterminate) ? { background: accent } : undefined}
    >
      <CheckboxPrimitive.Indicator className="flex text-white" keepMounted={false}>
        {indeterminate ? <Minus className="h-3 w-3" strokeWidth={3} /> : <Check className="h-3 w-3" strokeWidth={3} />}
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

/* Checkbox chip — a selectable pill used for multi-option toggles */

interface CheckboxChipProps {
  checked: boolean;
  disabled?: boolean;
  onChange: () => void;
  label: ReactNode;
  hint?: string;
  accent?: string;
}

export function CheckboxChip({ checked, disabled, onChange, label, hint, accent = 'rgb(9, 121, 112)' }: CheckboxChipProps) {
  return (
    <label
      className={cn(
        'group flex items-center gap-2.5 rounded-lg border px-3 py-2 text-sm font-medium transition-all select-none',
        disabled
          ? 'cursor-not-allowed border-slate-100 bg-slate-50 text-slate-400'
          : checked
            ? 'cursor-pointer border-transparent text-white shadow-sm'
            : 'cursor-pointer border-slate-200 bg-white text-slate-600 hover:border-slate-300 hover:bg-slate-50',
      )}
      style={checked && !disabled ? { background: accent } : undefined}
    >
      <CheckboxPrimitive.Root
        checked={checked}
        disabled={disabled}
        onCheckedChange={onChange}
        className={cn(
          'flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors',
          disabled
            ? 'border-slate-300 bg-slate-100'
            : checked
              ? 'border-white/60 bg-white/15'
              : 'border-slate-300 bg-white group-hover:border-slate-400',
        )}
      >
        <CheckboxPrimitive.Indicator className="flex text-current">
          <Check className="h-3 w-3" strokeWidth={3} />
        </CheckboxPrimitive.Indicator>
      </CheckboxPrimitive.Root>
      <span>{label}</span>
      {hint && <span className={cn('text-xs font-normal', checked ? 'text-white/70' : 'text-slate-400')}>{hint}</span>}
    </label>
  );
}
