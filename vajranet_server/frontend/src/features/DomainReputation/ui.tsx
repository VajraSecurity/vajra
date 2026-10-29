import type { ReactNode, KeyboardEvent } from 'react';
import { motion } from 'motion/react';
import { Select as SelectPrimitive } from '@base-ui/react/select';
import { Checkbox as CheckboxPrimitive } from '@base-ui/react/checkbox';
import { Autocomplete as AutocompletePrimitive } from '@base-ui/react/autocomplete';
import { Check, ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';

/* Segmented control — the pill tab-switcher shared by every tab bar on this page */

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
  options, value, onChange, layoutId, accent = 'rgb(4, 34, 119)',
  activeTextClassName = 'text-white', idleTextClassName = 'text-slate-500 hover:text-slate-700',
  size = 'md', className,
}: SegmentedControlProps<T>) {
  return (
    <div
      className={cn(
        'relative inline-flex items-center gap-0.5 rounded-xl border border-slate-200/80 bg-slate-100/70 p-1 shadow-inner',
        className,
      )}
    >
      {options.map((opt) => {
        const active = value === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            onClick={() => onChange(opt.value)}
            className={cn(
              'relative z-10 inline-flex items-center gap-1.5 rounded-lg font-semibold transition-colors duration-150',
              size === 'sm' ? 'px-3 py-1.5 text-xs' : 'px-4 py-2 text-sm',
              active ? activeTextClassName : idleTextClassName,
            )}
          >
            {active && (
              <motion.div
                layoutId={layoutId}
                transition={{ type: 'spring', bounce: 0.25, duration: 0.5 }}
                className="absolute inset-0 rounded-lg shadow-sm"
                style={{ zIndex: -1, background: accent }}
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
  focusRing?: string;
  className?: string;
}

export function FancySelect<T extends string>({
  value, onChange, items, placeholder, focusRing = 'focus-visible:ring-blue-200', className,
}: FancySelectProps<T>) {
  const current = items.find((i) => i.value === value);

  return (
    <SelectPrimitive.Root
      value={value}
      onValueChange={(v) => onChange(v as T)}
      items={items.map((i) => ({ value: i.value, label: i.label as string }))}
    >
      <SelectPrimitive.Trigger
        className={cn(
          'inline-flex w-full items-center justify-between gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-left text-sm font-medium text-slate-700 shadow-sm transition-all',
          'hover:border-slate-300 focus:outline-none focus-visible:ring-2 focus-visible:border-transparent',
          focusRing,
          'data-[popup-open]:ring-2 data-[popup-open]:border-transparent',
          className,
        )}
      >
        <span className="flex min-w-0 items-center gap-2 truncate">
          {current?.adornment}
          <SelectPrimitive.Value placeholder={placeholder}>
            {() => current?.label ?? placeholder}
          </SelectPrimitive.Value>
        </span>
        <SelectPrimitive.Icon className="shrink-0 text-slate-400">
          <ChevronDown className="h-4 w-4" />
        </SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>

      <SelectPrimitive.Portal>
        <SelectPrimitive.Positioner className="z-50 outline-none" sideOffset={6}>
          <SelectPrimitive.Popup
            className={cn(
              'min-w-[var(--anchor-width)] overflow-hidden rounded-xl border border-slate-200 bg-white p-1 shadow-lg shadow-slate-900/10',
              'origin-[var(--transform-origin)] transition-[transform,opacity] data-[starting-style]:scale-95 data-[starting-style]:opacity-0 data-[ending-style]:scale-95 data-[ending-style]:opacity-0',
            )}
          >
            {items.map((item) => (
              <SelectPrimitive.Item
                key={item.value}
                value={item.value}
                className={cn(
                  'flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-1.5 text-sm text-slate-700 outline-none transition-colors',
                  'data-[highlighted]:bg-slate-100 data-[selected]:font-semibold',
                )}
              >
                {item.adornment}
                <SelectPrimitive.ItemText className="flex-1 truncate">{item.label}</SelectPrimitive.ItemText>
                <SelectPrimitive.ItemIndicator className="text-slate-900">
                  <Check className="h-3.5 w-3.5" />
                </SelectPrimitive.ItemIndicator>
              </SelectPrimitive.Item>
            ))}
          </SelectPrimitive.Popup>
        </SelectPrimitive.Positioner>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  );
}

/* Checkbox chip — a selectable pill used for multi-provider toggles */

interface CheckboxChipProps {
  checked: boolean;
  disabled?: boolean;
  onChange: () => void;
  label: ReactNode;
  hint?: string;
  accent?: string;
}

export function CheckboxChip({ checked, disabled, onChange, label, hint, accent = 'rgb(4, 34, 119)' }: CheckboxChipProps) {
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
      <span className="capitalize">{label}</span>
      {hint && <span className={cn('text-xs font-normal', checked ? 'text-white/70' : 'text-slate-400')}>{hint}</span>}
    </label>
  );
}

/* Suggest field — a themed autocomplete input, replaces native <input list> + <datalist> */

interface SuggestFieldProps {
  value: string;
  onChange: (value: string) => void;
  items: string[];
  placeholder?: string;
  icon?: ReactNode;
  focusRing?: string;
  onKeyDown?: (e: KeyboardEvent<HTMLInputElement>) => void;
  className?: string;
}

export function SuggestField({
  value, onChange, items, placeholder, icon, focusRing = 'focus-visible:ring-emerald-200', onKeyDown, className,
}: SuggestFieldProps) {
  return (
    <AutocompletePrimitive.Root items={items} value={value} onValueChange={(v) => onChange(v)}>
      <AutocompletePrimitive.InputGroup className="relative">
        {icon && <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">{icon}</span>}
        <AutocompletePrimitive.Input
          placeholder={placeholder}
          onKeyDown={onKeyDown}
          className={cn(
            'w-full text-sm border border-slate-200 rounded-lg py-2 transition-shadow',
            icon ? 'pl-9 pr-3' : 'px-3',
            'focus:outline-none focus-visible:ring-2 focus-visible:border-transparent',
            focusRing,
            className,
          )}
        />
      </AutocompletePrimitive.InputGroup>

      <AutocompletePrimitive.Portal>
        <AutocompletePrimitive.Positioner className="z-50 outline-none" sideOffset={6} align="start">
          <AutocompletePrimitive.Popup
            className={cn(
              'w-[var(--anchor-width)] max-h-60 overflow-y-auto overflow-x-hidden rounded-xl border border-slate-200 bg-white p-1 shadow-lg shadow-slate-900/10',
              'origin-[var(--transform-origin)] transition-[transform,opacity] data-[starting-style]:scale-95 data-[starting-style]:opacity-0 data-[ending-style]:scale-95 data-[ending-style]:opacity-0',
              'empty:hidden',
            )}
          >
            <AutocompletePrimitive.Empty className="px-3 py-2 text-sm text-slate-400">No matches</AutocompletePrimitive.Empty>
            <AutocompletePrimitive.List>
              {(item: string) => (
                <AutocompletePrimitive.Item
                  key={item}
                  value={item}
                  className="cursor-pointer rounded-lg px-2.5 py-1.5 text-sm text-slate-700 outline-none transition-colors data-[highlighted]:bg-slate-100"
                >
                  {item}
                </AutocompletePrimitive.Item>
              )}
            </AutocompletePrimitive.List>
          </AutocompletePrimitive.Popup>
        </AutocompletePrimitive.Positioner>
      </AutocompletePrimitive.Portal>
    </AutocompletePrimitive.Root>
  );
}
