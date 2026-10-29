/**
 * Presentational primitives local to the Assets feature — the same role
 * features/Network/ui.tsx plays for Network Security. Badge/chip colors are
 * pulled from the shared VulnerabilityScanner token set (TONE_CLASSES) so
 * Assets reads as part of the same visual family as the OpenVAS scanner
 * views instead of keeping its own ad hoc palette — see
 * ADDENDUM 5 in the asset-identity spec for the restyle brief this
 * implements. `TONE_TINT` below is a small, additive generalisation of
 * scannerTokens.ts's SEVERITY_TINT (which is keyed by SeverityLevel, not the
 * generic Tone this feature needs for its stat tiles) — scannerTokens.ts
 * itself is untouched.
 *
 * Everything here exists to make one thing legible: how much the system
 * actually knows about a machine. An asset seen only at an IP address is a
 * weak guess and must never look like a confirmed machine.
 */
import type { ReactElement, ReactNode } from 'react';
import { motion } from 'motion/react';
import { Checkbox as CheckboxPrimitive } from '@base-ui/react/checkbox';
import {
  AlertTriangle, Check, Cpu, Fingerprint, Globe, Info, Laptop, Link2, MonitorSmartphone,
  Network, Radar, ShieldQuestion, Bug, Router, HelpCircle,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type {
  DropReason, IdentityKind, ObservationSource, ResolveDecision, VetoReason,
} from '@/api/services/assetsApi';
// Tone/brand constants come straight from scannerTokens.ts (not scannerUI.tsx,
// which only re-exports a subset — TONE_CLASSES/TONE_DOT aren't among them).
import { OPENVAS_BRAND, TONE_CLASSES, type Tone } from '../VulnerabilityScanner/scannerTokens';
import { SimpleTip } from '../VulnerabilityScanner/scannerUI';

/* Brand accent, matching every other feature hero in the app. Kept for the
   Checkbox primitive below; the header banner itself uses OPENVAS_BRAND. */
export const ASSETS_ACCENT = 'rgb(4, 34, 119)';

/**
 * Stat-tile tint, generalised from scannerTokens.ts's SEVERITY_TINT to the
 * generic Tone scale so AssetDetail's info tiles (which have no severity
 * concept) can use the same StatTile component OpenVAS's scan-detail page
 * uses for its severity counts.
 */
// eslint-disable-next-line react-refresh/only-export-components
export const TONE_TINT: Record<Tone, string> = {
  success: 'bg-gradient-to-br from-emerald-50 to-white border-emerald-100',
  info: 'bg-gradient-to-br from-blue-50 to-white border-blue-100',
  warning: 'bg-gradient-to-br from-amber-50 to-white border-amber-100',
  danger: 'bg-gradient-to-br from-red-50 to-white border-red-100',
  neutral: 'bg-gradient-to-br from-slate-100/80 to-white border-slate-200',
  progress: 'bg-gradient-to-br from-purple-50 to-white border-purple-100',
};

/* ---------------------------------------------------------------- tooltip */

/**
 * Hover/focus tooltip, built on the app's shared Tooltip primitive
 * (components/ui/tooltip.tsx, the same Base UI popup used elsewhere) rather
 * than a hand-rolled `group-hover` CSS trick. `children` is the already
 * fully-styled trigger element (a badge `<span>`) — it becomes the Tooltip's
 * `render` target as-is, so every call site below is unchanged. Being a real
 * portal-rendered popup, it gets floating-ui's collision detection/auto-flip
 * for free, so it never overlaps unrelated content the way the old
 * always-opens-downward CSS tooltip could inside a tightly-packed list.
 */
export function InfoTip({ children, label }: { children: ReactElement; label: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger render={children} />
      <TooltipContent className="max-w-64 text-left font-medium leading-relaxed">{label}</TooltipContent>
    </Tooltip>
  );
}

/* ------------------------------------------------------- identity confidence */

export interface ConfidenceLevel {
  /** Lower bound of the tier. The matcher only ever writes 100/80/40/5/0. */
  min: number;
  label: string;
  anchor: string;
  explanation: string;
  tone: Tone;
  icon: typeof Fingerprint;
}

/**
 * assets.identity_confidence is the weight of the strongest anchor ever seen
 * for this machine, not a percentage: 100 hardware BIOS UUID, 80 MAC,
 * 40 hostname, 5 IP only, 0 nothing. Tones follow the shared TONE_CLASSES
 * scale (100 hardware -> success, 80 MAC -> info, 40 hostname-only ->
 * warning, 5/0 weak-or-none -> neutral) per ADDENDUM 5.
 */
// eslint-disable-next-line react-refresh/only-export-components
export const CONFIDENCE_LEVELS: ConfidenceLevel[] = [
  {
    min: 100,
    label: 'Confirmed',
    anchor: 'Hardware BIOS UUID',
    explanation: 'Anchored on the SMBIOS/BIOS UUID reported by the agent. This identifies the physical machine itself and survives a change of IP, hostname or network card.',
    tone: 'success',
    icon: Cpu,
  },
  {
    min: 80,
    label: 'Strong',
    anchor: 'MAC address',
    explanation: 'Anchored on a hardware MAC address. Strong, but a network card can move between machines, and virtual/randomised addresses are deliberately excluded from matching.',
    tone: 'info',
    icon: Network,
  },
  {
    min: 40,
    label: 'Hostname only',
    anchor: 'Hostname',
    explanation: 'Matched on hostname alone — no hardware evidence. Hostnames are reused and reassigned, so treat this as a likely, not a proven, identity.',
    tone: 'warning',
    icon: MonitorSmartphone,
  },
  {
    min: 5,
    label: 'IP only',
    anchor: 'IP address',
    explanation: 'A weak guess. Only an IP address was ever seen for this host — a DHCP lease can move to a different machine, so this may not be a stable identity at all.',
    tone: 'neutral',
    icon: Globe,
  },
  {
    min: 0,
    label: 'No identity',
    anchor: 'None',
    explanation: 'Nothing usable survived normalisation — every value seen was generic, malformed or blocklisted. See the evidence view for what was dropped and why.',
    tone: 'neutral',
    icon: ShieldQuestion,
  },
];

// eslint-disable-next-line react-refresh/only-export-components
export function confidenceLevel(value: number): ConfidenceLevel {
  return CONFIDENCE_LEVELS.find((level) => value >= level.min) ?? CONFIDENCE_LEVELS[CONFIDENCE_LEVELS.length - 1];
}

/**
 * Header-level "what is this and how is it computed" explainer for the
 * Assets list itself — as opposed to InfoTip's per-badge tooltips below,
 * which only make sense once a row already has a badge to hover. A first-time
 * visitor to this tab has nothing to hover yet, hence a dedicated info icon
 * in the page header (see AssetsTab's PanelHeader `actions`).
 *
 * The confidence ladder below is generated from CONFIDENCE_LEVELS (skipping
 * the 0 "No identity" tier, which explains an absence rather than a kind of
 * evidence) so it can never drift out of sync with what ConfidenceBadge
 * itself shows per row. The attach/review/new-asset thresholds just below it
 * are hardcoded (100 / 40) rather than imported, since the frontend has no
 * access to the backend's own constants module — keep these in sync by hand
 * with ATTACH_THRESHOLD/REVIEW_THRESHOLD in backend/src/consts/assets.ts if
 * either ever changes.
 */
export function AssetsHelpTip() {
  return (
    <SimpleTip
      align="right"
      panelClassName="w-80"
      trigger={
        <button
          type="button"
          aria-label="How the Assets list works"
          className="inline-flex size-6 shrink-0 items-center justify-center rounded-full text-white/80 transition-colors hover:bg-white/15 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40"
        >
          <Info className="size-4" />
        </button>
      }
    >
      <p>
        Ties together the machines your Vajra agents report and the hosts your authenticated
        OpenVAS scans find, by matching hardware and network evidence — not by IP or hostname
        alone, since either can change or be reused by a different machine.
      </p>
      <p className="mt-2.5 font-semibold text-white">
        Identity confidence — the strongest evidence ever seen:
      </p>
      <ul className="mt-1 space-y-1">
        {CONFIDENCE_LEVELS.filter((level) => level.min > 0).map((level) => (
          <li key={level.min}>
            <span className="font-semibold">{level.min}, {level.label}</span> — {level.anchor}
          </li>
        ))}
      </ul>
      <p className="mt-2.5 font-semibold text-white">
        Attaching a new scan to an existing machine:
      </p>
      <ul className="mt-1 space-y-1">
        <li><span className="font-semibold">100+</span> — attaches automatically, no review needed.</li>
        <li><span className="font-semibold">40–99</span> — still attaches, but flagged for review (real evidence, just not certain enough on its own).</li>
        <li><span className="font-semibold">Below 40, or two machines equally likely</span> — refuses to guess and creates a new asset instead, flagged for review. A wrong guess silently mixes two machines&rsquo; histories together; a duplicate is easy to fix afterwards.</li>
      </ul>
      <p className="mt-2.5 text-white/70">
        &ldquo;Include merged&rdquo; duplicates are combined manually, not automatically — this
        matching only ever attaches new evidence or creates a new asset.
      </p>
      <p className="mt-2.5 text-white/70">
        Click any row for the full evidence trail and every scan that ever saw it.
      </p>
    </SimpleTip>
  );
}

export function ConfidenceBadge({ value, size = 'sm' }: { value: number; size?: 'sm' | 'md' }) {
  const level = confidenceLevel(value);
  const Icon = level.icon;
  return (
    <InfoTip
      label={
        <>
          <span className="font-semibold">{value} — {level.label}</span>
          <br />
          Strongest anchor: {level.anchor}.
          <br />
          {level.explanation}
        </>
      }
    >
      <span
        tabIndex={0}
        className={cn(
          'inline-flex items-center gap-1.5 rounded-full font-semibold outline-none focus-visible:ring-2 focus-visible:ring-blue-400',
          TONE_CLASSES[level.tone],
          size === 'md' ? 'px-2.5 py-1 text-xs' : 'px-2 py-0.5 text-[11px]',
        )}
      >
        <Icon className="size-3 shrink-0" />
        {level.label}
        <span className="tabular-nums opacity-70">{value}</span>
      </span>
    </InfoTip>
  );
}

/* ------------------------------------------------------------- sources */

interface SourceMeta { label: string; description: string; chip: string; icon: typeof Radar }

/**
 * OpenVAS is the one active feed (ADDENDUM 3 narrowed asset identity to
 * OpenVAS-only); it gets the brand's own teal treatment so it stands out as
 * "the" source, while the other, currently-disabled-but-still-valid legacy
 * sources fall back onto the generic TONE_CLASSES scale.
 */
// eslint-disable-next-line react-refresh/only-export-components
export const SOURCE_META: Record<ObservationSource, SourceMeta> = {
  agent: { label: 'Agent', description: 'Reported by the Vajra agent running on the host.', chip: TONE_CLASSES.success, icon: Laptop },
  nmap: { label: 'Nmap', description: 'Seen by a network discovery/port scan.', chip: TONE_CLASSES.info, icon: Radar },
  openvas: { label: 'OpenVAS', description: 'Seen in an authenticated OpenVAS vulnerability scan — the sole active identity feed.', chip: cn(OPENVAS_BRAND.softBg, OPENVAS_BRAND.softText, 'ring-1', OPENVAS_BRAND.softBorder), icon: ShieldQuestion },
  nuclei: { label: 'Nuclei', description: 'Seen by a Nuclei scan. Nuclei never creates an asset on its own — it only attaches to one that already exists.', chip: TONE_CLASSES.warning, icon: Bug },
  arp: { label: 'ARP', description: 'Seen in an agent ARP cache (IP-to-MAC bridge).', chip: TONE_CLASSES.neutral, icon: Router },
};

export function SourceBadge({ source }: { source: ObservationSource }) {
  const meta = SOURCE_META[source] ?? {
    label: source, description: 'Unknown source.', chip: TONE_CLASSES.neutral, icon: HelpCircle,
  };
  const Icon = meta.icon;
  return (
    <InfoTip label={meta.description}>
      <span
        tabIndex={0}
        className={cn('inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold outline-none focus-visible:ring-2 focus-visible:ring-blue-400', meta.chip)}
      >
        <Icon className="size-3 shrink-0" />
        {meta.label}
      </span>
    </InfoTip>
  );
}

/* ------------------------------------------------------------------ merge */

export function MergedBadge({ mergedInto }: { mergedInto: string }) {
  return (
    <InfoTip label={`Soft-merged into ${mergedInto}. The row is kept and the merge is reversible — observations are never rewritten.`}>
      <span
        tabIndex={0}
        className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold outline-none focus-visible:ring-2 focus-visible:ring-blue-400', TONE_CLASSES.neutral)}
      >
        <Link2 className="size-3 shrink-0" />
        Merged
      </span>
    </InfoTip>
  );
}

/* ------------------------------------------------------------- identities */

interface KindMeta { label: string; weight: number; note: string; tone: Tone }

/**
 * Each of the 6 identity kinds maps onto one of the 6 shared Tone values, so
 * every kind stays visually distinct while living entirely on the shared
 * palette rather than Assets' own ad hoc colors.
 */
// eslint-disable-next-line react-refresh/only-export-components
export const KIND_META: Record<IdentityKind, KindMeta> = {
  bios_uuid: { label: 'BIOS UUID', weight: 100, note: 'Hardware SMBIOS uuid — the strongest anchor there is.', tone: 'success' },
  mac: { label: 'MAC', weight: 80, note: 'Hardware MAC address. Zero, broadcast and locally-administered (virtual/randomised) addresses are dropped before matching.', tone: 'info' },
  hostname: { label: 'Hostname', weight: 40, note: 'Lowercased, DNS suffix stripped. Generic names such as localhost are dropped.', tone: 'warning' },
  os: { label: 'OS family', weight: 10, note: 'Collapsed to windows/linux/other — the exact edition is not evidence of identity.', tone: 'progress' },
  ip: { label: 'IP', weight: 5, note: 'Weakest anchor: addresses move between machines.', tone: 'danger' },
  osquery_uuid: { label: 'osquery UUID', weight: 0, note: 'Software-generated by osquery, not hardware. Stored as evidence only and never scored.', tone: 'neutral' },
};

export function KindBadge({ kind, weight }: { kind: IdentityKind; weight?: number }) {
  const meta = KIND_META[kind] ?? { label: kind, weight: 0, note: 'Unknown identity kind.', tone: 'neutral' as Tone };
  const shown = weight ?? meta.weight;
  return (
    <InfoTip label={<>
      <span className="font-semibold">{meta.label} — weight {shown}</span>
      <br />
      {meta.note}
    </>}>
      <span
        tabIndex={0}
        className={cn('inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold outline-none focus-visible:ring-2 focus-visible:ring-blue-400', TONE_CLASSES[meta.tone])}
      >
        {meta.label}
        <span className="tabular-nums opacity-70">{shown}</span>
      </span>
    </InfoTip>
  );
}

/* --------------------------------------------------------- match outcomes */

interface DecisionMeta { label: string; note: string; tone: Tone }

// eslint-disable-next-line react-refresh/only-export-components
export const DECISION_META: Record<ResolveDecision, DecisionMeta> = {
  attached: { label: 'Attached', note: 'Scored 100 or more against an existing asset and was attached to it outright.', tone: 'success' },
  attached_needs_review: { label: 'Attached — review', note: 'Attached on a middling score (40–99), or on an IP-only match. Flagged so a person can confirm it.', tone: 'warning' },
  new_asset: { label: 'New asset', note: 'Nothing matched, so this observation minted a brand-new asset.', tone: 'info' },
  ambiguous_new_asset: { label: 'Ambiguous — new asset', note: 'Two candidate machines scored too close to tell apart, so no merge was made: a new asset was minted and flagged instead. A silent wrong merge is far more costly than a duplicate.', tone: 'danger' },
  skipped_no_identities: { label: 'Skipped — no identity', note: 'Every value seen was dropped by normalisation, so there was nothing to match on. The row is kept purely to explain why this host never became an asset.', tone: 'neutral' },
  skipped_no_mint: { label: 'Skipped — no match', note: 'Nothing matched, and this source is not allowed to create assets on its own (Nuclei), so no asset was minted.', tone: 'neutral' },
};

export function DecisionBadge({ decision }: { decision: ResolveDecision }) {
  const meta = DECISION_META[decision] ?? { label: decision, note: 'Unknown decision.', tone: 'neutral' as Tone };
  return (
    <InfoTip label={meta.note}>
      <span
        tabIndex={0}
        className={cn('inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold outline-none focus-visible:ring-2 focus-visible:ring-blue-400', TONE_CLASSES[meta.tone])}
      >
        {meta.label}
      </span>
    </InfoTip>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export const VETO_LABEL: Record<VetoReason, { label: string; note: string }> = {
  bios_uuid_conflict: { label: 'BIOS UUID conflict', note: 'Both sides had a valid but different hardware uuid, so this can only be a different machine — a hard no-match regardless of score. This is what stops a reused DHCP lease from merging two machines.' },
  mac_conflict: { label: 'MAC conflict', note: 'This candidate already owns one or more MAC addresses, and the new observation carries a completely different set with no overlap and no BIOS-UUID match to explain it (e.g. a new NIC on known hardware) — treated as a different machine regardless of score.' },
  os_family_conflict: { label: 'OS family conflict', note: 'The operating system families differed with no BIOS-UUID or MAC match to override it.' },
  ambiguous_candidates: { label: 'Ambiguous candidates', note: 'The top two candidates were within 20 points of each other — too close to choose safely, so no merge was made.' },
};

export function VetoBadge({ veto }: { veto: VetoReason }) {
  const meta = VETO_LABEL[veto] ?? { label: veto, note: 'Unknown veto.' };
  return (
    <InfoTip label={meta.note}>
      <span
        tabIndex={0}
        className={cn('inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold outline-none focus-visible:ring-2 focus-visible:ring-blue-400', TONE_CLASSES.danger)}
      >
        <AlertTriangle className="size-3 shrink-0" />
        {meta.label}
      </span>
    </InfoTip>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export const DROP_REASON_LABEL: Record<DropReason, string> = {
  zero_mac: 'All-zero MAC (00:00:00:00:00:00) — held by many hosts, never an identity',
  broadcast_mac: 'Broadcast MAC (all-FF)',
  locally_administered_mac: 'Locally administered MAC — a virtual or randomised address (Docker, VMware, Hyper-V, private Wi-Fi)',
  malformed_mac: 'Not a well-formed MAC address',
  zero_bios_uuid: 'All-zero BIOS UUID',
  junk_bios_uuid: 'A known junk motherboard-default UUID shared across many machines',
  malformed_bios_uuid: 'Not a well-formed UUID',
  generic_hostname: 'Generic hostname (localhost, ubuntu, …) — not unique to one machine',
  empty_hostname: 'Empty hostname',
  loopback_ip: 'Loopback address',
  link_local_ip: 'Link-local address',
  malformed_ip: 'Not a well-formed IP address',
  unrecognized_os: 'OS string did not map to a known family',
};

/* --------------------------------------------------------------- layout */

/* Checkbox — Base UI primitive styled to match the rest of the app's tables,
   the same reason features/Network/ui.tsx carries its own. */

export function Checkbox({ checked, disabled, onChange, ...rest }: {
  checked: boolean;
  disabled?: boolean;
  onChange: () => void;
  'aria-label'?: string;
}) {
  return (
    <CheckboxPrimitive.Root
      checked={checked}
      disabled={disabled}
      onCheckedChange={onChange}
      aria-label={rest['aria-label']}
      className={cn(
        'flex size-4 shrink-0 items-center justify-center rounded border transition-colors',
        disabled
          ? 'cursor-not-allowed border-slate-200 bg-slate-100'
          : checked
            ? 'cursor-pointer border-transparent shadow-sm'
            : 'cursor-pointer border-slate-300 bg-white hover:border-slate-400',
      )}
      style={!disabled && checked ? { background: ASSETS_ACCENT } : undefined}
    >
      <CheckboxPrimitive.Indicator className="flex text-white" keepMounted={false}>
        <Check className="size-3" strokeWidth={3} />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

/* Segmented control — mirrors features/Network/ui.tsx's SegmentedControlOnDark,
   kept local so this feature owns its own presentational primitives. Recolored
   to the OpenVAS teal brand (rather than the app-wide blue) so it sits
   naturally inside a PanelHeader painted with OPENVAS_BRAND.gradient. */

interface SegmentOption<T extends string> { value: T; label: ReactNode; icon?: ReactNode }

export function SegmentedControlOnDark<T extends string>({ options, value, onChange, layoutId, className }: {
  options: SegmentOption<T>[];
  value: T;
  onChange: (value: T) => void;
  layoutId: string;
  className?: string;
}) {
  return (
    <div className={cn('relative inline-flex items-center gap-0.5 rounded-full border border-white/20 bg-white/10 p-1 backdrop-blur-sm', className)}>
      {options.map((opt) => {
        const active = value === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            onClick={() => onChange(opt.value)}
            className={cn(
              'relative z-10 inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-1.5 text-sm font-semibold transition-colors duration-150',
              active ? 'text-teal-800' : 'text-white/85 hover:text-white',
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

/* ------------------------------------------------------------ formatting */

// One hoisted Intl.DateTimeFormat rather than one per row: constructing it
// resolves locale + pattern, which is the most expensive common Intl call, and
// these tables re-render on every filter and page change (same reasoning as
// DomainReputation/HistoryTable.tsx).
const TIMESTAMP_FORMATTER = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

// eslint-disable-next-line react-refresh/only-export-components
export const formatTimestamp = (iso: string | null | undefined): string => {
  if (!iso) return '—';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '—' : TIMESTAMP_FORMATTER.format(date);
};

/** "3 days ago" — relative age, for the timeline gutter. */
// eslint-disable-next-line react-refresh/only-export-components
export const formatRelative = (iso: string | null | undefined): string => {
  if (!iso) return '';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '';
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 31) return `${days}d ago`;
  const months = Math.round(days / 30);
  return months < 12 ? `${months}mo ago` : `${Math.round(months / 12)}y ago`;
};
