import { useState } from 'react';
import { Server, BellRing, ShieldCheck, AppWindow, Users } from 'lucide-react';
import { DuoSpinner } from '@/components/ui/loading';
import type { PendingAction, ToolEvent } from './useAiChatSession';

/**
 * Shared between the full-page AI Assistant (`features/AI/index.tsx`) and
 * the app-wide `FloatingChatWidget` — extracted so both surfaces render the
 * same `propose_agent_action` confirmation UI and tool-call activity badge
 * instead of two copies drifting apart. Purely presentational; no behavior
 * changed from what `features/AI/index.tsx` had inline before this split.
 */

// eslint-disable-next-line react-refresh/only-export-components
export const RISK_STYLES: Record<PendingAction['risk'], { border: string; bg: string; text: string; badge: string }> = {
  low:    { border: 'border-emerald-400/60', bg: 'bg-emerald-500/10',  text: 'text-emerald-200', badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-400/40' },
  medium: { border: 'border-amber-400/60',   bg: 'bg-amber-500/10',    text: 'text-amber-200',   badge: 'bg-amber-500/20 text-amber-300 border-amber-400/40' },
  high:   { border: 'border-rose-400/60',    bg: 'bg-rose-500/10',     text: 'text-rose-200',    badge: 'bg-rose-500/20 text-rose-300 border-rose-400/40' },
};

// eslint-disable-next-line react-refresh/only-export-components
export const RISK_LABELS: Record<PendingAction['risk'], string> = {
  low: 'Low Risk', medium: 'Medium Risk', high: 'High Risk',
};

// eslint-disable-next-line react-refresh/only-export-components
export const ACTION_LABELS: Record<string, string> = {
  compliance_check:  'Run Compliance Check',
  isolate_node:      'Isolate Node',
  reenroll_node:     'Reenroll Node',
  block_port:        'Block Port',
  unblock_port:      'Unblock Port',
  block_ip:          'Block IP',
  unblock_ip:        'Unblock IP',
  disable_usb:       'Disable USB',
  enable_usb:        'Enable USB',
  disable_bluetooth: 'Disable Bluetooth',
  enable_bluetooth:  'Enable Bluetooth',
};

// eslint-disable-next-line react-refresh/only-export-components
export const TOOL_LABELS: Record<string, string> = {
  execute_db_query:    'Querying database',
  get_schema_info:     'Reading schema',
  propose_agent_action:'Preparing action',
};

/** Quick-prompt suggestion chips — shown on the full AI Assistant page's
 * empty state and (a shorter slice of) the floating widget's empty state. */
// eslint-disable-next-line react-refresh/only-export-components
export const SUGGESTIONS = [
  {
    title: 'Nodes Online',
    description: 'Check how many nodes are currently online.',
    text: 'How many nodes are currently online?',
    icon: Server,
    iconClass: 'bg-indigo-500/20 text-indigo-300',
    accent: '#818cf8',
  },
  {
    title: 'Critical Alerts',
    description: 'Show critical alerts from the last 7 days.',
    text: 'Show critical alerts from the last 7 days',
    icon: BellRing,
    iconClass: 'bg-rose-500/20 text-rose-300',
    accent: '#fb7185',
  },
  {
    title: 'Compliance Status',
    description: 'View compliance status across all Windows machines.',
    text: 'What is the compliance status across all Windows machines?',
    icon: ShieldCheck,
    iconClass: 'bg-emerald-500/20 text-emerald-300',
    accent: '#34d399',
  },
  {
    title: 'Defender Disabled',
    description: 'Find nodes with Windows Defender disabled.',
    text: 'Which nodes have Windows Defender disabled?',
    icon: AppWindow,
    iconClass: 'bg-sky-500/20 text-sky-300',
    accent: '#38bdf8',
  },
  {
    title: 'High Risk Nodes',
    description: 'Get a summary of high risk or vulnerable nodes.',
    text: 'Give me a summary of high risk nodes',
    icon: Users,
    iconClass: 'bg-amber-500/20 text-amber-300',
    accent: '#fbbf24',
  },
];

export function ActionConfirmCard({
  action,
  onConfirm,
  onDeny,
}: {
  action: PendingAction;
  onConfirm: (id: string) => Promise<boolean>;
  onDeny: (id: string) => Promise<boolean>;
}) {
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState<'confirmed' | 'denied' | null>(null);
  const s = RISK_STYLES[action.risk] ?? RISK_STYLES.medium;

  const handleConfirm = async () => {
    setLoading(true);
    const ok = await onConfirm(action.id);
    if (ok) setDone('confirmed');
    setLoading(false);
  };

  const handleDeny = async () => {
    setLoading(true);
    const ok = await onDeny(action.id);
    setLoading(false);
    if (ok) setDone('denied');
  };

  if (done === 'confirmed') {
    return (
      <div className="rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300 flex items-center gap-2">
        <span className="text-base">✓</span>
        Action dispatched to <span className="font-mono text-emerald-200">{action.hostname ?? action.host_identifier}</span>
      </div>
    );
  }
  if (done === 'denied') {
    return (
      <div className="rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-white/30 flex items-center gap-2">
        <span>✗</span> Action cancelled
      </div>
    );
  }

  return (
    <div
      className={`rounded-xl border-2 px-4 py-4 ${s.border} ${s.bg} backdrop-blur-sm`}
      style={{ boxShadow: '0 0 30px rgba(184,63,194,0.1)' }}
    >
      <div className="flex items-start gap-3 mb-3">
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
          style={{ background: 'linear-gradient(135deg, rgba(184,63,194,0.3), rgba(198,154,74,0.3))', boxShadow: '0 0 12px rgba(184,63,194,0.3)' }}
        >
          <span className="text-sm">⚡</span>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5 flex-wrap">
            <span className={`font-semibold text-sm ${s.text}`}>
              {ACTION_LABELS[action.action_type] ?? action.action_type}
            </span>
            <span className={`text-xs px-2 py-0.5 rounded-full border ${s.badge}`}>
              {RISK_LABELS[action.risk] ?? RISK_LABELS.medium}
            </span>
          </div>
          <div className={`text-xs opacity-70 ${s.text} font-mono`}>
            {action.hostname ?? action.host_identifier}
          </div>
        </div>
      </div>
      <p className={`text-sm mb-4 ${s.text} opacity-80 leading-relaxed`}>{action.description}</p>
      <div className="flex gap-2">
        <button
          disabled={loading}
          onClick={handleConfirm}
          className="flex-1 rounded-lg py-2 text-sm font-medium text-white transition-all disabled:opacity-40 hover:opacity-90"
          style={{ background: 'linear-gradient(135deg, rgba(184,63,194,0.5), rgba(198,154,74,0.5))', boxShadow: '0 0 16px rgba(184,63,194,0.3)' }}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <DuoSpinner size="xs" className="text-white" />
              Dispatching…
            </span>
          ) : 'Confirm & Execute'}
        </button>
        <button
          disabled={loading}
          onClick={handleDeny}
          className="px-4 rounded-lg py-2 text-sm font-medium text-white/50 hover:text-white/80 transition-colors disabled:opacity-40 border border-white/10 hover:border-white/20"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

export function ToolCallBadge({ event, isLive }: { event: ToolEvent; isLive?: boolean }) {
  const [open, setOpen] = useState(false);
  const isError = event.is_error;
  const isDone = event.result !== undefined;

  return (
    <div
      className={`rounded-xl border text-xs overflow-hidden transition-all duration-200
        ${isError
          ? 'border-rose-400/30 bg-rose-500/5'
          : 'border-white/10 bg-white/5'
        }`}
    >
      <button
        className="flex w-full items-center gap-2 px-3 py-2 rounded-lg text-left hover:bg-white/5 transition-colors"
        onClick={() => isDone && setOpen((p) => !p)}
      >
        {isLive && !isDone ? (
          <span className="flex gap-0.5">
            {[0, 1, 2].map((i) => (
              <span
                key={i}
                className="block w-1 h-1 rounded-full animate-bounce"
                style={{
                  background: 'linear-gradient(135deg, #b83fc2, #c69a4a)',
                  animationDelay: `${i * 0.15}s`,
                  animationDuration: '0.8s',
                }}
              />
            ))}
          </span>
        ) : (
          <span
            className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${isError ? 'bg-rose-400' : 'bg-[#b83fc2]'}`}
            style={!isError ? { boxShadow: '0 0 4px rgba(184,63,194,0.8)' } : {}}
          />
        )}
        <span className="font-mono text-[#e0a8e8]/80">
          {TOOL_LABELS[event.tool_name] ?? event.tool_name}
        </span>
        {isError && <span className="ml-auto text-rose-400 text-xs">error</span>}
        {isDone && <span className="ml-auto text-white/30">{open ? '▲' : '▼'}</span>}
      </button>

      {/* event.result !== undefined (not a truthy check) — isDone is defined
          the same way, so a tool that completed with an empty-string result
          must still expand instead of the chevron being a dead-end click. */}
      {open && event.result !== undefined && (
        <div className="max-h-52 overflow-auto border-t border-white/10 px-3 py-2.5">
          <pre className="whitespace-pre-wrap break-words text-[#f0d8f4]/70 text-[11px] leading-relaxed font-mono">
            {(() => {
              try { return JSON.stringify(JSON.parse(event.result), null, 2); }
              catch { return event.result; }
            })()}
          </pre>
        </div>
      )}
    </div>
  );
}

/**
 * Used by every markdown renderer's `a` component (this page and
 * `FloatingChatWidget.tsx`) to reject non-http(s) link targets before
 * rendering an `<a href>` at all. react-markdown/remark-gfm don't execute
 * arbitrary HTML, but they also don't validate a link's scheme — a
 * `javascript:` URI in the assistant's own text (whether from the model
 * itself or content it read that ends up echoed back, e.g. a node/alert
 * field) would otherwise render as a normal clickable link and execute on
 * click. `mailto:`/`tel:` are also allowed as ordinary safe non-http schemes;
 * anything else (including a relative/scheme-less href, which this app's
 * chat has no legitimate use for) is rejected.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function isSafeMarkdownHref(href: string | undefined): href is string {
  if (!href) return false;
  try {
    // No base argument — a relative/scheme-less href (e.g. "/settings")
    // isn't a valid absolute URL on its own and throws here, which is
    // exactly the "reject it" outcome this function wants. Passing
    // `window.location.origin` as a base would resolve relative hrefs into
    // http(s) URLs and let them through, contradicting the "relative href
    // is rejected" behavior this function is documented to have.
    const url = new URL(href);
    return url.protocol === 'http:' || url.protocol === 'https:' || url.protocol === 'mailto:' || url.protocol === 'tel:';
  } catch {
    return false;
  }
}
