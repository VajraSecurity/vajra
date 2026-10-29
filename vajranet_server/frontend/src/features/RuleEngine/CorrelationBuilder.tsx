import { useEffect, useMemo, useRef, useState } from 'react';
import {
  ReactFlow, Background, Controls, MarkerType, Handle, Position,
  useNodesState, useEdgesState,
  type Node, type Edge, type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Search, X, ArrowUp, ArrowDown, CheckCircle2, XCircle, Loader2 } from 'lucide-react';
import { Modal, Dropdown, TagInput, SegmentedControl, RawJsonView, ErrorBanner } from './ui';
import { CORRELATION_TYPES, CORRELATION_TYPE_LABELS, ORDERED_CORRELATION_TYPES } from './constants';
import { listRules, validateCorrelationRule, createCorrelationRule } from '../../api/api';
import type { CorrelationType, DetectionRule, NewCorrelationRule, ValidateResult } from '../../api/services/ruleEngineApi';

interface CorrelationBuilderProps {
  onClose: () => void;
  onCreated: () => void;
  /** Pre-fills the graph/form, e.g. from an AI `propose_correlation_rule` chat card's "Load into builder" action. */
  initialCorrelation?: Partial<NewCorrelationRule> | null;
}

interface PickedRule {
  id: number | string;
  description: string;
  event_type: string;
}

const SEARCH_DEBOUNCE_MS = 350;
const NODE_W = 200;
const NODE_H = 70;

// ── Custom node renderers — visually distinct chain-node vs. threshold-node
// shapes, per the spec's explicit requirement that ordered vs. unordered
// correlations "look" different at a glance, not just behave differently. ──

function RuleGraphNode({ data }: NodeProps<Node<{ label: string; sub: string; index?: number }>>) {
  return (
    <div className="rounded-xl border-2 border-indigo-300 dark:border-indigo-500/50 bg-white dark:bg-slate-800 px-3 py-2 shadow-sm" style={{ width: NODE_W }}>
      <Handle type="target" position={Position.Left} isConnectable={false} className="!bg-indigo-400" />
      <div className="flex items-center gap-1.5">
        {data.index !== undefined && (
          <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-[10px] font-bold text-white">{data.index}</span>
        )}
        <span className="truncate text-xs font-semibold text-slate-800 dark:text-slate-100">Rule {data.label}</span>
      </div>
      <p className="mt-0.5 truncate text-[11px] text-slate-500 dark:text-slate-400" title={data.sub}>{data.sub}</p>
      <Handle type="source" position={Position.Right} isConnectable={false} className="!bg-indigo-400" />
      <Handle type="source" position={Position.Bottom} id="down" isConnectable={false} className="!bg-indigo-400" />
    </div>
  );
}

function ThresholdGraphNode({ data }: NodeProps<Node<{ label: string; sub: string }>>) {
  return (
    <div className="rounded-xl border-2 border-amber-400 dark:border-amber-500/60 bg-amber-50 dark:bg-amber-500/10 px-3 py-2.5 shadow-sm" style={{ width: NODE_W }}>
      <Handle type="target" position={Position.Top} isConnectable={false} className="!bg-amber-500" />
      <div className="text-xs font-bold text-amber-800 dark:text-amber-300">{data.label}</div>
      <p className="mt-0.5 text-[11px] text-amber-700 dark:text-amber-400/90">{data.sub}</p>
    </div>
  );
}

const NODE_TYPES = { ruleNode: RuleGraphNode, thresholdNode: ThresholdGraphNode };

export default function CorrelationBuilder({ onClose, onCreated, initialCorrelation }: CorrelationBuilderProps) {
  const [view, setView] = useState<'graph' | 'raw'>('graph');
  const [type, setType] = useState<CorrelationType>((initialCorrelation?.type as CorrelationType) ?? 'temporal_ordered');
  const [description, setDescription] = useState(initialCorrelation?.description ?? '');
  const [groupBy, setGroupBy] = useState<string[]>(initialCorrelation?.group_by ?? ['host_identifier']);
  const [timespan, setTimespan] = useState(initialCorrelation?.timespan ?? 1800);
  const [level, setLevel] = useState(initialCorrelation?.level ?? 10);
  const [groups, setGroups] = useState<string[]>(initialCorrelation?.groups ?? []);
  const [mitre, setMitre] = useState<string[]>(initialCorrelation?.mitre ?? []);
  const [threshold, setThreshold] = useState<number>(initialCorrelation?.threshold ?? 3);
  const [field, setField] = useState<string>(initialCorrelation?.field ?? '');
  const [idOverride, setIdOverride] = useState<string>(initialCorrelation?.id !== undefined ? String(initialCorrelation.id) : '');

  // Ordered list of picked rules — the single source of truth for the graph
  // AND the assembled JSON's `rules` array (order matters for
  // temporal_ordered, per RULE_AUTHORING_TEMPLATE.md §8). Seeded from an AI
  // proposal's bare rule-id array with placeholder descriptions (the
  // proposal only carries ids, not (source,id) pairs, so real descriptions
  // aren't resolvable without a lookup per id) — the human can still
  // search/remove/reorder before saving, same as anything else here.
  const [pickedRules, setPickedRules] = useState<PickedRule[]>(() =>
    (initialCorrelation?.rules ?? []).map((id) => ({ id, description: '(from AI proposal — search to replace/confirm)', event_type: '' })),
  );

  // Rule search/picker — debounced against GET /rule-engine/rules?q=, never
  // loads the full ~1500-rule corpus at once.
  const [query, setQuery] = useState('');
  const [searchResults, setSearchResults] = useState<DetectionRule[]>([]);
  const [searching, setSearching] = useState(false);
  useEffect(() => {
    if (!query.trim()) { setSearchResults([]); return; }
    const t = setTimeout(async () => {
      setSearching(true);
      try {
        const resp = await listRules({ q: query.trim(), page: 1, page_size: 8 });
        setSearchResults(resp.items);
      } catch {
        setSearchResults([]);
      } finally {
        setSearching(false);
      }
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [query]);

  const addRule = (r: DetectionRule) => {
    if (pickedRules.some((p) => String(p.id) === String(r.id))) return;
    setPickedRules((prev) => [...prev, { id: r.id, description: r.description, event_type: r.event_type }]);
    setQuery('');
    setSearchResults([]);
  };
  const removeRule = (id: number | string) => setPickedRules((prev) => prev.filter((p) => String(p.id) !== String(id)));
  const moveRule = (idx: number, dir: -1 | 1) => {
    setPickedRules((prev) => {
      const next = [...prev];
      const j = idx + dir;
      if (j < 0 || j >= next.length) return prev;
      [next[idx], next[j]] = [next[j], next[idx]];
      return next;
    });
  };

  const isOrdered = ORDERED_CORRELATION_TYPES.has(type);

  const thresholdLabel = type === 'event_count'
    ? `Threshold (≥${threshold})`
    : type === 'value_count'
      ? `Distinct values (≥${threshold})`
      : 'Co-occurrence (any order)';
  const thresholdSub = type === 'event_count'
    ? `${pickedRules.length} rule(s) feed this count`
    : type === 'value_count'
      ? `distinct "${field || '(field not set)'}" values`
      : `every rule must match, order doesn't matter`;

  // ── React Flow state — recomputed from pickedRules/type, but preserves any
  // user-dragged positions for nodes that are still present. ──
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const prevPositions = useRef<Record<string, { x: number; y: number }>>({});

  useEffect(() => {
    setNodes((prevNodes) => {
      prevNodes.forEach((n) => { prevPositions.current[n.id] = n.position; });
      const ruleNodes: Node[] = pickedRules.map((r, i) => {
        const id = `rule-${r.id}`;
        const pos = prevPositions.current[id] ?? (
          isOrdered
            ? { x: i * (NODE_W + 60), y: 80 }
            : { x: (i % 4) * (NODE_W + 40), y: Math.floor(i / 4) * (NODE_H + 30) }
        );
        return {
          id,
          type: 'ruleNode',
          position: pos,
          data: { label: String(r.id), sub: r.description, index: isOrdered ? i + 1 : undefined },
        };
      });
      if (isOrdered) return ruleNodes;
      const thresholdId = 'threshold';
      const thresholdPos = prevPositions.current[thresholdId] ?? { x: (Math.min(pickedRules.length, 4) * (NODE_W + 40)) / 2, y: Math.ceil(pickedRules.length / 4) * (NODE_H + 30) + 60 };
      return [...ruleNodes, { id: thresholdId, type: 'thresholdNode', position: thresholdPos, data: { label: thresholdLabel, sub: thresholdSub } }];
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps -- setNodes is stable; recompute only on real dependency changes
  }, [pickedRules, isOrdered, thresholdLabel, thresholdSub]);

  useEffect(() => {
    if (isOrdered) {
      const chainEdges: Edge[] = [];
      for (let i = 0; i < pickedRules.length - 1; i++) {
        chainEdges.push({
          id: `e-${i}`,
          source: `rule-${pickedRules[i].id}`,
          target: `rule-${pickedRules[i + 1].id}`,
          markerEnd: { type: MarkerType.ArrowClosed },
          style: { stroke: '#6366f1', strokeWidth: 2 },
          label: `${i + 1} → ${i + 2}`,
        });
      }
      setEdges(chainEdges);
    } else {
      const fanEdges: Edge[] = pickedRules.map((r) => ({
        id: `e-${r.id}`,
        source: `rule-${r.id}`,
        sourceHandle: 'down',
        target: 'threshold',
        style: { stroke: '#d97706', strokeWidth: 1.5, strokeDasharray: '4 3' },
      }));
      setEdges(fanEdges);
    }
  }, [pickedRules, isOrdered, setEdges]);

  const guidedCorrelation: NewCorrelationRule = useMemo(() => ({
    ...(idOverride.trim() ? { id: /^\d+$/.test(idOverride.trim()) ? Number(idOverride.trim()) : idOverride.trim() } : {}),
    type,
    description,
    rules: pickedRules.map((r) => r.id),
    group_by: groupBy,
    timespan,
    level,
    ...(groups.length ? { groups } : {}),
    ...(mitre.length ? { mitre } : {}),
    ...(type === 'event_count' ? { threshold } : {}),
    ...(type === 'value_count' ? { threshold, field } : {}),
  }), [idOverride, type, description, pickedRules, groupBy, timespan, level, groups, mitre, threshold, field]);

  const [rawText, setRawText] = useState(() => JSON.stringify(initialCorrelation ?? guidedCorrelation, null, 2));
  const [rawError, setRawError] = useState<string | null>(null);

  const [validating, setValidating] = useState(false);
  const [validation, setValidation] = useState<ValidateResult | null>(null);
  const [validatedSnapshot, setValidatedSnapshot] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  const currentPayload = (): NewCorrelationRule | null => {
    if (view === 'graph') return guidedCorrelation;
    try {
      const parsed = JSON.parse(rawText);
      setRawError(null);
      return parsed;
    } catch (e) {
      setRawError(e instanceof Error ? e.message : 'Invalid JSON');
      return null;
    }
  };

  const handleValidate = async () => {
    const payload = currentPayload();
    if (!payload) return;
    if (view === 'graph' && !idOverride.trim()) {
      setValidation({ ok: false, message: 'Rule ID is required — the engine has no auto-assign, despite what this form used to claim.' });
      return;
    }
    const snapshot = JSON.stringify(payload);
    setValidating(true);
    setValidation(null);
    setValidatedSnapshot(null);
    try {
      const result = await validateCorrelationRule(payload);
      setValidation(result);
      if (result.ok) setValidatedSnapshot(snapshot);
    } catch (err) {
      setValidation({ ok: false, message: err instanceof Error ? err.message : 'Validation request failed' });
    } finally {
      setValidating(false);
    }
  };

  const handleSave = async () => {
    const payload = currentPayload();
    if (!payload) return;
    if (JSON.stringify(payload) !== validatedSnapshot) {
      setSaveError('The correlation rule changed since it was last validated — click Validate again before saving.');
      return;
    }
    setSaving(true);
    setSaveError(null);
    try {
      await createCorrelationRule(payload);
      onCreated();
      onClose();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save correlation rule');
    } finally {
      setSaving(false);
    }
  };

  const handleSwitchToRaw = () => {
    setRawText(JSON.stringify(guidedCorrelation, null, 2));
    setView('raw');
  };

  return (
    <Modal title="Build Correlation Rule" onClose={onClose} wide>
      <div className="flex items-center justify-between mb-4">
        <SegmentedControl
          value={view}
          onChange={(v) => (v === 'raw' ? handleSwitchToRaw() : setView(v))}
          size="sm"
          options={[{ value: 'graph', label: 'Visual Builder' }, { value: 'raw', label: 'Raw JSON' }]}
        />
        <Dropdown
          value={type}
          onChange={(v) => setType(v as CorrelationType)}
          options={CORRELATION_TYPES.map((t) => ({ value: t, label: CORRELATION_TYPE_LABELS[t] }))}
          className="w-96"
          aria-label="Correlation type"
        />
      </div>

      {view === 'graph' ? (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="lg:col-span-2">
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Description</label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="e.g. Recon -> credential access -> lateral movement"
                className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Timespan (seconds)</label>
              <input
                type="number"
                min={1}
                value={timespan}
                onChange={(e) => setTimespan(Number(e.target.value))}
                className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Level</label>
              <input
                type="number"
                min={0}
                value={level}
                onChange={(e) => setLevel(Number(e.target.value))}
                className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Group By</label>
              <TagInput values={groupBy} onChange={setGroupBy} placeholder="e.g. host_identifier" />
            </div>
            {type === 'value_count' && (
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Distinct-value field</label>
                <input
                  type="text"
                  value={field}
                  onChange={(e) => setField(e.target.value)}
                  placeholder="e.g. network.remote_address"
                  className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
                />
              </div>
            )}
            {(type === 'event_count' || type === 'value_count') && (
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Threshold (≥N)</label>
                <input
                  type="number"
                  min={1}
                  value={threshold}
                  onChange={(e) => setThreshold(Number(e.target.value))}
                  className="w-32 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
                />
              </div>
            )}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">
                Rule ID <span className="text-red-500">*</span>{' '}
                <span className="font-normal normal-case text-slate-400">(numeric, must not already exist — the engine has no auto-assign)</span>
              </label>
              <input
                type="text"
                value={idOverride}
                onChange={(e) => setIdOverride(e.target.value)}
                placeholder="e.g. 900101"
                className="w-40 rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Groups / MITRE ATT&amp;CK (optional)</label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <TagInput values={groups} onChange={setGroups} placeholder="e.g. kill_chain" />
              <TagInput values={mitre} onChange={setMitre} placeholder="e.g. T1482" />
            </div>
          </div>

          {/* Rule search/picker */}
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">
              Add rules to this correlation {isOrdered && <span className="font-normal normal-case">— order matters, added in sequence</span>}
            </label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search detection rules by id, description, MITRE technique… (debounced, never loads all rules)"
                className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 pl-9 pr-3 py-2 text-sm text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
              />
              {(searching || searchResults.length > 0) && (
                <div className="absolute z-20 mt-1 w-full rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 shadow-lg max-h-56 overflow-auto">
                  {searching && <div className="px-3 py-2 text-xs text-slate-400">Searching…</div>}
                  {!searching && searchResults.map((r) => (
                    <button
                      key={`${r.source}:${r.id}`}
                      onClick={() => addRule(r)}
                      className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-slate-50 dark:hover:bg-white/5"
                    >
                      <span className="truncate">
                        <span className="font-mono text-xs text-slate-400 mr-2">{r.id}</span>
                        {r.description}
                      </span>
                      <code className="shrink-0 text-[10px] bg-slate-100 dark:bg-white/10 rounded px-1.5 py-0.5">{r.event_type}</code>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {pickedRules.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-2">
                {pickedRules.map((r, idx) => (
                  <span key={r.id} className="inline-flex items-center gap-1.5 rounded-lg bg-indigo-50 dark:bg-indigo-500/15 pl-2.5 pr-1.5 py-1 text-xs font-medium text-indigo-700 dark:text-indigo-300">
                    {isOrdered && <span className="font-bold">{idx + 1}.</span>}
                    <span className="max-w-[160px] truncate" title={r.description}>{r.id}</span>
                    {isOrdered && (
                      <>
                        <button onClick={() => moveRule(idx, -1)} disabled={idx === 0} aria-label="Move earlier" className="disabled:opacity-30"><ArrowUp className="h-3 w-3" /></button>
                        <button onClick={() => moveRule(idx, 1)} disabled={idx === pickedRules.length - 1} aria-label="Move later" className="disabled:opacity-30"><ArrowDown className="h-3 w-3" /></button>
                      </>
                    )}
                    <button onClick={() => removeRule(r.id)} aria-label={`Remove rule ${r.id}`}><X className="h-3 w-3" /></button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Graph */}
          <div className="h-[340px] rounded-xl border border-slate-200 dark:border-white/10 overflow-hidden">
            {pickedRules.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-slate-400">
                Add rules above to build the {isOrdered ? 'kill-chain' : 'threshold'} graph
              </div>
            ) : (
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                nodeTypes={NODE_TYPES}
                nodesConnectable={false}
                fitView
                proOptions={{ hideAttribution: true }}
              >
                <Background gap={16} />
                <Controls showInteractive={false} />
              </ReactFlow>
            )}
          </div>

          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-1">Preview (what will be sent)</p>
            <RawJsonView value={guidedCorrelation} />
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            rows={18}
            spellCheck={false}
            className="w-full rounded-lg border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-black/30 p-3 font-mono text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
          />
          {rawError && <ErrorBanner message={`Invalid JSON: ${rawError}`} />}
        </div>
      )}

      <div className="mt-5 flex items-center justify-between border-t border-slate-200 dark:border-white/10 pt-4">
        <div className="flex-1 min-w-0">
          {validation && (
            validation.ok ? (
              <div className="flex items-center gap-2 text-sm text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span className="truncate">{validation.message || 'Valid — the real engine accepted this correlation rule.'}</span>
                {validation.warnings && validation.warnings.length > 0 && (
                  <span className="text-amber-600 dark:text-amber-400">({validation.warnings.join('; ')})</span>
                )}
              </div>
            ) : (
              <div className="flex items-center gap-2 text-sm text-red-600 dark:text-red-400">
                <XCircle className="h-4 w-4 shrink-0" />
                <span className="truncate">{validation.message}</span>
              </div>
            )
          )}
          {saveError && <ErrorBanner message={saveError} />}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleValidate}
            disabled={validating}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-200 dark:border-white/10 px-4 py-2 text-sm font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-white/5 disabled:opacity-50"
          >
            {validating && <Loader2 className="h-4 w-4 animate-spin" />}
            Validate
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !validatedSnapshot}
            title={!validatedSnapshot ? 'Validate successfully before saving' : undefined}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50 disabled:pointer-events-none"
          >
            {saving && <Loader2 className="h-4 w-4 animate-spin" />}
            Save Correlation Rule
          </button>
        </div>
      </div>
      <p className="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
        Correlation rules are hot-reloadable via SIGHUP the same as detection rules, but neither Test Event nor this
        builder&apos;s Validate button exercises the CorrelationEngine itself — use Correlation Simulation to prove
        this rule actually fires against a real ordered event sequence.
      </p>
    </Modal>
  );
}
