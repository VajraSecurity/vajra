import { useEffect, useState } from 'react';
import { Play, Loader2, Info, CheckCircle2, XCircle } from 'lucide-react';
import { RawJsonView, ErrorBanner, SeverityBadge } from './ui';
import { getSimulationSamples, simulateCorrelation } from '../../api/api';
import type { SimulationSample, SimulationResult } from '../../api/services/ruleEngineApi';

export default function CorrelationSimulationTab() {
  const [samples, setSamples] = useState<SimulationSample[]>([]);
  const [samplesError, setSamplesError] = useState<string | null>(null);
  const [selected, setSelected] = useState<SimulationSample | null>(null);
  const [eventsText, setEventsText] = useState('[]');
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  useEffect(() => {
    getSimulationSamples()
      .then((resp) => setSamples(resp.items))
      .catch((err) => setSamplesError(err instanceof Error ? err.message : 'Failed to load sample sequences'));
  }, []);

  const loadSample = (s: SimulationSample) => {
    setSelected(s);
    setEventsText(JSON.stringify(s.events, null, 2));
    setJsonError(null);
    setResult(null);
    setRunError(null);
  };

  const handleRun = async () => {
    let events: Record<string, unknown>[];
    try {
      const parsed = JSON.parse(eventsText);
      if (!Array.isArray(parsed)) throw new Error('Events must be a JSON array, in order');
      events = parsed;
    } catch (e) {
      setJsonError(e instanceof Error ? e.message : 'Invalid JSON');
      return;
    }
    setJsonError(null);
    setRunning(true);
    setRunError(null);
    setResult(null);
    try {
      const resp = await simulateCorrelation(events);
      setResult(resp);
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Simulation request failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="flex flex-col gap-4 h-full min-h-0">
      <div className="flex items-start gap-2 shrink-0 rounded-lg bg-indigo-50 dark:bg-indigo-500/10 border border-indigo-200 dark:border-indigo-500/30 px-3 py-2 text-xs text-indigo-800 dark:text-indigo-300">
        <Info className="h-3.5 w-3.5 shrink-0 mt-0.5" />
        <p>
          Feeds a real, <strong>ordered</strong> event sequence through the actual CorrelationEngine — the only way
          to prove an <code className="text-[11px]">event_count</code>/<code className="text-[11px]">value_count</code>/
          <code className="text-[11px]">temporal</code>/<code className="text-[11px]">temporal_ordered</code> rule
          actually fires an incident, end to end. Order matters for the events array below.
        </p>
      </div>

      {samplesError && <ErrorBanner message={samplesError} />}
      {samples.length > 0 && (
        <div className="shrink-0 flex flex-wrap gap-2">
          {samples.map((s) => (
            <button
              key={s.name}
              onClick={() => loadSample(s)}
              className={`rounded-lg border px-3 py-2 text-left text-xs transition-colors max-w-xs ${
                selected?.name === s.name
                  ? 'border-indigo-400 bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300'
                  : 'border-slate-200 dark:border-white/10 hover:bg-slate-50 dark:hover:bg-white/5 text-slate-600 dark:text-slate-300'
              }`}
            >
              <span className="flex items-center gap-1.5 font-semibold">
                {s.expect_incident ? <CheckCircle2 className="h-3 w-3 text-emerald-500 shrink-0" /> : <XCircle className="h-3 w-3 text-slate-400 shrink-0" />}
                {s.name}
              </span>
              <span className="block mt-0.5 text-slate-500 dark:text-slate-400">{s.label}</span>
            </button>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 flex-1 min-h-0">
        <div className="flex flex-col gap-2 min-h-0">
          <label className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 shrink-0">Event Sequence (JSON array, in order)</label>
          <textarea
            value={eventsText}
            onChange={(e) => setEventsText(e.target.value)}
            spellCheck={false}
            className="flex-1 min-h-[240px] rounded-lg border border-slate-200 dark:border-white/10 bg-slate-50 dark:bg-black/30 p-3 font-mono text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
          />
          {jsonError && <ErrorBanner message={`Invalid JSON: ${jsonError}`} />}
          <button
            onClick={handleRun}
            disabled={running}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 disabled:opacity-50 shrink-0"
          >
            {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Simulate
          </button>
        </div>

        <div className="flex flex-col gap-2 min-h-0">
          <label className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 shrink-0">Result</label>
          {runError && <ErrorBanner message={runError} />}
          {!result && !runError && (
            <div className="flex-1 flex items-center justify-center text-sm text-slate-400 border border-dashed border-slate-200 dark:border-white/10 rounded-lg">
              Run a sequence to see alerts and incidents
            </div>
          )}
          {result && !result.ok && (
            <ErrorBanner message={result.message ?? 'Simulation failed'} />
          )}
          {result?.ok && (
            <div className="flex-1 min-h-0 overflow-auto space-y-3">
              {result.summary && <p className="text-xs text-slate-400 font-mono">{result.summary}</p>}
              <div>
                <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">Incidents ({result.incidents?.length ?? 0})</p>
                {(result.incidents ?? []).length === 0 ? (
                  <p className="text-sm text-slate-400">No incident fired.</p>
                ) : (
                  <div className="space-y-2">
                    {result.incidents!.map((inc, i) => (
                      <div key={i} className="rounded-lg border-2 border-amber-300 dark:border-amber-500/40 bg-amber-50 dark:bg-amber-500/10 p-3">
                        <div className="flex items-center gap-2">
                          <SeverityBadge level={inc.level} />
                          <span className="text-xs font-mono text-amber-700 dark:text-amber-400">{inc.type}</span>
                        </div>
                        <p className="mt-1 text-sm text-amber-900 dark:text-amber-200">{inc.description}</p>
                        <p className="mt-1 text-[11px] text-amber-700/80 dark:text-amber-400/70">
                          contributing: {inc.contributing.map((c) => `${c.rule_id}@${c.alert_id}`).join(', ')}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">Detection alerts along the way ({result.alerts?.length ?? 0})</p>
                <div className="space-y-1.5">
                  {(result.alerts ?? []).map((a, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <SeverityBadge level={a.level} />
                      <span className="text-slate-600 dark:text-slate-300 truncate">{a.description}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {result && (
        <details className="shrink-0">
          <summary className="cursor-pointer text-xs font-semibold text-slate-500 dark:text-slate-400">Raw response</summary>
          <div className="mt-2"><RawJsonView value={result} /></div>
        </details>
      )}
    </div>
  );
}
