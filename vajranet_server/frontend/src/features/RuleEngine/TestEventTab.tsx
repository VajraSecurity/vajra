import { useCallback, useEffect, useState } from 'react';
import { Play, Loader2, Info, ShieldAlert } from 'lucide-react';
import { RawJsonView, ErrorBanner, SeverityBadge } from './ui';
import { getTestEventExamples, testEvent } from '../../api/api';
import type { TestEventExample, TestEventResult } from '../../api/services/ruleEngineApi';

export default function TestEventTab() {
  const [examples, setExamples] = useState<TestEventExample[]>([]);
  const [eventText, setEventText] = useState('{\n  \n}');
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<TestEventResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);

  useEffect(() => {
    getTestEventExamples().then((resp) => setExamples(resp.items)).catch(() => setExamples([]));
  }, []);

  const loadExample = useCallback((ex: TestEventExample) => {
    setEventText(JSON.stringify(ex.event, null, 2));
    setJsonError(null);
    setResult(null);
    setRunError(null);
  }, []);

  const handleRun = async () => {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(eventText);
    } catch (e) {
      setJsonError(e instanceof Error ? e.message : 'Invalid JSON');
      return;
    }
    setJsonError(null);
    setRunning(true);
    setRunError(null);
    setResult(null);
    try {
      const resp = await testEvent(parsed);
      setResult(resp);
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Test event request failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="flex flex-col gap-4 h-full min-h-0">
      <div className="flex items-start gap-2 shrink-0 rounded-lg bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
        <ShieldAlert className="h-3.5 w-3.5 shrink-0 mt-0.5" />
        <p>
          This runs the pasted event against every currently-enabled <strong>detection</strong> rule using the real
          compiled engine. It does <strong>not</strong> evaluate correlation rules — a correlation needs a sequence
          of events, not one; use Correlation Simulation for that.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 flex-1 min-h-0">
        <div className="flex flex-col gap-2 min-h-0">
          <div className="flex items-center justify-between shrink-0">
            <label className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Event JSON</label>
            {examples.length > 0 && (
              <div className="flex items-center gap-1.5">
                <Info className="h-3.5 w-3.5 text-slate-400" />
                <select
                  onChange={(e) => {
                    const ex = examples.find((x) => x.label === e.target.value);
                    if (ex) loadExample(ex);
                  }}
                  defaultValue=""
                  className="text-xs rounded-lg border border-slate-200 dark:border-white/10 bg-white dark:bg-slate-800 px-2 py-1 text-slate-600 dark:text-slate-300"
                >
                  <option value="" disabled>Load a real example…</option>
                  {examples.map((ex) => <option key={ex.label} value={ex.label}>{ex.label}</option>)}
                </select>
              </div>
            )}
          </div>
          <textarea
            value={eventText}
            onChange={(e) => setEventText(e.target.value)}
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
            Run Against Enabled Rules
          </button>
        </div>

        <div className="flex flex-col gap-2 min-h-0">
          <label className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 shrink-0">Matches</label>
          {runError && <ErrorBanner message={runError} />}
          {!result && !runError && (
            <div className="flex-1 flex items-center justify-center text-sm text-slate-400 border border-dashed border-slate-200 dark:border-white/10 rounded-lg">
              Run an event to see which rules fire
            </div>
          )}
          {result && (
            <div className="flex-1 min-h-0 overflow-auto space-y-2">
              <p className="text-xs text-slate-400 italic">{result.note}</p>
              {result.matches.length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">No rules matched this event.</p>
              ) : (
                result.matches.map((m, i) => (
                  <div key={i} className="rounded-lg border border-slate-200 dark:border-white/10 p-3 flex items-start gap-3">
                    <SeverityBadge level={m.level} />
                    <div className="min-w-0">
                      <p className="text-sm text-slate-800 dark:text-slate-100">{m.description}</p>
                      <p className="text-xs text-slate-400 font-mono">{m.source}:{m.id}</p>
                    </div>
                  </div>
                ))
              )}
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
