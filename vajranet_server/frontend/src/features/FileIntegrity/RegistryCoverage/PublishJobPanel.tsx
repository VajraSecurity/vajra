import { useEffect, useRef, useState } from 'react';
import { Ban, Loader2, X } from 'lucide-react';
import { cancelFimRegJob, type FimRegJob } from '../../../api/services/fimApi';
import { useConfirm } from '../../../context/useConfirm';
import { errMsg } from '../constants';
import { btnGhost } from '../styles';
import { safeText } from './safeText';
import { RegText } from './RegUi';
import { isJobActive, jobFailedHosts, jobProgressText, jobPublishedHosts, pollRegistryJob } from './regActions';

/**
 * Progress of a background profile publish: polls the job every ~2 s (backing off on errors),
 * shows "Publishing N/M, F failed", and the failed hosts once it ends. Stays visible (outside any
 * modal) until dismissed. Super Admins (`canCancel`) can cancel a running job.
 */
export default function PublishJobPanel({ jobId, initial, label, onFinished, onDismiss, intervalMs = 2000, canCancel }: {
  jobId: number; initial?: FimRegJob | null; label?: string; onFinished?: (j: FimRegJob) => void; onDismiss: () => void; intervalMs?: number; canCancel?: boolean;
}) {
  const confirm = useConfirm();
  const [job, setJob] = useState<FimRegJob | null>(initial ?? null);
  const [pollErr, setPollErr] = useState<string | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const [cancelBusy, setCancelBusy] = useState(false);
  const [cancelErr, setCancelErr] = useState<string | null>(null);
  const finishedRef = useRef(onFinished);
  useEffect(() => { finishedRef.current = onFinished; }, [onFinished]);

  useEffect(() => {
    const ctl = new AbortController();
    pollRegistryJob(jobId, {
      intervalMs, signal: ctl.signal,
      onUpdate: (j) => { setJob(j); setPollErr(null); },
      onError: (e, attempt) => setPollErr(`${errMsg(e, 'Progress temporarily unavailable')} (attempt ${attempt})`),
    }).then((j) => { if (j && !ctl.signal.aborted) finishedRef.current?.(j); })
      .catch((e) => { if (!ctl.signal.aborted) setFatal(errMsg(e, 'The publish job could not be read')); });
    return () => ctl.abort();
  }, [jobId, intervalMs]);

  const active = !!job && isJobActive(job) && !fatal;
  const ended = !!fatal || (!!job && !isJobActive(job));
  const failedHosts = job ? jobFailedHosts(job) : [];
  const publishedHosts = job ? jobPublishedHosts(job) : [];
  const bad = !!fatal || (!!job && ((job.status !== 'done' && !isJobActive(job)) || job.failed > 0));
  const pct = job && job.total > 0 ? Math.min(100, Math.round(((job.done + job.failed) / job.total) * 100)) : null;

  const cancel = async () => {
    const ok = await confirm({
      title: `Cancel publish job #${jobId}?`, variant: 'danger', confirmLabel: 'Cancel publish', cancelLabel: 'Keep running',
      description: 'Hosts already published keep their new configuration; the remaining hosts are not published. You can publish the profile again later.',
    });
    if (!ok) return;
    setCancelBusy(true); setCancelErr(null);
    try {
      const r = await cancelFimRegJob(jobId);
      const j = r && typeof r === 'object' && 'job' in r ? r.job : r;
      if (j && typeof j === 'object' && 'status' in j) setJob(j as FimRegJob);
    } catch (e) { setCancelErr(errMsg(e, 'Cancel failed')); } finally { setCancelBusy(false); }
  };

  return (
    <section role="status" aria-live="polite" aria-label="Profile publish progress" data-testid="fim-publish-job" data-active={active ? 'true' : 'false'}
      className={`rounded-lg border p-3 text-sm ${bad ? 'border-red-300 bg-red-50 text-red-900 dark:border-red-500/40 dark:bg-red-500/10 dark:text-red-200' : ended ? 'border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-200' : 'border-indigo-200 bg-indigo-50 text-indigo-900 dark:border-indigo-500/40 dark:bg-indigo-500/10 dark:text-indigo-200'}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="space-y-1">
          <p className="font-semibold">
            {active && <Loader2 aria-hidden data-testid="fim-job-spinner" className="mr-1 inline h-4 w-4 animate-spin" />}
            {label ? <><RegText value={label} />: </> : null}
            {safeText(fatal ? `Job #${jobId}: ${fatal}` : job ? jobProgressText(job) : `Publish job #${jobId} started...`)}
          </p>
          {pct !== null && active && <div className="h-1.5 w-56 overflow-hidden rounded bg-white/70 dark:bg-white/10"><div className="h-full bg-indigo-500" style={{ width: `${pct}%` }} /></div>}
          {pollErr && active && <p className="text-xs">{safeText(`Progress temporarily unavailable: ${pollErr}; retrying with backoff.`)}</p>}
          {cancelErr && <p className="text-xs">{safeText(cancelErr)}</p>}
          {ended && job?.status === 'done' && <p className="text-xs">New entries are offered in the Needs init queue; nothing was initialised automatically.</p>}
          {ended && !fatal && job && (job.status === 'aborted' || job.status === 'cancelled') && (
            <p className="text-xs">{publishedHosts.length} host(s) were already published and keep the new configuration; the rest were not published. Review the profile and publish again.</p>
          )}
          {ended && failedHosts.length > 0 && (
            <div className="text-xs">
              <p className="font-semibold">Failed hosts ({failedHosts.length}):</p>
              <ul className="max-h-40 list-disc overflow-auto pl-5">
                {failedHosts.slice(0, 200).map((r, i) => <li key={`${r.host}-${i}`}><RegText value={r.host} mono />: <RegText value={r.error} /></li>)}
              </ul>
              {failedHosts.length > 200 && <p>... and {failedHosts.length - 200} more</p>}
            </div>
          )}
        </div>
        <div className="flex shrink-0 gap-2">
          {active && canCancel && <button type="button" className={`${btnGhost} px-2 py-1 text-xs text-red-600`} disabled={cancelBusy} onClick={cancel}><Ban className="h-3.5 w-3.5" />{cancelBusy ? 'Cancelling...' : 'Cancel publish'}</button>}
          {ended && <button type="button" className={`${btnGhost} px-2 py-1 text-xs`} onClick={onDismiss} aria-label="Dismiss publish progress"><X className="h-3.5 w-3.5" />Dismiss</button>}
        </div>
      </div>
    </section>
  );
}
