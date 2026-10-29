import {
  getFimRegJob, initializeFimBaselineEntries, publishFimReg, startFimRegProfilePublish,
  type FimRegJob, type FimRegProfilePublishBody, type FimRegPublishBody, type FimRegPublishResponse,
} from '../../../api/services/fimApi';
import type { ConfirmOptions } from '../../../context/useConfirm';
import { errMsg, errStatus } from '../constants';

/**
 * Initialise exactly the given slots of one node's managed policy, only on the user's click.
 * A 409 (open critical drift on a slot) offers a "force" retry that raises an alert.
 */
export async function initWithForce(
  confirm: (o: ConfirmOptions) => Promise<boolean>, policyId: number, host: string, slots: number[], note: string,
): Promise<{ requests: number } | null> {
  try {
    return await initializeFimBaselineEntries(policyId, note, [host], slots);
  } catch (e) {
    if (errStatus(e) !== 409) throw e;
    const ok = await confirm({
      title: 'Force re-initialisation?',
      variant: 'danger',
      confirmLabel: 'Force initialise',
      description: `${errMsg(e, 'The server refused the initialisation.')} Forcing re-initialises slots that have open critical drift: that drift is superseded by the new baseline, and an alert is raised. Only continue if you have investigated the drift.`,
    });
    if (!ok) return null;
    return await initializeFimBaselineEntries(policyId, note, [host], slots, true);
  }
}

export const STALE_COVERAGE_TEXT = 'Coverage changed since you reviewed it; reload. The view was reloaded: review it again before publishing.';

const reviewedHash = (h: unknown, what: string): string => {
  if (typeof h !== 'string' || !h) throw new Error(`This view does not carry the ${what} of what you reviewed; reload it before publishing.`);
  return h;
};

/** Group publish body: states the group coverage's resolvedHash the user reviewed. */
export function groupPublishBody(groupId: string, reviewed: { resolvedHash?: string | null }, note: string, confirm: boolean): FimRegPublishBody {
  return { group: groupId, expectedGroupHash: reviewedHash(reviewed.resolvedHash, 'coverage hash'), note, confirm };
}

/**
 * Hosts publish body: a NON-EMPTY `expected[host]` (the resolvedHash the user reviewed for that
 * host) for EVERY host; throws (nothing is sent) when one is missing, since the server refuses
 * with 422 anyway.
 */
export function hostsPublishBody(reviewed: { host: string; resolvedHash?: string | null }[], note: string, confirm?: boolean): FimRegPublishBody {
  if (reviewed.length === 0) throw new Error('No hosts to publish.');
  const expected: Record<string, string> = {};
  const missing: string[] = [];
  for (const r of reviewed) {
    if (typeof r.resolvedHash === 'string' && r.resolvedHash) expected[r.host] = r.resolvedHash;
    else missing.push(r.host);
  }
  if (missing.length) throw new Error(`The reviewed coverage hash is missing for ${missing.length} host(s) (${missing.slice(0, 3).join(', ')}); reload before publishing.`);
  return { hosts: reviewed.map((r) => r.host), expected, note, ...(confirm !== undefined ? { confirm } : {}) };
}

/** Profile publish body: states the profile list item's digest the user reviewed. */
export function profilePublishBody(profile: { id: number; digest?: string | null }, note: string, confirm: boolean): FimRegProfilePublishBody {
  return { profile: profile.id, expectedProfileDigest: reviewedHash(profile.digest, 'profile digest'), note, confirm };
}

export type ReviewedPublishOutcome = { stale: true; message: string } | { stale: false; res: FimRegPublishResponse };

/**
 * Publish with a stale check: a 409 means the coverage changed since the user reviewed it (the
 * caller reloads and shows `message`); any other error is rethrown.
 */
export async function publishReviewed(body: FimRegPublishBody): Promise<ReviewedPublishOutcome> {
  try {
    return { stale: false, res: await publishFimReg(body) };
  } catch (e) {
    if (errStatus(e) !== 409) throw e;
    const detail = errMsg(e, '');
    return { stale: true, message: detail ? `${STALE_COVERAGE_TEXT} (${detail})` : STALE_COVERAGE_TEXT };
  }
}

export const PUBLISH_RUNNING_TEXT = 'A profile publish is already running; wait for it to finish (its progress is shown here when you started it).';

export type ProfilePublishOutcome =
  | { kind: 'started'; job: FimRegJob }
  | { kind: 'stale'; message: string }
  | { kind: 'running'; message: string };

/** Starts the background profile publish; maps the two 409s (stale digest / already running). */
export async function startProfilePublish(body: FimRegProfilePublishBody): Promise<ProfilePublishOutcome> {
  try {
    const r = await startFimRegProfilePublish(body);
    if (!r?.job || !Number.isInteger(Number(r.job.id))) throw new Error('The server did not return a publish job; treat the nodes as NOT published and reload.');
    return { kind: 'started', job: r.job };
  } catch (e) {
    if (errStatus(e) !== 409) throw e;
    const detail = errMsg(e, '');
    if (/already running/i.test(detail)) return { kind: 'running', message: `${PUBLISH_RUNNING_TEXT}${detail ? ` (${detail})` : ''}` };
    return { kind: 'stale', message: detail ? `${STALE_COVERAGE_TEXT} (${detail})` : STALE_COVERAGE_TEXT };
  }
}

/** A job is active only while queued or running; any other status (including unknown ones) ends it. */
export const isJobActive = (j: Pick<FimRegJob, 'status'>) => j.status === 'queued' || j.status === 'running';
export const isJobFinished = (j: Pick<FimRegJob, 'status'>) => !isJobActive(j);

/** "Publishing N/M, F failed" style progress line (plain text; render through safeText / RegText). */
export function jobProgressText(j: FimRegJob): string {
  const of = j.total > 0 ? `${j.done}/${j.total}` : `${j.done}`;
  const err = j.error ? `: ${j.error}` : '';
  switch (j.status) {
    case 'queued': return `Publish queued (${of}, ${j.failed} failed)`;
    case 'running': return `Publishing ${of}, ${j.failed} failed`;
    case 'done': return `Published ${of}, ${j.failed} failed`;
    case 'cancelled': return `Publish cancelled at ${of}, ${j.failed} failed${err}`;
    case 'aborted': return `Publish aborted at ${of}, ${j.failed} failed${err || ': stopped by the server'}`;
    case 'failed': return `Publish failed at ${of}, ${j.failed} failed${err}`;
    default: return `Publish ended with unknown status "${String(j.status)}" at ${of}, ${j.failed} failed${err}`;
  }
}

/** Hosts the job could not publish. */
export const jobFailedHosts = (j: FimRegJob) => (Array.isArray(j.results) ? j.results : []).filter((r) => !!r.error);
/** Hosts the job did publish (e.g. before it was aborted or cancelled). */
export const jobPublishedHosts = (j: FimRegJob) => (Array.isArray(j.results) ? j.results : []).filter((r) => !r.error);

export const JOB_POLL_MAX_FAILURES = 5;
export const JOB_POLL_MAX_DELAY_MS = 30000;

/** Polling gave up: a 4xx answer, or too many consecutive failures. */
export class JobPollError extends Error {
  readonly original?: unknown;
  constructor(message: string, original?: unknown) { super(message); this.name = 'JobPollError'; this.original = original; }
}

/**
 * Polls GET /registry/jobs/:id every `intervalMs` while the job is queued / running; returns the
 * job as soon as it has any other status (done / failed / cancelled / aborted / unknown) or null
 * when `signal` aborts. Any 4xx stops at once; network / 5xx errors are retried with exponential
 * backoff and polling stops after `maxFailures` consecutive failures (JobPollError, message
 * suitable for display after safeText).
 */
export async function pollRegistryJob(id: number, opts: {
  intervalMs?: number; maxFailures?: number; onUpdate?: (j: FimRegJob) => void; onError?: (e: unknown, attempt: number) => void; signal?: AbortSignal;
  sleep?: (ms: number) => Promise<void>; fetchJob?: (id: number) => Promise<FimRegJob>;
} = {}): Promise<FimRegJob | null> {
  const interval = opts.intervalMs ?? 2000;
  const maxFailures = opts.maxFailures ?? JOB_POLL_MAX_FAILURES;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const fetchJob = opts.fetchJob ?? getFimRegJob;
  let failures = 0;
  for (;;) {
    if (opts.signal?.aborted) return null;
    let delay = interval;
    try {
      const j = await fetchJob(id);
      if (opts.signal?.aborted) return null;
      failures = 0;
      opts.onUpdate?.(j);
      if (!j || typeof j !== 'object' || isJobFinished(j)) return j ?? null;
    } catch (e) {
      const st = errStatus(e);
      if (st !== undefined && st >= 400 && st < 500) {
        throw new JobPollError(`Progress of job #${id} cannot be read (HTTP ${st}): ${errMsg(e, 'request refused')}`, e);
      }
      failures += 1;
      if (failures >= maxFailures) {
        throw new JobPollError(`Progress of job #${id} could not be read after ${failures} attempts (${errMsg(e, 'network error')}). The publish may still be running on the server: reload later to check.`, e);
      }
      opts.onError?.(e, failures);
      delay = Math.min(interval * 2 ** failures, JOB_POLL_MAX_DELAY_MS);
    }
    await sleep(delay);
  }
}

/** sessionStorage key: the profile publish job started from this browser tab (resumed on remount). */
export const PROFILE_JOB_KEY = 'fim.reg.profilePublishJob';

export function rememberProfileJob(id: number | null) {
  try {
    if (id === null) sessionStorage.removeItem(PROFILE_JOB_KEY);
    else sessionStorage.setItem(PROFILE_JOB_KEY, String(id));
  } catch { /* storage unavailable: progress is simply not resumed after a remount */ }
}

export function rememberedProfileJob(): number | null {
  try {
    const n = Number(sessionStorage.getItem(PROFILE_JOB_KEY));
    return Number.isInteger(n) && n > 0 ? n : null;
  } catch { return null; }
}
