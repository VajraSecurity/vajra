import { Request, Response, NextFunction } from 'express';
import { spawn, ChildProcess } from 'child_process';
import { readFileSync, existsSync, mkdirSync, unlinkSync, promises as fsp } from 'fs';
import path from 'path';
import { IsNull } from 'typeorm';
import type { DataSource } from 'typeorm';
import type { NetworkScanHistory as NetworkScanHistoryEntity } from '../../orm/entities/fleet/NetworkScanHistory';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { NODE_STATUS_ONLINE_THRESHOLD_SECONDS } from '../../consts/database';
import {
  SCAN_OUTPUT_DIR_DEFAULT,
  MAX_CONCURRENT_NETWORK_SCANS,
  SCAN_RECOVERY_POLL_INTERVAL_MS,
  SCAN_PROGRESS_DB_FLUSH_INTERVAL_MS,
} from '../../consts/scanning';
import { isValidAndAllowedIP, isValidScheduleCidr, parseAndValidateTargets } from './targetValidation';
import { getLogger } from '../../utils/logger';
import { isPgUndefinedTableError } from '../../utils/dbErrors';

const logger = getLogger('network.nmap');

export { isValidAndAllowedIP, isValidScheduleCidr };

const activeScans = new Map<number, ChildProcess>();
const MAX_CONCURRENT_SCANS = MAX_CONCURRENT_NETWORK_SCANS;

// Synchronous slot reservation to close the TOCTOU window between checking
// `activeScans.size` and the real entry being added (which only happens
// after several awaits). Reservation keys are negative so they never collide
// with real (positive, bigserial) history IDs. Caller must eventually either
// hand the slot off (delete the reservation once the real historyId entry is
// set) or release it (delete on any failure path) — see launchNmapScan.
let reservationCounter = 0;
function reserveScanSlot(): number {
  reservationCounter -= 1;
  const key = reservationCounter;
  activeScans.set(key, null as unknown as ChildProcess);
  return key;
}

// Scan Output Directory
function getScanDir(): string {
  const dir = process.env.VAJRA_SCAN_DIR || path.join(process.cwd(), SCAN_OUTPUT_DIR_DEFAULT);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

function nmapOutPath(historyId: number): string {
  return path.join(getScanDir(), `nmap-${historyId}.txt`);
}

function cleanupScanFile(historyId: number): void {
  try { unlinkSync(nmapOutPath(historyId)); } catch (err: any) {
    if (err?.code !== 'ENOENT') {
      logger.warn({ err, historyId }, 'Failed to remove nmap scan output file during cleanup');
    }
  }
}

// Target Validation
// Real validation logic lives in ./targetValidation (shared with nucleiController
// and the Scan Scheduler) — literal private IPs and CIDR blocks only, no
// hostnames, with CIDR checked by actual expanded network range rather than
// the literal octets typed.

// Scan Flags
const VALID_SCAN_TYPES = ['discovery', 'quick', 'full', 'os', 'advanced'] as const;
type ScanType = (typeof VALID_SCAN_TYPES)[number];

function getScanFlags(scanType: ScanType): string[] {
  switch (scanType) {
    case 'discovery': return ['-sn', '-n', '-T4', '--max-retries', '1', '--host-timeout', '2s', '--min-parallelism', '50', '-v', '--open', '--send-ip'];
    case 'quick':     return ['-F', '-T4', '--max-retries', '1', '--host-timeout', '2s', '--min-parallelism', '50', '-v', '--open', '--send-ip'];
    case 'full':      return ['-p-', '-T5', '--max-retries', '2', '--max-rate', '300', '--send-ip'];
    case 'os':        return ['-A', '-T4', '--max-retries', '2', '--max-rate', '300', '--send-ip'];
    case 'advanced':  return ['-sT', '-A', '--script', 'default and not vulners', '-sV', '-T4', '-v', '--max-rate', '300', '--open', '--send-ip'];
  }
}

// Process Helpers
function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function isNmapProcess(pid: number): boolean {
  try {
    const cmdline = readFileSync(`/proc/${pid}/cmdline`, 'utf-8');
    return cmdline.includes('nmap');
  } catch {
    return false;
  }
}

const DEFAULT_NMAP_PATH = '/usr/bin/nmap';

/**
 * Absolute, existence-checked path — not the bare `nmap` token. `sudo` is
 * invoked with this exact path so it matches the documented sudoers rule
 * (`NOPASSWD: /usr/bin/nmap`) rather than resolving `nmap` via PATH/secure_path.
 */
function getNmapBinaryPath(): string {
  const configured = process.env.NMAP_BINARY_PATH;
  if (configured && existsSync(configured)) return configured;
  return DEFAULT_NMAP_PATH;
}

// Returns whether a SIGTERM was actually sent — callers that expected a live
// process (e.g. cancelScan) use this to tell a real kill apart from a silent
// no-op (pid already dead / reused by an unrelated process), which otherwise
// look identical from the caller's side.
function killScanProcess(pid: number): boolean {
  try {
    if (isNmapProcess(pid)) {
      // Negative PID → signal the whole process group. The tracked pid is
      // `sudo`'s (spawn was called with detached:true, making it its own
      // group leader), so signaling only the positive pid leaves the actual
      // nmap process sudo forked untouched if sudo doesn't forward signals.
      process.kill(-pid, 'SIGTERM');
      return true;
    }
    return false;
  } catch (err) {
    logger.warn({ err, pid }, 'Failed to send SIGTERM to nmap process group');
    return false;
  }
}

// Startup Recovery
const recoveryPollers = new Map<number, ReturnType<typeof setInterval>>();

function startRecoveryPoller(scanId: number, pid: number): void {
  if (recoveryPollers.has(scanId)) return;

  const interval = setInterval(async () => {
    // Use isNmapProcess instead of isProcessAlive to handle PID reuse —
    // if the PID was reused by an unrelated process, this correctly
    // detects that nmap is no longer running.
    if (isProcessAlive(pid) && isNmapProcess(pid)) return;

    clearInterval(interval);
    recoveryPollers.delete(scanId);

    try {
      const { dbSourceConnection } = await import('../../index');
      const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
      const ds = dbSourceConnection();
      if (!ds || ds.length < 2 || !ds[1].isInitialized) {
        logger.warn({ scanId }, 'Fleet database not available while finalizing recovered nmap scan, scan will remain stuck until next restart');
        return;
      }

      const repo = ds[1].getRepository(NetworkScanHistory);
      const scan = await repo.findOne({ where: { id: scanId } });
      if (!scan) {
        logger.warn({ scanId }, 'Nmap scan row not found while finalizing recovered scan');
        return;
      }
      if (scan.status === 'CANCELLED') {
        logger.info({ scanId }, 'Nmap scan already cancelled, skipping recovery finalization');
        return;
      }

      const outFile = nmapOutPath(scanId);
      if (existsSync(outFile)) {
        const fileOutput = await fsp.readFile(outFile, 'utf-8');
        const completed = fileOutput.includes('Nmap done');
        scan.status = completed ? 'COMPLETED' : 'FAILED';
        scan.progress = completed ? 100 : scan.progress;
        scan.output = fileOutput;
      } else {
        scan.status = 'FAILED';
        scan.output = (scan.output || '') + '\n\n[System] Scan process ended but output file not found.';
      }
      scan.pid = null;
      await repo.save(scan);
      cleanupScanFile(scanId);

      if (scan.status === 'COMPLETED') {
        logger.info({ scanId, status: scan.status }, 'Resumed nmap scan finalized after process exit');
      } else {
        logger.warn({ scanId, status: scan.status }, 'Resumed nmap scan finalized as FAILED after process exit');
      }
    } catch (err) {
      logger.error({ err, scanId }, 'Failed to finalize recovered nmap scan');
    }

  }, SCAN_RECOVERY_POLL_INTERVAL_MS);

  recoveryPollers.set(scanId, interval);
}

export async function cleanupOrphanedScans(): Promise<void> {
  try {
    const { dbSourceConnection } = await import('../../index');
    const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
    const ds = dbSourceConnection();

    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn('Fleet database not available, skipping orphaned nmap scan cleanup');
      return;
    }

    const repo = ds[1].getRepository(NetworkScanHistory);
    const orphaned = await repo.find({
      where: [{ status: 'RUNNING' }, { status: 'PENDING' }],
    });

    for (const scan of orphaned) {
      const scanId = Number(scan.id);

      if (scan.pid && isProcessAlive(scan.pid)) {
        // Scan is still running — resume tracking via polling
        startRecoveryPoller(scanId, scan.pid);
        logger.info({ scanId, pid: scan.pid }, 'Resumed tracking nmap scan after restart');
        continue;
      }

      // Process is dead — try to recover from output file
      const outFile = nmapOutPath(scanId);
      if (existsSync(outFile)) {
        try {
          const fileOutput = await fsp.readFile(outFile, 'utf-8');
          const completed = fileOutput.includes('Nmap done');
          scan.status = completed ? 'COMPLETED' : 'FAILED';
          scan.progress = completed ? 100 : scan.progress;
          scan.output = fileOutput;
          logger.info({ scanId, status: scan.status }, 'Recovered nmap scan from output file');
        } catch (err) {
          logger.warn({ err, scanId }, 'Failed to read nmap output file during orphaned scan recovery, marking scan failed');
          scan.status = 'FAILED';
        }
        cleanupScanFile(scanId);
      } else {
        if (scan.pid) killScanProcess(scan.pid);
        scan.status = 'FAILED';
        scan.output = (scan.output || '') + '\n\n[System] Scan was interrupted by server restart.';
        logger.warn({ scanId }, 'Orphaned nmap scan has no output file, marking failed');
      }
      scan.pid = null;
      await repo.save(scan);
    }

    const deadCount = orphaned.filter(s => s.status !== 'RUNNING' && s.status !== 'PENDING').length;
    if (deadCount > 0) {
      logger.info({ deadCount }, 'Finalized orphaned nmap scans');
    }
    // Always log a summary, even when nothing was found — otherwise a clean
    // restart (the common case) leaves zero trace that this startup check
    // ran at all, indistinguishable from it never having been invoked.
    logger.debug({ found: orphaned.length, resumedTracking: orphaned.length - deadCount, finalized: deadCount }, 'Orphaned nmap scan cleanup completed');
  } catch (err) {
    logger.error({ err }, 'Failed to cleanup orphaned scans');
  }
}

// Programmatic Scan Launch (shared by the HTTP handler and ScanSchedulerService)
export class ScanLaunchError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ScanLaunchError';
    this.status = status;
  }
}

export interface LaunchNmapScanOptions {
  target: string;
  scanType?: string;
  reason: string;
  createdByUserId?: number | null;
  createdByName?: string | null;
  createdByEmail?: string | null;
  parentId?: number | null;
  scheduleId?: number | null;
  clientIp?: string | null;
}

/**
 * Validates + persists a PENDING network_scan_history row and kicks off the
 * detached nmap process in the background, returning as soon as the row
 * exists (does not wait for the scan itself). Used directly by `runNmapScan`
 * (HTTP) and by ScanSchedulerService (cron-driven, no Express request).
 */
export async function launchNmapScan(opts: LaunchNmapScanOptions): Promise<{ historyId: number; resolvedTarget: string; resolvedScanType: ScanType }> {
  const { target, reason } = opts;
  const createdByUserId = opts.createdByUserId ?? null;
  const createdByName = opts.createdByName ?? null;
  const createdByEmail = opts.createdByEmail ?? null;
  let parentId: number | null = opts.parentId ?? null;
  if (parentId !== null) {
    const coerced = Number(parentId);
    if (!Number.isInteger(coerced)) {
      throw new ScanLaunchError(400, 'parentId must be an integer');
    }
    parentId = coerced;
  }
  const scheduleId = opts.scheduleId ?? null;
  // ip_address is a Postgres `inet` column — only ever a real IP or null,
  // never a sentinel string (that fails with "invalid input syntax for type inet").
  const clientIp = opts.clientIp ?? null;

  if (!target || typeof target !== 'string') {
    throw new ScanLaunchError(400, 'Target is required and must be a string');
  }
  if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
    throw new ScanLaunchError(400, 'Reason is required for scanning');
  }

  const validatedTargets = parseAndValidateTargets(target);
  if (!validatedTargets) {
    throw new ScanLaunchError(400,
      'Invalid target. Only private network IPs/CIDRs (10.x, 172.16-31.x, 192.168.x, 100.64-127.x) are allowed ' +
      '— hostnames are not accepted, and CIDR blocks must stay within a single allowed range.');
  }

  const resolvedScanType: ScanType = (VALID_SCAN_TYPES as readonly string[]).includes(opts.scanType as string)
    ? (opts.scanType as ScanType)
    : 'quick';

  const flagArgs = getScanFlags(resolvedScanType);
  const fullArgs = [...flagArgs, '--stats-every', '3s', '--', ...validatedTargets];
  const commandForAudit = `nmap ${fullArgs.join(' ')}`;

  // Check-then-reserve, synchronously (no await between them), so a burst of
  // concurrent requests can't all observe room under the cap before any of
  // them registers — see reserveScanSlot().
  if (activeScans.size >= MAX_CONCURRENT_SCANS) {
    throw new ScanLaunchError(429, `A maximum of ${MAX_CONCURRENT_SCANS} concurrent scans are allowed. Please wait for some to finish.`);
  }
  const reservationKey = reserveScanSlot();
  let reservationHandedOff = false;

  try {
    const { dbSourceConnection } = await import('../../index');
    const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
    const ds = dbSourceConnection();

    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      throw new ScanLaunchError(503, 'Fleet database not available');
    }

    const repo = ds[1].getRepository(NetworkScanHistory);

    // Only one main discovery scan (parent_id IS NULL) may be RUNNING/PENDING
    // at a time — this matches the UI's single "Run Scan" button/disabled-state
    // assumption. Per-host advanced scans (parent_id set) are NOT subject to
    // this check; they're expected to run in parallel across many hosts.
    if (parentId === null) {
      const existingMainScan = await repo.findOne({
        where: [
          { parent_id: IsNull(), status: 'RUNNING' },
          { parent_id: IsNull(), status: 'PENDING' },
        ],
      });
      if (existingMainScan) {
        throw new ScanLaunchError(409,
          'A network scan is already running. Wait for it to finish or cancel it before starting another.');
      }
    } else {
      // parentId (an advanced-scan "sessionId") comes straight from the
      // request body — confirm it actually references a real scan before
      // linking this one to it, instead of trusting an arbitrary integer.
      const parentExists = await repo.exist({ where: { id: parentId as any } });
      if (!parentExists) {
        throw new ScanLaunchError(400, `parentId ${parentId} does not reference an existing scan`);
      }
    }

    const historyEntry = repo.create({
      target: validatedTargets.join(' '),
      scanType: resolvedScanType,
      reason: reason.trim(),
      command: commandForAudit,
      output: '',
      status: 'PENDING',
      progress: 0,
      pid: null,
      created_by_user_id: createdByUserId,
      created_by_name: createdByName,
      parent_id: parentId,
      schedule_id: scheduleId,
    });

    const saved = await repo.save(historyEntry);
    const historyId = Number(saved.id);

    // Log for scheduler-triggered scans too (scheduleId set, no logged-in user) —
    // these are automated, potentially intrusive (-A/--script) scans against live
    // hosts and still need an audit trail entry, just under a synthetic identity.
    if (createdByUserId || scheduleId) {
      logAuditTrail({
        action: 'NETWORK_SCAN',
        status: 'success',
        userId: createdByUserId,
        email: createdByEmail ?? 'scan-scheduler@system',
        ipAddress: clientIp,
        userAgent: null,
        details: { event: 'SCAN_STARTED', target: validatedTargets.join(' '), scanType: resolvedScanType, reason: reason.trim(), historyId, sessionId: parentId, scheduleId },
      }).catch(err => logger.error({ err, historyId }, 'Failed to log scan initiation audit'));
    }

    const jwtPayloadLike = (createdByUserId || scheduleId)
      ? { id: createdByUserId, email: createdByEmail ?? 'scan-scheduler@system' }
      : undefined;

    // Hand the reserved slot off to the real historyId now — runScanBackground
    // will set activeScans.set(historyId, child) itself once the process spawns.
    reservationHandedOff = true;
    activeScans.delete(reservationKey);

    runScanBackground(historyId, fullArgs, validatedTargets.join(' '), resolvedScanType, reason.trim(), jwtPayloadLike, clientIp, parentId)
      .catch(err => {
        logger.error({ err, historyId }, 'Nmap background scan failed to start');
        activeScans.delete(historyId);
        repo.update(historyId, { status: 'FAILED', output: `[System] Failed to launch scan process: ${err.message}`, pid: null })
          .catch(updateErr => logger.error({ err: updateErr, historyId }, 'Failed to mark nmap scan FAILED after background launch failure, scan will be stuck as PENDING'));
      });

    return { historyId, resolvedTarget: validatedTargets.join(' '), resolvedScanType };
  } finally {
    if (!reservationHandedOff) activeScans.delete(reservationKey);
  }
}

/**
 * Polls network_scan_history until the row reaches a terminal status.
 * Used by ScanSchedulerService, which has no HTTP round-trip to piggyback
 * progress polling on the way the frontend does via getScanStatus.
 */
export async function awaitScanCompletion(historyId: number, timeoutMs = 15 * 60 * 1000): Promise<NetworkScanHistoryEntity> {
  const { dbSourceConnection } = await import('../../index');
  const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
  const ds = dbSourceConnection()!;
  const repo = ds[1].getRepository(NetworkScanHistory);

  const start = Date.now();
  const TERMINAL_STATUSES = new Set(['COMPLETED', 'FAILED', 'CANCELLED']);
  while (Date.now() - start < timeoutMs) {
    const scan = await repo.findOne({ where: { id: historyId } });
    if (!scan) throw new Error(`Scan #${historyId} not found`);
    if (TERMINAL_STATUSES.has(scan.status)) return scan as unknown as NetworkScanHistoryEntity;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw new Error(`Scan #${historyId} timed out after ${timeoutMs}ms waiting for completion`);
}

// Route Handlers
export const runNmapScan = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { target, scanType, reason, sessionId } = req.body;
    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    const clientIp = req.ip || req.socket?.remoteAddress || null;

    const { historyId, resolvedTarget, resolvedScanType } = await launchNmapScan({
      target,
      scanType,
      reason,
      createdByUserId: jwtPayload?.id ?? null,
      createdByName: jwtPayload?.name ?? null,
      createdByEmail: jwtPayload?.email ?? null,
      parentId: sessionId || null,
      clientIp,
    });

    // Log the resolved target/scanType actually launched (post-canonicalization,
    // post-fallback-to-default), not the raw request values — an invalid or
    // differently-formatted input silently falls back inside launchNmapScan, and
    // logging the raw input here would misrepresent which scan actually ran.
    logger.info({ historyId, target: resolvedTarget, scanType: resolvedScanType }, 'Nmap scan started');
    res.status(202).json({
      success: true,
      data: { historyId, message: 'Scan started asynchronously' },
    });
  } catch (error) {
    if (error instanceof ScanLaunchError) {
      if (error.status === 429 || error.status === 503 || error.status === 409) {
        logger.warn({ status: error.status, target: req.body?.target }, error.message);
        return res.status(error.status).json({ success: false, message: error.message });
      }
      logger.debug({ status: error.status, target: req.body?.target }, error.message);
      return next(new CustomError(error.status, 'Validation', error.message));
    }
    logger.error({ err: error, target: req.body?.target }, 'Unexpected error while starting nmap scan');
    next(new CustomError(500, 'Raw', 'An unexpected error occurred during the scan', null, error));
  }
};

// Background Scan
const runScanBackground = async (
  historyId: number,
  nmapArgs: string[],
  target: string,
  scanType: string,
  reason: string,
  jwtPayload: any,
  clientIp: string | null,
  parentId: number | null
) => {
  const { dbSourceConnection } = await import('../../index');
  const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
  const ds = dbSourceConnection()!;
  const repo = ds[1].getRepository(NetworkScanHistory);

  let fullOutput = '';

  // -oN writes results to file so they survive a server restart
  const outFile = nmapOutPath(historyId);
  const argsWithFile = ['-oN', outFile, ...nmapArgs];

  // detached: true → nmap survives if Node restarts (own process group)
  // stdio: 'pipe' (default) → stdout stays connected for live progress
  // No unref() → pipes stay open so we receive data events
  // On SIGTERM, we destroy pipes so Node can exit; nmap continues via -oN file
  const child = spawn('sudo', [getNmapBinaryPath(), ...argsWithFile], { detached: true });
  activeScans.set(historyId, child);

  const cleanupOnShutdown = () => {
    child.stdout?.destroy();
    child.stderr?.destroy();
    child.unref();
  };
  process.once('SIGTERM', cleanupOnShutdown);
  process.once('SIGINT', cleanupOnShutdown);
  child.on('close', () => {
    process.removeListener('SIGTERM', cleanupOnShutdown);
    process.removeListener('SIGINT', cleanupOnShutdown);
  });

  const childPid = child.pid ?? null;
  await repo.update(historyId, { status: 'RUNNING', pid: childPid });

  const calculateTotalHosts = (targetStr: string) => {
    let total = 0;
    for (const p of targetStr.split(/\s+/)) {
      const match = p.match(/\/(\d+)$/);
      if (match) {
        const bits = parseInt(match[1]);
        if (bits >= 0 && bits <= 32) total += Math.pow(2, 32 - bits);
      } else if (p.trim()) {
        total += 1;
      }
    }
    return total > 0 ? total : 1;
  };

  const totalHosts = calculateTotalHosts(target);
  let maxProgress = 0;
  let lastDbUpdate = 0;

  let completedHosts = 0;
  let currentChunkHosts = 0;
  let chunkProgress = 0;

  child.stdout.on('data', async (data) => {
    const chunk = data.toString();
    fullOutput += chunk;

    const chunkStartedMatch = chunk.match(/Scanning (\d+) hosts/);
    if (chunkStartedMatch && chunkStartedMatch[1]) {
      currentChunkHosts = parseInt(chunkStartedMatch[1], 10);
      chunkProgress = 0;
    }

    const chunkCompletedMatch = chunk.match(/elapsed \((\d+) total hosts\)/);
    if (chunkCompletedMatch && chunkCompletedMatch[1]) {
      completedHosts += parseInt(chunkCompletedMatch[1], 10);
      currentChunkHosts = 0;
      chunkProgress = 0;
    }

    const progressMatch = chunk.match(/About ([\d.]+)% done/);
    if (progressMatch && progressMatch[1]) {
      chunkProgress = parseFloat(progressMatch[1]);
    }

    let currentProgress = maxProgress;

    if (totalHosts > 0) {
      let overallProgress: number;
      const hostsMatch = chunk.match(/(\d+) hosts completed/);
      
      if (hostsMatch) {
        const completed = parseInt(hostsMatch[1], 10);
        overallProgress = (completed / totalHosts) * 100;
        if (overallProgress === 0 && chunkProgress > 0) {
          overallProgress = chunkProgress;
        }
      } else if (currentChunkHosts > 0 || completedHosts > 0) {
        overallProgress = ((completedHosts + (currentChunkHosts * (chunkProgress / 100))) / totalHosts) * 100;
      } else {
        overallProgress = chunkProgress;
      }
      
      currentProgress = Math.floor(overallProgress);
    }

    if (currentProgress > maxProgress && currentProgress <= 100) {
      maxProgress = currentProgress;
    }

    const now = Date.now();
    if (now - lastDbUpdate >= SCAN_PROGRESS_DB_FLUSH_INTERVAL_MS) {
      lastDbUpdate = now;
      await repo.update(historyId, { progress: maxProgress, output: fullOutput })
        .catch((err) => logger.error({ err, historyId }, 'Failed to update nmap scan progress'));
    }
  });

  child.stderr.on('data', async (data) => {
    const chunk = data.toString();
    fullOutput += chunk;

    let currentProgress = maxProgress;
    const progressMatch = chunk.match(/About ([\d.]+)% done/);
    if (progressMatch && progressMatch[1]) {
      currentProgress = Math.floor(parseFloat(progressMatch[1]));
    }
    
    if (currentProgress > maxProgress && currentProgress <= 100) {
      maxProgress = currentProgress;
    }

    const now = Date.now();
    if (now - lastDbUpdate >= SCAN_PROGRESS_DB_FLUSH_INTERVAL_MS) {
      lastDbUpdate = now;
      await repo.update(historyId, { progress: maxProgress, output: fullOutput })
        .catch((err) => logger.error({ err, historyId }, 'Failed to update nmap scan progress'));
    }
  });

  child.on('error', async (error) => {
    // try/catch (not just .catch on individual calls) so a thrown DB error
    // can't skip activeScans.delete() below and leak this slot forever.
    logger.error({ err: error, historyId }, 'Nmap process failed to start or crashed');
    try {
      fullOutput += `\n[Process Error] Failed to start nmap: ${error.message}`;
      await repo.update(historyId, { status: 'FAILED', output: fullOutput, pid: null });
      cleanupScanFile(historyId);
    } catch (err) {
      logger.error({ err, historyId }, 'Failed to finalize errored nmap scan');
    } finally {
      activeScans.delete(historyId);
    }
  });

  child.on('close', async (code) => {
    try {
      const current = await repo.findOne({ where: { id: historyId } });
      if (current && current.status === 'CANCELLED') {
        cleanupScanFile(historyId);
        logger.info({ historyId, exitCode: code }, 'Nmap process exited after scan was already cancelled, leaving status as CANCELLED');
        return;
      }

      const status = code === 0 ? 'COMPLETED' : 'FAILED';
      await repo.update(historyId, {
        status,
        progress: status === 'COMPLETED' ? 100 : current?.progress || 0,
        output: fullOutput,
        pid: null,
      });

      if (parentId && status === 'COMPLETED') {
        // Atomic SQL append (not findOne+save) — multiple advanced scans from the
        // same scheduler tick can complete concurrently against the same parent;
        // a read-modify-write here would lose whichever update saved last.
        await ds[1].query(
          `UPDATE network_scan_history SET output = output || $1 WHERE id = $2`,
          [`\n\n===== Advanced Scan (${target}) =====\n\n${fullOutput}`, parentId],
        ).catch((err) => logger.error({ err, parentId }, 'Failed to append advanced scan output to parent'));
      }

      cleanupScanFile(historyId);

      if (status === 'COMPLETED') {
        logger.info({ historyId, status, exitCode: code, parentId }, 'Nmap scan process exited');
      } else {
        logger.warn({ historyId, status, exitCode: code, parentId }, 'Nmap scan process exited with a non-zero exit code, marked FAILED');
      }

      if (jwtPayload) {
        logAuditTrail({
          action: 'NETWORK_SCAN',
          status: code === 0 ? 'success' : 'failure',
          userId: jwtPayload.id ?? null,
          email: jwtPayload.email ?? null,
          ipAddress: clientIp,
          userAgent: null,
          details: { event: 'SCAN_COMPLETED', target, scanType, reason, historyId, exitCode: code },
        }).catch(err => logger.error({ err, historyId }, 'Failed to log scan completion audit'));
      }
    } catch (err) {
      logger.error({ err, historyId }, 'Failed to finalize completed nmap scan');
    } finally {
      activeScans.delete(historyId);
    }
  });
};

// Known/Unmanaged IP Diffing
/**
 * Parses `Nmap scan report for (IP)` lines out of raw nmap output and splits
 * them into three buckets against the `nodes`/`interface_addresses` tables:
 * - `knownIps`: address belongs to an enrolled Vajra agent AND that agent is
 *   currently online — safe to trust.
 * - `staleManagedIps`: address belongs to an enrolled Vajra agent, but that
 *   agent is NOT currently online. This is the IP-reuse case — the registered
 *   device could be powered off and DHCP may have handed its IP to a
 *   different, unmanaged machine — so it's treated like an unknown host
 *   rather than silently trusted.
 * - `unknownIps`: no matching row at all ("unmanaged").
 * Shared by `getScanStatus` (ad-hoc scan drill-down) and ScanSchedulerService
 * (deciding which discovered IPs deserve an automatic advanced scan + alert).
 */
export async function getUnmanagedIps(
  outputText: string,
  ds: DataSource,
): Promise<{ knownIps: string[]; unknownIps: string[]; staleManagedIps: string[]; dbIps: Set<string> }> {
  const scanIps = new Set<string>();
  for (const line of outputText.split('\n')) {
    const match = line.match(/Nmap scan report for (?:[^\s(]+\s+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?/);
    if (match && match[1]) scanIps.add(match[1]);
  }

  // is_online mirrors the Online/Offline convention used elsewhere (e.g.
  // node_details.ts) via last_seen recency, OR'd with agent_online (the
  // WebSocket-connection-derived flag) since last_seen is written by an
  // external osquery/Fleet pipeline whose check-in cadence isn't guaranteed
  // to fall inside the threshold on every tick.
  const nodesResult = await ds.query(`
    SELECT address, bool_or(is_online) AS is_online FROM (
      SELECT n.address AS address,
        (n.agent_online = true OR (n.last_seen IS NOT NULL
          AND (EXTRACT(EPOCH FROM NOW()) - CAST(n.last_seen AS INTEGER)) < $1)) AS is_online
      FROM nodes n
      WHERE n.address IS NOT NULL AND n.address != ''

      UNION ALL

      SELECT ia.address AS address,
        (n.agent_online = true OR (n.last_seen IS NOT NULL
          AND (EXTRACT(EPOCH FROM NOW()) - CAST(n.last_seen AS INTEGER)) < $1)) AS is_online
      FROM interface_addresses ia
      JOIN nodes n ON n.host_identifier = ia.host_identifier
      WHERE ia.address IS NOT NULL AND ia.address != ''
      AND ia.id > (SELECT COALESCE(MAX(id), 0) - 5000000 FROM interface_addresses)
    ) combined
    GROUP BY address
  `, [NODE_STATUS_ONLINE_THRESHOLD_SECONDS]);

  const dbIps = new Set<string>(nodesResult.map((r: any) => r.address));
  const onlineIps = new Set<string>(nodesResult.filter((r: any) => r.is_online === true).map((r: any) => r.address));

  const knownIps: string[] = [];
  const staleManagedIps: string[] = [];
  const unknownIps: string[] = [];
  for (const ip of scanIps) {
    if (!dbIps.has(ip)) unknownIps.push(ip);
    else if (onlineIps.has(ip)) knownIps.push(ip);
    else staleManagedIps.push(ip);
  }

  return { knownIps, unknownIps, staleManagedIps, dbIps };
}

// Status / History / Cancel
export const getScanStatus = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const historyId = parseInt(req.params.id as string, 10);
    if (isNaN(historyId)) {
      return next(new CustomError(400, 'Validation', 'Invalid scan ID'));
    }

    const { dbSourceConnection } = await import('../../index');
    const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
    const ds = dbSourceConnection();

    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({ historyId }, 'Fleet database not available while fetching scan status');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NetworkScanHistory);
    const scan = await repo.findOne({ where: { id: historyId } });

    if (!scan) {
      return next(new CustomError(404, 'Validation', 'Scan not found'));
    }

    const child = activeScans.get(Number(scan.id));
    if ((scan.status === 'RUNNING' || scan.status === 'PENDING') && !child && (!scan.pid || !isProcessAlive(scan.pid))) {
      const outFile = nmapOutPath(historyId);
      if (existsSync(outFile)) {
        // fs.promises, not readFileSync: this runs on GET /network/scan/:id,
        // which the scan view polls every 3s. A -A / full-port scan of a /20
        // leaves a multi-MB .txt here, and reading it synchronously stalled the
        // whole process (every other HTTP request plus the WebSocket fan-out —
        // it is one Node process) for the duration of that read, on every tick.
        try { scan.output = await fsp.readFile(outFile, 'utf-8'); } catch (err) {
          logger.warn({ err, historyId }, 'Failed to read nmap output file while checking scan status');
        }
      } else {
        scan.status = 'FAILED';
        scan.output = (scan.output || '') + '\n\n[System] Scan was interrupted unexpectedly (e.g., server restart).';
        scan.pid = null;
        await repo.save(scan);
        logger.warn({ historyId }, 'Nmap scan found interrupted (process dead, no output file) during status check');
      }
    }

    let knownIps: string[] = [];
    let unknownIps: string[] = [];
    let staleManagedIps: string[] = [];
    let newIps: string[] = [];
    let disappearedIps: string[] = [];

    if (scan.status === 'COMPLETED' && scan.output) {
      const unmanaged = await getUnmanagedIps(scan.output, ds[1]);
      knownIps = unmanaged.knownIps;
      unknownIps = unmanaged.unknownIps;
      staleManagedIps = unmanaged.staleManagedIps;
      const dbIps = unmanaged.dbIps;

      const scanIps = new Set<string>([...knownIps, ...unknownIps, ...staleManagedIps]);

      const prevScans = await repo.find({
        where: { target: scan.target, status: 'COMPLETED' },
        order: { created_at: 'DESC' },
        take: 2
      });
      const prevScan = prevScans.find((s: any) => s.id !== scan.id);

      if (prevScan && prevScan.output) {
        const prevScanIps = new Set<string>();
        for (const line of prevScan.output.split('\n')) {
          const match = line.match(/Nmap scan report for (?:[^\s(]+\s+\()?(\d{1,3}(?:\.\d{1,3}){3})\)?/);
          if (match && match[1]) prevScanIps.add(match[1]);
        }

        const prevScanIpsArr = Array.from(prevScanIps);
        const scanIpsArr = Array.from(scanIps);

        // Use the Sets' O(1) .has() instead of Array.includes() (O(n) per
        // call) — a near-full CIDR scan can carry up to MAX_EXPANDED_HOSTS
        // (4096) addresses, so the naive .includes() version was O(n*m)
        // here, run on every scan-status poll (every 3s while a scan runs).
        newIps = scanIpsArr.filter(ip => !prevScanIps.has(ip));
        disappearedIps = prevScanIpsArr.filter(ip => !scanIps.has(ip));

        const knownIpsSet = new Set(knownIps);
        for (const ip of disappearedIps) {
          if (dbIps.has(ip) && !knownIpsSet.has(ip)) {
            knownIps.push(ip);
            knownIpsSet.add(ip);
          }
        }
      }
    }

    logger.debug({ historyId, status: scan.status }, 'Scan status retrieved');
    return res.status(200).json({
      success: true,
      data: { id: scan.id, status: scan.status, progress: scan.progress, output: scan.output, knownIps, unknownIps, staleManagedIps, newIps, disappearedIps },
    });
  } catch (error) {
    logger.error({ err: error, historyId: req.params.id }, 'Failed to fetch nmap scan status');
    return next(new CustomError(500, 'Raw', 'Failed to fetch scan status', null, error));
  }
};

export const cancelScan = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const historyId = parseInt(req.params.id as string, 10);
    if (isNaN(historyId)) {
      return next(new CustomError(400, 'Validation', 'Invalid scan ID'));
    }

    const { dbSourceConnection } = await import('../../index');
    const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
    const ds = dbSourceConnection();

    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({ historyId }, 'Fleet database not available while cancelling scan');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NetworkScanHistory);
    const scan = await repo.findOne({ where: { id: historyId } });

    if (!scan) {
      return next(new CustomError(404, 'Validation', 'Scan not found'));
    }

    const wasCancellable = scan.status === 'RUNNING' || scan.status === 'PENDING';
    if (scan.status === 'RUNNING' || scan.status === 'PENDING') {
      const child = activeScans.get(historyId);
      if (child && child.pid) {
        // Negative pid → whole process group (see killScanProcess for why).
        try { process.kill(-child.pid, 'SIGTERM'); } catch (err) {
          logger.warn({ err, historyId, pid: child.pid }, 'Failed to send SIGTERM to tracked nmap process group during cancel');
        }
        activeScans.delete(historyId);
      } else if (scan.pid) {
        const signaled = killScanProcess(scan.pid);
        if (!signaled) {
          logger.warn({ historyId, pid: scan.pid }, 'Cancel request found no live nmap process for tracked pid, only the DB status will change');
        }
      } else {
        logger.warn({ historyId, status: scan.status }, 'Cancelling scan with no tracked process or pid, only the DB status will change');
      }

      // Conditional update, not a blind findOne+save: if the scan actually
      // finishes for real in the moment between the findOne above and here,
      // this only overwrites it while still RUNNING/PENDING, so a genuine
      // completion (with real output) can't be clobbered back to CANCELLED.
      const result = await repo
        .createQueryBuilder()
        .update(NetworkScanHistory)
        .set({ status: 'CANCELLED', pid: null })
        .where('id = :id', { id: historyId })
        .andWhere('status IN (:...statuses)', { statuses: ['RUNNING', 'PENDING'] })
        .execute();
      cleanupScanFile(historyId);

      if ((result.affected ?? 0) > 0) {
        const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
        if (jwtPayload?.id) {
          logAuditTrail({
            action: 'NETWORK_SCAN',
            status: 'success',
            userId: jwtPayload.id,
            email: jwtPayload.email ?? null,
            ipAddress: req.ip || req.socket?.remoteAddress || null,
            userAgent: null,
            details: { event: 'SCAN_CANCELLED', historyId, target: scan.target, scanType: scan.scanType },
          }).catch(err => logger.error({ err, historyId }, 'Failed to log scan cancellation audit'));
        }
      }
    }

    if (wasCancellable) {
      logger.info({ historyId }, 'Nmap scan cancelled');
    } else {
      logger.info({ historyId, status: scan.status }, 'Nmap scan cancel request was a no-op, scan already in a terminal state');
    }
    return res.status(200).json({ success: true, message: 'Scan cancelled' });
  } catch (error) {
    logger.error({ err: error, historyId: req.params.id }, 'Failed to cancel nmap scan');
    return next(new CustomError(500, 'Raw', 'Failed to cancel scan', null, error));
  }
};

export const getActiveScan = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const { dbSourceConnection } = await import('../../index');
    const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
    const ds = dbSourceConnection();

    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn('Fleet database not available while fetching active scan');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NetworkScanHistory);
    // schedule_id IS NULL: a scheduler-launched scan must never surface here —
    // the frontend unconditionally adopts whatever this returns as "the
    // current user's active scan" (progress bar, cancel button, etc.).
    let scan = await repo.findOne({
      where: [
        { status: 'RUNNING', schedule_id: IsNull() },
        { status: 'PENDING', schedule_id: IsNull() },
      ],
      order: { created_at: 'DESC' },
    });

    if (scan) {
      const child = activeScans.get(Number(scan.id));
      if (!child && (!scan.pid || !isProcessAlive(scan.pid))) {
        const interruptedId = scan.id;
        scan.status = 'FAILED';
        scan.output = (scan.output || '') + '\n\n[System] Scan was interrupted unexpectedly (e.g., server restart).';
        scan.pid = null;
        await repo.save(scan);
        scan = null;
        logger.warn({ historyId: interruptedId }, 'Nmap scan found interrupted (process dead, no output file) during active-scan check');
      }
    }

    logger.debug({ historyId: scan?.id ?? null }, 'Active scan retrieved');
    return res.status(200).json({
      success: true,
      data: scan
        ? {
            historyId: scan.id,
            progress: scan.progress,
            status: scan.status,
            target: scan.target,
            scanType: scan.scanType,
            created_by_name: scan.created_by_name,
          }
        : null,
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch active nmap scan');
    return next(new CustomError(500, 'Raw', 'Failed to fetch active scan', null, error));
  }
};

const CHART_COLORS = ['#3b82f6', '#0d9488', '#fbbf24', '#ab3428', '#8b5cf6', '#10b981', '#f97316', '#64748b'];

// Minimal mirror of the open-port extraction in frontend's parseNmapOutput —
// only what's needed to backfill chart_data for scans that finished without a
// live view open (the only place that would have run the full client parser
// and POSTed the result via updateScanCharts).
function extractOpenPorts(raw: string): { port: string; protocol: string; service: string }[] {
  const ports: { port: string; protocol: string; service: string }[] = [];
  if (!raw) return ports;

  let inPortSection = false;
  for (const line of raw.split('\n')) {
    if (line.startsWith('PORT') && line.includes('STATE') && line.includes('SERVICE')) {
      inPortSection = true;
      continue;
    }
    if (!inPortSection) continue;

    if (/^\d+\/[a-z]+/.test(line)) {
      const parts = line.trim().split(/\s+/);
      const [port, protocol] = parts[0].split('/');
      const state = parts[1] || '';
      const service = parts[2] || '';
      if (state.toLowerCase().startsWith('open')) {
        ports.push({ port, protocol: protocol || 'tcp', service: service || 'unknown' });
      }
      continue;
    }

    if (line.trim() === '') inPortSection = false;
  }
  return ports;
}

// Rebuilds the same { portData, serviceData, hasData } shape NetworkScanCharts
// computes client-side from a live advancedScanResultsMap, but from persisted
// child scan rows — so completed scans get chart data even if nobody had the
// live scan view open to trigger the client's updateScanCharts POST.
function computeChartDataFromChildScans(childScans: { status: string; output: string }[]) {
  const completed = childScans.filter(c => c.status === 'COMPLETED');
  if (completed.length === 0) return null;

  const portCounts: Record<string, number> = {};
  const serviceCounts: Record<string, number> = {};

  completed.forEach(child => {
    const seenForHost = new Set<string>();
    extractOpenPorts(child.output).forEach(p => {
      const portKey = `${p.port}/${p.protocol}`;
      if (seenForHost.has(portKey)) return;
      seenForHost.add(portKey);
      portCounts[portKey] = (portCounts[portKey] || 0) + 1;
      serviceCounts[p.service] = (serviceCounts[p.service] || 0) + 1;
    });
  });

  const portData = Object.entries(portCounts)
    .map(([port, count]) => ({ port, count }))
    .sort((a, b) => b.count - a.count || parseInt(a.port, 10) - parseInt(b.port, 10))
    .slice(0, 15);

  const serviceEntries = Object.entries(serviceCounts).sort((a, b) => b[1] - a[1]);
  const TOP_N = 7;
  const serviceData = serviceEntries.slice(0, TOP_N).map(([name, value], idx) => ({
    name, value, fill: CHART_COLORS[idx % CHART_COLORS.length],
  }));
  const otherTotal = serviceEntries.slice(TOP_N).reduce((sum, [, v]) => sum + v, 0);
  if (otherTotal > 0) {
    serviceData.push({ name: 'Other', value: otherTotal, fill: CHART_COLORS[TOP_N % CHART_COLORS.length] });
  }

  return { portData, serviceData, hasData: true };
}

export const getNmapScanHistory = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const { dbSourceConnection } = await import('../../index');
    const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
    const ds = dbSourceConnection();

    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn('Fleet database not available while fetching scan history');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NetworkScanHistory);
    const history = await repo.createQueryBuilder('history')
      .select([
        'history.id', 'history.status', 'history.progress', 'history.target',
        'history.scanType', 'history.reason', 'history.command', 'history.output',
        'history.pid', 'history.created_by_user_id', 'history.created_by_name',
        'history.parent_id', 'history.schedule_id', 'history.created_at',
        'history.chart_data',
      ])
      .where('history.parent_id IS NULL')
      .orderBy('history.created_at', 'DESC')
      .take(100)
      .getMany();

    const parentIds = history.map(h => h.id);
    if (parentIds.length > 0) {
      const childScans = await repo.createQueryBuilder('child')
        .where('child.parent_id IN (:...parentIds)', { parentIds })
        .orderBy('child.created_at', 'DESC')
        .take(500)
        .getMany();

      const { NucleiScanHistory } = await import('../../orm/entities/fleet/NucleiScanHistory');
      const nucleiRepo = ds[1].getRepository(NucleiScanHistory);
      const vulnScans = await nucleiRepo.createQueryBuilder('vuln')
        .where('vuln.network_scan_id IN (:...parentIds)', { parentIds })
        .orderBy('vuln.created_at', 'DESC')
        .take(500)
        .getMany();
        
      const toPersist: { id: number; chart_data: any }[] = [];
      history.forEach(h => {
        const ownChildScans = childScans.filter(c => Number(c.parent_id) === Number(h.id));
        (h as any).childScans = ownChildScans;
        (h as any).vulnScans = vulnScans.filter(v => Number(v.network_scan_id) === Number(h.id));

        // Backfill chart_data for scans that completed without a live view open
        // (the only path that computes and POSTs it client-side today).
        if (!h.chart_data?.hasData) {
          const computed = computeChartDataFromChildScans(ownChildScans);
          if (computed) {
            h.chart_data = computed;
            toPersist.push({ id: Number(h.id), chart_data: computed });
          }
        }
      });

      if (toPersist.length > 0) {
        Promise.all(toPersist.map(({ id, chart_data }) => repo.update(id, { chart_data })))
          .then(() => logger.debug({ count: toPersist.length }, 'Backfilled chart_data for completed scans'))
          .catch(err => logger.error({ err }, 'Failed to persist backfilled chart_data'));
      }
    }

    logger.debug({ count: history.length }, 'Nmap scan history retrieved');
    return res.status(200).json({ success: true, data: history });
  } catch (error: any) {
    if (isPgUndefinedTableError(error)) {
      logger.warn({ err: error }, 'network_scan_history table does not exist, returning empty nmap scan history');
      return res.status(200).json({ success: true, data: [] });
    }
    logger.error({ err: error }, 'Failed to fetch nmap scan history');
    return next(new CustomError(500, 'Raw', 'Failed to fetch network scan history', null, error));
  }
};

export const getKnownIps = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const { dbSourceConnection } = await import('../../index');
    const ds = dbSourceConnection();

    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn('Fleet database not available while fetching known IPs');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const nodesResult = await ds[1].query(`
      SELECT DISTINCT address FROM nodes WHERE address IS NOT NULL AND address != ''
      UNION
      SELECT DISTINCT address FROM interface_addresses
      WHERE address IS NOT NULL AND address != ''
      AND id > (SELECT COALESCE(MAX(id), 0) - 5000000 FROM interface_addresses)
    `);

    const addresses = nodesResult.map((r: any) => typeof r.address === 'string' ? r.address.trim() : r.address);
    logger.debug({ count: addresses.length }, 'Known IPs retrieved');
    return res.status(200).json({ success: true, data: addresses });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch known IPs');
    return next(new CustomError(500, 'Raw', 'Failed to fetch known IPs', null, error));
  }
};

export const updateScanCharts = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const historyId = parseInt(req.params.id as string, 10);
    if (isNaN(historyId)) {
      return next(new CustomError(400, 'Validation', 'Invalid scan ID'));
    }

    const { chartData } = req.body;
    if (!chartData) {
      return next(new CustomError(400, 'Validation', 'Chart data is required'));
    }
    if (typeof chartData !== 'object' || Array.isArray(chartData)) {
      return next(new CustomError(400, 'Validation', 'Chart data must be a JSON object'));
    }
    const MAX_CHART_DATA_BYTES = 256 * 1024;
    const chartDataSize = Buffer.byteLength(JSON.stringify(chartData), 'utf-8');
    if (chartDataSize > MAX_CHART_DATA_BYTES) {
      return next(new CustomError(400, 'Validation',
        `Chart data too large (${chartDataSize} bytes, max ${MAX_CHART_DATA_BYTES})`));
    }

    const { dbSourceConnection } = await import('../../index');
    const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
    const ds = dbSourceConnection();

    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({ historyId }, 'Fleet database not available while updating scan chart data');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NetworkScanHistory);
    const scan = await repo.findOne({ where: { id: historyId } });

    if (!scan) {
      return next(new CustomError(404, 'Validation', 'Scan not found'));
    }

    scan.chart_data = chartData;
    await repo.save(scan);

    logger.info({ historyId }, 'Scan chart data updated');
    return res.status(200).json({ success: true, message: 'Chart data updated' });
  } catch (error) {
    logger.error({ err: error, historyId: req.params.id }, 'Failed to update nmap scan chart data');
    return next(new CustomError(500, 'Raw', 'Failed to update chart data', null, error));
  }
};