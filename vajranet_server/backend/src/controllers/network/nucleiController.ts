import { Request, Response, NextFunction } from 'express';
import { spawn, ChildProcess, exec, execFile } from 'child_process';
import { readFileSync, existsSync, mkdirSync, unlinkSync, promises as fsp } from 'fs';
import { promisify } from 'util';
import path from 'path';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { JwtPayload } from '../../types/JwtPayload';
import { isValidAndAllowedIP } from './targetValidation';
import { getLogger } from '../../utils/logger';
import {
  SCAN_OUTPUT_DIR_DEFAULT,
  MAX_CONCURRENT_NETWORK_SCANS,
  SCAN_RECOVERY_POLL_INTERVAL_MS,
} from '../../consts/scanning';
import { EXTERNAL_COMMAND_TIMEOUT_MS } from '../../consts/timeout';
import { isPgUndefinedTableError } from '../../utils/dbErrors';

const logger = getLogger('network.nuclei');

// Promisified child_process helpers. Everything here runs inside an Express handler on
// the single Node process that also serves every other HTTP request and the WebSocket
// fan-out, so a blocking spawn is not merely "slow for this endpoint" — it is a hard
// stall of the whole server for the duration of the child process.
const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

const activeScans = new Map<number, ChildProcess>();
const MAX_CONCURRENT_SCANS = MAX_CONCURRENT_NETWORK_SCANS;

// Synchronous slot reservation to close the TOCTOU window between checking
// `activeScans.size` and the real entry being added (after several awaits) —
// see nmapController's reserveScanSlot for the identical rationale.
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

function nucleiOutPath(historyId: number): string {
  return path.join(getScanDir(), `nuclei-${historyId}.jsonl`);
}

function cleanupScanFile(historyId: number): void {
  try { unlinkSync(nucleiOutPath(historyId)); } catch (err: any) {
    if (err?.code !== 'ENOENT') {
      logger.warn({ err, historyId }, 'Failed to remove Nuclei scan output file during cleanup');
    }
  }
}

// Target Validation (private IPs only, no CIDR — see ./targetValidation)
function validateTargets(raw: string): string[] | null {
  const normalized = raw.replace(/,/g, ' ').replace(/\s+/g, ' ').trim();
  const parts = normalized.split(' ').filter(Boolean);
  if (parts.length === 0) return null;

  for (const part of parts) {
    if (part.startsWith('-')) return null;
    if (part.includes('/')) return null; // nuclei targets are per-IP only, no CIDR expansion
    if (!isValidAndAllowedIP(part)) return null;
  }

  return parts;
}

// Scan Profiles
const VALID_SCAN_TYPES = ['posture', 'cve', 'misconfig', 'full'] as const;
type NucleiScanType = (typeof VALID_SCAN_TYPES)[number];

function getNucleiArgs(scanType: NucleiScanType): string[] {
  const base = [
    '-jsonl',
    '-no-color',
    '-stats',
    '-stats-interval', '5',
    '-no-interactsh',
    '-silent',
    '-exclude-tags', 'dos,fuzzing',
    '-rate-limit', '150',
    '-timeout', '10',
    '-retries', '1',
  ];

  switch (scanType) {
    case 'posture':
      // Security posture check: meaningful findings only, excludes info-level
      // noise — this is what actually distinguishes it from 'full' below.
      return [...base, '-severity', 'critical,high,medium,low'];
    case 'cve':
      return [...base, '-tags', 'cve', '-severity', 'critical,high,medium'];
    case 'misconfig':
      return [...base, '-tags', 'misconfig,default-login,exposure'];
    case 'full':
      return [...base];
  }
}

// Nuclei Binary Detection
const DEFAULT_NUCLEI_PATH = '/opt/nuclei/nuclei';

// Resolved once per process — the `which nuclei` fallback below would
// otherwise re-run on every scan/status request. The binary's location doesn't
// change at runtime, so caching indefinitely (until process restart) is safe.
let cachedNucleiBinaryPath: string | null | undefined;

// In-flight resolution, so two concurrent first-callers (a dashboard poll of
// In-flight resolution, so two concurrent first-callers (a dashboard poll of
// GET /nuclei/status racing a scan launch) share one `which` spawn instead of each
// starting their own. Needed because filling the cache spans an await.
let nucleiBinaryPathPromise: Promise<string | null> | null = null;

async function resolveNucleiBinaryPath(): Promise<string | null> {
  const envPath = process.env.NUCLEI_BINARY_PATH;
  if (envPath) {
    cachedNucleiBinaryPath = envPath;
  } else if (existsSync(DEFAULT_NUCLEI_PATH)) {
    cachedNucleiBinaryPath = DEFAULT_NUCLEI_PATH;
  } else {
    try {
      // Bounded by the same 10s ceiling as the rest of this file's external commands,
      // and off the event loop: an unbounded synchronous `which` that hangs — an
      // unresponsive NFS/autofs entry on PATH is the realistic way that happens — would
      // freeze the whole process indefinitely.
      const { stdout } = await execAsync('which nuclei', { encoding: 'utf-8', timeout: EXTERNAL_COMMAND_TIMEOUT_MS });
      cachedNucleiBinaryPath = stdout.trim() || null;
    } catch {
      cachedNucleiBinaryPath = null;
    }
  }
  return cachedNucleiBinaryPath;
}

async function getNucleiBinaryPath(): Promise<string | null> {
  if (cachedNucleiBinaryPath !== undefined) return cachedNucleiBinaryPath;
  if (!nucleiBinaryPathPromise) nucleiBinaryPathPromise = resolveNucleiBinaryPath();
  return nucleiBinaryPathPromise;
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

function isNucleiProcess(pid: number): boolean {
  try {
    const cmdline = readFileSync(`/proc/${pid}/cmdline`, 'utf-8');
    return cmdline.includes('nuclei');
  } catch {
    return false;
  }
}

// Returns whether a SIGTERM was actually sent — callers that expected a live
// process (e.g. cancelNucleiScan) use this to tell a real kill apart from a
// silent no-op (pid already dead / reused by an unrelated process), which
// otherwise look identical from the caller's side.
function killNucleiProcess(pid: number): boolean {
  try {
    if (isNucleiProcess(pid)) {
      // Negative PID → whole process group (spawn uses detached:true), so any
      // subprocess nuclei itself launches is also terminated, not just nuclei.
      process.kill(-pid, 'SIGTERM');
      return true;
    }
    return false;
  } catch (err) {
    logger.warn({ err, pid }, 'Failed to send SIGTERM to Nuclei process group');
    return false;
  }
}

// Finding Parser
interface NucleiFinding {
  templateId: string;
  name: string;
  severity: string;
  type: string;
  host: string;
  matchedAt: string;
  ip: string;
  tags: string[];
  reference: string[];
  description: string;
  cveId: string[];
  cvssScore: number | null;
  timestamp: string;
}

// Takes the already-decoded object rather than a string: the array branch of
// parseFindingsFromFile below would otherwise re-serialise every entry only for this
// function to parse it straight back, a full extra encode+decode of each finding
// (including the request/response bodies nuclei writes in full).
function parseFindingObject(raw: any): NucleiFinding | null {
  try {
    if (!raw['template-id'] || !raw.info) return null;

    return {
      templateId: raw['template-id'] || '',
      name: raw.info?.name || '',
      severity: (raw.info?.severity || 'unknown').toLowerCase(),
      type: raw.type || '',
      host: raw.host || '',
      matchedAt: raw['matched-at'] || '',
      ip: raw.ip || '',
      tags: raw.info?.tags || [],
      reference: raw.info?.reference || [],
      description: raw.info?.description || '',
      cveId: raw.info?.classification?.['cve-id'] || [],
      cvssScore: raw.info?.classification?.['cvss-score'] ?? null,
      timestamp: raw.timestamp || new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

function parseFindingLine(line: string): NucleiFinding | null {
  try {
    return parseFindingObject(JSON.parse(line));
  } catch {
    return null;
  }
}

// `scanId` is only used for logging — it does not affect what gets parsed or returned.
// Async because this is reached from GET /network/nuclei/scan/:id/status, which the scan
// view polls every few seconds while a scan runs. A posture/full scan's .jsonl carries
// every matched request and response body and routinely reaches tens of MB, so a
// synchronous read would block all HTTP and WebSocket traffic on every poll tick.
async function parseFindingsFromFile(filePath: string, scanId?: number): Promise<NucleiFinding[]> {
  const findings: NucleiFinding[] = [];
  if (!existsSync(filePath)) return findings;
  try {
    const content = (await fsp.readFile(filePath, 'utf-8')).trim();
    if (!content) return findings;

    // nuclei -je writes a JSON array, not JSON lines
    if (content.startsWith('[')) {
      const arr = JSON.parse(content);
      if (Array.isArray(arr)) {
        let skipped = 0;
        for (const raw of arr) {
          const f = parseFindingObject(raw);
          if (f) findings.push(f);
          else skipped++;
        }
        if (skipped > 0) {
          logger.warn({ scanId, filePath, skipped, parsed: findings.length }, 'Some entries in Nuclei findings array could not be parsed and were dropped');
        }
        return findings;
      }
    }

    // Fallback: JSON lines format (one object per line)
    let skippedLines = 0;
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const f = parseFindingLine(trimmed);
      if (f) findings.push(f);
      else skippedLines++;
    }
    if (skippedLines > 0) {
      logger.warn({ scanId, filePath, skipped: skippedLines, parsed: findings.length }, 'Some lines in Nuclei findings file could not be parsed and were dropped');
    }
  } catch (err) {
    logger.warn({ err, scanId, filePath }, 'Failed to read or parse Nuclei findings file, treating as no findings');
  }
  return findings;
}

function computeSummary(findings: NucleiFinding[]) {
  const severity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const cveIds: string[] = [];

  for (const f of findings) {
    if (severity[f.severity] !== undefined) severity[f.severity]++;
    else severity.info++;
    cveIds.push(...f.cveId);
  }

  return {
    totalFindings: findings.length,
    severity,
    uniqueCves: [...new Set(cveIds)],
    uniqueCveCount: new Set(cveIds).size,
  };
}

// Startup Recovery
const recoveryPollers = new Map<number, ReturnType<typeof setInterval>>();

function startRecoveryPoller(scanId: number, pid: number): void {
  if (recoveryPollers.has(scanId)) return;

  const interval = setInterval(async () => {
    if (isProcessAlive(pid) && isNucleiProcess(pid)) return;

    clearInterval(interval);
    recoveryPollers.delete(scanId);

    try {
      const { dbSourceConnection } = await import('../../index');
      const { NucleiScanHistory } = await import('../../orm/entities/fleet/NucleiScanHistory');
      const ds = dbSourceConnection();
      if (!ds || ds.length < 2 || !ds[1].isInitialized) {
        logger.warn({ scanId }, 'Fleet database not available while finalizing recovered Nuclei scan, scan will remain stuck until next restart');
        return;
      }

      const repo = ds[1].getRepository(NucleiScanHistory);
      const scan = await repo.findOne({ where: { id: scanId } });
      if (!scan) {
        logger.warn({ scanId }, 'Nuclei scan row not found while finalizing recovered scan');
        return;
      }
      if (scan.status === 'CANCELLED') {
        logger.info({ scanId }, 'Nuclei scan already cancelled, skipping recovery finalization');
        return;
      }

      const outFile = nucleiOutPath(scanId);
      const findings = await parseFindingsFromFile(outFile, scanId);
      const summary = computeSummary(findings);
      const finalStatus = findings.length > 0 || existsSync(outFile) ? 'COMPLETED' : 'FAILED';

      await repo.query(
        `UPDATE nuclei_scan_history SET status = $1, progress = 100, findings = $2, summary = $3, pid = NULL WHERE id = $4`,
        [finalStatus, JSON.stringify(findings), JSON.stringify(summary), scanId],
      );
      cleanupScanFile(scanId);

      if (finalStatus === 'COMPLETED') {
        logger.info({ scanId, status: finalStatus, findingsCount: findings.length }, 'Resumed Nuclei scan finalized after process exit');
      } else {
        logger.warn({ scanId, status: finalStatus }, 'Resumed Nuclei scan finalized as FAILED after process exit');
      }
    } catch (err) {
      logger.error({ err, scanId }, 'Failed to finalize recovered Nuclei scan');
    }

  }, SCAN_RECOVERY_POLL_INTERVAL_MS);

  recoveryPollers.set(scanId, interval);
}

export async function cleanupOrphanedNucleiScans(): Promise<void> {
  try {
    const { dbSourceConnection } = await import('../../index');
    const { NucleiScanHistory } = await import('../../orm/entities/fleet/NucleiScanHistory');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn('Fleet database not available, skipping orphaned Nuclei scan cleanup');
      return;
    }

    const repo = ds[1].getRepository(NucleiScanHistory);
    const orphaned = await repo.find({
      where: [{ status: 'RUNNING' }, { status: 'PENDING' }],
    });

    for (const scan of orphaned) {
      const scanId = Number(scan.id);

      if (scan.pid && isProcessAlive(scan.pid)) {
        startRecoveryPoller(scanId, scan.pid);
        logger.info({ scanId, pid: scan.pid }, 'Resumed tracking Nuclei scan after restart');
        continue;
      }

      // Process dead — try to recover from output file
      const outFile = nucleiOutPath(scanId);
      if (existsSync(outFile)) {
        try {
          const findings = await parseFindingsFromFile(outFile, scanId);
          const summary = computeSummary(findings);
          await repo.query(
            `UPDATE nuclei_scan_history SET status = 'COMPLETED', progress = 100, findings = $1, summary = $2, pid = NULL WHERE id = $3`,
            [JSON.stringify(findings), JSON.stringify(summary), scanId],
          );
          logger.info({ scanId, findingsCount: findings.length }, 'Recovered Nuclei scan from output file');
        } catch (err) {
          logger.warn({ err, scanId }, 'Failed to recover Nuclei scan from output file, marking scan failed');
          scan.status = 'FAILED';
          scan.pid = null;
          await repo.save(scan);
        }
        cleanupScanFile(scanId);
      } else {
        if (scan.pid) killNucleiProcess(scan.pid);
        scan.status = 'FAILED';
        scan.rawOutput = (scan.rawOutput || '') + '\n\n[System] Scan was interrupted by server restart.';
        scan.pid = null;
        await repo.save(scan);
        logger.warn({ scanId }, 'Orphaned Nuclei scan has no output file, marking failed');
      }
    }

    const deadCount = orphaned.filter(s => s.status !== 'RUNNING' && s.status !== 'PENDING').length;
    if (deadCount > 0) {
      logger.info({ deadCount }, 'Finalized orphaned Nuclei scans');
    }
    // Always log a summary, even when nothing was found — otherwise a clean
    // restart (the common case) leaves zero trace that this startup check
    // ran at all, indistinguishable from it never having been invoked.
    logger.debug({ found: orphaned.length, resumedTracking: orphaned.length - deadCount, finalized: deadCount }, 'Orphaned Nuclei scan cleanup completed');
  } catch (err) {
    logger.error({ err }, 'Failed to cleanup orphaned Nuclei scans');
  }
}

// Route Handlers
export const runNucleiScan = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { target, scanType, reason, networkScanId } = req.body;

    if (!target || typeof target !== 'string') {
      logger.debug('Nuclei scan rejected: missing or non-string target');
      return next(new CustomError(400, 'Validation', 'Target is required and must be a string'));
    }
    if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
      logger.debug({ target }, 'Nuclei scan rejected: missing reason');
      return next(new CustomError(400, 'Validation', 'Reason is required'));
    }

    const validatedTargets = validateTargets(target);
    if (!validatedTargets) {
      logger.debug({ target }, 'Nuclei scan rejected: invalid or disallowed target');
      return next(new CustomError(400, 'Validation',
        'Invalid target. Only private network IPs (10.x, 172.16-31.x, 192.168.x) are allowed.'));
    }

    const nucleiBinary = await getNucleiBinaryPath();
    if (!nucleiBinary) {
      logger.debug({ target }, 'Nuclei scan rejected: nuclei binary not found');
      return next(new CustomError(503, 'Raw',
        'Nuclei binary not found. Install it from https://github.com/projectdiscovery/nuclei/releases and ensure it is in PATH, or set NUCLEI_BINARY_PATH.'));
    }

    const resolvedScanType: NucleiScanType = (VALID_SCAN_TYPES as readonly string[]).includes(scanType)
      ? (scanType as NucleiScanType)
      : 'posture';

    // Check-then-reserve, synchronously (no await in between) — see
    // reserveScanSlot() for why this closes the TOCTOU gap the plain size
    // check alone leaves open.
    if (activeScans.size >= MAX_CONCURRENT_SCANS) {
      logger.warn({ activeCount: activeScans.size }, 'Nuclei scan rejected: concurrent scan limit reached');
      return res.status(429).json({
        success: false,
        message: `A maximum of ${MAX_CONCURRENT_SCANS} concurrent scans are allowed. Please wait for some to finish.`,
      });
    }
    const reservationKey = reserveScanSlot();
    let reservationHandedOff = false;

    try {
      const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;

      const { dbSourceConnection } = await import('../../index');
      const { NucleiScanHistory } = await import('../../orm/entities/fleet/NucleiScanHistory');
      const ds = dbSourceConnection();
      if (!ds || ds.length < 2 || !ds[1].isInitialized) {
        logger.warn('Fleet database not available while starting Nuclei scan');
        return res.status(503).json({ success: false, message: 'Fleet database not available' });
      }

      const repo = ds[1].getRepository(NucleiScanHistory);

      let linkedNetworkScanId: number | null = null;
      if (networkScanId !== undefined && networkScanId !== null && networkScanId !== '') {
        const parsed = Number(networkScanId);
        if (!Number.isInteger(parsed)) {
          logger.debug({ target, networkScanId }, 'Nuclei scan rejected: networkScanId is not an integer');
          return next(new CustomError(400, 'Validation', 'networkScanId must be an integer'));
        }
        const { NetworkScanHistory } = await import('../../orm/entities/fleet/NetworkScanHistory');
        const nmapRepo = ds[1].getRepository(NetworkScanHistory);
        const parentExists = await nmapRepo.exist({ where: { id: parsed as any } });
        if (!parentExists) {
          logger.debug({ target, networkScanId: parsed }, 'Nuclei scan rejected: networkScanId does not reference an existing scan');
          return next(new CustomError(400, 'Validation', `networkScanId ${parsed} does not reference an existing scan`));
        }
        linkedNetworkScanId = parsed;
      }

      const scanArgs = getNucleiArgs(resolvedScanType);
      const targetArgs = validatedTargets.flatMap(t => ['-target', t]);
      const fullArgs = [...scanArgs, ...targetArgs];
      const commandForAudit = `nuclei ${fullArgs.join(' ')}`;

      const historyEntry = repo.create({
        target: validatedTargets.join(' '),
        scanType: resolvedScanType,
        reason: reason.trim(),
        command: commandForAudit,
        rawOutput: '',
        findings: [],
        summary: null,
        pid: null,
        network_scan_id: linkedNetworkScanId,
        created_by_user_id: jwtPayload?.id ?? null,
        created_by_name: jwtPayload?.name ?? null,
      });

      const saved = await repo.save(historyEntry);
      const historyId = Number(saved.id);

      const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';

      if (jwtPayload?.id) {
        logAuditTrail({
          action: 'NETWORK_SCAN',
          status: 'success',
          userId: jwtPayload.id,
          email: jwtPayload.email ?? null,
          ipAddress: clientIp,
          userAgent: null,
          details: { event: 'NUCLEI_SCAN_STARTED', target: validatedTargets.join(' '), scanType: resolvedScanType, reason: reason.trim(), historyId },
        }).catch(err => logger.error({ err, historyId }, 'Failed to log Nuclei scan initiation audit'));
      }

      logger.info({ historyId, target: validatedTargets.join(' '), scanType: resolvedScanType }, 'Nuclei scan started');
      res.status(202).json({
        success: true,
        data: { historyId, message: 'Nuclei scan started asynchronously' },
      });

      reservationHandedOff = true;
      activeScans.delete(reservationKey);

      runNucleiBackground(historyId, nucleiBinary, fullArgs, validatedTargets.join(' '), resolvedScanType, reason.trim(), jwtPayload, clientIp)
        .catch(err => {
          logger.error({ err, historyId }, 'Nuclei background scan failed to start');
          activeScans.delete(historyId);
          repo.update(historyId, { status: 'FAILED', rawOutput: `[System] Failed to launch scan process: ${err.message}`, pid: null })
            .catch(updateErr => logger.error({ err: updateErr, historyId }, 'Failed to mark Nuclei scan FAILED after background launch failure, scan will be stuck as PENDING'));
        });
    } finally {
      if (!reservationHandedOff) activeScans.delete(reservationKey);
    }
  } catch (error) {
    logger.error({ err: error, target: req.body?.target }, 'Unexpected error while starting Nuclei scan');
    next(new CustomError(500, 'Raw', 'An unexpected error occurred starting the Nuclei scan', null, error));
  }
};

// Background Scan
const runNucleiBackground = async (
  historyId: number,
  binaryPath: string,
  nucleiArgs: string[],
  target: string,
  scanType: string,
  reason: string,
  jwtPayload: any,
  clientIp: string,
) => {
  const { dbSourceConnection } = await import('../../index');
  const { NucleiScanHistory } = await import('../../orm/entities/fleet/NucleiScanHistory');
  const ds = dbSourceConnection()!;
  const repo = ds[1].getRepository(NucleiScanHistory);

  let rawOutput = '';
  const findings: NucleiFinding[] = [];
  let stdoutBuffer = '';

  // -je writes findings to file so they survive a server restart
  const outFile = nucleiOutPath(historyId);
  const argsWithFile = [...nucleiArgs, '-je', outFile];

  const child = spawn(binaryPath, argsWithFile, { detached: true });
  child.unref();
  activeScans.set(historyId, child);

  const childPid = child.pid ?? null;
  await repo.update(historyId, { status: 'RUNNING', pid: childPid });

  let maxProgress = 0;

  // Periodic DB flush — runs every 5s regardless of whether stdout/stderr fired.
  // This is critical because nuclei with -silent produces NO stdout when there
  // are 0 findings, so tying DB writes to stdout would leave progress stuck at 0.
  const progressInterval = setInterval(async () => {
    await repo.query(
      `UPDATE nuclei_scan_history SET findings = $1, raw_output = $2, progress = $3 WHERE id = $4`,
      [JSON.stringify(findings), rawOutput, maxProgress, historyId],
    ).catch((err) => { logger.error({ err, historyId }, 'Failed to update Nuclei scan progress'); });
  }, 5000);

  child.stdout.on('data', (data: any) => {
    const chunk = data.toString();
    rawOutput += chunk;
    stdoutBuffer += chunk;

    const lines = stdoutBuffer.split('\n');
    stdoutBuffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const finding = parseFindingLine(trimmed);
      if (finding) findings.push(finding);
    }
  });

  child.stderr.on('data', (data) => {
    const chunk = data.toString();
    rawOutput += chunk;

    for (const line of chunk.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const statsJson = JSON.parse(trimmed);
        if (statsJson.percent != null) {
          const pct = Math.floor(parseFloat(statsJson.percent));
          if (pct > maxProgress && pct <= 100) maxProgress = pct;
        }
      } catch {
        const percentMatch = trimmed.match(/\((\d+(?:\.\d+)?)%\)/);
        if (percentMatch) {
          const pct = Math.floor(parseFloat(percentMatch[1]));
          if (pct > maxProgress && pct <= 100) maxProgress = pct;
        }
      }
    }
  });

  child.on('error', async (error) => {
    clearInterval(progressInterval);
    logger.error({ err: error, historyId }, 'Nuclei process failed to start or crashed');
    // try/catch so a thrown DB error can't skip activeScans.delete() below
    // and leak this slot forever.
    try {
      rawOutput += `\n[Process Error] Failed to start Nuclei: ${error.message}`;
      await repo.update(historyId, { status: 'FAILED', rawOutput, pid: null });
      cleanupScanFile(historyId);
    } catch (err) {
      logger.error({ err, historyId }, 'Failed to finalize errored Nuclei scan');
    } finally {
      activeScans.delete(historyId);
    }
  });

  child.on('close', async (code) => {
    clearInterval(progressInterval);
    try {
      if (stdoutBuffer.trim()) {
        const finding = parseFindingLine(stdoutBuffer.trim());
        if (finding) findings.push(finding);
      }

      const current = await repo.findOne({ where: { id: historyId } });
      if (current && current.status === 'CANCELLED') {
        cleanupScanFile(historyId);
        logger.info({ historyId, exitCode: code }, 'Nuclei process exited after scan was already cancelled, leaving status as CANCELLED');
        return;
      }

      const status = code === 0 ? 'COMPLETED' : 'FAILED';
      const summary = computeSummary(findings);

      await repo.query(
        `UPDATE nuclei_scan_history SET status = $1, progress = $2, raw_output = $3, findings = $4, summary = $5, pid = NULL WHERE id = $6`,
        [status, status === 'COMPLETED' ? 100 : maxProgress, rawOutput, JSON.stringify(findings), JSON.stringify(summary), historyId],
      );

      cleanupScanFile(historyId);

      if (status === 'COMPLETED') {
        logger.info({ historyId, status, exitCode: code, findingsCount: findings.length }, 'Nuclei scan process exited');
      } else {
        logger.warn({ historyId, status, exitCode: code, findingsCount: findings.length }, 'Nuclei scan process exited with a non-zero exit code, marked FAILED');
      }

      if (jwtPayload?.id) {
        logAuditTrail({
          action: 'NETWORK_SCAN',
          status: code === 0 ? 'success' : 'failure',
          userId: jwtPayload.id,
          email: jwtPayload.email ?? null,
          ipAddress: clientIp,
          userAgent: null,
          details: {
            event: 'NUCLEI_SCAN_COMPLETED',
            target, scanType, reason, historyId, exitCode: code,
            findingsCount: findings.length,
            summary,
          },
        }).catch(err => logger.error({ err, historyId }, 'Failed to log Nuclei scan completion audit'));
      }
    } catch (err) {
      logger.error({ err, historyId }, 'Failed to finalize completed Nuclei scan');
    } finally {
      activeScans.delete(historyId);
    }
  });
};

// Status / History / Cancel
export const getNucleiScanStatus = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const historyId = parseInt(req.params.id as string, 10);
    if (isNaN(historyId)) {
      return next(new CustomError(400, 'Validation', 'Invalid scan ID'));
    }

    const { dbSourceConnection } = await import('../../index');
    const { NucleiScanHistory } = await import('../../orm/entities/fleet/NucleiScanHistory');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({ historyId }, 'Fleet database not available while fetching Nuclei scan status');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NucleiScanHistory);
    const scan = await repo.findOne({ where: { id: historyId } });

    if (!scan) {
      return next(new CustomError(404, 'Validation', 'Scan not found'));
    }

    const child = activeScans.get(Number(scan.id));
    if ((scan.status === 'RUNNING' || scan.status === 'PENDING') && !child && (!scan.pid || !isProcessAlive(scan.pid))) {
      const outFile = nucleiOutPath(historyId);
      if (existsSync(outFile)) {
        const findings = await parseFindingsFromFile(outFile, historyId);
        scan.findings = findings;
      } else {
        scan.status = 'FAILED';
        scan.rawOutput = (scan.rawOutput || '') + '\n\n[System] Scan was interrupted unexpectedly (e.g., server restart).';
        scan.pid = null;
        await repo.save(scan);
        logger.warn({ historyId }, 'Nuclei scan found interrupted (process dead, no output file) during status check');
      }
    }

    logger.debug({ historyId, status: scan.status }, 'Nuclei scan status retrieved');
    return res.status(200).json({
      success: true,
      data: {
        id: scan.id,
        status: scan.status,
        progress: scan.progress,
        target: scan.target,
        scanType: scan.scanType,
        findings: scan.findings,
        summary: scan.summary,
        rawOutput: scan.rawOutput,
      },
    });
  } catch (error) {
    logger.error({ err: error, historyId: req.params.id }, 'Failed to fetch Nuclei scan status');
    return next(new CustomError(500, 'Raw', 'Failed to fetch Nuclei scan status', null, error));
  }
};

export const cancelNucleiScan = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const historyId = parseInt(req.params.id as string, 10);
    if (isNaN(historyId)) {
      return next(new CustomError(400, 'Validation', 'Invalid scan ID'));
    }

    const { dbSourceConnection } = await import('../../index');
    const { NucleiScanHistory } = await import('../../orm/entities/fleet/NucleiScanHistory');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn({ historyId }, 'Fleet database not available while cancelling Nuclei scan');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NucleiScanHistory);
    const scan = await repo.findOne({ where: { id: historyId } });

    if (!scan) {
      return next(new CustomError(404, 'Validation', 'Scan not found'));
    }

    const wasCancellable = scan.status === 'RUNNING' || scan.status === 'PENDING';
    if (scan.status === 'RUNNING' || scan.status === 'PENDING') {
      const child = activeScans.get(historyId);
      if (child && child.pid) {
        // Negative pid → whole process group (see killNucleiProcess).
        try { process.kill(-child.pid, 'SIGTERM'); } catch (err) {
          logger.warn({ err, historyId, pid: child.pid }, 'Failed to send SIGTERM to tracked Nuclei process group during cancel');
        }
        activeScans.delete(historyId);
      } else if (scan.pid) {
        const signaled = killNucleiProcess(scan.pid);
        if (!signaled) {
          logger.warn({ historyId, pid: scan.pid }, 'Cancel request found no live Nuclei process for tracked pid, only the DB status will change');
        }
      } else {
        logger.warn({ historyId, status: scan.status }, 'Cancelling Nuclei scan with no tracked process or pid, only the DB status will change');
      }

      // Conditional update, not a blind findOne+save: if the scan actually
      // completes for real in the moment between the findOne above and here,
      // this only overwrites it while still RUNNING/PENDING, so a genuine
      // completion (with real findings) can't be clobbered back to CANCELLED
      // with the stale/empty data this `scan` object was fetched with.
      const result = await repo
        .createQueryBuilder()
        .update(NucleiScanHistory)
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
            ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
            userAgent: null,
            details: { event: 'NUCLEI_SCAN_CANCELLED', historyId, target: scan.target, scanType: scan.scanType },
          }).catch(err => logger.error({ err, historyId }, 'Failed to log Nuclei scan cancellation audit'));
        }
      }
    }

    if (wasCancellable) {
      logger.info({ historyId }, 'Nuclei scan cancelled');
    } else {
      logger.info({ historyId, status: scan.status }, 'Nuclei scan cancel request was a no-op, scan already in a terminal state');
    }
    return res.status(200).json({ success: true, message: 'Nuclei scan cancelled' });
  } catch (error) {
    logger.error({ err: error, historyId: req.params.id }, 'Failed to cancel Nuclei scan');
    return next(new CustomError(500, 'Raw', 'Failed to cancel Nuclei scan', null, error));
  }
};

export const getActiveNucleiScan = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const { dbSourceConnection } = await import('../../index');
    const { NucleiScanHistory } = await import('../../orm/entities/fleet/NucleiScanHistory');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn('Fleet database not available while fetching active Nuclei scan');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NucleiScanHistory);
    let scan = await repo.findOne({
      where: [{ status: 'RUNNING' }, { status: 'PENDING' }],
      order: { created_at: 'DESC' },
    });

    if (scan) {
      const child = activeScans.get(Number(scan.id));
      if (!child && (!scan.pid || !isProcessAlive(scan.pid))) {
        const interruptedId = scan.id;
        scan.status = 'FAILED';
        scan.rawOutput = (scan.rawOutput || '') + '\n\n[System] Scan was interrupted unexpectedly (e.g., server restart).';
        scan.pid = null;
        await repo.save(scan);
        scan = null;
        logger.warn({ historyId: interruptedId }, 'Nuclei scan found interrupted (process dead, no output file) during active-scan check');
      }
    }

    logger.debug({ historyId: scan?.id ?? null }, 'Active Nuclei scan retrieved');
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
            findingsCount: scan.findings?.length ?? 0,
          }
        : null,
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch active Nuclei scan');
    return next(new CustomError(500, 'Raw', 'Failed to fetch active Nuclei scan', null, error));
  }
};

export const getNucleiScanHistory = async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const { dbSourceConnection } = await import('../../index');
    const { NucleiScanHistory } = await import('../../orm/entities/fleet/NucleiScanHistory');
    const ds = dbSourceConnection();
    if (!ds || ds.length < 2 || !ds[1].isInitialized) {
      logger.warn('Fleet database not available while fetching Nuclei scan history');
      return res.status(503).json({ success: false, message: 'Fleet database not available' });
    }

    const repo = ds[1].getRepository(NucleiScanHistory);
    const history = await repo.find({
      select: ['id', 'status', 'progress', 'target', 'scanType', 'reason', 'summary', 'created_by_name', 'created_at'],
      order: { created_at: 'DESC' },
      take: 100,
    });

    logger.debug({ count: history.length }, 'Nuclei scan history retrieved');
    return res.status(200).json({ success: true, data: history });
  } catch (error: any) {
    if (isPgUndefinedTableError(error)) {
      logger.warn({ err: error }, 'nuclei_scan_history table does not exist, returning empty Nuclei scan history');
      return res.status(200).json({ success: true, data: [] });
    }
    logger.error({ err: error }, 'Failed to fetch Nuclei scan history');
    return next(new CustomError(500, 'Raw', 'Failed to fetch Nuclei scan history', null, error));
  }
};

// Nuclei installation and template management
// `-version` and the recursive template-file count are external commands. With
// `nuclei-templates` checked out (~10k files over ~2.5k directories) the `find` alone is
// hundreds of milliseconds of cold stat() traffic, and both carry generous timeouts, so
// running them synchronously would stall Node's whole event loop — every HTTP request
// and the entire WebSocket fan-out, on one process — for up to the combined timeout. The
// 60s cache only bounds how often that happens, never the stall itself, so both are
// spawned asynchronously: a cache miss costs this one request its latency and nothing
// else its availability.
const NUCLEI_INSTALLED_CACHE_TTL_MS = 60_000;
let nucleiInstalledCache: { data: Record<string, unknown>; expiresAt: number } | null = null;

// Filling the cache spans awaits, so without this every poller arriving during a miss
// would launch its own `nuclei -version` and `find` before the first finished writing
// the cache — exactly the pile-up the cache exists to prevent. Concurrent misses share
// one computation and one result.
let nucleiInstalledInFlight: Promise<Record<string, unknown>> | null = null;

function invalidateNucleiInstalledCache(): void {
  nucleiInstalledCache = null;
}

async function computeNucleiInstalledStatus(): Promise<Record<string, unknown>> {
  const binaryPath = await getNucleiBinaryPath();
  if (!binaryPath) {
    return { installed: false, version: null, templatesPath: null, templateCount: 0 };
  }

  try {
    // execFile (async) with the same argv, timeout, maxBuffer and non-zero-exit
    // semantics execFileSync had, so every branch below is reached under the same
    // conditions.
    const versionOutput = (await execFileAsync(binaryPath, ['-version'], { encoding: 'utf-8', timeout: EXTERNAL_COMMAND_TIMEOUT_MS })).stdout.trim();
    const versionMatch = versionOutput.match(/v?(\d+\.\d+\.\d+)/);

    let templatesPath: string | null = null;
    let templateCount = 0;
    const home = process.env.HOME || '/root';
    const defaultPath = path.join(home, 'nuclei-templates');
    try {
      await fsp.stat(defaultPath);
      templatesPath = defaultPath;
    } catch {
      // Expected before the first `-update-templates` run — no templates dir yet.
    }
    if (templatesPath) {
      try {
        const countOutput = (await execFileAsync('find', [defaultPath, '-name', '*.yaml', '-type', 'f'], { encoding: 'utf-8', timeout: 15000 })).stdout;
        templateCount = countOutput.trim().split('\n').filter(Boolean).length;
      } catch (err) {
        logger.warn({ err, templatesPath }, 'Failed to count Nuclei template files, reporting templateCount as 0');
      }
    }

    return {
      installed: true,
      version: versionMatch ? versionMatch[1] : versionOutput.slice(0, 100),
      templatesPath,
      templateCount,
    };
  } catch (err) {
    logger.warn({ err, binaryPath }, 'Failed to determine Nuclei version, reporting as unknown');
    return { installed: true, version: 'unknown', templatesPath: null, templateCount: 0 };
  }
}

export const checkNucleiInstalled = async (_req: Request, res: Response, _next: NextFunction) => {
  if (nucleiInstalledCache && nucleiInstalledCache.expiresAt > Date.now()) {
    logger.debug({ installed: nucleiInstalledCache.data.installed }, 'Nuclei installation status served from cache');
    return res.status(200).json({ success: true, data: nucleiInstalledCache.data });
  }

  if (!nucleiInstalledInFlight) {
    // computeNucleiInstalledStatus never rejects (every failure mode is caught
    // and reported as a status object), so this promise always settles and the
    // finally below always clears it — no risk of wedging the endpoint on a
    // permanently-pending entry.
    nucleiInstalledInFlight = computeNucleiInstalledStatus()
      .then((data) => {
        nucleiInstalledCache = { data, expiresAt: Date.now() + NUCLEI_INSTALLED_CACHE_TTL_MS };
        return data;
      })
      .finally(() => { nucleiInstalledInFlight = null; });
  }

  const data = await nucleiInstalledInFlight;
  logger.debug({ installed: data.installed }, 'Nuclei installation status computed');
  return res.status(200).json({ success: true, data });
};

let templateUpdateInProgress = false;

export const updateNucleiTemplates = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const nucleiBinary = await getNucleiBinaryPath();
    if (!nucleiBinary) {
      return next(new CustomError(503, 'Raw',
        'Nuclei binary not found. Install it first.'));
    }

    if (templateUpdateInProgress) {
      logger.warn('Nuclei template update rejected, an update is already in progress');
      return res.status(409).json({ success: false, message: 'Template update is already in progress.' });
    }

    templateUpdateInProgress = true;

    const jwtPayload = (req as any).jwtPayload as JwtPayload | undefined;
    const clientIp = req.ip || req.socket?.remoteAddress || 'unknown';

    // Respond immediately — update runs in background
    logger.info('Nuclei template update started');
    res.status(202).json({ success: true, data: { message: 'Template update started in background.' } });

    let output = '';
    const child = spawn(nucleiBinary, ['-update-templates', '-no-color'], { detached: true });
    child.unref();

    child.stdout.on('data', (d) => { output += d.toString(); });
    child.stderr.on('data', (d) => { output += d.toString(); });

    child.on('close', async (code) => {
      templateUpdateInProgress = false;
      invalidateNucleiInstalledCache(); // template count just changed

      if (jwtPayload?.id) {
        logAuditTrail({
          action: 'NETWORK_SCAN',
          status: code === 0 ? 'success' : 'failure',
          userId: jwtPayload.id,
          email: jwtPayload.email ?? null,
          ipAddress: clientIp,
          userAgent: null,
          details: { event: 'NUCLEI_TEMPLATE_UPDATE', exitCode: code, output: output.slice(0, 2000) },
        }).catch(err => logger.error({ err }, 'Failed to log Nuclei template update audit'));
      }

      if (code === 0) {
        logger.info({ exitCode: code }, 'Nuclei template update completed');
      } else {
        logger.warn({ exitCode: code }, 'Nuclei template update failed');
      }
    });

    child.on('error', (err) => {
      logger.error({ err }, 'Nuclei template update process failed to start');
      templateUpdateInProgress = false;
    });
  } catch (error) {
    templateUpdateInProgress = false;
    logger.error({ err: error }, 'Failed to start Nuclei template update');
    next(new CustomError(500, 'Raw', 'Failed to start template update', null, error));
  }
};

export const getTemplateUpdateStatus = async (_req: Request, res: Response, _next: NextFunction) => {
  logger.debug({ inProgress: templateUpdateInProgress }, 'Nuclei template update status retrieved');
  return res.status(200).json({
    success: true,
    data: { inProgress: templateUpdateInProgress },
  });
};
