/**
 * Server-side "build a Patch Bundle from a folder of raw package files" pipeline. It
 * automates the mechanical parts of the offline sign-patch-bundle.ts CLI workflow (tar
 * the files, hash them, write the manifest, sign it) except for one deliberate
 * difference: where the private signing key lives.
 *
 * Accepted risk, per explicit product decision: this endpoint signs with a key resident
 * on this server (PATCH_BUNDLE_SIGN_KEY_PATH) rather than on an offline-only machine.
 * The offline CLI workflow (scripts/sign-patch-bundle.ts) remains available for anyone
 * who wants the stronger guarantee. A fully compromised backend can therefore forge
 * bundles agents will trust and install. Four mitigations make that trade acceptable —
 * do not remove any of them while touching this file:
 *   1. The key file's permissions are checked at every read (loadSignKey below) and the
 *      key is loaded fresh per call, never cached in a module-level variable.
 *   2. Gated like every other high-privilege patch action: Super-Admin (routes/api/
 *      patch.ts's router middleware) and requireMfa.
 *   3. Every call is audit-logged (PATCH_BUNDLE_BUILT), including failures.
 *   4. The freshly-signed manifest is re-verified with the same verifySignedPatchBundle
 *      the upload path fails closed on, before insertVerifiedPatchBundle is called.
 *
 * The folder mechanism is an admin-triggered scan of a fixed, operator-managed directory
 * (PATCH_BUNDLE_STAGING_DIR) rather than a filesystem watcher: this codebase runs no
 * background daemons, a watcher cannot attribute an audit-log actor to an automatic
 * trigger, and it risks hashing a package mid-copy. The explicit "build now" request is
 * the operator's signal that copying has finished.
 */

import { execFile } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
import { Request, Response, NextFunction } from 'express';
import { dbSourceConnection } from '../../index';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { FILENAME_RE, MAX_PACKAGES_PER_BUNDLE, PatchBundleManifest, PatchBundlePackage } from '../../utils/patchBundle';
import { signPatchBundleManifest } from '../../utils/patchBundleSign';
import {
  BARE_DIR_NAME_RE,
  BinaryMissingError,
  CHANNEL_RE,
  extractDebMetadata,
  extractRpmMetadata,
  findSymlinks,
  OS_MATCH_RE,
  resolveWithinRoot,
  sha256File,
  VERSION_FIELD_RE,
} from '../../utils/patchBundleBuildHelpers';
import { requireMfa } from './patch_management';
import { insertVerifiedPatchBundle } from './patch_bundles';
import { getLogger } from '../../utils/logger';
import { PATCH_ARCHIVE_ROUTE_PATH } from '../../consts/server';
import { HTTPS_URL_PATTERN } from '../../consts/http';

const logger = getLogger('nodes.patchBundlesBuild');

const execFileAsync = promisify(execFile);

function getFleetDb() {
  const dbSources = dbSourceConnection();
  if (!dbSources || dbSources.length < 2) return null;
  return dbSources[1];
}

function stagingRoot(): string {
  const dir = process.env.PATCH_BUNDLE_STAGING_DIR;
  if (!dir) throw new Error('PATCH_BUNDLE_STAGING_DIR is not configured on this server');
  return dir;
}

function archiveDir(): string {
  const dir = process.env.PATCH_ARCHIVE_DIR;
  if (!dir) throw new Error('PATCH_ARCHIVE_DIR is not configured on this server');
  return dir;
}

/**
 * Resolves `sourceDirName` (already BARE_DIR_NAME_RE-checked by the caller) under the
 * staging root. The realpath/containment logic itself lives in
 * utils/patchBundleBuildHelpers.ts's resolveWithinRoot, alongside the other pure helpers
 * imported above, so patchBundleBuild.selftest.ts can exercise them without booting the
 * server through this file's ../../index import.
 */
async function resolveStagingDir(sourceDirName: string): Promise<string> {
  return resolveWithinRoot(stagingRoot(), sourceDirName);
}

/**
 * Loads the private signing key, refusing (fail loudly, not silently) if
 * its on-disk permissions are more open than owner-only — a misconfigured
 * deploy could relax these after the fact, so this is enforced on every
 * read, not just at key-generation time (accepted-risk mitigation 1).
 */
function loadSignKey(): string {
  const keyPath = process.env.PATCH_BUNDLE_SIGN_KEY_PATH || path.join(__dirname, '..', '..', '..', 'keys', 'patch_bundle_sign.key');
  if (!fs.existsSync(keyPath)) {
    throw new Error(`patch bundle signing key not found at ${keyPath} — provision it (see scripts/sign-patch-bundle.ts keygen) before using the build endpoint`);
  }
  const mode = fs.statSync(keyPath).mode & 0o777;
  if (mode & 0o077) {
    throw new Error(`patch bundle signing key at ${keyPath} is readable/writable beyond its owner (mode ${mode.toString(8)}) — refusing to use it; chmod 600 it first`);
  }
  return fs.readFileSync(keyPath, 'utf-8');
}

type StagedPackage = { name: string; version: string; arch: string; filename: string; sha256: string };

/**
 * POST /api/patch/bundles/build
 * Body: { source_dir, family: 'deb'|'rpm', version, os_match, channel,
 *         archive_base_url?, totp_code, notes? }
 * Super-Admin (route-level) + MFA (requireMfa). See this file's header
 * comment for the full accepted-risk note and required mitigations.
 *
 * Scans PATCH_BUNDLE_STAGING_DIR/<source_dir> for files matching `family`'s
 * extension, derives each package's name/version/arch via dpkg-deb/rpm
 * (never trusts the filename), hashes every file, tars them into
 * PATCH_ARCHIVE_DIR/<bundle_id>.tar.gz, signs the resulting manifest with
 * the server-resident key, and stores it via the same
 * insertVerifiedPatchBundle path uploadPatchBundle uses.
 */
export const buildPatchBundle = async (req: Request, res: Response, next: NextFunction) => {
  let archivePath: string | null = null;
  let user: { id: number; email: string } | null = null;
  try {
    const fleetDb = getFleetDb();
    if (!fleetDb) return next(new CustomError(500, 'Database', 'DB connection missing', []));

    const dbSources = dbSourceConnection();
    if (!dbSources) return next(new CustomError(500, 'Database', 'DB connection missing', []));
    const mfaUser = await requireMfa(req, res, dbSources[0]);
    if (!mfaUser) return;
    user = mfaUser;

    const sourceDirRaw = req.body?.source_dir;
    const family = req.body?.family;
    const version = req.body?.version;
    const osMatch = req.body?.os_match;
    const channel = req.body?.channel;
    const notes = typeof req.body?.notes === 'string' ? req.body.notes.slice(0, 2000) : undefined;
    const archiveBaseUrl = typeof req.body?.archive_base_url === 'string' && req.body.archive_base_url
      ? req.body.archive_base_url
      : process.env.PATCH_ARCHIVE_BASE_URL;

    if (typeof sourceDirRaw !== 'string' || !BARE_DIR_NAME_RE.test(sourceDirRaw)) {
      return res.status(400).json({ status: 'Fail', message: 'source_dir must be a bare directory name (no "/" or "..")' });
    }
    if (family !== 'deb' && family !== 'rpm') {
      return res.status(400).json({ status: 'Fail', message: 'family must be "deb" or "rpm"' });
    }
    if (typeof version !== 'string' || !VERSION_FIELD_RE.test(version)) {
      return res.status(400).json({ status: 'Fail', message: 'version is missing or invalid' });
    }
    if (typeof osMatch !== 'string' || !OS_MATCH_RE.test(osMatch)) {
      return res.status(400).json({ status: 'Fail', message: 'os_match is missing or invalid' });
    }
    if (typeof channel !== 'string' || !CHANNEL_RE.test(channel)) {
      return res.status(400).json({ status: 'Fail', message: 'channel is missing or invalid' });
    }
    if (!archiveBaseUrl || !HTTPS_URL_PATTERN.test(archiveBaseUrl)) {
      return res.status(400).json({ status: 'Fail', message: 'archive_base_url must be an https URL (or set PATCH_ARCHIVE_BASE_URL)' });
    }

    let sourceDir: string;
    try {
      sourceDir = await resolveStagingDir(sourceDirRaw);
    } catch (e: any) {
      return res.status(400).json({ status: 'Fail', message: `invalid source_dir: ${e.message}` });
    }

    const ext = family === 'deb' ? '.deb' : '.rpm';
    let entries: string[];
    try {
      entries = (await fs.promises.readdir(sourceDir)).filter((f) => !f.startsWith('.'));
    } catch (e: any) {
      return res.status(400).json({ status: 'Fail', message: `could not read source_dir: ${e.message}` });
    }
    if (entries.length === 0) {
      return res.status(400).json({ status: 'Fail', message: `source_dir is empty (or contains only hidden files)` });
    }
    if (entries.length > MAX_PACKAGES_PER_BUNDLE) {
      return res.status(400).json({ status: 'Fail', message: `source_dir has more than ${MAX_PACKAGES_PER_BUNDLE} files` });
    }
    const mismatched = entries.filter((f) => !f.endsWith(ext));
    if (mismatched.length > 0) {
      return res.status(400).json({
        status: 'Fail',
        message: `source_dir contains file(s) not matching family "${family}" (expected ${ext}): ${mismatched.slice(0, 5).join(', ')}`,
      });
    }
    const invalidNames = entries.filter((f) => !FILENAME_RE.test(f));
    if (invalidNames.length > 0) {
      return res.status(400).json({ status: 'Fail', message: `invalid filename(s): ${invalidNames.slice(0, 5).join(', ')}` });
    }
    // Reject any symlink in the staging directory explicitly — see
    // findSymlinks' comment for why this is inert today either way (the
    // agent rejects non-regular tar entries outright) but worth pinning as
    // an explicit, immediate error rather than a confusing later surprise.
    const symlinks = await findSymlinks(sourceDir, entries);
    if (symlinks.length > 0) {
      return res.status(400).json({ status: 'Fail', message: `source_dir contains symlink(s), which a bundle archive can never install from: ${symlinks.slice(0, 5).join(', ')}` });
    }

    const packages: PatchBundlePackage[] = [];
    for (const filename of entries) {
      const absPath = path.join(sourceDir, filename);
      try {
        const meta = family === 'deb' ? await extractDebMetadata(absPath) : await extractRpmMetadata(absPath);
        const sha256 = await sha256File(absPath);
        const pkg: StagedPackage = { name: meta.name, version: meta.version, arch: meta.arch, filename, sha256 };
        packages.push(pkg);
      } catch (e) {
        // Identifies which specific file in the batch failed before rethrowing
        // to the handler's outer catch (unchanged control flow) — without
        // this, a bad package among dozens in source_dir is indistinguishable
        // from any other failure in this handler's generic error log.
        logger.warn({ err: e, filename, family, packages_processed: packages.length, packages_total: entries.length }, 'Failed to extract metadata for a staged package file');
        throw e;
      }
    }

    const bundleId = crypto.randomUUID();
    const outDir = archiveDir();
    await fs.promises.mkdir(outDir, { recursive: true, mode: 0o755 });
    archivePath = path.join(outDir, `${bundleId}.tar.gz`);

    // Fixed argv, no shell — package basenames only (already FILENAME_RE-
    // checked above), `-C sourceDir` so the archive contains flat, root-level
    // entries (bundle_extract.go on the agent side rejects subdirectory
    // entries), matching exactly what a hand-built `tar czf` for the offline
    // CLI workflow would also need to produce.
    try {
      await execFileAsync('tar', ['czf', archivePath, '-C', sourceDir, ...entries]);
    } catch (e: any) {
      if (e?.code === 'ENOENT') throw new BinaryMissingError('tar not found on this server');
      throw new Error(`tar failed building the archive: ${e.message}`, { cause: e });
    }

    // TOCTOU guard: each package's sha256 above was computed BEFORE this tar
    // step re-read the same staged files. If a file changed in between (an
    // operator still copying into source_dir, or a concurrent overwrite),
    // the signed manifest's per-file hash would silently no longer match
    // what actually got archived — the resulting bundle would fail safe at
    // the agent (hash mismatch -> reject) but with no error surfaced here at
    // build time. Re-hash every staged file now and compare; fail closed
    // rather than store a bundle that can never successfully apply.
    for (const pkg of packages) {
      const absPath = path.join(sourceDir, pkg.filename);
      const recheckedSha256 = await sha256File(absPath);
      if (recheckedSha256 !== pkg.sha256) {
        throw new Error(
          `source_dir file "${pkg.filename}" changed during the build (hash mismatch before/after archiving) — retry once the directory is stable`,
        );
      }
    }

    const archiveSha256 = await sha256File(archivePath);
    const archiveSize = (await fs.promises.stat(archivePath)).size;

    const manifest: Partial<PatchBundleManifest> = {
      bundle_id: bundleId,
      version,
      family,
      os_match: osMatch,
      channel,
      packages,
      archive_url: `${archiveBaseUrl.replace(/\/$/, '')}${PATCH_ARCHIVE_ROUTE_PATH}${bundleId}.tar.gz`,
      archive_sha256: archiveSha256,
      archive_size: archiveSize,
      notes,
    };

    let signKey: string;
    try {
      signKey = loadSignKey();
    } catch (e: any) {
      // Server misconfiguration (key missing, or perms loosened past owner-
      // only) — every build request will 503 until this is fixed, so it
      // needs a log trace, not just the one caller's error response.
      logger.error({ err: e }, 'Patch bundle build unavailable: signing key could not be loaded');
      return res.status(503).json({ status: 'Fail', message: e.message });
    }

    let signedResult: ReturnType<typeof signPatchBundleManifest>;
    try {
      signedResult = signPatchBundleManifest(manifest, signKey);
    } catch (e: any) {
      // Distinct step from every other rejection branch in this handler (key
      // load, tar, hash mismatch, bundle_id collision) — without a log line
      // here, a manifest that fails schema validation or self-verification
      // inside signPatchBundleManifest is indistinguishable from any other
      // 400 in this handler's logs.
      logger.warn({ err: e, bundle_id: manifest.bundle_id, family, version }, 'Patch bundle build rejected: built manifest failed signing/validation');
      return res.status(400).json({ status: 'Fail', message: `built manifest rejected: ${e.message}` });
    }
    const { signed, manifest: verified } = signedResult;

    const bundle = await insertVerifiedPatchBundle(fleetDb, verified, signed.payload, signed.signature, user.id, user.email);
    if (!bundle) {
      // Should be near-impossible (bundleId is a fresh crypto.randomUUID()
      // generated a few lines above) — logged at warn so an actual occurrence
      // (vs. a plain validation 400) is never silently indistinguishable from
      // "no problem happened" in the logs.
      logger.warn({ bundle_id: verified.bundle_id }, 'Patch bundle build rejected: bundle_id already exists (UUID collision)');
      return res.status(409).json({ status: 'Fail', message: `bundle ${verified.bundle_id} already exists (extremely unlikely UUID collision — retry)` });
    }
    archivePath = null; // committed — no longer ours to clean up on a later error in this handler

    logAuditTrail({
      action: 'PATCH_BUNDLE_BUILT',
      status: 'success',
      userId: user.id,
      email: user.email,
      details: {
        bundle_id: verified.bundle_id,
        version: verified.version,
        family: verified.family,
        os_match: verified.os_match,
        channel: verified.channel,
        packages_count: verified.packages.length,
        source_dir: sourceDirRaw,
      },
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
    }).catch((auditErr) => {
      logger.warn({ err: auditErr, bundle_id: verified.bundle_id }, 'Failed to write audit trail for patch bundle build');
    });

    logger.info(
      { bundle_id: verified.bundle_id, family: verified.family, version: verified.version, packages_count: verified.packages.length },
      'Patch bundle built and signed',
    );

    return res.status(201).json({ status: 'Success', bundle });
  } catch (error: any) {
    logger.error(
      { err: error, source_dir: req.body?.source_dir, family: req.body?.family, version: req.body?.version, user_id: user?.id },
      'Failed to build patch bundle',
    );
    if (user) {
      logAuditTrail({
        action: 'PATCH_BUNDLE_BUILT',
        status: 'failure',
        userId: user.id,
        email: user.email,
        details: { error: error?.message ?? String(error) },
        ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
      }).catch((auditErr) => {
        logger.warn({ err: auditErr }, 'Failed to write audit trail for failed patch bundle build');
      });
    }
    if (error instanceof BinaryMissingError) {
      return res.status(503).json({ status: 'Fail', message: error.message });
    }
    return next(new CustomError(500, 'Raw', 'Failed to build patch bundle', null, error));
  } finally {
    // Clean up an orphaned archive file if anything failed after tar
    // succeeded but before the DB insert committed (archivePath is nulled
    // out right after a successful insert, so this only fires on failure).
    if (archivePath) {
      await fs.promises.rm(archivePath, { force: true }).catch((rmErr) => {
        logger.warn({ err: rmErr, archivePath }, 'Failed to clean up orphaned patch archive file');
      });
    }
  }
};

/**
 * GET /api/agent/patch-archives/:filename
 * Agent-facing, deliberately no JWT session — same trust model as
 * GET /api/agent/manifest (routes/api/agent.ts's header comment): the
 * content itself is what's trusted (the agent independently verifies
 * archive_sha256 from the signed manifest against whatever bytes this
 * streams, and every individual file's hash again after extraction — see
 * bundle_download.go/bundle_extract.go), not the transport or a session.
 * Rate-limited, not session-gated, exactly like the manifest endpoint.
 *
 * Only ever streams from PATCH_ARCHIVE_DIR (server-generated output),
 * never PATCH_BUNDLE_STAGING_DIR (raw operator-dropped input) — :filename
 * is validated against FILENAME_RE (rejects '/', '..', absolute paths)
 * before any filesystem access, and the resolved path is re-checked to
 * still be inside PATCH_ARCHIVE_DIR before streaming (defense in depth
 * beyond the regex, same discipline resolveStagingDir applies above).
 */
export const servePatchArchive = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const filename = req.params.filename;
    if (typeof filename !== 'string' || !FILENAME_RE.test(filename) || !filename.endsWith('.tar.gz')) {
      return res.status(400).json({ status: 'Fail', message: 'Invalid archive filename' });
    }

    let dir: string;
    try {
      dir = archiveDir();
    } catch (e: any) {
      logger.warn({ err: e }, 'Patch archive download rejected: server misconfigured');
      return res.status(503).json({ status: 'Fail', message: e.message });
    }

    const dirReal = await fs.promises.realpath(dir).catch(() => null);
    if (!dirReal) {
      // Distinct from the two rejection branches below (same 404 shape
      // otherwise) — this means PATCH_ARCHIVE_DIR itself doesn't exist on
      // disk, a server misconfiguration rather than a missing/bad filename,
      // which would otherwise be indistinguishable from a routine "no such
      // archive" 404 in the logs.
      logger.warn({ filename, dir }, 'Patch archive download rejected: archive directory does not exist');
      return res.status(404).json({ status: 'Fail', message: 'Archive not found' });
    }
    const candidate = path.join(dirReal, filename);
    const resolved = await fs.promises.realpath(candidate).catch(() => null);
    const prefix = dirReal.endsWith(path.sep) ? dirReal : dirReal + path.sep;
    if (!resolved || !resolved.startsWith(prefix)) {
      // Covers both a genuinely missing archive file AND a resolved path
      // that escaped PATCH_ARCHIVE_DIR — the latter would only happen via a
      // symlink planted inside the archive dir, since :filename is already
      // FILENAME_RE-validated above (no '/', no '..'). Worth a trace either
      // way: a stale manifest reference vs. a potential path-escape attempt
      // are both otherwise silent 404s with no distinguishing signal.
      logger.warn({ filename, escaped: !!resolved }, 'Patch archive download rejected: archive not found or resolved outside archive directory');
      return res.status(404).json({ status: 'Fail', message: 'Archive not found' });
    }

    const stat = await fs.promises.stat(resolved).catch(() => null);
    if (!stat || !stat.isFile()) {
      logger.warn({ filename }, 'Patch archive download rejected: resolved path is not a regular file');
      return res.status(404).json({ status: 'Fail', message: 'Archive not found' });
    }

    logger.debug({ filename, size: stat.size }, 'Patch archive served');

    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Length', String(stat.size));
    const stream = fs.createReadStream(resolved);
    stream.on('error', (err) => {
      logger.error({ err, filename }, 'Failed to stream patch archive');
      next(new CustomError(500, 'Raw', 'Failed to stream archive', null, err));
    });
    stream.pipe(res);
  } catch (error) {
    logger.error({ err: error, filename: req.params?.filename }, 'Failed to serve patch archive');
    return next(new CustomError(500, 'Raw', 'Failed to serve patch archive', null, error));
  }
};
