/**
 * Browser-facing companion to patch_bundles_build.ts's "build from a server folder"
 * pipeline, which never accepts file bytes itself. This endpoint accepts a multipart
 * upload of raw package files, writes them into a fresh subdirectory of
 * PATCH_BUNDLE_STAGING_DIR, and returns that directory's name so the caller can pass it
 * as `source_dir` to POST /api/patch/bundles/build. The two-step upload-then-build split
 * is deliberate: the admin still explicitly confirms family/version/os_match/channel and
 * re-enters MFA for the signing step, like every other high-privilege patch action.
 *
 * Same accepted-risk posture as patch_bundles_build.ts (see that file's
 * header) — this doesn't change the signing trust model, it only changes
 * how files arrive in the staging directory. Gated identically: Super-Admin
 * (route-level) + MFA (requireMfa). Every call is audit-logged, including
 * rejections, and any partially-written directory is deleted on failure so
 * a rejected/failed upload never leaves orphaned files behind.
 *
 * Security notes specific to accepting uploaded bytes (beyond what the
 * folder-scan endpoint has to worry about):
 *   - `file.originalname` is fully attacker-controlled — validated against
 *     the same FILENAME_RE the folder-scan path already enforces, and never
 *     used to build a path beyond that validated basename.
 *   - The destination directory is generated server-side (crypto.randomUUID
 *     based), never derived from client input, so there's no path-traversal
 *     surface via a "folder name" the client could otherwise supply here.
 *   - `family` must arrive as a query parameter, not a form field — multer's
 *     per-file destination/filename callbacks run while the multipart body
 *     is still streaming, before form fields that happen to appear after the
 *     file parts are guaranteed to be parsed. A query param has no such
 *     ordering hazard.
 *   - Extension-vs-family and file-count/size limits are enforced twice:
 *     once cheaply via multer's `limits`/fileFilter while streaming (fails
 *     fast, bounds worst-case disk usage even before MFA is checked), and
 *     again after the fact against the fully-written directory (belt and
 *     suspenders — mirrors patch_bundles_build.ts's own re-check discipline).
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { Request, Response, NextFunction } from 'express';
import multer from 'multer';
import { dbSourceConnection } from '../../index';
import { CustomError } from '../../utils/response/custom-error/CustomError';
import { logAuditTrail } from '../../utils/auditTrailLogger';
import { FILENAME_RE, MAX_PACKAGES_PER_BUNDLE } from '../../utils/patchBundle';
import { resolveWithinRoot } from '../../utils/patchBundleBuildHelpers';
import { requireMfa } from './patch_management';

const MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024; // 500MB — generous for a single deb/rpm, still bounded
const MAX_FILES_PER_UPLOAD = 100;

function stagingRoot(): string {
  const dir = process.env.PATCH_BUNDLE_STAGING_DIR;
  if (!dir) throw new Error('PATCH_BUNDLE_STAGING_DIR is not configured on this server');
  return dir;
}

async function rmrf(dir: string | null) {
  if (!dir) return;
  await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
}

/**
 * POST /api/patch/bundles/staging-upload?family=deb|rpm
 * multipart/form-data: `packages` (one or more files) + `totp_code` field.
 * Super-Admin (route-level) + MFA. Returns { status, source_dir, files }
 * where `source_dir` is ready to pass straight to POST /api/patch/bundles/build.
 */
export const uploadPackagesForBuild = async (req: Request, res: Response, next: NextFunction) => {
  const family = req.query.family;
  if (family !== 'deb' && family !== 'rpm') {
    return res.status(400).json({ status: 'Fail', message: 'family query parameter must be "deb" or "rpm"' });
  }
  const ext = family === 'deb' ? '.deb' : '.rpm';

  let uploadDir: string | null = null;
  let dirName: string | null;
  try {
    const root = stagingRoot();
    await fs.promises.mkdir(root, { recursive: true, mode: 0o755 });
    dirName = `upload-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const candidate = path.join(root, dirName);
    await fs.promises.mkdir(candidate, { recursive: false, mode: 0o755 });
    // Defense in depth: confirm the freshly-created dir didn't somehow
    // resolve outside root (e.g. staging root itself is a symlink pointing
    // somewhere unexpected) — same discipline patch_bundles_build.ts applies
    // to admin-supplied source_dir names, applied here to our own generated one.
    uploadDir = await resolveWithinRoot(root, dirName);
  } catch (e: any) {
    return res.status(503).json({ status: 'Fail', message: `could not prepare staging directory: ${e.message}` });
  }

  const upload = multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb) => cb(null, uploadDir as string),
      filename: (_req, file, cb) => {
        if (!FILENAME_RE.test(file.originalname)) {
          // multer's DiskStorage filename callback is typed (error, filename);
          // the filename is ignored when an error is passed, but both args are
          // required. Pass an empty placeholder.
          cb(new Error(`invalid filename: ${file.originalname}`), '');
          return;
        }
        cb(null, file.originalname);
      },
    }),
    limits: { fileSize: MAX_FILE_SIZE_BYTES, files: MAX_FILES_PER_UPLOAD },
    fileFilter: (_req, file, cb) => {
      cb(null, file.originalname.toLowerCase().endsWith(ext));
    },
  }).array('packages', MAX_FILES_PER_UPLOAD);

  let user: { id: number; email: string } | null = null;
  try {
    await new Promise<void>((resolve, reject) => {
      upload(req, res, (err) => (err ? reject(err) : resolve()));
    });

    const files = (req.files as Express.Multer.File[] | undefined) ?? [];
    if (files.length === 0) {
      throw new Error(`no ${ext} files were accepted — check the files you selected match family "${family}"`);
    }
    if (files.length > MAX_PACKAGES_PER_BUNDLE) {
      throw new Error(`more than ${MAX_PACKAGES_PER_BUNDLE} files uploaded`);
    }
    // Re-check against the fully-written directory, not just multer's
    // streaming fileFilter — same belt-and-suspenders discipline
    // patch_bundles_build.ts applies to its own scanned entries.
    const onDisk = (await fs.promises.readdir(uploadDir)).filter((f) => !f.startsWith('.'));
    const mismatched = onDisk.filter((f) => !f.toLowerCase().endsWith(ext) || !FILENAME_RE.test(f));
    if (mismatched.length > 0) {
      throw new Error(`rejected file(s) not matching family "${family}": ${mismatched.slice(0, 5).join(', ')}`);
    }

    // MFA runs only after the upload is fully on disk (multer must finish
    // parsing the body — which includes totp_code — before req.body is
    // populated). Every failure path from here on calls rmrf(uploadDir)
    // explicitly, so a second-factor-unverified upload never lingers.
    const dbSources = dbSourceConnection();
    if (!dbSources) {
      // Clean up explicitly: this early return is the one path that neither throws into
      // the outer catch (which calls rmrf) nor cleans up on its own, so without this the
      // just-uploaded directory leaks.
      await rmrf(uploadDir);
      return next(new CustomError(500, 'Database', 'DB connection missing', []));
    }
    const mfaUser = await requireMfa(req, res, dbSources[0]);
    if (!mfaUser) {
      await rmrf(uploadDir);
      return; // requireMfa already sent the response
    }
    user = mfaUser;

    logAuditTrail({
      action: 'PATCH_BUNDLE_PACKAGES_UPLOADED',
      status: 'success',
      userId: user.id,
      email: user.email,
      details: { source_dir: dirName, family, files: onDisk },
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
    }).catch(() => {});

    return res.status(201).json({
      status: 'Success',
      source_dir: dirName,
      files: onDisk,
    });
  } catch (error: any) {
    await rmrf(uploadDir);
    const isMulterOrValidation = error instanceof multer.MulterError || typeof error?.message === 'string';
    logAuditTrail({
      action: 'PATCH_BUNDLE_PACKAGES_UPLOADED',
      status: 'failure',
      userId: user?.id ?? null,
      email: user?.email ?? null,
      details: { error: error?.message ?? String(error), family },
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown',
    }).catch(() => {});
    if (isMulterOrValidation) {
      return res.status(400).json({ status: 'Fail', message: error.message || 'Upload rejected' });
    }
    return next(new CustomError(500, 'Raw', 'Failed to upload packages', null, error));
  }
};
